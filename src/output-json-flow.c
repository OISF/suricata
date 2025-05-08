/* Copyright (C) 2007-2025 Open Information Security Foundation
 *
 * You can copy, redistribute or modify this Program under the terms of
 * the GNU General Public License version 2 as published by the Free
 * Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 */

/**
 * \file
 *
 * \author Victor Julien <victor@inliniac.net>
 *
 * Implements Flow JSON logging portion of the engine.
 */

#include "suricata-common.h"
#include "detect.h"
#include "pkt-var.h"
#include "conf.h"
#include "app-layer-parser.h"

#include "threads.h"
#include "threadvars.h"
#include "tm-threads.h"

#include "util-print.h"
#include "util-unittest.h"

#include "util-debug.h"

#include "output.h"
#include "util-privs.h"
#include "util-buffer.h"
#include "util-device-private.h"
#include "util-proto-name.h"
#include "util-logopenfile.h"
#include "util-time.h"
#include "output-json.h"
#include "output-json-flow.h"

#include "stream-tcp.h"
#include "stream-tcp-private.h"
#include "flow-storage.h"
#include "util-exception-policy.h"

static SCJsonBuilder *CreateEveHeaderFromFlow(const Flow *f)
{
    char timebuf[64];
    char srcip[46] = {0}, dstip[46] = {0};
    Port sp, dp;

    SCJsonBuilder *jb = SCJbNewObject();
    if (unlikely(jb == NULL)) {
        return NULL;
    }

    SCTime_t ts = TimeGet();

    CreateIsoTimeString(ts, timebuf, sizeof(timebuf));

    if ((f->flags & FLOW_DIR_REVERSED) == 0) {
        if (FLOW_IS_IPV4(f)) {
            PrintInet(AF_INET, (const void *)&(f->src.addr_data32[0]), srcip, sizeof(srcip));
            PrintInet(AF_INET, (const void *)&(f->dst.addr_data32[0]), dstip, sizeof(dstip));
        } else if (FLOW_IS_IPV6(f)) {
            PrintInet(AF_INET6, (const void *)&(f->src.address), srcip, sizeof(srcip));
            PrintInet(AF_INET6, (const void *)&(f->dst.address), dstip, sizeof(dstip));
        }
        sp = f->sp;
        dp = f->dp;
    } else {
        if (FLOW_IS_IPV4(f)) {
            PrintInet(AF_INET, (const void *)&(f->dst.addr_data32[0]), srcip, sizeof(srcip));
            PrintInet(AF_INET, (const void *)&(f->src.addr_data32[0]), dstip, sizeof(dstip));
        } else if (FLOW_IS_IPV6(f)) {
            PrintInet(AF_INET6, (const void *)&(f->dst.address), srcip, sizeof(srcip));
            PrintInet(AF_INET6, (const void *)&(f->src.address), dstip, sizeof(dstip));
        }
        sp = f->dp;
        dp = f->sp;
    }

    /* time */
    SCJbSetString(jb, "timestamp", timebuf);

    CreateEveFlowId(jb, (const Flow *)f);

#if 0 // TODO
    /* sensor id */
    if (sensor_id >= 0)
        json_object_set_new(js, "sensor_id", json_integer(sensor_id));
#endif

    /* input interface */
    if (f->livedev) {
        SCJbSetString(jb, "in_iface", f->livedev->dev);
    }

    JB_SET_STRING(jb, "event_type", "flow");

    /* vlan */
    if (f->vlan_idx > 0) {
        SCJbOpenArray(jb, "vlan");
        SCJbAppendUint(jb, f->vlan_id[0]);
        if (f->vlan_idx > 1) {
            SCJbAppendUint(jb, f->vlan_id[1]);
        }
        if (f->vlan_idx > 2) {
            SCJbAppendUint(jb, f->vlan_id[2]);
        }
        SCJbClose(jb);
    }

    /* tuple */
    SCJbSetString(jb, "src_ip", srcip);
    switch(f->proto) {
        case IPPROTO_ICMP:
            break;
        case IPPROTO_UDP:
        case IPPROTO_TCP:
        case IPPROTO_SCTP:
            SCJbSetUint(jb, "src_port", sp);
            break;
    }
    SCJbSetString(jb, "dest_ip", dstip);
    switch(f->proto) {
        case IPPROTO_ICMP:
            break;
        case IPPROTO_UDP:
        case IPPROTO_TCP:
        case IPPROTO_SCTP:
            SCJbSetUint(jb, "dest_port", dp);
            break;
    }

    /* ip version */
    if (FLOW_IS_IPV4(f)) {
        SCJbSetUint(jb, "ip_v", 4);
    } else if (FLOW_IS_IPV6(f)) {
        SCJbSetUint(jb, "ip_v", 6);
    }

    if (SCProtoNameValid(f->proto)) {
        SCJbSetString(jb, "proto", known_proto[f->proto]);
    } else {
        char proto[4];
        snprintf(proto, sizeof(proto), "%"PRIu8"", f->proto);
        SCJbSetString(jb, "proto", proto);
    }

    switch (f->proto) {
        case IPPROTO_ICMP:
        case IPPROTO_ICMPV6:
            SCJbSetUint(jb, "icmp_type", f->icmp_s.type);
            SCJbSetUint(jb, "icmp_code", f->icmp_s.code);
            if (f->tosrcpktcnt) {
                SCJbSetUint(jb, "response_icmp_type", f->icmp_d.type);
                SCJbSetUint(jb, "response_icmp_code", f->icmp_d.code);
            }
            break;
        case IPPROTO_ESP:
            SCJbSetUint(jb, "spi", f->esp.spi);
            break;
    }
    return jb;
}

void EveAddAppProto(Flow *f, SCJsonBuilder *js)
{
    if (f->alproto) {
        SCJbSetString(js, "app_proto", AppProtoToString(f->alproto));
    }
    if (f->alproto_ts && f->alproto_ts != f->alproto) {
        SCJbSetString(js, "app_proto_ts", AppProtoToString(f->alproto_ts));
    }
    if (f->alproto_tc && f->alproto_tc != f->alproto) {
        SCJbSetString(js, "app_proto_tc", AppProtoToString(f->alproto_tc));
    }
    if (f->alproto_orig != f->alproto && f->alproto_orig != ALPROTO_UNKNOWN) {
        SCJbSetString(js, "app_proto_orig", AppProtoToString(f->alproto_orig));
    }
    if (f->alproto_expect != f->alproto && f->alproto_expect != ALPROTO_UNKNOWN) {
        SCJbSetString(js, "app_proto_expected", AppProtoToString(f->alproto_expect));
    }

}

void EveAddFlow(Flow *f, SCJsonBuilder *js)
{
    FlowBypassInfo *fc = FlowGetStorageById(f, GetFlowBypassInfoID());
    if (fc) {
        SCJbSetUint(js, "pkts_toserver", f->todstpktcnt + fc->todstpktcnt);
        SCJbSetUint(js, "pkts_toclient", f->tosrcpktcnt + fc->tosrcpktcnt);
        SCJbSetUint(js, "bytes_toserver", f->todstbytecnt + fc->todstbytecnt);
        SCJbSetUint(js, "bytes_toclient", f->tosrcbytecnt + fc->tosrcbytecnt);

        SCJbOpenObject(js, "bypassed");
        SCJbSetUint(js, "pkts_toserver", fc->todstpktcnt);
        SCJbSetUint(js, "pkts_toclient", fc->tosrcpktcnt);
        SCJbSetUint(js, "bytes_toserver", fc->todstbytecnt);
        SCJbSetUint(js, "bytes_toclient", fc->tosrcbytecnt);
        SCJbClose(js);
    } else {
        SCJbSetUint(js, "pkts_toserver", f->todstpktcnt);
        SCJbSetUint(js, "pkts_toclient", f->tosrcpktcnt);
        SCJbSetUint(js, "bytes_toserver", f->todstbytecnt);
        SCJbSetUint(js, "bytes_toclient", f->tosrcbytecnt);
    }

    char timebuf1[64];
    CreateIsoTimeString(f->startts, timebuf1, sizeof(timebuf1));
    SCJbSetString(js, "start", timebuf1);
}

static void EveExceptionPolicyLog(SCJsonBuilder *js, uint16_t flag)
{
    if (flag & EXCEPTION_TARGET_FLAG_DEFRAG_MEMCAP) {
        SCJbStartObject(js);
        SCJbSetString(js, "target",
                ExceptionPolicyTargetFlagToString(EXCEPTION_TARGET_FLAG_DEFRAG_MEMCAP));
        SCJbSetString(js, "policy",
                ExceptionPolicyEnumToString(
                        ExceptionPolicyTargetPolicy(EXCEPTION_TARGET_FLAG_DEFRAG_MEMCAP), true));
        SCJbClose(js);
    }
    if (flag & EXCEPTION_TARGET_FLAG_SESSION_MEMCAP) {
        SCJbStartObject(js);
        SCJbSetString(js, "target",
                ExceptionPolicyTargetFlagToString(EXCEPTION_TARGET_FLAG_SESSION_MEMCAP));
        SCJbSetString(js, "policy",
                ExceptionPolicyEnumToString(
                        ExceptionPolicyTargetPolicy(EXCEPTION_TARGET_FLAG_SESSION_MEMCAP), true));
        SCJbClose(js);
    }
    if (flag & EXCEPTION_TARGET_FLAG_REASSEMBLY_MEMCAP) {
        SCJbStartObject(js);
        SCJbSetString(js, "target",
                ExceptionPolicyTargetFlagToString(EXCEPTION_TARGET_FLAG_REASSEMBLY_MEMCAP));
        SCJbSetString(js, "policy",
                ExceptionPolicyEnumToString(
                        ExceptionPolicyTargetPolicy(EXCEPTION_TARGET_FLAG_REASSEMBLY_MEMCAP),
                        true));
        SCJbClose(js);
    }
    if (flag & EXCEPTION_TARGET_FLAG_FLOW_MEMCAP) {
        SCJbStartObject(js);
        SCJbSetString(
                js, "target", ExceptionPolicyTargetFlagToString(EXCEPTION_TARGET_FLAG_FLOW_MEMCAP));
        SCJbSetString(js, "policy",
                ExceptionPolicyEnumToString(
                        ExceptionPolicyTargetPolicy(EXCEPTION_TARGET_FLAG_FLOW_MEMCAP), true));
        SCJbClose(js);
    }
    if (flag & EXCEPTION_TARGET_FLAG_MIDSTREAM) {
        SCJbStartObject(js);
        SCJbSetString(
                js, "target", ExceptionPolicyTargetFlagToString(EXCEPTION_TARGET_FLAG_MIDSTREAM));
        SCJbSetString(js, "policy",
                ExceptionPolicyEnumToString(
                        ExceptionPolicyTargetPolicy(EXCEPTION_TARGET_FLAG_MIDSTREAM), true));
        SCJbClose(js);
    }
    if (flag & EXCEPTION_TARGET_FLAG_APPLAYER_ERROR) {
        SCJbStartObject(js);
        SCJbSetString(js, "target",
                ExceptionPolicyTargetFlagToString(EXCEPTION_TARGET_FLAG_APPLAYER_ERROR));
        SCJbSetString(js, "policy",
                ExceptionPolicyEnumToString(
                        ExceptionPolicyTargetPolicy(EXCEPTION_TARGET_FLAG_APPLAYER_ERROR), true));
        SCJbClose(js);
    }
}

/* Eve format logging */
static void EveFlowLogJSON(OutputJsonThreadCtx *aft, SCJsonBuilder *jb, Flow *f)
{
    EveAddAppProto(f, jb);
    SCJbOpenObject(jb, "flow");
    EveAddFlow(f, jb);

    char timebuf2[64];
    CreateIsoTimeString(f->lastts, timebuf2, sizeof(timebuf2));
    SCJbSetString(jb, "end", timebuf2);

    uint64_t age = (SCTIME_SECS(f->lastts) - SCTIME_SECS(f->startts));
    SCJbSetUint(jb, "age", age);

    if (f->flow_end_flags & FLOW_END_FLAG_EMERGENCY)
        JB_SET_TRUE(jb, "emergency");

    const int flow_state = f->flow_state;
    switch (flow_state) {
        case FLOW_STATE_NEW:
            JB_SET_STRING(jb, "state", "new");
            break;
        case FLOW_STATE_ESTABLISHED:
            JB_SET_STRING(jb, "state", "established");
            break;
        case FLOW_STATE_CLOSED:
            JB_SET_STRING(jb, "state", "closed");
            break;
        case FLOW_STATE_LOCAL_BYPASSED:
            JB_SET_STRING(jb, "state", "bypassed");
            JB_SET_STRING(jb, "bypass", "local");
            break;
#ifdef CAPTURE_OFFLOAD
        case FLOW_STATE_CAPTURE_BYPASSED:
            JB_SET_STRING(jb, "state", "bypassed");
            JB_SET_STRING(jb, "bypass", "capture");
            break;
#endif
        case FLOW_STATE_SIZE:
            DEBUG_VALIDATE_BUG_ON(1);
            SCLogDebug("invalid flow state: %d, contact developers", flow_state);
    }

    const char *reason = NULL;
    if (f->flow_end_flags & FLOW_END_FLAG_TCPREUSE)
        reason = "tcp_reuse";
    else if (f->flow_end_flags & FLOW_END_FLAG_FORCED)
        reason = "forced";
    else if (f->flow_end_flags & FLOW_END_FLAG_SHUTDOWN)
        reason = "shutdown";
    else if (f->flow_end_flags & FLOW_END_FLAG_TIMEOUT)
        reason = "timeout";
    else
        reason = "unknown";

    SCJbSetString(jb, "reason", reason);

    SCJbSetBool(jb, "alerted", FlowHasAlerts(f));
    if (f->flags & FLOW_WRONG_THREAD)
        JB_SET_TRUE(jb, "wrong_thread");

    if (f->flags & FLOW_IS_ELEPHANT)
        JB_SET_TRUE(jb, "elephant");

    if (f->flags & FLOW_ACTION_DROP) {
        JB_SET_STRING(jb, "action", "drop");
    } else if (f->flags & FLOW_ACTION_ACCEPT) {
        JB_SET_STRING(jb, "action", "accept");
    } else if (f->flags & FLOW_ACTION_PASS) {
        JB_SET_STRING(jb, "action", "pass");
    }
    if (f->applied_exception_policy != 0) {
        SCJbOpenArray(jb, "exception_policy");
        EveExceptionPolicyLog(jb, f->applied_exception_policy);
        SCJbClose(jb); /* close array */
    }

    if (f->alstate) {
        uint64_t tx_id = AppLayerParserGetTxCnt(f, f->alstate);
        if (tx_id) {
            SCJbSetUint(jb, "tx_cnt", tx_id);
        }
    }

    /* Close flow. */
    SCJbClose(jb);

    EveAddCommonOptions(&aft->ctx->cfg, NULL, f, jb, LOG_DIR_FLOW);

    /* TCP */
    if (f->proto == IPPROTO_TCP) {
        SCJbOpenObject(jb, "tcp");

        TcpSession *ssn = f->protoctx;

        char hexflags[3];
        snprintf(hexflags, sizeof(hexflags), "%02x",
                ssn ? ssn->tcp_packet_flags : 0);
        SCJbSetString(jb, "tcp_flags", hexflags);

        snprintf(hexflags, sizeof(hexflags), "%02x",
                ssn ? ssn->client.tcp_flags : 0);
        SCJbSetString(jb, "tcp_flags_ts", hexflags);

        snprintf(hexflags, sizeof(hexflags), "%02x",
                ssn ? ssn->server.tcp_flags : 0);
        SCJbSetString(jb, "tcp_flags_tc", hexflags);

        EveTcpFlags(ssn ? ssn->tcp_packet_flags : 0, jb);

        if (ssn) {
            const char *tcp_state = StreamTcpStateAsString(ssn->state);
            if (tcp_state != NULL)
                SCJbSetString(jb, "state", tcp_state);
            if (ssn->server.flags & STREAMTCP_STREAM_FLAG_HAS_GAP) {
                JB_SET_TRUE(jb, "tc_gap");
            }
            if (ssn->client.flags & STREAMTCP_STREAM_FLAG_HAS_GAP) {
                JB_SET_TRUE(jb, "ts_gap");
            }

            SCJbSetUint(jb, "ts_max_regions", ssn->client.sb.max_regions);
            SCJbSetUint(jb, "tc_max_regions", ssn->server.sb.max_regions);

            if (ssn->urg_offset_ts)
                SCJbSetUint(jb, "ts_urgent_oob_data", ssn->urg_offset_ts);
            if (ssn->urg_offset_tc)
                SCJbSetUint(jb, "tc_urgent_oob_data", ssn->urg_offset_tc);
        }

        /* Close tcp. */
        SCJbClose(jb);
    }
}

static int JsonFlowLogger(ThreadVars *tv, void *thread_data, Flow *f)
{
    SCEnter();
    OutputJsonThreadCtx *thread = thread_data;

    /* reset */
    MemBufferReset(thread->buffer);

    SCJsonBuilder *jb = CreateEveHeaderFromFlow(f);
    if (unlikely(jb == NULL)) {
        SCReturnInt(TM_ECODE_OK);
    }

    EveFlowLogJSON(thread, jb, f);

    OutputJsonBuilderBuffer(tv, NULL, f, jb, thread);
    SCJbFree(jb);

    SCReturnInt(TM_ECODE_OK);
}

void JsonFlowLogRegister (void)
{
    /* register as child of eve-log */
    OutputRegisterFlowSubModule(LOGGER_JSON_FLOW, "eve-log", "JsonFlowLog", "eve-log.flow",
            OutputJsonLogInitSub, JsonFlowLogger, JsonLogThreadInit, JsonLogThreadDeinit);
}
