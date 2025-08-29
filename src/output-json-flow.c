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

#include "threads.h"
#include "threadvars.h"
#include "tm-threads.h"

#include "util-print.h"
#include "util-unittest.h"

#include "util-debug.h"

#include "output.h"
#include "util-privs.h"
#include "util-buffer.h"
#include "util-device.h"
#include "util-proto-name.h"
#include "util-logopenfile.h"
#include "util-time.h"
#include "output-json.h"
#include "output-json-flow.h"

#include "stream-tcp.h"
#include "stream-tcp-private.h"
#include "flow-storage.h"
#include "util-exception-policy.h"

typedef struct LogFlowCtx_ {
    bool log_exception_policies;
    OutputJsonCtx *eve_ctx;
} LogFlowCtx;

typedef struct LogFlowLogThread_ {
    LogFlowCtx *flowlog_ctx;
    OutputJsonThreadCtx *output_ctx;
} LogFlowLogThread;

static void OutputFlowLogDeInitCtxSub(OutputCtx *output_ctx)
{
    LogFlowCtx *flow_ctx = output_ctx->data;
    SCFree(flow_ctx);
    SCFree(output_ctx);
}

static void JsonFlowLogParseConfig(ConfNode *conf, LogFlowCtx *flow_ctx)
{
    /* by default, don't log exception policies */
    flow_ctx->log_exception_policies = false;

    if (conf != NULL) {
        if (ConfNodeChildValueIsTrue(conf, "exception-policy")) {
            flow_ctx->log_exception_policies = true;
        }
    }
    SCLogDebug("Exception policy logging for flow %s",
            flow_ctx->log_exception_policies ? "enabled" : "disabled");
}

static OutputInitResult OutputFlowLogInitSub(ConfNode *conf, OutputCtx *parent_ctx)
{
    OutputInitResult result = { NULL, false };
    OutputJsonCtx *ojc = parent_ctx->data;

    LogFlowCtx *flow_ctx = SCCalloc(1, sizeof(LogFlowCtx));
    if (unlikely(flow_ctx == NULL)) {
        return result;
    }

    OutputCtx *output_ctx = SCCalloc(1, sizeof(OutputCtx));
    if (unlikely(output_ctx == NULL)) {
        SCFree(flow_ctx);
        return result;
    }

    flow_ctx->eve_ctx = ojc;

    output_ctx->data = flow_ctx;
    output_ctx->DeInit = OutputFlowLogDeInitCtxSub;
    JsonFlowLogParseConfig(conf, flow_ctx);

    result.ctx = output_ctx;
    result.ok = true;

    return result;
}

static TmEcode JsonFlowLogThreadInit(ThreadVars *tv, const void *initdata, void **data)
{
    LogFlowLogThread *thread = SCCalloc(1, sizeof(LogFlowLogThread));
    if (unlikely(thread == NULL)) {
        return TM_ECODE_FAILED;
    }

    if (initdata == NULL) {
        SCLogDebug("Error getting context for EveLogFlow. \"initdata\" argument NULL");
        goto error_exit;
    }

    thread->flowlog_ctx = ((OutputCtx *)initdata)->data;
    thread->output_ctx = CreateEveThreadCtx(tv, thread->flowlog_ctx->eve_ctx);
    if (!thread->output_ctx) {
        goto error_exit;
    }

    *data = (void *)thread;
    return TM_ECODE_OK;

error_exit:
    SCFree(thread);
    return TM_ECODE_FAILED;
}

static TmEcode JsonFlowLogThreadDeInit(ThreadVars *tv, void *data)
{
    LogFlowLogThread *thread = (LogFlowLogThread *)data;
    if (thread == NULL) {
        return TM_ECODE_FAILED;
    }

    FreeEveThreadCtx(thread->output_ctx);
    SCFree(thread);
    return TM_ECODE_OK;
}

static JsonBuilder *CreateEveHeaderFromFlow(const Flow *f)
{
    char timebuf[64];
    char srcip[46] = {0}, dstip[46] = {0};
    Port sp, dp;

    JsonBuilder *jb = jb_new_object();
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
    jb_set_string(jb, "timestamp", timebuf);

    CreateEveFlowId(jb, (const Flow *)f);

#if 0 // TODO
    /* sensor id */
    if (sensor_id >= 0)
        json_object_set_new(js, "sensor_id", json_integer(sensor_id));
#endif

    /* input interface */
    if (f->livedev) {
        jb_set_string(jb, "in_iface", f->livedev->dev);
    }

    JB_SET_STRING(jb, "event_type", "flow");

    /* vlan */
    if (f->vlan_idx > 0) {
        jb_open_array(jb, "vlan");
        jb_append_uint(jb, f->vlan_id[0]);
        if (f->vlan_idx > 1) {
            jb_append_uint(jb, f->vlan_id[1]);
        }
        if (f->vlan_idx > 2) {
            jb_append_uint(jb, f->vlan_id[2]);
        }
        jb_close(jb);
    }

    /* tuple */
    jb_set_string(jb, "src_ip", srcip);
    switch(f->proto) {
        case IPPROTO_ICMP:
            break;
        case IPPROTO_UDP:
        case IPPROTO_TCP:
        case IPPROTO_SCTP:
            jb_set_uint(jb, "src_port", sp);
            break;
    }
    jb_set_string(jb, "dest_ip", dstip);
    switch(f->proto) {
        case IPPROTO_ICMP:
            break;
        case IPPROTO_UDP:
        case IPPROTO_TCP:
        case IPPROTO_SCTP:
            jb_set_uint(jb, "dest_port", dp);
            break;
    }

    if (SCProtoNameValid(f->proto)) {
        jb_set_string(jb, "proto", known_proto[f->proto]);
    } else {
        char proto[4];
        snprintf(proto, sizeof(proto), "%"PRIu8"", f->proto);
        jb_set_string(jb, "proto", proto);
    }

    switch (f->proto) {
        case IPPROTO_ICMP:
        case IPPROTO_ICMPV6:
            jb_set_uint(jb, "icmp_type", f->icmp_s.type);
            jb_set_uint(jb, "icmp_code", f->icmp_s.code);
            if (f->tosrcpktcnt) {
                jb_set_uint(jb, "response_icmp_type", f->icmp_d.type);
                jb_set_uint(jb, "response_icmp_code", f->icmp_d.code);
            }
            break;
        case IPPROTO_ESP:
            jb_set_uint(jb, "spi", f->esp.spi);
            break;
    }
    return jb;
}

void EveAddAppProto(Flow *f, JsonBuilder *js)
{
    if (f->alproto) {
        jb_set_string(js, "app_proto", AppProtoToString(f->alproto));
    }
    if (f->alproto_ts && f->alproto_ts != f->alproto) {
        jb_set_string(js, "app_proto_ts", AppProtoToString(f->alproto_ts));
    }
    if (f->alproto_tc && f->alproto_tc != f->alproto) {
        jb_set_string(js, "app_proto_tc", AppProtoToString(f->alproto_tc));
    }
    if (f->alproto_orig != f->alproto && f->alproto_orig != ALPROTO_UNKNOWN) {
        jb_set_string(js, "app_proto_orig", AppProtoToString(f->alproto_orig));
    }
    if (f->alproto_expect != f->alproto && f->alproto_expect != ALPROTO_UNKNOWN) {
        jb_set_string(js, "app_proto_expected",
                AppProtoToString(f->alproto_expect));
    }

}

void EveAddFlow(Flow *f, JsonBuilder *js)
{
    FlowBypassInfo *fc = FlowGetStorageById(f, GetFlowBypassInfoID());
    if (fc) {
        jb_set_uint(js, "pkts_toserver", f->todstpktcnt + fc->todstpktcnt);
        jb_set_uint(js, "pkts_toclient", f->tosrcpktcnt + fc->tosrcpktcnt);
        jb_set_uint(js, "bytes_toserver", f->todstbytecnt + fc->todstbytecnt);
        jb_set_uint(js, "bytes_toclient", f->tosrcbytecnt + fc->tosrcbytecnt);

        jb_open_object(js, "bypassed");
        jb_set_uint(js, "pkts_toserver", fc->todstpktcnt);
        jb_set_uint(js, "pkts_toclient", fc->tosrcpktcnt);
        jb_set_uint(js, "bytes_toserver", fc->todstbytecnt);
        jb_set_uint(js, "bytes_toclient", fc->tosrcbytecnt);
        jb_close(js);
    } else {
        jb_set_uint(js, "pkts_toserver", f->todstpktcnt);
        jb_set_uint(js, "pkts_toclient", f->tosrcpktcnt);
        jb_set_uint(js, "bytes_toserver", f->todstbytecnt);
        jb_set_uint(js, "bytes_toclient", f->tosrcbytecnt);
    }

    char timebuf1[64];
    CreateIsoTimeString(f->startts, timebuf1, sizeof(timebuf1));
    jb_set_string(js, "start", timebuf1);
}

static void EveExceptionPolicyLog(JsonBuilder *js, uint16_t flag)
{
    if (flag & EXCEPTION_TARGET_FLAG_DEFRAG_MEMCAP) {
        jb_start_object(js);
        jb_set_string(js, "target",
                ExceptionPolicyTargetFlagToString(EXCEPTION_TARGET_FLAG_DEFRAG_MEMCAP));
        jb_set_string(js, "policy",
                ExceptionPolicyEnumToString(
                        ExceptionPolicyTargetPolicy(EXCEPTION_TARGET_FLAG_DEFRAG_MEMCAP), true));
        jb_close(js);
    }
    if (flag & EXCEPTION_TARGET_FLAG_SESSION_MEMCAP) {
        jb_start_object(js);
        jb_set_string(js, "target",
                ExceptionPolicyTargetFlagToString(EXCEPTION_TARGET_FLAG_SESSION_MEMCAP));
        jb_set_string(js, "policy",
                ExceptionPolicyEnumToString(
                        ExceptionPolicyTargetPolicy(EXCEPTION_TARGET_FLAG_SESSION_MEMCAP), true));
        jb_close(js);
    }
    if (flag & EXCEPTION_TARGET_FLAG_REASSEMBLY_MEMCAP) {
        jb_start_object(js);
        jb_set_string(js, "target",
                ExceptionPolicyTargetFlagToString(EXCEPTION_TARGET_FLAG_REASSEMBLY_MEMCAP));
        jb_set_string(js, "policy",
                ExceptionPolicyEnumToString(
                        ExceptionPolicyTargetPolicy(EXCEPTION_TARGET_FLAG_REASSEMBLY_MEMCAP),
                        true));
        jb_close(js);
    }
    if (flag & EXCEPTION_TARGET_FLAG_FLOW_MEMCAP) {
        jb_start_object(js);
        jb_set_string(
                js, "target", ExceptionPolicyTargetFlagToString(EXCEPTION_TARGET_FLAG_FLOW_MEMCAP));
        jb_set_string(js, "policy",
                ExceptionPolicyEnumToString(
                        ExceptionPolicyTargetPolicy(EXCEPTION_TARGET_FLAG_FLOW_MEMCAP), true));
        jb_close(js);
    }
    if (flag & EXCEPTION_TARGET_FLAG_MIDSTREAM) {
        jb_start_object(js);
        jb_set_string(
                js, "target", ExceptionPolicyTargetFlagToString(EXCEPTION_TARGET_FLAG_MIDSTREAM));
        jb_set_string(js, "policy",
                ExceptionPolicyEnumToString(
                        ExceptionPolicyTargetPolicy(EXCEPTION_TARGET_FLAG_MIDSTREAM), true));
        jb_close(js);
    }
    if (flag & EXCEPTION_TARGET_FLAG_APPLAYER_ERROR) {
        jb_start_object(js);
        jb_set_string(js, "target",
                ExceptionPolicyTargetFlagToString(EXCEPTION_TARGET_FLAG_APPLAYER_ERROR));
        jb_set_string(js, "policy",
                ExceptionPolicyEnumToString(
                        ExceptionPolicyTargetPolicy(EXCEPTION_TARGET_FLAG_APPLAYER_ERROR), true));
        jb_close(js);
    }
}

/* Eve format logging */
static void EveFlowLogJSON(LogFlowLogThread *ft, JsonBuilder *jb, Flow *f)
{
    EveAddAppProto(f, jb);
    jb_open_object(jb, "flow");
    EveAddFlow(f, jb);

    char timebuf2[64];
    CreateIsoTimeString(f->lastts, timebuf2, sizeof(timebuf2));
    jb_set_string(jb, "end", timebuf2);

    int32_t age = SCTIME_SECS(f->lastts) - SCTIME_SECS(f->startts);
    jb_set_uint(jb, "age", age);

    if (f->flow_end_flags & FLOW_END_FLAG_EMERGENCY)
        JB_SET_TRUE(jb, "emergency");
    const char *state = NULL;
    if (f->flow_end_flags & FLOW_END_FLAG_STATE_NEW)
        state = "new";
    else if (f->flow_end_flags & FLOW_END_FLAG_STATE_ESTABLISHED)
        state = "established";
    else if (f->flow_end_flags & FLOW_END_FLAG_STATE_CLOSED)
        state = "closed";
    else if (f->flow_end_flags & FLOW_END_FLAG_STATE_BYPASSED) {
        state = "bypassed";
        int flow_state = f->flow_state;
        switch (flow_state) {
            case FLOW_STATE_LOCAL_BYPASSED:
                JB_SET_STRING(jb, "bypass", "local");
                break;
#ifdef CAPTURE_OFFLOAD
            case FLOW_STATE_CAPTURE_BYPASSED:
                JB_SET_STRING(jb, "bypass", "capture");
                break;
#endif
            default:
                SCLogError("Invalid flow state: %d, contact developers", flow_state);
        }
    }

    jb_set_string(jb, "state", state);

    const char *reason = NULL;
    if (f->flow_end_flags & FLOW_END_FLAG_FORCED)
        reason = "forced";
    else if (f->flow_end_flags & FLOW_END_FLAG_SHUTDOWN)
        reason = "shutdown";
    else if (f->flow_end_flags & FLOW_END_FLAG_TIMEOUT)
        reason = "timeout";
    else
        reason = "unknown";

    jb_set_string(jb, "reason", reason);

    jb_set_bool(jb, "alerted", FlowHasAlerts(f));
    if (f->flags & FLOW_WRONG_THREAD)
        JB_SET_TRUE(jb, "wrong_thread");

    if (f->flags & FLOW_ACTION_DROP) {
        JB_SET_STRING(jb, "action", "drop");
    } else if (f->flags & FLOW_ACTION_PASS) {
        JB_SET_STRING(jb, "action", "pass");
    }
    if (f->applied_exception_policy != 0 && ft->flowlog_ctx->log_exception_policies) {
        jb_open_array(jb, "exception_policy");
        EveExceptionPolicyLog(jb, f->applied_exception_policy);
        jb_close(jb); /* close array */
    }

    /* Close flow. */
    jb_close(jb);

    EveAddCommonOptions(&ft->output_ctx->ctx->cfg, NULL, f, jb, LOG_DIR_FLOW);

    /* TCP */
    if (f->proto == IPPROTO_TCP) {
        jb_open_object(jb, "tcp");

        TcpSession *ssn = f->protoctx;

        char hexflags[3];
        snprintf(hexflags, sizeof(hexflags), "%02x",
                ssn ? ssn->tcp_packet_flags : 0);
        jb_set_string(jb, "tcp_flags", hexflags);

        snprintf(hexflags, sizeof(hexflags), "%02x",
                ssn ? ssn->client.tcp_flags : 0);
        jb_set_string(jb, "tcp_flags_ts", hexflags);

        snprintf(hexflags, sizeof(hexflags), "%02x",
                ssn ? ssn->server.tcp_flags : 0);
        jb_set_string(jb, "tcp_flags_tc", hexflags);

        EveTcpFlags(ssn ? ssn->tcp_packet_flags : 0, jb);

        if (ssn) {
            const char *tcp_state = StreamTcpStateAsString(ssn->state);
            if (tcp_state != NULL)
                jb_set_string(jb, "state", tcp_state);
            if (ssn->server.flags & STREAMTCP_STREAM_FLAG_HAS_GAP) {
                JB_SET_TRUE(jb, "tc_gap");
            }
            if (ssn->client.flags & STREAMTCP_STREAM_FLAG_HAS_GAP) {
                JB_SET_TRUE(jb, "ts_gap");
            }

            jb_set_uint(jb, "ts_max_regions", ssn->client.sb.max_regions);
            jb_set_uint(jb, "tc_max_regions", ssn->server.sb.max_regions);

            if (ssn->urg_offset_ts)
                jb_set_uint(jb, "ts_urgent_oob_data", ssn->urg_offset_ts);
            if (ssn->urg_offset_tc)
                jb_set_uint(jb, "tc_urgent_oob_data", ssn->urg_offset_tc);
        }

        /* Close tcp. */
        jb_close(jb);
    }
}

static int JsonFlowLogger(ThreadVars *tv, void *thread_data, Flow *f)
{
    SCEnter();
    LogFlowLogThread *thread = thread_data;

    JsonBuilder *jb = CreateEveHeaderFromFlow(f);
    if (unlikely(jb == NULL)) {
        SCReturnInt(TM_ECODE_OK);
    }

    EveFlowLogJSON(thread, jb, f);

    OutputJsonBuilderBuffer(jb, thread->output_ctx);
    jb_free(jb);

    SCReturnInt(TM_ECODE_OK);
}

void JsonFlowLogRegister (void)
{
    /* register as child of eve-log */
    OutputRegisterFlowSubModule(LOGGER_JSON_FLOW, "eve-log", "JsonFlowLog", "eve-log.flow",
            OutputFlowLogInitSub, JsonFlowLogger, JsonFlowLogThreadInit, JsonFlowLogThreadDeInit,
            NULL);
}
