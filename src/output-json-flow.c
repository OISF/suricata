/* Copyright (C) 2007-2013 Open Information Security Foundation
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
#include "debug.h"
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
#include "util-proto-name.h"
#include "util-logopenfile.h"
#include "util-time.h"
#include "output-json.h"
#include "output-json-flow.h"

#include "stream-tcp-private.h"

#ifdef HAVE_LIBJANSSON

typedef struct LogJsonFileCtx_ {
    LogFileCtx *file_ctx;
    uint32_t flags; /** Store mode */
} LogJsonFileCtx;

typedef struct JsonFlowLogThread_ {
    LogJsonFileCtx *flowlog_ctx;
    /** LogFileCtx has the pointer to the file and a mutex to allow multithreading */
    uint32_t uri_cnt;

    MemBuffer *buffer;
} JsonFlowLogThread;


#define LOG_HTTP_DEFAULT 0
#define LOG_HTTP_EXTENDED 1
#define LOG_HTTP_CUSTOM 2

static json_t *CreateJSONHeaderFromFlow(Flow *f, const char *event_type)
{
    char timebuf[64];
    char srcip[46], dstip[46];
    Port sp, dp;

    json_t *js = json_object();
    if (unlikely(js == NULL))
        return NULL;

    struct timeval tv;
    memset(&tv, 0x00, sizeof(tv));
    TimeGet(&tv);

    CreateIsoTimeString(&tv, timebuf, sizeof(timebuf));

    srcip[0] = '\0';
    dstip[0] = '\0';
    if (FLOW_IS_IPV4(f)) {
        PrintInet(AF_INET, (const void *)&(f->src.addr_data32[0]), srcip, sizeof(srcip));
        PrintInet(AF_INET, (const void *)&(f->dst.addr_data32[0]), dstip, sizeof(dstip));
    } else if (FLOW_IS_IPV6(f)) {
        PrintInet(AF_INET6, (const void *)&(f->src.address), srcip, sizeof(srcip));
        PrintInet(AF_INET6, (const void *)&(f->dst.address), dstip, sizeof(dstip));
    }

    sp = f->sp;
    dp = f->dp;

    char proto[16];
    if (SCProtoNameValid(f->proto) == TRUE) {
        strlcpy(proto, known_proto[f->proto], sizeof(proto));
    } else {
        snprintf(proto, sizeof(proto), "%03" PRIu32, f->proto);
    }

    /* time */
    json_object_set_new(js, "timestamp", json_string(timebuf));

    CreateJSONFlowId(js, (const Flow *)f);

#if 0 // TODO
    /* sensor id */
    if (sensor_id >= 0)
        json_object_set_new(js, "sensor_id", json_integer(sensor_id));
#endif
    if (event_type) {
        json_object_set_new(js, "event_type", json_string(event_type));
    }
#if 0
    /* vlan */
    if (f->vlan_id[0] > 0) {
        json_t *js_vlan;
        switch (f->vlan_idx) {
            case 1:
                json_object_set_new(js, "vlan",
                                    json_integer(f->vlan_id[0]));
                break;
            case 2:
                js_vlan = json_array();
                if (unlikely(js != NULL)) {
                    json_array_append_new(js_vlan,
                                    json_integer(VLAN_GET_ID1(p)));
                    json_array_append_new(js_vlan,
                                    json_integer(VLAN_GET_ID2(p)));
                    json_object_set_new(js, "vlan", js_vlan);
                }
                break;
            default:
                /* shouldn't get here */
                break;
        }
    }
#endif
    /* tuple */
    json_object_set_new(js, "src_ip", json_string(srcip));
    switch(f->proto) {
        case IPPROTO_ICMP:
            break;
        case IPPROTO_UDP:
        case IPPROTO_TCP:
        case IPPROTO_SCTP:
            json_object_set_new(js, "src_port", json_integer(sp));
            break;
    }
    json_object_set_new(js, "dest_ip", json_string(dstip));
    switch(f->proto) {
        case IPPROTO_ICMP:
            break;
        case IPPROTO_UDP:
        case IPPROTO_TCP:
        case IPPROTO_SCTP:
            json_object_set_new(js, "dest_port", json_integer(dp));
            break;
    }
    json_object_set_new(js, "proto", json_string(proto));
    switch (f->proto) {
        case IPPROTO_ICMP:
        case IPPROTO_ICMPV6:
            json_object_set_new(js, "icmp_type",
                    json_integer(f->type));
            json_object_set_new(js, "icmp_code",
                    json_integer(f->code));
            break;
    }
    return js;
}

void JsonAddFlow(Flow *f, json_t *js, json_t *hjs)
{
    json_object_set_new(js, "app_proto",
            json_string(AppProtoToString(f->alproto)));
    if (f->alproto_ts != f->alproto) {
        json_object_set_new(js, "app_proto_ts",
                json_string(AppProtoToString(f->alproto_ts)));
    }
    if (f->alproto_tc != f->alproto) {
        json_object_set_new(js, "app_proto_tc",
                json_string(AppProtoToString(f->alproto_tc)));
    }
    if (f->alproto_orig != f->alproto && f->alproto_orig != ALPROTO_UNKNOWN) {
        json_object_set_new(js, "app_proto_orig",
                json_string(AppProtoToString(f->alproto_orig)));
    }
    if (f->alproto_expect != f->alproto && f->alproto_expect != ALPROTO_UNKNOWN) {
        json_object_set_new(js, "app_proto_expected",
                json_string(AppProtoToString(f->alproto_expect)));
    }

    json_object_set_new(hjs, "pkts_toserver",
            json_integer(f->todstpktcnt));
    json_object_set_new(hjs, "pkts_toclient",
            json_integer(f->tosrcpktcnt));
    json_object_set_new(hjs, "bytes_toserver",
            json_integer(f->todstbytecnt));
    json_object_set_new(hjs, "bytes_toclient",
            json_integer(f->tosrcbytecnt));

    char timebuf1[64];
    CreateIsoTimeString(&f->startts, timebuf1, sizeof(timebuf1));
    json_object_set_new(hjs, "start", json_string(timebuf1));
}

/* JSON format logging */
static void JsonFlowLogJSON(JsonFlowLogThread *aft, json_t *js, Flow *f)
{
#if 0
    LogJsonFileCtx *flow_ctx = aft->flowlog_ctx;
#endif
    json_t *hjs = json_object();
    if (hjs == NULL) {
        return;
    }

    JsonAddFlow(f, js, hjs);

    char timebuf2[64];
    CreateIsoTimeString(&f->lastts, timebuf2, sizeof(timebuf2));
    json_object_set_new(hjs, "end", json_string(timebuf2));

    int32_t age = f->lastts.tv_sec - f->startts.tv_sec;
    json_object_set_new(hjs, "age",
            json_integer(age));

    if (f->flow_end_flags & FLOW_END_FLAG_EMERGENCY)
        json_object_set_new(hjs, "emergency", json_true());
    const char *state = NULL;
    if (f->flow_end_flags & FLOW_END_FLAG_STATE_NEW)
        state = "new";
    else if (f->flow_end_flags & FLOW_END_FLAG_STATE_ESTABLISHED)
        state = "established";
    else if (f->flow_end_flags & FLOW_END_FLAG_STATE_CLOSED)
        state = "closed";
    else if (f->flow_end_flags & FLOW_END_FLAG_STATE_BYPASSED) {
        state = "bypassed";
        int flow_state = SC_ATOMIC_GET(f->flow_state);
        switch (flow_state) {
            case FLOW_STATE_LOCAL_BYPASSED:
                json_object_set_new(hjs, "bypass",
                        json_string("local"));
                break;
            case FLOW_STATE_CAPTURE_BYPASSED:
                json_object_set_new(hjs, "bypass",
                        json_string("capture"));
                break;
            default:
                SCLogError(SC_ERR_INVALID_VALUE,
                           "Invalid flow state: %d, contact developers",
                           flow_state);
        }
    }

    json_object_set_new(hjs, "state",
            json_string(state));

    const char *reason = NULL;
    if (f->flow_end_flags & FLOW_END_FLAG_TIMEOUT)
        reason = "timeout";
    else if (f->flow_end_flags & FLOW_END_FLAG_FORCED)
        reason = "forced";
    else if (f->flow_end_flags & FLOW_END_FLAG_SHUTDOWN)
        reason = "shutdown";

    json_object_set_new(hjs, "reason",
            json_string(reason));

    json_object_set_new(hjs, "alerted", json_boolean(FlowHasAlerts(f)));

    json_object_set_new(js, "flow", hjs);


    /* TCP */
    if (f->proto == IPPROTO_TCP) {
        json_t *tjs = json_object();
        if (tjs == NULL) {
            return;
        }

        TcpSession *ssn = f->protoctx;

        char hexflags[3];
        snprintf(hexflags, sizeof(hexflags), "%02x",
                ssn ? ssn->tcp_packet_flags : 0);
        json_object_set_new(tjs, "tcp_flags", json_string(hexflags));

        snprintf(hexflags, sizeof(hexflags), "%02x",
                ssn ? ssn->client.tcp_flags : 0);
        json_object_set_new(tjs, "tcp_flags_ts", json_string(hexflags));

        snprintf(hexflags, sizeof(hexflags), "%02x",
                ssn ? ssn->server.tcp_flags : 0);
        json_object_set_new(tjs, "tcp_flags_tc", json_string(hexflags));

        JsonTcpFlags(ssn ? ssn->tcp_packet_flags : 0, tjs);

        if (ssn) {
            const char *tcp_state = NULL;
            switch (ssn->state) {
                case TCP_NONE:
                    tcp_state = "none";
                    break;
                case TCP_LISTEN:
                    tcp_state = "listen";
                    break;
                case TCP_SYN_SENT:
                    tcp_state = "syn_sent";
                    break;
                case TCP_SYN_RECV:
                    tcp_state = "syn_recv";
                    break;
                case TCP_ESTABLISHED:
                    tcp_state = "established";
                    break;
                case TCP_FIN_WAIT1:
                    tcp_state = "fin_wait1";
                    break;
                case TCP_FIN_WAIT2:
                    tcp_state = "fin_wait2";
                    break;
                case TCP_TIME_WAIT:
                    tcp_state = "time_wait";
                    break;
                case TCP_LAST_ACK:
                    tcp_state = "last_ack";
                    break;
                case TCP_CLOSE_WAIT:
                    tcp_state = "close_wait";
                    break;
                case TCP_CLOSING:
                    tcp_state = "closing";
                    break;
                case TCP_CLOSED:
                    tcp_state = "closed";
                    break;
            }
            json_object_set_new(tjs, "state", json_string(tcp_state));
        }

        json_object_set_new(js, "tcp", tjs);
    }
}

static int JsonFlowLogger(ThreadVars *tv, void *thread_data, Flow *f)
{
    SCEnter();
    JsonFlowLogThread *jhl = (JsonFlowLogThread *)thread_data;

    /* reset */
    MemBufferReset(jhl->buffer);

    json_t *js = CreateJSONHeaderFromFlow(f, "flow"); //TODO const
    if (unlikely(js == NULL))
        return TM_ECODE_OK;

    JsonFlowLogJSON(jhl, js, f);

    OutputJSONBuffer(js, jhl->flowlog_ctx->file_ctx, &jhl->buffer);
    json_object_del(js, "http");

    json_object_clear(js);
    json_decref(js);

    SCReturnInt(TM_ECODE_OK);
}

static void OutputFlowLogDeinit(OutputCtx *output_ctx)
{
    LogJsonFileCtx *flow_ctx = output_ctx->data;
    LogFileCtx *logfile_ctx = flow_ctx->file_ctx;
    LogFileFreeCtx(logfile_ctx);
    SCFree(flow_ctx);
    SCFree(output_ctx);
}

#define DEFAULT_LOG_FILENAME "flow.json"
static OutputCtx *OutputFlowLogInit(ConfNode *conf)
{
    SCLogInfo("hi");
    LogFileCtx *file_ctx = LogFileNewCtx();
    if(file_ctx == NULL) {
        SCLogError(SC_ERR_FLOW_LOG_GENERIC, "couldn't create new file_ctx");
        return NULL;
    }

    if (SCConfLogOpenGeneric(conf, file_ctx, DEFAULT_LOG_FILENAME, 1) < 0) {
        LogFileFreeCtx(file_ctx);
        return NULL;
    }

    LogJsonFileCtx *flow_ctx = SCMalloc(sizeof(LogJsonFileCtx));
    if (unlikely(flow_ctx == NULL)) {
        LogFileFreeCtx(file_ctx);
        return NULL;
    }

    OutputCtx *output_ctx = SCCalloc(1, sizeof(OutputCtx));
    if (unlikely(output_ctx == NULL)) {
        LogFileFreeCtx(file_ctx);
        SCFree(flow_ctx);
        return NULL;
    }

    flow_ctx->file_ctx = file_ctx;
    output_ctx->data = flow_ctx;
    output_ctx->DeInit = OutputFlowLogDeinit;

    return output_ctx;
}

static void OutputFlowLogDeinitSub(OutputCtx *output_ctx)
{
    LogJsonFileCtx *flow_ctx = output_ctx->data;
    SCFree(flow_ctx);
    SCFree(output_ctx);
}

static OutputCtx *OutputFlowLogInitSub(ConfNode *conf, OutputCtx *parent_ctx)
{
    OutputJsonCtx *ojc = parent_ctx->data;

    LogJsonFileCtx *flow_ctx = SCMalloc(sizeof(LogJsonFileCtx));
    if (unlikely(flow_ctx == NULL))
        return NULL;

    OutputCtx *output_ctx = SCCalloc(1, sizeof(OutputCtx));
    if (unlikely(output_ctx == NULL)) {
        SCFree(flow_ctx);
        return NULL;
    }

    flow_ctx->file_ctx = ojc->file_ctx;
    flow_ctx->flags = LOG_HTTP_DEFAULT;

    output_ctx->data = flow_ctx;
    output_ctx->DeInit = OutputFlowLogDeinitSub;

    return output_ctx;
}

#define OUTPUT_BUFFER_SIZE 65535
static TmEcode JsonFlowLogThreadInit(ThreadVars *t, const void *initdata, void **data)
{
    JsonFlowLogThread *aft = SCMalloc(sizeof(JsonFlowLogThread));
    if (unlikely(aft == NULL))
        return TM_ECODE_FAILED;
    memset(aft, 0, sizeof(JsonFlowLogThread));

    if(initdata == NULL)
    {
        SCLogDebug("Error getting context for EveLogFlow.  \"initdata\" argument NULL");
        SCFree(aft);
        return TM_ECODE_FAILED;
    }

    /* Use the Ouptut Context (file pointer and mutex) */
    aft->flowlog_ctx = ((OutputCtx *)initdata)->data; //TODO

    aft->buffer = MemBufferCreateNew(OUTPUT_BUFFER_SIZE);
    if (aft->buffer == NULL) {
        SCFree(aft);
        return TM_ECODE_FAILED;
    }

    *data = (void *)aft;
    return TM_ECODE_OK;
}

static TmEcode JsonFlowLogThreadDeinit(ThreadVars *t, void *data)
{
    JsonFlowLogThread *aft = (JsonFlowLogThread *)data;
    if (aft == NULL) {
        return TM_ECODE_OK;
    }

    MemBufferFree(aft->buffer);
    /* clear memory */
    memset(aft, 0, sizeof(JsonFlowLogThread));

    SCFree(aft);
    return TM_ECODE_OK;
}

void JsonFlowLogRegister (void)
{
    /* register as separate module */
    OutputRegisterFlowModule(LOGGER_JSON_FLOW, "JsonFlowLog", "flow-json-log",
        OutputFlowLogInit, JsonFlowLogger, JsonFlowLogThreadInit,
        JsonFlowLogThreadDeinit, NULL);

    /* also register as child of eve-log */
    OutputRegisterFlowSubModule(LOGGER_JSON_FLOW, "eve-log", "JsonFlowLog",
        "eve-log.flow", OutputFlowLogInitSub, JsonFlowLogger,
        JsonFlowLogThreadInit, JsonFlowLogThreadDeinit, NULL);
}

#else

void JsonFlowLogRegister (void)
{
}

#endif
