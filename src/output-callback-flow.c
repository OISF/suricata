/**
 * \file
 *
 * \author Angelo Mirabella <mirabellaa@vmware.com>
 *
 * Generate flow events and invoke corresponding callback.
 *
 */

#include "suricata-common.h"

#include "output-callback-flow.h"

#include "output.h"
#include "output-callback.h"
#include "stream-tcp.h"
#include "stream-tcp-private.h"
#include "threadvars.h"
#include "util-device.h"
#include "util-proto-name.h"
#include "util-print.h"
#include "util-storage.h"

#define MODULE_NAME "CallbackFlowLog"

typedef struct CallbackFlowCtx {
    OutputCallbackCommonSettings cfg;
} CallbackFlowCtx;

typedef struct CallbackFlowLogThread {
    CallbackFlowCtx *flowlog_ctx;
} CallbackFlowLogThread;


static void CallbackFlowDeinitSub(OutputCtx *output_ctx) {
    CallbackFlowCtx *flow_ctx = output_ctx->data;

    SCFree(flow_ctx);
    SCFree(output_ctx);
}

static OutputInitResult CallbackFlowInitSub(ConfNode *conf, OutputCtx *parent_ctx) {
    OutputInitResult result = {NULL, false};
    OutputCallbackCtx *occ = parent_ctx->data;

    CallbackFlowCtx *flow_ctx = SCCalloc(1, sizeof(CallbackFlowCtx));
    if (unlikely(flow_ctx == NULL)) {
        return result;
    }
    flow_ctx->cfg = occ->cfg;

    OutputCtx *output_ctx = SCCalloc(1, sizeof(OutputCtx));
    if (unlikely(output_ctx == NULL)) {
        SCFree(flow_ctx);
        return result;
    }

    output_ctx->data = flow_ctx;
    output_ctx->DeInit = CallbackFlowDeinitSub;

    result.ctx = output_ctx;
    result.ok = true;
    return result;
}

/* Mock ThreadInit/DeInit methods.
 * Callbacks do not store any per-thread information. */
static TmEcode CallbackFlowLogThreadInit(ThreadVars *t, const void *initdata, void **data) {
    CallbackFlowLogThread *aft = SCCalloc(1, sizeof(CallbackFlowLogThread));
    if (unlikely(aft == NULL)) {
        return TM_ECODE_FAILED;
    }

    if (initdata == NULL) {
        SCLogDebug("Error getting context for CallbackFlowLog. \"initdata\" argument NULL");
        SCFree(aft);
        return TM_ECODE_FAILED;
    }

    aft->flowlog_ctx = ((OutputCtx *)initdata)->data;
    *data = (void *)aft;
    return TM_ECODE_OK;
}

static TmEcode CallbackFlowLogThreadDeinit(ThreadVars *t, void *data) {
    CallbackFlowLogThread *aft = (CallbackFlowLogThread *)data;
    if (aft == NULL) {
        return TM_ECODE_OK;
    }

    /* clear memory */
    memset(aft, 0, sizeof(CallbackFlowLogThread));

    SCFree(aft);
    return TM_ECODE_OK;
}

/* Create a flow event object from a flow. */
void CallbackFlowLog(const Flow *f, FlowInfo *flow) {
    /* Counters. */
    /* TODO: support bypassed flows ? */
    flow->pkts_toserver = f->todstpktcnt;
    flow->pkts_toclient = f->tosrcpktcnt;
    flow->bytes_toserver = f->todstbytecnt;
    flow->bytes_toclient = f->tosrcbytecnt;

    /* Timestamps. */
    CreateIsoTimeString(f->startts, flow->start, sizeof(flow->start));
    CreateIsoTimeString(f->lastts, flow->end, sizeof(flow->end));

    /* Age. */
    flow->age = SCTIME_SECS(f->lastts) - SCTIME_SECS(f->startts);

    /* Emergency flag. */
    flow->emergency = f->flow_end_flags & FLOW_END_FLAG_EMERGENCY;

    /* State. */
    if (f->flow_end_flags & FLOW_END_FLAG_STATE_NEW)
        flow->state = "new";
    else if (f->flow_end_flags & FLOW_END_FLAG_STATE_ESTABLISHED)
        flow->state = "established";
    else if (f->flow_end_flags & FLOW_END_FLAG_STATE_CLOSED)
        flow->state = "closed";
    else if (f->flow_end_flags & FLOW_END_FLAG_STATE_BYPASSED) {
        flow->state = "bypassed";
        int flow_state = f->flow_state;
        switch (flow_state) {
            case FLOW_STATE_LOCAL_BYPASSED:
                flow->bypass = "local";
                break;
#ifdef CAPTURE_OFFLOAD
            case FLOW_STATE_CAPTURE_BYPASSED:
                flow->bypass = "capture";
                break;
#endif
            default:
                SCLogError("Invalid flow state: %d, contact developers", flow_state);
        }
    }

    /* TODO: do we support flow bypass? */

    if (f->flow_end_flags & FLOW_END_FLAG_FORCED)
        flow->reason = "forced";
    else if (f->flow_end_flags & FLOW_END_FLAG_SHUTDOWN)
        flow->reason = "shutdown";
    else if (f->flow_end_flags & FLOW_END_FLAG_TIMEOUT)
        flow->reason = "timeout";
    else
        flow->reason = "unknown";

    /* If flow has alerts. */
    flow->alerted = FlowHasAlerts(f);

    if (f->flags & FLOW_ACTION_DROP) {
        flow->action = "drop";
    } else if (f->flags & FLOW_ACTION_PASS) {
        flow->action = "pass";
    }

    /* TODO: Add metadata (flowvars, pktvars)? */

    /* TCP */
    if (f->proto == IPPROTO_TCP) {
        TcpSession *ssn = f->protoctx;

        snprintf(flow->tcp.tcp_flags, sizeof(flow->tcp.tcp_flags), "%02x",
                 ssn ? ssn->tcp_packet_flags : 0);
        snprintf(flow->tcp.tcp_flags_ts, sizeof(flow->tcp.tcp_flags_ts), "%02x",
                 ssn ? ssn->client.tcp_flags : 0);
        snprintf(flow->tcp.tcp_flags_tc, sizeof(flow->tcp.tcp_flags_tc), "%02x",
                 ssn ? ssn->server.tcp_flags : 0);

        if (ssn) {
            /* TCP flags. */
            if (ssn->tcp_packet_flags & TH_SYN) {
                flow->tcp.syn = true;
            }
            if (ssn->tcp_packet_flags & TH_FIN) {
                flow->tcp.fin = true;
            }
            if (ssn->tcp_packet_flags & TH_RST) {
                flow->tcp.rst = true;
            }
            if (ssn->tcp_packet_flags & TH_PUSH) {
                flow->tcp.psh = true;
            }
            if (ssn->tcp_packet_flags & TH_ACK) {
                flow->tcp.ack = true;
            }
            if (ssn->tcp_packet_flags & TH_URG) {
                flow->tcp.urg = true;
            }
            if (ssn->tcp_packet_flags & TH_ECN) {
                flow->tcp.ecn = true;
            }
            if (ssn->tcp_packet_flags & TH_CWR) {
                flow->tcp.cwr = true;
            }

            flow->tcp.state = StreamTcpStateAsString(ssn->state);
        }
    }
}

static int CallbackFlowLogger(ThreadVars *tv, void *thread_data, Flow *f) {
    CallbackFlowLogThread *aft = (CallbackFlowLogThread *)thread_data;
    CallbackFlowCtx *ctx = aft->flowlog_ctx;

    if (!tv->callbacks->flow) {
        return 0;
    }

    FlowEvent event = {};
    JsonAddrInfo addr = json_addr_info_zero;

    EventAddCommonInfoFromFlow(f, &event.common, &addr, &ctx->cfg);
    CallbackFlowLog(f, &event.flow);

    /* Invoke callback. */
    tv->callbacks->flow(&event, f->tenant_uuid, f->user_ctx);

    return 0;
}

void CallbackFlowLogRegister(void) {
    OutputRegisterFlowSubModule(LOGGER_CALLBACK_FLOW, "callback", MODULE_NAME, "callback.flow",
                                CallbackFlowInitSub, CallbackFlowLogger,
                                CallbackFlowLogThreadInit, CallbackFlowLogThreadDeinit, NULL);
}
