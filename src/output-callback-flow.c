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
#include "threadvars.h"
#include "util-device.h"
#include "util-proto-name.h"
#include "util-print.h"
#include "util-storage.h"

#define MODULE_NAME "CallbackFlowLog"


/* Mock ThreadInit/DeInit methods.
 * Callbacks do not store any per-thread information. */
static TmEcode CallbackFlowLogThreadInit(ThreadVars *t, const void *initdata, void **data) {
    return TM_ECODE_OK;
}

static TmEcode CallbackFlowLogThreadDeinit(ThreadVars *t, void *data) {
    return TM_ECODE_OK;
}

/* Create a flow event object from a flow. */
void CallbackFlowLog(const Flow *f, FlowInfo *flow) {
    /* Input interface. */
    if (f->livedev) {
        flow->dev = f->livedev->dev;
    }

    /* Vlan. */
    if (f->vlan_idx > 0) {
        flow->vlan_id[0] = f->vlan_id[0];
        if (f->vlan_idx > 1) {
            flow->vlan_id[0] = f->vlan_id[1];
        }
    }

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

    /* TODO: Add metadata (flowvars, pktvars)? */

    /* TODO: do we want TCP flags and state? */
}

static int CallbackFlowLogger(ThreadVars *tv, void *thread_data, Flow *f) {
    if (!tv->callbacks->flow) {
        return 0;
    }

    FlowEvent event = {};
    JsonAddrInfo addr = json_addr_info_zero;

    EventAddCommonInfoFromFlow(f, &event.common, &addr);
    CallbackFlowLog(f, &event.flow);

    /* Invoke callback. */
    tv->callbacks->flow(&event, f->tenant_uuid, f->user_ctx);

    return 0;
}

void CallbackFlowLogRegister(void) {
    OutputRegisterFlowSubModule(LOGGER_CALLBACK_FLOW, "callback", MODULE_NAME, "callback.flow",
                                NULL, CallbackFlowLogger, CallbackFlowLogThreadInit,
                                CallbackFlowLogThreadDeinit, NULL);
}
