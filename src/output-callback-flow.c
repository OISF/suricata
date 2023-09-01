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
static TmEcode CallbackFlowLogThreadInit(ThreadVars *t, const void *initdata, void **data)
{
    return TM_ECODE_OK;
}

static TmEcode CallbackFlowLogThreadDeinit(ThreadVars *t, void *data)
{
    return TM_ECODE_OK;
}

static void AddCommonInfoFromFlow(const Flow *f, FlowEvent *event)
{
    char srcip[46] = { 0 }, dstip[46] = { 0 };
    Port sp, dp;

    SCTime_t ts = TimeGet();

    CreateIsoTimeString(ts, event->common.timestamp, sizeof(event->common.timestamp));

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

    /* Tuple */
    event->common.src_ip = SCStrdup(srcip);
    switch (f->proto) {
        case IPPROTO_ICMP:
            break;
        case IPPROTO_UDP:
        case IPPROTO_TCP:
        case IPPROTO_SCTP:
            event->common.sp = sp;
            break;
    }
    event->common.dst_ip = SCStrdup(dstip);
    switch (f->proto) {
        case IPPROTO_ICMP:
            break;
        case IPPROTO_UDP:
        case IPPROTO_TCP:
        case IPPROTO_SCTP:
            event->common.dp = dp;
            break;
    }

    /* Transport layer protocol. */
    event->common.proto = SCProtoNameValid(f->proto) ? known_proto[f->proto] : "unknown";

    /* TODO: do we care about ICMP codes? */

    /* App layer protocol. */
    if (f->alproto) {
        event->common.app_proto = AppProtoToString(f->alproto);
    }
}

static void CallbackFlowLog(const Flow *f, FlowEvent *event)
{
    /* Flow and parent ids. */
    int64_t flow_id = FlowGetId(f);
    event->flow.flow_id = flow_id;
    if (f->parent_id) {
        event->flow.parent_id = f->parent_id;
    }

    /* Input interface. */
    if (f->livedev) {
        event->flow.dev = f->livedev->dev;
    }

    /* Vlan. */
    if (f->vlan_idx > 0) {
        event->flow.vlan_id[0] = f->vlan_id[0];
        if (f->vlan_idx > 1) {
            event->flow.vlan_id[0] = f->vlan_id[1];
        }
    }

    /* Counters. */
    /* TODO: support bypassed flows ? */
    event->flow.pkts_toserver = f->todstpktcnt;
    event->flow.pkts_toclient = f->tosrcpktcnt;
    event->flow.bytes_toserver = f->todstbytecnt;
    event->flow.bytes_toclient = f->tosrcbytecnt;

    /* Timestamps. */
    CreateIsoTimeString(f->startts, event->flow.start, sizeof(event->flow.start));
    CreateIsoTimeString(f->lastts, event->flow.end, sizeof(event->flow.end));

    /* Age. */
    event->flow.age = SCTIME_SECS(f->lastts) - SCTIME_SECS(f->startts);

    /* Emergency flag. */
    event->flow.emergency = f->flow_end_flags & FLOW_END_FLAG_EMERGENCY;

    /* State. */
    if (f->flow_end_flags & FLOW_END_FLAG_STATE_NEW)
        event->flow.state = "new";
    else if (f->flow_end_flags & FLOW_END_FLAG_STATE_ESTABLISHED)
        event->flow.state = "established";
    else if (f->flow_end_flags & FLOW_END_FLAG_STATE_CLOSED)
        event->flow.state = "closed";

    /* TODO: do we support flow bypass? */

    if (f->flow_end_flags & FLOW_END_FLAG_FORCED)
        event->flow.reason = "forced";
    else if (f->flow_end_flags & FLOW_END_FLAG_SHUTDOWN)
        event->flow.reason = "shutdown";
    else if (f->flow_end_flags & FLOW_END_FLAG_TIMEOUT)
        event->flow.reason = "timeout";
    else
        event->flow.reason = "unknown";

    /* If flow has alerts. */
    event->flow.alerted = FlowHasAlerts(f);

    /* TODO: Add metadata (flowvars, pktvars)? */

    /* TODO: do we want TCP flags and state? */
}

static int CallbackFlowLogger(ThreadVars *tv, void *thread_data, Flow *f)
{
    if (!tv->callbacks || !tv->callbacks->flow.func) {
        return 0;
    }

    FlowEvent event = { .common = {} };

    AddCommonInfoFromFlow(f, &event);
    CallbackFlowLog(f, &event);

    /* Invoke callback. */
    tv->callbacks->flow.func(tv->callbacks->flow.user_ctx, &event);

    return 0;
}

void CallbackFlowLogRegister(void)
{
    OutputRegisterFlowSubModule(LOGGER_CALLBACK_FLOW, "", MODULE_NAME, "", NULL, CallbackFlowLogger,
            CallbackFlowLogThreadInit, CallbackFlowLogThreadDeinit, NULL);
}
