/**
 * \file
 *
 * \author Angelo Mirabella <mirabellaa@vmware.com>
 *
 * Generate alerts and invoke corresponding callback.
 *
 */

#include "suricata-common.h"

#include "output-callback-alert.h"

#include "action-globals.h"
#include "output.h"
#include "output-callback.h"
#include "output-callback-http.h"
#include "packet.h"
#include "suricata.h"
#include "threadvars.h"

#define MODULE_NAME "CallbackAlertLog"

/* Mock ThreadInit/DeInit methods.
 * Callbacks do not store any per-thread information. */
static TmEcode CallbackAlertLogThreadInit(ThreadVars *t, const void *initdata, void **data)
{
    return TM_ECODE_OK;
}

static TmEcode CallbackAlertLogThreadDeinit(ThreadVars *t, void *data)
{
    return TM_ECODE_OK;
}

static void AlertCallbackHeader(const Packet *p, const PacketAlert *pa, AlertEvent *event)
{
    const char *action = "allowed";
    /* use packet action if rate_filter modified the action */
    if (unlikely(pa->flags & PACKET_ALERT_RATE_FILTER_MODIFIED)) {
        if (PacketCheckAction(p, ACTION_DROP_REJECT)) {
            action = "blocked";
        }
    } else {
        if (pa->action & ACTION_REJECT_ANY) {
            action = "blocked";
        } else if ((pa->action & ACTION_DROP) && EngineModeIsIPS()) {
            action = "blocked";
        }
    }

    event->alert.action = action;
    event->alert.sid = pa->s->id;
    event->alert.gid = pa->s->gid;
    event->alert.rev = pa->s->rev;
    event->alert.msg = pa->s->msg ? pa->s->msg : "";
    event->alert.category = pa->s->class_msg ? pa->s->class_msg : "";
    event->alert.severity = pa->s->prio;

    /* TODO: AlertJsonSourceTarget ? */

    if (pa->s->metadata && pa->s->metadata->json_str) {
        event->alert.metadata = pa->s->metadata->json_str;
    }
}

static void AlertAddAppLayer(const Packet *p, const uint64_t tx_id, AlertEvent *event)
{
    const AppProto proto = FlowGetAppProtocol(p->flow);
    switch (proto) {
        case ALPROTO_HTTP:;
            HttpInfo *http = SCCalloc(1, sizeof(HttpInfo));
            if (http && CallbackHttpAddMetadata(p->flow, tx_id, http)) {
                event->app_layer.http = http;
            }
            break;
        default:
            break;
    }
}

static void AlertCleanupAppLayer(const Packet *p, const uint64_t tx_id, AlertEvent *event)
{
    const AppProto proto = FlowGetAppProtocol(p->flow);
    switch (proto) {
        case ALPROTO_HTTP:;
            if (event->app_layer.http) {
                CallbackHttpCleanupInfo(event->app_layer.http);
                SCFree(event->app_layer.http);
            }
            break;
        default:
            break;
    }
}

static int AlertCallback(ThreadVars *tv, const Packet *p)
{
    if (p->alerts.cnt == 0) {
        return TM_ECODE_OK;
    }

    for (int i = 0; i < p->alerts.cnt; i++) {
        const PacketAlert *pa = &p->alerts.alerts[i];

        if (unlikely(pa->s == NULL)) {
            continue;
        }

        AlertEvent event = { .common = {} };
        EventAddCommonInfo(p, LOG_DIR_PACKET, &event.common);

        /* TODO: Add metadata (flowvars, pktvars)? */

        /* Alert */
        AlertCallbackHeader(p, pa, &event);

        /* TODO: Add tunnel info? */

        if (p->flow != NULL) {
            AlertAddAppLayer(p, pa->tx_id, &event);

            /* TODO: Add file info? */

            /* TODO: Add flow info? */
        }

        /* Invoke callback and cleanup */
        tv->callbacks->alert.func(tv->callbacks->alert.user_ctx, &event);
        AlertCleanupAppLayer(p, pa->tx_id, &event);
    }

    return TM_ECODE_OK;
}

static int AlertCallbackDecoderEvent(ThreadVars *tv, const Packet *p)
{
    if (p->alerts.cnt == 0)
        return TM_ECODE_OK;

    for (int i = 0; i < p->alerts.cnt; i++) {
        const PacketAlert *pa = &p->alerts.alerts[i];
        if (unlikely(pa->s == NULL)) {
            continue;
        }

        AlertEvent event;

        /* Alert timestamp. */
        CreateIsoTimeString(p->ts, event.common.timestamp, sizeof(event.common.timestamp));

        AlertCallbackHeader(p, pa, &event);

        /* Invoke callback */
        tv->callbacks->alert.func(tv->callbacks->alert.user_ctx, &event);
    }

    return TM_ECODE_OK;
}

static int CallbackAlertLogger(ThreadVars *tv, void *thread_data, const Packet *p)
{
    if (PKT_IS_IPV4(p) || PKT_IS_IPV6(p)) {
        return AlertCallback(tv, p);
    } else if (p->alerts.cnt > 0) {
        return AlertCallbackDecoderEvent(tv, p);
    }
    return 0;
}

static int CallbackAlertLogCondition(ThreadVars *tv, void *thread_data, const Packet *p)
{
    if ((p->alerts.cnt || p->flags & PKT_HAS_TAG) && tv->callbacks && tv->callbacks->alert.func) {
        return TRUE;
    }
    return FALSE;
}

void CallbackAlertLogRegister(void)
{
    OutputRegisterPacketSubModule(LOGGER_CALLBACK_ALERT, "", MODULE_NAME, "", NULL,
            CallbackAlertLogger, CallbackAlertLogCondition, CallbackAlertLogThreadInit,
            CallbackAlertLogThreadDeinit, NULL);
}
