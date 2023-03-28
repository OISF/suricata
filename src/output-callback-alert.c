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
static TmEcode CallbackAlertLogThreadInit(ThreadVars *t, const void *initdata, void **data) {
    return TM_ECODE_OK;
}

static TmEcode CallbackAlertLogThreadDeinit(ThreadVars *t, void *data) {
    return TM_ECODE_OK;
}

void AlertCallbackHeader(const Packet *p, const PacketAlert *pa, Alert *alert) {
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

    alert->action = action;
    alert->sid = pa->s->id;
    alert->gid = pa->s->gid;
    alert->rev = pa->s->rev;
    alert->msg = pa->s->msg ? pa->s->msg: "";
    alert->category = pa->s->class_msg ? pa->s->class_msg: "";
    alert->severity = pa->s->prio;

    /* TODO: AlertJsonSourceTarget ? */

    if (pa->s->metadata && pa->s->metadata->json_str) {
        alert->metadata = pa->s->metadata->json_str;
    }
}

static int AlertCallback(ThreadVars *tv, const Packet *p) {
    if (p->alerts.cnt == 0) {
        return TM_ECODE_OK;
    }

    for (int i = 0; i < p->alerts.cnt; i++) {
        const PacketAlert *pa = &p->alerts.alerts[i];

        if (unlikely(pa->s == NULL)) {
            continue;
        }

        AlertEvent event = {};
        JsonAddrInfo addr = json_addr_info_zero;
        EventAddCommonInfo(p, LOG_DIR_PACKET, &event.common, &addr);

        /* TODO: Add metadata (flowvars, pktvars)? */

        /* Alert */
        AlertCallbackHeader(p, pa, &event.alert);

        /* TODO: Add tunnel info? */

        if (p->flow != NULL) {
            CallbackAddAppLayer(p, pa->tx_id, &event.app_layer);

            /* TODO: Add file info? */

            /* TODO: Add flow info? */
        }

        /* Invoke callback and cleanup. */
        tv->callbacks->alert(&event, p->flow->tenant_uuid, p->user_ctx);
        CallbackCleanupAppLayer(p, pa->tx_id, &event.app_layer);
    }

    return TM_ECODE_OK;
}

static int AlertCallbackDecoderEvent(ThreadVars *tv, const Packet *p) {
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

        AlertCallbackHeader(p, pa, &event.alert);

        /* Invoke callback */
        tv->callbacks->alert(&event, p->flow->tenant_uuid, p->user_ctx);
    }

    return TM_ECODE_OK;
}

static int CallbackAlertLogger(ThreadVars *tv, void *thread_data, const Packet *p) {
    if (PKT_IS_IPV4(p) || PKT_IS_IPV6(p)) {
        return AlertCallback(tv, p);
    } else if (p->alerts.cnt > 0) {
        return AlertCallbackDecoderEvent(tv, p);
    }
    return 0;
}

static int CallbackAlertLogCondition(ThreadVars *tv, void *thread_data, const Packet *p) {
    if ((p->alerts.cnt || p->flags & PKT_HAS_TAG) && tv->callbacks->alert) {
        return TRUE;
    }
    return FALSE;
}

void CallbackAlertLogRegister(void) {
    OutputRegisterPacketSubModule(LOGGER_CALLBACK_ALERT, "callback", MODULE_NAME, "callback.alert",
                                  NULL, CallbackAlertLogger, CallbackAlertLogCondition,
                                  CallbackAlertLogThreadInit, CallbackAlertLogThreadDeinit, NULL);
}
