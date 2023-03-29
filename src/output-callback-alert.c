/**
 * \file
 *
 * \author Angelo Mirabella <mirabellaa@vmware.com>
 *
 * Generate alerts and invoke corresponding callback.
 *
 */

#include "suricata-common.h"

#include "detect-engine.h"
#include "output-callback-alert.h"

#include "action-globals.h"
#include "output.h"
#include "output-callback.h"
#include "output-json-alert.h"
#include "packet.h"
#include "rust.h"
#include "suricata.h"
#include "threadvars.h"

#define MODULE_NAME "CallbackAlertLog"

typedef struct AlertCallbackOutputCtx_ {
    HttpXFFCfg *xff_cfg;
} AlertCallbackOutputCtx;

typedef struct CallbackAlertLogThread_ {
    AlertCallbackOutputCtx* callback_output_ctx;
} CallbackAlertLogThread;

static TmEcode CallbackAlertLogThreadInit(ThreadVars *t, const void *initdata, void **data) {
    CallbackAlertLogThread *aft = SCCalloc(1, sizeof(CallbackAlertLogThread));
    if (unlikely(aft == NULL)) {
        return TM_ECODE_FAILED;
    }

    if (initdata == NULL)     {
        SCLogDebug("Error getting context for CallbackLogAlert.  \"initdata\" argument NULL");
        SCFree(aft);
        return TM_ECODE_FAILED;
    }

    /** Use the Output Context (file pointer and mutex) */
    AlertCallbackOutputCtx *callback_output_ctx = ((OutputCtx *)initdata)->data;
    aft->callback_output_ctx = callback_output_ctx;

    *data = (void *)aft;
    return TM_ECODE_OK;
}

static TmEcode CallbackAlertLogThreadDeinit(ThreadVars *t, void *data) {
    CallbackAlertLogThread *aft = (CallbackAlertLogThread *)data;
    if (aft == NULL) {
        return TM_ECODE_OK;
    }

    /* clear memory */
    memset(aft, 0, sizeof(CallbackAlertLogThread));

    SCFree(aft);
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

    /* Add tx_id for correlation with other events. */
    if (pa->flags & PACKET_ALERT_FLAG_TX) {
        alert->tx_id = pa->tx_id;
    }

    /* TODO: AlertJsonSourceTarget ? */

    if (pa->s->metadata && pa->s->metadata->json_str) {
        alert->metadata = pa->s->metadata->json_str;
    }
}

static int AlertCallback(ThreadVars *tv, CallbackAlertLogThread *aft, const Packet *p) {
    if (p->alerts.cnt == 0) {
        return TM_ECODE_OK;
    }

    AlertCallbackOutputCtx *callback_output_ctx = aft->callback_output_ctx;

    for (int i = 0; i < p->alerts.cnt; i++) {
        const PacketAlert *pa = &p->alerts.alerts[i];

        if (unlikely(pa->s == NULL)) {
            continue;
        }

        AlertEvent event = {
            .alert.tx_id = -1
        };
        JsonAddrInfo addr = json_addr_info_zero;
        EventAddCommonInfo(p, LOG_DIR_PACKET, &event.common, &addr);

        /* TODO: Add metadata (flowvars, pktvars)? */

        /* Alert */
        AlertCallbackHeader(p, pa, &event.alert);

        /* TODO: Add tunnel info? */

        char xff_buffer[XFF_MAXLEN];
        if (p->flow != NULL) {
            CallbackAddAppLayer(p, pa->tx_id, &event.app_layer);

            /* TODO: Add file info? */

            /* Flow info. */
            event.flow.pkts_toserver = p->flow->todstpktcnt;
            event.flow.pkts_toclient = p->flow->tosrcpktcnt;
            event.flow.bytes_toserver = p->flow->todstbytecnt;
            event.flow.bytes_toclient = p->flow->tosrcbytecnt;
            CreateIsoTimeString(p->flow->startts, event.flow.start, sizeof(event.flow.start));

            /* XFF. */
            HttpXFFCfg *xff_cfg = callback_output_ctx->xff_cfg;
            int have_xff_ip = 0;
            if ((xff_cfg != NULL) && !(xff_cfg->flags & XFF_DISABLED)) {
                if (FlowGetAppProtocol(p->flow) == ALPROTO_HTTP) {
                    if (pa->flags & PACKET_ALERT_FLAG_TX) {
                        have_xff_ip = HttpXFFGetIPFromTx(p->flow, pa->tx_id, xff_cfg,
                                xff_buffer, XFF_MAXLEN);
                    } else {
                        have_xff_ip = HttpXFFGetIP(p->flow, xff_cfg, xff_buffer, XFF_MAXLEN);
                    }
                }

                if (have_xff_ip && xff_cfg->flags & XFF_OVERWRITE) {
                    if (p->flowflags & FLOW_PKT_TOCLIENT) {
                        strlcpy(addr.dst_ip, xff_buffer, JSON_ADDR_LEN);
                    } else {
                        strlcpy(addr.src_ip, xff_buffer, JSON_ADDR_LEN);
                    }
                    /* Clear have_xff_ip so the xff field does not get
                     * logged below. */
                    have_xff_ip = false;
                }
            }

            if (have_xff_ip && xff_cfg->flags & XFF_EXTRADATA) {
                event.common.xff = xff_buffer;
            }
        }

        /* Invoke callback and cleanup. */
        uint64_t *tenant_uuid = p->flow ? (uint64_t *) p->flow->tenant_uuid :
                                          (uint64_t *) p->tenant_uuid;
        void *user_ctx = p->flow ? p->flow->user_ctx : p->user_ctx;
        tv->callbacks->alert(&event, tenant_uuid, user_ctx);
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
        tv->callbacks->alert(&event, p->flow->tenant_uuid, p->flow->user_ctx);
    }

    return TM_ECODE_OK;
}

static int CallbackAlertLogger(ThreadVars *tv, void *thread_data, const Packet *p) {
    if (PKT_IS_IPV4(p) || PKT_IS_IPV6(p)) {
        return AlertCallback(tv, thread_data, p);
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

static void CallbackAlertLogDeInitCtxSub(OutputCtx *output_ctx) {
    AlertCallbackOutputCtx *callback_output_ctx = (AlertCallbackOutputCtx *)output_ctx->data;

    if (callback_output_ctx != NULL) {
        HttpXFFCfg *xff_cfg = callback_output_ctx->xff_cfg;
        if (xff_cfg != NULL) {
            SCFree(xff_cfg);
        }
        SCFree(callback_output_ctx);
    }
    SCFree(output_ctx);
}

static OutputInitResult CallbackAlertLogInitCtxSub(ConfNode *conf, OutputCtx *parent_ctx) {
    OutputInitResult result = { NULL, false };
    AlertCallbackOutputCtx *callback_output_ctx = NULL;

    OutputCtx *output_ctx = SCCalloc(1, sizeof(OutputCtx));
    if (unlikely(output_ctx == NULL)) {
        return result;
    }

    callback_output_ctx = SCMalloc(sizeof(AlertCallbackOutputCtx));
    if (unlikely(callback_output_ctx == NULL)) {
        if (output_ctx != NULL) {
            SCFree(output_ctx);
        }

        return result;
    }

    memset(callback_output_ctx, 0, sizeof(AlertCallbackOutputCtx));

    /* Enable metadata parsing. */
    DetectEngineSetParseMetadata();

    /* XFF. */
    if (conf != NULL && ConfNodeLookupChild(conf, "xff") != NULL) {
        callback_output_ctx->xff_cfg = SCCalloc(1, sizeof(HttpXFFCfg));
        if (likely(callback_output_ctx->xff_cfg != NULL)) {
            HttpXFFGetCfg(conf, callback_output_ctx->xff_cfg);
        }
    }

    output_ctx->data = callback_output_ctx;
    output_ctx->DeInit = CallbackAlertLogDeInitCtxSub;

    result.ctx = output_ctx;
    result.ok = true;
    return result;
}

void CallbackAlertLogRegister(void) {
    OutputRegisterPacketSubModule(LOGGER_CALLBACK_ALERT, "callback", MODULE_NAME, "callback.alert",
                                  CallbackAlertLogInitCtxSub, CallbackAlertLogger,
                                  CallbackAlertLogCondition, CallbackAlertLogThreadInit,
                                  CallbackAlertLogThreadDeinit, NULL);
}
