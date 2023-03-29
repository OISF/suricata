/**
 * \file
 *
 * \author Angelo Mirabella <mirabellaa@vmware.com>
 *
 * Generate PreventAction (drop/reject) events and invoke corresponding callback.
 *
 */
#include "output-callback.h"
#include "output-callback-prevent-action.h"
#include "suricata-common.h"
#include "action-globals.h"
#include "app-layer-parser.h"
#include "packet.h"
#include "suricata.h"

#define MODULE_NAME "CallbackPreventActionLog"

typedef struct LogPreventActionCtx {
    OutputCallbackCommonSettings cfg;
} LogPreventActionCtx;

typedef struct CallbackPreventActionLogThread {
    LogPreventActionCtx *prevent_action_log_ctx;
} CallbackPreventActionLogThread;


static TmEcode CallbackPreventActionLogThreadInit(ThreadVars *t, const void *initdata, void **data) {
    CallbackPreventActionLogThread *aft = SCCalloc(1, sizeof(CallbackPreventActionLogThread));
    if (unlikely(aft == NULL)) {
        return TM_ECODE_FAILED;
    }

    if(initdata == NULL) {
        SCLogDebug("Error getting context for CallbackLogPreventAction.  \"initdata\" argument NULL");
        return TM_ECODE_FAILED;
    }

    aft->prevent_action_log_ctx = ((OutputCtx *)initdata)->data;
    *data = (void *)aft;
    return TM_ECODE_OK;
}

static TmEcode CallbackPreventActionLogThreadDeinit(ThreadVars *t, void *data) {
    CallbackPreventActionLogThread *aft = (CallbackPreventActionLogThread *)data;
    if (aft == NULL) {
        return TM_ECODE_OK;
    }

    SCFree(aft);
    return TM_ECODE_OK;
}

static int CallbackPreventActionLogCondition(ThreadVars *tv, void *thread_data, const Packet *p) {
    if (!tv->callbacks->prevent_action) {
        return FALSE;
    } else if (p->flow && FLOW_ACTION_IS_PREVENT(p->flow)) {
        /* This flow was marked as drop/reject because of a previous matching packet. */
        return TRUE;
    }

    /* Need to check if the packet contains alerts and the associated action. */
    for (int i = 0; i < p->alerts.cnt; i++) {
        const PacketAlert *pa = &p->alerts.alerts[i];
        if (unlikely(pa->s == NULL)) {
            continue;
        }

        /* use packet action if rate_filter modified the action */
        if (unlikely(pa->flags & PACKET_ALERT_RATE_FILTER_MODIFIED)) {
            if (PacketCheckAction(p, ACTION_DROP_REJECT)) {
                return TRUE;
            }
        } else if (pa->action & ACTION_DROP_REJECT) {
            return TRUE;
        }
    }

    return FALSE;
}

static void CallbackPreventActionLogDeinitSub(OutputCtx *output_ctx) {
    LogPreventActionCtx *prevent_action_ctx = output_ctx->data;

    SCFree(prevent_action_ctx);
    SCFree(output_ctx);
}

static OutputInitResult CallbackPreventActionLogInitSub(ConfNode *conf, OutputCtx *parent_ctx) {
    OutputInitResult result = { NULL, false };
    OutputCallbackCtx *occ = parent_ctx->data;

    LogPreventActionCtx *prevent_action_ctx = SCCalloc(1, sizeof(LogPreventActionCtx));
    if (unlikely(prevent_action_ctx == NULL)) {
        return result;
    }
    memset(prevent_action_ctx, 0x00, sizeof(*prevent_action_ctx));
    prevent_action_ctx->cfg = occ->cfg;

    OutputCtx *output_ctx = SCCalloc(1, sizeof(OutputCtx));
    if (unlikely(output_ctx == NULL)) {
        SCFree(prevent_action_ctx);
        return result;
    }

    output_ctx->data = prevent_action_ctx;
    output_ctx->DeInit = CallbackPreventActionLogDeinitSub;

    result.ctx = output_ctx;
    result.ok = true;
    return result;
}

static void CallbackPreventActionLog(ThreadVars *tv, const Packet *p, const PacketAlert *pa,
                                     LogPreventActionCtx *prevent_action_log_ctx) {
    uint64_t *tenant_uuid;
    void *user_ctx;
    uint64_t tx_id = 0;
    const char *action = EngineModeIsIPS() ? "drop" : "reject";

    /* Get the tenant uuid and user context. */
    if (p->flow) {
        tenant_uuid = (uint64_t *)p->flow->tenant_uuid;
        user_ctx = p->flow->user_ctx;
    } else {
        tenant_uuid = (uint64_t *)p->tenant_uuid;
        user_ctx = p->user_ctx;
    }

    /* Get the event action (drop|reject). */
    if (pa) {
        tx_id = pa->tx_id;

        if (unlikely(pa->flags & PACKET_ALERT_RATE_FILTER_MODIFIED) && p != NULL) {
            if (PacketCheckAction(p, ACTION_REJECT)) {
                action = "reject";
            } else {
                action = "drop";
            }
        } else {
            if (pa->action & ACTION_REJECT_ANY) {
                action = "reject";
            } else if (pa->action & ACTION_DROP && EngineModeIsIPS()) {
                action = "drop";
            }
        }
    } else if (p->flow && FLOW_ACTION_IS_REJECT(p->flow)) {
        action = "reject";
    }

    PreventActionEvent event;
    memset(&event, 0, sizeof(PreventActionEvent));

    JsonAddrInfo addr = json_addr_info_zero;
    EventAddCommonInfo(p, LOG_DIR_PACKET, &event.common, &addr, &prevent_action_log_ctx->cfg);

    /* Add the drop/reject info. */
    event.prevent_action.action = action;
    event.prevent_action.pkt_is_ipv6 = PKT_IS_IPV6(p);

    if (PKT_IS_TCP(p)) {
        event.prevent_action.tcp.payload_len = p->payload_len;
        event.prevent_action.tcp.seq = TCP_GET_SEQ(p);
        event.prevent_action.tcp.ack = TCP_GET_ACK(p);
        event.prevent_action.tcp.win = TCP_GET_WINDOW(p);
    } else {
        /* UDP/ICMP. */
        if (p->flow && FlowGetAppProtocol(p->flow) == ALPROTO_DNS) {
            void *dns_state = (void *)FlowGetAppState(p->flow);

            if (dns_state) {
                void *tx_ptr = AppLayerParserGetTx(p->flow->proto, ALPROTO_DNS, dns_state, tx_id);

                if (tx_ptr) {
                    /* Retrieve DNS transaction id, rrtype and rrname to inject a DNS
                     * reply. */
                    event.prevent_action.dns.query_tx_id = rs_dns_tx_get_tx_id(tx_ptr);
                    rs_dns_tx_get_query_rrtype(tx_ptr, 0, &event.prevent_action.dns.query_rrtype);

                    rs_dns_tx_get_query_name(tx_ptr, 0, &event.prevent_action.dns.query_rrname,
                                             &event.prevent_action.dns.query_rrname_len);
                }
            }
        }

        /* Need to store the IP header and the first 8 bytes of the IP payload
         * (at most) for ICMP destination unreachable payload. */
        if (PKT_IS_IPV4(p)) {
            event.prevent_action.icmp.payload = (uint8_t *)p->ip4h;
            event.prevent_action.icmp.payload_len = IPV4_HEADER_LEN + MIN(8, IPV4_GET_IPLEN(p));
        } else {
            event.prevent_action.icmp.payload = (uint8_t *)p->ip6h;
            event.prevent_action.icmp.payload_len = IPV6_HEADER_LEN + MIN(8, IPV6_GET_PLEN(p));
        }
    }

    /* Invoke callback. */
    tv->callbacks->prevent_action(&event, tenant_uuid, user_ctx);
}

static int CallbackPreventActionLogger(ThreadVars *tv, void *thread_data, const Packet *p) {
    CallbackPreventActionLogThread *thread = (CallbackPreventActionLogThread *)thread_data;
    LogPreventActionCtx *prevent_action_log_ctx = thread->prevent_action_log_ctx;

    if (p->alerts.cnt == 0) {
        /* If the packet has no alerts it means this is a packet belonging to the same flow of the
         * first packet that triggered a `drop/reject` signature. */
        CallbackPreventActionLog(tv, p, NULL, prevent_action_log_ctx);
    } else {
        for (int i = 0; i < p->alerts.cnt; i++) {
            const PacketAlert *pa = &p->alerts.alerts[i];

            /* Check the signature that triggered it is a drop/reject. */
            if (unlikely(pa->s == NULL)) {
                continue;
            } else if (unlikely(pa->flags & PACKET_ALERT_RATE_FILTER_MODIFIED)) {
                if (p != NULL && !PacketCheckAction(p, ACTION_DROP_REJECT)) {
                    continue;
                }
            } else if (!(pa->action & ACTION_DROP_REJECT)) {
                continue;
            }

            /* Build event and invoke callback. */
            CallbackPreventActionLog(tv, p, pa, prevent_action_log_ctx);
        }
    }

    return TM_ECODE_OK;
}

void CallbackPreventActionLogRegister(void) {
    /* Register as an eve sub-module. */
    OutputRegisterPacketSubModule(LOGGER_CALLBACK_PREVENT_ACTION, "callback", MODULE_NAME,
                                  "callback.prevent-action", CallbackPreventActionLogInitSub,
                                  CallbackPreventActionLogger, CallbackPreventActionLogCondition,
                                  CallbackPreventActionLogThreadInit,
                                  CallbackPreventActionLogThreadDeinit, NULL);
}
