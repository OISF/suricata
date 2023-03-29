/**
 * \file
 *
 * \author Angelo Mirabella <mirabellaa@vmware.com>
 *
 * Generate Reject events and invoke corresponding callback.
 *
 */
#include "output-callback.h"
#include "output-callback-reject.h"
#include "suricata-common.h"
#include "app-layer-parser.h"
#include "action-globals.h"
#include "packet.h"

#define MODULE_NAME "CallbackRejectLog"

typedef struct LogRejectCtx {
    OutputCallbackCommonSettings cfg;
} LogRejectCtx;

typedef struct CallbackRejectLogThread {
    LogRejectCtx *rejectlog_ctx;
} CallbackRejectLogThread;


static TmEcode CallbackRejectLogThreadInit(ThreadVars *t, const void *initdata, void **data) {
    CallbackRejectLogThread *aft = SCCalloc(1, sizeof(CallbackRejectLogThread));
    if (unlikely(aft == NULL)) {
        return TM_ECODE_FAILED;
    }

    if(initdata == NULL) {
        SCLogDebug("Error getting context for CallbackLogReject.  \"initdata\" argument NULL");
        return TM_ECODE_FAILED;
    }

    aft->rejectlog_ctx = ((OutputCtx *)initdata)->data;
    *data = (void *)aft;
    return TM_ECODE_OK;
}

static TmEcode CallbackRejectLogThreadDeinit(ThreadVars *t, void *data) {
    CallbackRejectLogThread *aft = (CallbackRejectLogThread *)data;
    if (aft == NULL) {
        return TM_ECODE_OK;
    }

    SCFree(aft);
    return TM_ECODE_OK;
}

static int CallbackRejectLogCondition(ThreadVars *tv, void *thread_data, const Packet *p) {
    if (!tv->callbacks->reject) {
        return FALSE;
    } else if (p->flow && FLOW_ACTION_IS_REJECT(p->flow)) {
        /* This flow was marked as reject because of a previous matching packet. */
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
            if (PacketCheckAction(p, ACTION_REJECT_ANY)) {
                return TRUE;
            }
        } else if (pa->action & ACTION_REJECT_ANY) {
            return TRUE;
        }
    }

    return FALSE;
}

static void CallbackRejectLogDeinitSub(OutputCtx *output_ctx) {
    LogRejectCtx *reject_ctx = output_ctx->data;

    SCFree(reject_ctx);
    SCFree(output_ctx);
}

static OutputInitResult CallbackRejectLogInitSub(ConfNode *conf, OutputCtx *parent_ctx) {
    OutputInitResult result = { NULL, false };
    OutputCallbackCtx *occ = parent_ctx->data;

    LogRejectCtx *reject_ctx = SCCalloc(1, sizeof(LogRejectCtx));
    if (unlikely(reject_ctx == NULL)) {
        return result;
    }
    memset(reject_ctx, 0x00, sizeof(*reject_ctx));
    reject_ctx->cfg = occ->cfg;

    OutputCtx *output_ctx = SCCalloc(1, sizeof(OutputCtx));
    if (unlikely(output_ctx == NULL)) {
        SCFree(reject_ctx);
        return result;
    }

    output_ctx->data = reject_ctx;
    output_ctx->DeInit = CallbackRejectLogDeinitSub;

    result.ctx = output_ctx;
    result.ok = true;
    return result;
}

static int CallbackRejectLogger(ThreadVars *tv, void *thread_data, const Packet *p) {
    CallbackRejectLogThread *thread = (CallbackRejectLogThread *)thread_data;
    LogRejectCtx *rejectlog_ctx = thread->rejectlog_ctx;
    uint64_t *tenant_uuid;
    void *user_ctx;

    /* Mark the flow as reject and prevent further inspection. */
    if (p->flow) {
        tenant_uuid = (uint64_t *)p->flow->tenant_uuid;
        user_ctx = p->flow->user_ctx;
    } else {
        tenant_uuid = (uint64_t *)p->tenant_uuid;
        user_ctx = p->user_ctx;
    }

    for (int i = 0; i < p->alerts.cnt; i++) {
        const PacketAlert *pa = &p->alerts.alerts[i];

        if (unlikely(pa->s == NULL)) {
            continue;
        }

        RejectEvent event;
        memset(&event, 0, sizeof(RejectEvent));

        JsonAddrInfo addr = json_addr_info_zero;
        EventAddCommonInfo(p, LOG_DIR_PACKET, &event.common, &addr, &rejectlog_ctx->cfg);

        /* Add the reject info. */
        event.reject.pkt_is_ipv6 = PKT_IS_IPV6(p);

        if (PKT_IS_TCP(p)) {
            event.reject.tcp.payload_len = p->payload_len;
            event.reject.tcp.seq = TCP_GET_SEQ(p);
            event.reject.tcp.ack = TCP_GET_ACK(p);
            event.reject.tcp.win = TCP_GET_WINDOW(p);
        } else {
            /* UDP/ICMP. */
            if (p->flow && FlowGetAppProtocol(p->flow) == ALPROTO_DNS) {
                void *dns_state = (void *)FlowGetAppState(p->flow);

                if (dns_state) {
                    void *tx_ptr = AppLayerParserGetTx(p->flow->proto, ALPROTO_DNS, dns_state,
                                                       pa->tx_id);

                    if (tx_ptr) {
                        /* Retrieve DNS transaction id, rrtype and rrname to inject a DNS
                         * reply. */
                        event.reject.dns.query_tx_id = rs_dns_tx_get_tx_id(tx_ptr);
                        rs_dns_tx_get_query_rrtype(tx_ptr, 0, &event.reject.dns.query_rrtype);

                        rs_dns_tx_get_query_name(tx_ptr, 0, &event.reject.dns.query_rrname,
                                                 &event.reject.dns.query_rrname_len);
                    }
                }
            }

            /* Need to store the IP header and the first 8 bytes of the IP payload
             * (at most) for ICMP destination unreachable payload. */
            if (PKT_IS_IPV4(p)) {
                event.reject.icmp.payload = (uint8_t *)p->ip4h;
                event.reject.icmp.payload_len = IPV4_HEADER_LEN + MIN(8, IPV4_GET_IPLEN(p));
            } else {
                event.reject.icmp.payload = (uint8_t *)p->ip6h;
                event.reject.icmp.payload_len = IPV6_HEADER_LEN + MIN(8, IPV6_GET_PLEN(p));
            }
        }

        /* Invoke callback. */
        tv->callbacks->reject(&event, tenant_uuid, user_ctx);
    }

    return TM_ECODE_OK;
}

void CallbackRejectLogRegister(void) {
    /* Register as an eve sub-module. */
    OutputRegisterPacketSubModule(LOGGER_CALLBACK_REJECT, "callback", MODULE_NAME, "callback.reject",
                                  CallbackRejectLogInitSub, CallbackRejectLogger,
                                  CallbackRejectLogCondition, CallbackRejectLogThreadInit,
                                  CallbackRejectLogThreadDeinit, NULL);
}
