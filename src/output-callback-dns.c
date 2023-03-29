/**
 * \file
 *
 * \author Angelo Mirabella <mirabellaa@vmware.com>
 *
 * Generate DNS events and invoke corresponding callback (NTA).
 *
 */
#include "output-callback-dns.h"
#include "suricata-common.h"
#include "app-layer-parser.h"
#include "output-json.h"
#include "rust.h"

#define MODULE_NAME "CallbackDnsLog"


/* DNS flags (enable everything by default). */
static uint64_t CallbackDnsFlags = ~0ULL;

static int CallbackDnsLoggerToServer(ThreadVars *tv, void *thread_data, const Packet *p, Flow *f,
                                     void *alstate, void *txptr, uint64_t tx_id) {

    if (!tv->callbacks->nta) {
        return TM_ECODE_OK;
    }

    for (uint16_t i = 0; i < 0xffff; i++) {
        JsonBuilder *jb = CreateEveHeader(p, LOG_DIR_FLOW, "dns", NULL, NULL);
        if (unlikely(jb == NULL)) {
            return TM_ECODE_OK;
        }

        jb_open_object(jb, "dns");
        if (!rs_dns_log_json_query(txptr, i, CallbackDnsFlags, jb)) {
            jb_free(jb);
            break;
        }
        jb_close(jb);
        jb_close(jb);

        /* Invoke NTA callback. */
        tv->callbacks->nta((void *)jb_ptr(jb), jb_len(jb), "dns", f->tenant_uuid, f->user_ctx);

        jb_free(jb);
    }

    SCReturnInt(TM_ECODE_OK);
}

static int CallbackDnsLoggerToClient(ThreadVars *tv, void *thread_data, const Packet *p, Flow *f,
                                     void *alstate, void *txptr, uint64_t tx_id) {
    if (!tv->callbacks->nta) {
        return TM_ECODE_OK;
    }

    if (rs_dns_do_log_answer(txptr, CallbackDnsFlags)) {
        JsonBuilder *jb = CreateEveHeader(p, LOG_DIR_FLOW, "dns", NULL, NULL);
        if (unlikely(jb == NULL)) {
            return TM_ECODE_OK;
        }

        jb_open_object(jb, "dns");
        rs_dns_log_json_answer(txptr, CallbackDnsFlags, jb);
        jb_close(jb);
        jb_close(jb);

        /* Invoke NTA callback. */
        tv->callbacks->nta((void *)jb_ptr(jb), jb_len(jb), "dns", f->tenant_uuid, f->user_ctx);

        jb_free(jb);
    }

    SCReturnInt(TM_ECODE_OK);
}

static TmEcode CallbackDnsLogThreadInit(ThreadVars *t, const void *initdata, void **data) {
    return TM_ECODE_OK;
}

static TmEcode CallbackDnsLogThreadDeinit(ThreadVars *t, void *data) {
    return TM_ECODE_OK;
}

static OutputInitResult CallbackDnsLogInitCtxSub(ConfNode *conf, OutputCtx *parent_ctx) {
    OutputInitResult result = { NULL, true };

    AppLayerParserRegisterLogger(IPPROTO_UDP, ALPROTO_DNS);
    AppLayerParserRegisterLogger(IPPROTO_TCP, ALPROTO_DNS);

    return result;
}

static int CallbackDnsLogger(ThreadVars *tv, void *thread_data, const Packet *p, Flow *f,
                             void *alstate, void *txptr, uint64_t tx_id) {
    if (rs_dns_tx_is_request(txptr)) {
        return CallbackDnsLoggerToServer(tv, thread_data, p, f, alstate, txptr, tx_id);
    } else if (rs_dns_tx_is_response(txptr)) {
        return CallbackDnsLoggerToClient(tv, thread_data, p, f, alstate, txptr, tx_id);
    }
    return TM_ECODE_OK;
}

void CallbackDnsLogRegister(void) {
    OutputRegisterTxSubModule(LOGGER_CALLBACK_TX, "callback", MODULE_NAME, "callback.nta.dns",
                              CallbackDnsLogInitCtxSub, ALPROTO_DNS, CallbackDnsLogger,
                              CallbackDnsLogThreadInit, CallbackDnsLogThreadDeinit, NULL);
}
