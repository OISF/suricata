/**
 * \file
 *
 * \author Angelo Mirabella <mirabellaa@vmware.com>
 *
 * Generate KRB5 events and invoke corresponding callback (NTA).
 *
 */
#include "output-callback-dns.h"
#include "suricata-common.h"
#include "app-layer-parser.h"
#include "output-json.h"
#include "rust.h"

#define MODULE_NAME "CallbackKRB5Log"


static int CallbackKrb5Logger(ThreadVars *tv, void *thread_data, const Packet *p, Flow *f,
                              void *state, void *tx, uint64_t tx_id) {
    if (!tv->callbacks->nta) {
        return TM_ECODE_OK;
    }

    KRB5Transaction *krb5tx = tx;

    JsonBuilder *jb = CreateEveHeader(p, LOG_DIR_PACKET, "krb5", NULL, NULL);
    if (unlikely(jb == NULL)) {
        return TM_ECODE_FAILED;
    }

    jb_open_object(jb, "krb5");
    if (!rs_krb5_log_json_response(jb, state, krb5tx)) {
        jb_free(jb);
        return TM_ECODE_FAILED;
    }
    jb_close(jb);
    jb_close(jb);

    /* Invoke NTA callback. */
    tv->callbacks->nta((void *)jb_ptr(jb), jb_len(jb), "krb5", f->tenant_uuid, f->user_ctx);

    jb_free(jb);
    return TM_ECODE_OK;
}

static TmEcode CallbackKrb5LogThreadInit(ThreadVars *t, const void *initdata, void **data) {
    return TM_ECODE_OK;
}

static TmEcode CallbackKrb5LogThreadDeinit(ThreadVars *t, void *data) {
    return TM_ECODE_OK;
}

static OutputInitResult CallbackKrb5LogInitSub(ConfNode *conf, OutputCtx *parent_ctx) {
    OutputInitResult result = { NULL, true };

    AppLayerParserRegisterLogger(IPPROTO_TCP, ALPROTO_KRB5);
    AppLayerParserRegisterLogger(IPPROTO_UDP, ALPROTO_KRB5);

    return result;
}

void CallbackKrb5LogRegister(void) {
    /* Register as an eve sub-module. */
    OutputRegisterTxSubModule(LOGGER_CALLBACK_TX, "callback", MODULE_NAME,
                              "callback.nta.krb5", CallbackKrb5LogInitSub, ALPROTO_KRB5,
                              CallbackKrb5Logger, CallbackKrb5LogThreadInit,
                              CallbackKrb5LogThreadDeinit, NULL);
}
