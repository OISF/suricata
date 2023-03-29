/**
 * \file
 *
 * \author Angelo Mirabella <mirabellaa@vmware.com>
 *
 * Generate KRB5 events and invoke corresponding callback (NTA).
 *
 */
#include "output-callback.h"
#include "output-callback-krb5.h"
#include "suricata-common.h"
#include "app-layer-parser.h"
#include "output-json.h"
#include "rust.h"

#define MODULE_NAME "CallbackKRB5Log"

typedef struct LogKrb5Ctx {
    OutputCallbackCommonSettings cfg;
} LogKrb5Ctx;

typedef struct CallbackKrb5LogThread {
    LogKrb5Ctx *krb5log_ctx;
} CallbackKrb5LogThread;


static int CallbackKrb5Logger(ThreadVars *tv, void *thread_data, const Packet *p, Flow *f,
                              void *state, void *tx, uint64_t tx_id) {
    CallbackKrb5LogThread *thread = thread_data;

    if (!tv->callbacks->nta) {
        return TM_ECODE_OK;
    }

    KRB5Transaction *krb5tx = tx;

    JsonBuilder *jb = CreateEveHeader(p, LOG_DIR_PACKET, "krb5", NULL, NULL);
    if (unlikely(jb == NULL)) {
        return TM_ECODE_FAILED;
    }

    EveAddCommonOptions(&thread->krb5log_ctx->cfg, p, f, jb);

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
    CallbackKrb5LogThread *aft = SCCalloc(1, sizeof(CallbackKrb5LogThread));
    if (unlikely(aft == NULL)) {
        return TM_ECODE_FAILED;
    }

    if(initdata == NULL) {
        SCLogDebug("Error getting context for EveLogKrb5.  \"initdata\" argument NULL");
        return TM_ECODE_FAILED;
    }

    aft->krb5log_ctx = ((OutputCtx *)initdata)->data;
    *data = (void *)aft;
    return TM_ECODE_OK;
}

static TmEcode CallbackKrb5LogThreadDeinit(ThreadVars *t, void *data) {
    CallbackKrb5LogThread *aft = (CallbackKrb5LogThread *)data;
    if (aft == NULL) {
        return TM_ECODE_OK;
    }

    SCFree(aft);
    return TM_ECODE_OK;
}

static void CallbackKrb5LogDeinitSub(OutputCtx *output_ctx) {
    LogKrb5Ctx *krb5_ctx = output_ctx->data;

    SCFree(krb5_ctx);
    SCFree(output_ctx);
}

static OutputInitResult CallbackKrb5LogInitSub(ConfNode *conf, OutputCtx *parent_ctx) {
    OutputInitResult result = { NULL, false };
    OutputCallbackCtx *occ = parent_ctx->data;

    LogKrb5Ctx *krb5_ctx = SCCalloc(1, sizeof(LogKrb5Ctx));
    if (unlikely(krb5_ctx == NULL)) {
        return result;
    }
    memset(krb5_ctx, 0x00, sizeof(*krb5_ctx));
    krb5_ctx->cfg = occ->cfg;

    OutputCtx *output_ctx = SCCalloc(1, sizeof(OutputCtx));
    if (unlikely(output_ctx == NULL)) {
        SCFree(krb5_ctx);
        return result;
    }

    output_ctx->data = krb5_ctx;
    output_ctx->DeInit = CallbackKrb5LogDeinitSub;

    AppLayerParserRegisterLogger(IPPROTO_TCP, ALPROTO_KRB5);
    AppLayerParserRegisterLogger(IPPROTO_UDP, ALPROTO_KRB5);

    result.ctx = output_ctx;
    result.ok = true;
    return result;
}

void CallbackKrb5LogRegister(void) {
    /* Register as an eve sub-module. */
    OutputRegisterTxSubModule(LOGGER_CALLBACK_TX, "callback", MODULE_NAME,
                              "callback.nta.krb5", CallbackKrb5LogInitSub, ALPROTO_KRB5,
                              CallbackKrb5Logger, CallbackKrb5LogThreadInit,
                              CallbackKrb5LogThreadDeinit, NULL);
}
