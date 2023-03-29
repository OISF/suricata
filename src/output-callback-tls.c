/**
 * \file
 *
 * \author Angelo Mirabella <mirabellaa@vmware.com>
 *
 * Generate TLS events and invoke corresponding callback (NTA).
 *
 */

#include "output-callback-tls.h"
#include "suricata-common.h"
#include "app-layer.h"
#include "app-layer-parser.h"
#include "output-json.h"
#include "output-json-tls.h"
#include "rust.h"

#define MODULE_NAME "CallbackTlsLog"


static int CallbackTlsLogger(ThreadVars *tv, void *thread_data, const Packet *p,
                         Flow *f, void *state, void *txptr, uint64_t tx_id) {
    JsonTlsLogThread *aft = (JsonTlsLogThread *)thread_data;
    OutputTlsCtx *tls_ctx = aft->tlslog_ctx;
    SSLState *ssl_state = (SSLState *)state;

    if (!tv->callbacks->nta) {
        return TM_ECODE_OK;
    }

    if (unlikely(ssl_state == NULL)) {
        return TM_ECODE_OK;
    }

    if ((ssl_state->server_connp.cert0_issuerdn == NULL ||
            ssl_state->server_connp.cert0_subject == NULL) &&
            ((ssl_state->flags & SSL_AL_FLAG_SESSION_RESUMED) == 0 ||
            (tls_ctx->flags & LOG_TLS_SESSION_RESUMPTION) == 0) &&
            ((ssl_state->flags & SSL_AL_FLAG_LOG_WITHOUT_CERT) == 0)) {
        return TM_ECODE_OK;
    }

    JsonBuilder *jb = CreateEveHeader(p, LOG_DIR_FLOW, "tls", NULL, NULL);
    if (unlikely(jb == NULL)) {
        return TM_ECODE_OK;
    }

    jb_open_object(jb, "tls");

    /* log custom fields */
    if (tls_ctx->flags & LOG_TLS_CUSTOM) {
        JsonTlsLogJSONCustom(tls_ctx, jb, ssl_state);
    }
    /* log extended */
    else if (tls_ctx->flags & LOG_TLS_EXTENDED) {
        JsonTlsLogJSONExtended(jb, ssl_state);
    }
    /* log basic */
    else {
        JsonTlsLogJSONBasic(jb, ssl_state);
    }

    /* print original application level protocol when it has been changed
       because of STARTTLS, HTTP CONNECT, or similar. */
    if (f->alproto_orig != ALPROTO_UNKNOWN) {
        jb_set_string(jb, "from_proto", AppLayerGetProtoName(f->alproto_orig));
    }

    /* Close the tls object. */
    jb_close(jb);

    /* Close log line. */
    jb_close(jb);

    /* Invoke NTA callback. */
    tv->callbacks->nta((void *)jb_ptr(jb), jb_len(jb), "tls", f->tenant_uuid, f->user_ctx);

    jb_free(jb);

    return TM_ECODE_OK;
}

static TmEcode CallbackTlsLogThreadInit(ThreadVars *t, const void *initdata, void **data) {
    JsonTlsLogThread *aft = SCCalloc(1, sizeof(JsonTlsLogThread));
    if (unlikely(aft == NULL)) {
        return TM_ECODE_FAILED;
    }

    if (initdata == NULL) {
        SCLogDebug("Error getting context for callback tls 'initdata' argument NULL");
        return TM_ECODE_FAILED;
    }

    aft->tlslog_ctx = ((OutputCtx *)initdata)->data;
    *data = (void *)aft;

    return TM_ECODE_OK;
}

static TmEcode CallbackTlsLogThreadDeinit(ThreadVars *t, void *data) {
    JsonTlsLogThread *aft = (JsonTlsLogThread *)data;
    if (aft == NULL) {
        return TM_ECODE_OK;
    }

    SCFree(aft);
    return TM_ECODE_OK;
}

static OutputInitResult CallbackTlsLogInitSub(ConfNode *conf, OutputCtx *parent_ctx) {
    OutputInitResult result = { NULL, false };

    OutputTlsCtx *tls_ctx = OutputTlsInitCtx(conf);
    if (unlikely(tls_ctx == NULL)) {
        return result;
    }

    OutputCtx *output_ctx = SCCalloc(1, sizeof(OutputCtx));
    if (unlikely(output_ctx == NULL)) {
        SCFree(tls_ctx);
        return result;
    }

    if ((tls_ctx->fields & LOG_TLS_FIELD_CERTIFICATE) && (tls_ctx->fields & LOG_TLS_FIELD_CHAIN)) {
        SCLogWarning("Both 'certificate' and 'chain' contain the top "
                     "certificate, so only one of them should be enabled "
                     "at a time");
    }

    output_ctx->data = tls_ctx;
    output_ctx->DeInit = OutputTlsLogDeinitSub;

    AppLayerParserRegisterLogger(IPPROTO_TCP, ALPROTO_TLS);

    result.ctx = output_ctx;
    result.ok = true;
    return result;
}

void CallbackTlsLogRegister (void) {
    OutputRegisterTxSubModuleWithProgress(LOGGER_CALLBACK_TX, "callback", MODULE_NAME,
                                          "callback.nta.tls", CallbackTlsLogInitSub, ALPROTO_TLS,
                                          CallbackTlsLogger, TLS_HANDSHAKE_DONE,
                                          TLS_HANDSHAKE_DONE, CallbackTlsLogThreadInit,
                                          CallbackTlsLogThreadDeinit, NULL);
}
