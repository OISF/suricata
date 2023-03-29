/**
 * \file
 *
 * \author Angelo Mirabella <mirabellaa@vmware.com>
 *
 * Generate SMB events and invoke corresponding callback (NTA).
 *
 */
#include "output-callback.h"
#include "output-callback-smb.h"
#include "suricata-common.h"
#include "app-layer-parser.h"
#include "output-json.h"
#include "rust.h"

#define MODULE_NAME "CallbackSmbLog"

typedef struct LogSmbCtx {
    OutputCallbackCommonSettings cfg;
} LogSmbCtx;

typedef struct CallbackSmbLogThread {
    LogSmbCtx *smblog_ctx;
} CallbackSmbLogThread;


/* Mock ThreadInit/DeInit methods.
 * Callbacks do not store any per-thread information. */
static TmEcode CallbackSmbLogThreadInit(ThreadVars *t, const void *initdata, void **data) {
    CallbackSmbLogThread *aft = SCCalloc(1, sizeof(CallbackSmbLogThread));
    if (unlikely(aft == NULL)) {
        return TM_ECODE_FAILED;
    }

    if(initdata == NULL) {
        SCLogDebug("Error getting context for EveLogSmb.  \"initdata\" argument NULL");
        return TM_ECODE_FAILED;
    }

    aft->smblog_ctx = ((OutputCtx *)initdata)->data;
    *data = (void *)aft;
    return TM_ECODE_OK;
}

static TmEcode CallbackSmbLogThreadDeinit(ThreadVars *t, void *data) {
    CallbackSmbLogThread *aft = (CallbackSmbLogThread *)data;
    if (aft == NULL) {
        return TM_ECODE_OK;
    }

    SCFree(aft);
    return TM_ECODE_OK;
}

static void CallbackSmbLogDeinitSub(OutputCtx *output_ctx) {
    LogSmbCtx *smb_ctx = output_ctx->data;

    SCFree(smb_ctx);
    SCFree(output_ctx);
}

static OutputInitResult CallbackSmbLogInitSub(ConfNode *conf, OutputCtx *parent_ctx) {
    OutputInitResult result = { NULL, false };
    OutputCallbackCtx *occ = parent_ctx->data;

    LogSmbCtx *smb_ctx = SCCalloc(1, sizeof(LogSmbCtx));
    if (unlikely(smb_ctx == NULL)) {
        return result;
    }
    memset(smb_ctx, 0x00, sizeof(*smb_ctx));
    smb_ctx->cfg = occ->cfg;

    OutputCtx *output_ctx = SCCalloc(1, sizeof(OutputCtx));
    if (unlikely(output_ctx == NULL)) {
        SCFree(smb_ctx);
        return result;
    }

    output_ctx->data = smb_ctx;
    output_ctx->DeInit = CallbackSmbLogDeinitSub;

    /* Register app layer logger. */
    AppLayerParserRegisterLogger(IPPROTO_TCP, ALPROTO_SMB);
    AppLayerParserRegisterLogger(IPPROTO_UDP, ALPROTO_SMB);

    result.ctx = output_ctx;
    result.ok = true;
    return result;
}

static int CallbackSmbLogger(ThreadVars *tv, void *thread_data, const Packet *p, Flow *f,
                             void *state, void *tx, uint64_t tx_id) {
    CallbackSmbLogThread *thread = thread_data;

    if (!tv->callbacks->nta) {
        return TM_ECODE_OK;
    }

    JsonBuilder *jb = CreateEveHeader(p, LOG_DIR_FLOW, "smb", NULL, NULL);
    if (unlikely(jb == NULL)) {
        return TM_ECODE_FAILED;
    }

    EveAddCommonOptions(&thread->smblog_ctx->cfg, p, f, jb);

    jb_open_object(jb, "smb");
    if (!rs_smb_log_json_response(jb, state, tx)) {
        jb_free(jb);
        return TM_ECODE_FAILED;
    }
    /* Close SMB object. */
    jb_close(jb);

    /* Close log line. */
    jb_close(jb);

    /* Invoke NTA callback. */
    tv->callbacks->nta((void *)jb_ptr(jb), jb_len(jb), "smb", f->tenant_uuid, f->user_ctx);

    jb_free(jb);
    return TM_ECODE_OK;
}

void CallbackSmbLogRegister(void) {
    OutputRegisterTxSubModule(LOGGER_CALLBACK_TX, "callback", MODULE_NAME, "callback.nta.smb",
                              CallbackSmbLogInitSub, ALPROTO_SMB, CallbackSmbLogger,
                              CallbackSmbLogThreadInit, CallbackSmbLogThreadDeinit, NULL);
}
