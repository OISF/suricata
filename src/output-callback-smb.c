/**
 * \file
 *
 * \author Angelo Mirabella <mirabellaa@vmware.com>
 *
 * Generate SMB events and invoke corresponding callback (NTA).
 *
 */

#include "output-callback-smb.h"
#include "suricata-common.h"
#include "app-layer-parser.h"
#include "output-json.h"
#include "rust.h"

#define MODULE_NAME "CallbackSmbLog"

/* Mock ThreadInit/DeInit methods.
 * Callbacks do not store any per-thread information. */
static TmEcode CallbackSmbLogThreadInit(ThreadVars *t, const void *initdata, void **data) {
    return TM_ECODE_OK;
}

static TmEcode CallbackSmbLogThreadDeinit(ThreadVars *t, void *data) {
    return TM_ECODE_OK;
}

static OutputInitResult CallbackSmbLogInitSub(ConfNode *conf, OutputCtx *parent_ctx) {
    OutputInitResult result = { NULL, true };

    /* Register app layer logger. */
    AppLayerParserRegisterLogger(IPPROTO_TCP, ALPROTO_SMB);
    AppLayerParserRegisterLogger(IPPROTO_UDP, ALPROTO_SMB);

    return result;
}

static int CallbackSmbLogger(ThreadVars *tv, void *thread_data, const Packet *p, Flow *f,
                             void *state, void *tx, uint64_t tx_id) {
    if (!tv->callbacks->nta) {
        return TM_ECODE_OK;
    }

    JsonBuilder *jb = CreateEveHeader(p, LOG_DIR_FLOW, "smb", NULL, NULL);
    if (unlikely(jb == NULL)) {
        return TM_ECODE_FAILED;
    }

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
    tv->callbacks->nta((void *)jb_ptr(jb), jb_len(jb), f->tenant_uuid, f->user_ctx);

    jb_free(jb);
    return TM_ECODE_OK;
}

void CallbackSmbLogRegister(void) {
    OutputRegisterTxSubModule(LOGGER_CALLBACK_TX, "callback", MODULE_NAME, "callback.nta.smb",
                              CallbackSmbLogInitSub, ALPROTO_SMB, CallbackSmbLogger,
                              CallbackSmbLogThreadInit, CallbackSmbLogThreadDeinit, NULL);
}
