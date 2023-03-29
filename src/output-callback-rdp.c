/**
 * \file
 *
 * \author Angelo Mirabella <mirabellaa@vmware.com>
 *
 * Generate RDP events and invoke corresponding callback (NTA).
 *
 */
#include "output-callback-rdp.h"
#include "suricata-common.h"
#include "app-layer-parser.h"
#include "output-json.h"
#include "rust.h"

#define MODULE_NAME "CallbackRDPLog"


static TmEcode CallbackRdpLogThreadInit(ThreadVars *t, const void *initdata, void **data) {
    return TM_ECODE_OK;
}

static TmEcode CallbackRdpLogThreadDeinit(ThreadVars *t, void *data) {
    return TM_ECODE_OK;
}

static OutputInitResult CallbackRdpLogInitSub(ConfNode *conf, OutputCtx *parent_ctx) {
    OutputInitResult result = { NULL, true };

    AppLayerParserRegisterLogger(IPPROTO_TCP, ALPROTO_RDP);

    return result;
}

static int CallbackRdpLogger(ThreadVars *tv, void *thread_data, const Packet *p, Flow *f,
                             void *state, void *tx, uint64_t tx_id) {
    if (!tv->callbacks->nta) {
        return TM_ECODE_OK;
    }

    JsonBuilder *jb = CreateEveHeader((Packet *)p, LOG_DIR_PACKET, "rdp", NULL, NULL);
    if (unlikely(jb == NULL)) {
        return TM_ECODE_FAILED;
    }

    if (!rs_rdp_to_json(tx, jb)) {
        jb_free(jb);
        return TM_ECODE_FAILED;
    }

    /* Close log line. */
    jb_close(jb);

    /* Invoke NTA callback. */
    tv->callbacks->nta((void *)jb_ptr(jb), jb_len(jb), "rdp", f->tenant_uuid, f->user_ctx);

    jb_free(jb);
    return TM_ECODE_OK;
}

void CallbackRdpLogRegister(void) {
    /* Register as an eve sub-module. */
    OutputRegisterTxSubModule(LOGGER_CALLBACK_TX, "callback", MODULE_NAME, "callback.nta.rdp",
                              CallbackRdpLogInitSub, ALPROTO_RDP, CallbackRdpLogger,
                              CallbackRdpLogThreadInit, CallbackRdpLogThreadDeinit, NULL);
}
