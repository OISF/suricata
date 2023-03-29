/**
 * \file
 *
 * \author Angelo Mirabella <mirabellaa@vmware.com>
 *
 * Generate RDP events and invoke corresponding callback (NTA).
 *
 */
#include "output-callback.h"
#include "output-callback-rdp.h"
#include "suricata-common.h"
#include "app-layer-parser.h"
#include "output-json.h"
#include "rust.h"

#define MODULE_NAME "CallbackRDPLog"

typedef struct LogRdpCtx {
    OutputCallbackCommonSettings cfg;
} LogRdpCtx;

typedef struct CallbackRdpLogThread {
    LogRdpCtx *rdplog_ctx;
} CallbackRdpLogThread;


static TmEcode CallbackRdpLogThreadInit(ThreadVars *t, const void *initdata, void **data) {
    CallbackRdpLogThread *aft = SCCalloc(1, sizeof(CallbackRdpLogThread));
    if (unlikely(aft == NULL)) {
        return TM_ECODE_FAILED;
    }

    if(initdata == NULL) {
        SCLogDebug("Error getting context for EveLogRdp.  \"initdata\" argument NULL");
        return TM_ECODE_FAILED;
    }

    aft->rdplog_ctx = ((OutputCtx *)initdata)->data;
    *data = (void *)aft;
    return TM_ECODE_OK;
}

static TmEcode CallbackRdpLogThreadDeinit(ThreadVars *t, void *data) {
    CallbackRdpLogThread *aft = (CallbackRdpLogThread *)data;
    if (aft == NULL) {
        return TM_ECODE_OK;
    }

    SCFree(aft);
    return TM_ECODE_OK;
}

static void CallbackRdpLogDeinitSub(OutputCtx *output_ctx) {
    LogRdpCtx *rdp_ctx = output_ctx->data;

    SCFree(rdp_ctx);
    SCFree(output_ctx);
}

static OutputInitResult CallbackRdpLogInitSub(ConfNode *conf, OutputCtx *parent_ctx) {
    OutputInitResult result = { NULL, false };
    OutputCallbackCtx *occ = parent_ctx->data;

    LogRdpCtx *rdp_ctx = SCCalloc(1, sizeof(LogRdpCtx));
    if (unlikely(rdp_ctx == NULL)) {
        return result;
    }
    memset(rdp_ctx, 0x00, sizeof(*rdp_ctx));
    rdp_ctx->cfg = occ->cfg;

    OutputCtx *output_ctx = SCCalloc(1, sizeof(OutputCtx));
    if (unlikely(output_ctx == NULL)) {
        SCFree(rdp_ctx);
        return result;
    }

    output_ctx->data = rdp_ctx;
    output_ctx->DeInit = CallbackRdpLogDeinitSub;

    AppLayerParserRegisterLogger(IPPROTO_TCP, ALPROTO_RDP);

    result.ctx = output_ctx;
    result.ok = true;
    return result;
}

static int CallbackRdpLogger(ThreadVars *tv, void *thread_data, const Packet *p, Flow *f,
                             void *state, void *tx, uint64_t tx_id) {
    CallbackRdpLogThread *thread = thread_data;

    if (!tv->callbacks->nta) {
        return TM_ECODE_OK;
    }

    JsonBuilder *jb = CreateEveHeader((Packet *)p, LOG_DIR_PACKET, "rdp", NULL, NULL);
    if (unlikely(jb == NULL)) {
        return TM_ECODE_FAILED;
    }

    EveAddCommonOptions(&thread->rdplog_ctx->cfg, p, f, jb);

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
