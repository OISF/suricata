/**
 * \file
 *
 * \author Angelo Mirabella <mirabellaa@vmware.com>
 *
 * Generate DHCP events and invoke corresponding callback (NTA).
 *
 */
#include "output-callback.h"
#include "output-callback-dhcp.h"
#include "suricata-common.h"
#include "app-layer-parser.h"
#include "output-json.h"
#include "rust.h"

#define MODULE_NAME "CallbackDHCPLog"

typedef struct CallbackDHCPCtx {
    uint32_t flags;
    void  *rs_logger;
    OutputCallbackCommonSettings cfg;
} CallbackDHCPCtx;

typedef struct CallbackDHCPLogThread {
    CallbackDHCPCtx *dhcplog_ctx;
} CallbackDHCPLogThread;

static TmEcode CallbackDHCPLogThreadInit(ThreadVars *t, const void *initdata, void **data) {
    CallbackDHCPLogThread *thread = SCCalloc(1, sizeof(*thread));
    if (unlikely(thread == NULL)) {
        return TM_ECODE_FAILED;
    }

    if (initdata == NULL) {
        SCLogDebug("Error getting context for EveCallbackDHCP.  \"initdata\" is NULL.");
        return TM_ECODE_FAILED;
    }

    thread->dhcplog_ctx = ((OutputCtx *)initdata)->data;

    *data = (void *)thread;
    return TM_ECODE_OK;
}

static TmEcode CallbackDHCPLogThreadDeinit(ThreadVars *t, void *data) {
    CallbackDHCPLogThread *thread = (CallbackDHCPLogThread *)data;
    if (thread == NULL) {
        return TM_ECODE_OK;
    }

    SCFree(thread);
    return TM_ECODE_OK;
}

static void OutputDHCPCallbackDeInitCtxSub(OutputCtx *output_ctx) {
    CallbackDHCPCtx *dhcplog_ctx = (CallbackDHCPCtx *)output_ctx->data;
    rs_dhcp_logger_free(dhcplog_ctx->rs_logger);
    SCFree(dhcplog_ctx);
    SCFree(output_ctx);
}

static OutputInitResult CallbackDHCPLogInitSub(ConfNode *conf, OutputCtx *parent_ctx) {
    OutputInitResult result = { NULL, false };
    OutputCallbackCtx *occ = parent_ctx->data;

    CallbackDHCPCtx *dhcplog_ctx = SCCalloc(1, sizeof(*dhcplog_ctx));
    if (unlikely(dhcplog_ctx == NULL)) {
        return result;
    }
    dhcplog_ctx->cfg = occ->cfg;

    OutputCtx *output_ctx = SCCalloc(1, sizeof(*output_ctx));
    if (unlikely(output_ctx == NULL)) {
        SCFree(dhcplog_ctx);
        return result;
    }

    output_ctx->data = dhcplog_ctx;
    output_ctx->DeInit = OutputDHCPCallbackDeInitCtxSub;

    dhcplog_ctx->rs_logger = rs_dhcp_logger_new(conf);

    AppLayerParserRegisterLogger(IPPROTO_UDP, ALPROTO_DHCP);

    result.ctx = output_ctx;
    result.ok = true;
    return result;
}

static int CallbackDHCPLogger(ThreadVars *tv, void *thread_data, const Packet *p, Flow *f,
                             void *state, void *tx, uint64_t tx_id) {
    CallbackDHCPLogThread *thread = thread_data;
    CallbackDHCPCtx *ctx = thread->dhcplog_ctx;

    if (!tv->callbacks->nta) {
        return TM_ECODE_OK;
    }

    if (!rs_dhcp_logger_do_log(ctx->rs_logger, tx)) {
        return TM_ECODE_OK;
    }

    JsonBuilder *jb = CreateEveHeader((Packet *)p, 0, "dhcp", NULL, NULL);
    if (unlikely(jb == NULL)) {
        return TM_ECODE_FAILED;
    }

    EveAddCommonOptions(&ctx->cfg, p, f, jb);
    rs_dhcp_logger_log(ctx->rs_logger, tx, jb);

    /* Close log line. */
    jb_close(jb);

    /* Invoke NTA callback. */
    tv->callbacks->nta((void *)jb_ptr(jb), jb_len(jb), "dhcp", f->tenant_uuid, f->user_ctx);

    jb_free(jb);
    return TM_ECODE_OK;
}

void CallbackDHCPLogRegister(void) {
    /* Register as an eve sub-module. */
    OutputRegisterTxSubModule(LOGGER_CALLBACK_TX, "callback", MODULE_NAME, "callback.nta.dhcp",
                              CallbackDHCPLogInitSub, ALPROTO_DHCP, CallbackDHCPLogger,
                              CallbackDHCPLogThreadInit, CallbackDHCPLogThreadDeinit, NULL);
}
