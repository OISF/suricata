/* Copyright (C) 2015-2021 Open Information Security Foundation
 *
 * You can copy, redistribute or modify this Program under the terms of
 * the GNU General Public License version 2 as published by the Free
 * Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 */

/*
 * TODO: Update \author in this file and in output-json-template.h.
 * TODO: Remove SCLogNotice statements, or convert to debug.
 * TODO: Implement your app-layers logging.
 */

/**
 * \file
 *
 * \author FirstName LastName <yourname@domain>
 *
 * Implement JSON/eve logging app-layer Template.
 */

#include "suricata-common.h"

#include "output-json.h"

#include "app-layer-parser.h"

#include "app-layer-template.h"
#include "output-json-template.h"

typedef struct LogTemplateFileCtx_ {
    uint32_t    flags;
    OutputJsonCtx *eve_ctx;
} LogTemplateFileCtx;

typedef struct LogTemplateLogThread_ {
    LogTemplateFileCtx *templatelog_ctx;
    OutputJsonThreadCtx *ctx;
} LogTemplateLogThread;

static int JsonTemplateLogger(ThreadVars *tv, void *thread_data,
    const Packet *p, Flow *f, void *state, void *tx, uint64_t tx_id)
{
    TemplateTransaction *templatetx = tx;
    LogTemplateLogThread *thread = thread_data;

    SCLogNotice("Logging template transaction %"PRIu64".", templatetx->tx_id);

    JsonBuilder *js =
            CreateEveHeader(p, LOG_DIR_PACKET, "template", NULL, thread->templatelog_ctx->eve_ctx);
    if (unlikely(js == NULL)) {
        return TM_ECODE_FAILED;
    }

    jb_open_object(js, "template");

    /* Log the request buffer. */
    if (templatetx->request_buffer != NULL) {
        jb_set_string_from_bytes(js, "request", templatetx->request_buffer,
                templatetx->request_buffer_len);
    }

    /* Log the response buffer. */
    if (templatetx->response_buffer != NULL) {
        jb_set_string_from_bytes(js, "response", templatetx->response_buffer,
                templatetx->response_buffer_len);
    }

    /* Close template. */
    jb_close(js);

    OutputJsonBuilderBuffer(js, thread->ctx);

    jb_free(js);
    return TM_ECODE_OK;
}

static void OutputTemplateLogDeInitCtxSub(OutputCtx *output_ctx)
{
    LogTemplateFileCtx *templatelog_ctx = (LogTemplateFileCtx *)output_ctx->data;
    SCFree(templatelog_ctx);
    SCFree(output_ctx);
}

static OutputInitResult OutputTemplateLogInitSub(ConfNode *conf,
    OutputCtx *parent_ctx)
{
    OutputInitResult result = { NULL, false };
    OutputJsonCtx *ajt = parent_ctx->data;

    LogTemplateFileCtx *templatelog_ctx = SCCalloc(1, sizeof(*templatelog_ctx));
    if (unlikely(templatelog_ctx == NULL)) {
        return result;
    }
    templatelog_ctx->eve_ctx = ajt;

    OutputCtx *output_ctx = SCCalloc(1, sizeof(*output_ctx));
    if (unlikely(output_ctx == NULL)) {
        SCFree(templatelog_ctx);
        return result;
    }
    output_ctx->data = templatelog_ctx;
    output_ctx->DeInit = OutputTemplateLogDeInitCtxSub;

    SCLogNotice("Template log sub-module initialized.");

    AppLayerParserRegisterLogger(IPPROTO_TCP, ALPROTO_TEMPLATE);

    result.ctx = output_ctx;
    result.ok = true;
    return result;
}

static TmEcode JsonTemplateLogThreadInit(ThreadVars *t, const void *initdata, void **data)
{
    LogTemplateLogThread *thread = SCCalloc(1, sizeof(*thread));
    if (unlikely(thread == NULL)) {
        return TM_ECODE_FAILED;
    }

    if (initdata == NULL) {
        SCLogDebug("Error getting context for EveLogTemplate.  \"initdata\" is NULL.");
        goto error_exit;
    }

    thread->templatelog_ctx = ((OutputCtx *)initdata)->data;
    thread->ctx = CreateEveThreadCtx(t, thread->templatelog_ctx->eve_ctx);
    if (!thread->ctx) {
        goto error_exit;
    }
    *data = (void *)thread;

    return TM_ECODE_OK;

error_exit:
    SCFree(thread);
    return TM_ECODE_FAILED;
}

static TmEcode JsonTemplateLogThreadDeinit(ThreadVars *t, void *data)
{
    LogTemplateLogThread *thread = (LogTemplateLogThread *)data;
    if (thread == NULL) {
        return TM_ECODE_OK;
    }
    FreeEveThreadCtx(thread->ctx);
    SCFree(thread);
    return TM_ECODE_OK;
}

void JsonTemplateLogRegister(void)
{
    /* TEMPLATE_START_REMOVE */
    if (ConfGetNode("app-layer.protocols.template") == NULL) {
        return;
    }
    /* TEMPLATE_END_REMOVE */
    /* Register as an eve sub-module. */
    OutputRegisterTxSubModule(LOGGER_JSON_TEMPLATE, "eve-log", "JsonTemplateLog",
        "eve-log.template", OutputTemplateLogInitSub, ALPROTO_TEMPLATE,
        JsonTemplateLogger, JsonTemplateLogThreadInit,
        JsonTemplateLogThreadDeinit, NULL);

    SCLogNotice("Template JSON logger registered.");
}
