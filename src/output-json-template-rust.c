/* Copyright (C) 2018 Open Information Security Foundation
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
#include "debug.h"
#include "detect.h"
#include "pkt-var.h"
#include "conf.h"

#include "threads.h"
#include "threadvars.h"
#include "tm-threads.h"

#include "util-unittest.h"
#include "util-buffer.h"
#include "util-debug.h"
#include "util-byte.h"

#include "output.h"
#include "output-json.h"

#include "app-layer.h"
#include "app-layer-parser.h"

#include "app-layer-template-rust.h"
#include "output-json-template-rust.h"

#if defined(HAVE_LIBJANSSON) && defined(HAVE_RUST)

#include "rust-applayertemplate-logger-gen.h"

typedef struct LogTemplateFileCtx_ {
    LogFileCtx *file_ctx;
    uint32_t    flags;
} LogTemplateFileCtx;

typedef struct LogTemplateLogThread_ {
    LogTemplateFileCtx *templatelog_ctx;
    uint32_t            count;
    MemBuffer          *buffer;
} LogTemplateLogThread;

static int JsonTemplateLogger(ThreadVars *tv, void *thread_data,
    const Packet *p, Flow *f, void *state, void *tx, uint64_t tx_id)
{
    SCLogNotice("JsonTemplateLogger");
    LogTemplateLogThread *thread = thread_data;

    json_t *js = CreateJSONHeader(p, LOG_DIR_PACKET, "template-rust");
    if (unlikely(js == NULL)) {
        return TM_ECODE_FAILED;
    }

    json_t *template_js = rs_template_logger_log(tx);
    if (unlikely(template_js == NULL)) {
        goto error;
    }
    json_object_set_new(js, "template", template_js);

    MemBufferReset(thread->buffer);
    OutputJSONBuffer(js, thread->templatelog_ctx->file_ctx, &thread->buffer);
    json_decref(js);

    return TM_ECODE_OK;

error:
    json_decref(js);
    return TM_ECODE_FAILED;
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
    templatelog_ctx->file_ctx = ajt->file_ctx;

    OutputCtx *output_ctx = SCCalloc(1, sizeof(*output_ctx));
    if (unlikely(output_ctx == NULL)) {
        SCFree(templatelog_ctx);
        return result;
    }
    output_ctx->data = templatelog_ctx;
    output_ctx->DeInit = OutputTemplateLogDeInitCtxSub;

    SCLogNotice("Template log sub-module initialized.");

    AppLayerParserRegisterLogger(IPPROTO_TCP, ALPROTO_TEMPLATE_RUST);

    result.ctx = output_ctx;
    result.ok = true;
    return result;
}

#define OUTPUT_BUFFER_SIZE 65535

static TmEcode JsonTemplateLogThreadInit(ThreadVars *t, const void *initdata, void **data)
{
    LogTemplateLogThread *thread = SCCalloc(1, sizeof(*thread));
    if (unlikely(thread == NULL)) {
        return TM_ECODE_FAILED;
    }

    if (initdata == NULL) {
        SCLogDebug("Error getting context for EveLogTemplate.  \"initdata\" is NULL.");
        SCFree(thread);
        return TM_ECODE_FAILED;
    }

    thread->buffer = MemBufferCreateNew(OUTPUT_BUFFER_SIZE);
    if (unlikely(thread->buffer == NULL)) {
        SCFree(thread);
        return TM_ECODE_FAILED;
    }

    thread->templatelog_ctx = ((OutputCtx *)initdata)->data;
    *data = (void *)thread;

    return TM_ECODE_OK;
}

static TmEcode JsonTemplateLogThreadDeinit(ThreadVars *t, void *data)
{
    LogTemplateLogThread *thread = (LogTemplateLogThread *)data;
    if (thread == NULL) {
        return TM_ECODE_OK;
    }
    if (thread->buffer != NULL) {
        MemBufferFree(thread->buffer);
    }
    SCFree(thread);
    return TM_ECODE_OK;
}

void JsonTemplateRustLogRegister(void)
{
    /* TEMPLATE_START_REMOVE */
    if (ConfGetNode("app-layer.protocols.template-rust") == NULL) {
        return;
    }
    /* TEMPLATE_END_REMOVE */
    /* Register as an eve sub-module. */
    OutputRegisterTxSubModule(LOGGER_JSON_TEMPLATE_RUST, "eve-log",
        "JsonTemplateRustLog", "eve-log.template-rust",
        OutputTemplateLogInitSub, ALPROTO_TEMPLATE_RUST, JsonTemplateLogger,
        JsonTemplateLogThreadInit, JsonTemplateLogThreadDeinit, NULL);

    SCLogNotice("Template JSON logger registered.");
}

#else /* No JSON support. */

void JsonTemplateRustLogRegister(void)
{
}

#endif /* HAVE_LIBJANSSON */
