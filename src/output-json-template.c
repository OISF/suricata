/* Copyright (C) 2015 Open Information Security Foundation
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

#include "app-layer-template.h"
#include "output-json-template.h"

#ifdef HAVE_LIBJANSSON

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
    TemplateTransaction *templatetx = tx;
    LogTemplateLogThread *thread = thread_data;
    json_t *js, *templatejs;

    SCLogNotice("Logging template transaction %"PRIu64".", templatetx->tx_id);
    
    js = CreateJSONHeader((Packet *)p, 0, "template");
    if (unlikely(js == NULL)) {
        return TM_ECODE_FAILED;
    }

    templatejs = json_object();
    if (unlikely(templatejs == NULL)) {
        goto error;
    }

    /* Convert the request buffer to a string then log. */
    char *request_buffer = BytesToString(templatetx->request_buffer,
        templatetx->request_buffer_len);
    if (request_buffer != NULL) {
        json_object_set_new(templatejs, "request", json_string(request_buffer));
        SCFree(request_buffer);
    }

    /* Convert the response buffer to a string then log. */
    char *response_buffer = BytesToString(templatetx->response_buffer,
        templatetx->response_buffer_len);
    if (response_buffer != NULL) {
        json_object_set_new(templatejs, "response",
            json_string(response_buffer));
        SCFree(response_buffer);
    }

    json_object_set_new(js, "template", templatejs);

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

static OutputCtx *OutputTemplateLogInitSub(ConfNode *conf,
    OutputCtx *parent_ctx)
{
    AlertJsonThread *ajt = parent_ctx->data;

    LogTemplateFileCtx *templatelog_ctx = SCCalloc(1, sizeof(*templatelog_ctx));
    if (unlikely(templatelog_ctx == NULL)) {
        return NULL;
    }
    templatelog_ctx->file_ctx = ajt->file_ctx;

    OutputCtx *output_ctx = SCCalloc(1, sizeof(*output_ctx));
    if (unlikely(output_ctx == NULL)) {
        SCFree(templatelog_ctx);
        return NULL;
    }
    output_ctx->data = templatelog_ctx;
    output_ctx->DeInit = OutputTemplateLogDeInitCtxSub;

    SCLogNotice("Template log sub-module initialized.");

    AppLayerParserRegisterLogger(IPPROTO_TCP, ALPROTO_TEMPLATE);

    return output_ctx;
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

#else /* No JSON support. */

void JsonTemplateLogRegister(void)
{
}

#endif /* HAVE_LIBJANSSON */
