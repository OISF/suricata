/* Copyright (C) 2020 Open Information Security Foundation
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

/**
 * \file
 *
 * \author Philippe Antoine <p.antoine@catenacyber.fr>
 *
 * Implements HTTP2 JSON logging portion of the engine.
 */

#include "suricata-common.h"
#include "debug.h"
#include "detect.h"
#include "pkt-var.h"
#include "conf.h"

#include "threads.h"
#include "threadvars.h"
#include "tm-threads.h"

#include "util-print.h"
#include "util-unittest.h"

#include "util-debug.h"
#include "app-layer-parser.h"
#include "output.h"
#include "app-layer-http2.h"
#include "app-layer.h"
#include "util-privs.h"
#include "util-buffer.h"

#include "util-logopenfile.h"
#include "util-crypt.h"

#include "output-json.h"
#include "output-json-http2.h"
#include "rust.h"

#define MODULE_NAME "LogHttp2Log"

//TODO Cannot this be generic ? and most of the file as well
typedef struct OutputHttp2Ctx_ {
    LogFileCtx *file_ctx;
    OutputJsonCommonSettings cfg;
} OutputHttp2Ctx;


typedef struct JsonHttp2LogThread_ {
    OutputHttp2Ctx *http2log_ctx;
    MemBuffer *buffer;
} JsonHttp2LogThread;


static int JsonHttp2Logger(ThreadVars *tv, void *thread_data, const Packet *p,
                         Flow *f, void *state, void *txptr, uint64_t tx_id)
{
    JsonHttp2LogThread *aft = (JsonHttp2LogThread *)thread_data;
    OutputHttp2Ctx *http2_ctx = aft->http2log_ctx;

    if (unlikely(state == NULL)) {
        return 0;
    }

    json_t *js = CreateJSONHeader(p, LOG_DIR_FLOW, "http2");
    if (unlikely(js == NULL))
        return 0;

    JsonAddCommonOptions(&http2_ctx->cfg, p, f, js);

    /* reset */
    MemBufferReset(aft->buffer);

    json_t *tjs = rs_http2_log_json(txptr);
    if (unlikely(tjs == NULL)) {
        free(js);
        return 0;
    }
    json_object_set_new(js, "http2", tjs);

    OutputJSONBuffer(js, http2_ctx->file_ctx, &aft->buffer);
    json_object_clear(js);
    json_decref(js);

    return 0;
}

static TmEcode JsonHttp2LogThreadInit(ThreadVars *t, const void *initdata, void **data)
{
    JsonHttp2LogThread *aft = SCMalloc(sizeof(JsonHttp2LogThread));
    if (unlikely(aft == NULL))
        return TM_ECODE_FAILED;
    memset(aft, 0, sizeof(JsonHttp2LogThread));

    if(initdata == NULL)
    {
        SCLogDebug("Error getting context for EveLogHTTP2.  \"initdata\" argument NULL");
        SCFree(aft);
        return TM_ECODE_FAILED;
    }

    /* Use the Ouptut Context (file pointer and mutex) */
    aft->http2log_ctx = ((OutputCtx *)initdata)->data;

    aft->buffer = MemBufferCreateNew(JSON_OUTPUT_BUFFER_SIZE);
    if (aft->buffer == NULL) {
        SCFree(aft);
        return TM_ECODE_FAILED;
    }

    *data = (void *)aft;
    return TM_ECODE_OK;
}

static TmEcode JsonHttp2LogThreadDeinit(ThreadVars *t, void *data)
{
    JsonHttp2LogThread *aft = (JsonHttp2LogThread *)data;
    if (aft == NULL) {
        return TM_ECODE_OK;
    }

    MemBufferFree(aft->buffer);
    /* clear memory */
    memset(aft, 0, sizeof(JsonHttp2LogThread));

    SCFree(aft);
    return TM_ECODE_OK;
}

static void OutputHttp2LogDeinit(OutputCtx *output_ctx)
{
    OutputHttp2Ctx *http2_ctx = output_ctx->data;
    LogFileCtx *logfile_ctx = http2_ctx->file_ctx;
    LogFileFreeCtx(logfile_ctx);
    SCFree(http2_ctx);
    SCFree(output_ctx);
}

#define DEFAULT_LOG_FILENAME "http2.json"
static OutputInitResult OutputHttp2LogInit(ConfNode *conf)
{
    OutputInitResult result = { NULL, false };
    LogFileCtx *file_ctx = LogFileNewCtx();
    if(file_ctx == NULL) {
        SCLogError(SC_ERR_HTTP2_LOG_GENERIC, "couldn't create new file_ctx");
        return result;
    }

    if (SCConfLogOpenGeneric(conf, file_ctx, DEFAULT_LOG_FILENAME, 1) < 0) {
        LogFileFreeCtx(file_ctx);
        return result;
    }

    OutputHttp2Ctx *http2_ctx = SCMalloc(sizeof(OutputHttp2Ctx));
    if (unlikely(http2_ctx == NULL)) {
        LogFileFreeCtx(file_ctx);
        return result;
    }

    OutputCtx *output_ctx = SCCalloc(1, sizeof(OutputCtx));
    if (unlikely(output_ctx == NULL)) {
        LogFileFreeCtx(file_ctx);
        SCFree(http2_ctx);
        return result;
    }

    http2_ctx->file_ctx = file_ctx;

    output_ctx->data = http2_ctx;
    output_ctx->DeInit = OutputHttp2LogDeinit;

    AppLayerParserRegisterLogger(IPPROTO_TCP, ALPROTO_HTTP2);

    result.ctx = output_ctx;
    result.ok = true;
    return result;
}

static void OutputHttp2LogDeinitSub(OutputCtx *output_ctx)
{
    OutputHttp2Ctx *http2_ctx = output_ctx->data;
    SCFree(http2_ctx);
    SCFree(output_ctx);
}

static OutputInitResult OutputHttp2LogInitSub(ConfNode *conf, OutputCtx *parent_ctx)
{
    OutputInitResult result = { NULL, false };
    OutputJsonCtx *ojc = parent_ctx->data;

    OutputHttp2Ctx *http2_ctx = SCMalloc(sizeof(OutputHttp2Ctx));
    if (unlikely(http2_ctx == NULL))
        return result;

    OutputCtx *output_ctx = SCCalloc(1, sizeof(OutputCtx));
    if (unlikely(output_ctx == NULL)) {
        SCFree(http2_ctx);
        return result;
    }

    http2_ctx->file_ctx = ojc->file_ctx;
    http2_ctx->cfg = ojc->cfg;

    output_ctx->data = http2_ctx;
    output_ctx->DeInit = OutputHttp2LogDeinitSub;

    AppLayerParserRegisterLogger(IPPROTO_TCP, ALPROTO_HTTP2);

    result.ctx = output_ctx;
    result.ok = true;
    return result;
}

void JsonHttp2LogRegister (void)
{
    /* register as separate module */
    OutputRegisterTxModuleWithProgress(LOGGER_JSON_HTTP2,
        MODULE_NAME, "http2-json-log",
        OutputHttp2LogInit, ALPROTO_HTTP2, JsonHttp2Logger,
        1, 1, //TODO progress
        JsonHttp2LogThreadInit, JsonHttp2LogThreadDeinit, NULL);

    /* also register as child of eve-log */
    OutputRegisterTxSubModuleWithProgress(LOGGER_JSON_HTTP2,
        "eve-log", MODULE_NAME, "eve-log.http2",
        OutputHttp2LogInitSub, ALPROTO_HTTP2, JsonHttp2Logger,
        1, 1,
        JsonHttp2LogThreadInit, JsonHttp2LogThreadDeinit, NULL);
}
