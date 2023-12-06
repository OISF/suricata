/* Copyright (C) 2023 Open Information Security Foundation
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
 * \author Philippe Antoine
 *
 * Implement JSON/eve logging app-layer WebSockets.
 */

#include "suricata-common.h"
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

#include "output-json-websockets.h"
#include "rust.h"

typedef struct LogWebSocketsFileCtx_ {
    uint32_t flags;
    OutputJsonCtx *eve_ctx;
} LogWebSocketsFileCtx;

typedef struct LogWebSocketsLogThread_ {
    LogWebSocketsFileCtx *websocketslog_ctx;
    OutputJsonThreadCtx *ctx;
} LogWebSocketsLogThread;

static int JsonWebSocketsLogger(ThreadVars *tv, void *thread_data, const Packet *p, Flow *f,
        void *state, void *tx, uint64_t tx_id)
{
    LogWebSocketsLogThread *thread = thread_data;

    JsonBuilder *js = CreateEveHeader(
            p, LOG_DIR_PACKET, "websockets", NULL, thread->websocketslog_ctx->eve_ctx);
    if (unlikely(js == NULL)) {
        return TM_ECODE_FAILED;
    }

    if (!rs_websockets_logger_log(tx, js)) {
        goto error;
    }

    OutputJsonBuilderBuffer(js, thread->ctx);
    jb_free(js);

    return TM_ECODE_OK;

error:
    jb_free(js);
    return TM_ECODE_FAILED;
}

static void OutputWebSocketsLogDeInitCtxSub(OutputCtx *output_ctx)
{
    LogWebSocketsFileCtx *websocketslog_ctx = (LogWebSocketsFileCtx *)output_ctx->data;
    SCFree(websocketslog_ctx);
    SCFree(output_ctx);
}

static OutputInitResult OutputWebSocketsLogInitSub(ConfNode *conf, OutputCtx *parent_ctx)
{
    OutputInitResult result = { NULL, false };
    OutputJsonCtx *ajt = parent_ctx->data;

    LogWebSocketsFileCtx *websocketslog_ctx = SCCalloc(1, sizeof(*websocketslog_ctx));
    if (unlikely(websocketslog_ctx == NULL)) {
        return result;
    }
    websocketslog_ctx->eve_ctx = ajt;

    OutputCtx *output_ctx = SCCalloc(1, sizeof(*output_ctx));
    if (unlikely(output_ctx == NULL)) {
        SCFree(websocketslog_ctx);
        return result;
    }
    output_ctx->data = websocketslog_ctx;
    output_ctx->DeInit = OutputWebSocketsLogDeInitCtxSub;

    AppLayerParserRegisterLogger(IPPROTO_TCP, ALPROTO_WEBSOCKETS);

    result.ctx = output_ctx;
    result.ok = true;
    return result;
}

static TmEcode JsonWebSocketsLogThreadInit(ThreadVars *t, const void *initdata, void **data)
{
    LogWebSocketsLogThread *thread = SCCalloc(1, sizeof(*thread));
    if (unlikely(thread == NULL)) {
        return TM_ECODE_FAILED;
    }

    if (initdata == NULL) {
        SCLogDebug("Error getting context for EveLogWebSockets.  \"initdata\" is NULL.");
        goto error_exit;
    }

    thread->websocketslog_ctx = ((OutputCtx *)initdata)->data;
    thread->ctx = CreateEveThreadCtx(t, thread->websocketslog_ctx->eve_ctx);
    if (!thread->ctx) {
        goto error_exit;
    }
    *data = (void *)thread;

    return TM_ECODE_OK;

error_exit:
    SCFree(thread);
    return TM_ECODE_FAILED;
}

static TmEcode JsonWebSocketsLogThreadDeinit(ThreadVars *t, void *data)
{
    LogWebSocketsLogThread *thread = (LogWebSocketsLogThread *)data;
    if (thread == NULL) {
        return TM_ECODE_OK;
    }
    FreeEveThreadCtx(thread->ctx);
    SCFree(thread);
    return TM_ECODE_OK;
}

void JsonWebSocketsLogRegister(void)
{
    /* Register as an eve sub-module. */
    OutputRegisterTxSubModule(LOGGER_JSON_TX, "eve-log", "JsonWebSocketsLog", "eve-log.websockets",
            OutputWebSocketsLogInitSub, ALPROTO_WEBSOCKETS, JsonWebSocketsLogger,
            JsonWebSocketsLogThreadInit, JsonWebSocketsLogThreadDeinit, NULL);
}
