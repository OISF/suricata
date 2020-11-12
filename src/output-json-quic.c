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
 * Implements JSON/eve logging for Quic app-layer.
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

#include "output-json-quic.h"
#include "rust.h"

typedef struct LogQuicFileCtx_ {
    LogFileCtx *file_ctx;
    uint32_t flags;
} LogQuicFileCtx;

typedef struct LogQuicLogThread_ {
    LogQuicFileCtx *quiclog_ctx;
    uint32_t count;
    MemBuffer *buffer;
} LogQuicLogThread;

static int JsonQuicLogger(ThreadVars *tv, void *thread_data, const Packet *p, Flow *f, void *state,
        void *tx, uint64_t tx_id)
{
    LogQuicLogThread *thread = thread_data;

    JsonBuilder *js = CreateEveHeader(p, LOG_DIR_PACKET, "quic", NULL);
    if (unlikely(js == NULL)) {
        return TM_ECODE_FAILED;
    }

    jb_open_object(js, "quic");

    rs_quic_logger_log(tx, js);

    jb_close(js);

    MemBufferReset(thread->buffer);
    OutputJsonBuilderBuffer(js, thread->quiclog_ctx->file_ctx, &thread->buffer);

    jb_free(js);
    return TM_ECODE_OK;
}

static void OutputQuicLogDeInitCtxSub(OutputCtx *output_ctx)
{
    LogQuicFileCtx *quiclog_ctx = (LogQuicFileCtx *)output_ctx->data;
    SCFree(quiclog_ctx);
    SCFree(output_ctx);
}

static OutputInitResult OutputQuicLogInitSub(ConfNode *conf, OutputCtx *parent_ctx)
{
    OutputInitResult result = { NULL, false };
    OutputJsonCtx *ajt = parent_ctx->data;

    LogQuicFileCtx *quiclog_ctx = SCCalloc(1, sizeof(*quiclog_ctx));
    if (unlikely(quiclog_ctx == NULL)) {
        return result;
    }
    quiclog_ctx->file_ctx = ajt->file_ctx;

    OutputCtx *output_ctx = SCCalloc(1, sizeof(*output_ctx));
    if (unlikely(output_ctx == NULL)) {
        SCFree(quiclog_ctx);
        return result;
    }
    output_ctx->data = quiclog_ctx;
    output_ctx->DeInit = OutputQuicLogDeInitCtxSub;

    AppLayerParserRegisterLogger(IPPROTO_UDP, ALPROTO_QUIC);

    result.ctx = output_ctx;
    result.ok = true;
    return result;
}

static TmEcode JsonQuicLogThreadInit(ThreadVars *t, const void *initdata, void **data)
{
    LogQuicLogThread *thread = SCCalloc(1, sizeof(*thread));
    if (unlikely(thread == NULL)) {
        return TM_ECODE_FAILED;
    }

    if (initdata == NULL) {
        SCLogDebug("Error getting context for EveLogQuic.  \"initdata\" is NULL.");
        SCFree(thread);
        return TM_ECODE_FAILED;
    }

    thread->buffer = MemBufferCreateNew(JSON_OUTPUT_BUFFER_SIZE);
    if (unlikely(thread->buffer == NULL)) {
        SCFree(thread);
        return TM_ECODE_FAILED;
    }

    thread->quiclog_ctx = ((OutputCtx *)initdata)->data;
    *data = (void *)thread;

    return TM_ECODE_OK;
}

static TmEcode JsonQuicLogThreadDeinit(ThreadVars *t, void *data)
{
    LogQuicLogThread *thread = (LogQuicLogThread *)data;
    if (thread == NULL) {
        return TM_ECODE_OK;
    }
    if (thread->buffer != NULL) {
        MemBufferFree(thread->buffer);
    }
    SCFree(thread);
    return TM_ECODE_OK;
}

void JsonQuicLogRegister(void)
{
    if (ConfGetNode("app-layer.protocols.quic") == NULL) {
        return;
    }

    /* Register as an eve sub-module. */
    OutputRegisterTxSubModule(LOGGER_JSON_QUIC, "eve-log", "JsonQuicLog", "eve-log.quic",
            OutputQuicLogInitSub, ALPROTO_QUIC, JsonQuicLogger, JsonQuicLogThreadInit,
            JsonQuicLogThreadDeinit, NULL);
}
