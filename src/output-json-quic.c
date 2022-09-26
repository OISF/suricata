/* Copyright (C) 2021 Open Information Security Foundation
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
#include "output-json.h"
#include "app-layer-parser.h"
#include "output-json-quic.h"

typedef struct LogQuicFileCtx_ {
    LogFileCtx *file_ctx;
    OutputJsonCtx *eve_ctx;
} LogQuicFileCtx;

typedef struct JsonQuicLogThread_ {
    LogQuicFileCtx *quiclog_ctx;
    OutputJsonThreadCtx *ctx;
} JsonQuicLogThread;

static int JsonQuicLogger(ThreadVars *tv, void *thread_data, const Packet *p, Flow *f, void *state,
        void *tx, uint64_t tx_id)
{
    JsonQuicLogThread *thread = thread_data;

    JsonBuilder *js =
            CreateEveHeader(p, LOG_DIR_PACKET, "quic", NULL, thread->quiclog_ctx->eve_ctx);
    if (unlikely(js == NULL)) {
        return TM_ECODE_OK;
    }
    if (!rs_quic_to_json(tx, js)) {
        jb_free(js);
        return TM_ECODE_FAILED;
    }
    OutputJsonBuilderBuffer(js, thread->ctx);

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
    quiclog_ctx->eve_ctx = ajt;

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
    if (initdata == NULL) {
        SCLogDebug("Error getting context for EveLogQuic. \"initdata\" is NULL.");
        return TM_ECODE_FAILED;
    }

    JsonQuicLogThread *thread = SCCalloc(1, sizeof(*thread));
    if (unlikely(thread == NULL)) {
        return TM_ECODE_FAILED;
    }

    thread->quiclog_ctx = ((OutputCtx *)initdata)->data;
    thread->ctx = CreateEveThreadCtx(t, thread->quiclog_ctx->eve_ctx);
    if (thread->ctx == NULL) {
        goto error_exit;
    }

    *data = (void *)thread;
    return TM_ECODE_OK;

error_exit:
    SCFree(thread);
    return TM_ECODE_FAILED;
}

static TmEcode JsonQuicLogThreadDeinit(ThreadVars *t, void *data)
{
    JsonQuicLogThread *thread = (JsonQuicLogThread *)data;
    if (thread == NULL) {
        return TM_ECODE_OK;
    }
    FreeEveThreadCtx(thread->ctx);
    SCFree(thread);
    return TM_ECODE_OK;
}

bool JsonQuicAddMetadata(const Flow *f, uint64_t tx_id, JsonBuilder *js)
{
    void *state = FlowGetAppState(f);
    if (state) {
        void *tx = AppLayerParserGetTx(f->proto, ALPROTO_QUIC, state, tx_id);
        if (tx) {
            return rs_quic_to_json(tx, js);
        }
    }

    return false;
}

void JsonQuicLogRegister(void)
{
    /* Register as an eve sub-module. */
    OutputRegisterTxSubModule(LOGGER_JSON_QUIC, "eve-log", "JsonQuicLog", "eve-log.quic",
            OutputQuicLogInitSub, ALPROTO_QUIC, JsonQuicLogger, JsonQuicLogThreadInit,
            JsonQuicLogThreadDeinit, NULL);

    SCLogDebug("quic json logger registered.");
}
