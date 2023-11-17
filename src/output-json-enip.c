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
 * Implement JSON/eve logging app-layer Enip.
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

#include "output-json-enip.h"
#include "rust.h"

typedef struct LogEnipFileCtx_ {
    uint32_t flags;
    OutputJsonCtx *eve_ctx;
} LogEnipFileCtx;

typedef struct LogEnipLogThread_ {
    LogEnipFileCtx *eniplog_ctx;
    OutputJsonThreadCtx *ctx;
} LogEnipLogThread;

static int JsonEnipLogger(ThreadVars *tv, void *thread_data, const Packet *p, Flow *f, void *state,
        void *tx, uint64_t tx_id)
{
    LogEnipLogThread *thread = thread_data;

    JsonBuilder *js =
            CreateEveHeader(p, LOG_DIR_PACKET, "enip", NULL, thread->eniplog_ctx->eve_ctx);
    if (unlikely(js == NULL)) {
        return TM_ECODE_FAILED;
    }

    if (!rs_enip_logger_log(tx, js)) {
        goto error;
    }

    OutputJsonBuilderBuffer(js, thread->ctx);
    jb_free(js);

    return TM_ECODE_OK;

error:
    jb_free(js);
    return TM_ECODE_FAILED;
}

static void OutputEnipLogDeInitCtxSub(OutputCtx *output_ctx)
{
    LogEnipFileCtx *eniplog_ctx = (LogEnipFileCtx *)output_ctx->data;
    SCFree(eniplog_ctx);
    SCFree(output_ctx);
}

static OutputInitResult OutputEnipLogInitSub(ConfNode *conf, OutputCtx *parent_ctx)
{
    OutputInitResult result = { NULL, false };
    OutputJsonCtx *ajt = parent_ctx->data;

    LogEnipFileCtx *eniplog_ctx = SCCalloc(1, sizeof(*eniplog_ctx));
    if (unlikely(eniplog_ctx == NULL)) {
        return result;
    }
    eniplog_ctx->eve_ctx = ajt;

    OutputCtx *output_ctx = SCCalloc(1, sizeof(*output_ctx));
    if (unlikely(output_ctx == NULL)) {
        SCFree(eniplog_ctx);
        return result;
    }
    output_ctx->data = eniplog_ctx;
    output_ctx->DeInit = OutputEnipLogDeInitCtxSub;

    AppLayerParserRegisterLogger(IPPROTO_UDP, ALPROTO_ENIP);
    AppLayerParserRegisterLogger(IPPROTO_TCP, ALPROTO_ENIP);

    result.ctx = output_ctx;
    result.ok = true;
    return result;
}

static TmEcode JsonEnipLogThreadInit(ThreadVars *t, const void *initdata, void **data)
{
    LogEnipLogThread *thread = SCCalloc(1, sizeof(*thread));
    if (unlikely(thread == NULL)) {
        return TM_ECODE_FAILED;
    }

    if (initdata == NULL) {
        SCLogDebug("Error getting context for EveLogEnip.  \"initdata\" is NULL.");
        goto error_exit;
    }

    thread->eniplog_ctx = ((OutputCtx *)initdata)->data;
    thread->ctx = CreateEveThreadCtx(t, thread->eniplog_ctx->eve_ctx);
    if (!thread->ctx) {
        goto error_exit;
    }
    *data = (void *)thread;

    return TM_ECODE_OK;

error_exit:
    SCFree(thread);
    return TM_ECODE_FAILED;
}

static TmEcode JsonEnipLogThreadDeinit(ThreadVars *t, void *data)
{
    LogEnipLogThread *thread = (LogEnipLogThread *)data;
    if (thread == NULL) {
        return TM_ECODE_OK;
    }
    FreeEveThreadCtx(thread->ctx);
    SCFree(thread);
    return TM_ECODE_OK;
}

void JsonEnipLogRegister(void)
{
    /* Register as an eve sub-module. */
    OutputRegisterTxSubModule(LOGGER_JSON_TX, "eve-log", "JsonEnipLog", "eve-log.enip",
            OutputEnipLogInitSub, ALPROTO_ENIP, JsonEnipLogger, JsonEnipLogThreadInit,
            JsonEnipLogThreadDeinit, NULL);
}
