/* Copyright (C) 2022-2024 Open Information Security Foundation
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
 * \author Juliana Fajardini <jufajardini@oisf.net>
 *
 * Implement JSON/eve logging app-layer Stun.
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

#include "output-json-stun.h"
#include "rust.h"

typedef struct LogStunFileCtx_ {
    uint32_t flags;
    OutputJsonCtx *eve_ctx;
} LogStunFileCtx;

typedef struct LogStunLogThread_ {
    LogStunFileCtx *stunlog_ctx;
    OutputJsonThreadCtx *ctx;
} LogStunLogThread;

static int JsonStunLogger(ThreadVars *tv, void *thread_data, const Packet *p, Flow *f, void *state,
        void *tx, uint64_t tx_id)
{
    SCLogDebug("JsonStunLogger");
    LogStunLogThread *thread = thread_data;

    JsonBuilder *js =
            CreateEveHeader(p, LOG_DIR_PACKET, "stun", NULL, thread->stunlog_ctx->eve_ctx);
    if (unlikely(js == NULL)) {
        return TM_ECODE_FAILED;
    }

    jb_open_object(js, "stun");
    if (!SCStunLoggerLog(tx, js)) {
        goto error;
    }
    jb_close(js);

    OutputJsonBuilderBuffer(js, thread->ctx);
    jb_free(js);

    return TM_ECODE_OK;

error:
    jb_free(js);
    return TM_ECODE_FAILED;
}

static void OutputStunLogDeInitCtxSub(OutputCtx *output_ctx)
{
    LogStunFileCtx *stunlog_ctx = (LogStunFileCtx *)output_ctx->data;
    SCFree(stunlog_ctx);
    SCFree(output_ctx);
}

static OutputInitResult OutputStunLogInitSub(ConfNode *conf, OutputCtx *parent_ctx)
{
    OutputInitResult result = { NULL, false };
    OutputJsonCtx *ajt = parent_ctx->data;

    LogStunFileCtx *stunlog_ctx = SCCalloc(1, sizeof(*stunlog_ctx));
    if (unlikely(stunlog_ctx == NULL)) {
        return result;
    }
    stunlog_ctx->eve_ctx = ajt;

    OutputCtx *output_ctx = SCCalloc(1, sizeof(*output_ctx));
    if (unlikely(output_ctx == NULL)) {
        SCFree(stunlog_ctx);
        return result;
    }
    output_ctx->data = stunlog_ctx;
    output_ctx->DeInit = OutputStunLogDeInitCtxSub;

    SCLogNotice("Stun log sub-module initialized.");

    AppLayerParserRegisterLogger(IPPROTO_UDP, ALPROTO_STUN);

    result.ctx = output_ctx;
    result.ok = true;
    return result;
}

static TmEcode JsonStunLogThreadInit(ThreadVars *t, const void *initdata, void **data)
{
    LogStunLogThread *thread = SCCalloc(1, sizeof(*thread));
    if (unlikely(thread == NULL)) {
        return TM_ECODE_FAILED;
    }

    if (initdata == NULL) {
        SCLogDebug("Error getting context for EveLogStun.  \"initdata\" is NULL.");
        goto error_exit;
    }

    thread->stunlog_ctx = ((OutputCtx *)initdata)->data;
    thread->ctx = CreateEveThreadCtx(t, thread->stunlog_ctx->eve_ctx);
    if (!thread->ctx) {
        goto error_exit;
    }
    *data = (void *)thread;

    return TM_ECODE_OK;

error_exit:
    SCFree(thread);
    return TM_ECODE_FAILED;
}

static TmEcode JsonStunLogThreadDeinit(ThreadVars *t, void *data)
{
    LogStunLogThread *thread = (LogStunLogThread *)data;
    if (thread == NULL) {
        return TM_ECODE_OK;
    }
    FreeEveThreadCtx(thread->ctx);
    SCFree(thread);
    return TM_ECODE_OK;
}

void JsonStunLogRegister(void)
{
    /* Register as an eve sub-module. */
    OutputRegisterTxSubModule(LOGGER_JSON_TX, "eve-log", "JsonStunLog", "eve-log.stun",
            OutputStunLogInitSub, ALPROTO_STUN, JsonStunLogger, JsonStunLogThreadInit,
            JsonStunLogThreadDeinit, NULL);

    SCLogNotice("Stun JSON logger registered.");
}
