/* Copyright (C) 2018-2021 Open Information Security Foundation
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
 * \author Alex Savage <alexander.savage@cyber.gc.ca>
 *
 * Implement JSON/eve logging app-layer POP3.
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

#include "app-layer-pop3.h"
#include "output-json-pop3.h"
#include "rust.h"

typedef struct LogPOP3FileCtx_ {
    uint32_t flags;
    OutputJsonCtx *eve_ctx;
} LogPOP3FileCtx;

typedef struct LogPOP3LogThread_ {
    LogPOP3FileCtx *pop3log_ctx;
    OutputJsonThreadCtx *ctx;
} LogPOP3LogThread;

static int JsonPOP3Logger(ThreadVars *tv, void *thread_data, const Packet *p, Flow *f, void *state,
        void *tx, uint64_t tx_id)
{
    SCLogNotice("JsonPOP3Logger");
    LogPOP3LogThread *thread = thread_data;

    JsonBuilder *js =
            CreateEveHeader(p, LOG_DIR_PACKET, "pop3", NULL, thread->pop3log_ctx->eve_ctx);
    if (unlikely(js == NULL)) {
        return TM_ECODE_FAILED;
    }

    jb_open_object(js, "pop3");
    if (!rs_pop3_logger_log(tx, js)) {
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

static void OutputPOP3LogDeInitCtxSub(OutputCtx *output_ctx)
{
    LogPOP3FileCtx *pop3log_ctx = (LogPOP3FileCtx *)output_ctx->data;
    SCFree(pop3log_ctx);
    SCFree(output_ctx);
}

static OutputInitResult OutputPOP3LogInitSub(ConfNode *conf, OutputCtx *parent_ctx)
{
    OutputInitResult result = { NULL, false };
    OutputJsonCtx *ajt = parent_ctx->data;

    LogPOP3FileCtx *pop3log_ctx = SCCalloc(1, sizeof(*pop3log_ctx));
    if (unlikely(pop3log_ctx == NULL)) {
        return result;
    }
    pop3log_ctx->eve_ctx = ajt;

    OutputCtx *output_ctx = SCCalloc(1, sizeof(*output_ctx));
    if (unlikely(output_ctx == NULL)) {
        SCFree(pop3log_ctx);
        return result;
    }
    output_ctx->data = pop3log_ctx;
    output_ctx->DeInit = OutputPOP3LogDeInitCtxSub;

    SCLogNotice("POP3 log sub-module initialized.");

    AppLayerParserRegisterLogger(IPPROTO_TCP, ALPROTO_POP3);

    result.ctx = output_ctx;
    result.ok = true;
    return result;
}

static TmEcode JsonPOP3LogThreadInit(ThreadVars *t, const void *initdata, void **data)
{
    LogPOP3LogThread *thread = SCCalloc(1, sizeof(*thread));
    if (unlikely(thread == NULL)) {
        return TM_ECODE_FAILED;
    }

    if (initdata == NULL) {
        SCLogDebug("Error getting context for EveLogPOP3.  \"initdata\" is NULL.");
        goto error_exit;
    }

    thread->pop3log_ctx = ((OutputCtx *)initdata)->data;
    thread->ctx = CreateEveThreadCtx(t, thread->pop3log_ctx->eve_ctx);
    if (!thread->ctx) {
        goto error_exit;
    }
    *data = (void *)thread;

    return TM_ECODE_OK;

error_exit:
    SCFree(thread);
    return TM_ECODE_FAILED;
}

static TmEcode JsonPOP3LogThreadDeinit(ThreadVars *t, void *data)
{
    LogPOP3LogThread *thread = (LogPOP3LogThread *)data;
    if (thread == NULL) {
        return TM_ECODE_OK;
    }
    FreeEveThreadCtx(thread->ctx);
    SCFree(thread);
    return TM_ECODE_OK;
}

void JsonPOP3LogRegister(void)
{
    /* Register as an eve sub-module. */
    OutputRegisterTxSubModule(LOGGER_JSON_TX, "eve-log", "JsonPOP3Log", "eve-log.pop3",
            OutputPOP3LogInitSub, ALPROTO_POP3, JsonPOP3Logger, JsonPOP3LogThreadInit,
            JsonPOP3LogThreadDeinit, NULL);

    SCLogNotice("POP3 JSON logger registered.");
}
