/* Copyright (C) 2022 Open Information Security Foundation
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
 * Implement JSON/eve logging for app-layer Pgsql.
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

#include "output-json-pgsql.h"
#include "rust.h"

#define PGSQL_LOG_PASSWORDS BIT_U32(0)

typedef struct OutputPgsqlCtx_ {
    uint32_t flags;
    OutputJsonCtx *eve_ctx;
} OutputPgsqlCtx;

typedef struct LogPgsqlLogThread_ {
    OutputPgsqlCtx *pgsqllog_ctx;
    OutputJsonThreadCtx *ctx;
} LogPgsqlLogThread;

static int JsonPgsqlLogger(ThreadVars *tv, void *thread_data, const Packet *p, Flow *f, void *state,
        void *txptr, uint64_t tx_id)
{
    LogPgsqlLogThread *thread = thread_data;
    SCLogDebug("Logging pgsql transaction %" PRIu64 ".", tx_id);

    JsonBuilder *jb =
            CreateEveHeader(p, LOG_DIR_FLOW, "pgsql", NULL, thread->pgsqllog_ctx->eve_ctx);
    if (unlikely(jb == NULL)) {
        return TM_ECODE_FAILED;
    }

    jb_open_object(jb, "pgsql");
    if (!rs_pgsql_logger(txptr, thread->pgsqllog_ctx->flags, jb)) {
        goto error;
    }
    jb_close(jb);

    OutputJsonBuilderBuffer(jb, thread->ctx);
    jb_free(jb);

    return TM_ECODE_OK;

error:
    jb_free(jb);
    return TM_ECODE_FAILED;
}

static void OutputPgsqlLogDeInitCtxSub(OutputCtx *output_ctx)
{
    OutputPgsqlCtx *pgsqllog_ctx = (OutputPgsqlCtx *)output_ctx->data;
    SCFree(pgsqllog_ctx);
    SCFree(output_ctx);
}

static void JsonPgsqlLogParseConfig(ConfNode *conf, OutputPgsqlCtx *pgsqllog_ctx)
{
    pgsqllog_ctx->flags = ~0U;

    const char *query = ConfNodeLookupChildValue(conf, "passwords");
    if (query != NULL) {
        if (ConfValIsTrue(query)) {
            pgsqllog_ctx->flags |= PGSQL_LOG_PASSWORDS;
        } else {
            pgsqllog_ctx->flags &= ~PGSQL_LOG_PASSWORDS;
        }
    } else {
        pgsqllog_ctx->flags &= ~PGSQL_LOG_PASSWORDS;
    }
}

static OutputInitResult OutputPgsqlLogInitSub(ConfNode *conf, OutputCtx *parent_ctx)
{
    OutputInitResult result = { NULL, false };
    OutputJsonCtx *ojc = parent_ctx->data;

    OutputPgsqlCtx *pgsql_ctx = SCMalloc(sizeof(OutputPgsqlCtx));
    if (unlikely(pgsql_ctx == NULL))
        return result;

    OutputCtx *output_ctx = SCCalloc(1, sizeof(OutputCtx));
    if (unlikely(output_ctx == NULL)) {
        SCFree(pgsql_ctx);
        return result;
    }

    pgsql_ctx->eve_ctx = ojc;

    output_ctx->data = pgsql_ctx;
    output_ctx->DeInit = OutputPgsqlLogDeInitCtxSub;

    JsonPgsqlLogParseConfig(conf, pgsql_ctx);

    AppLayerParserRegisterLogger(IPPROTO_TCP, ALPROTO_PGSQL);

    SCLogDebug("PostgreSQL log sub-module initialized.");

    result.ctx = output_ctx;
    result.ok = true;
    return result;
}

static TmEcode JsonPgsqlLogThreadInit(ThreadVars *t, const void *initdata, void **data)
{
    LogPgsqlLogThread *thread = SCCalloc(1, sizeof(LogPgsqlLogThread));
    if (unlikely(thread == NULL)) {
        return TM_ECODE_FAILED;
    }

    if (initdata == NULL) {
        SCLogDebug("Error getting context for EveLogPgsql.  \"initdata\" is NULL.");
        goto error_exit;
    }

    thread->pgsqllog_ctx = ((OutputCtx *)initdata)->data;
    thread->ctx = CreateEveThreadCtx(t, thread->pgsqllog_ctx->eve_ctx);
    if (!thread->ctx) {
        goto error_exit;
    }
    *data = (void *)thread;

    return TM_ECODE_OK;

error_exit:
    SCFree(thread);
    return TM_ECODE_FAILED;
}

static TmEcode JsonPgsqlLogThreadDeinit(ThreadVars *t, void *data)
{
    LogPgsqlLogThread *thread = (LogPgsqlLogThread *)data;
    if (thread == NULL) {
        return TM_ECODE_OK;
    }
    FreeEveThreadCtx(thread->ctx);
    SCFree(thread);
    return TM_ECODE_OK;
}

void JsonPgsqlLogRegister(void)
{
    /* PGSQL_START_REMOVE */
    if (ConfGetNode("app-layer.protocols.pgsql") == NULL) {
        SCLogDebug("Disabling Pgsql eve-logger");
        return;
    }
    /* PGSQL_END_REMOVE */
    /* Register as an eve sub-module. */
    OutputRegisterTxSubModule(LOGGER_JSON_PGSQL, "eve-log", "JsonPgsqlLog", "eve-log.pgsql",
            OutputPgsqlLogInitSub, ALPROTO_PGSQL, JsonPgsqlLogger, JsonPgsqlLogThreadInit,
            JsonPgsqlLogThreadDeinit, NULL);

    SCLogDebug("PostgreSQL JSON logger registered.");
}
