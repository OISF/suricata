/* Copyright (C) 2018-2020 Open Information Security Foundation
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
 * TODO: Update \author in this file and in output-json-pgsql.h.
 * TODO: Remove SCLogNotice statements, or convert to debug.
 * TODO: Implement your app-layers logging.
 */

/**
 * \file
 *
 * \author FirstName LastName <yourname@domain>
 *
 * Implement JSON/eve logging app-layer PGSQL.
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

#include "app-layer-pgsql.h"
#include "output-json-pgsql.h"
#include "rust.h"

typedef struct LogPGSQLFileCtx_ {
    LogFileCtx *file_ctx;
    uint32_t flags;
} LogPGSQLFileCtx;

typedef struct LogPGSQLLogThread_ {
    LogPGSQLFileCtx *pgsqllog_ctx;
    LogFileCtx *file_ctx;
    MemBuffer *buffer;
} LogPGSQLLogThread;

static int JsonPGSQLLogger(ThreadVars *tv, void *thread_data, const Packet *p, Flow *f, void *state,
        void *tx, uint64_t tx_id)
{
    SCLogNotice("JsonPGSQLLogger");
    LogPGSQLLogThread *thread = thread_data;

    JsonBuilder *js = CreateEveHeader(p, LOG_DIR_PACKET, "postgresql", NULL);
    if (unlikely(js == NULL)) {
        return TM_ECODE_FAILED;
    }

    jb_open_object(js, "postgresql");
    if (!rs_pgsql_logger_log(tx, js)) {
        goto error;
    }
    jb_close(js);

    MemBufferReset(thread->buffer);
    OutputJsonBuilderBuffer(js, thread->file_ctx, &thread->buffer);
    jb_free(js);

    return TM_ECODE_OK;

error:
    jb_free(js);
    return TM_ECODE_FAILED;
}

static void OutputPGSQLLogDeInitCtxSub(OutputCtx *output_ctx)
{
    LogPGSQLFileCtx *pgsqllog_ctx = (LogPGSQLFileCtx *)output_ctx->data;
    SCFree(pgsqllog_ctx);
    SCFree(output_ctx);
}

static OutputInitResult OutputPGSQLLogInitSub(ConfNode *conf, OutputCtx *parent_ctx)
{
    OutputInitResult result = { NULL, false };
    OutputJsonCtx *ajt = parent_ctx->data;

    LogPGSQLFileCtx *pgsqllog_ctx = SCCalloc(1, sizeof(*pgsqllog_ctx));
    if (unlikely(pgsqllog_ctx == NULL)) {
        return result;
    }
    pgsqllog_ctx->file_ctx = ajt->file_ctx;

    OutputCtx *output_ctx = SCCalloc(1, sizeof(*output_ctx));
    if (unlikely(output_ctx == NULL)) {
        SCFree(pgsqllog_ctx);
        return result;
    }
    output_ctx->data = pgsqllog_ctx;
    output_ctx->DeInit = OutputPGSQLLogDeInitCtxSub;

    SCLogNotice("PostgreSQL log sub-module initialized.");

    AppLayerParserRegisterLogger(IPPROTO_TCP, ALPROTO_POSTGRESQL);

    result.ctx = output_ctx;
    result.ok = true;
    return result;
}

static TmEcode JsonPGSQLLogThreadInit(ThreadVars *t, const void *initdata, void **data)
{
    LogPGSQLLogThread *thread = SCCalloc(1, sizeof(*thread));
    if (unlikely(thread == NULL)) {
        return TM_ECODE_FAILED;
    }

    if (initdata == NULL) {
        SCLogDebug("Error getting context for EveLogPGSQL.  \"initdata\" is NULL.");
        goto error_exit;
    }

    thread->buffer = MemBufferCreateNew(JSON_OUTPUT_BUFFER_SIZE);
    if (unlikely(thread->buffer == NULL)) {
        goto error_exit;
    }

    thread->pgsqllog_ctx = ((OutputCtx *)initdata)->data;
    thread->file_ctx = LogFileEnsureExists(thread->pgsqllog_ctx->file_ctx, t->id);
    if (!thread->file_ctx) {
        goto error_exit;
    }
    *data = (void *)thread;

    return TM_ECODE_OK;

error_exit:
    if (thread->buffer != NULL) {
        MemBufferFree(thread->buffer);
    }
    SCFree(thread);
    return TM_ECODE_FAILED;
}

static TmEcode JsonPGSQLLogThreadDeinit(ThreadVars *t, void *data)
{
    LogPGSQLLogThread *thread = (LogPGSQLLogThread *)data;
    if (thread == NULL) {
        return TM_ECODE_OK;
    }
    if (thread->buffer != NULL) {
        MemBufferFree(thread->buffer);
    }
    SCFree(thread);
    return TM_ECODE_OK;
}

void JsonPGSQLLogRegister(void)
{
    /* Register as an eve sub-module. */
    OutputRegisterTxSubModule(LOGGER_JSON_POSTGRESQL, "eve-log", "JsonPGSQLLog",
            "eve-log.postgresql", OutputPGSQLLogInitSub, ALPROTO_POSTGRESQL, JsonPGSQLLogger,
            JsonPGSQLLogThreadInit, JsonPGSQLLogThreadDeinit, NULL);

    SCLogNotice("PostgreSQL JSON logger registered.");
}
