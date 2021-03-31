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

#include "app-layer-pgsql.h"
#include "output-json-pgsql.h"
#include "rust.h"

typedef struct LogPgsqlFileCtx_ {
    LogFileCtx *file_ctx;
    uint32_t flags;
} LogPgsqlFileCtx;

typedef struct LogPgsqlLogThread_ {
    LogPgsqlFileCtx *pgsqllog_ctx;
    LogFileCtx *file_ctx;
    MemBuffer *buffer;
} LogPgsqlLogThread;

// static int JsonPgsqlLogger(ThreadVars *tv, void *thread_data, const Packet *p, Flow *f, void
// *state,
//         void *tx, uint64_t tx_id)
// {
//     SCLogNotice("JsonPgsqlLogger");
//     LogPgsqlLogThread *thread = thread_data;

//     // TODO must figure out the best way to pass that new argument
//     JsonBuilder *js = CreateEveHeader(p, LOG_DIR_PACKET, "pgsql", NULL, NULL);
//     if (unlikely(js == NULL)) {
//         return TM_ECODE_FAILED;
//     }

//     jb_open_object(js, "pgsql");
//     if (!rs_pgsql_logger_log(tx, js)) {
//         goto error;
//     }
//     jb_close(js);

//     MemBufferReset(thread->buffer);
//     OutputJsonBuilderBuffer(js, thread->file_ctx, &thread->buffer);
//     jb_free(js);

//     return TM_ECODE_OK;

// error:
//     jb_free(js);
//     return TM_ECODE_FAILED;
// }

// static void OutputPgsqlLogDeInitCtxSub(OutputCtx *output_ctx)
// {
//     LogPgsqlFileCtx *pgsqllog_ctx = (LogPgsqlFileCtx *)output_ctx->data;
//     SCFree(pgsqllog_ctx);
//     SCFree(output_ctx);
// }

// static OutputInitResult OutputPgsqlLogInitSub(ConfNode *conf, OutputCtx *parent_ctx)
// {
//     OutputInitResult result = { NULL, false };
//     OutputJsonCtx *ajt = parent_ctx->data;

//     LogPgsqlFileCtx *pgsqllog_ctx = SCCalloc(1, sizeof(*pgsqllog_ctx));
//     if (unlikely(pgsqllog_ctx == NULL)) {
//         return result;
//     }
//     pgsqllog_ctx->file_ctx = ajt->file_ctx;

//     OutputCtx *output_ctx = SCCalloc(1, sizeof(*output_ctx));
//     if (unlikely(output_ctx == NULL)) {
//         SCFree(pgsqllog_ctx);
//         return result;
//     }
//     output_ctx->data = pgsqllog_ctx;
//     output_ctx->DeInit = OutputPgsqlLogDeInitCtxSub;

//     SCLogNotice("PostgreSQL log sub-module initialized.");

//     AppLayerParserRegisterLogger(IPPROTO_TCP, ALPROTO_PGSQL);

//     result.ctx = output_ctx;
//     result.ok = true;
//     return result;
// }

// static TmEcode JsonPgsqlLogThreadInit(ThreadVars *t, const void *initdata, void **data)
// {
//     LogPgsqlLogThread *thread = SCCalloc(1, sizeof(*thread));
//     if (unlikely(thread == NULL)) {
//         return TM_ECODE_FAILED;
//     }

//     if (initdata == NULL) {
//         SCLogDebug("Error getting context for EveLogPgsql.  \"initdata\" is NULL.");
//         goto error_exit;
//     }

//     thread->buffer = MemBufferCreateNew(JSON_OUTPUT_BUFFER_SIZE);
//     if (unlikely(thread->buffer == NULL)) {
//         goto error_exit;
//     }

//     thread->pgsqllog_ctx = ((OutputCtx *)initdata)->data;
//     thread->file_ctx = LogFileEnsureExists(thread->pgsqllog_ctx->file_ctx, t->id);
//     if (!thread->file_ctx) {
//         goto error_exit;
//     }
//     *data = (void *)thread;

//     return TM_ECODE_OK;

// error_exit:
//     if (thread->buffer != NULL) {
//         MemBufferFree(thread->buffer);
//     }
//     SCFree(thread);
//     return TM_ECODE_FAILED;
// }

// static TmEcode JsonPgsqlLogThreadDeinit(ThreadVars *t, void *data)
// {
//     LogPgsqlLogThread *thread = (LogPgsqlLogThread *)data;
//     if (thread == NULL) {
//         return TM_ECODE_OK;
//     }
//     if (thread->buffer != NULL) {
//         MemBufferFree(thread->buffer);
//     }
//     SCFree(thread);
//     return TM_ECODE_OK;
// }

void JsonPgsqlLogRegister(void)
{
    /* Register as an eve sub-module. */
    // OutputRegisterTxSubModule(LOGGER_JSON_PGSQL, "eve-log", "JsonPgsqlLog", "eve-log.postgresql",
    //         OutputPgsqlLogInitSub, ALPROTO_PGSQL, JsonPgsqlLogger, JsonPgsqlLogThreadInit,
    //         JsonPgsqlLogThreadDeinit, NULL);

    SCLogNotice("PostgreSQL JSON logger registered.");
}
