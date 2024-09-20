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
 * \author linqiankai <linqiankai@geweian.com>
 *
 * Implement JSON/eve logging for app-layer MySQL.
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

#include "output-json-mysql.h"
#include "rust.h"

#define MYSQL_LOG_NULL  BIT_U32(0)
#define MYSQL_DEFAULTS      (MYSQL_LOG_NULL)

typedef struct OutputMysqlCtx_ {
    uint32_t flags;
    OutputJsonCtx *eve_ctx;
} OutputMysqlCtx;

typedef struct LogMysqlLogThread_ {
    OutputMysqlCtx *mysqllog_ctx;
    OutputJsonThreadCtx *ctx;
} LogMysqlLogThread;

static int JsonMysqlLogger(ThreadVars *tv, void *thread_data, const Packet *p, Flow *f, void *state,
        void *txptr, uint64_t tx_id)
{
    LogMysqlLogThread *thread = thread_data;
    SCLogDebug("Logging mysql transaction %" PRIu64 ".", tx_id);

    JsonBuilder *jb =
            CreateEveHeader(p, LOG_DIR_FLOW, "mysql", NULL, thread->mysqllog_ctx->eve_ctx);
    if (unlikely(jb == NULL)) {
        return TM_ECODE_FAILED;
    }

    if (!rs_mysql_logger(txptr, thread->mysqllog_ctx->flags, jb)) {
        goto error;
    }

    OutputJsonBuilderBuffer(jb, thread->ctx);
    jb_free(jb);

    return TM_ECODE_OK;

error:
    jb_free(jb);
    return TM_ECODE_FAILED;
}

static void OutputMysqlLogDeInitCtxSub(OutputCtx *output_ctx)
{
    OutputMysqlCtx *mysqllog_ctx = (OutputMysqlCtx *)output_ctx->data;
    SCFree(mysqllog_ctx);
    SCFree(output_ctx);
}

static OutputInitResult OutputMysqlLogInitSub(ConfNode *conf, OutputCtx *parent_ctx)
{
    OutputInitResult result = { NULL, false };
    OutputJsonCtx *ojc = parent_ctx->data;

    OutputMysqlCtx *mysql_ctx = SCCalloc(1, sizeof(OutputMysqlCtx));
    if (unlikely(mysql_ctx == NULL))
        return result;

    OutputCtx *output_ctx = SCCalloc(1, sizeof(OutputCtx));
    if (unlikely(output_ctx == NULL)) {
        SCFree(mysql_ctx);
        return result;
    }

    mysql_ctx->eve_ctx = ojc;

    output_ctx->data = mysql_ctx;
    output_ctx->DeInit = OutputMysqlLogDeInitCtxSub;

    AppLayerParserRegisterLogger(IPPROTO_TCP, ALPROTO_MYSQL);

    SCLogDebug("MySQL log sub-module initialized.");

    result.ctx = output_ctx;
    result.ok = true;
    return result;
}

static TmEcode JsonMysqlLogThreadInit(ThreadVars *t, const void *initdata, void **data)
{
    LogMysqlLogThread *thread = SCCalloc(1, sizeof(LogMysqlLogThread));
    if (unlikely(thread == NULL)) {
        return TM_ECODE_FAILED;
    }

    if (initdata == NULL) {
        SCLogDebug("Error getting context for EveLogMysql.  \"initdata\" is NULL.");
        goto error_exit;
    }

    thread->mysqllog_ctx = ((OutputCtx *)initdata)->data;
    thread->ctx = CreateEveThreadCtx(t, thread->mysqllog_ctx->eve_ctx);
    if (!thread->ctx) {
        goto error_exit;
    }
    *data = (void *)thread;

    return TM_ECODE_OK;

error_exit:
    SCFree(thread);
    return TM_ECODE_FAILED;
}

static TmEcode JsonMysqlLogThreadDeinit(ThreadVars *t, void *data)
{
    LogMysqlLogThread *thread = (LogMysqlLogThread *)data;
    if (thread == NULL) {
        return TM_ECODE_OK;
    }
    FreeEveThreadCtx(thread->ctx);
    SCFree(thread);
    return TM_ECODE_OK;
}

void JsonMysqlLogRegister(void)
{
    /* MYSQL_START_REMOVE */
    if (ConfGetNode("app-layer.protocols.mysql") == NULL) {
        SCLogDebug("Disabling Mysql eve-logger");
        return;
    }
    /* MYSQL_END_REMOVE */
    /* Register as an eve sub-module. */
    OutputRegisterTxSubModule(LOGGER_JSON_TX, "eve-log", "JsonMysqlLog", "eve-log.mysql",
            OutputMysqlLogInitSub, ALPROTO_MYSQL, JsonMysqlLogger, JsonMysqlLogThreadInit,
            JsonMysqlLogThreadDeinit);

    SCLogDebug("MySQL JSON logger registered.");
}
