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

/**
 * \file
 *
 * \author Pierre Chifflier <chifflier@wzdftpd.net>
 *
 * Implement JSON/eve logging app-layer SNMP.
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

#include "app-layer-snmp.h"
#include "output-json-snmp.h"

#include "rust.h"

typedef struct LogSNMPFileCtx_ {
    LogFileCtx *file_ctx;
    OutputJsonCommonSettings cfg;
} LogSNMPFileCtx;

typedef struct LogSNMPLogThread_ {
    LogFileCtx *file_ctx;
    LogSNMPFileCtx *snmplog_ctx;
    MemBuffer          *buffer;
} LogSNMPLogThread;

static int JsonSNMPLogger(ThreadVars *tv, void *thread_data,
    const Packet *p, Flow *f, void *state, void *tx, uint64_t tx_id)
{
    SNMPTransaction *snmptx = tx;
    LogSNMPLogThread *thread = thread_data;

    JsonBuilder *jb = CreateEveHeader(p, LOG_DIR_PACKET, "snmp", NULL);
    if (unlikely(jb == NULL)) {
        return TM_ECODE_FAILED;
    }

    EveAddCommonOptions(&thread->snmplog_ctx->cfg, p, f, jb);

    jb_open_object(jb, "snmp");
    if (!rs_snmp_log_json_response(jb, state, snmptx)) {
        goto error;
    }
    jb_close(jb);

    MemBufferReset(thread->buffer);
    OutputJsonBuilderBuffer(jb, thread->file_ctx, &thread->buffer);

    jb_free(jb);
    return TM_ECODE_OK;

error:
    jb_free(jb);
    return TM_ECODE_FAILED;
}

static void OutputSNMPLogDeInitCtxSub(OutputCtx *output_ctx)
{
    LogSNMPFileCtx *snmplog_ctx = (LogSNMPFileCtx *)output_ctx->data;
    SCFree(snmplog_ctx);
    SCFree(output_ctx);
}

static OutputInitResult OutputSNMPLogInitSub(ConfNode *conf,
    OutputCtx *parent_ctx)
{
    OutputInitResult result = { NULL, false };
    OutputJsonCtx *ajt = parent_ctx->data;

    LogSNMPFileCtx *snmplog_ctx = SCCalloc(1, sizeof(*snmplog_ctx));
    if (unlikely(snmplog_ctx == NULL)) {
        return result;
    }
    snmplog_ctx->file_ctx = ajt->file_ctx;
    snmplog_ctx->cfg = ajt->cfg;

    OutputCtx *output_ctx = SCCalloc(1, sizeof(*output_ctx));
    if (unlikely(output_ctx == NULL)) {
        SCFree(snmplog_ctx);
        return result;
    }
    output_ctx->data = snmplog_ctx;
    output_ctx->DeInit = OutputSNMPLogDeInitCtxSub;

    SCLogDebug("SNMP log sub-module initialized.");

    AppLayerParserRegisterLogger(IPPROTO_UDP, ALPROTO_SNMP);

    result.ctx = output_ctx;
    result.ok = true;
    return result;
}

static TmEcode JsonSNMPLogThreadInit(ThreadVars *t, const void *initdata, void **data)
{
    LogSNMPLogThread *thread = SCCalloc(1, sizeof(*thread));
    if (unlikely(thread == NULL)) {
        return TM_ECODE_FAILED;
    }

    if (initdata == NULL) {
        SCLogDebug("Error getting context for EveLogSNMP.  \"initdata\" is NULL.");
        goto error_exit;
    }

    thread->buffer = MemBufferCreateNew(JSON_OUTPUT_BUFFER_SIZE);
    if (unlikely(thread->buffer == NULL)) {
        goto error_exit;
    }

    thread->snmplog_ctx = ((OutputCtx *)initdata)->data;

    thread->file_ctx = LogFileEnsureExists(thread->snmplog_ctx->file_ctx, t->id);
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

static TmEcode JsonSNMPLogThreadDeinit(ThreadVars *t, void *data)
{
    LogSNMPLogThread *thread = (LogSNMPLogThread *)data;
    if (thread == NULL) {
        return TM_ECODE_OK;
    }
    if (thread->buffer != NULL) {
        MemBufferFree(thread->buffer);
    }
    SCFree(thread);
    return TM_ECODE_OK;
}

void JsonSNMPLogRegister(void)
{
    /* Register as an eve sub-module. */
    OutputRegisterTxSubModule(LOGGER_JSON_SNMP, "eve-log", "JsonSNMPLog",
        "eve-log.snmp", OutputSNMPLogInitSub, ALPROTO_SNMP,
        JsonSNMPLogger, JsonSNMPLogThreadInit,
        JsonSNMPLogThreadDeinit, NULL);

    SCLogDebug("SNMP JSON logger registered.");
}
