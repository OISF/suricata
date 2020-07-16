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
 * \author Clément Galland <clement.galland@epita.fr>
 *
 * Implement JSON/eve logging app-layer TFTP.
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

#include "app-layer-tftp.h"
#include "output-json-tftp.h"

#include "rust.h"

typedef struct LogTFTPFileCtx_ {
    LogFileCtx *file_ctx;
    uint32_t    flags;
    OutputJsonCommonSettings cfg;
} LogTFTPFileCtx;

typedef struct LogTFTPLogThread_ {
    LogFileCtx *file_ctx;
    LogTFTPFileCtx *tftplog_ctx;
    MemBuffer          *buffer;
} LogTFTPLogThread;

static int JsonTFTPLogger(ThreadVars *tv, void *thread_data,
    const Packet *p, Flow *f, void *state, void *tx, uint64_t tx_id)
{
    LogTFTPLogThread *thread = thread_data;

    JsonBuilder *jb = CreateEveHeader(p, LOG_DIR_PACKET, "tftp", NULL);
    if (unlikely(jb == NULL)) {
        return TM_ECODE_FAILED;
    }

    jb_open_object(jb, "tftp");
    if (unlikely(!rs_tftp_log_json_request(tx, jb))) {
        goto error;
    }
    jb_close(jb);

    EveAddCommonOptions(&thread->tftplog_ctx->cfg, p, f, jb);
    MemBufferReset(thread->buffer);
    OutputJsonBuilderBuffer(jb, thread->file_ctx, &thread->buffer);

    jb_free(jb);
    return TM_ECODE_OK;

error:
    jb_free(jb);
    return TM_ECODE_FAILED;
}

static void OutputTFTPLogDeInitCtxSub(OutputCtx *output_ctx)
{
    LogTFTPFileCtx *tftplog_ctx = (LogTFTPFileCtx *)output_ctx->data;
    SCFree(tftplog_ctx);
    SCFree(output_ctx);
}

static OutputInitResult OutputTFTPLogInitSub(ConfNode *conf,
    OutputCtx *parent_ctx)
{
    OutputInitResult result = { NULL, false };
    OutputJsonCtx *ajt = parent_ctx->data;

    LogTFTPFileCtx *tftplog_ctx = SCCalloc(1, sizeof(*tftplog_ctx));
    if (unlikely(tftplog_ctx == NULL)) {
        return result;
    }
    tftplog_ctx->file_ctx = ajt->file_ctx;
    tftplog_ctx->cfg = ajt->cfg;

    OutputCtx *output_ctx = SCCalloc(1, sizeof(*output_ctx));
    if (unlikely(output_ctx == NULL)) {
        SCFree(tftplog_ctx);
        return result;
    }
    output_ctx->data = tftplog_ctx;
    output_ctx->DeInit = OutputTFTPLogDeInitCtxSub;

    SCLogDebug("TFTP log sub-module initialized.");

    AppLayerParserRegisterLogger(IPPROTO_UDP, ALPROTO_TFTP);

    result.ctx = output_ctx;
    result.ok = true;
    return result;
}

static TmEcode JsonTFTPLogThreadInit(ThreadVars *t, const void *initdata, void **data)
{
    LogTFTPLogThread *thread = SCCalloc(1, sizeof(*thread));
    if (unlikely(thread == NULL)) {
        return TM_ECODE_FAILED;
    }

    if (initdata == NULL) {
        SCLogDebug("Error getting context for EveLogTFTP.  \"initdata\" is NULL.");
        goto error_exit;
    }

    thread->buffer = MemBufferCreateNew(JSON_OUTPUT_BUFFER_SIZE);
    if (unlikely(thread->buffer == NULL)) {
        goto error_exit;
    }

    thread->tftplog_ctx = ((OutputCtx *)initdata)->data;
    thread->file_ctx = LogFileEnsureExists(thread->tftplog_ctx->file_ctx, t->id);
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

static TmEcode JsonTFTPLogThreadDeinit(ThreadVars *t, void *data)
{
    LogTFTPLogThread *thread = (LogTFTPLogThread *)data;
    if (thread == NULL) {
        return TM_ECODE_OK;
    }
    if (thread->buffer != NULL) {
        MemBufferFree(thread->buffer);
    }
    SCFree(thread);
    return TM_ECODE_OK;
}

void JsonTFTPLogRegister(void)
{
    /* Register as an eve sub-module. */
    OutputRegisterTxSubModule(LOGGER_JSON_TFTP, "eve-log", "JsonTFTPLog",
                              "eve-log.tftp", OutputTFTPLogInitSub,
                              ALPROTO_TFTP, JsonTFTPLogger,
                              JsonTFTPLogThreadInit, JsonTFTPLogThreadDeinit,
                              NULL);

    SCLogDebug("TFTP JSON logger registered.");
}
