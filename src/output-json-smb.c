/* Copyright (C) 2017 Open Information Security Foundation
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
 * \author Victor Julien <victor@inliniac.net>
 *
 * Implement JSON/eve logging app-layer SMB.
 */

#include "suricata-common.h"
#include "debug.h"
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

#include "output-json-smb.h"

#ifdef HAVE_RUST
#ifdef HAVE_LIBJANSSON
#include "rust.h"
#include "rust-smb-log-gen.h"

typedef struct LogSMBFileCtx_ {
    LogFileCtx *file_ctx;
    uint32_t    flags;
} LogSMBFileCtx;

typedef struct LogSMBLogThread_ {
    LogSMBFileCtx *smblog_ctx;
    uint32_t            count;
    MemBuffer          *buffer;
} LogSMBLogThread;

json_t *JsonSMBAddMetadata(const Flow *f, uint64_t tx_id)
{
    SMBState *state = FlowGetAppState(f);
    if (state) {
        SMBTransaction *tx = AppLayerParserGetTx(f->proto, ALPROTO_SMB, state, tx_id);
        if (tx) {
            return rs_smb_log_json_response(state, tx);
        }
    }

    return NULL;
}

static int JsonSMBLogger(ThreadVars *tv, void *thread_data,
    const Packet *p, Flow *f, void *state, void *tx, uint64_t tx_id)
{
    LogSMBLogThread *thread = thread_data;
    json_t *js, *smbjs;

    js = CreateJSONHeader(p, LOG_DIR_FLOW, "smb");
    if (unlikely(js == NULL)) {
        return TM_ECODE_FAILED;
    }

    smbjs = rs_smb_log_json_response(state, tx);
    if (unlikely(smbjs == NULL)) {
        goto error;
    }
    json_object_set_new(js, "smb", smbjs);

    MemBufferReset(thread->buffer);
    OutputJSONBuffer(js, thread->smblog_ctx->file_ctx, &thread->buffer);

    json_decref(js);
    return TM_ECODE_OK;

error:
    json_decref(js);
    return TM_ECODE_FAILED;
}

static void OutputSMBLogDeInitCtxSub(OutputCtx *output_ctx)
{
    LogSMBFileCtx *smblog_ctx = (LogSMBFileCtx *)output_ctx->data;
    SCFree(smblog_ctx);
    SCFree(output_ctx);
}

static OutputInitResult OutputSMBLogInitSub(ConfNode *conf,
    OutputCtx *parent_ctx)
{
    OutputInitResult result = { NULL, false };
    OutputJsonCtx *ajt = parent_ctx->data;

    LogSMBFileCtx *smblog_ctx = SCCalloc(1, sizeof(*smblog_ctx));
    if (unlikely(smblog_ctx == NULL)) {
        return result;
    }
    smblog_ctx->file_ctx = ajt->file_ctx;

    OutputCtx *output_ctx = SCCalloc(1, sizeof(*output_ctx));
    if (unlikely(output_ctx == NULL)) {
        SCFree(smblog_ctx);
        return result;
    }
    output_ctx->data = smblog_ctx;
    output_ctx->DeInit = OutputSMBLogDeInitCtxSub;

    SCLogDebug("SMB log sub-module initialized.");

    AppLayerParserRegisterLogger(IPPROTO_TCP, ALPROTO_SMB);
    AppLayerParserRegisterLogger(IPPROTO_UDP, ALPROTO_SMB);

    result.ctx = output_ctx;
    result.ok = true;
    return result;
}

#define OUTPUT_BUFFER_SIZE 65535

static TmEcode JsonSMBLogThreadInit(ThreadVars *t, const void *initdata, void **data)
{
    LogSMBLogThread *thread = SCCalloc(1, sizeof(*thread));
    if (unlikely(thread == NULL)) {
        return TM_ECODE_FAILED;
    }

    if (initdata == NULL) {
        SCLogDebug("Error getting context for EveLogSMB.  \"initdata\" is NULL.");
        SCFree(thread);
        return TM_ECODE_FAILED;
    }

    thread->buffer = MemBufferCreateNew(OUTPUT_BUFFER_SIZE);
    if (unlikely(thread->buffer == NULL)) {
        SCFree(thread);
        return TM_ECODE_FAILED;
    }

    thread->smblog_ctx = ((OutputCtx *)initdata)->data;
    *data = (void *)thread;

    return TM_ECODE_OK;
}

static TmEcode JsonSMBLogThreadDeinit(ThreadVars *t, void *data)
{
    LogSMBLogThread *thread = (LogSMBLogThread *)data;
    if (thread == NULL) {
        return TM_ECODE_OK;
    }
    if (thread->buffer != NULL) {
        MemBufferFree(thread->buffer);
    }
    SCFree(thread);
    return TM_ECODE_OK;
}

void JsonSMBLogRegister(void)
{
    /* Register as an eve sub-module. */
    OutputRegisterTxSubModule(LOGGER_JSON_SMB, "eve-log", "JsonSMBLog",
        "eve-log.smb", OutputSMBLogInitSub, ALPROTO_SMB,
        JsonSMBLogger, JsonSMBLogThreadInit,
        JsonSMBLogThreadDeinit, NULL);

    SCLogDebug("SMB JSON logger registered.");
}

#else /* No JSON support. */

void JsonSMBLogRegister(void)
{
}

#endif /* HAVE_LIBJANSSON */

#else /* no rust */

void JsonSMBLogRegister(void)
{
}

#endif /* HAVE_RUST */
