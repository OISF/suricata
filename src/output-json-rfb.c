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
 * \author Frank Honza <frank.honza@dcso.de>
 *
 * Implement JSON/eve logging app-layer RFB.
 */

#include "suricata-common.h"
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

#include "app-layer-rfb.h"
#include "output-json-rfb.h"

#include "rust-bindings.h"

typedef struct LogRFBFileCtx_ {
    LogFileCtx *file_ctx;
    uint32_t    flags;
} LogRFBFileCtx;

typedef struct LogRFBLogThread_ {
    LogRFBFileCtx *rfblog_ctx;
    uint32_t            count;
    MemBuffer          *buffer;
} LogRFBLogThread;

json_t *JsonRFBAddMetadata(const Flow *f, uint64_t tx_id)
{
    RFBState *state = FlowGetAppState(f);
    if (state) {
        RFBTransaction *tx = AppLayerParserGetTx(f->proto, ALPROTO_RFB, state, tx_id);
        if (tx) {
            return rs_rfb_logger_log(state, tx);
        }
    }

    return NULL;
}

static int JsonRFBLogger(ThreadVars *tv, void *thread_data,
    const Packet *p, Flow *f, void *state, void *tx, uint64_t tx_id)
{
    LogRFBLogThread *thread = thread_data;

    json_t *js = CreateJSONHeader(p, LOG_DIR_FLOW, "rfb", NULL);
    if (unlikely(js == NULL)) {
        return TM_ECODE_FAILED;
    }

    json_t *rfb_js = rs_rfb_logger_log(NULL, tx);
    if (unlikely(rfb_js == NULL)) {
        goto error;
    }
    json_object_set_new(js, "rfb", rfb_js);

    MemBufferReset(thread->buffer);
    OutputJSONBuffer(js, thread->rfblog_ctx->file_ctx, &thread->buffer);
    json_decref(js);

    return TM_ECODE_OK;

error:
    json_decref(js);
    return TM_ECODE_FAILED;
}

static void OutputRFBLogDeInitCtxSub(OutputCtx *output_ctx)
{
    LogRFBFileCtx *rfblog_ctx = (LogRFBFileCtx *)output_ctx->data;
    SCFree(rfblog_ctx);
    SCFree(output_ctx);
}

static OutputInitResult OutputRFBLogInitSub(ConfNode *conf,
    OutputCtx *parent_ctx)
{
    OutputInitResult result = { NULL, false };
    OutputJsonCtx *ajt = parent_ctx->data;

    LogRFBFileCtx *rfblog_ctx = SCCalloc(1, sizeof(*rfblog_ctx));
    if (unlikely(rfblog_ctx == NULL)) {
        return result;
    }
    rfblog_ctx->file_ctx = ajt->file_ctx;

    OutputCtx *output_ctx = SCCalloc(1, sizeof(*output_ctx));
    if (unlikely(output_ctx == NULL)) {
        SCFree(rfblog_ctx);
        return result;
    }
    output_ctx->data = rfblog_ctx;
    output_ctx->DeInit = OutputRFBLogDeInitCtxSub;

    AppLayerParserRegisterLogger(IPPROTO_TCP, ALPROTO_RFB);

    result.ctx = output_ctx;
    result.ok = true;
    return result;
}

static TmEcode JsonRFBLogThreadInit(ThreadVars *t, const void *initdata, void **data)
{
    if (initdata == NULL) {
        SCLogDebug("Error getting context for EveLogRFB.  \"initdata\" is NULL.");
        return TM_ECODE_FAILED;
    }

    LogRFBLogThread *thread = SCCalloc(1, sizeof(*thread));
    if (unlikely(thread == NULL)) {
        return TM_ECODE_FAILED;
    }

    thread->buffer = MemBufferCreateNew(JSON_OUTPUT_BUFFER_SIZE);
    if (unlikely(thread->buffer == NULL)) {
        SCFree(thread);
        return TM_ECODE_FAILED;
    }

    thread->rfblog_ctx = ((OutputCtx *)initdata)->data;
    *data = (void *)thread;

    return TM_ECODE_OK;
}

static TmEcode JsonRFBLogThreadDeinit(ThreadVars *t, void *data)
{
    LogRFBLogThread *thread = (LogRFBLogThread *)data;
    if (thread == NULL) {
        return TM_ECODE_OK;
    }
    if (thread->buffer != NULL) {
        MemBufferFree(thread->buffer);
    }
    SCFree(thread);
    return TM_ECODE_OK;
}

void JsonRFBLogRegister(void)
{
    /* Register as an eve sub-module. */
    OutputRegisterTxSubModule(LOGGER_JSON_RFB, "eve-log",
        "JsonRFBLog", "eve-log.rfb",
        OutputRFBLogInitSub, ALPROTO_RFB, JsonRFBLogger,
        JsonRFBLogThreadInit, JsonRFBLogThreadDeinit, NULL);
}
