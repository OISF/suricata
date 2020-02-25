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
 * Implement JSON/eve logging app-layer IKEV1.
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

#include "app-layer-ikev1.h"
#include "output-json-ikev1.h"
#include "rust.h"

#define LOG_IKEV1_DEFAULT                 0
#define LOG_IKEV1_EXTENDED                (1 << 0)

typedef struct LogIKEV1FileCtx_ {
    LogFileCtx *file_ctx;
    uint32_t    flags;
} LogIKEV1FileCtx;

typedef struct LogIKEV1LogThread_ {
    LogIKEV1FileCtx *ikev1log_ctx;
    uint32_t            count;
    MemBuffer          *buffer;
} LogIKEV1LogThread;

bool JsonIKEV1AddMetadata(const Flow *f, uint64_t tx_id, JsonBuilder *js)
{
    IKEV1State *state = FlowGetAppState(f);
    if (state) {
        IKEV1Transaction *tx = AppLayerParserGetTx(f->proto, ALPROTO_IKEV1, state, tx_id);
        if (tx) {
            return rs_ikev1_logger_log(state, tx, LOG_IKEV1_EXTENDED, js);
        }
    }

    return false;
}

static int JsonIKEV1Logger(ThreadVars *tv, void *thread_data,
    const Packet *p, Flow *f, void *state, void *tx, uint64_t tx_id)
{
    LogIKEV1LogThread *thread = thread_data;
    JsonBuilder *js = CreateEveHeader(p, LOG_DIR_PACKET, "ikev1", NULL);
    if (unlikely(js == NULL)) {
        return TM_ECODE_FAILED;
    }

    LogIKEV1FileCtx *ikev1_ctx = thread->ikev1log_ctx;
    if (!rs_ikev1_logger_log(state, tx, ikev1_ctx->flags, js)) {
        goto error;
    }

    MemBufferReset(thread->buffer);
    OutputJsonBuilderBuffer(js, thread->ikev1log_ctx->file_ctx, &thread->buffer);
    jb_free(js);

    return TM_ECODE_OK;

error:
    jb_free(js);
    return TM_ECODE_FAILED;
}

static void OutputIKEV1LogDeInitCtxSub(OutputCtx *output_ctx)
{
    LogIKEV1FileCtx *ikev1log_ctx = (LogIKEV1FileCtx *)output_ctx->data;
    SCFree(ikev1log_ctx);
    SCFree(output_ctx);
}

static OutputInitResult OutputIKEV1LogInitSub(ConfNode *conf,
    OutputCtx *parent_ctx)
{
    OutputInitResult result = { NULL, false };
    OutputJsonCtx *ajt = parent_ctx->data;

    LogIKEV1FileCtx *ikev1log_ctx = SCCalloc(1, sizeof(*ikev1log_ctx));
    if (unlikely(ikev1log_ctx == NULL)) {
        return result;
    }
    ikev1log_ctx->file_ctx = ajt->file_ctx;

    OutputCtx *output_ctx = SCCalloc(1, sizeof(*output_ctx));
    if (unlikely(output_ctx == NULL)) {
        SCFree(ikev1log_ctx);
        return result;
    }

    ikev1log_ctx->flags = LOG_IKEV1_DEFAULT;
    const char *extended = ConfNodeLookupChildValue(conf, "extended");
    if (extended) {
        if (ConfValIsTrue(extended)) {
            ikev1log_ctx->flags = LOG_IKEV1_EXTENDED;
        }
    }

    output_ctx->data = ikev1log_ctx;
    output_ctx->DeInit = OutputIKEV1LogDeInitCtxSub;

    AppLayerParserRegisterLogger(IPPROTO_UDP, ALPROTO_IKEV1);

    result.ctx = output_ctx;
    result.ok = true;
    return result;
}

static TmEcode JsonIKEV1LogThreadInit(ThreadVars *t, const void *initdata, void **data)
{
    LogIKEV1LogThread *thread = SCCalloc(1, sizeof(*thread));
    if (unlikely(thread == NULL)) {
        return TM_ECODE_FAILED;
    }

    if (initdata == NULL) {
        SCLogDebug("Error getting context for EveLogIKEV1.  \"initdata\" is NULL.");
        SCFree(thread);
        return TM_ECODE_FAILED;
    }

    thread->buffer = MemBufferCreateNew(JSON_OUTPUT_BUFFER_SIZE);
    if (unlikely(thread->buffer == NULL)) {
        SCFree(thread);
        return TM_ECODE_FAILED;
    }

    thread->ikev1log_ctx = ((OutputCtx *)initdata)->data;
    *data = (void *)thread;

    return TM_ECODE_OK;
}

static TmEcode JsonIKEV1LogThreadDeinit(ThreadVars *t, void *data)
{
    LogIKEV1LogThread *thread = (LogIKEV1LogThread *)data;
    if (thread == NULL) {
        return TM_ECODE_OK;
    }
    if (thread->buffer != NULL) {
        MemBufferFree(thread->buffer);
    }
    SCFree(thread);
    return TM_ECODE_OK;
}

void JsonIKEV1LogRegister(void)
{
    /* Register as an eve sub-module. */
    OutputRegisterTxSubModule(LOGGER_JSON_IKEV1, "eve-log",
        "JsonIKEV1Log", "eve-log.ikev1",
        OutputIKEV1LogInitSub, ALPROTO_IKEV1, JsonIKEV1Logger,
        JsonIKEV1LogThreadInit, JsonIKEV1LogThreadDeinit, NULL);
}
