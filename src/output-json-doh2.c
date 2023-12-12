/* Copyright (C) 2023 Open Information Security Foundation
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
 * \author Philippe Antoine
 *
 * Implement JSON/eve logging app-layer DoH2.
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

#include "output-json-doh2.h"
#include "rust.h"

typedef struct LogDoH2FileCtx_ {
    uint32_t flags;
    OutputJsonCtx *eve_ctx;
} LogDoH2FileCtx;

typedef struct LogDoH2LogThread_ {
    LogDoH2FileCtx *doh2log_ctx;
    OutputJsonThreadCtx *ctx;
} LogDoH2LogThread;

static int JsonDoH2Logger(ThreadVars *tv, void *thread_data, const Packet *p, Flow *f, void *state,
        void *tx, uint64_t tx_id)
{
    LogDoH2LogThread *thread = thread_data;

    JsonBuilder *js =
            CreateEveHeader(p, LOG_DIR_PACKET, "doh2", NULL, thread->doh2log_ctx->eve_ctx);
    if (unlikely(js == NULL)) {
        return TM_ECODE_FAILED;
    }

    if (!rs_http2_log_json(tx, js)) {
        goto error;
    }

    OutputJsonBuilderBuffer(js, thread->ctx);
    jb_free(js);

    return TM_ECODE_OK;

error:
    jb_free(js);
    return TM_ECODE_FAILED;
}

static void OutputDoH2LogDeInitCtxSub(OutputCtx *output_ctx)
{
    LogDoH2FileCtx *doh2log_ctx = (LogDoH2FileCtx *)output_ctx->data;
    SCFree(doh2log_ctx);
    SCFree(output_ctx);
}

static OutputInitResult OutputDoH2LogInitSub(ConfNode *conf, OutputCtx *parent_ctx)
{
    OutputInitResult result = { NULL, false };
    OutputJsonCtx *ajt = parent_ctx->data;

    LogDoH2FileCtx *doh2log_ctx = SCCalloc(1, sizeof(*doh2log_ctx));
    if (unlikely(doh2log_ctx == NULL)) {
        return result;
    }
    doh2log_ctx->eve_ctx = ajt;

    OutputCtx *output_ctx = SCCalloc(1, sizeof(*output_ctx));
    if (unlikely(output_ctx == NULL)) {
        SCFree(doh2log_ctx);
        return result;
    }
    output_ctx->data = doh2log_ctx;
    output_ctx->DeInit = OutputDoH2LogDeInitCtxSub;

    AppLayerParserRegisterLogger(IPPROTO_TCP, ALPROTO_DOH2);

    result.ctx = output_ctx;
    result.ok = true;
    return result;
}

static TmEcode JsonDoH2LogThreadInit(ThreadVars *t, const void *initdata, void **data)
{
    LogDoH2LogThread *thread = SCCalloc(1, sizeof(*thread));
    if (unlikely(thread == NULL)) {
        return TM_ECODE_FAILED;
    }

    if (initdata == NULL) {
        SCLogDebug("Error getting context for EveLogDoH2.  \"initdata\" is NULL.");
        goto error_exit;
    }

    thread->doh2log_ctx = ((OutputCtx *)initdata)->data;
    thread->ctx = CreateEveThreadCtx(t, thread->doh2log_ctx->eve_ctx);
    if (!thread->ctx) {
        goto error_exit;
    }
    *data = (void *)thread;

    return TM_ECODE_OK;

error_exit:
    SCFree(thread);
    return TM_ECODE_FAILED;
}

static TmEcode JsonDoH2LogThreadDeinit(ThreadVars *t, void *data)
{
    LogDoH2LogThread *thread = (LogDoH2LogThread *)data;
    if (thread == NULL) {
        return TM_ECODE_OK;
    }
    FreeEveThreadCtx(thread->ctx);
    SCFree(thread);
    return TM_ECODE_OK;
}

void JsonDoH2LogRegister(void)
{
    /* Register as an eve sub-module. */
    OutputRegisterTxSubModule(LOGGER_JSON_TX, "eve-log", "JsonDoH2Log", "eve-log.doh2",
            OutputDoH2LogInitSub, ALPROTO_DOH2, JsonDoH2Logger, JsonDoH2LogThreadInit,
            JsonDoH2LogThreadDeinit, NULL);
}
