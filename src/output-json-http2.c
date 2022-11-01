/* Copyright (C) 2020-2021 Open Information Security Foundation
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
 * \author Philippe Antoine <p.antoine@catenacyber.fr>
 *
 * Implements HTTP2 JSON logging portion of the engine.
 */

#include "suricata-common.h"

#include "app-layer-parser.h"

#include "output-json.h"
#include "output-json-http2.h"

#define MODULE_NAME "LogHttp2Log"

typedef struct OutputHttp2Ctx_ {
    OutputJsonCtx *eve_ctx;
} OutputHttp2Ctx;


typedef struct JsonHttp2LogThread_ {
    OutputHttp2Ctx *http2log_ctx;
    OutputJsonThreadCtx *ctx;
} JsonHttp2LogThread;


bool EveHTTP2AddMetadata(const Flow *f, uint64_t tx_id, JsonBuilder *jb)
{
    void *state = FlowGetAppState(f);
    if (state) {
        void *tx = AppLayerParserGetTx(f->proto, ALPROTO_HTTP2, state, tx_id);
        if (tx) {
            return rs_http2_log_json(tx, jb);
        }
    }
    return false;
}

static int JsonHttp2Logger(ThreadVars *tv, void *thread_data, const Packet *p,
                         Flow *f, void *state, void *txptr, uint64_t tx_id)
{
    JsonHttp2LogThread *aft = (JsonHttp2LogThread *)thread_data;

    if (unlikely(state == NULL)) {
        return 0;
    }

    JsonBuilder *js = CreateEveHeaderWithTxId(
            p, LOG_DIR_FLOW, "http", NULL, tx_id, aft->http2log_ctx->eve_ctx);
    if (unlikely(js == NULL))
        return 0;

    jb_open_object(js, "http");
    if (!rs_http2_log_json(txptr, js)) {
        goto end;
    }
    jb_close(js);
    OutputJsonBuilderBuffer(js, aft->ctx);
end:
    jb_free(js);
    return 0;
}

static TmEcode JsonHttp2LogThreadInit(ThreadVars *t, const void *initdata, void **data)
{
    JsonHttp2LogThread *aft = SCCalloc(1, sizeof(JsonHttp2LogThread));
    if (unlikely(aft == NULL))
        return TM_ECODE_FAILED;

    if(initdata == NULL)
    {
        SCLogDebug("Error getting context for EveLogHTTP2.  \"initdata\" argument NULL");
        goto error_exit;
    }

    /* Use the Output Context (file pointer and mutex) */
    aft->http2log_ctx = ((OutputCtx *)initdata)->data;
    aft->ctx = CreateEveThreadCtx(t, aft->http2log_ctx->eve_ctx);
    if (!aft->ctx) {
        goto error_exit;
    }

    *data = (void *)aft;
    return TM_ECODE_OK;

error_exit:
    SCFree(aft);
    return TM_ECODE_FAILED;
}

static TmEcode JsonHttp2LogThreadDeinit(ThreadVars *t, void *data)
{
    JsonHttp2LogThread *aft = (JsonHttp2LogThread *)data;
    if (aft == NULL) {
        return TM_ECODE_OK;
    }

    FreeEveThreadCtx(aft->ctx);
    /* clear memory */
    memset(aft, 0, sizeof(JsonHttp2LogThread));

    SCFree(aft);
    return TM_ECODE_OK;
}

static void OutputHttp2LogDeinitSub(OutputCtx *output_ctx)
{
    OutputHttp2Ctx *http2_ctx = output_ctx->data;
    SCFree(http2_ctx);
    SCFree(output_ctx);
}

static OutputInitResult OutputHttp2LogInitSub(ConfNode *conf, OutputCtx *parent_ctx)
{
    OutputInitResult result = { NULL, false };
    OutputJsonCtx *ojc = parent_ctx->data;

    OutputHttp2Ctx *http2_ctx = SCMalloc(sizeof(OutputHttp2Ctx));
    if (unlikely(http2_ctx == NULL))
        return result;

    OutputCtx *output_ctx = SCCalloc(1, sizeof(OutputCtx));
    if (unlikely(output_ctx == NULL)) {
        SCFree(http2_ctx);
        return result;
    }

    http2_ctx->eve_ctx = ojc;

    output_ctx->data = http2_ctx;
    output_ctx->DeInit = OutputHttp2LogDeinitSub;

    AppLayerParserRegisterLogger(IPPROTO_TCP, ALPROTO_HTTP2);

    result.ctx = output_ctx;
    result.ok = true;
    return result;
}

void JsonHttp2LogRegister (void)
{
    /* also register as child of eve-log */
    OutputRegisterTxSubModuleWithProgress(LOGGER_JSON_TX, "eve-log", MODULE_NAME, "eve-log.http2",
            OutputHttp2LogInitSub, ALPROTO_HTTP2, JsonHttp2Logger, HTTP2StateClosed,
            HTTP2StateClosed, JsonHttp2LogThreadInit, JsonHttp2LogThreadDeinit, NULL);
}
