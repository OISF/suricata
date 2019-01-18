/* Copyright (C) 2018 Open Information Security Foundation
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
 * Implement JSON/eve logging app-layer IKEv2.
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

#include "app-layer-ikev2.h"
#include "output-json-ikev2.h"

#ifdef HAVE_RUST
#ifdef HAVE_LIBJANSSON

#include "rust.h"
#include "rust-ikev2-log-gen.h"

typedef struct LogIKEv2FileCtx_ {
    LogFileCtx *file_ctx;
    OutputJsonCommonSettings cfg;
} LogIKEv2FileCtx;

typedef struct LogIKEv2LogThread_ {
    LogIKEv2FileCtx *ikev2log_ctx;
    MemBuffer          *buffer;
} LogIKEv2LogThread;

static int JsonIKEv2Logger(ThreadVars *tv, void *thread_data,
    const Packet *p, Flow *f, void *state, void *tx, uint64_t tx_id)
{
    IKEV2Transaction *ikev2tx = tx;
    LogIKEv2LogThread *thread = thread_data;
    json_t *js, *ikev2js;

    js = CreateJSONHeader((Packet *)p, LOG_DIR_PACKET, "ikev2");
    if (unlikely(js == NULL)) {
        return TM_ECODE_FAILED;
    }

    JsonAddCommonOptions(&thread->ikev2log_ctx->cfg, p, f, js);

    ikev2js = rs_ikev2_log_json_response(state, ikev2tx);
    if (unlikely(ikev2js == NULL)) {
        goto error;
    }
    json_object_set_new(js, "ikev2", ikev2js);

    MemBufferReset(thread->buffer);
    OutputJSONBuffer(js, thread->ikev2log_ctx->file_ctx, &thread->buffer);

    json_decref(js);
    return TM_ECODE_OK;

error:
    json_decref(js);
    return TM_ECODE_FAILED;
}

static void OutputIKEv2LogDeInitCtxSub(OutputCtx *output_ctx)
{
    LogIKEv2FileCtx *ikev2log_ctx = (LogIKEv2FileCtx *)output_ctx->data;
    SCFree(ikev2log_ctx);
    SCFree(output_ctx);
}

static OutputInitResult OutputIKEv2LogInitSub(ConfNode *conf,
    OutputCtx *parent_ctx)
{
    OutputInitResult result = { NULL, false };
    OutputJsonCtx *ajt = parent_ctx->data;

    LogIKEv2FileCtx *ikev2log_ctx = SCCalloc(1, sizeof(*ikev2log_ctx));
    if (unlikely(ikev2log_ctx == NULL)) {
        return result;
    }
    ikev2log_ctx->file_ctx = ajt->file_ctx;
    ikev2log_ctx->cfg = ajt->cfg;

    OutputCtx *output_ctx = SCCalloc(1, sizeof(*output_ctx));
    if (unlikely(output_ctx == NULL)) {
        SCFree(ikev2log_ctx);
        return result;
    }
    output_ctx->data = ikev2log_ctx;
    output_ctx->DeInit = OutputIKEv2LogDeInitCtxSub;

    SCLogDebug("IKEv2 log sub-module initialized.");

    AppLayerParserRegisterLogger(IPPROTO_UDP, ALPROTO_IKEV2);

    result.ctx = output_ctx;
    result.ok = true;
    return result;
}

#define OUTPUT_BUFFER_SIZE 65535

static TmEcode JsonIKEv2LogThreadInit(ThreadVars *t, const void *initdata, void **data)
{
    LogIKEv2LogThread *thread = SCCalloc(1, sizeof(*thread));
    if (unlikely(thread == NULL)) {
        return TM_ECODE_FAILED;
    }

    if (initdata == NULL) {
        SCLogDebug("Error getting context for EveLogIKEv2.  \"initdata\" is NULL.");
        SCFree(thread);
        return TM_ECODE_FAILED;
    }

    thread->buffer = MemBufferCreateNew(OUTPUT_BUFFER_SIZE);
    if (unlikely(thread->buffer == NULL)) {
        SCFree(thread);
        return TM_ECODE_FAILED;
    }

    thread->ikev2log_ctx = ((OutputCtx *)initdata)->data;
    *data = (void *)thread;

    return TM_ECODE_OK;
}

static TmEcode JsonIKEv2LogThreadDeinit(ThreadVars *t, void *data)
{
    LogIKEv2LogThread *thread = (LogIKEv2LogThread *)data;
    if (thread == NULL) {
        return TM_ECODE_OK;
    }
    if (thread->buffer != NULL) {
        MemBufferFree(thread->buffer);
    }
    SCFree(thread);
    return TM_ECODE_OK;
}

void JsonIKEv2LogRegister(void)
{
    /* Register as an eve sub-module. */
    OutputRegisterTxSubModule(LOGGER_JSON_IKEV2, "eve-log", "JsonIKEv2Log",
        "eve-log.ikev2", OutputIKEv2LogInitSub, ALPROTO_IKEV2,
        JsonIKEv2Logger, JsonIKEv2LogThreadInit,
        JsonIKEv2LogThreadDeinit, NULL);

    SCLogDebug("IKEv2 JSON logger registered.");
}

#else /* No JSON support. */

void JsonIKEv2LogRegister(void)
{
}

#endif /* HAVE_LIBJANSSON */
#else /* No rust support. */

void JsonIKEv2LogRegister(void)
{
}

#endif /* HAVE_RUST */
