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
 * Implement JSON/eve logging app-layer KRB5.
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

#include "app-layer-krb5.h"
#include "output-json-krb5.h"

#include "rust.h"

typedef struct LogKRB5FileCtx_ {
    LogFileCtx *file_ctx;
    OutputJsonCommonSettings cfg;
} LogKRB5FileCtx;

typedef struct LogKRB5LogThread_ {
    LogFileCtx *file_ctx;
    LogKRB5FileCtx *krb5log_ctx;
    MemBuffer          *buffer;
} LogKRB5LogThread;

static int JsonKRB5Logger(ThreadVars *tv, void *thread_data,
    const Packet *p, Flow *f, void *state, void *tx, uint64_t tx_id)
{
    KRB5Transaction *krb5tx = tx;
    LogKRB5LogThread *thread = thread_data;

    JsonBuilder *jb = CreateEveHeader(p, LOG_DIR_PACKET, "krb5", NULL);
    if (unlikely(jb == NULL)) {
        return TM_ECODE_FAILED;
    }

    EveAddCommonOptions(&thread->krb5log_ctx->cfg, p, f, jb);

    jb_open_object(jb, "krb5");
    if (!rs_krb5_log_json_response(jb, state, krb5tx)) {
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

static void OutputKRB5LogDeInitCtxSub(OutputCtx *output_ctx)
{
    LogKRB5FileCtx *krb5log_ctx = (LogKRB5FileCtx *)output_ctx->data;
    SCFree(krb5log_ctx);
    SCFree(output_ctx);
}

static OutputInitResult OutputKRB5LogInitSub(ConfNode *conf,
    OutputCtx *parent_ctx)
{
    OutputInitResult result = { NULL, false };
    OutputJsonCtx *ajt = parent_ctx->data;

    LogKRB5FileCtx *krb5log_ctx = SCCalloc(1, sizeof(*krb5log_ctx));
    if (unlikely(krb5log_ctx == NULL)) {
        return result;
    }
    krb5log_ctx->file_ctx = ajt->file_ctx;
    krb5log_ctx->cfg = ajt->cfg;

    OutputCtx *output_ctx = SCCalloc(1, sizeof(*output_ctx));
    if (unlikely(output_ctx == NULL)) {
        SCFree(krb5log_ctx);
        return result;
    }
    output_ctx->data = krb5log_ctx;
    output_ctx->DeInit = OutputKRB5LogDeInitCtxSub;

    SCLogDebug("KRB5 log sub-module initialized.");

    AppLayerParserRegisterLogger(IPPROTO_TCP, ALPROTO_KRB5);
    AppLayerParserRegisterLogger(IPPROTO_UDP, ALPROTO_KRB5);

    result.ctx = output_ctx;
    result.ok = true;
    return result;
}

static TmEcode JsonKRB5LogThreadInit(ThreadVars *t, const void *initdata, void **data)
{
    LogKRB5LogThread *thread = SCCalloc(1, sizeof(*thread));
    if (unlikely(thread == NULL)) {
        return TM_ECODE_FAILED;
    }

    if (initdata == NULL) {
        SCLogDebug("Error getting context for EveLogKRB5.  \"initdata\" is NULL.");
        goto error_exit;
    }

    thread->buffer = MemBufferCreateNew(JSON_OUTPUT_BUFFER_SIZE);
    if (unlikely(thread->buffer == NULL)) {
        goto error_exit;
    }

    thread->krb5log_ctx = ((OutputCtx *)initdata)->data;
    thread->file_ctx = LogFileEnsureExists(thread->krb5log_ctx->file_ctx, t->id);
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

static TmEcode JsonKRB5LogThreadDeinit(ThreadVars *t, void *data)
{
    LogKRB5LogThread *thread = (LogKRB5LogThread *)data;
    if (thread == NULL) {
        return TM_ECODE_OK;
    }
    if (thread->buffer != NULL) {
        MemBufferFree(thread->buffer);
    }
    SCFree(thread);
    return TM_ECODE_OK;
}

void JsonKRB5LogRegister(void)
{
    /* Register as an eve sub-module. */
    OutputRegisterTxSubModule(LOGGER_JSON_KRB5, "eve-log", "JsonKRB5Log",
        "eve-log.krb5", OutputKRB5LogInitSub, ALPROTO_KRB5,
        JsonKRB5Logger, JsonKRB5LogThreadInit,
        JsonKRB5LogThreadDeinit, NULL);

    SCLogDebug("KRB5 JSON logger registered.");
}
