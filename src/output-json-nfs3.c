/* Copyright (C) 2015 Open Information Security Foundation
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

/*
 * TODO: Update \author in this file and in output-json-nfs3.h.
 * TODO: Remove SCLogNotice statements, or convert to debug.
 * TODO: Implement your app-layers logging.
 */

/**
 * \file
 *
 * \author FirstName LastName <yourname@domain>
 *
 * Implement JSON/eve logging app-layer NFS3.
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

#include "app-layer-nfs3.h"
#include "output-json-nfs3.h"

#ifdef HAVE_RUST
#ifdef HAVE_LIBJANSSON
#include "rust-nfs-log-gen.h"

typedef struct LogNFS3FileCtx_ {
    LogFileCtx *file_ctx;
    uint32_t    flags;
} LogNFS3FileCtx;

typedef struct LogNFS3LogThread_ {
    LogNFS3FileCtx *nfs3log_ctx;
    uint32_t            count;
    MemBuffer          *buffer;
} LogNFS3LogThread;

static int JsonNFS3Logger(ThreadVars *tv, void *thread_data,
    const Packet *p, Flow *f, void *state, void *tx, uint64_t tx_id)
{
    NFS3Transaction *nfs3tx = tx;
    LogNFS3LogThread *thread = thread_data;
    json_t *js, *nfs3js;

    if (rs_nfs3_tx_logging_is_filtered(nfs3tx))
        return TM_ECODE_OK;

    js = CreateJSONHeader((Packet *)p, 0, "nfs3");
    if (unlikely(js == NULL)) {
        return TM_ECODE_FAILED;
    }

    nfs3js = rs_nfs3_log_json_response(tx);
    if (unlikely(nfs3js == NULL)) {
        goto error;
    }

    json_object_set_new(js, "nfs3", nfs3js);

    MemBufferReset(thread->buffer);
    OutputJSONBuffer(js, thread->nfs3log_ctx->file_ctx, &thread->buffer);

    json_decref(js);
    return TM_ECODE_OK;

error:
    json_decref(js);
    return TM_ECODE_FAILED;
}

static void OutputNFS3LogDeInitCtxSub(OutputCtx *output_ctx)
{
    LogNFS3FileCtx *nfs3log_ctx = (LogNFS3FileCtx *)output_ctx->data;
    SCFree(nfs3log_ctx);
    SCFree(output_ctx);
}

static OutputCtx *OutputNFS3LogInitSub(ConfNode *conf,
    OutputCtx *parent_ctx)
{
    AlertJsonThread *ajt = parent_ctx->data;

    LogNFS3FileCtx *nfs3log_ctx = SCCalloc(1, sizeof(*nfs3log_ctx));
    if (unlikely(nfs3log_ctx == NULL)) {
        return NULL;
    }
    nfs3log_ctx->file_ctx = ajt->file_ctx;

    OutputCtx *output_ctx = SCCalloc(1, sizeof(*output_ctx));
    if (unlikely(output_ctx == NULL)) {
        SCFree(nfs3log_ctx);
        return NULL;
    }
    output_ctx->data = nfs3log_ctx;
    output_ctx->DeInit = OutputNFS3LogDeInitCtxSub;

    SCLogDebug("NFS3 log sub-module initialized.");

    AppLayerParserRegisterLogger(IPPROTO_TCP, ALPROTO_NFS3);

    return output_ctx;
}

#define OUTPUT_BUFFER_SIZE 65535

static TmEcode JsonNFS3LogThreadInit(ThreadVars *t, const void *initdata, void **data)
{
    LogNFS3LogThread *thread = SCCalloc(1, sizeof(*thread));
    if (unlikely(thread == NULL)) {
        return TM_ECODE_FAILED;
    }

    if (initdata == NULL) {
        SCLogDebug("Error getting context for EveLogNFS3.  \"initdata\" is NULL.");
        SCFree(thread);
        return TM_ECODE_FAILED;
    }

    thread->buffer = MemBufferCreateNew(OUTPUT_BUFFER_SIZE);
    if (unlikely(thread->buffer == NULL)) {
        SCFree(thread);
        return TM_ECODE_FAILED;
    }

    thread->nfs3log_ctx = ((OutputCtx *)initdata)->data;
    *data = (void *)thread;

    return TM_ECODE_OK;
}

static TmEcode JsonNFS3LogThreadDeinit(ThreadVars *t, void *data)
{
    LogNFS3LogThread *thread = (LogNFS3LogThread *)data;
    if (thread == NULL) {
        return TM_ECODE_OK;
    }
    if (thread->buffer != NULL) {
        MemBufferFree(thread->buffer);
    }
    SCFree(thread);
    return TM_ECODE_OK;
}

void JsonNFS3LogRegister(void)
{
    /* Register as an eve sub-module. */
    OutputRegisterTxSubModule(LOGGER_JSON_NFS3, "eve-log", "JsonNFS3Log",
        "eve-log.nfs3", OutputNFS3LogInitSub, ALPROTO_NFS3,
        JsonNFS3Logger, JsonNFS3LogThreadInit,
        JsonNFS3LogThreadDeinit, NULL);

    SCLogDebug("NFS3 JSON logger registered.");
}

#else /* No JSON support. */

void JsonNFS3LogRegister(void)
{
}

#endif /* HAVE_LIBJANSSON */

#else /* no rust */

void JsonNFS3LogRegister(void)
{
}

#endif /* HAVE_RUST */
