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

/**
 * \file
 *
 * \author Victor Julien <victor@inliniac.net>
 *
 * Implement JSON/eve logging app-layer NFS.
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

#include "output-json-nfs.h"

#ifdef HAVE_RUST
#ifdef HAVE_LIBJANSSON
#include "rust.h"
#include "rust-nfs-log-gen.h"

typedef struct LogNFSFileCtx_ {
    LogFileCtx *file_ctx;
    uint32_t    flags;
} LogNFSFileCtx;

typedef struct LogNFSLogThread_ {
    LogNFSFileCtx *nfslog_ctx;
    uint32_t            count;
    MemBuffer          *buffer;
} LogNFSLogThread;

json_t *JsonNFSAddMetadataRPC(const Flow *f, uint64_t tx_id)
{
    NFSState *state = FlowGetAppState(f);
    if (state) {
        NFSTransaction *tx = AppLayerParserGetTx(f->proto, ALPROTO_NFS, state, tx_id);
        if (tx) {
            return rs_rpc_log_json_response(tx);
        }
    }

    return NULL;
}

json_t *JsonNFSAddMetadata(const Flow *f, uint64_t tx_id)
{
    NFSState *state = FlowGetAppState(f);
    if (state) {
        NFSTransaction *tx = AppLayerParserGetTx(f->proto, ALPROTO_NFS, state, tx_id);
        if (tx) {
            return rs_nfs_log_json_response(state, tx);
        }
    }

    return NULL;
}

static int JsonNFSLogger(ThreadVars *tv, void *thread_data,
    const Packet *p, Flow *f, void *state, void *tx, uint64_t tx_id)
{
    NFSTransaction *nfstx = tx;
    LogNFSLogThread *thread = thread_data;
    json_t *js, *nfsjs;

    if (rs_nfs_tx_logging_is_filtered(nfstx))
        return TM_ECODE_OK;

    js = CreateJSONHeader((Packet *)p, 0, "nfs");
    if (unlikely(js == NULL)) {
        return TM_ECODE_FAILED;
    }

    json_t *rpcjs = rs_rpc_log_json_response(tx);
    if (unlikely(rpcjs == NULL)) {
        goto error;
    }
    json_object_set_new(js, "rpc", rpcjs);

    nfsjs = rs_nfs_log_json_response(state, tx);
    if (unlikely(nfsjs == NULL)) {
        goto error;
    }
    json_object_set_new(js, "nfs", nfsjs);

    MemBufferReset(thread->buffer);
    OutputJSONBuffer(js, thread->nfslog_ctx->file_ctx, &thread->buffer);

    json_decref(js);
    return TM_ECODE_OK;

error:
    json_decref(js);
    return TM_ECODE_FAILED;
}

static void OutputNFSLogDeInitCtxSub(OutputCtx *output_ctx)
{
    LogNFSFileCtx *nfslog_ctx = (LogNFSFileCtx *)output_ctx->data;
    SCFree(nfslog_ctx);
    SCFree(output_ctx);
}

static OutputCtx *OutputNFSLogInitSub(ConfNode *conf,
    OutputCtx *parent_ctx)
{
    AlertJsonThread *ajt = parent_ctx->data;

    LogNFSFileCtx *nfslog_ctx = SCCalloc(1, sizeof(*nfslog_ctx));
    if (unlikely(nfslog_ctx == NULL)) {
        return NULL;
    }
    nfslog_ctx->file_ctx = ajt->file_ctx;

    OutputCtx *output_ctx = SCCalloc(1, sizeof(*output_ctx));
    if (unlikely(output_ctx == NULL)) {
        SCFree(nfslog_ctx);
        return NULL;
    }
    output_ctx->data = nfslog_ctx;
    output_ctx->DeInit = OutputNFSLogDeInitCtxSub;

    SCLogDebug("NFS log sub-module initialized.");

    AppLayerParserRegisterLogger(IPPROTO_TCP, ALPROTO_NFS);
    AppLayerParserRegisterLogger(IPPROTO_UDP, ALPROTO_NFS);

    return output_ctx;
}

#define OUTPUT_BUFFER_SIZE 65535

static TmEcode JsonNFSLogThreadInit(ThreadVars *t, const void *initdata, void **data)
{
    LogNFSLogThread *thread = SCCalloc(1, sizeof(*thread));
    if (unlikely(thread == NULL)) {
        return TM_ECODE_FAILED;
    }

    if (initdata == NULL) {
        SCLogDebug("Error getting context for EveLogNFS.  \"initdata\" is NULL.");
        SCFree(thread);
        return TM_ECODE_FAILED;
    }

    thread->buffer = MemBufferCreateNew(OUTPUT_BUFFER_SIZE);
    if (unlikely(thread->buffer == NULL)) {
        SCFree(thread);
        return TM_ECODE_FAILED;
    }

    thread->nfslog_ctx = ((OutputCtx *)initdata)->data;
    *data = (void *)thread;

    return TM_ECODE_OK;
}

static TmEcode JsonNFSLogThreadDeinit(ThreadVars *t, void *data)
{
    LogNFSLogThread *thread = (LogNFSLogThread *)data;
    if (thread == NULL) {
        return TM_ECODE_OK;
    }
    if (thread->buffer != NULL) {
        MemBufferFree(thread->buffer);
    }
    SCFree(thread);
    return TM_ECODE_OK;
}

void JsonNFSLogRegister(void)
{
    /* Register as an eve sub-module. */
    OutputRegisterTxSubModule(LOGGER_JSON_NFS, "eve-log", "JsonNFSLog",
        "eve-log.nfs", OutputNFSLogInitSub, ALPROTO_NFS,
        JsonNFSLogger, JsonNFSLogThreadInit,
        JsonNFSLogThreadDeinit, NULL);

    SCLogDebug("NFS JSON logger registered.");
}

#else /* No JSON support. */

void JsonNFSLogRegister(void)
{
}

#endif /* HAVE_LIBJANSSON */

#else /* no rust */

void JsonNFSLogRegister(void)
{
}

#endif /* HAVE_RUST */
