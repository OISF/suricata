/* Copyright (C) 2015-2018 Open Information Security Foundation
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
    OutputJsonThreadCtx *thread = thread_data;

    if (rs_nfs_tx_logging_is_filtered(state, nfstx))
        return TM_ECODE_OK;

    json_t *js = CreateJSONHeader(p, LOG_DIR_PACKET, "nfs");
    if (unlikely(js == NULL)) {
        return TM_ECODE_FAILED;
    }

    JsonAddCommonOptions(&thread->ctx->cfg, p, f, js);

    json_t *rpcjs = rs_rpc_log_json_response(tx);
    if (unlikely(rpcjs == NULL)) {
        goto error;
    }
    json_object_set_new(js, "rpc", rpcjs);

    json_t *nfsjs = rs_nfs_log_json_response(state, tx);
    if (unlikely(nfsjs == NULL)) {
        goto error;
    }
    json_object_set_new(js, "nfs", nfsjs);

    MemBufferReset(thread->buffer);
    OutputJSONBuffer(js, thread->ctx->file_ctx, &thread->buffer);

    json_decref(js);
    return TM_ECODE_OK;

error:
    json_decref(js);
    return TM_ECODE_FAILED;
}

static OutputInitResult NFSLogInitSub(ConfNode *conf,
    OutputCtx *parent_ctx)
{
    AppLayerParserRegisterLogger(IPPROTO_TCP, ALPROTO_NFS);
    AppLayerParserRegisterLogger(IPPROTO_UDP, ALPROTO_NFS);
    return OutputJsonLogInitSub(conf, parent_ctx);
}

void JsonNFSLogRegister(void)
{
    /* Register as an eve sub-module. */
    OutputRegisterTxSubModule(LOGGER_JSON_NFS, "eve-log", "JsonNFSLog",
        "eve-log.nfs", NFSLogInitSub, ALPROTO_NFS,
        JsonNFSLogger, JsonLogThreadInit,
        JsonLogThreadDeinit, NULL);

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
