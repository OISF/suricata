/* Copyright (C) 2015-2021 Open Information Security Foundation
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
#include "detect.h"

#include "output-json.h"

#include "app-layer-parser.h"

#include "output-json-nfs.h"

bool EveNFSAddMetadataRPC(const Flow *f, uint64_t tx_id, JsonBuilder *jb)
{
    NFSState *state = FlowGetAppState(f);
    if (state) {
        NFSTransaction *tx = AppLayerParserGetTx(f->proto, ALPROTO_NFS, state, tx_id);
        if (tx) {
            return rs_rpc_log_json_response(tx, jb);
        }
    }
    return false;
}

bool EveNFSAddMetadata(const Flow *f, uint64_t tx_id, JsonBuilder *jb)
{
    NFSState *state = FlowGetAppState(f);
    if (state) {
        NFSTransaction *tx = AppLayerParserGetTx(f->proto, ALPROTO_NFS, state, tx_id);
        if (tx) {
            return rs_nfs_log_json_response(state, tx, jb);
        }
    }
    return false;
}

static int JsonNFSLogger(ThreadVars *tv, void *thread_data,
    const Packet *p, Flow *f, void *state, void *tx, uint64_t tx_id)
{
    NFSTransaction *nfstx = tx;
    OutputJsonThreadCtx *thread = thread_data;

    if (rs_nfs_tx_logging_is_filtered(state, nfstx))
        return TM_ECODE_OK;

    JsonBuilder *jb = CreateEveHeader(p, LOG_DIR_PACKET, "nfs", NULL, thread->ctx);
    if (unlikely(jb == NULL)) {
        return TM_ECODE_OK;
    }

    jb_open_object(jb, "rpc");
    rs_rpc_log_json_response(tx, jb);
    jb_close(jb);

    jb_open_object(jb, "nfs");
    rs_nfs_log_json_response(state, tx, jb);
    jb_close(jb);

    MemBufferReset(thread->buffer);
    OutputJsonBuilderBuffer(jb, thread);
    jb_free(jb);
    return TM_ECODE_OK;
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
    OutputRegisterTxSubModule(LOGGER_JSON_TX, "eve-log", "JsonNFSLog", "eve-log.nfs", NFSLogInitSub,
            ALPROTO_NFS, JsonNFSLogger, JsonLogThreadInit, JsonLogThreadDeinit, NULL);

    SCLogDebug("NFS JSON logger registered.");
}
