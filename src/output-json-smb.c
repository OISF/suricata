/* Copyright (C) 2017-2018 Open Information Security Foundation
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
 * Implement JSON/eve logging app-layer SMB.
 */

#include "suricata-common.h"
#include "debug.h"
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

#include "output-json-smb.h"

#ifdef HAVE_LIBJANSSON
#include "rust.h"
#include "rust-smb-log-gen.h"

json_t *JsonSMBAddMetadata(const Flow *f, uint64_t tx_id)
{
    SMBState *state = FlowGetAppState(f);
    if (state) {
        SMBTransaction *tx = AppLayerParserGetTx(f->proto, ALPROTO_SMB, state, tx_id);
        if (tx) {
            return rs_smb_log_json_response(state, tx);
        }
    }

    return NULL;
}

static int JsonSMBLogger(ThreadVars *tv, void *thread_data,
    const Packet *p, Flow *f, void *state, void *tx, uint64_t tx_id)
{
    OutputJsonThreadCtx *thread = thread_data;
    json_t *js, *smbjs;

    js = CreateJSONHeader(p, LOG_DIR_FLOW, "smb");
    if (unlikely(js == NULL)) {
        return TM_ECODE_FAILED;
    }

    smbjs = rs_smb_log_json_response(state, tx);
    if (unlikely(smbjs == NULL)) {
        goto error;
    }
    json_object_set_new(js, "smb", smbjs);

    MemBufferReset(thread->buffer);
    OutputJSONBuffer(js, thread->ctx->file_ctx, &thread->buffer);

    json_decref(js);
    return TM_ECODE_OK;

error:
    json_decref(js);
    return TM_ECODE_FAILED;
}

static OutputInitResult SMBLogInitSub(ConfNode *conf, OutputCtx *parent_ctx)
{
    AppLayerParserRegisterLogger(IPPROTO_TCP, ALPROTO_SMB);
    AppLayerParserRegisterLogger(IPPROTO_UDP, ALPROTO_SMB);
    return OutputJsonLogInitSub(conf, parent_ctx);
}

void JsonSMBLogRegister(void)
{
    /* Register as an eve sub-module. */
    OutputRegisterTxSubModule(LOGGER_JSON_SMB, "eve-log", "JsonSMBLog",
        "eve-log.smb", SMBLogInitSub, ALPROTO_SMB,
        JsonSMBLogger, JsonLogThreadInit,
        JsonLogThreadDeinit, NULL);

    SCLogDebug("SMB JSON logger registered.");
}

#else /* No JSON support. */

void JsonSMBLogRegister(void)
{
}

#endif /* HAVE_LIBJANSSON */

