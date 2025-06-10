/* Copyright (C) 2017-2021 Open Information Security Foundation
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
#include "util-buffer.h"
#include "output.h"
#include "output-json.h"
#include "app-layer-parser.h"
#include "output-json-smb.h"
#include "rust.h"

bool EveSMBAddMetadata(const Flow *f, uint64_t tx_id, SCJsonBuilder *jb)
{
    SMBState *state = FlowGetAppState(f);
    if (state) {
        SMBTransaction *tx = AppLayerParserGetTx(f->proto, ALPROTO_SMB, state, tx_id);
        if (tx) {
            // flags 0 means log all
            return SCSmbLogJsonResponse(jb, state, tx, 0);
        }
    }
    return false;
}

typedef struct LogSmbFileCtx_ {
    uint64_t flags;
    // generic context needed for init by CreateEveThreadCtx
    // comes from parent in SMBLogInitSub
    OutputJsonCtx *eve_ctx;
} LogSmbFileCtx;

// wrapper structure
typedef struct LogSmbLogThread_ {
    // generic structure
    OutputJsonThreadCtx *ctx;
    // smb-specific structure
    LogSmbFileCtx *smblog_ctx;
} LogSmbLogThread;

static int JsonSMBLogger(ThreadVars *tv, void *thread_data,
    const Packet *p, Flow *f, void *state, void *tx, uint64_t tx_id)
{
    LogSmbLogThread *thread = thread_data;

    SCJsonBuilder *jb =
            CreateEveHeaderWithTxId(p, LOG_DIR_FLOW, "smb", NULL, tx_id, thread->ctx->ctx);
    if (unlikely(jb == NULL)) {
        return TM_ECODE_FAILED;
    }

    SCJbOpenObject(jb, "smb");
    if (!SCSmbLogJsonResponse(jb, state, tx, thread->smblog_ctx->flags)) {
        goto error;
    }
    SCJbClose(jb);

    OutputJsonBuilderBuffer(tv, p, p->flow, jb, thread->ctx);

    SCJbFree(jb);
    return TM_ECODE_OK;

error:
    SCJbFree(jb);
    return TM_ECODE_FAILED;
}

static void LogSmbLogDeInitCtxSub(OutputCtx *output_ctx)
{
    LogSmbFileCtx *smblog_ctx = (LogSmbFileCtx *)output_ctx->data;
    SCFree(smblog_ctx);
    SCFree(output_ctx);
}

static OutputInitResult SMBLogInitSub(SCConfNode *conf, OutputCtx *parent_ctx)
{
    SCAppLayerParserRegisterLogger(IPPROTO_TCP, ALPROTO_SMB);
    SCAppLayerParserRegisterLogger(IPPROTO_UDP, ALPROTO_SMB);
    OutputInitResult r = OutputJsonLogInitSub(conf, parent_ctx);
    if (r.ok) {
        // generic init is ok, try smb-specific one
        LogSmbFileCtx *smblog_ctx = SCCalloc(1, sizeof(LogSmbFileCtx));
        if (unlikely(smblog_ctx == NULL)) {
            SCFree(r.ctx);
            r.ctx = NULL;
            r.ok = false;
            return r;
        }
        smblog_ctx->eve_ctx = parent_ctx->data;
        // parse config for flags/types to log
        smblog_ctx->flags = SCSmbLogParseConfig(conf);
        r.ctx->data = smblog_ctx;
        r.ctx->DeInit = LogSmbLogDeInitCtxSub;
    }
    return r;
}

static TmEcode LogSmbLogThreadInit(ThreadVars *t, const void *initdata, void **data)
{
    if (initdata == NULL) {
        return TM_ECODE_FAILED;
    }

    LogSmbLogThread *aft = SCCalloc(1, sizeof(LogSmbLogThread));
    if (unlikely(aft == NULL)) {
        return TM_ECODE_FAILED;
    }

    aft->smblog_ctx = ((OutputCtx *)initdata)->data;
    aft->ctx = CreateEveThreadCtx(t, aft->smblog_ctx->eve_ctx);
    if (!aft->ctx) {
        SCFree(aft);
        return TM_ECODE_FAILED;
    }

    *data = (void *)aft;
    return TM_ECODE_OK;
}

// LogSmbLogThread structure wraps a generic OutputJsonThreadCtx
// created by CreateEveThreadCtx
static TmEcode LogSmbLogThreadDeinit(ThreadVars *t, void *data)
{
    LogSmbLogThread *aft = (LogSmbLogThread *)data;
    TmEcode r = JsonLogThreadDeinit(t, aft->ctx);
    SCFree(aft);
    return r;
}

void JsonSMBLogRegister(void)
{
    /* Register as an eve sub-module. */
    OutputRegisterTxSubModule(LOGGER_JSON_TX, "eve-log", "JsonSMBLog", "eve-log.smb", SMBLogInitSub,
            ALPROTO_SMB, JsonSMBLogger, LogSmbLogThreadInit, LogSmbLogThreadDeinit);

    SCLogDebug("SMB JSON logger registered.");
}
