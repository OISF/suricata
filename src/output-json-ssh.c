/* Copyright (C) 2014-2020 Open Information Security Foundation
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
 * Implements SSH JSON logging portion of the engine.
 */

#include "suricata-common.h"
#include "debug.h"
#include "detect.h"
#include "pkt-var.h"
#include "conf.h"

#include "threads.h"
#include "threadvars.h"
#include "tm-threads.h"

#include "util-print.h"
#include "util-unittest.h"

#include "util-debug.h"
#include "app-layer-parser.h"
#include "output.h"
#include "app-layer-ssh.h"
#include "app-layer.h"
#include "util-privs.h"
#include "util-buffer.h"

#include "util-logopenfile.h"
#include "util-crypt.h"

#include "output-json.h"
#include "output-json-ssh.h"
#include "rust.h"

#define MODULE_NAME "LogSshLog"

typedef struct OutputSshCtx_ {
    LogFileCtx *file_ctx;
    OutputJsonCommonSettings cfg;
} OutputSshCtx;


typedef struct JsonSshLogThread_ {
    OutputSshCtx *sshlog_ctx;
    LogFileCtx *file_ctx;
    MemBuffer *buffer;
} JsonSshLogThread;


static int JsonSshLogger(ThreadVars *tv, void *thread_data, const Packet *p,
                         Flow *f, void *state, void *txptr, uint64_t tx_id)
{
    JsonSshLogThread *aft = (JsonSshLogThread *)thread_data;
    OutputSshCtx *ssh_ctx = aft->sshlog_ctx;

    if (unlikely(state == NULL)) {
        return 0;
    }

    JsonBuilder *js = CreateEveHeaderWithTxId(p, LOG_DIR_FLOW, "ssh", NULL, tx_id);
    if (unlikely(js == NULL))
        return 0;

    EveAddCommonOptions(&ssh_ctx->cfg, p, f, js);

    /* reset */
    MemBufferReset(aft->buffer);

    jb_open_object(js, "ssh");
    if (!rs_ssh_log_json(txptr, js)) {
        goto end;
    }
    jb_close(js);
    OutputJsonBuilderBuffer(js, aft->file_ctx, &aft->buffer);

end:
    jb_free(js);
    return 0;
}

static TmEcode JsonSshLogThreadInit(ThreadVars *t, const void *initdata, void **data)
{
    if (initdata == NULL) {
        SCLogDebug("Error getting context for EveLogSSH.  \"initdata\" argument NULL");
        return TM_ECODE_FAILED;
    }

    JsonSshLogThread *aft = SCCalloc(1, sizeof(JsonSshLogThread));
    if (unlikely(aft == NULL))
        return TM_ECODE_FAILED;

    /* Use the Output Context (file pointer and mutex) */
    aft->sshlog_ctx = ((OutputCtx *)initdata)->data;

    aft->buffer = MemBufferCreateNew(JSON_OUTPUT_BUFFER_SIZE);
    if (aft->buffer == NULL) {
        goto error_exit;
    }

    aft->file_ctx = LogFileEnsureExists(aft->sshlog_ctx->file_ctx, t->id);
    if (!aft->file_ctx) {
        goto error_exit;
    }

    *data = (void *)aft;
    return TM_ECODE_OK;

error_exit:
    if (aft->buffer != NULL) {
        MemBufferFree(aft->buffer);
    }
    SCFree(aft);
    return TM_ECODE_FAILED;
}

static TmEcode JsonSshLogThreadDeinit(ThreadVars *t, void *data)
{
    JsonSshLogThread *aft = (JsonSshLogThread *)data;
    if (aft == NULL) {
        return TM_ECODE_OK;
    }

    MemBufferFree(aft->buffer);
    /* clear memory */
    memset(aft, 0, sizeof(JsonSshLogThread));

    SCFree(aft);
    return TM_ECODE_OK;
}

static void OutputSshLogDeinitSub(OutputCtx *output_ctx)
{
    OutputSshCtx *ssh_ctx = output_ctx->data;
    SCFree(ssh_ctx);
    SCFree(output_ctx);
}

static OutputInitResult OutputSshLogInitSub(ConfNode *conf, OutputCtx *parent_ctx)
{
    OutputInitResult result = { NULL, false };
    OutputJsonCtx *ojc = parent_ctx->data;

    OutputSshCtx *ssh_ctx = SCMalloc(sizeof(OutputSshCtx));
    if (unlikely(ssh_ctx == NULL))
        return result;

    OutputCtx *output_ctx = SCCalloc(1, sizeof(OutputCtx));
    if (unlikely(output_ctx == NULL)) {
        SCFree(ssh_ctx);
        return result;
    }

    ssh_ctx->file_ctx = ojc->file_ctx;
    ssh_ctx->cfg = ojc->cfg;

    output_ctx->data = ssh_ctx;
    output_ctx->DeInit = OutputSshLogDeinitSub;

    AppLayerParserRegisterLogger(IPPROTO_TCP, ALPROTO_SSH);

    result.ctx = output_ctx;
    result.ok = true;
    return result;
}

void JsonSshLogRegister (void)
{
    /* register as child of eve-log */
    OutputRegisterTxSubModuleWithCondition(LOGGER_JSON_SSH,
        "eve-log", "JsonSshLog", "eve-log.ssh",
        OutputSshLogInitSub, ALPROTO_SSH, JsonSshLogger,
        SSHTxLogCondition, JsonSshLogThreadInit, JsonSshLogThreadDeinit, NULL);
}
