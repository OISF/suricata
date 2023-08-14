/* Copyright (C) 2023 Open Information Security Foundation
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
 * TODO: Update \author in this file and in output-json-bacnetip.h.
 * TODO: Remove SCLogNotice statements, or convert to debug.
 * TODO: Implement your app-layers logging.
 */

/**
 * \file
 *
 * \author FirstName LastName <yourname@domain>
 *
 * Implement JSON/eve logging app-layer BacNetIp.
 */

#include "suricata-common.h"
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

#include "output-json-bacnetip.h"
#include "rust.h"

typedef struct LogBacNetIpFileCtx_ {
    uint32_t flags;
    OutputJsonCtx *eve_ctx;
} LogBacNetIpFileCtx;

typedef struct LogBacNetIpLogThread_ {
    LogBacNetIpFileCtx *bacnetiplog_ctx;
    OutputJsonThreadCtx *ctx;
} LogBacNetIpLogThread;

static int JsonBacNetIpLogger(ThreadVars *tv, void *thread_data, const Packet *p, Flow *f,
        void *state, void *tx, uint64_t tx_id)
{
    SCLogNotice("JsonBacNetIpLogger");
    LogBacNetIpLogThread *thread = thread_data;

    JsonBuilder *js =
            CreateEveHeader(p, LOG_DIR_PACKET, "bacnetip", NULL, thread->bacnetiplog_ctx->eve_ctx);
    if (unlikely(js == NULL)) {
        return TM_ECODE_FAILED;
    }

    jb_open_object(js, "bacnetip");
    if (!rs_bacnetip_logger_log(tx, js)) {
        goto error;
    }
    jb_close(js);

    OutputJsonBuilderBuffer(js, thread->ctx);
    jb_free(js);

    return TM_ECODE_OK;

error:
    jb_free(js);
    return TM_ECODE_FAILED;
}

static void OutputBacNetIpLogDeInitCtxSub(OutputCtx *output_ctx)
{
    LogBacNetIpFileCtx *bacnetiplog_ctx = (LogBacNetIpFileCtx *)output_ctx->data;
    SCFree(bacnetiplog_ctx);
    SCFree(output_ctx);
}

static OutputInitResult OutputBacNetIpLogInitSub(ConfNode *conf, OutputCtx *parent_ctx)
{
    OutputInitResult result = { NULL, false };
    OutputJsonCtx *ajt = parent_ctx->data;

    LogBacNetIpFileCtx *bacnetiplog_ctx = SCCalloc(1, sizeof(*bacnetiplog_ctx));
    if (unlikely(bacnetiplog_ctx == NULL)) {
        return result;
    }
    bacnetiplog_ctx->eve_ctx = ajt;

    OutputCtx *output_ctx = SCCalloc(1, sizeof(*output_ctx));
    if (unlikely(output_ctx == NULL)) {
        SCFree(bacnetiplog_ctx);
        return result;
    }
    output_ctx->data = bacnetiplog_ctx;
    output_ctx->DeInit = OutputBacNetIpLogDeInitCtxSub;

    SCLogNotice("BacNetIp log sub-module initialized.");

    AppLayerParserRegisterLogger(IPPROTO_TCP, ALPROTO_BACNETIP);

    result.ctx = output_ctx;
    result.ok = true;
    return result;
}

static TmEcode JsonBacNetIpLogThreadInit(ThreadVars *t, const void *initdata, void **data)
{
    LogBacNetIpLogThread *thread = SCCalloc(1, sizeof(*thread));
    if (unlikely(thread == NULL)) {
        return TM_ECODE_FAILED;
    }

    if (initdata == NULL) {
        SCLogDebug("Error getting context for EveLogBacNetIp.  \"initdata\" is NULL.");
        goto error_exit;
    }

    thread->bacnetiplog_ctx = ((OutputCtx *)initdata)->data;
    thread->ctx = CreateEveThreadCtx(t, thread->bacnetiplog_ctx->eve_ctx);
    if (!thread->ctx) {
        goto error_exit;
    }
    *data = (void *)thread;

    return TM_ECODE_OK;

error_exit:
    SCFree(thread);
    return TM_ECODE_FAILED;
}

static TmEcode JsonBacNetIpLogThreadDeinit(ThreadVars *t, void *data)
{
    LogBacNetIpLogThread *thread = (LogBacNetIpLogThread *)data;
    if (thread == NULL) {
        return TM_ECODE_OK;
    }
    FreeEveThreadCtx(thread->ctx);
    SCFree(thread);
    return TM_ECODE_OK;
}

void JsonBacNetIpLogRegister(void)
{
    /* Register as an eve sub-module. */
    OutputRegisterTxSubModule(LOGGER_JSON_TX, "eve-log", "JsonBacNetIpLog", "eve-log.bacnetip",
            OutputBacNetIpLogInitSub, ALPROTO_BACNETIP, JsonBacNetIpLogger,
            JsonBacNetIpLogThreadInit, JsonBacNetIpLogThreadDeinit, NULL);

    SCLogNotice("BacNetIp JSON logger registered.");
}
