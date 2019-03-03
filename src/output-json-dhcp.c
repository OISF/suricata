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
 * TODO: Update \author in this file and in output-json-dhcp.h.
 * TODO: Remove SCLogNotice statements, or convert to debug.
 * TODO: Implement your app-layers logging.
 */

/**
 * \file
 *
 * \author Jason Ish <jason.ish@oisf.net>
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

#include "app-layer-dhcp.h"
#include "output-json-dhcp.h"

#if defined(HAVE_LIBJANSSON) && defined(HAVE_RUST)

#include "rust-dhcp-logger-gen.h"

typedef struct LogDHCPFileCtx_ {
    LogFileCtx *file_ctx;
    uint32_t    flags;
    void       *rs_logger;
} LogDHCPFileCtx;

typedef struct LogDHCPLogThread_ {
    LogDHCPFileCtx *dhcplog_ctx;
    uint32_t        count;
    MemBuffer      *buffer;
} LogDHCPLogThread;

static int JsonDHCPLogger(ThreadVars *tv, void *thread_data,
    const Packet *p, Flow *f, void *state, void *tx, uint64_t tx_id)
{
    LogDHCPLogThread *thread = thread_data;
    LogDHCPFileCtx *ctx = thread->dhcplog_ctx;

    json_t *js = CreateJSONHeader((Packet *)p, 0, "dhcp");
    if (unlikely(js == NULL)) {
        return TM_ECODE_FAILED;
    }

    json_t *dhcp_js = rs_dhcp_logger_log(ctx->rs_logger, tx);
    if (unlikely(dhcp_js == NULL)) {
        goto skip;
    }
    json_object_set_new(js, "dhcp", dhcp_js);

    MemBufferReset(thread->buffer);
    OutputJSONBuffer(js, thread->dhcplog_ctx->file_ctx, &thread->buffer);
    json_decref(js);

    return TM_ECODE_OK;

skip:
    json_decref(js);
    return TM_ECODE_OK;
}

static void OutputDHCPLogDeInitCtxSub(OutputCtx *output_ctx)
{
    LogDHCPFileCtx *dhcplog_ctx = (LogDHCPFileCtx *)output_ctx->data;
    rs_dhcp_logger_free(dhcplog_ctx->rs_logger);
    SCFree(dhcplog_ctx);
    SCFree(output_ctx);
}

static OutputInitResult OutputDHCPLogInitSub(ConfNode *conf,
    OutputCtx *parent_ctx)
{
    OutputInitResult result = { NULL, false };
    OutputJsonCtx *ajt = parent_ctx->data;

    LogDHCPFileCtx *dhcplog_ctx = SCCalloc(1, sizeof(*dhcplog_ctx));
    if (unlikely(dhcplog_ctx == NULL)) {
        return result;
    }
    dhcplog_ctx->file_ctx = ajt->file_ctx;

    OutputCtx *output_ctx = SCCalloc(1, sizeof(*output_ctx));
    if (unlikely(output_ctx == NULL)) {
        SCFree(dhcplog_ctx);
        return result;
    }
    output_ctx->data = dhcplog_ctx;
    output_ctx->DeInit = OutputDHCPLogDeInitCtxSub;

    dhcplog_ctx->rs_logger = rs_dhcp_logger_new(conf);

    AppLayerParserRegisterLogger(IPPROTO_UDP, ALPROTO_DHCP);

    result.ctx = output_ctx;
    result.ok = true;
    return result;
}

#define OUTPUT_BUFFER_SIZE 65535

static TmEcode JsonDHCPLogThreadInit(ThreadVars *t, const void *initdata, void **data)
{
    LogDHCPLogThread *thread = SCCalloc(1, sizeof(*thread));
    if (unlikely(thread == NULL)) {
        return TM_ECODE_FAILED;
    }

    if (initdata == NULL) {
        SCLogDebug("Error getting context for EveLogDHCP.  \"initdata\" is NULL.");
        SCFree(thread);
        return TM_ECODE_FAILED;
    }

    thread->buffer = MemBufferCreateNew(OUTPUT_BUFFER_SIZE);
    if (unlikely(thread->buffer == NULL)) {
        SCFree(thread);
        return TM_ECODE_FAILED;
    }

    thread->dhcplog_ctx = ((OutputCtx *)initdata)->data;
    *data = (void *)thread;

    return TM_ECODE_OK;
}

static TmEcode JsonDHCPLogThreadDeinit(ThreadVars *t, void *data)
{
    LogDHCPLogThread *thread = (LogDHCPLogThread *)data;
    if (thread == NULL) {
        return TM_ECODE_OK;
    }
    if (thread->buffer != NULL) {
        MemBufferFree(thread->buffer);
    }
    SCFree(thread);
    return TM_ECODE_OK;
}

void JsonDHCPLogRegister(void)
{
    /* Register as an eve sub-module. */
    OutputRegisterTxSubModule(LOGGER_JSON_DHCP, "eve-log", "JsonDHCPLog",
        "eve-log.dhcp", OutputDHCPLogInitSub, ALPROTO_DHCP,
        JsonDHCPLogger, JsonDHCPLogThreadInit,
        JsonDHCPLogThreadDeinit, NULL);

    SCSetModule("output-json-dhcp");
}

#else /* No JSON support. */

void JsonDHCPLogRegister(void)
{
}

#endif /* HAVE_LIBJANSSON */
