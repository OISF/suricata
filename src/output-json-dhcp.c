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
 * \author Jason Ish <jason.ish@oisf.net>
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

#include "output-json-dhcp.h"
#include "rust.h"


typedef struct LogDHCPFileCtx_ {
    void       *rs_logger;
    OutputJsonCtx *eve_ctx;
} LogDHCPFileCtx;

typedef struct LogDHCPLogThread_ {
    LogDHCPFileCtx *dhcplog_ctx;
    OutputJsonThreadCtx *thread;
} LogDHCPLogThread;

static int JsonDHCPLogger(ThreadVars *tv, void *thread_data,
    const Packet *p, Flow *f, void *state, void *tx, uint64_t tx_id)
{
    LogDHCPLogThread *thread = thread_data;
    LogDHCPFileCtx *ctx = thread->dhcplog_ctx;

    if (!rs_dhcp_logger_do_log(ctx->rs_logger, tx)) {
        return TM_ECODE_OK;
    }

    JsonBuilder *js = CreateEveHeader((Packet *)p, 0, "dhcp", NULL, ctx->eve_ctx);
    if (unlikely(js == NULL)) {
        return TM_ECODE_FAILED;
    }

    rs_dhcp_logger_log(ctx->rs_logger, tx, js);

    OutputJsonBuilderBuffer(js, thread->thread);
    jb_free(js);

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

    LogDHCPFileCtx *dhcplog_ctx = SCCalloc(1, sizeof(*dhcplog_ctx));
    if (unlikely(dhcplog_ctx == NULL)) {
        return result;
    }
    dhcplog_ctx->eve_ctx = parent_ctx->data;

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

static TmEcode JsonDHCPLogThreadInit(ThreadVars *t, const void *initdata, void **data)
{
    LogDHCPLogThread *thread = SCCalloc(1, sizeof(*thread));
    if (unlikely(thread == NULL)) {
        return TM_ECODE_FAILED;
    }
    LogDHCPFileCtx *ctx = ((OutputCtx *)initdata)->data;
    thread->dhcplog_ctx = ctx;
    thread->thread = CreateEveThreadCtx(t, ctx->eve_ctx);
    if (thread->thread == NULL) {
        SCFree(thread);
        return TM_ECODE_FAILED;
    }

    *data = (void *)thread;
    return TM_ECODE_OK;
}

static TmEcode JsonDHCPLogThreadDeinit(ThreadVars *t, void *data)
{
    LogDHCPLogThread *thread = (LogDHCPLogThread *)data;
    if (thread == NULL) {
        return TM_ECODE_OK;
    }
    FreeEveThreadCtx(thread->thread);
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
}
