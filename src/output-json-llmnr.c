/* Copyright (C) 2026 Open Information Security Foundation
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

// written by Giuseppe Longo <giuseppe@glongo.it>

#include "suricata-common.h"
#include "conf.h"

#include "threadvars.h"

#include "util-byte.h"
#include "util-debug.h"
#include "util-mem.h"
#include "app-layer-parser.h"
#include "output.h"

#include "output-json.h"
#include "output-json-dns.h"
#include "output-json-llmnr.h"
#include "rust.h"

typedef struct LogLLMNRFileCtx_ {
    uint64_t flags; /** Store mode */
    OutputJsonCtx *eve_ctx;
} LogLLMNRFileCtx;

typedef struct LogLLMNRLogThread_ {
    LogLLMNRFileCtx *llmnrlog_ctx;
    OutputJsonThreadCtx *ctx;
} LogLLMNRLogThread;

bool AlertJsonLLMNR(void *txptr, SCJsonBuilder *js)
{
    return SCLLMNRLogJson(
            txptr, LOG_FORMAT_DETAILED | LOG_QUERIES | LOG_ANSWERS | LOG_ALL_RRTYPES, js);
}

static int JsonLLMNRLogger(ThreadVars *tv, void *thread_data, const Packet *p, Flow *f,
        void *alstate, void *txptr, uint64_t tx_id)
{
    LogLLMNRLogThread *td = (LogLLMNRLogThread *)thread_data;
    LogLLMNRFileCtx *llmnrlog_ctx = td->llmnrlog_ctx;

    if (SCLLMNRTxIsRequest(txptr)) {
        if (unlikely(llmnrlog_ctx->flags & LOG_QUERIES) == 0) {
            return TM_ECODE_OK;
        }
    } else if (SCLLMNRTxIsResponse(txptr)) {
        if (unlikely(llmnrlog_ctx->flags & LOG_ANSWERS) == 0) {
            return TM_ECODE_OK;
        }
    }

    if (!SCLLMNRLogEnabled(txptr, td->llmnrlog_ctx->flags)) {
        return TM_ECODE_OK;
    }

    SCJsonBuilder *jb = CreateEveHeader(p, LOG_DIR_FLOW, "llmnr", NULL, llmnrlog_ctx->eve_ctx);
    if (unlikely(jb == NULL)) {
        return TM_ECODE_OK;
    }

    if (SCLLMNRLogJson(txptr, td->llmnrlog_ctx->flags, jb)) {
        OutputJsonBuilderBuffer(tv, p, p->flow, jb, td->ctx);
    }
    SCJbFree(jb);

    return TM_ECODE_OK;
}

static TmEcode LogLLMNRLogThreadInit(ThreadVars *t, const void *initdata, void **data)
{
    LogLLMNRLogThread *aft = SCCalloc(1, sizeof(LogLLMNRLogThread));
    if (unlikely(aft == NULL))
        return TM_ECODE_FAILED;

    if (initdata == NULL) {
        SCLogDebug("Error getting context for EveLogLLMNR.  \"initdata\" argument NULL");
        goto error_exit;
    }

    /* Use the Output Context (file pointer and mutex) */
    aft->llmnrlog_ctx = ((OutputCtx *)initdata)->data;
    aft->ctx = CreateEveThreadCtx(t, aft->llmnrlog_ctx->eve_ctx);
    if (!aft->ctx) {
        goto error_exit;
    }

    *data = (void *)aft;
    return TM_ECODE_OK;

error_exit:
    SCFree(aft);
    return TM_ECODE_FAILED;
}

static TmEcode LogLLMNRLogThreadDeinit(ThreadVars *t, void *data)
{
    LogLLMNRLogThread *aft = (LogLLMNRLogThread *)data;
    if (aft == NULL) {
        return TM_ECODE_OK;
    }
    FreeEveThreadCtx(aft->ctx);

    /* clear memory */
    memset(aft, 0, sizeof(LogLLMNRLogThread));

    SCFree(aft);
    return TM_ECODE_OK;
}

static void LogLLMNRLogDeInitCtxSub(OutputCtx *output_ctx)
{
    SCLogDebug("cleaning up sub output_ctx %p", output_ctx);
    LogLLMNRFileCtx *llmnrlog_ctx = (LogLLMNRFileCtx *)output_ctx->data;
    SCFree(llmnrlog_ctx);
    SCFree(output_ctx);
}

static OutputInitResult JsonLLMNRLogInitCtxSub(SCConfNode *conf, OutputCtx *parent_ctx)
{
    OutputInitResult result = { NULL, false };
    const char *enabled = SCConfNodeLookupChildValue(conf, "enabled");
    if (enabled != NULL && !SCConfValIsTrue(enabled)) {
        result.ok = true;
        return result;
    }

    OutputJsonCtx *ojc = parent_ctx->data;

    LogLLMNRFileCtx *llmnrlog_ctx = SCCalloc(1, sizeof(LogLLMNRFileCtx));
    if (unlikely(llmnrlog_ctx == NULL)) {
        return result;
    }

    llmnrlog_ctx->eve_ctx = ojc;
    llmnrlog_ctx->flags = ~0ULL;

    OutputCtx *output_ctx = SCCalloc(1, sizeof(OutputCtx));
    if (unlikely(output_ctx == NULL)) {
        SCFree(llmnrlog_ctx);
        return result;
    }

    output_ctx->data = llmnrlog_ctx;
    output_ctx->DeInit = LogLLMNRLogDeInitCtxSub;

    SCLogDebug("LLMNR log sub-module initialized");

    SCAppLayerParserRegisterLogger(IPPROTO_UDP, ALPROTO_LLMNR);
    SCAppLayerParserRegisterLogger(IPPROTO_TCP, ALPROTO_LLMNR);

    result.ctx = output_ctx;
    result.ok = true;
    return result;
}

void JsonLLMNRLogRegister(void)
{
    OutputRegisterTxSubModule(LOGGER_JSON_TX, "eve-log", "JsonLLMNRLog", "eve-log.llmnr",
            JsonLLMNRLogInitCtxSub, ALPROTO_LLMNR, JsonLLMNRLogger, LogLLMNRLogThreadInit,
            LogLLMNRLogThreadDeinit);
}