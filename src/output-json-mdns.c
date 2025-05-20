/* Copyright (C) 2025 Open Information Security Foundation
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

#include "suricata-common.h"
#include "conf.h"

#include "threadvars.h"

#include "util-debug.h"
#include "app-layer-parser.h"
#include "output.h"

#include "output-json.h"
#include "output-json-mdns.h"
#include "output-json-dns.h"
#include "rust.h"

typedef struct LogDnsFileCtx_ {
    uint64_t flags; /** Store mode */
    OutputJsonCtx *eve_ctx;
    uint8_t version;
} LogDnsFileCtx;

typedef struct LogDnsLogThread_ {
    LogDnsFileCtx *dnslog_ctx;
    OutputJsonThreadCtx *ctx;
} LogDnsLogThread;

bool AlertJsonMdns(void *txptr, SCJsonBuilder *js)
{
    return SCDnsLogJson(txptr, ~0ULL, js, "mdns");
}

static int JsonMdnsLogger(ThreadVars *tv, void *thread_data, const Packet *p, Flow *f,
        void *alstate, void *txptr, uint64_t tx_id)
{
    LogDnsLogThread *td = (LogDnsLogThread *)thread_data;
    LogDnsFileCtx *dnslog_ctx = td->dnslog_ctx;

    if (SCDnsTxIsRequest(txptr) && (dnslog_ctx->flags & DNS_LOG_QUERIES) == 0) {
        return TM_ECODE_OK;
    }

    if (SCDnsTxIsResponse(txptr) && (dnslog_ctx->flags & DNS_LOG_ANSWERS) == 0) {
        return TM_ECODE_OK;
    }

    SCJsonBuilder *jb = CreateEveHeader(p, LOG_DIR_FLOW, "mdns", NULL, dnslog_ctx->eve_ctx);
    if (unlikely(jb == NULL)) {
        return TM_ECODE_OK;
    }

    if (SCDnsLogJson(txptr, td->dnslog_ctx->flags, jb, "mdns")) {
        OutputJsonBuilderBuffer(tv, p, p->flow, jb, td->ctx);
    }
    SCJbFree(jb);

    return TM_ECODE_OK;
}

static TmEcode LogDnsLogThreadInit(ThreadVars *t, const void *initdata, void **data)
{
    LogDnsLogThread *aft = SCCalloc(1, sizeof(LogDnsLogThread));
    if (unlikely(aft == NULL))
        return TM_ECODE_FAILED;

    if (initdata == NULL) {
        SCLogDebug("Error getting log context for eve-log.mdns.  \"initdata\" argument NULL");
        goto error_exit;
    }

    /* Use the Output Context (file pointer and mutex) */
    aft->dnslog_ctx = ((OutputCtx *)initdata)->data;
    aft->ctx = CreateEveThreadCtx(t, aft->dnslog_ctx->eve_ctx);
    if (!aft->ctx) {
        goto error_exit;
    }

    *data = (void *)aft;
    return TM_ECODE_OK;

error_exit:
    SCFree(aft);
    return TM_ECODE_FAILED;
}

static TmEcode LogDnsLogThreadDeinit(ThreadVars *t, void *data)
{
    LogDnsLogThread *aft = (LogDnsLogThread *)data;
    if (aft == NULL) {
        return TM_ECODE_OK;
    }
    FreeEveThreadCtx(aft->ctx);

    /* clear memory */
    memset(aft, 0, sizeof(LogDnsLogThread));

    SCFree(aft);
    return TM_ECODE_OK;
}

static void LogDnsLogDeInitCtxSub(OutputCtx *output_ctx)
{
    LogDnsFileCtx *dnslog_ctx = (LogDnsFileCtx *)output_ctx->data;
    SCFree(dnslog_ctx);
    SCFree(output_ctx);
}

static OutputInitResult JsonDnsLogInitCtxSub(SCConfNode *conf, OutputCtx *parent_ctx)
{
    OutputInitResult result = { NULL, false };
    const char *enabled = SCConfNodeLookupChildValue(conf, "enabled");
    if (enabled != NULL && !SCConfValIsTrue(enabled)) {
        result.ok = true;
        return result;
    }

    OutputJsonCtx *ojc = parent_ctx->data;

    LogDnsFileCtx *dnslog_ctx = SCCalloc(1, sizeof(LogDnsFileCtx));
    if (unlikely(dnslog_ctx == NULL)) {
        return result;
    }

    dnslog_ctx->eve_ctx = ojc;
    dnslog_ctx->version = DNS_LOG_VERSION_3;

    /* For mDNS, log everything, except grouped. */
    dnslog_ctx->flags = ~0ULL & ~DNS_LOG_FORMAT_GROUPED;

    const char *requests = SCConfNodeLookupChildValue(conf, "requests");
    if (requests && SCConfValIsFalse(requests)) {
        dnslog_ctx->flags &= ~DNS_LOG_QUERIES;
    }

    const char *responses = SCConfNodeLookupChildValue(conf, "responses");
    if (responses && SCConfValIsFalse(responses)) {
        dnslog_ctx->flags &= ~DNS_LOG_ANSWERS;
    }

    const char *grouped = SCConfNodeLookupChildValue(conf, "grouped");
    if (grouped && SCConfValIsTrue(grouped)) {
        dnslog_ctx->flags |= DNS_LOG_FORMAT_GROUPED;
    }

    OutputCtx *output_ctx = SCCalloc(1, sizeof(OutputCtx));
    if (unlikely(output_ctx == NULL)) {
        SCFree(dnslog_ctx);
        return result;
    }

    output_ctx->data = dnslog_ctx;
    output_ctx->DeInit = LogDnsLogDeInitCtxSub;

    AppLayerParserRegisterLogger(IPPROTO_UDP, ALPROTO_MDNS);

    result.ctx = output_ctx;
    result.ok = true;
    return result;
}

void JsonMdnsLogRegister(void)
{
    OutputRegisterTxSubModule(LOGGER_JSON_TX, "eve-log", "JsonMdnsLog", "eve-log.mdns",
            JsonDnsLogInitCtxSub, ALPROTO_MDNS, JsonMdnsLogger, LogDnsLogThreadInit,
            LogDnsLogThreadDeinit);
}
