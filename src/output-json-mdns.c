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

/* Using SCDnsLogFileCtx and SCDnsLogThread from output-json-dns.h */

bool AlertJsonMdns(void *txptr, SCJsonBuilder *js)
{
    SCDnsLogConfig config = {
        .version = DNS_LOG_VERSION_DEFAULT,
        .flags = DNS_LOG_FORMAT_DETAILED | DNS_LOG_REQUESTS | DNS_LOG_RESPONSES |
                 DNS_LOG_ALL_RRTYPES,
        .log_additionals = true,
        .log_authorities = true,
        .answers_in_request = true,
    };
    /* For alerts, we output everything for better visibility */
    return SCDnsLogJson(txptr, &config, js, "mdns");
}

static int JsonMdnsLogger(ThreadVars *tv, void *thread_data, const Packet *p, Flow *f,
        void *alstate, void *txptr, uint64_t tx_id)
{
    SCDnsLogThread *td = (SCDnsLogThread *)thread_data;
    SCDnsLogFileCtx *dnslog_ctx = td->dnslog_ctx;

    if (SCDnsTxIsRequest(txptr)) {
        /* Request logging disabled. */
        if ((dnslog_ctx->config.flags & DNS_LOG_REQUESTS) == 0) {
            return TM_ECODE_OK;
        }

        /* Don't log requests with no queries. */
        if (!SCDnsTxHasQueries(txptr, false)) {
            return TM_ECODE_OK;
        }
    }

    if (SCDnsTxIsResponse(txptr)) {
        /* Response logging disabled. */
        if ((dnslog_ctx->config.flags & DNS_LOG_RESPONSES) == 0) {
            return TM_ECODE_OK;
        }

        /* Don't log responses with no answers. */
        if (!SCDnsTxHasAnswers(txptr, true)) {
            return TM_ECODE_OK;
        }
    }

    SCJsonBuilder *jb = CreateEveHeader(p, LOG_DIR_FLOW, "mdns", NULL, dnslog_ctx->eve_ctx);
    if (unlikely(jb == NULL)) {
        return TM_ECODE_OK;
    }

    if (SCDnsLogJson(txptr, &dnslog_ctx->config, jb, "mdns")) {
        OutputJsonBuilderBuffer(tv, p, p->flow, jb, td->ctx);
    }
    SCJbFree(jb);

    return TM_ECODE_OK;
}

static TmEcode SCDnsLogThreadInit(ThreadVars *t, const void *initdata, void **data)
{
    SCDnsLogThread *aft = SCCalloc(1, sizeof(SCDnsLogThread));
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

static TmEcode SCDnsLogThreadDeinit(ThreadVars *t, void *data)
{
    SCDnsLogThread *aft = (SCDnsLogThread *)data;
    if (aft == NULL) {
        return TM_ECODE_OK;
    }
    FreeEveThreadCtx(aft->ctx);

    /* clear memory */
    memset(aft, 0, sizeof(SCDnsLogThread));

    SCFree(aft);
    return TM_ECODE_OK;
}

static void DnsLogDeInitCtxSub(OutputCtx *output_ctx)
{
    SCDnsLogFileCtx *dnslog_ctx = (SCDnsLogFileCtx *)output_ctx->data;
    SCFree(dnslog_ctx);
    SCFree(output_ctx);
}

static OutputInitResult DnsLogInitCtxSub(SCConfNode *conf, OutputCtx *parent_ctx)
{
    OutputInitResult result = { NULL, false };
    const char *enabled = SCConfNodeLookupChildValue(conf, "enabled");
    if (enabled != NULL && !SCConfValIsTrue(enabled)) {
        result.ok = true;
        return result;
    }

    OutputJsonCtx *ojc = parent_ctx->data;

    SCDnsLogFileCtx *dnslog_ctx = SCCalloc(1, sizeof(SCDnsLogFileCtx));
    if (unlikely(dnslog_ctx == NULL)) {
        return result;
    }

    dnslog_ctx->eve_ctx = ojc;
    dnslog_ctx->config.version = DNS_LOG_VERSION_3;

    /* For mDNS, log everything, except grouped. */
    dnslog_ctx->config.flags = ~0ULL & ~DNS_LOG_FORMAT_GROUPED;

    const char *requests = SCConfNodeLookupChildValue(conf, "requests");
    if (requests && SCConfValIsFalse(requests)) {
        dnslog_ctx->config.flags &= ~DNS_LOG_REQUESTS;
    }

    const char *responses = SCConfNodeLookupChildValue(conf, "responses");
    if (responses && SCConfValIsFalse(responses)) {
        dnslog_ctx->config.flags &= ~DNS_LOG_RESPONSES;
    }

    const char *grouped = SCConfNodeLookupChildValue(conf, "grouped");
    if (grouped && SCConfValIsTrue(grouped)) {
        dnslog_ctx->config.flags |= DNS_LOG_FORMAT_GROUPED;
    }

    const char *log_additionals = SCConfNodeLookupChildValue(conf, "log-additionals");
    if (log_additionals && SCConfValIsTrue(log_additionals)) {
        dnslog_ctx->config.log_additionals = true;
    }

    const char *log_authorities = SCConfNodeLookupChildValue(conf, "log-authorities");
    if (log_authorities && SCConfValIsTrue(log_authorities)) {
        dnslog_ctx->config.log_authorities = true;
    }

    const char *answers_in_request = SCConfNodeLookupChildValue(conf, "answers-in-request");
    if (answers_in_request && SCConfValIsTrue(answers_in_request)) {
        dnslog_ctx->config.answers_in_request = true;
    }

    OutputCtx *output_ctx = SCCalloc(1, sizeof(OutputCtx));
    if (unlikely(output_ctx == NULL)) {
        SCFree(dnslog_ctx);
        return result;
    }

    output_ctx->data = dnslog_ctx;
    output_ctx->DeInit = DnsLogDeInitCtxSub;

    AppLayerParserRegisterLogger(IPPROTO_UDP, ALPROTO_MDNS);

    result.ctx = output_ctx;
    result.ok = true;
    return result;
}

void JsonMdnsLogRegister(void)
{
    OutputRegisterTxSubModule(LOGGER_JSON_TX, "eve-log", "JsonMdnsLog", "eve-log.mdns",
            DnsLogInitCtxSub, ALPROTO_MDNS, JsonMdnsLogger, SCDnsLogThreadInit,
            SCDnsLogThreadDeinit);
}
