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
#include "rust.h"

typedef struct SCDnsLogFileCtx_ {
    uint64_t flags; /** Store mode */
    OutputJsonCtx *eve_ctx;
    uint8_t version;
} SCDnsLogFileCtx;

typedef struct SCDnsLogThread_ {
    SCDnsLogFileCtx *dnslog_ctx;
    OutputJsonThreadCtx *ctx;
} SCDnsLogThread;

bool AlertJsonMdns(void *txptr, SCJsonBuilder *js)
{
    return SCMdnsLogJson(txptr, js);
}

static int JsonMdnsLogger(ThreadVars *tv, void *thread_data, const Packet *p, Flow *f,
        void *alstate, void *txptr, uint64_t tx_id)
{
    SCDnsLogThread *td = (SCDnsLogThread *)thread_data;
    SCDnsLogFileCtx *dnslog_ctx = td->dnslog_ctx;

    SCJsonBuilder *jb = CreateEveHeader(p, LOG_DIR_FLOW, "mdns", NULL, dnslog_ctx->eve_ctx);
    if (unlikely(jb == NULL)) {
        return TM_ECODE_OK;
    }

    if (SCMdnsLogJson(txptr, jb)) {
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
    dnslog_ctx->version = DNS_LOG_VERSION_3;

    /* For mDNS, log everything.
     *
     * TODO: Maybe add flags for request and/or response only.
     */
    dnslog_ctx->flags = ~0ULL;

    OutputCtx *output_ctx = SCCalloc(1, sizeof(OutputCtx));
    if (unlikely(output_ctx == NULL)) {
        SCFree(dnslog_ctx);
        return result;
    }

    output_ctx->data = dnslog_ctx;
    output_ctx->DeInit = DnsLogDeInitCtxSub;

    SCAppLayerParserRegisterLogger(IPPROTO_UDP, ALPROTO_MDNS);

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
