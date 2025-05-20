/* Copyright (C) 2007-2022 Open Information Security Foundation
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
 * \author Tom DeCanio <td@npulsetech.com>
 *
 * Implements JSON DNS logging portion of the engine.
 */

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
#include "rust.h"

typedef enum {
    DNS_RRTYPE_A = 0,
    DNS_RRTYPE_NS,
    DNS_RRTYPE_MD,
    DNS_RRTYPE_MF,
    DNS_RRTYPE_CNAME,
    DNS_RRTYPE_SOA,
    DNS_RRTYPE_MB,
    DNS_RRTYPE_MG,
    DNS_RRTYPE_MR,
    DNS_RRTYPE_NULL,
    DNS_RRTYPE_WKS,
    DNS_RRTYPE_PTR,
    DNS_RRTYPE_HINFO,
    DNS_RRTYPE_MINFO,
    DNS_RRTYPE_MX,
    DNS_RRTYPE_TXT,
    DNS_RRTYPE_RP,
    DNS_RRTYPE_AFSDB,
    DNS_RRTYPE_X25,
    DNS_RRTYPE_ISDN,
    DNS_RRTYPE_RT,
    DNS_RRTYPE_NSAP,
    DNS_RRTYPE_NSAPPTR,
    DNS_RRTYPE_SIG,
    DNS_RRTYPE_KEY,
    DNS_RRTYPE_PX,
    DNS_RRTYPE_GPOS,
    DNS_RRTYPE_AAAA,
    DNS_RRTYPE_LOC,
    DNS_RRTYPE_NXT,
    DNS_RRTYPE_SRV,
    DNS_RRTYPE_ATMA,
    DNS_RRTYPE_NAPTR,
    DNS_RRTYPE_KX,
    DNS_RRTYPE_CERT,
    DNS_RRTYPE_A6,
    DNS_RRTYPE_DNAME,
    DNS_RRTYPE_OPT,
    DNS_RRTYPE_APL,
    DNS_RRTYPE_DS,
    DNS_RRTYPE_SSHFP,
    DNS_RRTYPE_IPSECKEY,
    DNS_RRTYPE_RRSIG,
    DNS_RRTYPE_NSEC,
    DNS_RRTYPE_DNSKEY,
    DNS_RRTYPE_DHCID,
    DNS_RRTYPE_NSEC3,
    DNS_RRTYPE_NSEC3PARAM,
    DNS_RRTYPE_TLSA,
    DNS_RRTYPE_HIP,
    DNS_RRTYPE_CDS,
    DNS_RRTYPE_CDNSKEY,
    DNS_RRTYPE_HTTPS,
    DNS_RRTYPE_SPF,
    DNS_RRTYPE_TKEY,
    DNS_RRTYPE_TSIG,
    DNS_RRTYPE_MAILA,
    DNS_RRTYPE_ANY,
    DNS_RRTYPE_URI,
    DNS_RRTYPE_MAX,
} DnsRRTypes;

static struct {
    const char *config_rrtype;
    uint64_t flags;
} dns_rrtype_fields[] = {
    // clang-format off
   { "a", DNS_LOG_A },
   { "ns", DNS_LOG_NS },
   { "md", DNS_LOG_MD },
   { "mf", DNS_LOG_MF },
   { "cname", DNS_LOG_CNAME },
   { "soa", DNS_LOG_SOA },
   { "mb", DNS_LOG_MB },
   { "mg", DNS_LOG_MG },
   { "mr", DNS_LOG_MR },
   { "null", DNS_LOG_NULL },
   { "wks", DNS_LOG_WKS },
   { "ptr", DNS_LOG_PTR },
   { "hinfo", DNS_LOG_HINFO },
   { "minfo", DNS_LOG_MINFO },
   { "mx", DNS_LOG_MX },
   { "txt", DNS_LOG_TXT },
   { "rp", DNS_LOG_RP },
   { "afsdb", DNS_LOG_AFSDB },
   { "x25", DNS_LOG_X25 },
   { "isdn", DNS_LOG_ISDN },
   { "rt", DNS_LOG_RT },
   { "nsap", DNS_LOG_NSAP },
   { "nsapptr", DNS_LOG_NSAPPTR },
   { "sig", DNS_LOG_SIG },
   { "key", DNS_LOG_KEY },
   { "px", DNS_LOG_PX },
   { "gpos", DNS_LOG_GPOS },
   { "aaaa", DNS_LOG_AAAA },
   { "loc", DNS_LOG_LOC },
   { "nxt", DNS_LOG_NXT },
   { "srv", DNS_LOG_SRV },
   { "atma", DNS_LOG_ATMA },
   { "naptr", DNS_LOG_NAPTR },
   { "kx", DNS_LOG_KX },
   { "cert", DNS_LOG_CERT },
   { "a6", DNS_LOG_A6 },
   { "dname", DNS_LOG_DNAME },
   { "opt", DNS_LOG_OPT },
   { "apl", DNS_LOG_APL },
   { "ds", DNS_LOG_DS },
   { "sshfp", DNS_LOG_SSHFP },
   { "ipseckey", DNS_LOG_IPSECKEY },
   { "rrsig", DNS_LOG_RRSIG },
   { "nsec", DNS_LOG_NSEC },
   { "dnskey", DNS_LOG_DNSKEY },
   { "dhcid", DNS_LOG_DHCID },
   { "nsec3", DNS_LOG_NSEC3 },
   { "nsec3param", DNS_LOG_NSEC3PARAM },
   { "tlsa", DNS_LOG_TLSA },
   { "hip", DNS_LOG_HIP },
   { "cds", DNS_LOG_CDS },
   { "cdnskey", DNS_LOG_CDNSKEY },
   { "https", DNS_LOG_HTTPS },
   { "spf", DNS_LOG_SPF },
   { "tkey", DNS_LOG_TKEY },
   { "tsig", DNS_LOG_TSIG },
   { "maila", DNS_LOG_MAILA },
   { "any", DNS_LOG_ANY },
   { "uri", DNS_LOG_URI }
    // clang-format on
};

bool AlertJsonDns(void *txptr, SCJsonBuilder *js)
{
    SCDnsLogConfig config = {
        .version = DNS_LOG_VERSION_DEFAULT,
        .flags = DNS_LOG_FORMAT_DETAILED | DNS_LOG_REQUESTS | DNS_LOG_RESPONSES | DNS_LOG_ALL_RRTYPES,
        .log_additionals = true,
        .log_authorities = true,
        .answers_in_request = true,
    };
    /* For alerts, we want to see everything */
    return SCDnsLogJson(txptr, &config, js, "dns");
}

bool AlertJsonDoh2(void *txptr, SCJsonBuilder *js)
{
    SCJsonBuilderMark mark = { 0, 0, 0 };

    SCJbGetMark(js, &mark);
    // first log HTTP2 part
    bool r = SCHttp2LogJson(txptr, js);
    if (!r) {
        SCJbRestoreMark(js, &mark);
    }
    // then log one DNS tx if any, preferring the answer
    void *tx_dns = DetectGetInnerTx(txptr, ALPROTO_DOH2, ALPROTO_DNS, STREAM_TOCLIENT);
    if (tx_dns == NULL) {
        tx_dns = DetectGetInnerTx(txptr, ALPROTO_DOH2, ALPROTO_DNS, STREAM_TOSERVER);
    }
    bool r2 = false;
    if (tx_dns) {
        SCJbGetMark(js, &mark);
        r2 = AlertJsonDns(tx_dns, js);
        if (!r2) {
            SCJbRestoreMark(js, &mark);
        }
    }
    return r || r2;
}

static int JsonDoh2Logger(ThreadVars *tv, void *thread_data, const Packet *p, Flow *f,
        void *alstate, void *txptr, uint64_t tx_id)
{
    SCDnsLogThread *td = (SCDnsLogThread *)thread_data;
    SCDnsLogFileCtx *dnslog_ctx = td->dnslog_ctx;

    SCJsonBuilder *jb = CreateEveHeader(p, LOG_DIR_FLOW, "dns", NULL, dnslog_ctx->eve_ctx);

    if (unlikely(jb == NULL)) {
        return TM_ECODE_OK;
    }

    SCJsonBuilderMark mark = { 0, 0, 0 };

    SCJbGetMark(jb, &mark);
    // first log HTTP2 part
    bool r = SCHttp2LogJson(txptr, jb);
    if (!r) {
        SCJbRestoreMark(jb, &mark);
    }

    void *tx_dns = DetectGetInnerTx(txptr, ALPROTO_DOH2, ALPROTO_DNS, STREAM_TOCLIENT);
    if (tx_dns == NULL) {
        tx_dns = DetectGetInnerTx(txptr, ALPROTO_DOH2, ALPROTO_DNS, STREAM_TOSERVER);
    }
    bool r2 = false;
    if (tx_dns) {
        // mix of JsonDnsLogger
        if (SCDnsTxIsRequest(tx_dns)) {
            if (unlikely(dnslog_ctx->config.flags & DNS_LOG_REQUESTS) == 0) {
                goto out;
            }
        } else if (SCDnsTxIsResponse(tx_dns)) {
            if (unlikely(dnslog_ctx->config.flags & DNS_LOG_RESPONSES) == 0) {
                goto out;
            }
        }

        if (!SCDnsLogEnabled(tx_dns, td->dnslog_ctx->config.flags)) {
            goto out;
        }

        SCJbGetMark(jb, &mark);
        // log DOH2 with DNS config
        r2 = SCDnsLogJson(tx_dns, &dnslog_ctx->config, jb, "dns");
        if (!r2) {
            SCJbRestoreMark(jb, &mark);
        }
    }
out:
    if (r || r2) {
        OutputJsonBuilderBuffer(tv, p, p->flow, jb, td->ctx);
    }
    SCJbFree(jb);
    return TM_ECODE_OK;
}

static int JsonDnsLoggerToServer(ThreadVars *tv, void *thread_data,
    const Packet *p, Flow *f, void *alstate, void *txptr, uint64_t tx_id)
{
    SCEnter();

    SCDnsLogThread *td = (SCDnsLogThread *)thread_data;
    SCDnsLogFileCtx *dnslog_ctx = td->dnslog_ctx;

    if (unlikely(dnslog_ctx->config.flags & DNS_LOG_REQUESTS) == 0) {
        return TM_ECODE_OK;
    }

    for (uint16_t i = 0; i < 0xffff; i++) {
        SCJsonBuilder *jb = CreateEveHeader(p, LOG_DIR_FLOW, "dns", NULL, dnslog_ctx->eve_ctx);
        if (unlikely(jb == NULL)) {
            return TM_ECODE_OK;
        }

        SCJbOpenObject(jb, "dns");
        SCJbSetInt(jb, "version", 2);
        if (!SCDnsLogJsonQuery(txptr, i, td->dnslog_ctx->config.flags, jb)) {
            SCJbFree(jb);
            break;
        }
        SCJbClose(jb);

        OutputJsonBuilderBuffer(tv, p, p->flow, jb, td->ctx);
        SCJbFree(jb);
    }

    SCReturnInt(TM_ECODE_OK);
}

static int JsonDnsLoggerToClient(ThreadVars *tv, void *thread_data,
    const Packet *p, Flow *f, void *alstate, void *txptr, uint64_t tx_id)
{
    SCEnter();

    SCDnsLogThread *td = (SCDnsLogThread *)thread_data;
    SCDnsLogFileCtx *dnslog_ctx = td->dnslog_ctx;

    if (unlikely(dnslog_ctx->config.flags & DNS_LOG_RESPONSES) == 0) {
        return TM_ECODE_OK;
    }

    if (SCDnsLogAnswerEnabled(txptr, td->dnslog_ctx->config.flags)) {
        SCJsonBuilder *jb = CreateEveHeader(p, LOG_DIR_FLOW, "dns", NULL, dnslog_ctx->eve_ctx);
        if (unlikely(jb == NULL)) {
            return TM_ECODE_OK;
        }

        SCJbOpenObject(jb, "dns");
        SCJbSetInt(jb, "version", 2);
        SCDnsLogJsonAnswer(txptr, td->dnslog_ctx->config.flags, jb);
        SCJbClose(jb);
        OutputJsonBuilderBuffer(tv, p, p->flow, jb, td->ctx);
        SCJbFree(jb);
    }

    SCReturnInt(TM_ECODE_OK);
}

static int JsonDnsLogger(ThreadVars *tv, void *thread_data, const Packet *p, Flow *f, void *alstate,
        void *txptr, uint64_t tx_id)
{
    SCDnsLogThread *td = (SCDnsLogThread *)thread_data;
    SCDnsLogFileCtx *dnslog_ctx = td->dnslog_ctx;

    if (dnslog_ctx->config.version == DNS_LOG_VERSION_2) {
        if (SCDnsTxIsRequest(txptr)) {
            return JsonDnsLoggerToServer(tv, thread_data, p, f, alstate, txptr, tx_id);
        } else if (SCDnsTxIsResponse(txptr)) {
            return JsonDnsLoggerToClient(tv, thread_data, p, f, alstate, txptr, tx_id);
        }
    } else {
        if (SCDnsTxIsRequest(txptr)) {
            if (unlikely(dnslog_ctx->config.flags & DNS_LOG_REQUESTS) == 0) {
                return TM_ECODE_OK;
            }
        } else if (SCDnsTxIsResponse(txptr)) {
            if (unlikely(dnslog_ctx->config.flags & DNS_LOG_RESPONSES) == 0) {
                return TM_ECODE_OK;
            }
        }

        if (!SCDnsLogEnabled(txptr, td->dnslog_ctx->config.flags)) {
            return TM_ECODE_OK;
        }

        SCJsonBuilder *jb = CreateEveHeader(p, LOG_DIR_FLOW, "dns", NULL, dnslog_ctx->eve_ctx);
        if (unlikely(jb == NULL)) {
            return TM_ECODE_OK;
        }

        if (SCDnsLogJson(txptr, &td->dnslog_ctx->config, jb, "dns")) {
            OutputJsonBuilderBuffer(tv, p, p->flow, jb, td->ctx);
        }
        SCJbFree(jb);
    }
    return TM_ECODE_OK;
}

static TmEcode SCDnsLogThreadInit(ThreadVars *t, const void *initdata, void **data)
{
    SCDnsLogThread *aft = SCCalloc(1, sizeof(SCDnsLogThread));
    if (unlikely(aft == NULL))
        return TM_ECODE_FAILED;

    if(initdata == NULL)
    {
        SCLogDebug("Error getting context for EveLogDNS.  \"initdata\" argument NULL");
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
    SCLogDebug("cleaning up sub output_ctx %p", output_ctx);
    SCDnsLogFileCtx *dnslog_ctx = (SCDnsLogFileCtx *)output_ctx->data;
    SCFree(dnslog_ctx);
    SCFree(output_ctx);
}

static void JsonDnsLogParseConfig(SCDnsLogFileCtx *dnslog_ctx, SCConfNode *conf,
        const char *query_key, const char *answer_key, const char *answer_types_key)
{
    const char *query = SCConfNodeLookupChildValue(conf, query_key);
    if (query != NULL) {
        if (SCConfValIsTrue(query)) {
            dnslog_ctx->config.flags |= DNS_LOG_REQUESTS;
        } else {
            dnslog_ctx->config.flags &= ~DNS_LOG_REQUESTS;
        }
    } else {
        dnslog_ctx->config.flags |= DNS_LOG_REQUESTS;
    }

    const char *response = SCConfNodeLookupChildValue(conf, answer_key);
    if (response != NULL) {
        if (SCConfValIsTrue(response)) {
            dnslog_ctx->config.flags |= DNS_LOG_RESPONSES;
        } else {
            dnslog_ctx->config.flags &= ~DNS_LOG_RESPONSES;
        }
    } else {
        dnslog_ctx->config.flags |= DNS_LOG_RESPONSES;
    }

    SCConfNode *custom;
    if ((custom = SCConfNodeLookupChild(conf, answer_types_key)) != NULL) {
        dnslog_ctx->config.flags &= ~DNS_LOG_ALL_RRTYPES;
        SCConfNode *field;
        TAILQ_FOREACH (field, &custom->head, next) {
            DnsRRTypes f;
            for (f = DNS_RRTYPE_A; f < DNS_RRTYPE_MAX; f++) {
                if (strcasecmp(dns_rrtype_fields[f].config_rrtype, field->val) == 0) {
                    dnslog_ctx->config.flags |= dns_rrtype_fields[f].flags;
                    break;
                }
            }
        }
    } else {
        dnslog_ctx->config.flags |= DNS_LOG_ALL_RRTYPES;
    }
}

static uint8_t GetDnsLogVersion(SCConfNode *conf)
{
    if (conf == NULL) {
        return DNS_LOG_VERSION_DEFAULT;
    }

    char *version_string = NULL;
    const SCConfNode *version_node = SCConfNodeLookupChild(conf, "version");
    if (version_node != NULL) {
        version_string = version_node->val;
    }

    if (version_string == NULL) {
        version_string = getenv("SURICATA_EVE_DNS_VERSION");
    }

    if (version_string == NULL) {
        return DNS_LOG_VERSION_DEFAULT;
    }

    uint8_t version;
    if (StringParseUint8(&version, 10, 0, version_string) >= 0) {
        return version;
    }
    SCLogWarning("Failed to parse EVE DNS log version of \"%s\"", version_string);
    return DNS_LOG_VERSION_DEFAULT;
}

static uint8_t JsonDnsCheckVersion(SCConfNode *conf)
{
    const uint8_t default_version = DNS_LOG_VERSION_DEFAULT;
    const uint8_t version = GetDnsLogVersion(conf);
    static bool v1_deprecation_warned = false;
    static bool v2_deprecation_warned = false;

    switch (version) {
        case 3:
            return DNS_LOG_VERSION_3;
        case 2:
            if (!v2_deprecation_warned) {
                SCLogNotice("DNS EVE v2 logging has been deprecated and will be removed in "
                            "Suricata 9.0");
                v2_deprecation_warned = true;
            }
            return DNS_LOG_VERSION_2;
        case 1:
            if (!v1_deprecation_warned) {
                SCLogWarning("DNS EVE v1 logging has been removed, will use v2");
                v1_deprecation_warned = true;
            }
            return default_version;
        default:
            SCLogWarning(
                    "Invalid EVE DNS version %d, will use v%d", version, DNS_LOG_VERSION_DEFAULT);
            return default_version;
    }

    return default_version;
}

static void JsonDnsLogInitFilters(SCDnsLogFileCtx *dnslog_ctx, SCConfNode *conf)
{
    dnslog_ctx->config.flags = ~0ULL;

    /* Always true for DNS. */
    dnslog_ctx->config.answers_in_request = true;
    dnslog_ctx->config.log_additionals = true;
    dnslog_ctx->config.log_authorities = true;

    if (conf) {
        JsonDnsLogParseConfig(dnslog_ctx, conf, "requests", "responses", "types");
        if (dnslog_ctx->config.flags & DNS_LOG_RESPONSES) {
            SCConfNode *format;
            if ((format = SCConfNodeLookupChild(conf, "formats")) != NULL) {
                uint64_t flags = 0;
                SCConfNode *field;
                TAILQ_FOREACH (field, &format->head, next) {
                    if (strcasecmp(field->val, "detailed") == 0) {
                        flags |= DNS_LOG_FORMAT_DETAILED;
                    } else if (strcasecmp(field->val, "grouped") == 0) {
                        flags |= DNS_LOG_FORMAT_GROUPED;
                    } else {
                        SCLogWarning("Invalid JSON DNS log format: %s", field->val);
                    }
                }
                if (flags) {
                    dnslog_ctx->config.flags &= ~DNS_LOG_FORMAT_ALL;
                    dnslog_ctx->config.flags |= flags;
                } else {
                    SCLogWarning("Empty EVE DNS format array, using defaults");
                }
            } else {
                dnslog_ctx->config.flags |= DNS_LOG_FORMAT_ALL;
            }
        }
    }
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
    dnslog_ctx->config.version = JsonDnsCheckVersion(conf);

    OutputCtx *output_ctx = SCCalloc(1, sizeof(OutputCtx));
    if (unlikely(output_ctx == NULL)) {
        SCFree(dnslog_ctx);
        return result;
    }

    output_ctx->data = dnslog_ctx;
    output_ctx->DeInit = DnsLogDeInitCtxSub;

    JsonDnsLogInitFilters(dnslog_ctx, conf);

    SCLogDebug("DNS log sub-module initialized");

    AppLayerParserRegisterLogger(IPPROTO_UDP, ALPROTO_DNS);
    AppLayerParserRegisterLogger(IPPROTO_TCP, ALPROTO_DNS);

    result.ctx = output_ctx;
    result.ok = true;
    return result;
}


#define MODULE_NAME "JsonDnsLog"
void JsonDnsLogRegister (void)
{
    OutputRegisterTxSubModule(LOGGER_JSON_TX, "eve-log", MODULE_NAME, "eve-log.dns",
            DnsLogInitCtxSub, ALPROTO_DNS, JsonDnsLogger, SCDnsLogThreadInit, SCDnsLogThreadDeinit);
}

void JsonDoh2LogRegister(void)
{
    OutputRegisterTxSubModule(LOGGER_JSON_TX, "eve-log", "JsonDoH2Log", "eve-log.doh2",
            DnsLogInitCtxSub, ALPROTO_DOH2, JsonDoh2Logger, SCDnsLogThreadInit,
            SCDnsLogThreadDeinit);
}
