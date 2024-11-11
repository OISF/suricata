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

#define LOG_QUERIES    BIT_U64(0)
#define LOG_ANSWERS    BIT_U64(1)

#define LOG_A          BIT_U64(2)
#define LOG_NS         BIT_U64(3)
#define LOG_MD         BIT_U64(4)
#define LOG_MF         BIT_U64(5)
#define LOG_CNAME      BIT_U64(6)
#define LOG_SOA        BIT_U64(7)
#define LOG_MB         BIT_U64(8)
#define LOG_MG         BIT_U64(9)
#define LOG_MR         BIT_U64(10)
#define LOG_NULL       BIT_U64(11)
#define LOG_WKS        BIT_U64(12)
#define LOG_PTR        BIT_U64(13)
#define LOG_HINFO      BIT_U64(14)
#define LOG_MINFO      BIT_U64(15)
#define LOG_MX         BIT_U64(16)
#define LOG_TXT        BIT_U64(17)
#define LOG_RP         BIT_U64(18)
#define LOG_AFSDB      BIT_U64(19)
#define LOG_X25        BIT_U64(20)
#define LOG_ISDN       BIT_U64(21)
#define LOG_RT         BIT_U64(22)
#define LOG_NSAP       BIT_U64(23)
#define LOG_NSAPPTR    BIT_U64(24)
#define LOG_SIG        BIT_U64(25)
#define LOG_KEY        BIT_U64(26)
#define LOG_PX         BIT_U64(27)
#define LOG_GPOS       BIT_U64(28)
#define LOG_AAAA       BIT_U64(29)
#define LOG_LOC        BIT_U64(30)
#define LOG_NXT        BIT_U64(31)
#define LOG_SRV        BIT_U64(32)
#define LOG_ATMA       BIT_U64(33)
#define LOG_NAPTR      BIT_U64(34)
#define LOG_KX         BIT_U64(35)
#define LOG_CERT       BIT_U64(36)
#define LOG_A6         BIT_U64(37)
#define LOG_DNAME      BIT_U64(38)
#define LOG_OPT        BIT_U64(39)
#define LOG_APL        BIT_U64(40)
#define LOG_DS         BIT_U64(41)
#define LOG_SSHFP      BIT_U64(42)
#define LOG_IPSECKEY   BIT_U64(43)
#define LOG_RRSIG      BIT_U64(44)
#define LOG_NSEC       BIT_U64(45)
#define LOG_DNSKEY     BIT_U64(46)
#define LOG_DHCID      BIT_U64(47)
#define LOG_NSEC3      BIT_U64(48)
#define LOG_NSEC3PARAM BIT_U64(49)
#define LOG_TLSA       BIT_U64(50)
#define LOG_HIP        BIT_U64(51)
#define LOG_CDS        BIT_U64(52)
#define LOG_CDNSKEY    BIT_U64(53)
#define LOG_SPF        BIT_U64(54)
#define LOG_TKEY       BIT_U64(55)
#define LOG_TSIG       BIT_U64(56)
#define LOG_MAILA      BIT_U64(57)
#define LOG_ANY        BIT_U64(58)
#define LOG_URI        BIT_U64(59)

#define LOG_FORMAT_GROUPED     BIT_U64(60)
#define LOG_FORMAT_DETAILED    BIT_U64(61)
#define LOG_HTTPS              BIT_U64(62)

#define LOG_FORMAT_ALL (LOG_FORMAT_GROUPED|LOG_FORMAT_DETAILED)
#define LOG_ALL_RRTYPES (~(uint64_t)(LOG_QUERIES|LOG_ANSWERS|LOG_FORMAT_DETAILED|LOG_FORMAT_GROUPED))

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
   { "a", LOG_A },
   { "ns", LOG_NS },
   { "md", LOG_MD },
   { "mf", LOG_MF },
   { "cname", LOG_CNAME },
   { "soa", LOG_SOA },
   { "mb", LOG_MB },
   { "mg", LOG_MG },
   { "mr", LOG_MR },
   { "null", LOG_NULL },
   { "wks", LOG_WKS },
   { "ptr", LOG_PTR },
   { "hinfo", LOG_HINFO },
   { "minfo", LOG_MINFO },
   { "mx", LOG_MX },
   { "txt", LOG_TXT },
   { "rp", LOG_RP },
   { "afsdb", LOG_AFSDB },
   { "x25", LOG_X25 },
   { "isdn", LOG_ISDN },
   { "rt", LOG_RT },
   { "nsap", LOG_NSAP },
   { "nsapptr", LOG_NSAPPTR },
   { "sig", LOG_SIG },
   { "key", LOG_KEY },
   { "px", LOG_PX },
   { "gpos", LOG_GPOS },
   { "aaaa", LOG_AAAA },
   { "loc", LOG_LOC },
   { "nxt", LOG_NXT },
   { "srv", LOG_SRV },
   { "atma", LOG_ATMA },
   { "naptr", LOG_NAPTR },
   { "kx", LOG_KX },
   { "cert", LOG_CERT },
   { "a6", LOG_A6 },
   { "dname", LOG_DNAME },
   { "opt", LOG_OPT },
   { "apl", LOG_APL },
   { "ds", LOG_DS },
   { "sshfp", LOG_SSHFP },
   { "ipseckey", LOG_IPSECKEY },
   { "rrsig", LOG_RRSIG },
   { "nsec", LOG_NSEC },
   { "dnskey", LOG_DNSKEY },
   { "dhcid", LOG_DHCID },
   { "nsec3", LOG_NSEC3 },
   { "nsec3param", LOG_NSEC3PARAM },
   { "tlsa", LOG_TLSA },
   { "hip", LOG_HIP },
   { "cds", LOG_CDS },
   { "cdnskey", LOG_CDNSKEY },
   { "https", LOG_HTTPS },
   { "spf", LOG_SPF },
   { "tkey", LOG_TKEY },
   { "tsig", LOG_TSIG },
   { "maila", LOG_MAILA },
   { "any", LOG_ANY },
   { "uri", LOG_URI }
    // clang-format on
};

typedef struct LogDnsFileCtx_ {
    uint64_t flags; /** Store mode */
    OutputJsonCtx *eve_ctx;
    uint8_t version;
} LogDnsFileCtx;

typedef struct LogDnsLogThread_ {
    LogDnsFileCtx *dnslog_ctx;
    OutputJsonThreadCtx *ctx;
} LogDnsLogThread;

bool AlertJsonDns(void *txptr, JsonBuilder *js)
{
    return SCDnsLogJson(
            txptr, LOG_FORMAT_DETAILED | LOG_QUERIES | LOG_ANSWERS | LOG_ALL_RRTYPES, js);
}

bool AlertJsonDoh2(void *txptr, JsonBuilder *js)
{
    JsonBuilderMark mark = { 0, 0, 0 };

    jb_get_mark(js, &mark);
    // first log HTTP2 part
    bool r = rs_http2_log_json(txptr, js);
    if (!r) {
        jb_restore_mark(js, &mark);
    }
    // then log one DNS tx if any, preferring the answer
    void *tx_dns = DetectGetInnerTx(txptr, ALPROTO_DOH2, ALPROTO_DNS, STREAM_TOCLIENT);
    if (tx_dns == NULL) {
        tx_dns = DetectGetInnerTx(txptr, ALPROTO_DOH2, ALPROTO_DNS, STREAM_TOSERVER);
    }
    bool r2 = false;
    if (tx_dns) {
        jb_get_mark(js, &mark);
        r2 = AlertJsonDns(tx_dns, js);
        if (!r2) {
            jb_restore_mark(js, &mark);
        }
    }
    return r || r2;
}

static int JsonDoh2Logger(ThreadVars *tv, void *thread_data, const Packet *p, Flow *f,
        void *alstate, void *txptr, uint64_t tx_id)
{
    LogDnsLogThread *td = (LogDnsLogThread *)thread_data;
    LogDnsFileCtx *dnslog_ctx = td->dnslog_ctx;

    JsonBuilder *jb = CreateEveHeader(p, LOG_DIR_FLOW, "dns", NULL, dnslog_ctx->eve_ctx);

    if (unlikely(jb == NULL)) {
        return TM_ECODE_OK;
    }

    JsonBuilderMark mark = { 0, 0, 0 };

    jb_get_mark(jb, &mark);
    // first log HTTP2 part
    bool r = rs_http2_log_json(txptr, jb);
    if (!r) {
        jb_restore_mark(jb, &mark);
    }

    void *tx_dns = DetectGetInnerTx(txptr, ALPROTO_DOH2, ALPROTO_DNS, STREAM_TOCLIENT);
    if (tx_dns == NULL) {
        tx_dns = DetectGetInnerTx(txptr, ALPROTO_DOH2, ALPROTO_DNS, STREAM_TOSERVER);
    }
    bool r2 = false;
    if (tx_dns) {
        // mix of JsonDnsLogger
        if (SCDnsTxIsRequest(tx_dns)) {
            if (unlikely(dnslog_ctx->flags & LOG_QUERIES) == 0) {
                goto out;
            }
        } else if (SCDnsTxIsResponse(tx_dns)) {
            if (unlikely(dnslog_ctx->flags & LOG_ANSWERS) == 0) {
                goto out;
            }
        }

        if (!SCDnsLogEnabled(tx_dns, td->dnslog_ctx->flags)) {
            goto out;
        }

        jb_get_mark(jb, &mark);
        // log DOH2 with DNS config
        r2 = SCDnsLogJson(tx_dns, td->dnslog_ctx->flags, jb);
        if (!r2) {
            jb_restore_mark(jb, &mark);
        }
    }
out:
    if (r || r2) {
        OutputJsonBuilderBuffer(tv, p, p->flow, jb, td->ctx);
    }
    jb_free(jb);
    return TM_ECODE_OK;
}

static int JsonDnsLoggerToServer(ThreadVars *tv, void *thread_data,
    const Packet *p, Flow *f, void *alstate, void *txptr, uint64_t tx_id)
{
    SCEnter();

    LogDnsLogThread *td = (LogDnsLogThread *)thread_data;
    LogDnsFileCtx *dnslog_ctx = td->dnslog_ctx;

    if (unlikely(dnslog_ctx->flags & LOG_QUERIES) == 0) {
        return TM_ECODE_OK;
    }

    for (uint16_t i = 0; i < 0xffff; i++) {
        JsonBuilder *jb = CreateEveHeader(p, LOG_DIR_FLOW, "dns", NULL, dnslog_ctx->eve_ctx);
        if (unlikely(jb == NULL)) {
            return TM_ECODE_OK;
        }

        jb_open_object(jb, "dns");
        jb_set_int(jb, "version", 2);
        if (!SCDnsLogJsonQuery(txptr, i, td->dnslog_ctx->flags, jb)) {
            jb_free(jb);
            break;
        }
        jb_close(jb);

        OutputJsonBuilderBuffer(tv, p, p->flow, jb, td->ctx);
        jb_free(jb);
    }

    SCReturnInt(TM_ECODE_OK);
}

static int JsonDnsLoggerToClient(ThreadVars *tv, void *thread_data,
    const Packet *p, Flow *f, void *alstate, void *txptr, uint64_t tx_id)
{
    SCEnter();

    LogDnsLogThread *td = (LogDnsLogThread *)thread_data;
    LogDnsFileCtx *dnslog_ctx = td->dnslog_ctx;

    if (unlikely(dnslog_ctx->flags & LOG_ANSWERS) == 0) {
        return TM_ECODE_OK;
    }

    if (SCDnsLogAnswerEnabled(txptr, td->dnslog_ctx->flags)) {
        JsonBuilder *jb = CreateEveHeader(p, LOG_DIR_FLOW, "dns", NULL, dnslog_ctx->eve_ctx);
        if (unlikely(jb == NULL)) {
            return TM_ECODE_OK;
        }

        jb_open_object(jb, "dns");
        jb_set_int(jb, "version", 2);
        SCDnsLogJsonAnswer(txptr, td->dnslog_ctx->flags, jb);
        jb_close(jb);
        OutputJsonBuilderBuffer(tv, p, p->flow, jb, td->ctx);
        jb_free(jb);
    }

    SCReturnInt(TM_ECODE_OK);
}

static int JsonDnsLogger(ThreadVars *tv, void *thread_data, const Packet *p, Flow *f, void *alstate,
        void *txptr, uint64_t tx_id)
{
    LogDnsLogThread *td = (LogDnsLogThread *)thread_data;
    LogDnsFileCtx *dnslog_ctx = td->dnslog_ctx;

    if (dnslog_ctx->version == DNS_LOG_VERSION_2) {
        if (SCDnsTxIsRequest(txptr)) {
            return JsonDnsLoggerToServer(tv, thread_data, p, f, alstate, txptr, tx_id);
        } else if (SCDnsTxIsResponse(txptr)) {
            return JsonDnsLoggerToClient(tv, thread_data, p, f, alstate, txptr, tx_id);
        }
    } else {
        if (SCDnsTxIsRequest(txptr)) {
            if (unlikely(dnslog_ctx->flags & LOG_QUERIES) == 0) {
                return TM_ECODE_OK;
            }
        } else if (SCDnsTxIsResponse(txptr)) {
            if (unlikely(dnslog_ctx->flags & LOG_ANSWERS) == 0) {
                return TM_ECODE_OK;
            }
        }

        if (!SCDnsLogEnabled(txptr, td->dnslog_ctx->flags)) {
            return TM_ECODE_OK;
        }

        JsonBuilder *jb = CreateEveHeader(p, LOG_DIR_FLOW, "dns", NULL, dnslog_ctx->eve_ctx);
        if (unlikely(jb == NULL)) {
            return TM_ECODE_OK;
        }

        if (SCDnsLogJson(txptr, td->dnslog_ctx->flags, jb)) {
            OutputJsonBuilderBuffer(tv, p, p->flow, jb, td->ctx);
        }
        jb_free(jb);
    }
    return TM_ECODE_OK;
}

static TmEcode LogDnsLogThreadInit(ThreadVars *t, const void *initdata, void **data)
{
    LogDnsLogThread *aft = SCCalloc(1, sizeof(LogDnsLogThread));
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
    SCLogDebug("cleaning up sub output_ctx %p", output_ctx);
    LogDnsFileCtx *dnslog_ctx = (LogDnsFileCtx *)output_ctx->data;
    SCFree(dnslog_ctx);
    SCFree(output_ctx);
}

static void JsonDnsLogParseConfig(LogDnsFileCtx *dnslog_ctx, ConfNode *conf,
                                  const char *query_key, const char *answer_key,
                                  const char *answer_types_key)
{
    const char *query = ConfNodeLookupChildValue(conf, query_key);
    if (query != NULL) {
        if (ConfValIsTrue(query)) {
            dnslog_ctx->flags |= LOG_QUERIES;
        } else {
            dnslog_ctx->flags &= ~LOG_QUERIES;
        }
    } else {
        dnslog_ctx->flags |= LOG_QUERIES;
    }

    const char *response = ConfNodeLookupChildValue(conf, answer_key);
    if (response != NULL) {
        if (ConfValIsTrue(response)) {
            dnslog_ctx->flags |= LOG_ANSWERS;
        } else {
            dnslog_ctx->flags &= ~LOG_ANSWERS;
        }
    } else {
        dnslog_ctx->flags |= LOG_ANSWERS;
    }

    ConfNode *custom;
    if ((custom = ConfNodeLookupChild(conf, answer_types_key)) != NULL) {
        dnslog_ctx->flags &= ~LOG_ALL_RRTYPES;
        ConfNode *field;
        TAILQ_FOREACH (field, &custom->head, next) {
            DnsRRTypes f;
            for (f = DNS_RRTYPE_A; f < DNS_RRTYPE_MAX; f++) {
                if (strcasecmp(dns_rrtype_fields[f].config_rrtype, field->val) == 0) {
                    dnslog_ctx->flags |= dns_rrtype_fields[f].flags;
                    break;
                }
            }
        }
    } else {
        dnslog_ctx->flags |= LOG_ALL_RRTYPES;
    }
}

static uint8_t GetDnsLogVersion(ConfNode *conf)
{
    if (conf == NULL) {
        return DNS_LOG_VERSION_DEFAULT;
    }

    char *version_string = NULL;
    const ConfNode *version_node = ConfNodeLookupChild(conf, "version");
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

static uint8_t JsonDnsCheckVersion(ConfNode *conf)
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

static void JsonDnsLogInitFilters(LogDnsFileCtx *dnslog_ctx, ConfNode *conf)
{
    dnslog_ctx->flags = ~0ULL;

    if (conf) {
        JsonDnsLogParseConfig(dnslog_ctx, conf, "requests", "responses", "types");
        if (dnslog_ctx->flags & LOG_ANSWERS) {
            ConfNode *format;
            if ((format = ConfNodeLookupChild(conf, "formats")) != NULL) {
                uint64_t flags = 0;
                ConfNode *field;
                TAILQ_FOREACH (field, &format->head, next) {
                    if (strcasecmp(field->val, "detailed") == 0) {
                        flags |= LOG_FORMAT_DETAILED;
                    } else if (strcasecmp(field->val, "grouped") == 0) {
                        flags |= LOG_FORMAT_GROUPED;
                    } else {
                        SCLogWarning("Invalid JSON DNS log format: %s", field->val);
                    }
                }
                if (flags) {
                    dnslog_ctx->flags &= ~LOG_FORMAT_ALL;
                    dnslog_ctx->flags |= flags;
                } else {
                    SCLogWarning("Empty EVE DNS format array, using defaults");
                }
            } else {
                dnslog_ctx->flags |= LOG_FORMAT_ALL;
            }
        }
    }
}

static OutputInitResult JsonDnsLogInitCtxSub(ConfNode *conf, OutputCtx *parent_ctx)
{
    OutputInitResult result = { NULL, false };
    const char *enabled = ConfNodeLookupChildValue(conf, "enabled");
    if (enabled != NULL && !ConfValIsTrue(enabled)) {
        result.ok = true;
        return result;
    }

    OutputJsonCtx *ojc = parent_ctx->data;

    LogDnsFileCtx *dnslog_ctx = SCCalloc(1, sizeof(LogDnsFileCtx));
    if (unlikely(dnslog_ctx == NULL)) {
        return result;
    }

    dnslog_ctx->eve_ctx = ojc;
    dnslog_ctx->version = JsonDnsCheckVersion(conf);

    OutputCtx *output_ctx = SCCalloc(1, sizeof(OutputCtx));
    if (unlikely(output_ctx == NULL)) {
        SCFree(dnslog_ctx);
        return result;
    }

    output_ctx->data = dnslog_ctx;
    output_ctx->DeInit = LogDnsLogDeInitCtxSub;

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
            JsonDnsLogInitCtxSub, ALPROTO_DNS, JsonDnsLogger, LogDnsLogThreadInit,
            LogDnsLogThreadDeinit);
}

void JsonDoh2LogRegister(void)
{
    OutputRegisterTxSubModule(LOGGER_JSON_TX, "eve-log", "JsonDoH2Log", "eve-log.doh2",
            JsonDnsLogInitCtxSub, ALPROTO_DOH2, JsonDoh2Logger, LogDnsLogThreadInit,
            LogDnsLogThreadDeinit);
}
