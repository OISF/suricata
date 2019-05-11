/* Copyright (C) 2007-2013 Open Information Security Foundation
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
#include "util-mem.h"
#include "app-layer-parser.h"
#include "output.h"
#include "app-layer-dns-udp.h"
#include "app-layer.h"
#include "util-privs.h"
#include "util-buffer.h"
#include "util-proto-name.h"
#include "util-logopenfile.h"
#include "util-time.h"

#include "output-json.h"
#include "output-json-dns.h"

#include "rust-dns-log-gen.h"

/* we can do query logging as well, but it's disabled for now as the
 * TX id handling doesn't expect it */
#define QUERY 0

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
    DNS_RRTYPE_SPF,
    DNS_RRTYPE_TKEY,
    DNS_RRTYPE_TSIG,
    DNS_RRTYPE_MAILA,
    DNS_RRTYPE_ANY,
    DNS_RRTYPE_URI,
    DNS_RRTYPE_MAX,
} DnsRRTypes;

typedef enum {
    DNS_VERSION_1 = 1,
    DNS_VERSION_2
} DnsVersion;

#define DNS_VERSION_DEFAULT DNS_VERSION_2

static struct {
    const char *config_rrtype;
    uint64_t flags;
} dns_rrtype_fields[] = {
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
   { "spf", LOG_SPF },
   { "tkey", LOG_TKEY },
   { "tsig", LOG_TSIG },
   { "maila", LOG_MAILA },
   { "any", LOG_ANY },
   { "uri", LOG_URI }
};

typedef struct LogDnsFileCtx_ {
    LogFileCtx *file_ctx;
    uint64_t flags; /** Store mode */
    DnsVersion version;
    OutputJsonCommonSettings cfg;
} LogDnsFileCtx;

typedef struct LogDnsLogThread_ {
    LogDnsFileCtx *dnslog_ctx;
    /** LogFileCtx has the pointer to the file and a mutex to allow multithreading */
    uint32_t dns_cnt;

    MemBuffer *buffer;
} LogDnsLogThread;

json_t *JsonDNSLogQuery(void *txptr, uint64_t tx_id)
{
    json_t *queryjs = json_array();
    if (queryjs == NULL)
        return NULL;

    for (uint16_t i = 0; i < UINT16_MAX; i++) {
        json_t *dns = rs_dns_log_json_query((void *)txptr, i, LOG_ALL_RRTYPES);
        if (unlikely(dns == NULL)) {
            break;
        }
        json_array_append_new(queryjs, dns);
    }

    return queryjs;
}

json_t *JsonDNSLogAnswer(void *txptr, uint64_t tx_id)
{
    return rs_dns_log_json_answer(txptr, LOG_ALL_RRTYPES);
}

static int JsonDnsLoggerToServer(ThreadVars *tv, void *thread_data,
    const Packet *p, Flow *f, void *alstate, void *txptr, uint64_t tx_id)
{
    SCEnter();

    LogDnsLogThread *td = (LogDnsLogThread *)thread_data;
    LogDnsFileCtx *dnslog_ctx = td->dnslog_ctx;
    json_t *js;

    if (unlikely(dnslog_ctx->flags & LOG_QUERIES) == 0) {
        return TM_ECODE_OK;
    }

    for (uint16_t i = 0; i < 0xffff; i++) {
        js = CreateJSONHeader(p, LOG_DIR_PACKET, "dns");
        if (unlikely(js == NULL)) {
            return TM_ECODE_OK;
        }
        JsonAddCommonOptions(&dnslog_ctx->cfg, p, f, js);

        json_t *dns = rs_dns_log_json_query(txptr, i, td->dnslog_ctx->flags);
        if (unlikely(dns == NULL)) {
            json_decref(js);
            break;
        }
        json_object_set_new(js, "dns", dns);
        MemBufferReset(td->buffer);
        OutputJSONBuffer(js, td->dnslog_ctx->file_ctx, &td->buffer);
        json_decref(js);
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

    json_t *js = CreateJSONHeader(p, LOG_DIR_PACKET, "dns");
    if (unlikely(js == NULL))
        return TM_ECODE_OK;

    JsonAddCommonOptions(&dnslog_ctx->cfg, p, f, js);

    if (td->dnslog_ctx->version == DNS_VERSION_2) {
        json_t *answer = rs_dns_log_json_answer(txptr,
                td->dnslog_ctx->flags);
        if (answer != NULL) {
            json_object_set_new(js, "dns", answer);
            MemBufferReset(td->buffer);
            OutputJSONBuffer(js, td->dnslog_ctx->file_ctx, &td->buffer);
        }
    } else {
        /* Log answers. */
        for (uint16_t i = 0; i < UINT16_MAX; i++) {
            json_t *answer = rs_dns_log_json_answer_v1(txptr, i,
                    td->dnslog_ctx->flags);
            if (answer == NULL) {
                break;
            }
            json_object_set_new(js, "dns", answer);
            MemBufferReset(td->buffer);
            OutputJSONBuffer(js, td->dnslog_ctx->file_ctx, &td->buffer);
            json_object_del(js, "dns");
        }
        /* Log authorities. */
        for (uint16_t i = 0; i < UINT16_MAX; i++) {
            json_t *answer = rs_dns_log_json_authority_v1(txptr, i,
                    td->dnslog_ctx->flags);
            if (answer == NULL) {
                break;
            }
            json_object_set_new(js, "dns", answer);
            MemBufferReset(td->buffer);
            OutputJSONBuffer(js, td->dnslog_ctx->file_ctx, &td->buffer);
            json_object_del(js, "dns");
        }
    }

    json_decref(js);

    SCReturnInt(TM_ECODE_OK);
}

#define OUTPUT_BUFFER_SIZE 65536
static TmEcode LogDnsLogThreadInit(ThreadVars *t, const void *initdata, void **data)
{
    LogDnsLogThread *aft = SCMalloc(sizeof(LogDnsLogThread));
    if (unlikely(aft == NULL))
        return TM_ECODE_FAILED;
    memset(aft, 0, sizeof(LogDnsLogThread));

    if(initdata == NULL)
    {
        SCLogDebug("Error getting context for EveLogDNS.  \"initdata\" argument NULL");
        SCFree(aft);
        return TM_ECODE_FAILED;
    }

    aft->buffer = MemBufferCreateNew(OUTPUT_BUFFER_SIZE);
    if (aft->buffer == NULL) {
        SCFree(aft);
        return TM_ECODE_FAILED;
    }

    /* Use the Ouptut Context (file pointer and mutex) */
    aft->dnslog_ctx= ((OutputCtx *)initdata)->data;

    *data = (void *)aft;
    return TM_ECODE_OK;
}

static TmEcode LogDnsLogThreadDeinit(ThreadVars *t, void *data)
{
    LogDnsLogThread *aft = (LogDnsLogThread *)data;
    if (aft == NULL) {
        return TM_ECODE_OK;
    }

    MemBufferFree(aft->buffer);
    /* clear memory */
    memset(aft, 0, sizeof(LogDnsLogThread));

    SCFree(aft);
    return TM_ECODE_OK;
}

static void LogDnsLogDeInitCtx(OutputCtx *output_ctx)
{
    LogDnsFileCtx *dnslog_ctx = (LogDnsFileCtx *)output_ctx->data;
    LogFileFreeCtx(dnslog_ctx->file_ctx);
    SCFree(dnslog_ctx);
    SCFree(output_ctx);
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
        if (dnslog_ctx->version == DNS_VERSION_2) {
            dnslog_ctx->flags |= LOG_QUERIES;
        }
    }

    const char *response = ConfNodeLookupChildValue(conf, answer_key);
    if (response != NULL) {
        if (ConfValIsTrue(response)) {
            dnslog_ctx->flags |= LOG_ANSWERS;
        } else {
            dnslog_ctx->flags &= ~LOG_ANSWERS;
        }
    } else {
        if (dnslog_ctx->version == DNS_VERSION_2) {
            dnslog_ctx->flags |= LOG_ANSWERS;
        }
    }

    ConfNode *custom;
    if ((custom = ConfNodeLookupChild(conf, answer_types_key)) != NULL) {
        dnslog_ctx->flags &= ~LOG_ALL_RRTYPES;
        ConfNode *field;
        TAILQ_FOREACH(field, &custom->head, next)
        {
            if (field != NULL)
            {
                DnsRRTypes f;
                for (f = DNS_RRTYPE_A; f < DNS_RRTYPE_MAX; f++)
                {
                    if (strcasecmp(dns_rrtype_fields[f].config_rrtype,
                                   field->val) == 0)
                    {
                        dnslog_ctx->flags |= dns_rrtype_fields[f].flags;
                        break;
                    }
                }
            }
        }
    } else {
        if (dnslog_ctx->version == DNS_VERSION_2) {
            dnslog_ctx->flags |= LOG_ALL_RRTYPES;
        }
    }
}

static DnsVersion JsonDnsParseVersion(ConfNode *conf)
{
    if (conf == NULL) {
        return DNS_VERSION_DEFAULT;
    }

    DnsVersion version = DNS_VERSION_DEFAULT;
    intmax_t config_version;
    if (ConfGetChildValueInt(conf, "version", &config_version)) {
        switch(config_version) {
            case 1:
                version = DNS_VERSION_1;
                break;
            case 2:
                version = DNS_VERSION_2;
                break;
            default:
                SCLogWarning(SC_ERR_INVALID_ARGUMENT,
                        "invalid eve-log dns version option: %"PRIuMAX", "
                        "forcing it to version %u",
                        config_version, DNS_VERSION_DEFAULT);
                version = DNS_VERSION_DEFAULT;
                break;
        }
    } else {
        SCLogWarning(SC_ERR_INVALID_ARGUMENT,
                "eve-log dns version not found, forcing it to version %u",
                DNS_VERSION_DEFAULT);
        version = DNS_VERSION_DEFAULT;
    }
    return version;
}

static void JsonDnsLogInitFilters(LogDnsFileCtx *dnslog_ctx, ConfNode *conf)
{
    dnslog_ctx->flags = ~0UL;

    if (conf) {
        if (dnslog_ctx->version == DNS_VERSION_1) {
            JsonDnsLogParseConfig(dnslog_ctx, conf, "query", "answer", "custom");
        } else {
            JsonDnsLogParseConfig(dnslog_ctx, conf, "requests", "responses", "types");

            if (dnslog_ctx->flags & LOG_ANSWERS) {
                ConfNode *format;
                if ((format = ConfNodeLookupChild(conf, "formats")) != NULL) {
                    dnslog_ctx->flags &= ~LOG_FORMAT_ALL;
                    ConfNode *field;
                    TAILQ_FOREACH(field, &format->head, next) {
                        if (strcasecmp(field->val, "detailed") == 0) {
                            dnslog_ctx->flags |= LOG_FORMAT_DETAILED;
                        } else if (strcasecmp(field->val, "grouped") == 0) {
                            dnslog_ctx->flags |= LOG_FORMAT_GROUPED;
                        }
                    }
                } else {
                    dnslog_ctx->flags |= LOG_FORMAT_ALL;
                }
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

    DnsVersion version = JsonDnsParseVersion(conf);

    OutputJsonCtx *ojc = parent_ctx->data;

    LogDnsFileCtx *dnslog_ctx = SCMalloc(sizeof(LogDnsFileCtx));
    if (unlikely(dnslog_ctx == NULL)) {
        return result;
    }
    memset(dnslog_ctx, 0x00, sizeof(LogDnsFileCtx));

    dnslog_ctx->file_ctx = ojc->file_ctx;
    dnslog_ctx->cfg = ojc->cfg;

    OutputCtx *output_ctx = SCCalloc(1, sizeof(OutputCtx));
    if (unlikely(output_ctx == NULL)) {
        SCFree(dnslog_ctx);
        return result;
    }

    output_ctx->data = dnslog_ctx;
    output_ctx->DeInit = LogDnsLogDeInitCtxSub;

    dnslog_ctx->version = version;
    JsonDnsLogInitFilters(dnslog_ctx, conf);

    SCLogDebug("DNS log sub-module initialized");

    AppLayerParserRegisterLogger(IPPROTO_UDP, ALPROTO_DNS);
    AppLayerParserRegisterLogger(IPPROTO_TCP, ALPROTO_DNS);

    result.ctx = output_ctx;
    result.ok = true;
    return result;
}

#define DEFAULT_LOG_FILENAME "dns.json"
/** \brief Create a new dns log LogFileCtx.
 *  \param conf Pointer to ConfNode containing this loggers configuration.
 *  \return NULL if failure, LogFileCtx* to the file_ctx if succesful
 * */
static OutputInitResult JsonDnsLogInitCtx(ConfNode *conf)
{
    OutputInitResult result = { NULL, false };
    const char *enabled = ConfNodeLookupChildValue(conf, "enabled");
    if (enabled != NULL && !ConfValIsTrue(enabled)) {
        return result;
    }

    DnsVersion version = JsonDnsParseVersion(conf);

    LogFileCtx *file_ctx = LogFileNewCtx();

    if(file_ctx == NULL) {
        SCLogError(SC_ERR_DNS_LOG_GENERIC, "couldn't create new file_ctx");
        return result;
    }

    if (SCConfLogOpenGeneric(conf, file_ctx, DEFAULT_LOG_FILENAME, 1) < 0) {
        LogFileFreeCtx(file_ctx);
        return result;
    }

    LogDnsFileCtx *dnslog_ctx = SCMalloc(sizeof(LogDnsFileCtx));
    if (unlikely(dnslog_ctx == NULL)) {
        LogFileFreeCtx(file_ctx);
        return result;
    }
    memset(dnslog_ctx, 0x00, sizeof(LogDnsFileCtx));

    dnslog_ctx->file_ctx = file_ctx;

    OutputCtx *output_ctx = SCCalloc(1, sizeof(OutputCtx));
    if (unlikely(output_ctx == NULL)) {
        LogFileFreeCtx(file_ctx);
        SCFree(dnslog_ctx);
        return result;
    }

    output_ctx->data = dnslog_ctx;
    output_ctx->DeInit = LogDnsLogDeInitCtx;

    dnslog_ctx->version = version;
    JsonDnsLogInitFilters(dnslog_ctx, conf);

    SCLogDebug("DNS log output initialized");

    AppLayerParserRegisterLogger(IPPROTO_UDP, ALPROTO_DNS);
    AppLayerParserRegisterLogger(IPPROTO_TCP, ALPROTO_DNS);

    result.ctx = output_ctx;
    result.ok = true;
    return result;
}


#define MODULE_NAME "JsonDnsLog"
void JsonDnsLogRegister (void)
{
    /* Logger for requests. */
    OutputRegisterTxModuleWithProgress(LOGGER_JSON_DNS_TS, MODULE_NAME,
        "dns-json-log", JsonDnsLogInitCtx, ALPROTO_DNS, JsonDnsLoggerToServer,
        0, 1, LogDnsLogThreadInit, LogDnsLogThreadDeinit, NULL);

    /* Logger for replies. */
    OutputRegisterTxModuleWithProgress(LOGGER_JSON_DNS_TC, MODULE_NAME,
        "dns-json-log", JsonDnsLogInitCtx, ALPROTO_DNS, JsonDnsLoggerToClient,
        1, 1, LogDnsLogThreadInit, LogDnsLogThreadDeinit, NULL);

    /* Sub-logger for requests. */
    OutputRegisterTxSubModuleWithProgress(LOGGER_JSON_DNS_TS, "eve-log",
        MODULE_NAME, "eve-log.dns", JsonDnsLogInitCtxSub, ALPROTO_DNS,
        JsonDnsLoggerToServer, 0, 1, LogDnsLogThreadInit,
        LogDnsLogThreadDeinit, NULL);

    /* Sub-logger for replies. */
    OutputRegisterTxSubModuleWithProgress(LOGGER_JSON_DNS_TC, "eve-log",
        MODULE_NAME, "eve-log.dns", JsonDnsLogInitCtxSub, ALPROTO_DNS,
        JsonDnsLoggerToClient, 1, 1, LogDnsLogThreadInit, LogDnsLogThreadDeinit,
        NULL);
}
