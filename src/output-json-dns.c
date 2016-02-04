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

#ifdef HAVE_LIBJANSSON

/* we can do query logging as well, but it's disabled for now as the
 * TX id handling doesn't expect it */
#define QUERY 0

#define LOG_QUERIES   (1<<0)
#define LOG_ANSWERS  (1<<1)

#define LOG_A         (1<<2)
#define LOG_NS        (1<<3)
#define LOG_CNAME     (1<<4)
#define LOG_SOA       (1<<5)
#define LOG_PTR       (1<<6)
#define LOG_MX        (1<<7)
#define LOG_TXT       (1<<8)
#define LOG_AAAA      (1<<9)
#define LOG_SRV       (1<<10)
#define LOG_NAPTR     (1<<11)
#define LOG_DS        (1<<12)
#define LOG_RRSIG     (1<<13)
#define LOG_NSEC      (1<<14)
#define LOG_NSEC3     (1<<15)
#define LOG_TKEY      (1<<16)
#define LOG_TSIG      (1<<17)

#define LOG_ALL_RRTYPES (~(LOG_QUERIES|LOG_ANSWERS))

typedef enum {
    DNS_RRTYPE_A = 0,
    DNS_RRTYPE_NS,
    DNS_RRTYPE_CNAME,
    DNS_RRTYPE_SOA,
    DNS_RRTYPE_PTR,
    DNS_RRTYPE_MX,
    DNS_RRTYPE_TXT,
    DNS_RRTYPE_AAAA,
    DNS_RRTYPE_SRV,
    DNS_RRTYPE_NAPTR,
    DNS_RRTYPE_DS,
    DNS_RRTYPE_RRSIG,
    DNS_RRTYPE_NSEC,
    DNS_RRTYPE_NSEC3,
    DNS_RRTYPE_TKEY,
    DNS_RRTYPE_TSIG
} DnsRRTypes;

struct {
    char *config_rrtype;
    uint32_t flags;
} dns_rrtype_fields[] = {
   { "a", LOG_A },
   { "ns", LOG_NS },
   { "cname", LOG_CNAME },
   { "soa", LOG_SOA },
   { "ptr", LOG_PTR },
   { "mx", LOG_MX },
   { "txt", LOG_TXT },
   { "aaaa", LOG_AAAA },
   { "srv", LOG_SRV },
   { "naptr", LOG_NAPTR },
   { "ds", LOG_DS },
   { "rrsig", LOG_RRSIG },
   { "nsec", LOG_NSEC },
   { "nsec3", LOG_NSEC3 },
   { "tkey", LOG_TKEY },
   { "tsig", LOG_TSIG }
};

typedef struct LogDnsFileCtx_ {
    LogFileCtx *file_ctx;
    uint32_t flags; /** Store mode */
} LogDnsFileCtx;

typedef struct LogDnsLogThread_ {
    LogDnsFileCtx *dnslog_ctx;
    /** LogFileCtx has the pointer to the file and a mutex to allow multithreading */
    uint32_t dns_cnt;

    MemBuffer *buffer;
} LogDnsLogThread;

static int DNSRRTypeEnabled(uint16_t type, uint32_t flags)
{
    switch (type) {
        case DNS_RECORD_TYPE_A:
            return ((flags & LOG_A) != 0) ? 1 : 0;
        case DNS_RECORD_TYPE_NS:
            return ((flags & LOG_NS) != 0) ? 1 : 0;
        case DNS_RECORD_TYPE_CNAME:
            return ((flags & LOG_CNAME) != 0) ? 1 : 0;
        case DNS_RECORD_TYPE_SOA:
            return ((flags & LOG_SOA) != 0) ? 1 : 0;
        case DNS_RECORD_TYPE_PTR:
            return ((flags & LOG_PTR) != 0) ? 1 : 0;
        case DNS_RECORD_TYPE_MX:
            return ((flags & LOG_MX) != 0) ? 1 : 0;
        case DNS_RECORD_TYPE_TXT:
            return ((flags & LOG_TXT) != 0) ? 1 : 0;
        case DNS_RECORD_TYPE_AAAA:
            return ((flags & LOG_AAAA) != 0) ? 1 : 0;
        case DNS_RECORD_TYPE_SRV:
            return ((flags & LOG_SRV) != 0) ? 1 : 0;
        case DNS_RECORD_TYPE_NAPTR:
            return ((flags & LOG_NAPTR) != 0) ? 1 : 0;
        case DNS_RECORD_TYPE_DS:
            return ((flags & LOG_DS) != 0) ? 1 : 0;
        case DNS_RECORD_TYPE_RRSIG:
            return ((flags & LOG_RRSIG) != 0) ? 1 : 0;
        case DNS_RECORD_TYPE_NSEC:
            return ((flags & LOG_NSEC) != 0) ? 1 : 0;
        case DNS_RECORD_TYPE_NSEC3:
            return ((flags & LOG_NSEC3) != 0) ? 1 : 0;
        case DNS_RECORD_TYPE_TKEY:
            return ((flags & LOG_TKEY) != 0) ? 1 : 0;
        case DNS_RECORD_TYPE_TSIG:
            return ((flags & LOG_TSIG) != 0) ? 1 : 0;
        default:
            return 0;
    }
}

static void LogQuery(LogDnsLogThread *aft, json_t *js, DNSTransaction *tx,
        uint64_t tx_id, DNSQueryEntry *entry)
{
    SCLogDebug("got a DNS request and now logging !!");

    json_t *djs = json_object();
    if (djs == NULL) {
        return;
    }

    /* reset */
    MemBufferReset(aft->buffer);

    /* type */
    json_object_set_new(djs, "type", json_string("query"));

    /* id */
    json_object_set_new(djs, "id", json_integer(tx->tx_id));

    /* query */
    char *c;
    c = BytesToString((uint8_t *)((uint8_t *)entry + sizeof(DNSQueryEntry)), entry->len);
    if (c != NULL) {
        json_object_set_new(djs, "rrname", json_string(c));
        SCFree(c);
    }

    /* name */
    char record[16] = "";
    DNSCreateTypeString(entry->type, record, sizeof(record));
    json_object_set_new(djs, "rrtype", json_string(record));

    /* tx id (tx counter) */
    json_object_set_new(djs, "tx_id", json_integer(tx_id));

    /* dns */
    json_object_set_new(js, "dns", djs);
    if (likely(DNSRRTypeEnabled(entry->type, aft->dnslog_ctx->flags))) {
        OutputJSONBuffer(js, aft->dnslog_ctx->file_ctx, &aft->buffer);
    }
    json_object_del(js, "dns");
}

static void OutputAnswer(LogDnsLogThread *aft, json_t *djs, DNSTransaction *tx, DNSAnswerEntry *entry)
{
    json_t *js = json_object();
    if (js == NULL)
        return;

    /* type */
    json_object_set_new(js, "type", json_string("answer"));

    /* id */
    json_object_set_new(js, "id", json_integer(tx->tx_id));

    /* rcode */
    char rcode[16] = "";
    DNSCreateRcodeString(tx->rcode, rcode, sizeof(rcode));
    json_object_set_new(js, "rcode", json_string(rcode));

    /* we are logging an answer RR */
    if (entry != NULL) {
        /* query */
        if (entry->fqdn_len > 0) {
            char *c;
            c = BytesToString((uint8_t *)((uint8_t *)entry + sizeof(DNSAnswerEntry)),
                    entry->fqdn_len);
            if (c != NULL) {
                json_object_set_new(js, "rrname", json_string(c));
                SCFree(c);
            }
        }

        /* name */
        char record[16] = "";
        DNSCreateTypeString(entry->type, record, sizeof(record));
        json_object_set_new(js, "rrtype", json_string(record));

        /* ttl */
        json_object_set_new(js, "ttl", json_integer(entry->ttl));

        uint8_t *ptr = (uint8_t *)((uint8_t *)entry + sizeof(DNSAnswerEntry)+ entry->fqdn_len);
        if (entry->type == DNS_RECORD_TYPE_A) {
            char a[16] = "";
            PrintInet(AF_INET, (const void *)ptr, a, sizeof(a));
            json_object_set_new(js, "rdata", json_string(a));
        } else if (entry->type == DNS_RECORD_TYPE_AAAA) {
            char a[46] = "";
            PrintInet(AF_INET6, (const void *)ptr, a, sizeof(a));
            json_object_set_new(js, "rdata", json_string(a));
        } else if (entry->data_len == 0) {
            json_object_set_new(js, "rdata", json_string(""));
        } else if (entry->type == DNS_RECORD_TYPE_TXT || entry->type == DNS_RECORD_TYPE_CNAME ||
                   entry->type == DNS_RECORD_TYPE_MX || entry->type == DNS_RECORD_TYPE_PTR ||
                   entry->type == DNS_RECORD_TYPE_NS) {
            if (entry->data_len != 0) {
                char buffer[256] = "";
                uint16_t copy_len = entry->data_len < (sizeof(buffer) - 1) ?
                    entry->data_len : sizeof(buffer) - 1;
                memcpy(buffer, ptr, copy_len);
                buffer[copy_len] = '\0';
                json_object_set_new(js, "rdata", json_string(buffer));
            } else {
                json_object_set_new(js, "rdata", json_string(""));
            }
        } else if (entry->type == DNS_RECORD_TYPE_SSHFP) {
            if (entry->data_len > 2) {
                /* get algo and type */
                uint8_t algo = *ptr;
                uint8_t fptype = *(ptr+1);

                /* turn fp raw buffer into a nice :-separate hex string */
                uint16_t fp_len = (entry->data_len - 2);
                uint8_t *dptr = ptr+2;
                uint32_t output_len = fp_len * 2 + 1; // create c-string, so add space for 0.
                char hexstring[output_len], *p = hexstring;
                memset(hexstring, 0x00, output_len);

                uint16_t x;
                for (x = 0; x < fp_len; x++, p += 3) {
                    snprintf(p, 4, x == fp_len - 1 ? "%02x" : "%02x:", dptr[x]);
                }

                /* wrap the whole thing in it's own structure */
                json_t *hjs = json_object();
                if (hjs != NULL) {
                    json_object_set_new(hjs, "fingerprint", json_string(hexstring));
                    json_object_set_new(hjs, "algo", json_integer(algo));
                    json_object_set_new(hjs, "type", json_integer(fptype));

                    json_object_set_new(js, "sshfp", hjs);
                }
            }
        }
    }

    /* reset */
    MemBufferReset(aft->buffer);
    json_object_set_new(djs, "dns", js);
    if (likely(DNSRRTypeEnabled(entry->type, aft->dnslog_ctx->flags))) {
        OutputJSONBuffer(djs, aft->dnslog_ctx->file_ctx, &aft->buffer);
    }
    json_object_del(djs, "dns");

    return;
}

static void OutputFailure(LogDnsLogThread *aft, json_t *djs, DNSTransaction *tx, DNSQueryEntry *entry)
{
    json_t *js = json_object();
    if (js == NULL)
        return;

    /* type */
    json_object_set_new(js, "type", json_string("answer"));

    /* id */
    json_object_set_new(js, "id", json_integer(tx->tx_id));

    /* rcode */
    char rcode[16] = "";
    DNSCreateRcodeString(tx->rcode, rcode, sizeof(rcode));
    json_object_set_new(js, "rcode", json_string(rcode));

    /* no answer RRs, use query for rname */
    char *c;
    c = BytesToString((uint8_t *)((uint8_t *)entry + sizeof(DNSQueryEntry)), entry->len);
    if (c != NULL) {
        json_object_set_new(js, "rrname", json_string(c));
        SCFree(c);
    }

    /* reset */
    MemBufferReset(aft->buffer);
    json_object_set_new(djs, "dns", js);
    if (likely(DNSRRTypeEnabled(entry->type, aft->dnslog_ctx->flags))) {
        OutputJSONBuffer(djs, aft->dnslog_ctx->file_ctx, &aft->buffer);
    }
    json_object_del(djs, "dns");

    return;
}

static void LogAnswers(LogDnsLogThread *aft, json_t *js, DNSTransaction *tx, uint64_t tx_id)
{

    SCLogDebug("got a DNS response and now logging !!");

    /* rcode != noerror */
    if (tx->rcode) {
        /* Most DNS servers do not support multiple queries because
         * the rcode in response is not per-query.  Multiple queries
         * are likely to lead to FORMERR, so log this. */
        DNSQueryEntry *query = NULL;
        TAILQ_FOREACH(query, &tx->query_list, next) {
            OutputFailure(aft, js, tx, query);
        }
    }

    DNSAnswerEntry *entry = NULL;
    TAILQ_FOREACH(entry, &tx->answer_list, next) {
        OutputAnswer(aft, js, tx, entry);
    }

    entry = NULL;
    TAILQ_FOREACH(entry, &tx->authority_list, next) {
        OutputAnswer(aft, js, tx, entry);
    }

}

static int JsonDnsLogger(ThreadVars *tv, void *thread_data, const Packet *p, Flow *f, void *alstate, void *txptr, uint64_t tx_id)
{
    SCEnter();

    LogDnsLogThread *td = (LogDnsLogThread *)thread_data;
    LogDnsFileCtx *dnslog_ctx = td->dnslog_ctx;
    DNSTransaction *tx = txptr;
    json_t *js;

    if (likely(dnslog_ctx->flags & LOG_QUERIES) != 0) {
        DNSQueryEntry *query = NULL;
        TAILQ_FOREACH(query, &tx->query_list, next) {
            js = CreateJSONHeader((Packet *)p, 1, "dns");
            if (unlikely(js == NULL))
                return TM_ECODE_OK;

            LogQuery(td, js, tx, tx_id, query);

            json_decref(js);
        }
    }

    if (likely(dnslog_ctx->flags & LOG_ANSWERS) != 0) {
        js = CreateJSONHeader((Packet *)p, 0, "dns");
        if (unlikely(js == NULL))
            return TM_ECODE_OK;

        LogAnswers(td, js, tx, tx_id);

        json_decref(js);
    }

    SCReturnInt(TM_ECODE_OK);
}

#define OUTPUT_BUFFER_SIZE 65536
static TmEcode LogDnsLogThreadInit(ThreadVars *t, void *initdata, void **data)
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

static OutputCtx *JsonDnsLogInitCtxSub(ConfNode *conf, OutputCtx *parent_ctx)
{
    AlertJsonThread *ajt = parent_ctx->data;

    LogDnsFileCtx *dnslog_ctx = SCMalloc(sizeof(LogDnsFileCtx));
    if (unlikely(dnslog_ctx == NULL)) {
        return NULL;
    }
    memset(dnslog_ctx, 0x00, sizeof(LogDnsFileCtx));

    dnslog_ctx->file_ctx = ajt->file_ctx;

    OutputCtx *output_ctx = SCCalloc(1, sizeof(OutputCtx));
    if (unlikely(output_ctx == NULL)) {
        SCFree(dnslog_ctx);
        return NULL;
    }

    output_ctx->data = dnslog_ctx;
    output_ctx->DeInit = LogDnsLogDeInitCtxSub;

    dnslog_ctx->flags = (uint32_t)~0;

    if (conf) {
        const char *query = ConfNodeLookupChildValue(conf, "query");
        if (query != NULL) {
            if (ConfValIsTrue(query)) {
                dnslog_ctx->flags |= LOG_QUERIES;
            } else {
                dnslog_ctx->flags &= ~LOG_QUERIES;
            }
        }
        const char *response = ConfNodeLookupChildValue(conf, "answer");
        if (response != NULL) {
            if (ConfValIsTrue(response)) {
                dnslog_ctx->flags |= LOG_ANSWERS;
            } else {
                dnslog_ctx->flags &= ~LOG_ANSWERS;
            }
        }
        ConfNode *custom;
        if ((custom = ConfNodeLookupChild(conf, "custom")) != NULL) {
            dnslog_ctx->flags &= ~LOG_ALL_RRTYPES;
            ConfNode *field;
            TAILQ_FOREACH(field, &custom->head, next)
            {
                if (field != NULL)
                {
                    DnsRRTypes f;
                    for (f = DNS_RRTYPE_A; f < DNS_RRTYPE_TXT; f++)
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
        }
    }

    SCLogDebug("DNS log sub-module initialized");

    AppLayerParserRegisterLogger(IPPROTO_UDP, ALPROTO_DNS);
    AppLayerParserRegisterLogger(IPPROTO_TCP, ALPROTO_DNS);

    return output_ctx;
}

#define DEFAULT_LOG_FILENAME "dns.json"
/** \brief Create a new dns log LogFileCtx.
 *  \param conf Pointer to ConfNode containing this loggers configuration.
 *  \return NULL if failure, LogFileCtx* to the file_ctx if succesful
 * */
static OutputCtx *JsonDnsLogInitCtx(ConfNode *conf)
{
    LogFileCtx *file_ctx = LogFileNewCtx();

    if(file_ctx == NULL) {
        SCLogError(SC_ERR_DNS_LOG_GENERIC, "couldn't create new file_ctx");
        return NULL;
    }

    if (SCConfLogOpenGeneric(conf, file_ctx, DEFAULT_LOG_FILENAME, 1) < 0) {
        LogFileFreeCtx(file_ctx);
        return NULL;
    }

    LogDnsFileCtx *dnslog_ctx = SCMalloc(sizeof(LogDnsFileCtx));
    if (unlikely(dnslog_ctx == NULL)) {
        LogFileFreeCtx(file_ctx);
        return NULL;
    }
    memset(dnslog_ctx, 0x00, sizeof(LogDnsFileCtx));

    dnslog_ctx->file_ctx = file_ctx;

    OutputCtx *output_ctx = SCCalloc(1, sizeof(OutputCtx));
    if (unlikely(output_ctx == NULL)) {
        LogFileFreeCtx(file_ctx);
        SCFree(dnslog_ctx);
        return NULL;
    }

    output_ctx->data = dnslog_ctx;
    output_ctx->DeInit = LogDnsLogDeInitCtx;

    SCLogDebug("DNS log output initialized");

    AppLayerParserRegisterLogger(IPPROTO_UDP, ALPROTO_DNS);
    AppLayerParserRegisterLogger(IPPROTO_TCP, ALPROTO_DNS);

    return output_ctx;
}


#define MODULE_NAME "JsonDnsLog"
void TmModuleJsonDnsLogRegister (void)
{
    tmm_modules[TMM_JSONDNSLOG].name = MODULE_NAME;
    tmm_modules[TMM_JSONDNSLOG].ThreadInit = LogDnsLogThreadInit;
    tmm_modules[TMM_JSONDNSLOG].ThreadDeinit = LogDnsLogThreadDeinit;
    tmm_modules[TMM_JSONDNSLOG].RegisterTests = NULL;
    tmm_modules[TMM_JSONDNSLOG].cap_flags = 0;
    tmm_modules[TMM_JSONDNSLOG].flags = TM_FLAG_LOGAPI_TM;

    OutputRegisterTxModule(MODULE_NAME, "dns-json-log", JsonDnsLogInitCtx,
            ALPROTO_DNS, JsonDnsLogger);
    OutputRegisterTxSubModule("eve-log", MODULE_NAME, "eve-log.dns", JsonDnsLogInitCtxSub,
            ALPROTO_DNS, JsonDnsLogger);
}

#else

static TmEcode OutputJsonThreadInit(ThreadVars *t, void *initdata, void **data)
{
    SCLogInfo("Can't init JSON output - JSON support was disabled during build.");
    return TM_ECODE_FAILED;
}

void TmModuleJsonDnsLogRegister (void)
{
    tmm_modules[TMM_JSONDNSLOG].name = "JsonDnsLog";
    tmm_modules[TMM_JSONDNSLOG].ThreadInit = OutputJsonThreadInit;
}

#endif
