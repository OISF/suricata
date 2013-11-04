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
 * \author Victor Julien <victor@inliniac.net>
 *
 * Implements dns logging portion of the engine.
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

#include "output.h"
#include "output-dnslog.h"
#include "app-layer-dns-udp.h"
#include "app-layer.h"
#include "util-privs.h"
#include "util-buffer.h"

#include "util-logopenfile.h"
#include "util-time.h"

#ifdef HAVE_LIBJANSSON
#include <jansson.h>

#define DEFAULT_DNS_SYSLOG_FACILITY_STR       "local0"
#define DEFAULT_DNS_SYSLOG_FACILITY           LOG_LOCAL0
#define DEFAULT_DNS_SYSLOG_LEVEL              LOG_INFO

#ifndef OS_WIN32
static int dns_syslog_level = DEFAULT_DNS_SYSLOG_LEVEL;
#endif
#endif

#define DEFAULT_LOG_FILENAME "dns.log"

#define MODULE_NAME "DnsJson"

#define OUTPUT_BUFFER_SIZE 65535

/* we can do query logging as well, but it's disabled for now as the
 * TX id handling doesn't expect it */
#define QUERY 0

TmEcode DnsJson (ThreadVars *, Packet *, void *, PacketQueue *, PacketQueue *);
TmEcode DnsJsonIPv4(ThreadVars *, Packet *, void *, PacketQueue *, PacketQueue *);
TmEcode DnsJsonIPv6(ThreadVars *, Packet *, void *, PacketQueue *, PacketQueue *);
TmEcode DnsJsonThreadInit(ThreadVars *, void *, void **);
TmEcode DnsJsonThreadDeinit(ThreadVars *, void *);
void DnsJsonExitPrintStats(ThreadVars *, void *);
static void DnsJsonDeInitCtx(OutputCtx *);

void TmModuleDnsJsonRegister (void) {
    tmm_modules[TMM_LOGDNSJSON].name = MODULE_NAME;
    tmm_modules[TMM_LOGDNSJSON].ThreadInit = DnsJsonThreadInit;
    tmm_modules[TMM_LOGDNSJSON].Func = DnsJson;
    tmm_modules[TMM_LOGDNSJSON].ThreadExitPrintStats = DnsJsonExitPrintStats;
    tmm_modules[TMM_LOGDNSJSON].ThreadDeinit = DnsJsonThreadDeinit;
    tmm_modules[TMM_LOGDNSJSON].RegisterTests = NULL;
    tmm_modules[TMM_LOGDNSJSON].cap_flags = 0;

    OutputRegisterModule(MODULE_NAME, "dns-log-json", DnsJsonInitCtx);

    /* enable the logger for the app layer */
    AppLayerRegisterLogger(ALPROTO_DNS_UDP);
    AppLayerRegisterLogger(ALPROTO_DNS_TCP);
    SCLogDebug("registered %s", MODULE_NAME);
}

typedef struct LogDnsFileCtx_ {
    LogFileCtx *file_ctx;
    uint32_t flags; /** Store mode */
} LogDnsFileCtx;

#define LOG_DNS_DEFAULT 0
#define LOG_DNS_JSON_SYSLOG 2 /* JSON output via syslog */

typedef struct LogDnsLogThread_ {
    LogDnsFileCtx *dnslog_ctx;
    /** LogFileCtx has the pointer to the file and a mutex to allow multithreading */
    uint32_t dns_cnt;

    MemBuffer *buffer;
} LogDnsLogThread;

static void CreateTypeString(uint16_t type, char *str, size_t str_size) {
    if (type == DNS_RECORD_TYPE_A) {
        snprintf(str, str_size, "A");
    } else if (type == DNS_RECORD_TYPE_NS) {
        snprintf(str, str_size, "NS");
    } else if (type == DNS_RECORD_TYPE_AAAA) {
        snprintf(str, str_size, "AAAA");
    } else if (type == DNS_RECORD_TYPE_TXT) {
        snprintf(str, str_size, "TXT");
    } else if (type == DNS_RECORD_TYPE_CNAME) {
        snprintf(str, str_size, "CNAME");
    } else if (type == DNS_RECORD_TYPE_SOA) {
        snprintf(str, str_size, "SOA");
    } else if (type == DNS_RECORD_TYPE_MX) {
        snprintf(str, str_size, "MX");
    } else if (type == DNS_RECORD_TYPE_PTR) {
        snprintf(str, str_size, "PTR");
    } else if (type == DNS_RECORD_TYPE_ANY) {
        snprintf(str, str_size, "ANY");
    } else if (type == DNS_RECORD_TYPE_TKEY) {
        snprintf(str, str_size, "TKEY");
    } else if (type == DNS_RECORD_TYPE_TSIG) {
        snprintf(str, str_size, "TSIG");
    } else {
        snprintf(str, str_size, "%04x/%u", type, type);
    }
}

static void LogQuery(LogDnsLogThread *aft, char *timebuf, char *srcip, char *dstip, Port sp, Port dp, DNSTransaction *tx, DNSQueryEntry *entry) {
    LogDnsFileCtx *hlog = aft->dnslog_ctx;

    SCLogDebug("got a DNS request and now logging !!");

    /* reset */
    MemBufferReset(aft->buffer);

    json_t *js = json_object();
    if (js == NULL)
        return;

    json_t *djs = json_object();
    if (djs == NULL) {
        free(js);
        return;
    }

    /* time & tx */
    json_object_set_new(js, "time", json_string(timebuf));

    /* tuple */
    json_object_set_new(js, "srcip", json_string(srcip));
    json_object_set_new(js, "sp", json_integer(sp));
    json_object_set_new(js, "dstip", json_string(dstip));
    json_object_set_new(js, "dp", json_integer(dp));

    /* type */
    json_object_set_new(djs, "type", json_string("query"));

    /* id */
    json_object_set_new(djs, "id", json_integer(tx->tx_id));

    /* query */
    char *c;
    json_object_set_new(djs, "query",
                        json_string(c = strndup(
            (char *)((char *)entry + sizeof(DNSQueryEntry)),
            entry->len)));
    if (c) free(c);

    /* name */
    char record[16] = "";
    CreateTypeString(entry->type, record, sizeof(record));
    json_object_set_new(djs, "record", json_string(record));

    /* dns */
    json_object_set_new(js, "dns", djs);
    char *s = json_dumps(js, JSON_PRESERVE_ORDER|JSON_COMPACT|JSON_ENSURE_ASCII);
    MemBufferWriteString(aft->buffer, "%s", s);
    free(s);
    free(djs);
    free(js);

    aft->dns_cnt++;

    SCMutexLock(&hlog->file_ctx->fp_mutex);
#ifdef HAVE_LIBJANSSON
    if (hlog->flags & LOG_DNS_JSON_SYSLOG) {
        syslog(dns_syslog_level, "%s", (char *)aft->buffer->buffer);
    } else {
            MemBufferWriteString(aft->buffer, "\n");
#endif
        (void)MemBufferPrintToFPAsString(aft->buffer, hlog->file_ctx->fp);
        fflush(hlog->file_ctx->fp);
#ifdef HAVE_LIBJANSSON
    }
#endif
    SCMutexUnlock(&hlog->file_ctx->fp_mutex);
}
#if 0
static void LogAnswer(LogDnsLogThread *aft, char *timebuf, char *srcip, char *dstip, Port sp, Port dp, DNSTransaction *tx, DNSAnswerEntry *entry) {
    LogDnsFileCtx *hlog = aft->dnslog_ctx;

    SCLogDebug("got a DNS response and now logging !!");

    /* reset */
    MemBufferReset(aft->buffer);

    json_t *js = json_object();
    if (js == NULL)
        return;

    json_t *djs = json_object();
    if (djs == NULL) {
        free(js);
        return;
    }

    /* time & tx */
    json_object_set_new(js, "time", json_string(timebuf));

    /* tuple */
    json_object_set_new(js, "srcip", json_string(srcip));
    json_object_set_new(js, "sp", json_integer(sp));
    json_object_set_new(js, "dstip", json_string(dstip));
    json_object_set_new(js, "dp", json_integer(dp));

    /* type */
    json_object_set_new(djs, "type", json_string("answer"));

    /* id */
    json_object_set_new(djs, "id", json_integer(tx->tx_id));

    if (entry != NULL) {
        /* query */
        if (entry->fqdn_len > 0) {
            char *c;
            json_object_set_new(djs, "query",
                            json_string(c = strndup(
                (char *)((char *)entry + sizeof(DNSAnswerEntry)),
                entry->fqdn_len)));
            if (c) free(c);
        }

        /* name */
        char record[16] = "";
        CreateTypeString(entry->type, record, sizeof(record));
        json_object_set_new(djs, "record", json_string(record));

        /* ttl */
        json_object_set_new(djs, "ttl", json_integer(entry->ttl));

        uint8_t *ptr = (uint8_t *)((uint8_t *)entry + sizeof(DNSAnswerEntry)+ entry->fqdn_len);
        if (entry->type == DNS_RECORD_TYPE_A) {
            char a[16] = "";
            PrintInet(AF_INET, (const void *)ptr, a, sizeof(a));
            json_object_set_new(djs, "addr", json_string(a));
        } else if (entry->type == DNS_RECORD_TYPE_AAAA) {
            char a[46] = "";
            PrintInet(AF_INET6, (const void *)ptr, a, sizeof(a));
            json_object_set_new(djs, "addr", json_string(a));
        } else if (entry->data_len == 0) {
            json_object_set_new(djs, "addr", json_string(""));
        }
    }

    /* dns */
    json_object_set_new(js, "dns", djs);
    char *s = json_dumps(js, JSON_PRESERVE_ORDER|JSON_COMPACT|JSON_ENSURE_ASCII);
    MemBufferWriteString(aft->buffer, "%s", s);
    free(s);
    free(djs);
    free(js);
    
    aft->dns_cnt++;

    SCMutexLock(&hlog->file_ctx->fp_mutex);
#ifdef HAVE_LIBJANSSON
    if (hlog->flags & LOG_DNS_JSON_SYSLOG) {
        syslog(dns_syslog_level, "%s", (char *)aft->buffer->buffer);
    } else {
            MemBufferWriteString(aft->buffer, "\n");
#endif
        (void)MemBufferPrintToFPAsString(aft->buffer, hlog->file_ctx->fp);
        fflush(hlog->file_ctx->fp);
#ifdef HAVE_LIBJANSSON
    }
#endif
    SCMutexUnlock(&hlog->file_ctx->fp_mutex);
}
#endif
static void AppendAnswer(json_t *djs, DNSTransaction *tx, DNSAnswerEntry *entry) {
    json_t *js = json_object();
    if (js == NULL)
        return;

    /* type */
    json_object_set_new(js, "type", json_string("answer"));

    /* id */
    json_object_set_new(js, "id", json_integer(tx->tx_id));

    if (entry != NULL) {
        /* query */
        if (entry->fqdn_len > 0) {
            char *c;
            json_object_set_new(js, "query",
                            json_string(c = strndup(
                (char *)((char *)entry + sizeof(DNSAnswerEntry)),
                entry->fqdn_len)));
            if (c) free(c);
        }

        /* name */
        char record[16] = "";
        CreateTypeString(entry->type, record, sizeof(record));
        json_object_set_new(js, "record", json_string(record));

        /* ttl */
        json_object_set_new(js, "ttl", json_integer(entry->ttl));

        uint8_t *ptr = (uint8_t *)((uint8_t *)entry + sizeof(DNSAnswerEntry)+ entry->fqdn_len);
        if (entry->type == DNS_RECORD_TYPE_A) {
            char a[16] = "";
            PrintInet(AF_INET, (const void *)ptr, a, sizeof(a));
            json_object_set_new(js, "addr", json_string(a));
        } else if (entry->type == DNS_RECORD_TYPE_AAAA) {
            char a[46] = "";
            PrintInet(AF_INET6, (const void *)ptr, a, sizeof(a));
            json_object_set_new(js, "addr", json_string(a));
        } else if (entry->data_len == 0) {
            json_object_set_new(js, "addr", json_string(""));
        }
    }
    json_array_append_new(djs, js);
}

static void LogAnswers(LogDnsLogThread *aft, char *timebuf, char *srcip, char *dstip, Port sp, Port dp, DNSTransaction *tx) {
    LogDnsFileCtx *hlog = aft->dnslog_ctx;

    SCLogDebug("got a DNS response and now logging !!");

    /* reset */
    MemBufferReset(aft->buffer);

    json_t *js = json_object();
    if (js == NULL)
        return;

    json_t *djs = json_array();
    if (djs == NULL) {
        free(js);
        return;
    }

    /* time & tx */
    json_object_set_new(js, "time", json_string(timebuf));

    /* tuple */
    json_object_set_new(js, "srcip", json_string(srcip));
    json_object_set_new(js, "sp", json_integer(sp));
    json_object_set_new(js, "dstip", json_string(dstip));
    json_object_set_new(js, "dp", json_integer(dp));

#if 1
    if (tx->no_such_name) {
        AppendAnswer(djs, tx, NULL);
    }

    DNSAnswerEntry *entry = NULL;
    TAILQ_FOREACH(entry, &tx->answer_list, next) {
        AppendAnswer(djs, tx, entry);
    }

    entry = NULL;
    TAILQ_FOREACH(entry, &tx->authority_list, next) {
        AppendAnswer(djs, tx, entry);
    }
#else
    /* type */
    json_object_set_new(djs, "type", json_string("answer"));

    /* id */
    json_object_set_new(djs, "id", json_integer(tx->tx_id));

    if (entry != NULL) {
        /* query */
        if (entry->fqdn_len > 0) {
            char *c;
            json_object_set_new(djs, "query",
                            json_string(c = strndup(
                (char *)((char *)entry + sizeof(DNSAnswerEntry)),
                entry->fqdn_len)));
            if (c) free(c);
        }

        /* name */
        char record[16] = "";
        CreateTypeString(entry->type, record, sizeof(record));
        json_object_set_new(djs, "record", json_string(record));

        /* ttl */
        json_object_set_new(djs, "ttl", json_integer(entry->ttl));

        uint8_t *ptr = (uint8_t *)((uint8_t *)entry + sizeof(DNSAnswerEntry)+ entry->fqdn_len);
        if (entry->type == DNS_RECORD_TYPE_A) {
            char a[16] = "";
            PrintInet(AF_INET, (const void *)ptr, a, sizeof(a));
            json_object_set_new(djs, "addr", json_string(a));
        } else if (entry->type == DNS_RECORD_TYPE_AAAA) {
            char a[46] = "";
            PrintInet(AF_INET6, (const void *)ptr, a, sizeof(a));
            json_object_set_new(djs, "addr", json_string(a));
        } else if (entry->data_len == 0) {
            json_object_set_new(djs, "addr", json_string(""));
        }
    }
#endif

    /* dns */
    json_object_set_new(js, "dns", djs);
    char *s = json_dumps(js, JSON_PRESERVE_ORDER|JSON_COMPACT|JSON_ENSURE_ASCII);
    MemBufferWriteString(aft->buffer, "%s", s);
    free(s);
    free(djs);
    free(js);
    
    aft->dns_cnt++;

    SCMutexLock(&hlog->file_ctx->fp_mutex);
#ifdef HAVE_LIBJANSSON
    if (hlog->flags & LOG_DNS_JSON_SYSLOG) {
        syslog(dns_syslog_level, "%s", (char *)aft->buffer->buffer);
    } else {
            MemBufferWriteString(aft->buffer, "\n");
#endif
        (void)MemBufferPrintToFPAsString(aft->buffer, hlog->file_ctx->fp);
        fflush(hlog->file_ctx->fp);
#ifdef HAVE_LIBJANSSON
    }
#endif
    SCMutexUnlock(&hlog->file_ctx->fp_mutex);
}

static TmEcode DnsJsonIPWrapper(ThreadVars *tv, Packet *p, void *data, PacketQueue *pq,
                            PacketQueue *postpq, int ipproto)
{
    SCEnter();

    LogDnsLogThread *aft = (LogDnsLogThread *)data;
    char timebuf[64];

    /* no flow, no htp state */
    if (p->flow == NULL) {
        SCLogDebug("no flow");
        SCReturnInt(TM_ECODE_OK);
    }

    /* check if we have DNS state or not */
    FLOWLOCK_WRLOCK(p->flow); /* WRITE lock before we updated flow logged id */
    uint16_t proto = AppLayerGetProtoFromPacket(p);
    if (proto != ALPROTO_DNS_UDP && proto != ALPROTO_DNS_TCP) {
        SCLogDebug("proto not ALPROTO_DNS_UDP: %u", proto);
        goto end;
    }

    DNSState *dns_state = (DNSState *)AppLayerGetProtoStateFromPacket(p);
    if (dns_state == NULL) {
        SCLogDebug("no dns state, so no request logging");
        goto end;
    }

    uint64_t total_txs = AppLayerGetTxCnt(proto, dns_state);
    uint64_t tx_id = AppLayerTransactionGetLogId(p->flow);
    //int tx_progress_done_value_ts = AppLayerGetAlstateProgressCompletionStatus(proto, 0);
    //int tx_progress_done_value_tc = AppLayerGetAlstateProgressCompletionStatus(proto, 1);

    SCLogDebug("pcap_cnt %"PRIu64, p->pcap_cnt);
    CreateTimeString(&p->ts, timebuf, sizeof(timebuf));

    char srcip[46], dstip[46];
    Port sp, dp;
    if ((PKT_IS_TOCLIENT(p))) {
        switch (ipproto) {
            case AF_INET:
                PrintInet(AF_INET, (const void *)GET_IPV4_SRC_ADDR_PTR(p), srcip, sizeof(srcip));
                PrintInet(AF_INET, (const void *)GET_IPV4_DST_ADDR_PTR(p), dstip, sizeof(dstip));
                break;
            case AF_INET6:
                PrintInet(AF_INET6, (const void *)GET_IPV6_SRC_ADDR(p), srcip, sizeof(srcip));
                PrintInet(AF_INET6, (const void *)GET_IPV6_DST_ADDR(p), dstip, sizeof(dstip));
                break;
            default:
                goto end;
        }
        sp = p->sp;
        dp = p->dp;
    } else {
        switch (ipproto) {
            case AF_INET:
                PrintInet(AF_INET, (const void *)GET_IPV4_DST_ADDR_PTR(p), srcip, sizeof(srcip));
                PrintInet(AF_INET, (const void *)GET_IPV4_SRC_ADDR_PTR(p), dstip, sizeof(dstip));
                break;
            case AF_INET6:
                PrintInet(AF_INET6, (const void *)GET_IPV6_DST_ADDR(p), srcip, sizeof(srcip));
                PrintInet(AF_INET6, (const void *)GET_IPV6_SRC_ADDR(p), dstip, sizeof(dstip));
                break;
            default:
                goto end;
        }
        sp = p->dp;
        dp = p->sp;
    }
#if QUERY
    if (PKT_IS_TOSERVER(p)) {
        DNSTransaction *tx = NULL;
        TAILQ_FOREACH(tx, &dns_state->tx_list, next) {
            DNSQueryEntry *entry = NULL;
            TAILQ_FOREACH(entry, &tx->query_list, next) {
                LogQuery(aft, timebuf, srcip, dstip, sp, dp, tx, entry);
            }
        }
    } else
#endif
    if ((PKT_IS_TOCLIENT(p))) {
        DNSTransaction *tx = NULL;
        for (; tx_id < total_txs; tx_id++)
        {
            tx = AppLayerGetTx(proto, dns_state, tx_id);
            if (tx == NULL)
                continue;

            DNSQueryEntry *query = NULL;
            TAILQ_FOREACH(query, &tx->query_list, next) {
                LogQuery(aft, timebuf, dstip, srcip, dp, sp, tx, query);
            }

#if 1
            LogAnswers(aft, timebuf, srcip, dstip, sp, dp, tx);
#else
            if (tx->no_such_name) {
                LogAnswer(aft, timebuf, srcip, dstip, sp, dp, tx, NULL);
            }

            DNSAnswerEntry *entry = NULL;
            TAILQ_FOREACH(entry, &tx->answer_list, next) {
                LogAnswer(aft, timebuf, srcip, dstip, sp, dp, tx, entry);
            }

            entry = NULL;
            TAILQ_FOREACH(entry, &tx->authority_list, next) {
                LogAnswer(aft, timebuf, srcip, dstip, sp, dp, tx, entry);
            }
#endif

            SCLogDebug("calling AppLayerTransactionUpdateLoggedId");
            AppLayerTransactionUpdateLogId(ALPROTO_DNS_UDP, p->flow);
        }
    }

end:
    FLOWLOCK_UNLOCK(p->flow);
    SCReturnInt(TM_ECODE_OK);
}

TmEcode DnsJsonIPv4(ThreadVars *tv, Packet *p, void *data, PacketQueue *pq, PacketQueue *postpq)
{
    return DnsJsonIPWrapper(tv, p, data, pq, postpq, AF_INET);
}

TmEcode DnsJsonIPv6(ThreadVars *tv, Packet *p, void *data, PacketQueue *pq, PacketQueue *postpq)
{
    return DnsJsonIPWrapper(tv, p, data, pq, postpq, AF_INET6);
}

TmEcode DnsJson (ThreadVars *tv, Packet *p, void *data, PacketQueue *pq, PacketQueue *postpq)
{
    SCEnter();

    SCLogDebug("pcap_cnt %"PRIu64, p->pcap_cnt);
    /* no flow, no htp state */
    if (p->flow == NULL) {
        SCReturnInt(TM_ECODE_OK);
    }

    if (!(PKT_IS_UDP(p)) && !(PKT_IS_TCP(p))) {
        SCReturnInt(TM_ECODE_OK);
    }

    if (PKT_IS_IPV4(p)) {
        int r  = DnsJsonIPv4(tv, p, data, pq, postpq);
        SCReturnInt(r);
    } else if (PKT_IS_IPV6(p)) {
        int r  = DnsJsonIPv6(tv, p, data, pq, postpq);
        SCReturnInt(r);
    }

    SCReturnInt(TM_ECODE_OK);
}

TmEcode DnsJsonThreadInit(ThreadVars *t, void *initdata, void **data)
{
    LogDnsLogThread *aft = SCMalloc(sizeof(LogDnsLogThread));
    if (unlikely(aft == NULL))
        return TM_ECODE_FAILED;
    memset(aft, 0, sizeof(LogDnsLogThread));

    if(initdata == NULL)
    {
        SCLogDebug("Error getting context for DNSLog.  \"initdata\" argument NULL");
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

TmEcode DnsJsonThreadDeinit(ThreadVars *t, void *data)
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

void DnsJsonExitPrintStats(ThreadVars *tv, void *data) {
    LogDnsLogThread *aft = (LogDnsLogThread *)data;
    if (aft == NULL) {
        return;
    }

    SCLogInfo("DNS logger logged %" PRIu32 " requests", aft->dns_cnt);
}

/** \brief Create a new dns log LogFileCtx.
 *  \param conf Pointer to ConfNode containing this loggers configuration.
 *  \return NULL if failure, LogFileCtx* to the file_ctx if succesful
 * */
OutputCtx *DnsJsonInitCtx(ConfNode *conf)
{
    LogFileCtx* file_ctx = LogFileNewCtx();

    if(file_ctx == NULL) {
        SCLogError(SC_ERR_DNS_LOG_GENERIC, "couldn't create new file_ctx");
        return NULL;
    }

    if (SCConfLogOpenGeneric(conf, file_ctx, DEFAULT_LOG_FILENAME) < 0) {
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

#ifdef HAVE_LIBJANSSON
    const char *json = ConfNodeLookupChildValue(conf, "json");
    if (json) {
        if (strcmp(json, "syslog") == 0) {
            dnslog_ctx->flags |= LOG_DNS_JSON_SYSLOG;
        }
    }
#endif

    OutputCtx *output_ctx = SCCalloc(1, sizeof(OutputCtx));
    if (unlikely(output_ctx == NULL)) {
        LogFileFreeCtx(file_ctx);
        SCFree(dnslog_ctx);
        return NULL;
    }

    output_ctx->data = dnslog_ctx;
    output_ctx->DeInit = DnsJsonDeInitCtx;

    SCLogDebug("DNS json output initialized");

    return output_ctx;
}

static void DnsJsonDeInitCtx(OutputCtx *output_ctx)
{
    LogDnsFileCtx *dnslog_ctx = (LogDnsFileCtx *)output_ctx->data;
    LogFileFreeCtx(dnslog_ctx->file_ctx);
    SCFree(dnslog_ctx);
    SCFree(output_ctx);
}
