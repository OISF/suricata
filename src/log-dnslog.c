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
#include "log-dnslog.h"
#include "app-layer-dns-common.h"
#include "app-layer-dns-udp.h"
#include "app-layer.h"
#include "util-privs.h"
#include "util-buffer.h"

#include "util-logopenfile.h"
#include "util-time.h"

#define DEFAULT_LOG_FILENAME "dns.log"

#define MODULE_NAME "LogDnsLog"

#define OUTPUT_BUFFER_SIZE 65535

/* we can do query logging as well, but it's disabled for now as the
 * TX id handling doesn't expect it */
#define QUERY 0

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

static void LogQuery(LogDnsLogThread *aft, char *timebuf, char *srcip, char *dstip, Port sp, Port dp, DNSTransaction *tx, DNSQueryEntry *entry)
{
    LogDnsFileCtx *hlog = aft->dnslog_ctx;

    SCLogDebug("got a DNS request and now logging !!");

    /* reset */
    MemBufferReset(aft->buffer);

    /* time & tx */
    MemBufferWriteString(aft->buffer,
            "%s [**] Query TX %04x [**] ", timebuf, tx->tx_id);

    /* query */
    PrintRawUriBuf((char *)aft->buffer->buffer, &aft->buffer->offset, aft->buffer->size,
            (uint8_t *)((uint8_t *)entry + sizeof(DNSQueryEntry)),
            entry->len);

    char record[16] = "";
    DNSCreateTypeString(entry->type, record, sizeof(record));
    MemBufferWriteString(aft->buffer,
            " [**] %s [**] %s:%" PRIu16 " -> %s:%" PRIu16 "\n",
            record, srcip, sp, dstip, dp);

    SCMutexLock(&hlog->file_ctx->fp_mutex);
    hlog->file_ctx->Write((const char *)MEMBUFFER_BUFFER(aft->buffer),
        MEMBUFFER_OFFSET(aft->buffer), hlog->file_ctx);
    SCMutexUnlock(&hlog->file_ctx->fp_mutex);
}

static void LogAnswer(LogDnsLogThread *aft, char *timebuf, char *srcip, char *dstip, Port sp, Port dp, DNSTransaction *tx, DNSAnswerEntry *entry)
{
    LogDnsFileCtx *hlog = aft->dnslog_ctx;

    SCLogDebug("got a DNS response and now logging !!");

    /* reset */
    MemBufferReset(aft->buffer);
    /* time & tx*/
    MemBufferWriteString(aft->buffer,
            "%s [**] Response TX %04x [**] ", timebuf, tx->tx_id);

    if (entry == NULL) {
        if (tx->rcode) {
            char rcode[16] = "";
            DNSCreateRcodeString(tx->rcode, rcode, sizeof(rcode));
            MemBufferWriteString(aft->buffer, "%s", rcode);
        } else if (tx->recursion_desired) {
            MemBufferWriteString(aft->buffer, "Recursion Desired");
        }
    } else {
        /* query */
        if (entry->fqdn_len > 0) {
            PrintRawUriBuf((char *)aft->buffer->buffer, &aft->buffer->offset, aft->buffer->size,
                    (uint8_t *)((uint8_t *)entry + sizeof(DNSAnswerEntry)),
                    entry->fqdn_len);
        } else {
            MemBufferWriteString(aft->buffer, "<no data>");
        }

        char record[16] = "";
        DNSCreateTypeString(entry->type, record, sizeof(record));
        MemBufferWriteString(aft->buffer,
                " [**] %s [**] TTL %u [**] ", record, entry->ttl);

        uint8_t *ptr = (uint8_t *)((uint8_t *)entry + sizeof(DNSAnswerEntry) + entry->fqdn_len);
        if (entry->type == DNS_RECORD_TYPE_A) {
            char a[16] = "";
            PrintInet(AF_INET, (const void *)ptr, a, sizeof(a));
            MemBufferWriteString(aft->buffer, "%s", a);
        } else if (entry->type == DNS_RECORD_TYPE_AAAA) {
            char a[46];
            PrintInet(AF_INET6, (const void *)ptr, a, sizeof(a));
            MemBufferWriteString(aft->buffer, "%s", a);
        } else if (entry->data_len == 0) {
            MemBufferWriteString(aft->buffer, "<no data>");
        } else {
            PrintRawUriBuf((char *)aft->buffer->buffer, &aft->buffer->offset,
                    aft->buffer->size, ptr, entry->data_len);
        }
    }

    /* ip/tcp header info */
    MemBufferWriteString(aft->buffer,
            " [**] %s:%" PRIu16 " -> %s:%" PRIu16 "\n",
            srcip, sp, dstip, dp);

    SCMutexLock(&hlog->file_ctx->fp_mutex);
    hlog->file_ctx->Write((const char *)MEMBUFFER_BUFFER(aft->buffer),
        MEMBUFFER_OFFSET(aft->buffer), hlog->file_ctx);
    SCMutexUnlock(&hlog->file_ctx->fp_mutex);
}

static int LogDnsLogger(ThreadVars *tv, void *data, const Packet *p, Flow *f,
    void *state, void *tx, uint64_t tx_id)
{
    LogDnsLogThread *aft = (LogDnsLogThread *)data;
    DNSTransaction *dns_tx = (DNSTransaction *)tx;
    SCLogDebug("pcap_cnt %ju", p->pcap_cnt);
    char timebuf[64];
    CreateTimeString(&p->ts, timebuf, sizeof(timebuf));

    int ipproto = 0;
    if (PKT_IS_IPV4(p))
        ipproto = AF_INET;
    else if (PKT_IS_IPV6(p))
        ipproto = AF_INET6;

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

    DNSQueryEntry *query = NULL;
    TAILQ_FOREACH(query, &dns_tx->query_list, next) {
        LogQuery(aft, timebuf, dstip, srcip, dp, sp, dns_tx, query);
    }

    if (dns_tx->rcode)
        LogAnswer(aft, timebuf, srcip, dstip, sp, dp, dns_tx, NULL);
    if (dns_tx->recursion_desired)
        LogAnswer(aft, timebuf, srcip, dstip, sp, dp, dns_tx, NULL);

    DNSAnswerEntry *entry = NULL;
    TAILQ_FOREACH(entry, &dns_tx->answer_list, next) {
        LogAnswer(aft, timebuf, srcip, dstip, sp, dp, dns_tx, entry);
    }

    entry = NULL;
    TAILQ_FOREACH(entry, &dns_tx->authority_list, next) {
        LogAnswer(aft, timebuf, srcip, dstip, sp, dp, dns_tx, entry);
    }

    aft->dns_cnt++;
end:
    return 0;
}

static TmEcode LogDnsLogThreadInit(ThreadVars *t, void *initdata, void **data)
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

static void LogDnsLogExitPrintStats(ThreadVars *tv, void *data)
{
    LogDnsLogThread *aft = (LogDnsLogThread *)data;
    if (aft == NULL) {
        return;
    }

    SCLogInfo("DNS logger logged %" PRIu32 " transactions", aft->dns_cnt);
}

static void LogDnsLogDeInitCtx(OutputCtx *output_ctx)
{
    LogDnsFileCtx *dnslog_ctx = (LogDnsFileCtx *)output_ctx->data;
    LogFileFreeCtx(dnslog_ctx->file_ctx);
    SCFree(dnslog_ctx);
    SCFree(output_ctx);
}

/** \brief Create a new dns log LogFileCtx.
 *  \param conf Pointer to ConfNode containing this loggers configuration.
 *  \return NULL if failure, LogFileCtx* to the file_ctx if succesful
 * */
static OutputCtx *LogDnsLogInitCtx(ConfNode *conf)
{
    LogFileCtx* file_ctx = LogFileNewCtx();

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

void TmModuleLogDnsLogRegister (void)
{
    tmm_modules[TMM_LOGDNSLOG].name = MODULE_NAME;
    tmm_modules[TMM_LOGDNSLOG].ThreadInit = LogDnsLogThreadInit;
    tmm_modules[TMM_LOGDNSLOG].ThreadExitPrintStats = LogDnsLogExitPrintStats;
    tmm_modules[TMM_LOGDNSLOG].ThreadDeinit = LogDnsLogThreadDeinit;
    tmm_modules[TMM_LOGDNSLOG].RegisterTests = NULL;
    tmm_modules[TMM_LOGDNSLOG].cap_flags = 0;
    tmm_modules[TMM_LOGDNSLOG].flags = TM_FLAG_LOGAPI_TM;

    OutputRegisterTxModule(MODULE_NAME, "dns-log", LogDnsLogInitCtx,
            ALPROTO_DNS, LogDnsLogger);

    /* enable the logger for the app layer */
    SCLogDebug("registered %s", MODULE_NAME);
}
