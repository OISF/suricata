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
#include <jansson.h>

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

static void LogQuery(LogDnsLogThread *aft, json_t *js, DNSTransaction *tx,
        uint64_t tx_id, DNSQueryEntry *entry)
{
    MemBuffer *buffer = (MemBuffer *)aft->buffer;

    SCLogDebug("got a DNS request and now logging !!");

    json_t *djs = json_object();
    if (djs == NULL) {
        return;
    }

    /* reset */
    MemBufferReset(buffer);

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
    OutputJSONBuffer(js, aft->dnslog_ctx->file_ctx, buffer);
    json_object_del(js, "dns");
}

static void OutputAnswer(LogDnsLogThread *aft, json_t *djs, DNSTransaction *tx, DNSAnswerEntry *entry)
{
    MemBuffer *buffer = (MemBuffer *)aft->buffer;
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
                    entry->type == DNS_RECORD_TYPE_MX || entry->type == DNS_RECORD_TYPE_PTR) {
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
        }
    }

    /* reset */
    MemBufferReset(buffer);
    json_object_set_new(djs, "dns", js);
    OutputJSONBuffer(djs, aft->dnslog_ctx->file_ctx, buffer);
    json_object_del(djs, "dns");

    return;
}

static void OutputFailure(LogDnsLogThread *aft, json_t *djs, DNSTransaction *tx, DNSQueryEntry *entry)
{
    MemBuffer *buffer = (MemBuffer *)aft->buffer;
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
    MemBufferReset(buffer);
    json_object_set_new(djs, "dns", js);
    OutputJSONBuffer(djs, aft->dnslog_ctx->file_ctx, buffer);
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
    DNSTransaction *tx = txptr;
    json_t *js;

    DNSQueryEntry *query = NULL;
    TAILQ_FOREACH(query, &tx->query_list, next) {
        js = CreateJSONHeader((Packet *)p, 1, "dns");
        if (unlikely(js == NULL))
            return TM_ECODE_OK;

        LogQuery(td, js, tx, tx_id, query);

        json_decref(js);
    }

    js = CreateJSONHeader((Packet *)p, 0, "dns");
    if (unlikely(js == NULL))
        return TM_ECODE_OK;

    LogAnswers(td, js, tx, tx_id);

    json_decref(js);

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
