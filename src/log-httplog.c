/* Copyright (C) 2007-2011 Open Information Security Foundation
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
 * \author Ignacio Sanchez <sanchezmartin.ji@gmail.com>
 *
 * Implements http logging portion of the engine.
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
#include "log-httplog.h"
#include "app-layer-htp.h"
#include "app-layer.h"
#include "util-privs.h"
#include "util-buffer.h"

#include "util-logopenfile.h"

#define DEFAULT_LOG_FILENAME "http.log"

#define MODULE_NAME "LogHttpLog"

#define OUTPUT_BUFFER_SIZE 65535

TmEcode LogHttpLog (ThreadVars *, Packet *, void *, PacketQueue *, PacketQueue *);
TmEcode LogHttpLogIPv4(ThreadVars *, Packet *, void *, PacketQueue *, PacketQueue *);
TmEcode LogHttpLogIPv6(ThreadVars *, Packet *, void *, PacketQueue *, PacketQueue *);
TmEcode LogHttpLogThreadInit(ThreadVars *, void *, void **);
TmEcode LogHttpLogThreadDeinit(ThreadVars *, void *);
void LogHttpLogExitPrintStats(ThreadVars *, void *);
static void LogHttpLogDeInitCtx(OutputCtx *);

void TmModuleLogHttpLogRegister (void) {
    tmm_modules[TMM_LOGHTTPLOG].name = MODULE_NAME;
    tmm_modules[TMM_LOGHTTPLOG].ThreadInit = LogHttpLogThreadInit;
    tmm_modules[TMM_LOGHTTPLOG].Func = LogHttpLog;
    tmm_modules[TMM_LOGHTTPLOG].ThreadExitPrintStats = LogHttpLogExitPrintStats;
    tmm_modules[TMM_LOGHTTPLOG].ThreadDeinit = LogHttpLogThreadDeinit;
    tmm_modules[TMM_LOGHTTPLOG].RegisterTests = NULL;
    tmm_modules[TMM_LOGHTTPLOG].cap_flags = 0;

    OutputRegisterModule(MODULE_NAME, "http-log", LogHttpLogInitCtx);

    /* enable the logger for the app layer */
    AppLayerRegisterLogger(ALPROTO_HTTP);
}

void TmModuleLogHttpLogIPv4Register (void) {
    tmm_modules[TMM_LOGHTTPLOG4].name = "LogHttpLogIPv4";
    tmm_modules[TMM_LOGHTTPLOG4].ThreadInit = LogHttpLogThreadInit;
    tmm_modules[TMM_LOGHTTPLOG4].Func = LogHttpLogIPv4;
    tmm_modules[TMM_LOGHTTPLOG4].ThreadExitPrintStats = LogHttpLogExitPrintStats;
    tmm_modules[TMM_LOGHTTPLOG4].ThreadDeinit = LogHttpLogThreadDeinit;
    tmm_modules[TMM_LOGHTTPLOG4].RegisterTests = NULL;
}

void TmModuleLogHttpLogIPv6Register (void) {
    tmm_modules[TMM_LOGHTTPLOG6].name = "LogHttpLogIPv6";
    tmm_modules[TMM_LOGHTTPLOG6].ThreadInit = LogHttpLogThreadInit;
    tmm_modules[TMM_LOGHTTPLOG6].Func = LogHttpLogIPv6;
    tmm_modules[TMM_LOGHTTPLOG6].ThreadExitPrintStats = LogHttpLogExitPrintStats;
    tmm_modules[TMM_LOGHTTPLOG6].ThreadDeinit = LogHttpLogThreadDeinit;
    tmm_modules[TMM_LOGHTTPLOG6].RegisterTests = NULL;
}

#define LOG_HTTP_MAXN_NODES 64
#define LOG_HTTP_NODE_STRLEN 256

#define TIMESTAMP_DEFAULT_FORMAT "%b %d, %Y; %H:%M:%S"
#define LOG_HTTP_CF_NONE "-"
#define LOG_HTTP_CF_LITERAL '%'
#define LOG_HTTP_CF_REQUEST_HOST 'h'
#define LOG_HTTP_CF_REQUEST_PROTOCOL 'H'
#define LOG_HTTP_CF_REQUEST_METHOD 'm'
#define LOG_HTTP_CF_REQUEST_URI 'u'
#define LOG_HTTP_CF_REQUEST_TIME 't'
#define LOG_HTTP_CF_REQUEST_HEADER 'i'
#define LOG_HTTP_CF_REQUEST_COOKIE 'C'
#define LOG_HTTP_CF_RESPONSE_STATUS 's'
#define LOG_HTTP_CF_RESPONSE_HEADER 'o'
#define LOG_HTTP_CF_RESPONSE_LEN 'B'
#define LOG_HTTP_CF_TIMESTAMP 't'
#define LOG_HTTP_CF_TIMESTAMP_U 'z'
#define LOG_HTTP_CF_CLIENT_IP 'a'
#define LOG_HTTP_CF_SERVER_IP 'A'
#define LOG_HTTP_CF_CLIENT_PORT 'p'
#define LOG_HTTP_CF_SERVER_PORT 'P'

typedef struct LogHttpCustomFormatNode_ {
    uint32_t type; /** Node format type. ie: LOG_HTTP_CF_LITERAL, LOG_HTTP_CF_REQUEST_HEADER */
    char data[LOG_HTTP_NODE_STRLEN]; /** optional data. ie: http header name */
} LogHttpCustomFormatNode;

typedef struct LogHttpFileCtx_ {
    LogFileCtx *file_ctx;
    uint32_t flags; /** Store mode */
    uint32_t cf_n; /** Total number of custom string format nodes */
    LogHttpCustomFormatNode *cf_nodes[LOG_HTTP_MAXN_NODES]; /** Custom format string nodes */
} LogHttpFileCtx;

#define LOG_HTTP_DEFAULT 0
#define LOG_HTTP_EXTENDED 1
#define LOG_HTTP_CUSTOM 2

typedef struct LogHttpLogThread_ {
    LogHttpFileCtx *httplog_ctx;
    /** LogFileCtx has the pointer to the file and a mutex to allow multithreading */
    uint32_t uri_cnt;

    MemBuffer *buffer;
} LogHttpLogThread;

static void CreateTimeString (const struct timeval *ts, char *str, size_t size)
{
    time_t time = ts->tv_sec;
    struct tm local_tm;
    struct tm *t = (struct tm *)SCLocalTime(time, &local_tm);

    snprintf(str, size, "%02d/%02d/%02d-%02d:%02d:%02d.%06u",
        t->tm_mon + 1, t->tm_mday, t->tm_year + 1900, t->tm_hour,
            t->tm_min, t->tm_sec, (uint32_t) ts->tv_usec);
}

/* Custom format logging */
static void LogHttpLogCustom(LogHttpLogThread *aft, htp_tx_t *tx, const struct timeval *ts,
                                            char *srcip, Port sp, char *dstip, Port dp)
{
    LogHttpFileCtx *httplog_ctx = aft->httplog_ctx;
    uint32_t i;
    char buf[128];

    htp_header_t *h_request_hdr = NULL;
    htp_header_t *h_response_hdr = NULL;

    time_t time = ts->tv_sec;
    struct tm local_tm;
    struct tm *timestamp = (struct tm *)SCLocalTime(time, &local_tm);

    for (i = 0; i < httplog_ctx->cf_n; i++) {
        switch (httplog_ctx->cf_nodes[i]->type){
            case LOG_HTTP_CF_LITERAL:
            /* LITERAL */
                PrintRawUriBuf((char *)aft->buffer->buffer, &aft->buffer->offset,
                        aft->buffer->size, (uint8_t *)httplog_ctx->cf_nodes[i]->data,
                        strlen(httplog_ctx->cf_nodes[i]->data));
                break;
            case LOG_HTTP_CF_TIMESTAMP:
            /* TIMESTAMP */
                if (httplog_ctx->cf_nodes[i]->data[0] == '\0') {
                    strftime(buf, 62, TIMESTAMP_DEFAULT_FORMAT, timestamp);
                } else {
                    strftime(buf, 62, httplog_ctx->cf_nodes[i]->data, timestamp);
                }
                PrintRawUriBuf((char *)aft->buffer->buffer, &aft->buffer->offset,
                            aft->buffer->size, (uint8_t *)buf,strlen(buf));
                break;
            case LOG_HTTP_CF_TIMESTAMP_U:
            /* TIMESTAMP USECONDS */
                snprintf(buf, 62, "%06u", (unsigned int) ts->tv_usec);
                PrintRawUriBuf((char *)aft->buffer->buffer, &aft->buffer->offset,
                            aft->buffer->size, (uint8_t *)buf,strlen(buf));
                break;
            case LOG_HTTP_CF_CLIENT_IP:
            /* CLIENT IP ADDRESS */
                PrintRawUriBuf((char *)aft->buffer->buffer, &aft->buffer->offset,
                            aft->buffer->size, (uint8_t *)srcip,strlen(srcip));
                break;
            case LOG_HTTP_CF_SERVER_IP:
            /* SERVER IP ADDRESS */
                PrintRawUriBuf((char *)aft->buffer->buffer, &aft->buffer->offset,
                            aft->buffer->size, (uint8_t *)dstip,strlen(dstip));
                break;
            case LOG_HTTP_CF_CLIENT_PORT:
            /* CLIENT PORT */
                MemBufferWriteString(aft->buffer, "%" PRIu16 "", sp);
                break;
            case LOG_HTTP_CF_SERVER_PORT:
            /* SERVER PORT */
                MemBufferWriteString(aft->buffer, "%" PRIu16 "", dp);
                break;
            case LOG_HTTP_CF_REQUEST_METHOD:
            /* METHOD */
                if (tx->request_method != NULL) {
                    PrintRawUriBuf((char *)aft->buffer->buffer, &aft->buffer->offset,
                                aft->buffer->size, (uint8_t *)bstr_ptr(tx->request_method),
                                bstr_len(tx->request_method));
                } else {
                    MemBufferWriteString(aft->buffer, LOG_HTTP_CF_NONE);
                }
                break;
            case LOG_HTTP_CF_REQUEST_URI:
            /* URI */
                if (tx->request_uri != NULL) {
                    PrintRawUriBuf((char *)aft->buffer->buffer, &aft->buffer->offset,
                                aft->buffer->size, (uint8_t *)bstr_ptr(tx->request_uri),
                                bstr_len(tx->request_uri));
                } else {
                    MemBufferWriteString(aft->buffer, LOG_HTTP_CF_NONE);
                }
                break;
            case LOG_HTTP_CF_REQUEST_HOST:
            /* HOSTNAME */
                if (tx->parsed_uri != NULL && tx->parsed_uri->hostname != NULL)
                {
                    PrintRawUriBuf((char *)aft->buffer->buffer, &aft->buffer->offset,
                                aft->buffer->size, (uint8_t *)bstr_ptr(tx->parsed_uri->hostname),
                                bstr_len(tx->parsed_uri->hostname));
                } else {
                    MemBufferWriteString(aft->buffer, LOG_HTTP_CF_NONE);
                }
                break;
            case LOG_HTTP_CF_REQUEST_PROTOCOL:
            /* PROTOCOL */
                if (tx->request_protocol != NULL) {
                    PrintRawUriBuf((char *)aft->buffer->buffer, &aft->buffer->offset,
                                    aft->buffer->size, (uint8_t *)bstr_ptr(tx->request_protocol),
                                    bstr_len(tx->request_protocol));
                } else {
                    MemBufferWriteString(aft->buffer, LOG_HTTP_CF_NONE);
                }
                break;
            case LOG_HTTP_CF_REQUEST_HEADER:
            /* REQUEST HEADER */
                if (tx->request_headers != NULL) {
                    h_request_hdr = table_getc(tx->request_headers, httplog_ctx->cf_nodes[i]->data);
                }
                if (h_request_hdr != NULL) {
                    PrintRawUriBuf((char *)aft->buffer->buffer, &aft->buffer->offset,
                                    aft->buffer->size, (uint8_t *)bstr_ptr(h_request_hdr->value),
                                    bstr_len(h_request_hdr->value));
                } else {
                    MemBufferWriteString(aft->buffer, LOG_HTTP_CF_NONE);
                }
                break;
            case LOG_HTTP_CF_RESPONSE_STATUS:
            /* RESPONSE STATUS */
                if (tx->response_status != NULL) {
                    PrintRawUriBuf((char *)aft->buffer->buffer, &aft->buffer->offset,
                                    aft->buffer->size, (uint8_t *)bstr_ptr(tx->response_status),
                                    bstr_len(tx->response_status));
                    /* Redirect? */
                    if (tx->response_headers != NULL &&
                            tx->response_status_number > 300 &&
                            tx->response_status_number < 303)
                    {
                        htp_header_t *h_location = table_getc(tx->response_headers, "location");
                        if (h_location != NULL) {
                            MemBufferWriteString(aft->buffer, "(");

                            PrintRawUriBuf((char *)aft->buffer->buffer, &aft->buffer->offset,
                                        aft->buffer->size, (uint8_t *)bstr_ptr(h_location->value),
                                        bstr_len(h_location->value));
                            MemBufferWriteString(aft->buffer, ")");
                        }
                    }
                } else {
                    MemBufferWriteString(aft->buffer, LOG_HTTP_CF_NONE);
                }
                break;
            case LOG_HTTP_CF_RESPONSE_HEADER:
            /* RESPONSE HEADER */
                if (tx->response_headers != NULL) {
                    h_response_hdr = table_getc(tx->response_headers,
                                    httplog_ctx->cf_nodes[i]->data);
                }
                if (h_response_hdr != NULL) {
                    PrintRawUriBuf((char *)aft->buffer->buffer, &aft->buffer->offset,
                                    aft->buffer->size, (uint8_t *)bstr_ptr(h_response_hdr->value),
                                    bstr_len(h_response_hdr->value));
                } else {
                    MemBufferWriteString(aft->buffer, LOG_HTTP_CF_NONE);
                }
                break;
            case LOG_HTTP_CF_RESPONSE_LEN:
            /* RESPONSE LEN */
                MemBufferWriteString(aft->buffer, "%"PRIuMAX"", (uintmax_t)tx->response_message_len);
                break;
        }
    }
    MemBufferWriteString(aft->buffer, "\n");
}

static void LogHttpLogExtended(LogHttpLogThread *aft, htp_tx_t *tx)
{
    MemBufferWriteString(aft->buffer, " [**] ");

    /* referer */
    htp_header_t *h_referer = NULL;
    if (tx->request_headers != NULL) {
        h_referer = table_getc(tx->request_headers, "referer");
    }
    if (h_referer != NULL) {
        PrintRawUriBuf((char *)aft->buffer->buffer, &aft->buffer->offset, aft->buffer->size,
                       (uint8_t *)bstr_ptr(h_referer->value),
                       bstr_len(h_referer->value));
    } else {
        MemBufferWriteString(aft->buffer, "<no referer>");
    }
    MemBufferWriteString(aft->buffer, " [**] ");

    /* method */
    if (tx->request_method != NULL) {
        PrintRawUriBuf((char *)aft->buffer->buffer, &aft->buffer->offset, aft->buffer->size,
                       (uint8_t *)bstr_ptr(tx->request_method),
                       bstr_len(tx->request_method));
    }
    MemBufferWriteString(aft->buffer, " [**] ");

    /* protocol */
    if (tx->request_protocol != NULL) {
        PrintRawUriBuf((char *)aft->buffer->buffer, &aft->buffer->offset, aft->buffer->size,
                       (uint8_t *)bstr_ptr(tx->request_protocol),
                       bstr_len(tx->request_protocol));
    } else {
        MemBufferWriteString(aft->buffer, "<no protocol>");
    }
    MemBufferWriteString(aft->buffer, " [**] ");

    /* response status */
    if (tx->response_status != NULL) {
        PrintRawUriBuf((char *)aft->buffer->buffer, &aft->buffer->offset, aft->buffer->size,
                       (uint8_t *)bstr_ptr(tx->response_status),
                       bstr_len(tx->response_status));
        /* Redirect? */
        if ((tx->response_status_number > 300) && ((tx->response_status_number) < 303)) {
            htp_header_t *h_location = table_getc(tx->response_headers, "location");
            if (h_location != NULL) {
                MemBufferWriteString(aft->buffer, " => ");

                PrintRawUriBuf((char *)aft->buffer->buffer, &aft->buffer->offset, aft->buffer->size,
                               (uint8_t *)bstr_ptr(h_location->value),
                               bstr_len(h_location->value));
            }
        }
    } else {
        MemBufferWriteString(aft->buffer, "<no status>");
    }

    /* length */
    MemBufferWriteString(aft->buffer, " [**] %"PRIuMAX" bytes", (uintmax_t)tx->response_message_len);
}

static TmEcode LogHttpLogIPWrapper(ThreadVars *tv, Packet *p, void *data, PacketQueue *pq,
                            PacketQueue *postpq, int ipproto)
{
    SCEnter();

    LogHttpLogThread *aft = (LogHttpLogThread *)data;
    LogHttpFileCtx *hlog = aft->httplog_ctx;
    char timebuf[64];
    size_t idx = 0;

    /* no flow, no htp state */
    if (p->flow == NULL) {
        SCReturnInt(TM_ECODE_OK);
    }

    /* check if we have HTTP state or not */
    FLOWLOCK_WRLOCK(p->flow); /* WRITE lock before we updated flow logged id */
    uint16_t proto = AppLayerGetProtoFromPacket(p);
    if (proto != ALPROTO_HTTP)
        goto end;

    int r = AppLayerTransactionGetLoggedId(p->flow);
    if (r < 0) {
        goto end;
    }
    size_t logged = (size_t)r;

    r = HtpTransactionGetLoggableId(p->flow);
    if (r < 0) {
        goto end;
    }
    size_t loggable = (size_t)r;

    /* nothing to do */
    if (logged >= loggable) {
        goto end;
    }

    HtpState *htp_state = (HtpState *)AppLayerGetProtoStateFromPacket(p);
    if (htp_state == NULL) {
        SCLogDebug("no http state, so no request logging");
        goto end;
    }

    if (htp_state->connp == NULL || htp_state->connp->conn == NULL)
        goto end;

    htp_tx_t *tx = NULL;

    CreateTimeString(&p->ts, timebuf, sizeof(timebuf));

    char srcip[46], dstip[46];
    Port sp, dp;
    if ((PKT_IS_TOSERVER(p))) {
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

    for (idx = logged; idx < loggable; idx++)
    {
        tx = list_get(htp_state->connp->conn->transactions, idx);
        if (tx == NULL) {
            SCLogDebug("tx is NULL not logging !!");
            continue;
        }

        SCLogDebug("got a HTTP request and now logging !!");

        /* reset */
        MemBufferReset(aft->buffer);

        if (hlog->flags & LOG_HTTP_CUSTOM) {
            LogHttpLogCustom(aft, tx, &p->ts, srcip, sp, dstip, dp);
        } else {
            /* time */
            MemBufferWriteString(aft->buffer, "%s ", timebuf);

            /* hostname */
            if (tx->parsed_uri != NULL &&
                    tx->parsed_uri->hostname != NULL)
            {
                PrintRawUriBuf((char *)aft->buffer->buffer, &aft->buffer->offset, aft->buffer->size,
                               (uint8_t *)bstr_ptr(tx->parsed_uri->hostname),
                               bstr_len(tx->parsed_uri->hostname));
            } else {
                MemBufferWriteString(aft->buffer, "<hostname unknown>");
            }
            MemBufferWriteString(aft->buffer, " [**] ");

            /* uri */
            if (tx->request_uri != NULL) {
                PrintRawUriBuf((char *)aft->buffer->buffer, &aft->buffer->offset, aft->buffer->size,
                               (uint8_t *)bstr_ptr(tx->request_uri),
                               bstr_len(tx->request_uri));
            }
            MemBufferWriteString(aft->buffer, " [**] ");

            /* user agent */
            htp_header_t *h_user_agent = NULL;
            if (tx->request_headers != NULL) {
                h_user_agent = table_getc(tx->request_headers, "user-agent");
            }
            if (h_user_agent != NULL) {
                PrintRawUriBuf((char *)aft->buffer->buffer, &aft->buffer->offset, aft->buffer->size,
                                (uint8_t *)bstr_ptr(h_user_agent->value),
                                bstr_len(h_user_agent->value));
            } else {
                MemBufferWriteString(aft->buffer, "<useragent unknown>");
            }
            if (hlog->flags & LOG_HTTP_EXTENDED) {
                LogHttpLogExtended(aft, tx);
            }

            /* ip/tcp header info */
            MemBufferWriteString(aft->buffer,
                                 " [**] %s:%" PRIu16 " -> %s:%" PRIu16 "\n",
                                 srcip, sp, dstip, dp);
        }

        aft->uri_cnt ++;

        SCMutexLock(&hlog->file_ctx->fp_mutex);
        (void)MemBufferPrintToFPAsString(aft->buffer, hlog->file_ctx->fp);
        fflush(hlog->file_ctx->fp);
        SCMutexUnlock(&hlog->file_ctx->fp_mutex);

        AppLayerTransactionUpdateLoggedId(p->flow);
    }

end:
    FLOWLOCK_UNLOCK(p->flow);
    SCReturnInt(TM_ECODE_OK);

}

TmEcode LogHttpLogIPv4(ThreadVars *tv, Packet *p, void *data, PacketQueue *pq, PacketQueue *postpq)
{
    return LogHttpLogIPWrapper(tv, p, data, pq, postpq, AF_INET);
}

TmEcode LogHttpLogIPv6(ThreadVars *tv, Packet *p, void *data, PacketQueue *pq, PacketQueue *postpq)
{
    return LogHttpLogIPWrapper(tv, p, data, pq, postpq, AF_INET6);
}

TmEcode LogHttpLog (ThreadVars *tv, Packet *p, void *data, PacketQueue *pq, PacketQueue *postpq)
{
    SCEnter();

    /* no flow, no htp state */
    if (p->flow == NULL) {
        SCReturnInt(TM_ECODE_OK);
    }

    if (!(PKT_IS_TCP(p))) {
        SCReturnInt(TM_ECODE_OK);
    }

    if (PKT_IS_IPV4(p)) {
        SCReturnInt(LogHttpLogIPv4(tv, p, data, pq, postpq));
    } else if (PKT_IS_IPV6(p)) {
        SCReturnInt(LogHttpLogIPv6(tv, p, data, pq, postpq));
    }

    SCReturnInt(TM_ECODE_OK);
}

TmEcode LogHttpLogThreadInit(ThreadVars *t, void *initdata, void **data)
{
    LogHttpLogThread *aft = SCMalloc(sizeof(LogHttpLogThread));
    if (unlikely(aft == NULL))
        return TM_ECODE_FAILED;
    memset(aft, 0, sizeof(LogHttpLogThread));

    if(initdata == NULL)
    {
        SCLogDebug("Error getting context for HTTPLog.  \"initdata\" argument NULL");
        SCFree(aft);
        return TM_ECODE_FAILED;
    }

    aft->buffer = MemBufferCreateNew(OUTPUT_BUFFER_SIZE);
    if (aft->buffer == NULL) {
        SCFree(aft);
        return TM_ECODE_FAILED;
    }

    /* Use the Ouptut Context (file pointer and mutex) */
    aft->httplog_ctx= ((OutputCtx *)initdata)->data;

    *data = (void *)aft;
    return TM_ECODE_OK;
}

TmEcode LogHttpLogThreadDeinit(ThreadVars *t, void *data)
{
    LogHttpLogThread *aft = (LogHttpLogThread *)data;
    if (aft == NULL) {
        return TM_ECODE_OK;
    }

    MemBufferFree(aft->buffer);
    /* clear memory */
    memset(aft, 0, sizeof(LogHttpLogThread));

    SCFree(aft);
    return TM_ECODE_OK;
}

void LogHttpLogExitPrintStats(ThreadVars *tv, void *data) {
    LogHttpLogThread *aft = (LogHttpLogThread *)data;
    if (aft == NULL) {
        return;
    }

    SCLogInfo("HTTP logger logged %" PRIu32 " requests", aft->uri_cnt);
}

/** \brief Create a new http log LogFileCtx.
 *  \param conf Pointer to ConfNode containing this loggers configuration.
 *  \return NULL if failure, LogFileCtx* to the file_ctx if succesful
 * */
OutputCtx *LogHttpLogInitCtx(ConfNode *conf)
{
    LogFileCtx* file_ctx = LogFileNewCtx();
    const char *p, *np;
    uint32_t n;
    if(file_ctx == NULL) {
        SCLogError(SC_ERR_HTTP_LOG_GENERIC, "couldn't create new file_ctx");
        return NULL;
    }

    if (SCConfLogOpenGeneric(conf, file_ctx, DEFAULT_LOG_FILENAME) < 0) {
        LogFileFreeCtx(file_ctx);
        return NULL;
    }

    LogHttpFileCtx *httplog_ctx = SCMalloc(sizeof(LogHttpFileCtx));
    if (unlikely(httplog_ctx == NULL)) {
        LogFileFreeCtx(file_ctx);
        return NULL;
    }
    memset(httplog_ctx, 0x00, sizeof(LogHttpFileCtx));

    httplog_ctx->file_ctx = file_ctx;
    httplog_ctx->cf_n=0;

    const char *extended = ConfNodeLookupChildValue(conf, "extended");
    const char *custom = ConfNodeLookupChildValue(conf, "custom");
    const char *customformat = ConfNodeLookupChildValue(conf, "customformat");

    /* If custom logging format is selected, lets parse it */
    if (custom != NULL && customformat != NULL && ConfValIsTrue(custom)) {
        p=customformat;
        httplog_ctx->flags |= LOG_HTTP_CUSTOM;
        for (httplog_ctx->cf_n = 0; httplog_ctx->cf_n < LOG_HTTP_MAXN_NODES-1 && p && *p != '\0';
                                                    httplog_ctx->cf_n++){
            httplog_ctx->cf_nodes[httplog_ctx->cf_n] = SCMalloc(sizeof(LogHttpCustomFormatNode));
            if (httplog_ctx->cf_nodes[httplog_ctx->cf_n] == NULL) {
                for (n = 0; n < httplog_ctx->cf_n; n++) {
                    SCFree(httplog_ctx->cf_nodes[n]);
                }
                LogFileFreeCtx(file_ctx);
                SCFree(httplog_ctx);
                return NULL;
            }
            if (*p != '%'){
                /* Literal found in format string */
                httplog_ctx->cf_nodes[httplog_ctx->cf_n]->type = LOG_HTTP_CF_LITERAL;
                np = strchr(p, '%');
                if (np == NULL){
                    n = LOG_HTTP_NODE_STRLEN-2;
                    np = NULL; /* End */
                }else{
                    n = np-p;
                }
                strlcpy(httplog_ctx->cf_nodes[httplog_ctx->cf_n]->data,p,n+1);
                p = np;
            } else {
                /* Non Literal found in format string */
                p++;
                if (*p == '{') { /* Simple format char */
                    np = strchr(p, '}');
                     if (np != NULL && np-p > 1 && np-p < LOG_HTTP_NODE_STRLEN-2) {
                        p++;
                        n = np-p;
                        strlcpy(httplog_ctx->cf_nodes[httplog_ctx->cf_n]->data, p, n+1);
                        p = np;
                    }
                    p++;
                } else {
                    httplog_ctx->cf_nodes[httplog_ctx->cf_n]->data[0] = '\0';
                }
                httplog_ctx->cf_nodes[httplog_ctx->cf_n]->type = *p;
                if (*p == '%'){
                    httplog_ctx->cf_nodes[httplog_ctx->cf_n]->type = LOG_HTTP_CF_LITERAL;
                    strlcpy(httplog_ctx->cf_nodes[httplog_ctx->cf_n]->data, "%", 2);
                }
                p++;
            }
        }
    } else {
        if (extended == NULL) {
            httplog_ctx->flags |= LOG_HTTP_DEFAULT;
        } else {
            if (ConfValIsTrue(extended)) {
                httplog_ctx->flags |= LOG_HTTP_EXTENDED;
            }
        }
    }

    OutputCtx *output_ctx = SCCalloc(1, sizeof(OutputCtx));
    if (unlikely(output_ctx == NULL)) {
        for (n = 0;n < httplog_ctx->cf_n;n++) {
            SCFree(httplog_ctx->cf_nodes[n]);
        }
        LogFileFreeCtx(file_ctx);
        SCFree(httplog_ctx);
        return NULL;
    }

    output_ctx->data = httplog_ctx;
    output_ctx->DeInit = LogHttpLogDeInitCtx;

    SCLogDebug("HTTP log output initialized");

    return output_ctx;
}

static void LogHttpLogDeInitCtx(OutputCtx *output_ctx)
{
    LogHttpFileCtx *httplog_ctx = (LogHttpFileCtx *)output_ctx->data;
    uint32_t i;
    for (i = 0; i < httplog_ctx->cf_n; i++) {
        SCFree(httplog_ctx->cf_nodes[i]);
    }
    LogFileFreeCtx(httplog_ctx->file_ctx);
    SCFree(httplog_ctx);
    SCFree(output_ctx);
}
