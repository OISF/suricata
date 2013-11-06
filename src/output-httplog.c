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
 * Implements HTTP JSON logging portion of the engine.
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
#include "output-httplog.h"
#include "app-layer-htp.h"
#include "app-layer.h"
#include "util-privs.h"
#include "util-buffer.h"
#include "util-proto-name.h"
#include "util-logopenfile.h"
#include "util-time.h"
#include "alert-json.h"

#ifdef HAVE_LIBJANSSON
#include <jansson.h>

#define LOG_HTTP_MAXN_NODES 64
#define LOG_HTTP_NODE_STRLEN 256
#define LOG_HTTP_NODE_MAXOUTPUTLEN 8192

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
#define LOG_HTTP_CF_REQUEST_LEN 'b'
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
    uint32_t maxlen; /** Maximun length of the data */
    char data[LOG_HTTP_NODE_STRLEN]; /** optional data. ie: http header name */
} LogHttpCustomFormatNode;

#if 1
typedef struct OutputHttpCtx_ {
    uint32_t flags; /** Store mode */
} OutputHttpCtx;
#else
typedef struct LogHttpFileCtx_ {
    LogFileCtx *file_ctx;
    uint32_t flags; /** Store mode */
    uint32_t cf_n; /** Total number of custom string format nodes */
    LogHttpCustomFormatNode *cf_nodes[LOG_HTTP_MAXN_NODES]; /** Custom format string nodes */
} LogHttpFileCtx;
#endif

#define LOG_HTTP_DEFAULT 0
#define LOG_HTTP_EXTENDED 1
#define LOG_HTTP_CUSTOM 2

#if 0
typedef struct LogHttpLogThread_ {
    LogHttpFileCtx *httplog_ctx;
    /** LogFileCtx has the pointer to the file and a mutex to allow multithreading */
    uint32_t uri_cnt;

    MemBuffer *buffer;
} LogHttpLogThread;
#endif

/* Retrieves the selected cookie value */
static uint32_t GetCookieValue(uint8_t *rawcookies, uint32_t rawcookies_len, char *cookiename,
                                                        uint8_t **cookievalue) {
    uint8_t *p = rawcookies;
    uint8_t *cn = p; /* ptr to cookie name start */
    uint8_t *cv = NULL; /* ptr to cookie value start */
    while (p < rawcookies + rawcookies_len) {
        if (cv == NULL && *p == '=') {
            cv = p + 1;
        } else if (cv != NULL && (*p == ';' || p == rawcookies + rawcookies_len - 1) ) {
            /* Found end of cookie */
            p++;
            if (strlen(cookiename) == (unsigned int) (cv-cn-1) &&
                        strncmp(cookiename, (char *) cn, cv-cn-1) == 0) {
                *cookievalue = cv;
                return (uint32_t) (p-cv);
            }
            cv = NULL;
            cn = p + 1;
        }
        p++;
    }
    return 0;
}

/* Custom format logging */
static void LogHttpLogJSONCustom(AlertJsonThread *aft, json_t *js, htp_tx_t *tx, const struct timeval *ts /*,
                                            char *srcip, Port sp, char *dstip, Port dp*/)
{
#if 0
    LogHttpFileCtx *httplog_ctx = aft->httplog_ctx;
#endif
#if 0
    uint32_t i;
    uint32_t datalen;
    char buf[128];

    uint8_t *cvalue;
    uint32_t cvalue_len = 0;

    htp_header_t *h_request_hdr;
    htp_header_t *h_response_hdr;

    time_t time = ts->tv_sec;
    struct tm local_tm;
    struct tm *timestamp = SCLocalTime(time, &local_tm);

    for (i = 0; i < httplog_ctx->cf_n; i++) {
        h_request_hdr = NULL;
        h_response_hdr = NULL;
        switch (httplog_ctx->cf_nodes[i]->type){
            case LOG_HTTP_CF_LITERAL:
            /* LITERAL */
                MemBufferWriteString(aft->buffer, "%s", httplog_ctx->cf_nodes[i]->data);
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
#ifdef NOTYET
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
#endif
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
                    datalen = httplog_ctx->cf_nodes[i]->maxlen;
                    if (datalen == 0 || datalen > bstr_len(tx->request_uri)) {
                        datalen = bstr_len(tx->request_uri);
                    }
                    PrintRawUriBuf((char *)aft->buffer->buffer, &aft->buffer->offset,
                                aft->buffer->size, (uint8_t *)bstr_ptr(tx->request_uri),
                                datalen);
                } else {
                    MemBufferWriteString(aft->buffer, LOG_HTTP_CF_NONE);
                }
                break;
            case LOG_HTTP_CF_REQUEST_HOST:
            /* HOSTNAME */
                if (tx->request_hostname != NULL)
                {
                    datalen = httplog_ctx->cf_nodes[i]->maxlen;
                    if (datalen == 0 || datalen > bstr_len(tx->parsed_uri->hostname)) {
                        datalen = bstr_len(tx->parsed_uri->hostname);
                    }
                    PrintRawUriBuf((char *)aft->buffer->buffer, &aft->buffer->offset,
                                aft->buffer->size, (uint8_t *)bstr_ptr(tx->request_hostname),
                                bstr_len(tx->request_hostname));
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
                    h_request_hdr = htp_table_get_c(tx->request_headers, httplog_ctx->cf_nodes[i]->data);
                }
                if (h_request_hdr != NULL) {
                    datalen = httplog_ctx->cf_nodes[i]->maxlen;
                    if (datalen == 0 || datalen > bstr_len(h_request_hdr->value)) {
                        datalen = bstr_len(h_request_hdr->value);
                    }
                    PrintRawUriBuf((char *)aft->buffer->buffer, &aft->buffer->offset,
                                    aft->buffer->size, (uint8_t *)bstr_ptr(h_request_hdr->value),
                                    datalen);
                } else {
                    MemBufferWriteString(aft->buffer, LOG_HTTP_CF_NONE);
                }
                break;
            case LOG_HTTP_CF_REQUEST_COOKIE:
            /* REQUEST COOKIE */
                if (tx->request_headers != NULL) {
                    h_request_hdr = htp_table_get_c(tx->request_headers, "Cookie");
                    if (h_request_hdr != NULL) {
                        cvalue_len = GetCookieValue((uint8_t *) bstr_ptr(h_request_hdr->value),
                                    bstr_len(h_request_hdr->value), (char *) httplog_ctx->cf_nodes[i]->data,
                                    &cvalue);
                    }
                }
                if (cvalue_len > 0) {
                    datalen = httplog_ctx->cf_nodes[i]->maxlen;
                    if (datalen == 0 || datalen > cvalue_len) {
                        datalen = cvalue_len;
                    }
                    PrintRawUriBuf((char *)aft->buffer->buffer, &aft->buffer->offset,
                                    aft->buffer->size, cvalue, datalen);
                } else {
                    MemBufferWriteString(aft->buffer, LOG_HTTP_CF_NONE);
                }
                break;
            case LOG_HTTP_CF_REQUEST_LEN:
            /* REQUEST LEN */
                MemBufferWriteString(aft->buffer, "%"PRIuMAX"", (uintmax_t)tx->request_message_len);
                break;
            case LOG_HTTP_CF_RESPONSE_STATUS:
            /* RESPONSE STATUS */
                if (tx->response_status != NULL) {
                    PrintRawUriBuf((char *)aft->buffer->buffer, &aft->buffer->offset,
                                    aft->buffer->size, (uint8_t *)bstr_ptr(tx->response_status),
                                    bstr_len(tx->response_status));
                } else {
                    MemBufferWriteString(aft->buffer, LOG_HTTP_CF_NONE);
                }
                break;
            case LOG_HTTP_CF_RESPONSE_HEADER:
            /* RESPONSE HEADER */
                if (tx->response_headers != NULL) {
                    h_response_hdr = htp_table_get_c(tx->response_headers,
                                    httplog_ctx->cf_nodes[i]->data);
                }
                if (h_response_hdr != NULL) {
                    datalen = httplog_ctx->cf_nodes[i]->maxlen;
                    if (datalen == 0 || datalen > bstr_len(h_response_hdr->value)) {
                        datalen = bstr_len(h_response_hdr->value);
                    }
                    PrintRawUriBuf((char *)aft->buffer->buffer, &aft->buffer->offset,
                                    aft->buffer->size, (uint8_t *)bstr_ptr(h_response_hdr->value),
                                    datalen);
                } else {
                    MemBufferWriteString(aft->buffer, LOG_HTTP_CF_NONE);
                }
                break;
            case LOG_HTTP_CF_RESPONSE_LEN:
            /* RESPONSE LEN */
                MemBufferWriteString(aft->buffer, "%"PRIuMAX"", (uintmax_t)tx->response_message_len);
                break;
            default:
            /* NO MATCH */
                MemBufferWriteString(aft->buffer, LOG_HTTP_CF_NONE);
                SCLogDebug("No matching parameter %%%c for custom http log.", httplog_ctx->cf_nodes[i]->type);
                break;
        }
    }
    MemBufferWriteString(aft->buffer, "\n");
#endif
}

/* JSON format logging */
static void LogHttpLogJSON(AlertJsonThread *aft, json_t *js, htp_tx_t *tx /*, char * timebuf,
                           char *srcip, Port sp, char *dstip, Port dp,
                           char *proto*/)
{
    //OutputHttpCtx *http_ctx = aft->http_ctx;
    OutputHttpCtx *http_ctx = aft->http_ctx->data;
    json_t *hjs = json_object();
    if (hjs == NULL) {
        return;
    }

    char *c;
    /* hostname */
    if (tx->request_hostname != NULL)
    {
        json_object_set_new(hjs, "hostname",
            json_string(c = strndup((char *)bstr_ptr(tx->request_hostname),
                                    bstr_len(tx->request_hostname))));
            if (c) free(c);
    } else {
        json_object_set_new(hjs, "hostname", json_string("<hostname unknown>"));
    }

    /* uri */
    if (tx->request_uri != NULL)
    {
        json_object_set_new(hjs, "uri",
                            json_string(c = strndup((char *)bstr_ptr(tx->request_uri),
                                                    bstr_len(tx->request_uri))));
        if (c) free(c);
    }

    /* user agent */
    htp_header_t *h_user_agent = NULL;
    if (tx->request_headers != NULL) {
        h_user_agent = htp_table_get_c(tx->request_headers, "user-agent");
    }
    if (h_user_agent != NULL) {
        json_object_set_new(hjs, "user-agent",
            json_string(c = strndup((char *)bstr_ptr(h_user_agent->value),
                                    bstr_len(h_user_agent->value))));
        if (c) free(c);
    } else {
        json_object_set_new(hjs, "user-agent", json_string("<useragent unknown>"));
    }

    /* x-forwarded-for */
    htp_header_t *h_x_forwarded_for = NULL;
    if (tx->request_headers != NULL) {
        h_x_forwarded_for = htp_table_get_c(tx->request_headers, "x-forwarded-for");
    }
    if (h_x_forwarded_for != NULL) {
        json_object_set_new(hjs, "xff",
            json_string(c = strndup((char *)bstr_ptr(h_x_forwarded_for->value),
                                    bstr_len(h_x_forwarded_for->value))));
        if (c) free(c);
    }

    /* content-type */
    htp_header_t *h_content_type = NULL;
    if (tx->response_headers != NULL) {
        h_content_type = htp_table_get_c(tx->response_headers, "content-type");
    }
    if (h_content_type != NULL) {
        char *p;
        c = strndup((char *)bstr_ptr(h_content_type->value),
                    bstr_len(h_content_type->value));
        p = strchrnul(c, ';');
        *p = '\0';
        json_object_set_new(hjs, "content-type", json_string(c));
        if (c) free(c);
    }

    if (http_ctx->flags & LOG_HTTP_EXTENDED) {
        /* referer */
        htp_header_t *h_referer = NULL;
        if (tx->request_headers != NULL) {
            h_referer = htp_table_get_c(tx->request_headers, "referer");
        }
        if (h_referer != NULL) {
            json_object_set_new(hjs, "referer",
                json_string(c = strndup((char *)bstr_ptr(h_referer->value),
                                        bstr_len(h_referer->value))));
            if (c) free(c);
        }

        /* method */
        if (tx->request_method != NULL) {
            json_object_set_new(hjs, "method",
                json_string(c = strndup((char *)bstr_ptr(tx->request_method),
                                        bstr_len(tx->request_method))));
            if (c) free(c);
        }

        /* protocol */
        if (tx->request_protocol != NULL) {
            json_object_set_new(hjs, "protocol",
                json_string(c = strndup((char *)bstr_ptr(tx->request_protocol),
                                        bstr_len(tx->request_protocol))));
            if (c) free(c);
        }

        /* response status */
        if (tx->response_status != NULL) {
            json_object_set_new(hjs, "status",
                 json_string(c = strndup((char *)bstr_ptr(tx->response_status),
                                         bstr_len(tx->response_status))));
            if (c) free(c);

            htp_header_t *h_location = htp_table_get_c(tx->response_headers, "location");
            if (h_location != NULL) {
                json_object_set_new(hjs, "redirect",
                    json_string(c = strndup((char *)bstr_ptr(h_location->value),
                                            bstr_len(h_location->value))));
                if (c) free(c);
            }
        }

        /* length */
        json_object_set_new(hjs, "length", json_integer(tx->response_message_len));
    }

    json_object_set_new(js, "http", hjs);
}

#if 0
static void LogHttpLogExtended(LogHttpLogThread *aft, htp_tx_t *tx)
{
    MemBufferWriteString(aft->buffer, " [**] ");

    /* referer */
    htp_header_t *h_referer = NULL;
    if (tx->request_headers != NULL) {
        h_referer = htp_table_get_c(tx->request_headers, "referer");
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
            htp_header_t *h_location = htp_table_get_c(tx->response_headers, "location");
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
#endif

static TmEcode HttpJsonIPWrapper(ThreadVars *tv, Packet *p, void *data, PacketQueue *pq,
                            PacketQueue *postpq/*, int ipproto*/)
{
    SCEnter();

    uint64_t tx_id = 0;
    uint64_t total_txs = 0;
    htp_tx_t *tx = NULL;
    HtpState *htp_state = NULL;
    int tx_progress = 0;
    int tx_progress_done_value_ts = 0;
    int tx_progress_done_value_tc = 0;
    AlertJsonThread *aft = (AlertJsonThread *)data;
    MemBuffer *buffer = (MemBuffer *)aft->buffer;
    OutputHttpCtx *http_ctx = aft->http_ctx->data;

    /* no flow, no htp state */
    if (p->flow == NULL) {
        SCReturnInt(TM_ECODE_OK);
    }

    /* check if we have HTTP state or not */
    FLOWLOCK_WRLOCK(p->flow); /* WRITE lock before we updated flow logged id */
    uint16_t proto = AppLayerGetProtoFromPacket(p);
    if (proto != ALPROTO_HTTP)
        goto end;

    htp_state = (HtpState *)AppLayerGetProtoStateFromPacket(p);
    if (htp_state == NULL) {
        SCLogDebug("no http state, so no request logging");
        goto end;
    }

    total_txs = AppLayerGetTxCnt(ALPROTO_HTTP, htp_state);
    tx_id = AppLayerTransactionGetLogId(p->flow);
    tx_progress_done_value_ts = AppLayerGetAlstateProgressCompletionStatus(ALPROTO_HTTP, 0);
    tx_progress_done_value_tc = AppLayerGetAlstateProgressCompletionStatus(ALPROTO_HTTP, 1);

    json_t *js = CreateJSONHeader(p, 1);
    if (unlikely(js == NULL))
        return TM_ECODE_OK;

    for (; tx_id < total_txs; tx_id++)
    {
        tx = AppLayerGetTx(ALPROTO_HTTP, htp_state, tx_id);
        if (tx == NULL) {
            SCLogDebug("tx is NULL not logging !!");
            continue;
        }

        if (!(((AppLayerParserStateStore *)p->flow->alparser)->id_flags & APP_LAYER_TRANSACTION_EOF)) {
            tx_progress = AppLayerGetAlstateProgress(ALPROTO_HTTP, tx, 0);
            if (tx_progress < tx_progress_done_value_ts)
                break;

            tx_progress = AppLayerGetAlstateProgress(ALPROTO_HTTP, tx, 1);
            if (tx_progress < tx_progress_done_value_tc)
                break;
        }

        SCLogDebug("got a HTTP request and now logging !!");

        /* reset */
        MemBufferReset(buffer);

        //if (aft->http_flags & LOG_HTTP_CUSTOM) {
        if (http_ctx->flags & LOG_HTTP_CUSTOM) {
            LogHttpLogJSONCustom(aft, js, tx, &p->ts/*, srcip, sp, dstip, dp*/);
        } else {
            LogHttpLogJSON(aft, js, tx /*, timebuf, srcip, sp, dstip, dp, proto_s*/);
        }

        OutputJSON(js, aft, &aft->http_cnt);
        json_object_del(js, "http");

        AppLayerTransactionUpdateLogId(ALPROTO_HTTP, p->flow);
    }
    json_object_clear(js);
    json_decref(js);

end:
    FLOWLOCK_UNLOCK(p->flow);
    SCReturnInt(TM_ECODE_OK);

}

TmEcode OutputHttpLog (ThreadVars *tv, Packet *p, void *data, PacketQueue *pq, PacketQueue *postpq)
{
    SCEnter();
    HttpJsonIPWrapper(tv, p, data, pq, postpq);
    SCReturnInt(TM_ECODE_OK);
}

OutputCtx *OutputHttpLogInit(ConfNode *conf)
{
    OutputHttpCtx *http_ctx = SCMalloc(sizeof(OutputHttpCtx));
    if (unlikely(http_ctx == NULL))
        return NULL;

    OutputCtx *output_ctx = SCCalloc(1, sizeof(OutputCtx));
    if (unlikely(output_ctx == NULL))
        return NULL;

    const char *extended = ConfNodeLookupChildValue(conf, "extended");

    http_ctx->flags = LOG_HTTP_DEFAULT;

    if (extended != NULL) {
        if (ConfValIsTrue(extended)) {
            http_ctx->flags = LOG_HTTP_EXTENDED;
        }
    }
    output_ctx->data = http_ctx;
    output_ctx->DeInit = NULL;

    return output_ctx;
}

#endif
