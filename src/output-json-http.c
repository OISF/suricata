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
#include "app-layer-htp.h"
#include "app-layer-htp-file.h"
#include "app-layer-htp-xff.h"
#include "app-layer.h"
#include "app-layer-parser.h"
#include "util-privs.h"
#include "util-buffer.h"
#include "util-proto-name.h"
#include "util-logopenfile.h"
#include "util-time.h"
#include "util-crypt.h"
#include "output-json.h"
#include "output-json-alert.h"
#include "output-json-http.h"
#include "util-byte.h"

#ifdef HAVE_LIBJANSSON

typedef struct LogHttpFileCtx_ {
    LogFileCtx *file_ctx;
    uint32_t flags; /** Store mode */
    uint64_t fields;/** Store fields */
    HttpXFFCfg *xff_cfg;
    HttpXFFCfg *parent_xff_cfg;
    OutputJsonCommonSettings cfg;
} LogHttpFileCtx;

typedef struct JsonHttpLogThread_ {
    LogHttpFileCtx *httplog_ctx;
    /** LogFileCtx has the pointer to the file and a mutex to allow multithreading */
    uint32_t uri_cnt;

    MemBuffer *buffer;
} JsonHttpLogThread;

#define MAX_SIZE_HEADER_NAME 256
#define MAX_SIZE_HEADER_VALUE 2048

#define LOG_HTTP_DEFAULT 0
#define LOG_HTTP_EXTENDED 1
#define LOG_HTTP_REQUEST 2 /* request field */
#define LOG_HTTP_ARRAY 4 /* require array handling */
#define LOG_HTTP_REQ_HEADERS 8
#define LOG_HTTP_RES_HEADERS 16

typedef enum {
    HTTP_FIELD_ACCEPT = 0,
    HTTP_FIELD_ACCEPT_CHARSET,
    HTTP_FIELD_ACCEPT_ENCODING,
    HTTP_FIELD_ACCEPT_LANGUAGE,
    HTTP_FIELD_ACCEPT_DATETIME,
    HTTP_FIELD_AUTHORIZATION,
    HTTP_FIELD_CACHE_CONTROL,
    HTTP_FIELD_COOKIE,
    HTTP_FIELD_FROM,
    HTTP_FIELD_MAX_FORWARDS,
    HTTP_FIELD_ORIGIN,
    HTTP_FIELD_PRAGMA,
    HTTP_FIELD_PROXY_AUTHORIZATION,
    HTTP_FIELD_RANGE,
    HTTP_FIELD_TE,
    HTTP_FIELD_VIA,
    HTTP_FIELD_X_REQUESTED_WITH,
    HTTP_FIELD_DNT,
    HTTP_FIELD_X_FORWARDED_PROTO,
    HTTP_FIELD_X_AUTHENTICATED_USER,
    HTTP_FIELD_X_FLASH_VERSION,
    HTTP_FIELD_ACCEPT_RANGES,
    HTTP_FIELD_AGE,
    HTTP_FIELD_ALLOW,
    HTTP_FIELD_CONNECTION,
    HTTP_FIELD_CONTENT_ENCODING,
    HTTP_FIELD_CONTENT_LANGUAGE,
    HTTP_FIELD_CONTENT_LENGTH,
    HTTP_FIELD_CONTENT_LOCATION,
    HTTP_FIELD_CONTENT_MD5,
    HTTP_FIELD_CONTENT_RANGE,
    HTTP_FIELD_CONTENT_TYPE,
    HTTP_FIELD_DATE,
    HTTP_FIELD_ETAG,
    HTTP_FIELD_EXPIRES,
    HTTP_FIELD_LAST_MODIFIED,
    HTTP_FIELD_LINK,
    HTTP_FIELD_LOCATION,
    HTTP_FIELD_PROXY_AUTHENTICATE,
    HTTP_FIELD_REFERRER,
    HTTP_FIELD_REFRESH,
    HTTP_FIELD_RETRY_AFTER,
    HTTP_FIELD_SERVER,
    HTTP_FIELD_SET_COOKIE,
    HTTP_FIELD_TRAILER,
    HTTP_FIELD_TRANSFER_ENCODING,
    HTTP_FIELD_UPGRADE,
    HTTP_FIELD_VARY,
    HTTP_FIELD_WARNING,
    HTTP_FIELD_WWW_AUTHENTICATE,
    HTTP_FIELD_TRUE_CLIENT_IP,
    HTTP_FIELD_ORG_SRC_IP,
    HTTP_FIELD_X_BLUECOAT_VIA,
    HTTP_FIELD_SIZE
} HttpField;

struct {
    const char *config_field;
    const char *htp_field;
    uint32_t flags;
} http_fields[] =  {
    { "accept", "accept", LOG_HTTP_REQUEST },
    { "accept_charset", "accept-charset", LOG_HTTP_REQUEST },
    { "accept_encoding", "accept-encoding", LOG_HTTP_REQUEST },
    { "accept_language", "accept-language", LOG_HTTP_REQUEST },
    { "accept_datetime", "accept-datetime", LOG_HTTP_REQUEST },
    { "authorization", "authorization", LOG_HTTP_REQUEST },
    { "cache_control", "cache-control", LOG_HTTP_REQUEST },
    { "cookie", "cookie", LOG_HTTP_REQUEST|LOG_HTTP_ARRAY },
    { "from", "from", LOG_HTTP_REQUEST },
    { "max_forwards", "max-forwards", LOG_HTTP_REQUEST },
    { "origin", "origin", LOG_HTTP_REQUEST },
    { "pragma", "pragma", LOG_HTTP_REQUEST },
    { "proxy_authorization", "proxy-authorization", LOG_HTTP_REQUEST },
    { "range", "range", LOG_HTTP_REQUEST },
    { "te", "te", LOG_HTTP_REQUEST },
    { "via", "via", LOG_HTTP_REQUEST },
    { "x_requested_with", "x-requested-with", LOG_HTTP_REQUEST },
    { "dnt", "dnt", LOG_HTTP_REQUEST },
    { "x_forwarded_proto", "x-forwarded-proto", LOG_HTTP_REQUEST },
    { "x_authenticated_user", "x-authenticated-user", LOG_HTTP_REQUEST },
    { "x_flash_version", "x-flash-version", LOG_HTTP_REQUEST },
    { "accept_range", "accept-range", 0 },
    { "age", "age", 0 },
    { "allow", "allow", 0 },
    { "connection", "connection", 0 },
    { "content_encoding", "content-encoding", 0 },
    { "content_language", "content-language", 0 },
    { "content_length", "content-length", 0 },
    { "content_location", "content-location", 0 },
    { "content_md5", "content-md5", 0 },
    { "content_range", "content-range", 0 },
    { "content_type", "content-type", 0 },
    { "date", "date", 0 },
    { "etag", "etags", 0 },
    { "expires", "expires" , 0 },
    { "last_modified", "last-modified", 0 },
    { "link", "link", 0 },
    { "location", "location", 0 },
    { "proxy_authenticate", "proxy-authenticate", 0 },
    { "referrer", "referrer", LOG_HTTP_EXTENDED },
    { "refresh", "refresh", 0 },
    { "retry_after", "retry-after", 0 },
    { "server", "server", 0 },
    { "set_cookie", "set-cookie", 0 },
    { "trailer", "trailer", 0 },
    { "transfer_encoding", "transfer-encoding", 0 },
    { "upgrade", "upgrade", 0 },
    { "vary", "vary", 0 },
    { "warning", "warning", 0 },
    { "www_authenticate", "www-authenticate", 0 },
    { "true_client_ip", "true-client-ip", LOG_HTTP_REQUEST },
    { "org_src_ip", "org-src-ip", LOG_HTTP_REQUEST },
    { "x_bluecoat_via", "x-bluecoat-via", LOG_HTTP_REQUEST },
};

static void JsonHttpLogJSONBasic(json_t *js, htp_tx_t *tx)
{
    /* hostname */
    if (tx->request_hostname != NULL) {
        const size_t size = bstr_len(tx->request_hostname) * 2 + 1;
        char string[size];
        BytesToStringBuffer(bstr_ptr(tx->request_hostname), bstr_len(tx->request_hostname), string, size);
        json_object_set_new(js, "hostname", SCJsonString(string));
    }

    /* port */
    /* NOTE: this field will be set ONLY if the port is present in the
     * hostname. It may be present in the header "Host" or in the URL.
     * There is no connection (from the suricata point of view) between this
     * port and the TCP destination port of the flow.
     */
    if (tx->request_port_number >= 0) {
        json_object_set_new(js, "http_port",
                json_integer(tx->request_port_number));
    }

    /* uri */
    if (tx->request_uri != NULL) {
        const size_t size = bstr_len(tx->request_uri) * 2 + 1;
        char string[size];
        BytesToStringBuffer(bstr_ptr(tx->request_uri), bstr_len(tx->request_uri), string, size);
        json_object_set_new(js, "url", SCJsonString(string));
    }

    if (tx->request_headers != NULL) {
        /* user agent */
        htp_header_t *h_user_agent = htp_table_get_c(tx->request_headers, "user-agent");
        if (h_user_agent != NULL) {
            const size_t size = bstr_len(h_user_agent->value) * 2 + 1;
            char string[size];
            BytesToStringBuffer(bstr_ptr(h_user_agent->value), bstr_len(h_user_agent->value), string, size);
            json_object_set_new(js, "http_user_agent", SCJsonString(string));
        }

        /* x-forwarded-for */
        htp_header_t *h_x_forwarded_for = htp_table_get_c(tx->request_headers, "x-forwarded-for");
        if (h_x_forwarded_for != NULL) {
            const size_t size = bstr_len(h_x_forwarded_for->value) * 2 + 1;
            char string[size];
            BytesToStringBuffer(bstr_ptr(h_x_forwarded_for->value), bstr_len(h_x_forwarded_for->value), string, size);
            json_object_set_new(js, "xff", json_string(string));
        }
    }

    /* content-type */
    if (tx->response_headers != NULL) {
        htp_header_t *h_content_type = htp_table_get_c(tx->response_headers, "content-type");
        if (h_content_type != NULL) {
            const size_t size = bstr_len(h_content_type->value) * 2 + 1;
            char string[size];
            BytesToStringBuffer(bstr_ptr(h_content_type->value), bstr_len(h_content_type->value), string, size);
            char *p = strchr(string, ';');
            if (p != NULL)
                *p = '\0';
            json_object_set_new(js, "http_content_type", SCJsonString(string));
        }
        htp_header_t *h_content_range = htp_table_get_c(tx->response_headers, "content-range");
        if (h_content_range != NULL) {
            const size_t size = bstr_len(h_content_range->value) * 2 + 1;
            char string[size];
            BytesToStringBuffer(bstr_ptr(h_content_range->value), bstr_len(h_content_range->value), string, size);
            json_t *crjs = json_object();
            if (crjs != NULL) {
                json_object_set_new(crjs, "raw", SCJsonString(string));
                HtpContentRange crparsed;
                if (HTPParseContentRange(h_content_range->value, &crparsed) == 0) {
                    if (crparsed.start >= 0)
                        json_object_set_new(crjs, "start", json_integer(crparsed.start));
                    if (crparsed.end >= 0)
                        json_object_set_new(crjs, "end", json_integer(crparsed.end));
                    if (crparsed.size >= 0)
                        json_object_set_new(crjs, "size", json_integer(crparsed.size));
                }
                json_object_set_new(js, "content_range", crjs);
            }
        }
    }
}

static void JsonHttpLogJSONCustom(LogHttpFileCtx *http_ctx, json_t *js, htp_tx_t *tx)
{
    char *c;
    HttpField f;

    for (f = HTTP_FIELD_ACCEPT; f < HTTP_FIELD_SIZE; f++)
    {
        if ((http_ctx->fields & (1ULL<<f)) != 0)
        {
            /* prevent logging a field twice if extended logging is
                enabled */
            if (((http_ctx->flags & LOG_HTTP_EXTENDED) == 0) ||
                ((http_ctx->flags & LOG_HTTP_EXTENDED) !=
                      (http_fields[f].flags & LOG_HTTP_EXTENDED)))
            {
                htp_header_t *h_field = NULL;
                if ((http_fields[f].flags & LOG_HTTP_REQUEST) != 0)
                {
                    if (tx->request_headers != NULL) {
                        h_field = htp_table_get_c(tx->request_headers,
                                                  http_fields[f].htp_field);
                    }
                } else {
                    if (tx->response_headers != NULL) {
                        h_field = htp_table_get_c(tx->response_headers,
                                                  http_fields[f].htp_field);
                    }
                }
                if (h_field != NULL) {
                    c = bstr_util_strdup_to_c(h_field->value);
                    if (c != NULL) {
                        json_object_set_new(js,
                                http_fields[f].config_field,
                                SCJsonString(c));
                        SCFree(c);
                    }
                }
            }
        }
    }
}

static void JsonHttpLogJSONExtended(json_t *js, htp_tx_t *tx)
{
    /* referer */
    htp_header_t *h_referer = NULL;
    if (tx->request_headers != NULL) {
        h_referer = htp_table_get_c(tx->request_headers, "referer");
    }
    if (h_referer != NULL) {
        const size_t size = bstr_len(h_referer->value) * 2 + 1;
        char string[size];
        BytesToStringBuffer(bstr_ptr(h_referer->value), bstr_len(h_referer->value), string, size);

        json_object_set_new(js, "http_refer", SCJsonString(string));
    }

    /* method */
    if (tx->request_method != NULL) {
        const size_t size = bstr_len(tx->request_method) * 2 + 1;
        char string[size];
        BytesToStringBuffer(bstr_ptr(tx->request_method), bstr_len(tx->request_method), string, size);
        json_object_set_new(js, "http_method", SCJsonString(string));
    }

    /* protocol */
    if (tx->request_protocol != NULL) {
        const size_t size = bstr_len(tx->request_protocol) * 2 + 1;
        char string[size];
        BytesToStringBuffer(bstr_ptr(tx->request_protocol), bstr_len(tx->request_protocol), string, size);
        json_object_set_new(js, "protocol", SCJsonString(string));
    }

    /* response status */
    if (tx->response_status != NULL) {
        const size_t status_size = bstr_len(tx->response_status) * 2 + 1;
        char status_string[status_size];
        BytesToStringBuffer(bstr_ptr(tx->response_status), bstr_len(tx->response_status),
                status_string, status_size);
        unsigned int val = strtoul(status_string, NULL, 10);
        json_object_set_new(js, "status", json_integer(val));

        htp_header_t *h_location = htp_table_get_c(tx->response_headers, "location");
        if (h_location != NULL) {
            const size_t size = bstr_len(h_location->value) * 2 + 1;
            char string[size];
            BytesToStringBuffer(bstr_ptr(h_location->value), bstr_len(h_location->value), string, size);
            json_object_set_new(js, "redirect", SCJsonString(string));
        }
    }

    /* length */
    json_object_set_new(js, "length", json_integer(tx->response_message_len));
}

static void JsonHttpLogJSONHeaders(json_t *js, uint32_t direction, htp_tx_t *tx)
{
    htp_table_t * headers = direction & LOG_HTTP_REQ_HEADERS ?
        tx->request_headers : tx->response_headers;
    char name[MAX_SIZE_HEADER_NAME] = {0};
    char value[MAX_SIZE_HEADER_VALUE] = {0};
    size_t n = htp_table_size(headers);
    json_t * arr = json_array();
    if (arr == NULL) {
        return;
    }
    for (size_t i = 0; i < n; i++) {
        htp_header_t * h = htp_table_get_index(headers, i, NULL);
        if (h == NULL) {
            continue;
        }
        json_t * obj = json_object();
        if (obj == NULL) {
            continue;
        }
        size_t size_name = bstr_len(h->name) < MAX_SIZE_HEADER_NAME - 1 ?
            bstr_len(h->name) : MAX_SIZE_HEADER_NAME - 1;
        memcpy(name, bstr_ptr(h->name), size_name);
        name[size_name] = '\0';
        json_object_set_new(obj, "name", SCJsonString(name));
        size_t size_value = bstr_len(h->value) < MAX_SIZE_HEADER_VALUE - 1 ?
            bstr_len(h->value) : MAX_SIZE_HEADER_VALUE - 1;
        memcpy(value, bstr_ptr(h->value), size_value);
        value[size_value] = '\0';
        json_object_set_new(obj, "value", SCJsonString(value));
        json_array_append_new(arr, obj);
    }
    json_object_set_new(js, direction & LOG_HTTP_REQ_HEADERS ?
            "request_headers" : "response_headers", arr);
}

static void BodyPrintableBuffer(json_t *js, HtpBody *body, const char *key)
{
    if (body->sb != NULL && body->sb->buf != NULL) {
        uint32_t offset = 0;
        const uint8_t *body_data;
        uint32_t body_data_len;
        uint64_t body_offset;

        if (StreamingBufferGetData(body->sb, &body_data,
                                   &body_data_len, &body_offset) == 0) {
            return;
        }

        uint8_t printable_buf[body_data_len + 1];
        PrintStringsToBuffer(printable_buf, &offset,
                             sizeof(printable_buf),
                             body_data, body_data_len);
        if (offset > 0) {
            json_object_set_new(js, key, json_string((char *)printable_buf));
        }
    }
}

void JsonHttpLogJSONBodyPrintable(json_t *js, Flow *f, uint64_t tx_id)
{
    HtpState *htp_state = (HtpState *)FlowGetAppState(f);
    if (htp_state) {
        htp_tx_t *tx = AppLayerParserGetTx(IPPROTO_TCP, ALPROTO_HTTP, htp_state, tx_id);
        if (tx) {
            HtpTxUserData *htud = (HtpTxUserData *)htp_tx_get_user_data(tx);
            if (htud != NULL) {
                BodyPrintableBuffer(js, &htud->request_body, "http_request_body_printable");
                BodyPrintableBuffer(js, &htud->response_body, "http_response_body_printable");
            }
        }
    }
}

static void BodyBase64Buffer(json_t *js, HtpBody *body, const char *key)
{
    if (body->sb != NULL && body->sb->buf != NULL) {
        const uint8_t *body_data;
        uint32_t body_data_len;
        uint64_t body_offset;

        if (StreamingBufferGetData(body->sb, &body_data,
                                   &body_data_len, &body_offset) == 0) {
            return;
        }

        unsigned long len = body_data_len * 2 + 1;
        uint8_t encoded[len];
        if (Base64Encode(body_data, body_data_len, encoded, &len) == SC_BASE64_OK) {
            json_object_set_new(js, key, json_string((char *)encoded));
        }
    }
}

void JsonHttpLogJSONBodyBase64(json_t *js, Flow *f, uint64_t tx_id)
{
    HtpState *htp_state = (HtpState *)FlowGetAppState(f);
    if (htp_state) {
        htp_tx_t *tx = AppLayerParserGetTx(IPPROTO_TCP, ALPROTO_HTTP, htp_state, tx_id);
        if (tx) {
            HtpTxUserData *htud = (HtpTxUserData *)htp_tx_get_user_data(tx);
            if (htud != NULL) {
                BodyBase64Buffer(js, &htud->request_body, "http_request_body");
                BodyBase64Buffer(js, &htud->response_body, "http_response_body");
            }
        }
    }
}

/* JSON format logging */
static void JsonHttpLogJSON(JsonHttpLogThread *aft, json_t *js, htp_tx_t *tx, uint64_t tx_id)
{
    LogHttpFileCtx *http_ctx = aft->httplog_ctx;
    json_t *hjs = json_object();
    if (hjs == NULL) {
        return;
    }

    JsonHttpLogJSONBasic(hjs, tx);
    /* log custom fields if configured */
    if (http_ctx->fields != 0)
        JsonHttpLogJSONCustom(http_ctx, hjs, tx);
    if (http_ctx->flags & LOG_HTTP_EXTENDED)
        JsonHttpLogJSONExtended(hjs, tx);
    if (http_ctx->flags & LOG_HTTP_REQ_HEADERS)
        JsonHttpLogJSONHeaders(hjs, LOG_HTTP_REQ_HEADERS, tx);
    if (http_ctx->flags & LOG_HTTP_RES_HEADERS)
        JsonHttpLogJSONHeaders(hjs, LOG_HTTP_RES_HEADERS, tx);

    json_object_set_new(js, "http", hjs);
}

static int JsonHttpLogger(ThreadVars *tv, void *thread_data, const Packet *p, Flow *f, void *alstate, void *txptr, uint64_t tx_id)
{
    SCEnter();

    htp_tx_t *tx = txptr;
    JsonHttpLogThread *jhl = (JsonHttpLogThread *)thread_data;

    json_t *js = CreateJSONHeaderWithTxId(p, LOG_DIR_FLOW, "http", tx_id);
    if (unlikely(js == NULL))
        return TM_ECODE_OK;

    JsonAddCommonOptions(&jhl->httplog_ctx->cfg, p, f, js);

    SCLogDebug("got a HTTP request and now logging !!");

    /* reset */
    MemBufferReset(jhl->buffer);

    JsonHttpLogJSON(jhl, js, tx, tx_id);
    HttpXFFCfg *xff_cfg = jhl->httplog_ctx->xff_cfg != NULL ?
        jhl->httplog_ctx->xff_cfg : jhl->httplog_ctx->parent_xff_cfg;

    /* xff header */
    if ((xff_cfg != NULL) && !(xff_cfg->flags & XFF_DISABLED) && p->flow != NULL) {
        int have_xff_ip = 0;
        char buffer[XFF_MAXLEN];

        have_xff_ip = HttpXFFGetIPFromTx(p->flow, tx_id, xff_cfg, buffer, XFF_MAXLEN);

        if (have_xff_ip) {
            if (xff_cfg->flags & XFF_EXTRADATA) {
                json_object_set_new(js, "xff", json_string(buffer));
            }
            else if (xff_cfg->flags & XFF_OVERWRITE) {
                if (p->flowflags & FLOW_PKT_TOCLIENT) {
                    json_object_set(js, "dest_ip", json_string(buffer));
                } else {
                    json_object_set(js, "src_ip", json_string(buffer));
                }
            }
        }
    }

    OutputJSONBuffer(js, jhl->httplog_ctx->file_ctx, &jhl->buffer);
    json_object_del(js, "http");

    json_object_clear(js);
    json_decref(js);

    SCReturnInt(TM_ECODE_OK);
}

json_t *JsonHttpAddMetadata(const Flow *f, uint64_t tx_id)
{
    HtpState *htp_state = (HtpState *)FlowGetAppState(f);
    if (htp_state) {
        htp_tx_t *tx = AppLayerParserGetTx(IPPROTO_TCP, ALPROTO_HTTP, htp_state, tx_id);

        if (tx) {
            json_t *hjs = json_object();
            if (unlikely(hjs == NULL))
                return NULL;

            JsonHttpLogJSONBasic(hjs, tx);
            JsonHttpLogJSONExtended(hjs, tx);
            return hjs;
        }
    }

    return NULL;
}

static void OutputHttpLogDeinit(OutputCtx *output_ctx)
{
    LogHttpFileCtx *http_ctx = output_ctx->data;
    LogFileCtx *logfile_ctx = http_ctx->file_ctx;
    LogFileFreeCtx(logfile_ctx);
    if (http_ctx->xff_cfg) {
        SCFree(http_ctx->xff_cfg);
    }
    SCFree(http_ctx);
    SCFree(output_ctx);
}

#define DEFAULT_LOG_FILENAME "http.json"
static OutputInitResult OutputHttpLogInit(ConfNode *conf)
{
    OutputInitResult result = { NULL, false };
    LogFileCtx *file_ctx = LogFileNewCtx();
    if(file_ctx == NULL) {
        SCLogError(SC_ERR_HTTP_LOG_GENERIC, "couldn't create new file_ctx");
        return result;
    }

    if (SCConfLogOpenGeneric(conf, file_ctx, DEFAULT_LOG_FILENAME, 1) < 0) {
        LogFileFreeCtx(file_ctx);
        return result;
    }

    LogHttpFileCtx *http_ctx = SCMalloc(sizeof(LogHttpFileCtx));
    if (unlikely(http_ctx == NULL)) {
        LogFileFreeCtx(file_ctx);
        return result;
    }

    OutputCtx *output_ctx = SCCalloc(1, sizeof(OutputCtx));
    if (unlikely(output_ctx == NULL)) {
        LogFileFreeCtx(file_ctx);
        SCFree(http_ctx);
        return result;
    }

    http_ctx->file_ctx = file_ctx;
    http_ctx->flags = LOG_HTTP_DEFAULT;

    if (conf) {
        const char *extended = ConfNodeLookupChildValue(conf, "extended");

        if (extended != NULL) {
            if (ConfValIsTrue(extended)) {
                http_ctx->flags = LOG_HTTP_EXTENDED;
            }
        }
        const char *all_headers = ConfNodeLookupChildValue(
                conf, "dump-all-headers");
        if (all_headers != NULL) {
            if (strcmp(all_headers, "both") == 0) {
                http_ctx->flags |= LOG_HTTP_REQ_HEADERS;
                http_ctx->flags |= LOG_HTTP_RES_HEADERS;
            } else if (strcmp(all_headers, "request") == 0) {
                http_ctx->flags |= LOG_HTTP_REQ_HEADERS;
            } else if (strcmp(all_headers, "response") == 0) {
                http_ctx->flags |= LOG_HTTP_RES_HEADERS;
            }
        }
    }
    http_ctx->xff_cfg = SCCalloc(1, sizeof(HttpXFFCfg));
    if (http_ctx->xff_cfg != NULL) {
        HttpXFFGetCfg(conf, http_ctx->xff_cfg);
    }

    output_ctx->data = http_ctx;
    output_ctx->DeInit = OutputHttpLogDeinit;

    /* enable the logger for the app layer */
    AppLayerParserRegisterLogger(IPPROTO_TCP, ALPROTO_HTTP);

    result.ctx = output_ctx;
    result.ok = true;
    return result;
}

static void OutputHttpLogDeinitSub(OutputCtx *output_ctx)
{
    LogHttpFileCtx *http_ctx = output_ctx->data;
    if (http_ctx->xff_cfg) {
        SCFree(http_ctx->xff_cfg);
    }
    SCFree(http_ctx);
    SCFree(output_ctx);
}

static OutputInitResult OutputHttpLogInitSub(ConfNode *conf, OutputCtx *parent_ctx)
{
    OutputInitResult result = { NULL, false };
    OutputJsonCtx *ojc = parent_ctx->data;

    LogHttpFileCtx *http_ctx = SCCalloc(1, sizeof(LogHttpFileCtx));
    if (unlikely(http_ctx == NULL))
        return result;
    memset(http_ctx, 0x00, sizeof(*http_ctx));

    OutputCtx *output_ctx = SCCalloc(1, sizeof(OutputCtx));
    if (unlikely(output_ctx == NULL)) {
        SCFree(http_ctx);
        return result;
    }

    http_ctx->file_ctx = ojc->file_ctx;
    http_ctx->flags = LOG_HTTP_DEFAULT;
    http_ctx->cfg = ojc->cfg;

    if (conf) {
        const char *extended = ConfNodeLookupChildValue(conf, "extended");

        if (extended != NULL) {
            if (ConfValIsTrue(extended)) {
                http_ctx->flags = LOG_HTTP_EXTENDED;
            }
        }

        ConfNode *custom;
        if ((custom = ConfNodeLookupChild(conf, "custom")) != NULL) {
            ConfNode *field;
            TAILQ_FOREACH(field, &custom->head, next)
            {
                if (field != NULL)
                {
                    HttpField f;
                    for (f = HTTP_FIELD_ACCEPT; f < HTTP_FIELD_SIZE; f++)
                    {
                        if ((strcmp(http_fields[f].config_field,
                                   field->val) == 0) ||
                            (strcasecmp(http_fields[f].htp_field,
                                        field->val) == 0))
                        {
                            http_ctx->fields |= (1ULL<<f);
                            break;
                        }
                    }
                }
            }
        }
        const char *all_headers = ConfNodeLookupChildValue(
                conf, "dump-all-headers");
        if (all_headers != NULL) {
            if (strncmp(all_headers, "both", 4) == 0) {
                http_ctx->flags |= LOG_HTTP_REQ_HEADERS;
                http_ctx->flags |= LOG_HTTP_RES_HEADERS;
            } else if (strncmp(all_headers, "request", 7) == 0) {
                http_ctx->flags |= LOG_HTTP_REQ_HEADERS;
            } else if (strncmp(all_headers, "response", 8) == 0) {
                http_ctx->flags |= LOG_HTTP_RES_HEADERS;
            }
        }
    }

    if (conf != NULL && ConfNodeLookupChild(conf, "xff") != NULL) {
        http_ctx->xff_cfg = SCCalloc(1, sizeof(HttpXFFCfg));
        if (http_ctx->xff_cfg != NULL) {
            HttpXFFGetCfg(conf, http_ctx->xff_cfg);
        }
    } else if (ojc->xff_cfg) {
        http_ctx->parent_xff_cfg = ojc->xff_cfg;
    }

    output_ctx->data = http_ctx;
    output_ctx->DeInit = OutputHttpLogDeinitSub;

    /* enable the logger for the app layer */
    AppLayerParserRegisterLogger(IPPROTO_TCP, ALPROTO_HTTP);

    result.ctx = output_ctx;
    result.ok = true;
    return result;
}

#define OUTPUT_BUFFER_SIZE 65535
static TmEcode JsonHttpLogThreadInit(ThreadVars *t, const void *initdata, void **data)
{
    JsonHttpLogThread *aft = SCMalloc(sizeof(JsonHttpLogThread));
    if (unlikely(aft == NULL))
        return TM_ECODE_FAILED;
    memset(aft, 0, sizeof(JsonHttpLogThread));

    if(initdata == NULL)
    {
        SCLogDebug("Error getting context for EveLogHTTP.  \"initdata\" argument NULL");
        SCFree(aft);
        return TM_ECODE_FAILED;
    }

    /* Use the Ouptut Context (file pointer and mutex) */
    aft->httplog_ctx = ((OutputCtx *)initdata)->data; //TODO

    aft->buffer = MemBufferCreateNew(OUTPUT_BUFFER_SIZE);
    if (aft->buffer == NULL) {
        SCFree(aft);
        return TM_ECODE_FAILED;
    }

    *data = (void *)aft;
    return TM_ECODE_OK;
}

static TmEcode JsonHttpLogThreadDeinit(ThreadVars *t, void *data)
{
    JsonHttpLogThread *aft = (JsonHttpLogThread *)data;
    if (aft == NULL) {
        return TM_ECODE_OK;
    }

    MemBufferFree(aft->buffer);
    /* clear memory */
    memset(aft, 0, sizeof(JsonHttpLogThread));

    SCFree(aft);
    return TM_ECODE_OK;
}

void JsonHttpLogRegister (void)
{
    /* register as separate module */
    OutputRegisterTxModule(LOGGER_JSON_HTTP, "JsonHttpLog", "http-json-log",
        OutputHttpLogInit, ALPROTO_HTTP, JsonHttpLogger, JsonHttpLogThreadInit,
        JsonHttpLogThreadDeinit, NULL);

    /* also register as child of eve-log */
    OutputRegisterTxSubModule(LOGGER_JSON_HTTP, "eve-log", "JsonHttpLog",
        "eve-log.http", OutputHttpLogInitSub, ALPROTO_HTTP, JsonHttpLogger,
        JsonHttpLogThreadInit, JsonHttpLogThreadDeinit, NULL);
}

#else

void JsonHttpLogRegister (void)
{
}

#endif
