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

#ifdef HAVE_LIBJANSSON

typedef struct LogHttpFileCtx_ {
    LogFileCtx *file_ctx;
    uint32_t flags; /** Store mode */
    uint64_t fields;/** Store fields */
} LogHttpFileCtx;

typedef struct JsonHttpLogThread_ {
    LogHttpFileCtx *httplog_ctx;
    /** LogFileCtx has the pointer to the file and a mutex to allow multithreading */
    uint32_t uri_cnt;

    MemBuffer *buffer;
} JsonHttpLogThread;


#define LOG_HTTP_DEFAULT 0
#define LOG_HTTP_EXTENDED 1
#define LOG_HTTP_REQUEST 2 /* request field */
#define LOG_HTTP_ARRAY 4 /* require array handling */

typedef enum {
    HTTP_FIELD_ACCEPT = 0,
    HTTP_FIELD_ACCEPT_CHARSET,
    HTTP_FIELD_ACCEPT_ENCODING,
    HTTP_FIELD_ACCEPT_LANGUAGE,
    HTTP_FIELD_ACCEPT_DATETIME,
    HTTP_FIELD_AUTHORIZATION,
    HTTP_FIELD_CACHE_CONTROL,
    HTTP_FIELD_CONNECTION,
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
};

static void JsonHttpLogJSONBasic(json_t *js, htp_tx_t *tx)
{
    char *c;

    /* hostname */
    if (tx->request_hostname != NULL)
    {
        c = bstr_util_strdup_to_c(tx->request_hostname);
        if (c != NULL) {
            json_object_set_new(js, "hostname", json_string(c));
            SCFree(c);
        }
    }

    /* uri */
    if (tx->request_uri != NULL)
    {
        c = bstr_util_strdup_to_c(tx->request_uri);
        if (c != NULL) {
            json_object_set_new(js, "url", json_string(c));
            SCFree(c);
        }
    }

    /* user agent */
    htp_header_t *h_user_agent = NULL;
    if (tx->request_headers != NULL) {
        h_user_agent = htp_table_get_c(tx->request_headers, "user-agent");
    }
    if (h_user_agent != NULL) {
        c = bstr_util_strdup_to_c(h_user_agent->value);
        if (c != NULL) {
            json_object_set_new(js, "http_user_agent", json_string(c));
            SCFree(c);
        }
    }

    /* x-forwarded-for */
    htp_header_t *h_x_forwarded_for = NULL;
    if (tx->request_headers != NULL) {
        h_x_forwarded_for = htp_table_get_c(tx->request_headers, "x-forwarded-for");
    }
    if (h_x_forwarded_for != NULL) {
        c = bstr_util_strdup_to_c(h_x_forwarded_for->value);
        if (c != NULL) {
            json_object_set_new(js, "xff", json_string(c));
            SCFree(c);
        }
    }

    /* content-type */
    htp_header_t *h_content_type = NULL;
    if (tx->response_headers != NULL) {
        h_content_type = htp_table_get_c(tx->response_headers, "content-type");
    }
    if (h_content_type != NULL) {
        char *p;
        c = bstr_util_strdup_to_c(h_content_type->value);
        if (c != NULL) {
            p = strchr(c, ';');
            if (p != NULL)
                *p = '\0';
            json_object_set_new(js, "http_content_type", json_string(c));
            SCFree(c);
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
                                json_string(c));
                        SCFree(c);
                    }
                }
            }
        }
    }
}

static void JsonHttpLogJSONExtended(json_t *js, htp_tx_t *tx)
{
    char *c;

    /* referer */
    htp_header_t *h_referer = NULL;
    if (tx->request_headers != NULL) {
        h_referer = htp_table_get_c(tx->request_headers, "referer");
    }
    if (h_referer != NULL) {
        c = bstr_util_strdup_to_c(h_referer->value);
        if (c != NULL) {
            json_object_set_new(js, "http_refer", json_string(c));
            SCFree(c);
        }
    }

    /* method */
    if (tx->request_method != NULL) {
        c = bstr_util_strdup_to_c(tx->request_method);
        if (c != NULL) {
            json_object_set_new(js, "http_method", json_string(c));
            SCFree(c);
        }
    }

    /* protocol */
    if (tx->request_protocol != NULL) {
        c = bstr_util_strdup_to_c(tx->request_protocol);
        if (c != NULL) {
            json_object_set_new(js, "protocol", json_string(c));
            SCFree(c);
        }
    }

    /* response status */
    if (tx->response_status != NULL) {
        c = bstr_util_strdup_to_c(tx->response_status);
        if (c != NULL) {
            unsigned int val = strtoul(c, NULL, 10);
            json_object_set_new(js, "status", json_integer(val));
            SCFree(c);
        }

        htp_header_t *h_location = htp_table_get_c(tx->response_headers, "location");
        if (h_location != NULL) {
            c = bstr_util_strdup_to_c(h_location->value);
            if (c != NULL) {
                json_object_set_new(js, "redirect", json_string(c));
                SCFree(c);
            }
        }
    }

    /* length */
    json_object_set_new(js, "length", json_integer(tx->response_message_len));
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

    json_object_set_new(js, "http", hjs);
}

static int JsonHttpLogger(ThreadVars *tv, void *thread_data, const Packet *p, Flow *f, void *alstate, void *txptr, uint64_t tx_id)
{
    SCEnter();

    htp_tx_t *tx = txptr;
    JsonHttpLogThread *jhl = (JsonHttpLogThread *)thread_data;

    json_t *js = CreateJSONHeaderWithTxId((Packet *)p, 1, "http", tx_id); //TODO const
    if (unlikely(js == NULL))
        return TM_ECODE_OK;

    SCLogDebug("got a HTTP request and now logging !!");

    /* reset */
    MemBufferReset(jhl->buffer);

    JsonHttpLogJSON(jhl, js, tx, tx_id);

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
    SCFree(http_ctx);
    SCFree(output_ctx);
}

#define DEFAULT_LOG_FILENAME "http.json"
static OutputCtx *OutputHttpLogInit(ConfNode *conf)
{
    LogFileCtx *file_ctx = LogFileNewCtx();
    if(file_ctx == NULL) {
        SCLogError(SC_ERR_HTTP_LOG_GENERIC, "couldn't create new file_ctx");
        return NULL;
    }

    if (SCConfLogOpenGeneric(conf, file_ctx, DEFAULT_LOG_FILENAME, 1) < 0) {
        LogFileFreeCtx(file_ctx);
        return NULL;
    }

    LogHttpFileCtx *http_ctx = SCMalloc(sizeof(LogHttpFileCtx));
    if (unlikely(http_ctx == NULL)) {
        LogFileFreeCtx(file_ctx);
        return NULL;
    }

    OutputCtx *output_ctx = SCCalloc(1, sizeof(OutputCtx));
    if (unlikely(output_ctx == NULL)) {
        LogFileFreeCtx(file_ctx);
        SCFree(http_ctx);
        return NULL;
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
    }
    output_ctx->data = http_ctx;
    output_ctx->DeInit = OutputHttpLogDeinit;

    /* enable the logger for the app layer */
    AppLayerParserRegisterLogger(IPPROTO_TCP, ALPROTO_HTTP);

    return output_ctx;
}

static void OutputHttpLogDeinitSub(OutputCtx *output_ctx)
{
    LogHttpFileCtx *http_ctx = output_ctx->data;
    SCFree(http_ctx);
    SCFree(output_ctx);
}

static OutputCtx *OutputHttpLogInitSub(ConfNode *conf, OutputCtx *parent_ctx)
{
    OutputJsonCtx *ojc = parent_ctx->data;

    LogHttpFileCtx *http_ctx = SCMalloc(sizeof(LogHttpFileCtx));
    if (unlikely(http_ctx == NULL))
        return NULL;
    memset(http_ctx, 0x00, sizeof(*http_ctx));

    OutputCtx *output_ctx = SCCalloc(1, sizeof(OutputCtx));
    if (unlikely(output_ctx == NULL)) {
        SCFree(http_ctx);
        return NULL;
    }

    http_ctx->file_ctx = ojc->file_ctx;
    http_ctx->flags = LOG_HTTP_DEFAULT;

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
    }
    output_ctx->data = http_ctx;
    output_ctx->DeInit = OutputHttpLogDeinitSub;

    /* enable the logger for the app layer */
    AppLayerParserRegisterLogger(IPPROTO_TCP, ALPROTO_HTTP);

    return output_ctx;
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
