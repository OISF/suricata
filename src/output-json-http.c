/* Copyright (C) 2007-2021 Open Information Security Foundation
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
#include "detect.h"
#include "pkt-var.h"
#include "conf.h"

#include "threads.h"
#include "threadvars.h"
#include "tm-threads.h"

#include "util-print.h"

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
#include "output-json.h"
#include "output-json-alert.h"
#include "output-json-http.h"
#include "util-byte.h"
#include "util-misc.h"

typedef struct LogHttpFileCtx_ {
    uint32_t flags; /** Store mode */
    uint64_t fields;/** Store fields */
    uint32_t string_log_limit; /** per-field string cap */
    uint32_t header_log_limit; /** total header bytes per direction */
    HttpXFFCfg *xff_cfg;
    HttpXFFCfg *parent_xff_cfg;
    OutputJsonCtx *eve_ctx;
} LogHttpFileCtx;

typedef struct JsonHttpLogThread_ {
    LogHttpFileCtx *httplog_ctx;
    uint32_t uri_cnt;
    OutputJsonThreadCtx *ctx;
} JsonHttpLogThread;

#define HTTP_LOG_DEFAULT_STRING_LIMIT (16 * 1024)
#define HTTP_LOG_MAX_STRING_LIMIT     (64 * 1024)
#define HTTP_LOG_DEFAULT_HEADER_LIMIT (32 * 1024)
#define HTTP_LOG_MAX_HEADER_LIMIT     (64 * 1024)

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
} http_fields[] = {
    { "accept", "accept", LOG_HTTP_REQUEST },
    { "accept_charset", "accept-charset", LOG_HTTP_REQUEST },
    { "accept_encoding", "accept-encoding", LOG_HTTP_REQUEST },
    { "accept_language", "accept-language", LOG_HTTP_REQUEST },
    { "accept_datetime", "accept-datetime", LOG_HTTP_REQUEST },
    { "authorization", "authorization", LOG_HTTP_REQUEST },
    { "cache_control", "cache-control", LOG_HTTP_REQUEST },
    { "cookie", "cookie", LOG_HTTP_REQUEST | LOG_HTTP_ARRAY },
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
    { "expires", "expires", 0 },
    { "last_modified", "last-modified", 0 },
    { "link", "link", 0 },
    { "location", "location", 0 },
    { "proxy_authenticate", "proxy-authenticate", 0 },
    { "referer", "referer", LOG_HTTP_EXTENDED },
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

static void EveHttpLogJSONBasic(SCJsonBuilder *js, htp_tx_t *tx, uint32_t str_limit)
{
    /* hostname */
    if (htp_tx_request_hostname(tx) != NULL) {
        SCJbSetStringFromBytesLimited(js, "hostname", bstr_ptr(htp_tx_request_hostname(tx)),
                (uint32_t)bstr_len(htp_tx_request_hostname(tx)), str_limit);
    }

    /* port */
    /* NOTE: this field will be set ONLY if the port is present in the
     * hostname. It may be present in the header "Host" or in the URL.
     * There is no connection (from the suricata point of view) between this
     * port and the TCP destination port of the flow.
     */
    if (htp_tx_request_port_number(tx) >= 0) {
        SCJbSetUint(js, "http_port", htp_tx_request_port_number(tx));
    }

    /* uri */
    if (htp_tx_request_uri(tx) != NULL) {
        SCJbSetStringFromBytesLimited(js, "url", bstr_ptr(htp_tx_request_uri(tx)),
                (uint32_t)bstr_len(htp_tx_request_uri(tx)), str_limit);
    }

    if (htp_tx_request_headers(tx) != NULL) {
        /* user agent */
        const htp_header_t *h_user_agent = htp_tx_request_header(tx, "user-agent");
        if (h_user_agent != NULL) {
            SCJbSetStringFromBytesLimited(js, "http_user_agent", htp_header_value_ptr(h_user_agent),
                    (uint32_t)htp_header_value_len(h_user_agent), str_limit);
        }

        /* x-forwarded-for */
        const htp_header_t *h_x_forwarded_for = htp_tx_request_header(tx, "x-forwarded-for");
        if (h_x_forwarded_for != NULL) {
            SCJbSetStringFromBytesLimited(js, "xff", htp_header_value_ptr(h_x_forwarded_for),
                    (uint32_t)htp_header_value_len(h_x_forwarded_for), str_limit);
        }
    }

    /* content-type */
    if (htp_tx_response_headers(tx) != NULL) {
        const htp_header_t *h_content_type = htp_tx_response_header(tx, "content-type");
        if (h_content_type != NULL) {
            uint32_t len = (uint32_t)htp_header_value_len(h_content_type);
            const uint8_t *p = memchr(htp_header_value_ptr(h_content_type), ';', len);
            if (p != NULL)
                len = (uint32_t)(p - htp_header_value_ptr(h_content_type));
            SCJbSetStringFromBytesLimited(
                    js, "http_content_type", htp_header_value_ptr(h_content_type), len, str_limit);
        }
        const htp_header_t *h_content_range = htp_tx_response_header(tx, "content-range");
        if (h_content_range != NULL) {
            SCJbOpenObject(js, "content_range");
            SCJbSetStringFromBytesLimited(js, "raw", htp_header_value_ptr(h_content_range),
                    (uint32_t)htp_header_value_len(h_content_range), str_limit);
            HTTPContentRange crparsed;
            if (HTPParseContentRange(htp_header_value(h_content_range), &crparsed) == 0) {
                if (crparsed.start >= 0)
                    SCJbSetUint(js, "start", crparsed.start);
                if (crparsed.end >= 0)
                    SCJbSetUint(js, "end", crparsed.end);
                if (crparsed.size >= 0)
                    SCJbSetUint(js, "size", crparsed.size);
            }
            SCJbClose(js);
        }
    }
}

static void EveHttpLogJSONExtended(SCJsonBuilder *js, htp_tx_t *tx, uint32_t str_limit)
{
    /* referer */
    const htp_header_t *h_referer = NULL;
    if (htp_tx_request_headers(tx) != NULL) {
        h_referer = htp_tx_request_header(tx, "referer");
    }
    if (h_referer != NULL) {
        SCJbSetStringFromBytesLimited(js, "http_refer", htp_header_value_ptr(h_referer),
                (uint32_t)htp_header_value_len(h_referer), str_limit);
    }

    /* method */
    if (htp_tx_request_method(tx) != NULL) {
        SCJbSetStringFromBytesLimited(js, "http_method", bstr_ptr(htp_tx_request_method(tx)),
                (uint32_t)bstr_len(htp_tx_request_method(tx)), str_limit);
    }

    /* protocol */
    if (htp_tx_request_protocol(tx) != NULL) {
        SCJbSetStringFromBytesLimited(js, "protocol", bstr_ptr(htp_tx_request_protocol(tx)),
                (uint32_t)bstr_len(htp_tx_request_protocol(tx)), str_limit);
    }

    /* response status */
    const int resp = htp_tx_response_status_number(tx);
    if (resp > 0) {
        SCJbSetUint(js, "status", (uint32_t)resp);
    } else if (htp_tx_response_status(tx) != NULL) {
        SCJbSetStringFromBytesLimited(js, "status_string", bstr_ptr(htp_tx_response_status(tx)),
                (uint32_t)bstr_len(htp_tx_response_status(tx)), str_limit);
    }

    const htp_header_t *h_location = htp_tx_response_header(tx, "location");
    if (h_location != NULL) {
        SCJbSetStringFromBytesLimited(js, "redirect", htp_header_value_ptr(h_location),
                (uint32_t)htp_header_value_len(h_location), str_limit);
    }

    /* length */
    SCJbSetUint(js, "length", htp_tx_response_message_len(tx));
}

static void EveHttpLogJSONHeaders(
        SCJsonBuilder *js, uint32_t direction, htp_tx_t *tx, LogHttpFileCtx *http_ctx)
{
    const htp_headers_t *headers = direction & LOG_HTTP_REQ_HEADERS ? htp_tx_request_headers(tx)
                                                                    : htp_tx_response_headers(tx);
    const bool request = (direction & LOG_HTTP_REQ_HEADERS) != 0;
    const char *array_key = request ? "request_headers" : "response_headers";
    const char *truncated_key =
            request ? "request_headers_truncated" : "response_headers_truncated";
    size_t n = htp_headers_size(headers);
    SCJsonBuilderMark mark = { 0, 0, 0 };
    SCJbGetMark(js, &mark);
    bool array_empty = true;
    bool truncated = false;
    /* budget covers the name+value bytes of one direction */
    uint32_t remaining = http_ctx->header_log_limit;
    SCJbOpenArray(js, array_key);
    for (size_t i = 0; i < n; i++) {
        const htp_header_t *h = htp_headers_get_index(headers, i);
        if ((http_ctx->flags & direction) == 0 && http_ctx->fields != 0) {
            bool tolog = false;
            for (HttpField f = HTTP_FIELD_ACCEPT; f < HTTP_FIELD_SIZE; f++) {
                if ((http_ctx->fields & (1ULL << f)) != 0) {
                    /* prevent logging a field twice if extended logging is
                     * enabled */
                    if (((http_ctx->flags & LOG_HTTP_EXTENDED) == 0) ||
                            ((http_ctx->flags & LOG_HTTP_EXTENDED) !=
                                    (http_fields[f].flags & LOG_HTTP_EXTENDED))) {
                        if (bstr_cmp_c_nocase(htp_header_name(h), http_fields[f].htp_field)) {
                            tolog = true;
                            break;
                        }
                    }
                }
            }
            if (!tolog) {
                continue;
            }
        }
        if (remaining == 0) {
            truncated = true;
            break;
        }
        array_empty = false;
        uint32_t name_len = (uint32_t)htp_header_name_len(h);
        uint32_t value_len = (uint32_t)htp_header_value_len(h);
        if (name_len > remaining) {
            name_len = remaining;
            truncated = true;
        }
        remaining -= name_len;
        if (value_len > remaining) {
            value_len = remaining;
            truncated = true;
        }
        remaining -= value_len;
        SCJbStartObject(js);
        if (name_len > 0) {
            SCJbSetStringFromBytes(js, "name", htp_header_name_ptr(h), name_len);
        } else {
            SCJbSetString(js, "name", "");
        }
        if (value_len > 0) {
            SCJbSetStringFromBytes(js, "value", htp_header_value_ptr(h), value_len);
        } else {
            SCJbSetString(js, "value", "");
        }
        SCJbClose(js);
    }
    if (array_empty) {
        SCJbRestoreMark(js, &mark);
        return;
    }
    SCJbClose(js);
    if (truncated) {
        SCJbSetBool(js, truncated_key, true);
    }
}

static void BodyBuffer(SCJsonBuilder *js, HtpBody *body, const char *base64_key,
        const char *printable_key, const char *truncated_key, bool base64, bool printable,
        uint32_t limit)
{
    if (body->sb != NULL && body->sb->region.buf != NULL) {
        const uint8_t *body_data;
        uint32_t body_data_len;
        uint64_t body_offset;

        if (StreamingBufferGetData(body->sb, &body_data,
                                   &body_data_len, &body_offset) == 0) {
            return;
        }

        /* the streaming buffer only exposes the current region: mark
         * region/prune truncation as well as the logger cap */
        bool truncated = body->content_len_so_far > body_data_len;
        if (body_data_len > limit) {
            body_data_len = limit;
            truncated = true;
        }
        if (base64) {
            SCJbSetBase64(js, base64_key, body_data, body_data_len);
        }
        if (printable) {
            SCJbSetPrintAsciiString(js, printable_key, body_data, body_data_len);
        }
        if (truncated) {
            SCJbSetBool(js, truncated_key, true);
        }
    }
}

void EveHttpLogJSONBody(SCJsonBuilder *js, Flow *f, uint64_t tx_id, bool base64, bool printable,
        uint32_t body_log_limit)
{
    HtpState *htp_state = (HtpState *)FlowGetAppState(f);
    if (htp_state) {
        htp_tx_t *tx = AppLayerParserGetTx(IPPROTO_TCP, ALPROTO_HTTP1, htp_state, tx_id);
        if (tx) {
            HtpTxUserData *htud = (HtpTxUserData *)htp_tx_get_user_data(tx);
            BodyBuffer(js, &htud->request_body, "http_request_body", "http_request_body_printable",
                    "http_request_body_truncated", base64, printable, body_log_limit);
            BodyBuffer(js, &htud->response_body, "http_response_body",
                    "http_response_body_printable", "http_response_body_truncated", base64,
                    printable, body_log_limit);
        }
    }
}

/* JSON format logging */
static void EveHttpLogJSON(JsonHttpLogThread *aft, SCJsonBuilder *js, htp_tx_t *tx, uint64_t tx_id)
{
    LogHttpFileCtx *http_ctx = aft->httplog_ctx;
    SCJbOpenObject(js, "http");

    EveHttpLogJSONBasic(js, tx, http_ctx->string_log_limit);
    if (http_ctx->flags & LOG_HTTP_EXTENDED)
        EveHttpLogJSONExtended(js, tx, http_ctx->string_log_limit);
    if (http_ctx->flags & LOG_HTTP_REQ_HEADERS || http_ctx->fields != 0)
        EveHttpLogJSONHeaders(js, LOG_HTTP_REQ_HEADERS, tx, http_ctx);
    if (http_ctx->flags & LOG_HTTP_RES_HEADERS || http_ctx->fields != 0)
        EveHttpLogJSONHeaders(js, LOG_HTTP_RES_HEADERS, tx, http_ctx);

    SCJbClose(js);
}

static int JsonHttpLogger(ThreadVars *tv, void *thread_data, const Packet *p, Flow *f, void *alstate, void *txptr, uint64_t tx_id)
{
    SCEnter();

    htp_tx_t *tx = txptr;
    JsonHttpLogThread *jhl = (JsonHttpLogThread *)thread_data;

    SCJsonBuilder *js = CreateEveHeaderWithTxId(
            p, LOG_DIR_FLOW, "http", NULL, tx_id, jhl->httplog_ctx->eve_ctx);
    if (unlikely(js == NULL))
        return TM_ECODE_OK;

    SCLogDebug("got a HTTP request and now logging !!");

    EveHttpLogJSON(jhl, js, tx, tx_id);
    HttpXFFCfg *xff_cfg = jhl->httplog_ctx->xff_cfg != NULL ?
        jhl->httplog_ctx->xff_cfg : jhl->httplog_ctx->parent_xff_cfg;

    /* xff header */
    if ((xff_cfg != NULL) && !(xff_cfg->flags & XFF_DISABLED) && p->flow != NULL) {
        int have_xff_ip = 0;
        char buffer[XFF_MAXLEN];

        have_xff_ip = HttpXFFGetIPFromTx(p->flow, tx_id, xff_cfg, buffer, XFF_MAXLEN);

        if (have_xff_ip) {
            if (xff_cfg->flags & XFF_EXTRADATA) {
                SCJbSetString(js, "xff", buffer);
            }
            else if (xff_cfg->flags & XFF_OVERWRITE) {
                if (p->flowflags & FLOW_PKT_TOCLIENT) {
                    SCJbSetString(js, "dest_ip", buffer);
                } else {
                    SCJbSetString(js, "src_ip", buffer);
                }
            }
        }
    }

    OutputJsonBuilderBuffer(tv, p, p->flow, js, jhl->ctx);
    SCJbFree(js);

    SCReturnInt(TM_ECODE_OK);
}

bool EveHttpAddMetadata(const Flow *f, uint64_t tx_id, SCJsonBuilder *js)
{
    HtpState *htp_state = (HtpState *)FlowGetAppState(f);
    if (htp_state) {
        htp_tx_t *tx = AppLayerParserGetTx(IPPROTO_TCP, ALPROTO_HTTP1, htp_state, tx_id);

        if (tx) {
            EveHttpLogJSONBasic(js, tx, HTTP_LOG_DEFAULT_STRING_LIMIT);
            EveHttpLogJSONExtended(js, tx, HTTP_LOG_DEFAULT_STRING_LIMIT);
            return true;
        }
    }

    return false;
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

static OutputInitResult OutputHttpLogInitSub(SCConfNode *conf, OutputCtx *parent_ctx)
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

    http_ctx->flags = LOG_HTTP_DEFAULT;
    http_ctx->string_log_limit = HTTP_LOG_DEFAULT_STRING_LIMIT;
    http_ctx->header_log_limit = HTTP_LOG_DEFAULT_HEADER_LIMIT;
    http_ctx->eve_ctx = ojc;

    if (conf) {
        const char *extended = SCConfNodeLookupChildValue(conf, "extended");

        if (extended != NULL) {
            if (SCConfValIsTrue(extended)) {
                http_ctx->flags = LOG_HTTP_EXTENDED;
            }
        }

        const char *string_log_limit = SCConfNodeLookupChildValue(conf, "string-log-limit");
        if (string_log_limit != NULL) {
            uint32_t limit = 0;
            if (ParseSizeStringU32(string_log_limit, &limit) < 0 || limit == 0 ||
                    limit > HTTP_LOG_MAX_STRING_LIMIT) {
                SCLogError("invalid eve-log.http string-log-limit '%s'", string_log_limit);
            } else {
                http_ctx->string_log_limit = limit;
            }
        }

        const char *header_log_limit = SCConfNodeLookupChildValue(conf, "header-log-limit");
        if (header_log_limit != NULL) {
            uint32_t limit = 0;
            if (ParseSizeStringU32(header_log_limit, &limit) < 0 || limit == 0 ||
                    limit > HTTP_LOG_MAX_HEADER_LIMIT) {
                SCLogError("invalid eve-log.http header-log-limit '%s'", header_log_limit);
            } else {
                http_ctx->header_log_limit = limit;
            }
        }

        const char *all_headers = SCConfNodeLookupChildValue(conf, "dump-all-headers");
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
        SCConfNode *custom;
        if ((custom = SCConfNodeLookupChild(conf, "custom")) != NULL) {
            if ((http_ctx->flags & (LOG_HTTP_REQ_HEADERS | LOG_HTTP_RES_HEADERS)) ==
                    (LOG_HTTP_REQ_HEADERS | LOG_HTTP_RES_HEADERS)) {
                SCLogWarning("No need for custom as dump-all-headers is already present");
            }
            SCConfNode *field;
            TAILQ_FOREACH (field, &custom->head, next) {
                HttpField f;
                for (f = HTTP_FIELD_ACCEPT; f < HTTP_FIELD_SIZE; f++) {
                    if ((strcmp(http_fields[f].config_field, field->val) == 0) ||
                            (strcasecmp(http_fields[f].htp_field, field->val) == 0)) {
                        http_ctx->fields |= (1ULL << f);
                        break;
                    }
                }
            }
        }
    }

    if (conf != NULL && SCConfNodeLookupChild(conf, "xff") != NULL) {
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
    SCAppLayerParserRegisterLogger(IPPROTO_TCP, ALPROTO_HTTP1);

    result.ctx = output_ctx;
    result.ok = true;
    return result;
}

static TmEcode JsonHttpLogThreadInit(ThreadVars *t, const void *initdata, void **data)
{
    JsonHttpLogThread *aft = SCCalloc(1, sizeof(JsonHttpLogThread));
    if (unlikely(aft == NULL))
        return TM_ECODE_FAILED;

    if(initdata == NULL)
    {
        SCLogDebug("Error getting context for EveLogHTTP.  \"initdata\" argument NULL");
        goto error_exit;
    }

    /* Use the Output Context (file pointer and mutex) */
    aft->httplog_ctx = ((OutputCtx *)initdata)->data; //TODO

    aft->ctx = CreateEveThreadCtx(t, aft->httplog_ctx->eve_ctx);
    if (!aft->ctx) {
        goto error_exit;
    }

    *data = (void *)aft;
    return TM_ECODE_OK;

error_exit:
    SCFree(aft);
    return TM_ECODE_FAILED;
}

static TmEcode JsonHttpLogThreadDeinit(ThreadVars *t, void *data)
{
    JsonHttpLogThread *aft = (JsonHttpLogThread *)data;
    if (aft == NULL) {
        return TM_ECODE_OK;
    }

    FreeEveThreadCtx(aft->ctx);

    /* clear memory */
    memset(aft, 0, sizeof(JsonHttpLogThread));

    SCFree(aft);
    return TM_ECODE_OK;
}

void JsonHttpLogRegister (void)
{
    /* register as child of eve-log */
    OutputRegisterTxSubModule(LOGGER_JSON_TX, "eve-log", "JsonHttpLog", "eve-log.http",
            OutputHttpLogInitSub, ALPROTO_HTTP1, JsonHttpLogger, JsonHttpLogThreadInit,
            JsonHttpLogThreadDeinit);
}
