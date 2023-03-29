/**
 * \file
 *
 * \author Angelo Mirabella <mirabellaa@vmware.com>
 *
 * Generate HTTP events and invoke corresponding callback.
 *
 */

#include "suricata-common.h"


#include "app-layer-htp.h"
#include "app-layer-htp-file.h"
#include "app-layer-htp-xff.h"
#include "app-layer-parser.h"
#include "output.h"
#include "output-callback.h"
#include "output-callback-http.h"
#include "output-json-http.h"
#include "threadvars.h"
#include "util-byte.h"

#define MODULE_NAME "CallbackHttpLog"


typedef struct LogHttpCtx {
    uint32_t flags; /** Store mode */
    uint64_t fields;/** Store fields */
    HttpXFFCfg *xff_cfg;
    OutputCallbackCommonSettings cfg;
} LogHttpCtx;

typedef struct CallbackHttpLogThread {
    LogHttpCtx *httplog_ctx;
} CallbackHttpLogThread;

static TmEcode CallbackHttpLogThreadInit(ThreadVars *t, const void *initdata, void **data) {
    CallbackHttpLogThread *aft = SCCalloc(1, sizeof(CallbackHttpLogThread));
    if (unlikely(aft == NULL)) {
        return TM_ECODE_FAILED;
    }

    if(initdata == NULL) {
        SCLogDebug("Error getting context for EveLogHTTP.  \"initdata\" argument NULL");
        return TM_ECODE_FAILED;
    }

    aft->httplog_ctx = ((OutputCtx *)initdata)->data;
    *data = (void *)aft;
    return TM_ECODE_OK;
}

static TmEcode CallbackHttpLogThreadDeinit(ThreadVars *t, void *data) {
    CallbackHttpLogThread *aft = (CallbackHttpLogThread *)data;
    if (aft == NULL) {
        return TM_ECODE_OK;
    }

    SCFree(aft);
    return TM_ECODE_OK;
}

static void CallbackHttpLogDeinitSub(OutputCtx *output_ctx) {
    LogHttpCtx *http_ctx = output_ctx->data;
    if (http_ctx->xff_cfg) {
        SCFree(http_ctx->xff_cfg);
    }
    SCFree(http_ctx);
    SCFree(output_ctx);
}

static OutputInitResult CallbackHttpLogInitSub(ConfNode *conf, OutputCtx *parent_ctx) {
    OutputInitResult result = { NULL, false };
    OutputCallbackCtx *occ = parent_ctx->data;

    LogHttpCtx *http_ctx = SCCalloc(1, sizeof(LogHttpCtx));
    if (unlikely(http_ctx == NULL)) {
        return result;
    }
    memset(http_ctx, 0x00, sizeof(*http_ctx));
    http_ctx->flags = LOG_HTTP_DEFAULT;
    http_ctx->cfg = occ->cfg;

    OutputCtx *output_ctx = SCCalloc(1, sizeof(OutputCtx));
    if (unlikely(output_ctx == NULL)) {
        SCFree(http_ctx);
        return result;
    }

    if (conf) {
        const char *extended = ConfNodeLookupChildValue(conf, "extended");

        if (extended != NULL) {
            if (ConfValIsTrue(extended)) {
                http_ctx->flags = LOG_HTTP_EXTENDED;
            }
        }

        const char *all_headers = ConfNodeLookupChildValue(conf, "dump-all-headers");
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
        /* TODO: handle LOG_HTTP_WITH_FILE? */
        /* TODO: handle request body? */
    }

    if (conf != NULL && ConfNodeLookupChild(conf, "xff") != NULL) {
        http_ctx->xff_cfg = SCCalloc(1, sizeof(HttpXFFCfg));
        if (http_ctx->xff_cfg != NULL) {
            HttpXFFGetCfg(conf, http_ctx->xff_cfg);
        }
    }

    output_ctx->data = http_ctx;
    output_ctx->DeInit = CallbackHttpLogDeinitSub;

    /* enable the logger for the app layer */
    AppLayerParserRegisterLogger(IPPROTO_TCP, ALPROTO_HTTP);

    result.ctx = output_ctx;
    result.ok = true;
    return result;
}

static void CallbackHttpLogHeaders(htp_tx_t *tx, HttpInfo *http, uint32_t direction) {
    htp_table_t *headers = direction & LOG_HTTP_REQ_HEADERS ? tx->request_headers :
                                                              tx->response_headers;
    size_t header_size = htp_table_size(headers);
    size_t j = 0;
    size_t n = header_size > MAX_NUM_HTTP_HEADERS ? MAX_NUM_HTTP_HEADERS : header_size;
    HttpHeader *event_headers = direction == LOG_HTTP_REQ_HEADERS ? http->request_headers :
                                                              http->response_headers;

    for (size_t i = 0; i < n; i++) {
        htp_header_t *h = htp_table_get_index(headers, i, NULL);

        if (h == NULL) {
            continue;
        }

        event_headers[j].name = h->name;
        event_headers[j++].value = h->value;
    }
}

static void CallbackHttpLogBasic(htp_tx_t *tx, HttpInfo *http) {
    /* Hostname. */
    http->hostname = tx->request_hostname;

    /* Port. */
    /* NOTE: this field will be set ONLY if the port is present in the
     * hostname. It may be present in the header "Host" or in the URL.
     * There is no connection (from the suricata point of view) between this
     * port and the TCP destination port of the flow.
     */
    http->http_port = tx->request_port_number;

    /* Uri. */
    http->uri = tx->request_uri;

    if (tx->request_headers != NULL) {
        /* User agent. */
        htp_header_t *h_user_agent = htp_table_get_c(tx->request_headers, "user-agent");
        if (h_user_agent != NULL) {
            http->user_agent = h_user_agent->value;
        }

        /* X-Forwarded-For */
        htp_header_t *h_x_forwarded_for = htp_table_get_c(tx->request_headers, "x-forwarded-for");
        if (h_x_forwarded_for != NULL) {
            http->xff = h_x_forwarded_for->value;
        }
    }

    if (tx->response_headers != NULL) {
        /* Content-Type. */
        htp_header_t *h_content_type = htp_table_get_c(tx->response_headers, "content-type");
        if (h_content_type != NULL) {
            http->content_type = h_content_type->value;
        }
        htp_header_t *h_content_range = htp_table_get_c(tx->response_headers, "content-range");
        if (h_content_range != NULL) {
            http->content_range_raw = h_content_range->value;
            http->content_range_start = http->content_range_end = http->content_range_size = -1;

            HTTPContentRange crparsed;
            if (HTPParseContentRange(h_content_range->value, &crparsed) == 0) {
                if (crparsed.start >= 0) {
                    http->content_range_start = crparsed.start;
                }
                if (crparsed.end >= 0) {
                    http->content_range_end = crparsed.end;
                }
                if (crparsed.size >= 0) {
                    http->content_range_size = crparsed.size;
                }
            }
        }
    }
}

static void CallbackHttpLogExtended(htp_tx_t *tx, HttpInfo *http) {
    /* Referer */
    htp_header_t *h_referer = NULL;
    if (tx->request_headers != NULL) {
        h_referer = htp_table_get_c(tx->request_headers, "referer");
        if (h_referer != NULL) {
            http->referer = h_referer->value;
        }
    }

    /* Method. */
    http->http_method = tx->request_method;

    /* Protocol. */
    http->protocol = tx->request_protocol;

    /* Response message len. */
    http->response_len = tx->response_message_len;

    /* Response status. */
    if (tx->response_status != NULL) {
        const size_t status_size = bstr_len(tx->response_status) * 2 + 1;
        char status_string[status_size];
        BytesToStringBuffer(bstr_ptr(tx->response_status), bstr_len(tx->response_status),
                status_string, status_size);
        unsigned int status = strtoul(status_string, NULL, 10);
        http->status = status;

        /* Redirect. */
        htp_header_t *h_location = htp_table_get_c(tx->response_headers, "location");
        if (h_location != NULL) {
            http->redirect = h_location->value;
        }
    }
}

static void CallbackHttpLog(CallbackHttpLogThread *aft, htp_tx_t *tx, const char *dir,
                            HttpInfo *http) {
    LogHttpCtx *http_ctx = aft->httplog_ctx;

    /* Always log basic information. */
    CallbackHttpLogBasic(tx, http);

    /* TODO: support custom fields? */

    /* Log extra information if configured. */
    if (http_ctx->flags & LOG_HTTP_EXTENDED) {
        CallbackHttpLogExtended(tx, http);
    }
    if (http_ctx->flags & LOG_HTTP_REQ_HEADERS) {
        CallbackHttpLogHeaders(tx, http, LOG_HTTP_REQ_HEADERS);
    }
    if (http_ctx->flags & LOG_HTTP_RES_HEADERS) {
        CallbackHttpLogHeaders(tx, http, LOG_HTTP_RES_HEADERS);
    }
    /* TODO: support request body? */
    /* TODO: support files? */
}

static int CallbackHttpLogger(ThreadVars *tv, void *thread_data, const Packet *p, Flow *f,
                              void *alstate, void *txptr, uint64_t tx_id) {
    if (!tv->callbacks->http) {
        return 0;
    }

    HttpEvent event = {};
    htp_tx_t *tx = txptr;
    CallbackHttpLogThread *chl = (CallbackHttpLogThread *)thread_data;
    LogHttpCtx *ctx = chl->httplog_ctx;


    JsonAddrInfo addr= json_addr_info_zero;
    EventAddCommonInfo(p, LOG_DIR_FLOW, &event.common, &addr, &ctx->cfg);
    event.http.tx_id = tx_id;

    /* TODO: Add metadata (flowvars, pktvars)? */

    const char *dir = NULL;
    if (PKT_IS_TOCLIENT(p)) {
        dir = LOG_HTTP_DIR_DOWNLOAD;
    } else {
        dir = LOG_HTTP_DIR_UPLOAD;
    }
    CallbackHttpLog(chl, tx, dir, &event.http);

    /* XFF header. */
    HttpXFFCfg *xff_cfg = chl->httplog_ctx->xff_cfg;
    char buffer[XFF_MAXLEN];
    if ((xff_cfg != NULL) && !(xff_cfg->flags & XFF_DISABLED) && p->flow != NULL) {
        int have_xff_ip = 0;

        have_xff_ip = HttpXFFGetIPFromTx(p->flow, tx_id, xff_cfg, buffer, XFF_MAXLEN);

        /* Support only overwrite mode. */
        if (have_xff_ip && xff_cfg->flags & XFF_OVERWRITE) {
            if (p->flowflags & FLOW_PKT_TOCLIENT) {
                event.common.dst_ip = buffer;
            } else {
                event.common.src_ip = buffer;
            }
        }
    }

    /* Invoke callback. */
    tv->callbacks->http(&event, f->tenant_uuid, f->user_ctx);

    return 0;
}

bool CallbackHttpAddMetadata(const Flow *f, uint64_t tx_id, HttpInfo *http) {
    HtpState *htp_state = (HtpState *)FlowGetAppState(f);
    if (htp_state) {
        htp_tx_t *tx = AppLayerParserGetTx(IPPROTO_TCP, ALPROTO_HTTP1, htp_state, tx_id);

        if (tx) {
            CallbackHttpLogBasic(tx, http);
            CallbackHttpLogExtended(tx, http);
            return true;
        }
    }

    return false;
}

void CallbackHttpLogRegister(void) {
    OutputRegisterTxSubModule(LOGGER_CALLBACK_TX, "callback", MODULE_NAME, "callback.http",
                              CallbackHttpLogInitSub, ALPROTO_HTTP1, CallbackHttpLogger,
                              CallbackHttpLogThreadInit, CallbackHttpLogThreadDeinit, NULL);
}
