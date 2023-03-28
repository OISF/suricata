/**
 * \file
 *
 * \author Angelo Mirabella <mirabellaa@vmware.com>
 *
 * Generate HTTP events and invoke corresponding callback.
 *
 */

#include "suricata-common.h"

#include "output-callback-http.h"

#include "app-layer-htp.h"
#include "app-layer-parser.h"
#include "output.h"
#include "output-callback.h"
#include "threadvars.h"
#include "util-byte.h"

#define MODULE_NAME "CallbackHttpLog"


/* Mock ThreadInit/DeInit methods.
 * Callbacks do not store any per-thread information. */
static TmEcode CallbackHttpLogThreadInit(ThreadVars *t, const void *initdata, void **data) {
    return TM_ECODE_OK;
}

static TmEcode CallbackHttpLogThreadDeinit(ThreadVars *t, void *data) {
    return TM_ECODE_OK;
}

static OutputInitResult CallbackHttpLogInitSub(ConfNode *conf, OutputCtx *parent_ctx) {
    OutputInitResult result;

    /* Enable the logger for the app layer */
    AppLayerParserRegisterLogger(IPPROTO_TCP, ALPROTO_HTTP);

    result.ctx = NULL;
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

static void CallbackHttpLog(htp_tx_t *tx, const char *dir, HttpInfo *http) {
    /* Hostname. */
    http->hostname = tx->request_hostname;

    /* Method. */
    http->http_method = tx->request_method;

    /* Protocol. */
    http->protocol = tx->request_protocol;

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

        /* Redirect. */
        htp_header_t *h_location = htp_table_get_c(tx->response_headers, "location");
        if (h_location != NULL) {
            http->redirect = h_location->value;
        }
        /* TODO: content-range header? */
    }

    /* Direction */
    http->direction = dir ? dir : "";

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
    }

     /* Headers. */
    CallbackHttpLogHeaders(tx, http, LOG_HTTP_REQ_HEADERS);
    CallbackHttpLogHeaders(tx, http, LOG_HTTP_RES_HEADERS);
}

static int CallbackHttpLogger(ThreadVars *tv, void *thread_data, const Packet *p, Flow *f,
                              void *alstate, void *txptr, uint64_t tx_id) {
    if (!tv->callbacks->http.func) {
        return 0;
    }

    HttpEvent event = {};
    htp_tx_t *tx = txptr;

    JsonAddrInfo addr= json_addr_info_zero;
    EventAddCommonInfo(p, LOG_DIR_FLOW, &event.common, &addr);
    event.http.tx_id = tx_id;

    /* TODO: Add metadata (flowvars, pktvars)? */

    const char *dir = NULL;
    if (PKT_IS_TOCLIENT(p)) {
        dir = LOG_HTTP_DIR_DOWNLOAD;
    } else {
        dir = LOG_HTTP_DIR_UPLOAD;
    }
    CallbackHttpLog(tx, dir, &event.http);

    /* TODO: handle xff? */

    /* Invoke callback. */
    tv->callbacks->http.func(&event, f->tenant_uuid, tv->callbacks->http.user_ctx);

    return 0;
}

bool CallbackHttpAddMetadata(const Flow *f, uint64_t tx_id, const char *dir, HttpInfo *http) {
    HtpState *htp_state = (HtpState *)FlowGetAppState(f);
    if (htp_state) {
        htp_tx_t *tx = AppLayerParserGetTx(IPPROTO_TCP, ALPROTO_HTTP, htp_state, tx_id);

        if (tx) {
            CallbackHttpLog(tx, dir, http);
            return true;
        }
    }

    return false;
}

void CallbackHttpLogRegister(void) {
    OutputRegisterTxSubModule(LOGGER_CALLBACK_TX, "", MODULE_NAME, "", CallbackHttpLogInitSub,
                              ALPROTO_HTTP, CallbackHttpLogger, CallbackHttpLogThreadInit,
                              CallbackHttpLogThreadDeinit, NULL);
}
