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
static TmEcode CallbackHttpLogThreadInit(ThreadVars *t, const void *initdata, void **data)
{
    return TM_ECODE_OK;
}

static TmEcode CallbackHttpLogThreadDeinit(ThreadVars *t, void *data)
{
    return TM_ECODE_OK;
}

/* Cleanup all the heap allocated strings in the event. */
void CallbackHttpCleanupInfo(HttpInfo *http)
{
    if (http->hostname) {
        SCFree(http->hostname);
    }

    if (http->uri) {
        SCFree(http->uri);
    }

    if (http->user_agent) {
        SCFree(http->user_agent);
    }

    if (http->xff) {
        SCFree(http->xff);
    }

    if (http->content_type) {
        SCFree(http->content_type);
    }
}

static void CallbackHttpLog(htp_tx_t *tx, HttpInfo *http)
{
    /* Hostname. */
    if (tx->request_hostname != NULL) {
        http->hostname = SCMalloc(bstr_len(tx->request_hostname) + 1 * sizeof(char));
        if (http->hostname != NULL) {
            memcpy(http->hostname, bstr_ptr(tx->request_hostname), bstr_len(tx->request_hostname));
            http->hostname[bstr_len(tx->request_hostname)] = 0;
        }
    }

    /* Port. */
    /* NOTE: this field will be set ONLY if the port is present in the
     * hostname. It may be present in the header "Host" or in the URL.
     * There is no connection (from the suricata point of view) between this
     * port and the TCP destination port of the flow.
     */
    if (tx->request_port_number >= 0) {
        http->http_port = tx->request_port_number;
    }

    /* Uri. */
    if (tx->request_uri != NULL) {
        http->uri = SCMalloc(bstr_len(tx->request_uri) + 1 * sizeof(char));
        if (http->uri != NULL) {
            memcpy(http->uri, bstr_ptr(tx->request_uri), bstr_len(tx->request_uri));
            http->uri[bstr_len(tx->request_uri)] = 0;
        }
    }

    if (tx->request_headers != NULL) {
        /* User agent. */
        htp_header_t *h_user_agent = htp_table_get_c(tx->request_headers, "user-agent");
        if (h_user_agent != NULL) {
            http->user_agent = SCMalloc(bstr_len(h_user_agent->value) + 1 * sizeof(char));
            if (http->user_agent != NULL) {
                memcpy(http->user_agent, bstr_ptr(h_user_agent->value),
                        bstr_len(h_user_agent->value));
            }
        }

        /* X-Forwarded-For */
        htp_header_t *h_x_forwarded_for = htp_table_get_c(tx->request_headers, "x-forwarded-for");
        if (h_x_forwarded_for != NULL) {
            http->xff = SCMalloc(bstr_len(h_x_forwarded_for->value) + 1 * sizeof(char));
            if (http->xff != NULL) {
                memcpy(http->xff, bstr_ptr(h_x_forwarded_for->value),
                        bstr_len(h_x_forwarded_for->value));
            }
        }
    }

    if (tx->response_headers != NULL) {
        /* Content-Type. */
        htp_header_t *h_content_type = htp_table_get_c(tx->response_headers, "content-type");
        if (h_content_type != NULL) {
            const size_t size = bstr_len(h_content_type->value) * 2 + 1;
            http->content_type = SCMalloc(size * sizeof(char));
            if (http->content_type != NULL) {
                BytesToStringBuffer(bstr_ptr(h_content_type->value),
                        bstr_len(h_content_type->value), http->content_type, size);
                char *p = strchr(http->content_type, ';');
                if (p != NULL)
                    *p = '\0';
            }
        }

        /* TODO: content-range header? */
    }

    /* TODO: log extra fields, such as headers and body? */
}

static int CallbackHttpLogger(ThreadVars *tv, void *thread_data, const Packet *p, Flow *f,
        void *alstate, void *txptr, uint64_t tx_id)
{
    if (!tv->callbacks || !tv->callbacks->http.func) {
        return 0;
    }

    HttpEvent event = { .common = {} };
    htp_tx_t *tx = txptr;

    EventAddCommonInfo(p, LOG_DIR_FLOW, &event.common);
    event.http.tx_id = tx_id;

    /* TODO: Add metadata (flowvars, pktvars)? */

    CallbackHttpLog(tx, &event.http);

    /* TODO: handle xff? */

    /* Invoke callback and cleanup event */
    tv->callbacks->http.func(tv->callbacks->http.user_ctx, &event);
    CallbackHttpCleanupInfo(&event.http);

    return 0;
}

bool CallbackHttpAddMetadata(const Flow *f, uint64_t tx_id, HttpInfo *http)
{
    HtpState *htp_state = (HtpState *)FlowGetAppState(f);
    if (htp_state) {
        htp_tx_t *tx = AppLayerParserGetTx(IPPROTO_TCP, ALPROTO_HTTP, htp_state, tx_id);

        if (tx) {
            CallbackHttpLog(tx, http);
            return true;
        }
    }

    return false;
}

void CallbackHttpLogRegister(void)
{
    OutputRegisterTxSubModule(LOGGER_CALLBACK_TX, "", MODULE_NAME, "", NULL, ALPROTO_HTTP,
            CallbackHttpLogger, CallbackHttpLogThreadInit, CallbackHttpLogThreadDeinit, NULL);
}
