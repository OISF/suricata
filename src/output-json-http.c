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
#include "output-json.h"

#ifdef HAVE_LIBJANSSON
#include <jansson.h>

typedef struct LogHttpFileCtx_ {
    LogFileCtx *file_ctx;
    uint32_t flags; /** Store mode */
} LogHttpFileCtx;

typedef struct JsonHttpLogThread_ {
    LogHttpFileCtx *httplog_ctx;
    /** LogFileCtx has the pointer to the file and a mutex to allow multithreading */
    uint32_t uri_cnt;

    MemBuffer *buffer;
} JsonHttpLogThread;


#define LOG_HTTP_DEFAULT 0
#define LOG_HTTP_EXTENDED 1
#define LOG_HTTP_CUSTOM 2

/* JSON format logging */
static void JsonHttpLogJSON(JsonHttpLogThread *aft, json_t *js, htp_tx_t *tx)
{
    LogHttpFileCtx *http_ctx = aft->httplog_ctx;
    json_t *hjs = json_object();
    if (hjs == NULL) {
        return;
    }

    char *c;
    /* hostname */
    if (tx->request_hostname != NULL)
    {
        c = bstr_util_strdup_to_c(tx->request_hostname);
        if (c != NULL) {
            json_object_set_new(hjs, "hostname", json_string(c));
            SCFree(c);
        }
    } else {
        json_object_set_new(hjs, "hostname", json_string("<unknown>"));
    }

    /* uri */
    if (tx->request_uri != NULL)
    {
        c = bstr_util_strdup_to_c(tx->request_uri);
        if (c != NULL) {
            json_object_set_new(hjs, "url", json_string(c));
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
            json_object_set_new(hjs, "http_user_agent", json_string(c));
            SCFree(c);
        }
    } else {
        json_object_set_new(hjs, "http_user_agent", json_string("unknown>"));
    }

    /* x-forwarded-for */
    htp_header_t *h_x_forwarded_for = NULL;
    if (tx->request_headers != NULL) {
        h_x_forwarded_for = htp_table_get_c(tx->request_headers, "x-forwarded-for");
    }
    if (h_x_forwarded_for != NULL) {
        c = bstr_util_strdup_to_c(h_x_forwarded_for->value);
        if (c != NULL) {
            json_object_set_new(hjs, "xff", json_string(c));
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
            json_object_set_new(hjs, "http_content_type", json_string(c));
            SCFree(c);
        }
    }

    if (http_ctx->flags & LOG_HTTP_EXTENDED) {
        /* referer */
        htp_header_t *h_referer = NULL;
        if (tx->request_headers != NULL) {
            h_referer = htp_table_get_c(tx->request_headers, "referer");
        }
        if (h_referer != NULL) {
            c = bstr_util_strdup_to_c(h_referer->value);
            if (c != NULL) {
                json_object_set_new(hjs, "http_refer", json_string(c));
                SCFree(c);
            }
        }

        /* method */
        if (tx->request_method != NULL) {
            c = bstr_util_strdup_to_c(tx->request_method);
            if (c != NULL) {
                json_object_set_new(hjs, "http_method", json_string(c));
                SCFree(c);
            }
        }

        /* protocol */
        if (tx->request_protocol != NULL) {
            c = bstr_util_strdup_to_c(tx->request_protocol);
            if (c != NULL) {
                json_object_set_new(hjs, "protocol", json_string(c));
                SCFree(c);
            }
        }

        /* response status */
        if (tx->response_status != NULL) {
            c = bstr_util_strdup_to_c(tx->response_status);
            if (c != NULL) {
                json_object_set_new(hjs, "status", json_string(c));
                SCFree(c);
            }

            htp_header_t *h_location = htp_table_get_c(tx->response_headers, "location");
            if (h_location != NULL) {
                c = bstr_util_strdup_to_c(h_location->value);
                if (c != NULL) {
                    json_object_set_new(hjs, "redirect", json_string(c));
                    SCFree(c);
                }
            }
        }

        /* length */
        json_object_set_new(hjs, "length", json_integer(tx->response_message_len));
    }

    json_object_set_new(js, "http", hjs);
}

static int JsonHttpLogger(ThreadVars *tv, void *thread_data, const Packet *p, Flow *f, void *alstate, void *txptr, uint64_t tx_id)
{
    SCEnter();

    htp_tx_t *tx = txptr;
    JsonHttpLogThread *jhl = (JsonHttpLogThread *)thread_data;
    MemBuffer *buffer = (MemBuffer *)jhl->buffer;

    json_t *js = CreateJSONHeader((Packet *)p, 1, "http"); //TODO const
    if (unlikely(js == NULL))
        return TM_ECODE_OK;

    SCLogDebug("got a HTTP request and now logging !!");

    /* reset */
    MemBufferReset(buffer);

    JsonHttpLogJSON(jhl, js, tx);

    OutputJSONBuffer(js, jhl->httplog_ctx->file_ctx, buffer);
    json_object_del(js, "http");

    json_object_clear(js);
    json_decref(js);

    SCReturnInt(TM_ECODE_OK);
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
OutputCtx *OutputHttpLogInit(ConfNode *conf)
{
    LogFileCtx *file_ctx = LogFileNewCtx();
    if(file_ctx == NULL) {
        SCLogError(SC_ERR_HTTP_LOG_GENERIC, "couldn't create new file_ctx");
        return NULL;
    }

    if (SCConfLogOpenGeneric(conf, file_ctx, DEFAULT_LOG_FILENAME) < 0) {
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

OutputCtx *OutputHttpLogInitSub(ConfNode *conf, OutputCtx *parent_ctx)
{
    AlertJsonThread *ajt = parent_ctx->data;

    LogHttpFileCtx *http_ctx = SCMalloc(sizeof(LogHttpFileCtx));
    if (unlikely(http_ctx == NULL))
        return NULL;

    OutputCtx *output_ctx = SCCalloc(1, sizeof(OutputCtx));
    if (unlikely(output_ctx == NULL)) {
        SCFree(http_ctx);
        return NULL;
    }

    http_ctx->file_ctx = ajt->file_ctx;
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
    output_ctx->DeInit = OutputHttpLogDeinitSub;

    /* enable the logger for the app layer */
    AppLayerParserRegisterLogger(IPPROTO_TCP, ALPROTO_HTTP);

    return output_ctx;
}

#define OUTPUT_BUFFER_SIZE 65535
static TmEcode JsonHttpLogThreadInit(ThreadVars *t, void *initdata, void **data)
{
    JsonHttpLogThread *aft = SCMalloc(sizeof(JsonHttpLogThread));
    if (unlikely(aft == NULL))
        return TM_ECODE_FAILED;
    memset(aft, 0, sizeof(JsonHttpLogThread));

    if(initdata == NULL)
    {
        SCLogDebug("Error getting context for HTTPLog.  \"initdata\" argument NULL");
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

void TmModuleJsonHttpLogRegister (void) {
    tmm_modules[TMM_JSONHTTPLOG].name = "JsonHttpLog";
    tmm_modules[TMM_JSONHTTPLOG].ThreadInit = JsonHttpLogThreadInit;
    tmm_modules[TMM_JSONHTTPLOG].ThreadDeinit = JsonHttpLogThreadDeinit;
    tmm_modules[TMM_JSONHTTPLOG].RegisterTests = NULL;
    tmm_modules[TMM_JSONHTTPLOG].cap_flags = 0;
    tmm_modules[TMM_JSONHTTPLOG].flags = TM_FLAG_LOGAPI_TM;

    /* register as separate module */
    OutputRegisterTxModule("JsonHttpLog", "http-json-log", OutputHttpLogInit,
            ALPROTO_HTTP, JsonHttpLogger);

    /* also register as child of eve-log */
    OutputRegisterTxSubModule("eve-log", "JsonHttpLog", "eve-log.http", OutputHttpLogInitSub,
            ALPROTO_HTTP, JsonHttpLogger);
}

#else

static TmEcode OutputJsonThreadInit(ThreadVars *t, void *initdata, void **data)
{
    SCLogInfo("Can't init JSON output - JSON support was disabled during build.");
    return TM_ECODE_FAILED;
}

void TmModuleJsonHttpLogRegister (void)
{
    tmm_modules[TMM_JSONHTTPLOG].name = "JsonHttpLog";
    tmm_modules[TMM_JSONHTTPLOG].ThreadInit = OutputJsonThreadInit;
}

#endif
