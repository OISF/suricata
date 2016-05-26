/* Copyright (C) 2007-2012 Open Information Security Foundation
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
 * Implements TLS JSON logging portion of the engine.
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
#include "app-layer-parser.h"
#include "output.h"
#include "app-layer-ssl.h"
#include "app-layer.h"
#include "util-privs.h"
#include "util-buffer.h"

#include "util-logopenfile.h"
#include "util-crypt.h"

#include "output-json.h"

#ifdef HAVE_LIBJANSSON

SC_ATOMIC_DECLARE(unsigned int, cert_id);

#define MODULE_NAME "LogTlsLog"

#define LOG_TLS_DEFAULT     0
#define LOG_TLS_EXTENDED    (1 << 0)

typedef struct OutputTlsCtx_ {
    LogFileCtx *file_ctx;
    uint32_t flags; /** Store mode */
} OutputTlsCtx;


typedef struct JsonTlsLogThread_ {
    OutputTlsCtx *tlslog_ctx;
    MemBuffer *buffer;
} JsonTlsLogThread;

#define SSL_VERSION_LENGTH 13

void JsonTlsLogJSONBasic(json_t *js, SSLState *ssl_state)
{
    /* tls.subject */
    json_object_set_new(js, "subject",
                        json_string(ssl_state->server_connp.cert0_subject));

    /* tls.issuerdn */
    json_object_set_new(js, "issuerdn",
                        json_string(ssl_state->server_connp.cert0_issuerdn));

}

void JsonTlsLogJSONExtended(json_t *tjs, SSLState * state)
{
    char ssl_version[SSL_VERSION_LENGTH + 1];

    /* tls.fingerprint */
    json_object_set_new(tjs, "fingerprint",
                        json_string(state->server_connp.cert0_fingerprint));

    /* tls.sni */
    if (state->client_connp.sni) {
        json_object_set_new(tjs, "sni",
                            json_string(state->client_connp.sni));
    }

    /* tls.version */
    switch (state->server_connp.version) {
        case TLS_VERSION_UNKNOWN:
            snprintf(ssl_version, SSL_VERSION_LENGTH, "UNDETERMINED");
            break;
        case SSL_VERSION_2:
            snprintf(ssl_version, SSL_VERSION_LENGTH, "SSLv2");
            break;
        case SSL_VERSION_3:
            snprintf(ssl_version, SSL_VERSION_LENGTH, "SSLv3");
            break;
        case TLS_VERSION_10:
            snprintf(ssl_version, SSL_VERSION_LENGTH, "TLSv1");
            break;
        case TLS_VERSION_11:
            snprintf(ssl_version, SSL_VERSION_LENGTH, "TLS 1.1");
            break;
        case TLS_VERSION_12:
            snprintf(ssl_version, SSL_VERSION_LENGTH, "TLS 1.2");
            break;
        default:
            snprintf(ssl_version, SSL_VERSION_LENGTH, "0x%04x",
                     state->server_connp.version);
            break;
    }
    json_object_set_new(tjs, "version", json_string(ssl_version));
}

static int JsonTlsLogger(ThreadVars *tv, void *thread_data, const Packet *p,
                         Flow *f, void *state, void *txptr, uint64_t tx_id)
{
    JsonTlsLogThread *aft = (JsonTlsLogThread *)thread_data;
    OutputTlsCtx *tls_ctx = aft->tlslog_ctx;

    SSLState *ssl_state = (SSLState *)state;
    if (unlikely(ssl_state == NULL)) {
        return 0;
    }

    if (ssl_state->server_connp.cert0_issuerdn == NULL ||
            ssl_state->server_connp.cert0_subject == NULL)
        return 0;

    json_t *js = CreateJSONHeader((Packet *)p, 0, "tls");
    if (unlikely(js == NULL))
        return 0;

    json_t *tjs = json_object();
    if (tjs == NULL) {
        free(js);
        return 0;
    }

    /* reset */
    MemBufferReset(aft->buffer);

    JsonTlsLogJSONBasic(tjs, ssl_state);

    if (tls_ctx->flags & LOG_TLS_EXTENDED) {
        JsonTlsLogJSONExtended(tjs, ssl_state);
    }

    json_object_set_new(js, "tls", tjs);

    OutputJSONBuffer(js, tls_ctx->file_ctx, &aft->buffer);
    json_object_clear(js);
    json_decref(js);

    return 0;
}

#define OUTPUT_BUFFER_SIZE 65535
static TmEcode JsonTlsLogThreadInit(ThreadVars *t, void *initdata, void **data)
{
    JsonTlsLogThread *aft = SCMalloc(sizeof(JsonTlsLogThread));
    if (unlikely(aft == NULL))
        return TM_ECODE_FAILED;
    memset(aft, 0, sizeof(JsonTlsLogThread));

    if(initdata == NULL)
    {
        SCLogDebug("Error getting context for EveLogTLS.  \"initdata\" argument NULL");
        SCFree(aft);
        return TM_ECODE_FAILED;
    }

    /* Use the Ouptut Context (file pointer and mutex) */
    aft->tlslog_ctx = ((OutputCtx *)initdata)->data;

    aft->buffer = MemBufferCreateNew(OUTPUT_BUFFER_SIZE);
    if (aft->buffer == NULL) {
        SCFree(aft);
        return TM_ECODE_FAILED;
    }

    *data = (void *)aft;
    return TM_ECODE_OK;
}

static TmEcode JsonTlsLogThreadDeinit(ThreadVars *t, void *data)
{
    JsonTlsLogThread *aft = (JsonTlsLogThread *)data;
    if (aft == NULL) {
        return TM_ECODE_OK;
    }

    MemBufferFree(aft->buffer);
    /* clear memory */
    memset(aft, 0, sizeof(JsonTlsLogThread));

    SCFree(aft);
    return TM_ECODE_OK;
}

static void OutputTlsLogDeinit(OutputCtx *output_ctx)
{
    OutputTlsCtx *tls_ctx = output_ctx->data;
    LogFileCtx *logfile_ctx = tls_ctx->file_ctx;
    LogFileFreeCtx(logfile_ctx);
    SCFree(tls_ctx);
    SCFree(output_ctx);
}

#define DEFAULT_LOG_FILENAME "tls.json"
OutputCtx *OutputTlsLogInit(ConfNode *conf)
{
    LogFileCtx *file_ctx = LogFileNewCtx();
    if(file_ctx == NULL) {
        SCLogError(SC_ERR_TLS_LOG_GENERIC, "couldn't create new file_ctx");
        return NULL;
    }

    if (SCConfLogOpenGeneric(conf, file_ctx, DEFAULT_LOG_FILENAME, 1) < 0) {
        LogFileFreeCtx(file_ctx);
        return NULL;
    }

    OutputTlsCtx *tls_ctx = SCMalloc(sizeof(OutputTlsCtx));
    if (unlikely(tls_ctx == NULL)) {
        LogFileFreeCtx(file_ctx);
        return NULL;
    }

    OutputCtx *output_ctx = SCCalloc(1, sizeof(OutputCtx));
    if (unlikely(output_ctx == NULL)) {
        LogFileFreeCtx(file_ctx);
        SCFree(tls_ctx);
        return NULL;
    }

    tls_ctx->file_ctx = file_ctx;
    tls_ctx->flags = LOG_TLS_DEFAULT;

    if (conf) {
        const char *extended = ConfNodeLookupChildValue(conf, "extended");

        if (extended != NULL) {
            if (ConfValIsTrue(extended)) {
                tls_ctx->flags = LOG_TLS_EXTENDED;
            }
        }
    }
    output_ctx->data = tls_ctx;
    output_ctx->DeInit = OutputTlsLogDeinit;

    AppLayerParserRegisterLogger(IPPROTO_TCP, ALPROTO_TLS);

    return output_ctx;
}

static void OutputTlsLogDeinitSub(OutputCtx *output_ctx)
{
    OutputTlsCtx *tls_ctx = output_ctx->data;
    SCFree(tls_ctx);
    SCFree(output_ctx);
}

OutputCtx *OutputTlsLogInitSub(ConfNode *conf, OutputCtx *parent_ctx)
{
    OutputJsonCtx *ojc = parent_ctx->data;

    OutputTlsCtx *tls_ctx = SCMalloc(sizeof(OutputTlsCtx));
    if (unlikely(tls_ctx == NULL))
        return NULL;

    OutputCtx *output_ctx = SCCalloc(1, sizeof(OutputCtx));
    if (unlikely(output_ctx == NULL)) {
        SCFree(tls_ctx);
        return NULL;
    }

    tls_ctx->file_ctx = ojc->file_ctx;
    tls_ctx->flags = LOG_TLS_DEFAULT;

    if (conf) {
        const char *extended = ConfNodeLookupChildValue(conf, "extended");

        if (extended != NULL) {
            if (ConfValIsTrue(extended)) {
                tls_ctx->flags = LOG_TLS_EXTENDED;
            }
        }
    }
    output_ctx->data = tls_ctx;
    output_ctx->DeInit = OutputTlsLogDeinitSub;

    AppLayerParserRegisterLogger(IPPROTO_TCP, ALPROTO_TLS);

    return output_ctx;
}

void TmModuleJsonTlsLogRegister (void)
{
    tmm_modules[TMM_JSONTLSLOG].name = "JsonTlsLog";
    tmm_modules[TMM_JSONTLSLOG].ThreadInit = JsonTlsLogThreadInit;
    tmm_modules[TMM_JSONTLSLOG].ThreadDeinit = JsonTlsLogThreadDeinit;
    tmm_modules[TMM_JSONTLSLOG].RegisterTests = NULL;
    tmm_modules[TMM_JSONTLSLOG].cap_flags = 0;
    tmm_modules[TMM_JSONTLSLOG].flags = TM_FLAG_LOGAPI_TM;

    /* register as separate module */
    OutputRegisterTxModuleWithProgress("JsonTlsLog", "tls-json-log",
            OutputTlsLogInit, ALPROTO_TLS, JsonTlsLogger, TLS_HANDSHAKE_DONE,
            TLS_HANDSHAKE_DONE);

    /* also register as child of eve-log */
    OutputRegisterTxSubModuleWithProgress("eve-log", "JsonTlsLog",
            "eve-log.tls", OutputTlsLogInitSub, ALPROTO_TLS, JsonTlsLogger,
            TLS_HANDSHAKE_DONE, TLS_HANDSHAKE_DONE);
}

#else

static TmEcode OutputJsonThreadInit(ThreadVars *t, void *initdata, void **data)
{
    SCLogInfo("Can't init JSON output - JSON support was disabled during build.");
    return TM_ECODE_FAILED;
}

void TmModuleJsonTlsLogRegister (void)
{
    tmm_modules[TMM_JSONTLSLOG].name = "JsonTlsLog";
    tmm_modules[TMM_JSONTLSLOG].ThreadInit = OutputJsonThreadInit;
}

#endif
