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
#include "output-json-tls.h"

#ifdef HAVE_LIBJANSSON

SC_ATOMIC_DECLARE(unsigned int, cert_id);

#define MODULE_NAME "LogTlsLog"
#define DEFAULT_LOG_FILENAME "tls.json"

#define OUTPUT_BUFFER_SIZE 65535

#define SSL_VERSION_LENGTH 13

#define LOG_TLS_DEFAULT                 0
#define LOG_TLS_EXTENDED                (1 << 0)
#define LOG_TLS_CUSTOM                  (1 << 1)
#define LOG_TLS_SESSION_RESUMPTION      (1 << 2)

#define LOG_TLS_FIELD_VERSION           (1 << 0)
#define LOG_TLS_FIELD_SUBJECT           (1 << 1)
#define LOG_TLS_FIELD_ISSUER            (1 << 2)
#define LOG_TLS_FIELD_SERIAL            (1 << 3)
#define LOG_TLS_FIELD_FINGERPRINT       (1 << 4)
#define LOG_TLS_FIELD_NOTBEFORE         (1 << 5)
#define LOG_TLS_FIELD_NOTAFTER          (1 << 6)
#define LOG_TLS_FIELD_SNI               (1 << 7)
#define LOG_TLS_FIELD_CERTIFICATE       (1 << 8)
#define LOG_TLS_FIELD_CHAIN             (1 << 9)
#define LOG_TLS_FIELD_SESSION_RESUMED   (1 << 10)

typedef struct {
    const char *name;
    uint64_t flag;
} TlsFields;

TlsFields tls_fields[] = {
    { "version",         LOG_TLS_FIELD_VERSION },
    { "subject",         LOG_TLS_FIELD_SUBJECT },
    { "issuer",          LOG_TLS_FIELD_ISSUER },
    { "serial",          LOG_TLS_FIELD_SERIAL },
    { "fingerprint",     LOG_TLS_FIELD_FINGERPRINT },
    { "not_before",      LOG_TLS_FIELD_NOTBEFORE },
    { "not_after",       LOG_TLS_FIELD_NOTAFTER },
    { "sni",             LOG_TLS_FIELD_SNI },
    { "certificate",     LOG_TLS_FIELD_CERTIFICATE },
    { "chain",           LOG_TLS_FIELD_CHAIN },
    { "session_resumed", LOG_TLS_FIELD_SESSION_RESUMED },
    { NULL,              -1 }
};

typedef struct OutputTlsCtx_ {
    LogFileCtx *file_ctx;
    uint32_t flags;  /** Store mode */
    uint64_t fields; /** Store fields */
} OutputTlsCtx;


typedef struct JsonTlsLogThread_ {
    OutputTlsCtx *tlslog_ctx;
    MemBuffer *buffer;
} JsonTlsLogThread;

static void JsonTlsLogSubject(json_t *js, SSLState *ssl_state)
{
    if (ssl_state->server_connp.cert0_subject) {
        json_object_set_new(js, "subject",
                            json_string(ssl_state->server_connp.cert0_subject));
    }
}

static void JsonTlsLogIssuer(json_t *js, SSLState *ssl_state)
{
    if (ssl_state->server_connp.cert0_issuerdn) {
        json_object_set_new(js, "issuerdn",
                            json_string(ssl_state->server_connp.cert0_issuerdn));
    }
}

static void JsonTlsLogSessionResumed(json_t *js, SSLState *ssl_state)
{
    if (ssl_state->flags & SSL_AL_FLAG_SESSION_RESUMED) {
        json_object_set_new(js, "session_resumed", json_boolean(true));
    }
}

static void JsonTlsLogFingerprint(json_t *js, SSLState *ssl_state)
{
    json_object_set_new(js, "fingerprint",
                        json_string(ssl_state->server_connp.cert0_fingerprint));
}

static void JsonTlsLogSni(json_t *js, SSLState *ssl_state)
{
    if (ssl_state->client_connp.sni) {
        json_object_set_new(js, "sni",
                            json_string(ssl_state->client_connp.sni));
    }
}

static void JsonTlsLogSerial(json_t *js, SSLState *ssl_state)
{
    if (ssl_state->server_connp.cert0_serial) {
        json_object_set_new(js, "serial",
                            json_string(ssl_state->server_connp.cert0_serial));
    }
}

static void JsonTlsLogVersion(json_t *js, SSLState *ssl_state)
{
    char ssl_version[SSL_VERSION_LENGTH + 1];

    switch (ssl_state->server_connp.version) {
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
                     ssl_state->server_connp.version);
            break;
    }
    json_object_set_new(js, "version", json_string(ssl_version));
}

static void JsonTlsLogNotBefore(json_t *js, SSLState *ssl_state)
{
    if (ssl_state->server_connp.cert0_not_before != 0) {
        char timebuf[64];
        struct timeval tv;
        tv.tv_sec = ssl_state->server_connp.cert0_not_before;
        tv.tv_usec = 0;
        CreateUtcIsoTimeString(&tv, timebuf, sizeof(timebuf));
        json_object_set_new(js, "notbefore", json_string(timebuf));
    }
}

static void JsonTlsLogNotAfter(json_t *js, SSLState *ssl_state)
{
    if (ssl_state->server_connp.cert0_not_after != 0) {
        char timebuf[64];
        struct timeval tv;
        tv.tv_sec = ssl_state->server_connp.cert0_not_after;
        tv.tv_usec = 0;
        CreateUtcIsoTimeString(&tv, timebuf, sizeof(timebuf));
       json_object_set_new(js, "notafter", json_string(timebuf));
    }
}

static void JsonTlsLogCertificate(json_t *js, SSLState *ssl_state)
{
    if ((ssl_state->server_connp.cert_input == NULL) ||
            (ssl_state->server_connp.cert_input_len == 0)) {
        return;
    }

    SSLCertsChain *cert = TAILQ_FIRST(&ssl_state->server_connp.certs);
    if (cert == NULL) {
        return;
    }

    unsigned long len = cert->cert_len * 2;
    uint8_t encoded[len];
    if (Base64Encode(cert->cert_data, cert->cert_len, encoded, &len) ==
                     SC_BASE64_OK) {
        json_object_set_new(js, "certificate", json_string((char *)encoded));
    }
}

static void JsonTlsLogChain(json_t *js, SSLState *ssl_state)
{
    if ((ssl_state->server_connp.cert_input == NULL) ||
            (ssl_state->server_connp.cert_input_len == 0)) {
        return;
    }

    json_t *chain = json_array();
    if (chain == NULL) {
        return;
    }

    SSLCertsChain *cert;
    TAILQ_FOREACH(cert, &ssl_state->server_connp.certs, next) {
        unsigned long len = cert->cert_len * 2;
        uint8_t encoded[len];
        if (Base64Encode(cert->cert_data, cert->cert_len, encoded, &len) ==
                         SC_BASE64_OK) {
            json_array_append_new(chain, json_string((char *)encoded));
        }
    }

    json_object_set_new(js, "chain", chain);
}

void JsonTlsLogJSONBasic(json_t *js, SSLState *ssl_state)
{
    /* tls subject */
    JsonTlsLogSubject(js, ssl_state);

    /* tls issuerdn */
    JsonTlsLogIssuer(js, ssl_state);

    /* tls session resumption */
    JsonTlsLogSessionResumed(js, ssl_state);
}

static void JsonTlsLogJSONCustom(OutputTlsCtx *tls_ctx, json_t *js,
                                 SSLState *ssl_state)
{
    /* tls subject */
    if (tls_ctx->fields & LOG_TLS_FIELD_SUBJECT)
        JsonTlsLogSubject(js, ssl_state);

    /* tls issuerdn */
    if (tls_ctx->fields & LOG_TLS_FIELD_ISSUER)
        JsonTlsLogIssuer(js, ssl_state);

    /* tls session resumption */
    if (tls_ctx->fields & LOG_TLS_FIELD_SESSION_RESUMED)
        JsonTlsLogSessionResumed(js, ssl_state);

    /* tls serial */
    if (tls_ctx->fields & LOG_TLS_FIELD_SERIAL)
        JsonTlsLogSerial(js, ssl_state);

    /* tls fingerprint */
    if (tls_ctx->fields & LOG_TLS_FIELD_FINGERPRINT)
        JsonTlsLogFingerprint(js, ssl_state);

    /* tls sni */
    if (tls_ctx->fields & LOG_TLS_FIELD_SNI)
        JsonTlsLogSni(js, ssl_state);

    /* tls version */
    if (tls_ctx->fields & LOG_TLS_FIELD_VERSION)
        JsonTlsLogVersion(js, ssl_state);

    /* tls notbefore */
    if (tls_ctx->fields & LOG_TLS_FIELD_NOTBEFORE)
        JsonTlsLogNotBefore(js, ssl_state);

    /* tls notafter */
    if (tls_ctx->fields & LOG_TLS_FIELD_NOTAFTER)
        JsonTlsLogNotAfter(js, ssl_state);

    /* tls certificate */
    if (tls_ctx->fields & LOG_TLS_FIELD_CERTIFICATE)
        JsonTlsLogCertificate(js, ssl_state);

    /* tls chain */
    if (tls_ctx->fields & LOG_TLS_FIELD_CHAIN)
        JsonTlsLogChain(js, ssl_state);
}

void JsonTlsLogJSONExtended(json_t *tjs, SSLState * state)
{
    JsonTlsLogJSONBasic(tjs, state);

    /* tls serial */
    JsonTlsLogSerial(tjs, state);

    /* tls fingerprint */
    JsonTlsLogFingerprint(tjs, state);

    /* tls sni */
    JsonTlsLogSni(tjs, state);

    /* tls version */
    JsonTlsLogVersion(tjs, state);

    /* tls notbefore */
    JsonTlsLogNotBefore(tjs, state);

    /* tls notafter */
    JsonTlsLogNotAfter(tjs, state);
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

    if ((ssl_state->server_connp.cert0_issuerdn == NULL ||
            ssl_state->server_connp.cert0_subject == NULL) &&
            ((ssl_state->flags & SSL_AL_FLAG_SESSION_RESUMED) == 0 ||
            (tls_ctx->flags & LOG_TLS_SESSION_RESUMPTION) == 0)) {
        return 0;
    }

    json_t *js = CreateJSONHeader((Packet *)p, 1, "tls");
    if (unlikely(js == NULL)) {
        return 0;
    }

    json_t *tjs = json_object();
    if (tjs == NULL) {
        free(js);
        return 0;
    }

    /* reset */
    MemBufferReset(aft->buffer);

    /* log custom fields */
    if (tls_ctx->flags & LOG_TLS_CUSTOM) {
        JsonTlsLogJSONCustom(tls_ctx, tjs, ssl_state);
    }
    /* log extended */
    else if (tls_ctx->flags & LOG_TLS_EXTENDED) {
        JsonTlsLogJSONExtended(tjs, ssl_state);
    }
    /* log basic */
    else {
        JsonTlsLogJSONBasic(tjs, ssl_state);
    }

    /* print original application level protocol when it have been changed
       because of STARTTLS, HTTP CONNECT, or similar. */
    if (f->alproto_orig != ALPROTO_UNKNOWN) {
        json_object_set_new(tjs, "from_proto",
                json_string(AppLayerGetProtoName(f->alproto_orig)));
    }

    json_object_set_new(js, "tls", tjs);

    OutputJSONBuffer(js, tls_ctx->file_ctx, &aft->buffer);
    json_object_clear(js);
    json_decref(js);

    return 0;
}

static TmEcode JsonTlsLogThreadInit(ThreadVars *t, const void *initdata, void **data)
{
    JsonTlsLogThread *aft = SCMalloc(sizeof(JsonTlsLogThread));
    if (unlikely(aft == NULL)) {
        return TM_ECODE_FAILED;
    }

    memset(aft, 0, sizeof(JsonTlsLogThread));

    if (initdata == NULL) {
        SCLogDebug("Error getting context for eve-log tls 'initdata' argument NULL");
        SCFree(aft);
        return TM_ECODE_FAILED;
    }

    /* use the Output Context (file pointer and mutex) */
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

static OutputTlsCtx *OutputTlsInitCtx(ConfNode *conf)
{
    OutputTlsCtx *tls_ctx = SCMalloc(sizeof(OutputTlsCtx));
    if (unlikely(tls_ctx == NULL))
        return NULL;

    tls_ctx->flags = LOG_TLS_DEFAULT;
    tls_ctx->fields = 0;

    if (conf == NULL)
        return tls_ctx;

    const char *extended = ConfNodeLookupChildValue(conf, "extended");
    if (extended) {
        if (ConfValIsTrue(extended)) {
            tls_ctx->flags = LOG_TLS_EXTENDED;
        }
    }

    ConfNode *custom = ConfNodeLookupChild(conf, "custom");
    if (custom) {
        tls_ctx->flags = LOG_TLS_CUSTOM;
        ConfNode *field;
        TAILQ_FOREACH(field, &custom->head, next)
        {
            TlsFields *valid_fields = tls_fields;
            for ( ; valid_fields->name != NULL; valid_fields++) {
                if (strcasecmp(field->val, valid_fields->name) == 0) {
                    tls_ctx->fields |= valid_fields->flag;
                    break;
                }
            }
        }
    }

    const char *session_resumption = ConfNodeLookupChildValue(conf, "session-resumption");
    if (session_resumption == NULL || ConfValIsTrue(session_resumption)) {
        tls_ctx->flags |= LOG_TLS_SESSION_RESUMPTION;
    }

    if ((tls_ctx->fields & LOG_TLS_FIELD_CERTIFICATE) &&
            (tls_ctx->fields & LOG_TLS_FIELD_CHAIN)) {
        SCLogWarning(SC_WARN_DUPLICATE_OUTPUT,
                     "Both 'certificate' and 'chain' contains the top "
                     "certificate, so only one of them should be enabled "
                     "at a time");
    }

    return tls_ctx;
}

static OutputCtx *OutputTlsLogInit(ConfNode *conf)
{
    LogFileCtx *file_ctx = LogFileNewCtx();
    if (file_ctx == NULL) {
        SCLogError(SC_ERR_TLS_LOG_GENERIC, "couldn't create new file_ctx");
        return NULL;
    }

    if (SCConfLogOpenGeneric(conf, file_ctx, DEFAULT_LOG_FILENAME, 1) < 0) {
        LogFileFreeCtx(file_ctx);
        return NULL;
    }

    OutputTlsCtx *tls_ctx = OutputTlsInitCtx(conf);
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

static OutputCtx *OutputTlsLogInitSub(ConfNode *conf, OutputCtx *parent_ctx)
{
    OutputJsonCtx *ojc = parent_ctx->data;

    OutputTlsCtx *tls_ctx = OutputTlsInitCtx(conf);
    if (unlikely(tls_ctx == NULL))
        return NULL;

    OutputCtx *output_ctx = SCCalloc(1, sizeof(OutputCtx));
    if (unlikely(output_ctx == NULL)) {
        SCFree(tls_ctx);
        return NULL;
    }

    tls_ctx->file_ctx = ojc->file_ctx;

    if ((tls_ctx->fields & LOG_TLS_FIELD_CERTIFICATE) &&
            (tls_ctx->fields & LOG_TLS_FIELD_CHAIN)) {
        SCLogWarning(SC_WARN_DUPLICATE_OUTPUT,
                     "Both 'certificate' and 'chain' contains the top "
                     "certificate, so only one of them should be enabled "
                     "at a time");
    }

    output_ctx->data = tls_ctx;
    output_ctx->DeInit = OutputTlsLogDeinitSub;

    AppLayerParserRegisterLogger(IPPROTO_TCP, ALPROTO_TLS);

    return output_ctx;
}

void JsonTlsLogRegister (void)
{
    /* register as separate module */
    OutputRegisterTxModuleWithProgress(LOGGER_JSON_TLS, "JsonTlsLog",
        "tls-json-log", OutputTlsLogInit, ALPROTO_TLS, JsonTlsLogger,
        TLS_HANDSHAKE_DONE, TLS_HANDSHAKE_DONE, JsonTlsLogThreadInit,
        JsonTlsLogThreadDeinit, NULL);

    /* also register as child of eve-log */
    OutputRegisterTxSubModuleWithProgress(LOGGER_JSON_TLS, "eve-log",
        "JsonTlsLog", "eve-log.tls", OutputTlsLogInitSub, ALPROTO_TLS,
        JsonTlsLogger, TLS_HANDSHAKE_DONE, TLS_HANDSHAKE_DONE,
        JsonTlsLogThreadInit, JsonTlsLogThreadDeinit, NULL);
}

#else

void JsonTlsLogRegister (void)
{
}

#endif /* HAVE_LIBJANSSON */

