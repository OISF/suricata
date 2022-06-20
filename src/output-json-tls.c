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
#include "util-time.h"
#include "util-unittest.h"

#include "util-debug.h"
#include "app-layer-parser.h"
#include "output.h"
#include "app-layer-ssl.h"
#include "app-layer.h"
#include "util-privs.h"
#include "util-buffer.h"

#include "util-logopenfile.h"
#include "util-ja3.h"

#include "output-json.h"
#include "output-json-tls.h"

SC_ATOMIC_EXTERN(unsigned int, cert_id);

#define MODULE_NAME "LogTlsLog"
#define DEFAULT_LOG_FILENAME "tls.json"

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
#define LOG_TLS_FIELD_JA3               (1 << 11)
#define LOG_TLS_FIELD_JA3S              (1 << 12)

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
    { "ja3",             LOG_TLS_FIELD_JA3 },
    { "ja3s",            LOG_TLS_FIELD_JA3S },
    { NULL,              -1 }
};

typedef struct OutputTlsCtx_ {
    uint32_t flags;  /** Store mode */
    uint64_t fields; /** Store fields */
    OutputJsonCtx *eve_ctx;
} OutputTlsCtx;


typedef struct JsonTlsLogThread_ {
    OutputTlsCtx *tlslog_ctx;
    OutputJsonThreadCtx *ctx;
} JsonTlsLogThread;

static void JsonTlsLogSubject(JsonBuilder *js, SSLState *ssl_state)
{
    if (ssl_state->server_connp.cert0_subject) {
        jb_set_string(js, "subject",
                            ssl_state->server_connp.cert0_subject);
    }
}

static void JsonTlsLogIssuer(JsonBuilder *js, SSLState *ssl_state)
{
    if (ssl_state->server_connp.cert0_issuerdn) {
        jb_set_string(js, "issuerdn",
                            ssl_state->server_connp.cert0_issuerdn);
    }
}

static void JsonTlsLogSessionResumed(JsonBuilder *js, SSLState *ssl_state)
{
    if (ssl_state->flags & SSL_AL_FLAG_SESSION_RESUMED) {
        /* Only log a session as 'resumed' if a certificate has not
           been seen, and the session is not TLSv1.3 or later. */
        if ((ssl_state->server_connp.cert0_issuerdn == NULL &&
               ssl_state->server_connp.cert0_subject == NULL) &&
               (ssl_state->flags & SSL_AL_FLAG_STATE_SERVER_HELLO) &&
               ((ssl_state->flags & SSL_AL_FLAG_LOG_WITHOUT_CERT) == 0)) {
            jb_set_bool(js, "session_resumed", true);
        }
    }
}

static void JsonTlsLogFingerprint(JsonBuilder *js, SSLState *ssl_state)
{
    if (ssl_state->server_connp.cert0_fingerprint) {
        jb_set_string(js, "fingerprint",
                ssl_state->server_connp.cert0_fingerprint);
    }
}

static void JsonTlsLogSni(JsonBuilder *js, SSLState *ssl_state)
{
    if (ssl_state->client_connp.sni) {
        jb_set_string(js, "sni",
                            ssl_state->client_connp.sni);
    }
}

static void JsonTlsLogSerial(JsonBuilder *js, SSLState *ssl_state)
{
    if (ssl_state->server_connp.cert0_serial) {
        jb_set_string(js, "serial",
                            ssl_state->server_connp.cert0_serial);
    }
}

static void JsonTlsLogVersion(JsonBuilder *js, SSLState *ssl_state)
{
    char ssl_version[SSL_VERSION_MAX_STRLEN];
    SSLVersionToString(ssl_state->server_connp.version, ssl_version);
    jb_set_string(js, "version", ssl_version);
}

static void JsonTlsLogNotBefore(JsonBuilder *js, SSLState *ssl_state)
{
    if (ssl_state->server_connp.cert0_not_before != 0) {
        char timebuf[64];
        struct timeval tv;
        tv.tv_sec = ssl_state->server_connp.cert0_not_before;
        tv.tv_usec = 0;
        CreateUtcIsoTimeString(&tv, timebuf, sizeof(timebuf));
        jb_set_string(js, "notbefore", timebuf);
    }
}

static void JsonTlsLogNotAfter(JsonBuilder *js, SSLState *ssl_state)
{
    if (ssl_state->server_connp.cert0_not_after != 0) {
        char timebuf[64];
        struct timeval tv;
        tv.tv_sec = ssl_state->server_connp.cert0_not_after;
        tv.tv_usec = 0;
        CreateUtcIsoTimeString(&tv, timebuf, sizeof(timebuf));
        jb_set_string(js, "notafter", timebuf);
    }
}

static void JsonTlsLogJa3Hash(JsonBuilder *js, SSLState *ssl_state)
{
    if (ssl_state->client_connp.ja3_hash != NULL) {
        jb_set_string(js, "hash",
                            ssl_state->client_connp.ja3_hash);
    }
}

static void JsonTlsLogJa3String(JsonBuilder *js, SSLState *ssl_state)
{
    if ((ssl_state->client_connp.ja3_str != NULL) &&
            ssl_state->client_connp.ja3_str->data != NULL) {
        jb_set_string(js, "string",
                            ssl_state->client_connp.ja3_str->data);
    }
}

static void JsonTlsLogJa3(JsonBuilder *js, SSLState *ssl_state)
{
    if ((ssl_state->client_connp.ja3_hash != NULL) ||
            ((ssl_state->client_connp.ja3_str != NULL) &&
                    ssl_state->client_connp.ja3_str->data != NULL)) {
        jb_open_object(js, "ja3");

        JsonTlsLogJa3Hash(js, ssl_state);
        JsonTlsLogJa3String(js, ssl_state);

        jb_close(js);
    }
}

static void JsonTlsLogJa3SHash(JsonBuilder *js, SSLState *ssl_state)
{
    if (ssl_state->server_connp.ja3_hash != NULL) {
        jb_set_string(js, "hash",
                            ssl_state->server_connp.ja3_hash);
    }
}

static void JsonTlsLogJa3SString(JsonBuilder *js, SSLState *ssl_state)
{
    if ((ssl_state->server_connp.ja3_str != NULL) &&
            ssl_state->server_connp.ja3_str->data != NULL) {
        jb_set_string(js, "string",
                            ssl_state->server_connp.ja3_str->data);
    }
}

static void JsonTlsLogJa3S(JsonBuilder *js, SSLState *ssl_state)
{
    if ((ssl_state->server_connp.ja3_hash != NULL) ||
            ((ssl_state->server_connp.ja3_str != NULL) &&
                    ssl_state->server_connp.ja3_str->data != NULL)) {
        jb_open_object(js, "ja3s");

        JsonTlsLogJa3SHash(js, ssl_state);
        JsonTlsLogJa3SString(js, ssl_state);

        jb_close(js);
    }
}

static void JsonTlsLogCertificate(JsonBuilder *js, SSLState *ssl_state)
{
    if (TAILQ_EMPTY(&ssl_state->server_connp.certs)) {
        return;
    }

    SSLCertsChain *cert = TAILQ_FIRST(&ssl_state->server_connp.certs);
    if (cert == NULL) {
        return;
    }

    jb_set_base64(js, "certificate", cert->cert_data, cert->cert_len);
}

static void JsonTlsLogChain(JsonBuilder *js, SSLState *ssl_state)
{
    if (TAILQ_EMPTY(&ssl_state->server_connp.certs)) {
        return;
    }

    jb_open_array(js, "chain");

    SSLCertsChain *cert;
    TAILQ_FOREACH(cert, &ssl_state->server_connp.certs, next) {
        jb_append_base64(js, cert->cert_data, cert->cert_len);
    }

    jb_close(js);
}

void JsonTlsLogJSONBasic(JsonBuilder *js, SSLState *ssl_state)
{
    /* tls subject */
    JsonTlsLogSubject(js, ssl_state);

    /* tls issuerdn */
    JsonTlsLogIssuer(js, ssl_state);

    /* tls session resumption */
    JsonTlsLogSessionResumed(js, ssl_state);
}

static void JsonTlsLogJSONCustom(OutputTlsCtx *tls_ctx, JsonBuilder *js,
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

    /* tls ja3_hash */
    if (tls_ctx->fields & LOG_TLS_FIELD_JA3)
        JsonTlsLogJa3(js, ssl_state);

    /* tls ja3s */
    if (tls_ctx->fields & LOG_TLS_FIELD_JA3S)
        JsonTlsLogJa3S(js, ssl_state);
}

void JsonTlsLogJSONExtended(JsonBuilder *tjs, SSLState * state)
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

    /* tls ja3 */
    JsonTlsLogJa3(tjs, state);

    /* tls ja3s */
    JsonTlsLogJa3S(tjs, state);
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
            (tls_ctx->flags & LOG_TLS_SESSION_RESUMPTION) == 0) &&
            ((ssl_state->flags & SSL_AL_FLAG_LOG_WITHOUT_CERT) == 0)) {
        return 0;
    }

    JsonBuilder *js = CreateEveHeader(p, LOG_DIR_FLOW, "tls", NULL, aft->tlslog_ctx->eve_ctx);
    if (unlikely(js == NULL)) {
        return 0;
    }

    jb_open_object(js, "tls");

    /* log custom fields */
    if (tls_ctx->flags & LOG_TLS_CUSTOM) {
        JsonTlsLogJSONCustom(tls_ctx, js, ssl_state);
    }
    /* log extended */
    else if (tls_ctx->flags & LOG_TLS_EXTENDED) {
        JsonTlsLogJSONExtended(js, ssl_state);
    }
    /* log basic */
    else {
        JsonTlsLogJSONBasic(js, ssl_state);
    }

    /* print original application level protocol when it have been changed
       because of STARTTLS, HTTP CONNECT, or similar. */
    if (f->alproto_orig != ALPROTO_UNKNOWN) {
        jb_set_string(js, "from_proto",
                AppLayerGetProtoName(f->alproto_orig));
    }

    /* Close the tls object. */
    jb_close(js);

    OutputJsonBuilderBuffer(js, aft->ctx);
    jb_free(js);

    return 0;
}

static TmEcode JsonTlsLogThreadInit(ThreadVars *t, const void *initdata, void **data)
{
    JsonTlsLogThread *aft = SCCalloc(1, sizeof(JsonTlsLogThread));
    if (unlikely(aft == NULL)) {
        return TM_ECODE_FAILED;
    }

    if (initdata == NULL) {
        SCLogDebug("Error getting context for eve-log tls 'initdata' argument NULL");
        goto error_exit;
    }

    /* use the Output Context (file pointer and mutex) */
    aft->tlslog_ctx = ((OutputCtx *)initdata)->data;

    aft->ctx = CreateEveThreadCtx(t, aft->tlslog_ctx->eve_ctx);
    if (!aft->ctx) {
        goto error_exit;
    }
    *data = (void *)aft;
    return TM_ECODE_OK;

error_exit:
    SCFree(aft);
    return TM_ECODE_FAILED;
}

static TmEcode JsonTlsLogThreadDeinit(ThreadVars *t, void *data)
{
    JsonTlsLogThread *aft = (JsonTlsLogThread *)data;
    if (aft == NULL) {
        return TM_ECODE_OK;
    }

    FreeEveThreadCtx(aft->ctx);

    /* clear memory */
    memset(aft, 0, sizeof(JsonTlsLogThread));

    SCFree(aft);
    return TM_ECODE_OK;
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

    if ((tls_ctx->fields & LOG_TLS_FIELD_JA3) &&
            Ja3IsDisabled("fields")) {
        /* JA3 is disabled, so don't log any JA3 fields */
        tls_ctx->fields &= ~LOG_TLS_FIELD_JA3;
        tls_ctx->fields &= ~LOG_TLS_FIELD_JA3S;
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

static void OutputTlsLogDeinitSub(OutputCtx *output_ctx)
{
    OutputTlsCtx *tls_ctx = output_ctx->data;
    SCFree(tls_ctx);
    SCFree(output_ctx);
}

static OutputInitResult OutputTlsLogInitSub(ConfNode *conf, OutputCtx *parent_ctx)
{
    OutputInitResult result = { NULL, false };
    OutputJsonCtx *ojc = parent_ctx->data;

    OutputTlsCtx *tls_ctx = OutputTlsInitCtx(conf);
    if (unlikely(tls_ctx == NULL))
        return result;

    OutputCtx *output_ctx = SCCalloc(1, sizeof(OutputCtx));
    if (unlikely(output_ctx == NULL)) {
        SCFree(tls_ctx);
        return result;
    }

    tls_ctx->eve_ctx = ojc;

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

    result.ctx = output_ctx;
    result.ok = true;
    return result;
}

void JsonTlsLogRegister (void)
{
    /* register as child of eve-log */
    OutputRegisterTxSubModuleWithProgress(LOGGER_JSON_TLS, "eve-log",
        "JsonTlsLog", "eve-log.tls", OutputTlsLogInitSub, ALPROTO_TLS,
        JsonTlsLogger, TLS_HANDSHAKE_DONE, TLS_HANDSHAKE_DONE,
        JsonTlsLogThreadInit, JsonTlsLogThreadDeinit, NULL);
}
