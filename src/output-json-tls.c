/* Copyright (C) 2007-2024 Open Information Security Foundation
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

#include "app-layer-parser.h"
#include "app-layer-ssl.h"
#include "app-layer.h"
#include "conf.h"
#include "output-json-tls.h"
#include "output-json.h"
#include "output.h"
#include "threadvars.h"
#include "util-debug.h"
#include "util-ja3.h"
#include "util-time.h"

#define LOG_TLS_FIELD_VERSION          BIT_U64(0)
#define LOG_TLS_FIELD_SUBJECT          BIT_U64(1)
#define LOG_TLS_FIELD_ISSUER           BIT_U64(2)
#define LOG_TLS_FIELD_SERIAL           BIT_U64(3)
#define LOG_TLS_FIELD_FINGERPRINT      BIT_U64(4)
#define LOG_TLS_FIELD_NOTBEFORE        BIT_U64(5)
#define LOG_TLS_FIELD_NOTAFTER         BIT_U64(6)
#define LOG_TLS_FIELD_SNI              BIT_U64(7)
#define LOG_TLS_FIELD_CERTIFICATE      BIT_U64(8)
#define LOG_TLS_FIELD_CHAIN            BIT_U64(9)
#define LOG_TLS_FIELD_SESSION_RESUMED  BIT_U64(10)
#define LOG_TLS_FIELD_JA3              BIT_U64(11)
#define LOG_TLS_FIELD_JA3S             BIT_U64(12)
#define LOG_TLS_FIELD_CLIENT           BIT_U64(13) /**< client fields (issuer, subject, etc) */
#define LOG_TLS_FIELD_CLIENT_CERT      BIT_U64(14)
#define LOG_TLS_FIELD_CLIENT_CHAIN     BIT_U64(15)
#define LOG_TLS_FIELD_JA4              BIT_U64(16)
#define LOG_TLS_FIELD_SUBJECTALTNAME   BIT_U64(17)
#define LOG_TLS_FIELD_CLIENT_ALPNS     BIT_U64(18)
#define LOG_TLS_FIELD_SERVER_ALPNS     BIT_U64(19)
#define LOG_TLS_FIELD_CLIENT_HANDSHAKE BIT_U64(20)
#define LOG_TLS_FIELD_SERVER_HANDSHAKE BIT_U64(21)

typedef struct {
    const char *name;
    uint64_t flag;
} TlsFields;

TlsFields tls_fields[] = {
    // clang-format off
    { "version", LOG_TLS_FIELD_VERSION },
    { "subject", LOG_TLS_FIELD_SUBJECT },
    { "issuer", LOG_TLS_FIELD_ISSUER },
    { "serial", LOG_TLS_FIELD_SERIAL },
    { "fingerprint", LOG_TLS_FIELD_FINGERPRINT },
    { "not_before", LOG_TLS_FIELD_NOTBEFORE },
    { "not_after", LOG_TLS_FIELD_NOTAFTER },
    { "sni", LOG_TLS_FIELD_SNI },
    { "certificate", LOG_TLS_FIELD_CERTIFICATE },
    { "chain", LOG_TLS_FIELD_CHAIN },
    { "session_resumed", LOG_TLS_FIELD_SESSION_RESUMED },
    { "ja3", LOG_TLS_FIELD_JA3 },
    { "ja3s", LOG_TLS_FIELD_JA3S },
    { "client", LOG_TLS_FIELD_CLIENT },
    { "client_certificate", LOG_TLS_FIELD_CLIENT_CERT },
    { "client_chain", LOG_TLS_FIELD_CLIENT_CHAIN },
    // accept if as nop if we do not HAVE_JA4
    { "ja4", LOG_TLS_FIELD_JA4 },
    { "subjectaltname", LOG_TLS_FIELD_SUBJECTALTNAME },
    { "client_alpns", LOG_TLS_FIELD_CLIENT_ALPNS },
    { "server_alpns", LOG_TLS_FIELD_SERVER_ALPNS },
    { "client_handshake", LOG_TLS_FIELD_CLIENT_HANDSHAKE },
    { "server_handshake", LOG_TLS_FIELD_SERVER_HANDSHAKE },
    { NULL, -1 },
    // clang-format on
};

// clang-format off
#define BASIC_FIELDS                            \
    (LOG_TLS_FIELD_SUBJECT |                    \
     LOG_TLS_FIELD_ISSUER |                     \
     LOG_TLS_FIELD_SUBJECTALTNAME)
// clang-format on

// clang-format off
#define EXTENDED_FIELDS                         \
    (BASIC_FIELDS |                             \
     LOG_TLS_FIELD_VERSION |                    \
     LOG_TLS_FIELD_SERIAL |                     \
     LOG_TLS_FIELD_FINGERPRINT |                \
     LOG_TLS_FIELD_NOTBEFORE |                  \
     LOG_TLS_FIELD_NOTAFTER |                   \
     LOG_TLS_FIELD_JA3 |                        \
     LOG_TLS_FIELD_JA3S |                       \
     LOG_TLS_FIELD_JA4 |                        \
     LOG_TLS_FIELD_CLIENT |                     \
     LOG_TLS_FIELD_CLIENT_ALPNS |               \
     LOG_TLS_FIELD_SERVER_ALPNS |               \
     LOG_TLS_FIELD_SNI)
// clang-format on

typedef struct OutputTlsCtx_ {
    uint64_t fields; /** Store fields */
    bool session_resumed;
    OutputJsonCtx *eve_ctx;
} OutputTlsCtx;

typedef struct JsonTlsLogThread_ {
    OutputTlsCtx *tlslog_ctx;
    OutputJsonThreadCtx *ctx;
} JsonTlsLogThread;

static void JsonTlsLogSubject(SCJsonBuilder *js, SSLState *ssl_state)
{
    if (ssl_state->server_connp.cert0_subject) {
        SCJbSetString(js, "subject", ssl_state->server_connp.cert0_subject);
    }
}

static void JsonTlsLogIssuer(SCJsonBuilder *js, SSLState *ssl_state)
{
    if (ssl_state->server_connp.cert0_issuerdn) {
        SCJbSetString(js, "issuerdn", ssl_state->server_connp.cert0_issuerdn);
    }
}

static void JsonTlsLogSAN(SCJsonBuilder *js, SSLState *ssl_state)
{
    if (ssl_state->server_connp.cert0_sans_len > 0) {
        SCJbOpenArray(js, "subjectaltname");
        for (uint16_t i = 0; i < ssl_state->server_connp.cert0_sans_len; i++) {
            SCJbAppendString(js, ssl_state->server_connp.cert0_sans[i]);
        }
        SCJbClose(js);
    }
}

static void JsonTlsLogSessionResumed(SCJsonBuilder *js, SSLState *ssl_state)
{
    if (ssl_state->flags & SSL_AL_FLAG_SESSION_RESUMED) {
        /* Only log a session as 'resumed' if a certificate has not
           been seen, and the session is not TLSv1.3 or later. */
        if ((ssl_state->server_connp.cert0_issuerdn == NULL &&
               ssl_state->server_connp.cert0_subject == NULL) &&
               (ssl_state->flags & SSL_AL_FLAG_STATE_SERVER_HELLO) &&
               ((ssl_state->flags & SSL_AL_FLAG_LOG_WITHOUT_CERT) == 0)) {
            SCJbSetBool(js, "session_resumed", true);
        }
    }
}

static void JsonTlsLogFingerprint(SCJsonBuilder *js, SSLState *ssl_state)
{
    if (ssl_state->server_connp.cert0_fingerprint) {
        SCJbSetString(js, "fingerprint", ssl_state->server_connp.cert0_fingerprint);
    }
}

static void JsonTlsLogSni(SCJsonBuilder *js, SSLState *ssl_state)
{
    if (ssl_state->client_connp.sni) {
        SCJbSetString(js, "sni", ssl_state->client_connp.sni);
    }
}

static void JsonTlsLogSerial(SCJsonBuilder *js, SSLState *ssl_state)
{
    if (ssl_state->server_connp.cert0_serial) {
        SCJbSetString(js, "serial", ssl_state->server_connp.cert0_serial);
    }
}

static void JsonTlsLogVersion(SCJsonBuilder *js, SSLState *ssl_state)
{
    char ssl_version[SSL_VERSION_MAX_STRLEN];
    SSLVersionToString(ssl_state->server_connp.version, ssl_version);
    SCJbSetString(js, "version", ssl_version);
}

static void JsonTlsLogNotBefore(SCJsonBuilder *js, SSLState *ssl_state)
{
    if (ssl_state->server_connp.cert0_not_before != 0) {
        sc_x509_log_timestamp(js, "notbefore", ssl_state->server_connp.cert0_not_before);
    }
}

static void JsonTlsLogNotAfter(SCJsonBuilder *js, SSLState *ssl_state)
{
    if (ssl_state->server_connp.cert0_not_after != 0) {
        sc_x509_log_timestamp(js, "notafter", ssl_state->server_connp.cert0_not_after);
    }
}

static void JsonTlsLogJa3Hash(SCJsonBuilder *js, SSLState *ssl_state)
{
    if (ssl_state->client_connp.ja3_hash != NULL) {
        SCJbSetString(js, "hash", ssl_state->client_connp.ja3_hash);
    }
}

static void JsonTlsLogJa3String(SCJsonBuilder *js, SSLState *ssl_state)
{
    if ((ssl_state->client_connp.ja3_str != NULL) &&
            ssl_state->client_connp.ja3_str->data != NULL) {
        SCJbSetString(js, "string", ssl_state->client_connp.ja3_str->data);
    }
}

static void JsonTlsLogJa3(SCJsonBuilder *js, SSLState *ssl_state)
{
    if ((ssl_state->client_connp.ja3_hash != NULL) ||
            ((ssl_state->client_connp.ja3_str != NULL) &&
                    ssl_state->client_connp.ja3_str->data != NULL)) {
        SCJbOpenObject(js, "ja3");

        JsonTlsLogJa3Hash(js, ssl_state);
        JsonTlsLogJa3String(js, ssl_state);

        SCJbClose(js);
    }
}

static void JsonTlsLogSCJA4(SCJsonBuilder *js, SSLState *ssl_state)
{
#ifdef HAVE_JA4
    if (ssl_state->client_connp.hs != NULL) {
        uint8_t buffer[JA4_HEX_LEN];
        /* JA4 hash has 36 characters */
        SCJA4GetHash(ssl_state->client_connp.hs, (uint8_t(*)[JA4_HEX_LEN])buffer);
        SCJbSetStringFromBytes(js, "ja4", buffer, JA4_HEX_LEN);
    }
#endif
}

static void JsonTlsLogJa3SHash(SCJsonBuilder *js, SSLState *ssl_state)
{
    if (ssl_state->server_connp.ja3_hash != NULL) {
        SCJbSetString(js, "hash", ssl_state->server_connp.ja3_hash);
    }
}

static void JsonTlsLogJa3SString(SCJsonBuilder *js, SSLState *ssl_state)
{
    if ((ssl_state->server_connp.ja3_str != NULL) &&
            ssl_state->server_connp.ja3_str->data != NULL) {
        SCJbSetString(js, "string", ssl_state->server_connp.ja3_str->data);
    }
}

static void JsonTlsLogJa3S(SCJsonBuilder *js, SSLState *ssl_state)
{
    if ((ssl_state->server_connp.ja3_hash != NULL) ||
            ((ssl_state->server_connp.ja3_str != NULL) &&
                    ssl_state->server_connp.ja3_str->data != NULL)) {
        SCJbOpenObject(js, "ja3s");

        JsonTlsLogJa3SHash(js, ssl_state);
        JsonTlsLogJa3SString(js, ssl_state);

        SCJbClose(js);
    }
}

static void JsonTlsLogAlpns(SCJsonBuilder *js, SSLStateConnp *connp, const char *object)
{
    if (connp->hs == NULL) {
        return;
    }

    if (SCTLSHandshakeIsEmpty(connp->hs)) {
        return;
    }
    SCTLSHandshakeLogALPNs(connp->hs, js, object);
}

static void JsonTlsLogCertificate(SCJsonBuilder *js, SSLStateConnp *connp)
{
    if (TAILQ_EMPTY(&connp->certs)) {
        return;
    }

    SSLCertsChain *cert = TAILQ_FIRST(&connp->certs);
    if (cert == NULL) {
        return;
    }

    SCJbSetBase64(js, "certificate", cert->cert_data, cert->cert_len);
}

static void JsonTlsLogChain(SCJsonBuilder *js, SSLStateConnp *connp)
{
    if (TAILQ_EMPTY(&connp->certs)) {
        return;
    }

    SCJbOpenArray(js, "chain");

    SSLCertsChain *cert;
    TAILQ_FOREACH (cert, &connp->certs, next) {
        SCJbAppendBase64(js, cert->cert_data, cert->cert_len);
    }

    SCJbClose(js);
}

static bool HasClientCert(SSLStateConnp *connp)
{
    if (connp->cert0_subject || connp->cert0_issuerdn)
        return true;
    return false;
}

static void JsonTlsLogClientCert(
        SCJsonBuilder *js, SSLStateConnp *connp, const bool log_cert, const bool log_chain)
{
    if (connp->cert0_subject != NULL) {
        SCJbSetString(js, "subject", connp->cert0_subject);
    }
    if (connp->cert0_issuerdn != NULL) {
        SCJbSetString(js, "issuerdn", connp->cert0_issuerdn);
    }
    if (connp->cert0_fingerprint) {
        SCJbSetString(js, "fingerprint", connp->cert0_fingerprint);
    }
    if (connp->cert0_serial) {
        SCJbSetString(js, "serial", connp->cert0_serial);
    }
    if (connp->cert0_not_before != 0) {
        char timebuf[64];
        SCTime_t ts = SCTIME_FROM_SECS(connp->cert0_not_before);
        CreateUtcIsoTimeString(ts, timebuf, sizeof(timebuf));
        SCJbSetString(js, "notbefore", timebuf);
    }
    if (connp->cert0_not_after != 0) {
        char timebuf[64];
        SCTime_t ts = SCTIME_FROM_SECS(connp->cert0_not_after);
        CreateUtcIsoTimeString(ts, timebuf, sizeof(timebuf));
        SCJbSetString(js, "notafter", timebuf);
    }

    if (log_cert) {
        JsonTlsLogCertificate(js, connp);
    }
    if (log_chain) {
        JsonTlsLogChain(js, connp);
    }
}

static void JsonTlsLogClientHandshake(SCJsonBuilder *js, SSLState *ssl_state)
{
    if (ssl_state->client_connp.hs == NULL) {
        return;
    }

    // Don't write an empty handshake
    if (SCTLSHandshakeIsEmpty(ssl_state->client_connp.hs)) {
        return;
    }

    SCJbOpenObject(js, "client_handshake");

    SCTLSHandshakeLogVersion(ssl_state->client_connp.hs, js);
    SCTLSHandshakeLogCiphers(ssl_state->client_connp.hs, js);
    SCTLSHandshakeLogExtensions(ssl_state->client_connp.hs, js);
    SCTLSHandshakeLogSigAlgs(ssl_state->client_connp.hs, js);

    SCJbClose(js);
}

static void JsonTlsLogServerHandshake(SCJsonBuilder *js, SSLState *ssl_state)
{
    if (ssl_state->server_connp.hs == NULL) {
        return;
    }

    if (SCTLSHandshakeIsEmpty(ssl_state->server_connp.hs)) {
        return;
    }

    SCJbOpenObject(js, "server_handshake");

    SCTLSHandshakeLogVersion(ssl_state->server_connp.hs, js);
    SCTLSHandshakeLogFirstCipher(ssl_state->server_connp.hs, js);
    SCTLSHandshakeLogExtensions(ssl_state->server_connp.hs, js);

    SCJbClose(js);
}

static void JsonTlsLogFields(SCJsonBuilder *js, SSLState *ssl_state, uint64_t fields)
{
    /* tls subject */
    if (fields & LOG_TLS_FIELD_SUBJECT)
        JsonTlsLogSubject(js, ssl_state);

    /* tls issuerdn */
    if (fields & LOG_TLS_FIELD_ISSUER)
        JsonTlsLogIssuer(js, ssl_state);

    /* tls subjectaltname */
    if (fields & LOG_TLS_FIELD_SUBJECTALTNAME)
        JsonTlsLogSAN(js, ssl_state);

    /* tls session resumption */
    if (fields & LOG_TLS_FIELD_SESSION_RESUMED)
        JsonTlsLogSessionResumed(js, ssl_state);

    /* tls serial */
    if (fields & LOG_TLS_FIELD_SERIAL)
        JsonTlsLogSerial(js, ssl_state);

    /* tls fingerprint */
    if (fields & LOG_TLS_FIELD_FINGERPRINT)
        JsonTlsLogFingerprint(js, ssl_state);

    /* tls sni */
    if (fields & LOG_TLS_FIELD_SNI)
        JsonTlsLogSni(js, ssl_state);

    /* tls version */
    if (fields & LOG_TLS_FIELD_VERSION) {
        JsonTlsLogVersion(js, ssl_state);
    }

    /* tls notbefore */
    if (fields & LOG_TLS_FIELD_NOTBEFORE)
        JsonTlsLogNotBefore(js, ssl_state);

    /* tls notafter */
    if (fields & LOG_TLS_FIELD_NOTAFTER)
        JsonTlsLogNotAfter(js, ssl_state);

    /* tls certificate */
    if (fields & LOG_TLS_FIELD_CERTIFICATE)
        JsonTlsLogCertificate(js, &ssl_state->server_connp);

    /* tls chain */
    if (fields & LOG_TLS_FIELD_CHAIN)
        JsonTlsLogChain(js, &ssl_state->server_connp);

    /* tls ja3_hash */
    if (fields & LOG_TLS_FIELD_JA3)
        JsonTlsLogJa3(js, ssl_state);

    /* tls ja3s */
    if (fields & LOG_TLS_FIELD_JA3S)
        JsonTlsLogJa3S(js, ssl_state);

    /* tls ja4 */
    if (fields & LOG_TLS_FIELD_JA4)
        JsonTlsLogSCJA4(js, ssl_state);

    if (fields & LOG_TLS_FIELD_CLIENT_ALPNS) {
        JsonTlsLogAlpns(js, &ssl_state->client_connp, "client_alpns");
    }

    if (fields & LOG_TLS_FIELD_SERVER_ALPNS) {
        JsonTlsLogAlpns(js, &ssl_state->server_connp, "server_alpns");
    }

    /* tls client handshake parameters */
    if (fields & LOG_TLS_FIELD_CLIENT_HANDSHAKE)
        JsonTlsLogClientHandshake(js, ssl_state);

    /* tls server handshake parameters */
    if (fields & LOG_TLS_FIELD_SERVER_HANDSHAKE)
        JsonTlsLogServerHandshake(js, ssl_state);

    if (fields & LOG_TLS_FIELD_CLIENT) {
        const bool log_cert = (fields & LOG_TLS_FIELD_CLIENT_CERT) != 0;
        const bool log_chain = (fields & LOG_TLS_FIELD_CLIENT_CHAIN) != 0;
        if (HasClientCert(&ssl_state->client_connp)) {
            SCJbOpenObject(js, "client");
            JsonTlsLogClientCert(js, &ssl_state->client_connp, log_cert, log_chain);
            SCJbClose(js);
        }
    }
}

bool JsonTlsLogJSONExtended(void *vtx, SCJsonBuilder *tjs)
{
    SSLState *state = (SSLState *)vtx;
    SCJbOpenObject(tjs, "tls");
    JsonTlsLogFields(tjs, state, EXTENDED_FIELDS);
    return SCJbClose(tjs);
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
                    (!tls_ctx->session_resumed)) &&
            ((ssl_state->flags & SSL_AL_FLAG_LOG_WITHOUT_CERT) == 0)) {
        return 0;
    }

    SCJsonBuilder *js = CreateEveHeader(p, LOG_DIR_FLOW, "tls", NULL, aft->tlslog_ctx->eve_ctx);
    if (unlikely(js == NULL)) {
        return 0;
    }

    SCJbOpenObject(js, "tls");

    JsonTlsLogFields(js, ssl_state, tls_ctx->fields);

    /* print original application level protocol when it have been changed
       because of STARTTLS, HTTP CONNECT, or similar. */
    if (f->alproto_orig != ALPROTO_UNKNOWN) {
        SCJbSetString(js, "from_proto", AppLayerGetProtoName(f->alproto_orig));
    }

    /* Close the tls object. */
    SCJbClose(js);

    OutputJsonBuilderBuffer(tv, p, p->flow, js, aft->ctx);
    SCJbFree(js);

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

static OutputTlsCtx *OutputTlsInitCtx(SCConfNode *conf)
{
    OutputTlsCtx *tls_ctx = SCCalloc(1, sizeof(OutputTlsCtx));
    if (unlikely(tls_ctx == NULL))
        return NULL;

    tls_ctx->fields = BASIC_FIELDS;
    tls_ctx->session_resumed = false;

    if (conf == NULL)
        return tls_ctx;

    const char *extended = SCConfNodeLookupChildValue(conf, "extended");
    if (extended) {
        if (SCConfValIsTrue(extended)) {
            tls_ctx->fields = EXTENDED_FIELDS;
        }
    }

    SCConfNode *custom = SCConfNodeLookupChild(conf, "custom");
    if (custom) {
        tls_ctx->fields = 0;
        SCConfNode *field;
        TAILQ_FOREACH(field, &custom->head, next)
        {
            bool valid = false;
            TlsFields *valid_fields = tls_fields;
            for ( ; valid_fields->name != NULL; valid_fields++) {
                if (strcasecmp(field->val, valid_fields->name) == 0) {
                    tls_ctx->fields |= valid_fields->flag;
                    SCLogDebug("enabled %s", field->val);
                    valid = true;
                    break;
                }
            }
            if (!valid) {
                SCLogWarning("eve.tls: unknown 'custom' field '%s'", field->val);
            }
        }
    }

    const char *session_resumption = SCConfNodeLookupChildValue(conf, "session-resumption");
    if (session_resumption == NULL || SCConfValIsTrue(session_resumption)) {
        tls_ctx->fields |= LOG_TLS_FIELD_SESSION_RESUMED;
        tls_ctx->session_resumed = true;
    }

    if ((tls_ctx->fields & LOG_TLS_FIELD_CERTIFICATE) &&
            (tls_ctx->fields & LOG_TLS_FIELD_CHAIN)) {
        SCLogWarning("Both 'certificate' and 'chain' contains the top "
                     "certificate, so only one of them should be enabled "
                     "at a time");
    }
    if ((tls_ctx->fields & LOG_TLS_FIELD_CLIENT_CERT) &&
            (tls_ctx->fields & LOG_TLS_FIELD_CLIENT_CHAIN)) {
        SCLogWarning("Both 'client_certificate' and 'client_chain' contains the top "
                     "certificate, so only one of them should be enabled "
                     "at a time");
    }

    if ((tls_ctx->fields & LOG_TLS_FIELD_CLIENT) == 0) {
        if (tls_ctx->fields & LOG_TLS_FIELD_CLIENT_CERT) {
            SCLogConfig("enabling \"client\" as a dependency of \"client_certificate\"");
            tls_ctx->fields |= LOG_TLS_FIELD_CLIENT;
        }
        if (tls_ctx->fields & LOG_TLS_FIELD_CLIENT_CHAIN) {
            SCLogConfig("enabling \"client\" as a dependency of \"client_chain\"");
            tls_ctx->fields |= LOG_TLS_FIELD_CLIENT;
        }
    }

    return tls_ctx;
}

static void OutputTlsLogDeinitSub(OutputCtx *output_ctx)
{
    OutputTlsCtx *tls_ctx = output_ctx->data;
    SCFree(tls_ctx);
    SCFree(output_ctx);
}

static OutputInitResult OutputTlsLogInitSub(SCConfNode *conf, OutputCtx *parent_ctx)
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
        SCLogWarning("Both 'certificate' and 'chain' contains the top "
                     "certificate, so only one of them should be enabled "
                     "at a time");
    }

    output_ctx->data = tls_ctx;
    output_ctx->DeInit = OutputTlsLogDeinitSub;

    SCAppLayerParserRegisterLogger(IPPROTO_TCP, ALPROTO_TLS);

    result.ctx = output_ctx;
    result.ok = true;
    return result;
}

void JsonTlsLogRegister (void)
{
    /* register as child of eve-log */
    OutputRegisterTxSubModuleWithProgress(LOGGER_JSON_TX, "eve-log", "JsonTlsLog", "eve-log.tls",
            OutputTlsLogInitSub, ALPROTO_TLS, JsonTlsLogger, TLS_STATE_SERVER_HANDSHAKE_DONE,
            TLS_STATE_CLIENT_HANDSHAKE_DONE, JsonTlsLogThreadInit, JsonTlsLogThreadDeinit);
}
