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
 * \author Anoop Saldanha <anoopsaldanha@gmail.com>
 * \author Pierre Chifflier <pierre.chifflier@ssi.gouv.fr>
 * \author Mats Klepsland <mats.klepsland@gmail.com>
 *
 */

#include "suricata-common.h"
#include "debug.h"
#include "decode.h"
#include "threads.h"

#include "stream-tcp-private.h"
#include "stream-tcp-reassemble.h"
#include "stream-tcp.h"
#include "stream.h"

#include "app-layer.h"
#include "app-layer-protos.h"
#include "app-layer-parser.h"
#include "app-layer-ssl.h"

#include "decode-events.h"
#include "conf.h"

#include "util-crypt.h"
#include "util-decode-der.h"
#include "util-decode-der-get.h"
#include "util-spm.h"
#include "util-unittest.h"
#include "util-debug.h"
#include "util-print.h"
#include "util-pool.h"
#include "util-byte.h"
#include "util-ja3.h"
#include "flow-util.h"
#include "flow-private.h"

SCEnumCharMap tls_decoder_event_table[ ] = {
    /* TLS protocol messages */
    { "INVALID_SSLV2_HEADER",        TLS_DECODER_EVENT_INVALID_SSLV2_HEADER },
    { "INVALID_TLS_HEADER",          TLS_DECODER_EVENT_INVALID_TLS_HEADER },
    { "INVALID_RECORD_VERSION",      TLS_DECODER_EVENT_INVALID_RECORD_VERSION },
    { "INVALID_RECORD_TYPE",         TLS_DECODER_EVENT_INVALID_RECORD_TYPE },
    { "INVALID_HANDSHAKE_MESSAGE",   TLS_DECODER_EVENT_INVALID_HANDSHAKE_MESSAGE },
    { "HEARTBEAT_MESSAGE",           TLS_DECODER_EVENT_HEARTBEAT },
    { "INVALID_HEARTBEAT_MESSAGE",   TLS_DECODER_EVENT_INVALID_HEARTBEAT },
    { "OVERFLOW_HEARTBEAT_MESSAGE",  TLS_DECODER_EVENT_OVERFLOW_HEARTBEAT },
    { "DATALEAK_HEARTBEAT_MISMATCH", TLS_DECODER_EVENT_DATALEAK_HEARTBEAT_MISMATCH },
    { "HANDSHAKE_INVALID_LENGTH",    TLS_DECODER_EVENT_HANDSHAKE_INVALID_LENGTH },
    { "MULTIPLE_SNI_EXTENSIONS",     TLS_DECODER_EVENT_MULTIPLE_SNI_EXTENSIONS },
    { "INVALID_SNI_TYPE",            TLS_DECODER_EVENT_INVALID_SNI_TYPE },
    { "INVALID_SNI_LENGTH",          TLS_DECODER_EVENT_INVALID_SNI_LENGTH },
    { "TOO_MANY_RECORDS_IN_PACKET",  TLS_DECODER_EVENT_TOO_MANY_RECORDS_IN_PACKET },
    /* certificate decoding messages */
    { "INVALID_CERTIFICATE",         TLS_DECODER_EVENT_INVALID_CERTIFICATE },
    { "CERTIFICATE_MISSING_ELEMENT", TLS_DECODER_EVENT_CERTIFICATE_MISSING_ELEMENT },
    { "CERTIFICATE_UNKNOWN_ELEMENT", TLS_DECODER_EVENT_CERTIFICATE_UNKNOWN_ELEMENT },
    { "CERTIFICATE_INVALID_LENGTH",  TLS_DECODER_EVENT_CERTIFICATE_INVALID_LENGTH },
    { "CERTIFICATE_INVALID_STRING",  TLS_DECODER_EVENT_CERTIFICATE_INVALID_STRING },
    { "ERROR_MESSAGE_ENCOUNTERED",   TLS_DECODER_EVENT_ERROR_MSG_ENCOUNTERED },
    /* used as a generic error event */
    { "INVALID_SSL_RECORD",          TLS_DECODER_EVENT_INVALID_SSL_RECORD },
    { NULL,                          -1 },
};

/* JA3 fingerprints are disabled by default */
#define SSL_CONFIG_DEFAULT_JA3 0

enum SslConfigEncryptHandling {
    SSL_CNF_ENC_HANDLE_DEFAULT = 0, /**< disable raw content, continue tracking */
    SSL_CNF_ENC_HANDLE_BYPASS = 1,  /**< skip processing of flow, bypass if possible */
    SSL_CNF_ENC_HANDLE_FULL = 2,    /**< handle fully like any other proto */
};

typedef struct SslConfig_ {
    enum SslConfigEncryptHandling encrypt_mode;
    int enable_ja3;
} SslConfig;

SslConfig ssl_config;

/* SSLv3 record types */
#define SSLV3_CHANGE_CIPHER_SPEC       20
#define SSLV3_ALERT_PROTOCOL           21
#define SSLV3_HANDSHAKE_PROTOCOL       22
#define SSLV3_APPLICATION_PROTOCOL     23
#define SSLV3_HEARTBEAT_PROTOCOL       24

/* SSLv3 handshake protocol types */
#define SSLV3_HS_HELLO_REQUEST          0
#define SSLV3_HS_CLIENT_HELLO           1
#define SSLV3_HS_SERVER_HELLO           2
#define SSLV3_HS_NEW_SESSION_TICKET     4
#define SSLV3_HS_CERTIFICATE           11
#define SSLV3_HS_SERVER_KEY_EXCHANGE   12
#define SSLV3_HS_CERTIFICATE_REQUEST   13
#define SSLV3_HS_SERVER_HELLO_DONE     14
#define SSLV3_HS_CERTIFICATE_VERIFY    15
#define SSLV3_HS_CLIENT_KEY_EXCHANGE   16
#define SSLV3_HS_FINISHED              20
#define SSLV3_HS_CERTIFICATE_URL       21
#define SSLV3_HS_CERTIFICATE_STATUS    22

/* SSLv2 protocol message types */
#define SSLV2_MT_ERROR                  0
#define SSLV2_MT_CLIENT_HELLO           1
#define SSLV2_MT_CLIENT_MASTER_KEY      2
#define SSLV2_MT_CLIENT_FINISHED        3
#define SSLV2_MT_SERVER_HELLO           4
#define SSLV2_MT_SERVER_VERIFY          5
#define SSLV2_MT_SERVER_FINISHED        6
#define SSLV2_MT_REQUEST_CERTIFICATE    7
#define SSLV2_MT_CLIENT_CERTIFICATE     8

#define SSLV3_RECORD_HDR_LEN            5
#define SSLV3_MESSAGE_HDR_LEN           4

#define SSLV3_CLIENT_HELLO_VERSION_LEN  2
#define SSLV3_CLIENT_HELLO_RANDOM_LEN  32

/* TLS heartbeat protocol types */
#define TLS_HB_REQUEST                  1
#define TLS_HB_RESPONSE                 2

#define SSL_RECORD_MINIMUM_LENGTH       6

#define SHA1_STRING_LENGTH             60

#define HAS_SPACE(n) ((uint64_t)(input - initial_input) + (uint64_t)(n) > (uint64_t)(input_len)) ?  0 : 1

static void SSLParserReset(SSLState *ssl_state)
{
    ssl_state->curr_connp->bytes_processed = 0;
}

void SSLSetEvent(SSLState *ssl_state, uint8_t event)
{
    if (ssl_state == NULL) {
        SCLogDebug("Could not set decoder event: %u", event);
        return;
    }

    AppLayerDecoderEventsSetEventRaw(&ssl_state->decoder_events, event);
    ssl_state->events++;
}

static AppLayerDecoderEvents *SSLGetEvents(void *tx)
{
    /* for TLS, TX == state, see GetTx */
    SSLState *ssl_state = (SSLState *)tx;
    return ssl_state->decoder_events;
}

static int SSLSetTxDetectState(void *vtx, DetectEngineState *de_state)
{
    SSLState *ssl_state = (SSLState *)vtx;
    ssl_state->de_state = de_state;
    return 0;
}

static DetectEngineState *SSLGetTxDetectState(void *vtx)
{
    SSLState *ssl_state = (SSLState *)vtx;
    return ssl_state->de_state;
}

static void *SSLGetTx(void *state, uint64_t tx_id)
{
    SSLState *ssl_state = (SSLState *)state;
    return ssl_state;
}

static uint64_t SSLGetTxCnt(void *state)
{
    /* single tx */
    return 1;
}

static void SSLSetTxLogged(void *state, void *tx, LoggerId logged)
{
    SSLState *ssl_state = (SSLState *)state;
    if (ssl_state)
        ssl_state->logged = logged;
}

static LoggerId SSLGetTxLogged(void *state, void *tx)
{
    SSLState *ssl_state = (SSLState *)state;
    if (ssl_state)
        return (ssl_state->logged);

    return 0;
}

static int SSLGetAlstateProgressCompletionStatus(uint8_t direction)
{
    return TLS_STATE_FINISHED;
}

static int SSLGetAlstateProgress(void *tx, uint8_t direction)
{
    SSLState *ssl_state = (SSLState *)tx;

    /* we don't care about direction, only that app-layer parser is done
       and have sent an EOF */
    if (ssl_state->flags & SSL_AL_FLAG_STATE_FINISHED) {
        return TLS_STATE_FINISHED;
    }

    /* we want the logger to log when the handshake is done, even if the
       state is not finished */
    if (ssl_state->flags & SSL_AL_FLAG_HANDSHAKE_DONE) {
        return TLS_HANDSHAKE_DONE;
    }

    if (direction == STREAM_TOSERVER &&
        (ssl_state->server_connp.cert0_subject != NULL ||
         ssl_state->server_connp.cert0_issuerdn != NULL))
    {
        return TLS_STATE_CERT_READY;
    }

    return TLS_STATE_IN_PROGRESS;
}

static uint64_t SSLGetTxDetectFlags(void *vtx, uint8_t dir)
{
    SSLState *ssl_state = (SSLState *)vtx;
    if (dir & STREAM_TOSERVER) {
        return ssl_state->detect_flags_ts;
    } else {
        return ssl_state->detect_flags_tc;
    }
}

static void SSLSetTxDetectFlags(void *vtx, uint8_t dir, uint64_t flags)
{
    SSLState *ssl_state = (SSLState *)vtx;
    if (dir & STREAM_TOSERVER) {
        ssl_state->detect_flags_ts = flags;
    } else {
        ssl_state->detect_flags_tc = flags;
    }
}

void SSLVersionToString(uint16_t version, char *buffer)
{
    buffer[0] = '\0';

    switch (version) {
        case TLS_VERSION_UNKNOWN:
            strlcat(buffer, "UNDETERMINED", 13);
            break;
        case SSL_VERSION_2:
            strlcat(buffer, "SSLv2", 6);
            break;
        case SSL_VERSION_3:
            strlcat(buffer, "SSLv3", 6);
            break;
        case TLS_VERSION_10:
            strlcat(buffer, "TLSv1", 6);
            break;
        case TLS_VERSION_11:
            strlcat(buffer, "TLS 1.1", 8);
            break;
        case TLS_VERSION_12:
            strlcat(buffer, "TLS 1.2", 8);
            break;
        case TLS_VERSION_13:
            strlcat(buffer, "TLS 1.3", 8);
            break;
        case TLS_VERSION_13_DRAFT28:
            strlcat(buffer, "TLS 1.3 draft-28", 17);
            break;
        case TLS_VERSION_13_DRAFT27:
            strlcat(buffer, "TLS 1.3 draft-27", 17);
            break;
        case TLS_VERSION_13_DRAFT26:
            strlcat(buffer, "TLS 1.3 draft-26", 17);
            break;
        case TLS_VERSION_13_DRAFT25:
            strlcat(buffer, "TLS 1.3 draft-25", 17);
            break;
        case TLS_VERSION_13_DRAFT24:
            strlcat(buffer, "TLS 1.3 draft-24", 17);
            break;
        case TLS_VERSION_13_DRAFT23:
            strlcat(buffer, "TLS 1.3 draft-23", 17);
            break;
        case TLS_VERSION_13_DRAFT22:
            strlcat(buffer, "TLS 1.3 draft-22", 17);
            break;
        case TLS_VERSION_13_DRAFT21:
            strlcat(buffer, "TLS 1.3 draft-21", 17);
            break;
        case TLS_VERSION_13_DRAFT20:
            strlcat(buffer, "TLS 1.3 draft-20", 17);
            break;
        case TLS_VERSION_13_DRAFT19:
            strlcat(buffer, "TLS 1.3 draft-19", 17);
            break;
        case TLS_VERSION_13_DRAFT18:
            strlcat(buffer, "TLS 1.3 draft-18", 17);
            break;
        case TLS_VERSION_13_DRAFT17:
            strlcat(buffer, "TLS 1.3 draft-17", 17);
            break;
        case TLS_VERSION_13_DRAFT16:
            strlcat(buffer, "TLS 1.3 draft-16", 17);
            break;
        case TLS_VERSION_13_PRE_DRAFT16:
            strlcat(buffer, "TLS 1.3 draft-<16", 18);
            break;
        case TLS_VERSION_13_DRAFT20_FB:
            strlcat(buffer, "TLS 1.3 draft-20-fb", 20);
            break;
        case TLS_VERSION_13_DRAFT21_FB:
            strlcat(buffer, "TLS 1.3 draft-21-fb", 20);
            break;
        case TLS_VERSION_13_DRAFT22_FB:
            strlcat(buffer, "TLS 1.3 draft-22-fb", 20);
            break;
        case TLS_VERSION_13_DRAFT23_FB:
            strlcat(buffer, "TLS 1.3 draft-23-fb", 20);
            break;
        case TLS_VERSION_13_DRAFT26_FB:
            strlcat(buffer, "TLS 1.3 draft-26-fb", 20);
            break;
        default:
            snprintf(buffer, 7, "0x%04x", version);
            break;
    }
}

static void TlsDecodeHSCertificateErrSetEvent(SSLState *ssl_state, uint32_t err)
{
    switch (err) {
        case ERR_DER_UNKNOWN_ELEMENT:
            SSLSetEvent(ssl_state,
                        TLS_DECODER_EVENT_CERTIFICATE_UNKNOWN_ELEMENT);
            break;
        case ERR_DER_ELEMENT_SIZE_TOO_BIG:
        case ERR_DER_INVALID_SIZE:
        case ERR_DER_RECURSION_LIMIT:
            SSLSetEvent(ssl_state,
                        TLS_DECODER_EVENT_CERTIFICATE_INVALID_LENGTH);
            break;
        case ERR_DER_UNSUPPORTED_STRING:
            SSLSetEvent(ssl_state,
                        TLS_DECODER_EVENT_CERTIFICATE_INVALID_STRING);
            break;
        case ERR_DER_MISSING_ELEMENT:
            SSLSetEvent(ssl_state,
                        TLS_DECODER_EVENT_CERTIFICATE_MISSING_ELEMENT);
            break;
        case ERR_DER_INVALID_TAG:
        case ERR_DER_INVALID_OBJECT:
        case ERR_DER_GENERIC:
        default:
            SSLSetEvent(ssl_state, TLS_DECODER_EVENT_INVALID_CERTIFICATE);
            break;
    }
}

static inline int TlsDecodeHSCertificateSubject(SSLState *ssl_state,
                                                Asn1Generic *cert)
{
    if (unlikely(ssl_state->server_connp.cert0_subject != NULL))
        return 0;

    uint32_t err = 0;
    char buffer[512];

    int rc = Asn1DerGetSubjectDN(cert, buffer, sizeof(buffer), &err);
    if (rc != 0) {
        TlsDecodeHSCertificateErrSetEvent(ssl_state, err);
        return 0;
    }

    ssl_state->server_connp.cert0_subject = SCStrdup(buffer);
    if (ssl_state->server_connp.cert0_subject == NULL)
        return -1;

    return 0;
}

static inline int TlsDecodeHSCertificateIssuer(SSLState *ssl_state,
                                               Asn1Generic *cert)
{
    if (unlikely(ssl_state->server_connp.cert0_issuerdn != NULL))
        return 0;

    uint32_t err = 0;
    char buffer[512];

    int rc = Asn1DerGetIssuerDN(cert, buffer, sizeof(buffer), &err);
    if (rc != 0) {
        TlsDecodeHSCertificateErrSetEvent(ssl_state, err);
        return 0;
    }

    ssl_state->server_connp.cert0_issuerdn = SCStrdup(buffer);
    if (ssl_state->server_connp.cert0_issuerdn == NULL)
        return -1;

    return 0;
}

static inline int TlsDecodeHSCertificateSerial(SSLState *ssl_state,
                                               Asn1Generic *cert)
{
    if (unlikely(ssl_state->server_connp.cert0_serial != NULL))
        return 0;

    uint32_t err = 0;
    char buffer[512];

    int rc = Asn1DerGetSerial(cert, buffer, sizeof(buffer), &err);
    if (rc != 0) {
        TlsDecodeHSCertificateErrSetEvent(ssl_state, err);
        return 0;
    }

    ssl_state->server_connp.cert0_serial = SCStrdup(buffer);
    if (ssl_state->server_connp.cert0_serial == NULL)
        return -1;

    return 0;
}

static inline int TlsDecodeHSCertificateValidity(SSLState *ssl_state,
                                                 Asn1Generic *cert)
{
    uint32_t err = 0;
    time_t not_before;
    time_t not_after;

    int rc = Asn1DerGetValidity(cert, &not_before, &not_after, &err);
    if (rc != 0) {
        TlsDecodeHSCertificateErrSetEvent(ssl_state, err);
        return 0;
    }

    ssl_state->server_connp.cert0_not_before = not_before;
    ssl_state->server_connp.cert0_not_after = not_after;

    return 0;
}

static inline int TlsDecodeHSCertificateFingerprint(SSLState *ssl_state,
                                                    const uint8_t *input,
                                                    uint32_t cert_len)
{
    if (unlikely(ssl_state->server_connp.cert0_fingerprint != NULL))
        return 0;

    ssl_state->server_connp.cert0_fingerprint = SCCalloc(1, SHA1_STRING_LENGTH *
                                                         sizeof(char));
    if (ssl_state->server_connp.cert0_fingerprint == NULL)
        return -1;

    uint8_t hash[SHA1_LENGTH];
    if (ComputeSHA1(input, cert_len, hash, sizeof(hash)) == 1) {
        for (int i = 0, x = 0; x < SHA1_LENGTH; x++)
        {
            i += snprintf(ssl_state->server_connp.cert0_fingerprint + i,
                    SHA1_STRING_LENGTH - i, i == 0 ? "%02x" : ":%02x",
                    hash[x]);
        }
    }
    return 0;
}

static inline int TlsDecodeHSCertificateAddCertToChain(SSLState *ssl_state,
                                                       const uint8_t *input,
                                                       uint32_t cert_len)
{
    SSLCertsChain *cert = SCCalloc(1, sizeof(SSLCertsChain));
    if (cert == NULL)
        return -1;

    cert->cert_data = (uint8_t *)input;
    cert->cert_len = cert_len;
    TAILQ_INSERT_TAIL(&ssl_state->server_connp.certs, cert, next);

    return 0;
}

static int TlsDecodeHSCertificate(SSLState *ssl_state,
                                  const uint8_t * const initial_input,
                                  const uint32_t input_len)
{
    const uint8_t *input = (uint8_t *)initial_input;

    Asn1Generic *cert = NULL;

    if (!(HAS_SPACE(3)))
        return 1;

    uint32_t cert_chain_len = *input << 16 | *(input + 1) << 8 | *(input + 2);
    input += 3;

    if (!(HAS_SPACE(cert_chain_len)))
        return 0;

    uint32_t processed_len = 0;
    /* coverity[tainted_data] */
    while (processed_len < cert_chain_len)
    {
        if (!(HAS_SPACE(3)))
            goto invalid_cert;

        uint32_t cert_len = *input << 16 | *(input + 1) << 8 | *(input + 2);
        input += 3;

        if (!(HAS_SPACE(cert_len)))
            goto invalid_cert;

        uint32_t err = 0;
        int rc = 0;

        /* only store fields from the first certificate in the chain */
        if (processed_len == 0) {
            /* coverity[tainted_data] */
            cert = DecodeDer(input, cert_len, &err);
            if (cert == NULL) {
                TlsDecodeHSCertificateErrSetEvent(ssl_state, err);
                goto next;
            }

            rc = TlsDecodeHSCertificateSubject(ssl_state, cert);
            if (rc != 0)
                goto error;

            rc = TlsDecodeHSCertificateIssuer(ssl_state, cert);
            if (rc != 0)
                goto error;

            rc = TlsDecodeHSCertificateSerial(ssl_state, cert);
            if (rc != 0)
                goto error;

            rc = TlsDecodeHSCertificateValidity(ssl_state, cert);
            if (rc != 0)
                goto error;

            rc = TlsDecodeHSCertificateFingerprint(ssl_state, input, cert_len);
            if (rc != 0)
                goto error;

            DerFree(cert);
            cert = NULL;
        }

        rc = TlsDecodeHSCertificateAddCertToChain(ssl_state, input, cert_len);
        if (rc != 0)
            goto error;

next:
        input += cert_len;
        processed_len += cert_len + 3;
    }

    return (input - initial_input);

error:
    if (cert != NULL)
        DerFree(cert);
    return -1;

invalid_cert:
    SCLogDebug("TLS invalid certificate");
    SSLSetEvent(ssl_state, TLS_DECODER_EVENT_INVALID_CERTIFICATE);
    return -1;
}

/**
 * \inline
 * \brief Check if value is GREASE.
 *
 * http://tools.ietf.org/html/draft-davidben-tls-grease-00
 *
 * \param value Value to check.
 *
 * \retval 1 if is GREASE.
 * \retval 0 if not is GREASE.
 */
static inline int TLSDecodeValueIsGREASE(const uint16_t value)
{
    switch (value)
    {
        case 0x0a0a:
        case 0x1a1a:
        case 0x2a2a:
        case 0x3a3a:
        case 0x4a4a:
        case 0x5a5a:
        case 0x6a6a:
        case 0x7a7a:
        case 0x8a8a:
        case 0x9a9a:
        case 0xaaaa:
        case 0xbaba:
        case 0xcaca:
        case 0xdada:
        case 0xeaea:
        case 0xfafa:
            return 1;
        default:
            return 0;
    }
}

static inline int TLSDecodeHSHelloVersion(SSLState *ssl_state,
                                          const uint8_t * const initial_input,
                                          const uint32_t input_len)
{
    uint8_t *input = (uint8_t *)initial_input;

    if (!(HAS_SPACE(SSLV3_CLIENT_HELLO_VERSION_LEN))) {
        SCLogDebug("TLS handshake invalid length");
        SSLSetEvent(ssl_state,
                    TLS_DECODER_EVENT_HANDSHAKE_INVALID_LENGTH);
        return -1;
    }

    uint16_t version = *input << 8 | *(input + 1);
    ssl_state->curr_connp->version = version;

    /* TLSv1.3 draft1 to draft21 use the version field as earlier TLS
       versions, instead of using the supported versions extension. */
    if ((ssl_state->current_flags & SSL_AL_FLAG_STATE_SERVER_HELLO) &&
            ((ssl_state->curr_connp->version == TLS_VERSION_13) ||
            (((ssl_state->curr_connp->version >> 8) & 0xff) == 0x7f))) {
        ssl_state->flags |= SSL_AL_FLAG_LOG_WITHOUT_CERT;
    }

    /* Catch some early TLSv1.3 draft implementations that does not conform
       to the draft version. */
    if ((ssl_state->curr_connp->version >= 0x7f01) &&
            (ssl_state->curr_connp->version < 0x7f10)) {
        ssl_state->curr_connp->version = TLS_VERSION_13_PRE_DRAFT16;
    }

    /* TLSv1.3 drafts from draft1 to draft15 use 0x0304 (TLSv1.3) as the
       version number, which makes it hard to accurately pinpoint the
       exact draft version. */
    else if (ssl_state->curr_connp->version == TLS_VERSION_13) {
        ssl_state->curr_connp->version = TLS_VERSION_13_PRE_DRAFT16;
    }

    if (ssl_config.enable_ja3 && ssl_state->curr_connp->ja3_str == NULL) {
        ssl_state->curr_connp->ja3_str = Ja3BufferInit();
        if (ssl_state->curr_connp->ja3_str == NULL)
            return -1;

        int rc = Ja3BufferAddValue(&ssl_state->curr_connp->ja3_str, version);
        if (rc != 0)
            return -1;
    }

    input += SSLV3_CLIENT_HELLO_VERSION_LEN;

    return (input - initial_input);
}

static inline int TLSDecodeHSHelloRandom(SSLState *ssl_state,
                                         const uint8_t * const initial_input,
                                         const uint32_t input_len)
{
    uint8_t *input = (uint8_t *)initial_input;

    if (!(HAS_SPACE(SSLV3_CLIENT_HELLO_RANDOM_LEN))) {
        SCLogDebug("TLS handshake invalid length");
        SSLSetEvent(ssl_state,
                    TLS_DECODER_EVENT_HANDSHAKE_INVALID_LENGTH);
        return -1;
    }

    /* Skip random */
    input += SSLV3_CLIENT_HELLO_RANDOM_LEN;

    return (input - initial_input);
}

static inline int TLSDecodeHSHelloSessionID(SSLState *ssl_state,
                                            const uint8_t * const initial_input,
                                            const uint32_t input_len)
{
    uint8_t *input = (uint8_t *)initial_input;

    if (!(HAS_SPACE(1)))
        goto invalid_length;

    uint8_t session_id_length = *input;
    input += 1;

    if (!(HAS_SPACE(session_id_length)))
        goto invalid_length;

    if (session_id_length != 0 && ssl_state->curr_connp->session_id == NULL) {
        ssl_state->curr_connp->session_id = SCMalloc(session_id_length);

        if (unlikely(ssl_state->curr_connp->session_id == NULL)) {
            return -1;
        }

        memcpy(ssl_state->curr_connp->session_id, input, session_id_length);
        ssl_state->curr_connp->session_id_length = session_id_length;

        if ((ssl_state->current_flags & SSL_AL_FLAG_STATE_SERVER_HELLO) &&
                ssl_state->client_connp.session_id != NULL &&
                ssl_state->server_connp.session_id != NULL) {
            if ((ssl_state->client_connp.session_id_length ==
                    ssl_state->server_connp.session_id_length) &&
                    (memcmp(ssl_state->server_connp.session_id,
                    ssl_state->client_connp.session_id, session_id_length) == 0)) {
                ssl_state->flags |= SSL_AL_FLAG_SESSION_RESUMED;
            }
        }
    }

    input += session_id_length;

    return (input - initial_input);

invalid_length:
    SCLogDebug("TLS handshake invalid length");
    SSLSetEvent(ssl_state,
                TLS_DECODER_EVENT_HANDSHAKE_INVALID_LENGTH);
    return -1;
}

static inline int TLSDecodeHSHelloCipherSuites(SSLState *ssl_state,
                                           const uint8_t * const initial_input,
                                           const uint32_t input_len)
{
    uint8_t *input = (uint8_t *)initial_input;

    if (!(HAS_SPACE(2)))
        goto invalid_length;

    uint16_t cipher_suites_length;

    if (ssl_state->current_flags & SSL_AL_FLAG_STATE_SERVER_HELLO) {
        cipher_suites_length = 2;
    } else if (ssl_state->current_flags & SSL_AL_FLAG_STATE_CLIENT_HELLO) {
        cipher_suites_length = *input << 8 | *(input + 1);
        input += 2;
    } else {
        return -1;
    }

    if (!(HAS_SPACE(cipher_suites_length)))
        goto invalid_length;

    /* Cipher suites length should always be divisible by 2 */
    if ((cipher_suites_length % 2) != 0) {
        goto invalid_length;
    }

    if (ssl_config.enable_ja3) {
        int rc;

        JA3Buffer *ja3_cipher_suites = Ja3BufferInit();
        if (ja3_cipher_suites == NULL)
            return -1;

        uint16_t processed_len = 0;
        /* coverity[tainted_data] */
        while (processed_len < cipher_suites_length)
        {
            if (!(HAS_SPACE(2))) {
                Ja3BufferFree(&ja3_cipher_suites);
                goto invalid_length;
            }

            uint16_t cipher_suite = *input << 8 | *(input + 1);
            input += 2;

            if (TLSDecodeValueIsGREASE(cipher_suite) != 1) {
                rc = Ja3BufferAddValue(&ja3_cipher_suites, cipher_suite);
                if (rc != 0) {
                    return -1;
                }
            }

            processed_len += 2;
        }

        rc = Ja3BufferAppendBuffer(&ssl_state->curr_connp->ja3_str,
                                   &ja3_cipher_suites);
        if (rc == -1) {
            return -1;
        }

    } else {
        /* Skip cipher suites */
        input += cipher_suites_length;
    }

    return (input - initial_input);

invalid_length:
    SCLogDebug("TLS handshake invalid length");
    SSLSetEvent(ssl_state,
                TLS_DECODER_EVENT_HANDSHAKE_INVALID_LENGTH);
    return -1;
}

static inline int TLSDecodeHSHelloCompressionMethods(SSLState *ssl_state,
                                           const uint8_t * const initial_input,
                                           const uint32_t input_len)
{
    uint8_t *input = (uint8_t *)initial_input;

    if (!(HAS_SPACE(1)))
        goto invalid_length;

    /* Skip compression methods */
    if (ssl_state->current_flags & SSL_AL_FLAG_STATE_SERVER_HELLO) {
        input += 1;
    } else {
        uint8_t compression_methods_length = *input;
        input += 1;

        if (!(HAS_SPACE(compression_methods_length)))
            goto invalid_length;

        input += compression_methods_length;
    }

    return (input - initial_input);

invalid_length:
    SCLogDebug("TLS handshake invalid_length");
    SSLSetEvent(ssl_state,
                TLS_DECODER_EVENT_HANDSHAKE_INVALID_LENGTH);
    return -1;
}

static inline int TLSDecodeHSHelloExtensionSni(SSLState *ssl_state,
                                           const uint8_t * const initial_input,
                                           const uint32_t input_len)
{
    uint8_t *input = (uint8_t *)initial_input;

    /* Empty extension */
    if (input_len == 0)
        return 0;

    if (!(HAS_SPACE(2)))
        goto invalid_length;

    /* Skip sni_list_length */
    input += 2;

    if (!(HAS_SPACE(1)))
        goto invalid_length;

    uint8_t sni_type = *input;
    input += 1;

    /* Currently the only type allowed is host_name
       (RFC6066 section 3). */
    if (sni_type != SSL_SNI_TYPE_HOST_NAME) {
        SCLogDebug("Unknown SNI type");
        SSLSetEvent(ssl_state,
                TLS_DECODER_EVENT_INVALID_SNI_TYPE);
        return -1;
    }

    if (!(HAS_SPACE(2)))
        goto invalid_length;

    uint16_t sni_len = *input << 8 | *(input + 1);
    input += 2;

    if (!(HAS_SPACE(sni_len)))
        goto invalid_length;

    /* There must not be more than one extension of the same
       type (RFC5246 section 7.4.1.4). */
    if (ssl_state->curr_connp->sni) {
        SCLogDebug("Multiple SNI extensions");
        SSLSetEvent(ssl_state,
                TLS_DECODER_EVENT_MULTIPLE_SNI_EXTENSIONS);
        input += sni_len;
        return (input - initial_input);
    }

    /* host_name contains the fully qualified domain name,
       and should therefore be limited by the maximum domain
       name length. */
    if (sni_len > 255) {
        SCLogDebug("SNI length >255");
        SSLSetEvent(ssl_state,
                TLS_DECODER_EVENT_INVALID_SNI_LENGTH);
        return -1;
    }

    size_t sni_strlen = sni_len + 1;
    ssl_state->curr_connp->sni = SCMalloc(sni_strlen);

    if (unlikely(ssl_state->curr_connp->sni == NULL))
        return -1;

    memcpy(ssl_state->curr_connp->sni, input, sni_strlen - 1);
    ssl_state->curr_connp->sni[sni_strlen-1] = 0;

    input += sni_len;

    return (input - initial_input);

invalid_length:
    SCLogDebug("TLS handshake invalid length");
    SSLSetEvent(ssl_state,
                TLS_DECODER_EVENT_HANDSHAKE_INVALID_LENGTH);


    return -1;
}

static inline int TLSDecodeHSHelloExtensionSupportedVersions(SSLState *ssl_state,
                                             const uint8_t * const initial_input,
                                             const uint32_t input_len)
{
    uint8_t *input = (uint8_t *)initial_input;

    /* Empty extension */
    if (input_len == 0)
        return 0;

    if (ssl_state->current_flags & SSL_AL_FLAG_STATE_CLIENT_HELLO) {
        if (!(HAS_SPACE(1)))
            goto invalid_length;

        uint8_t supported_ver_len = *input;
        input += 1;

        if (!(HAS_SPACE(supported_ver_len)))
            goto invalid_length;

        /* Use the first (and prefered) version as client version */
        ssl_state->curr_connp->version = *input << 8 | *(input + 1);

        /* Set a flag to indicate that we have seen this extension */
        ssl_state->flags |= SSL_AL_FLAG_CH_VERSION_EXTENSION;

        input += supported_ver_len;
    }

    else if (ssl_state->current_flags & SSL_AL_FLAG_STATE_SERVER_HELLO) {
        if (!(HAS_SPACE(2)))
            goto invalid_length;

        uint16_t ver = *input << 8 | *(input + 1);

        if ((ssl_state->flags & SSL_AL_FLAG_CH_VERSION_EXTENSION) &&
                (ver > TLS_VERSION_12)) {
            ssl_state->flags |= SSL_AL_FLAG_LOG_WITHOUT_CERT;
        }

        ssl_state->curr_connp->version = ver;
        input += 2;
    }

    return (input - initial_input);

invalid_length:
    SCLogDebug("TLS handshake invalid length");
    SSLSetEvent(ssl_state,
                TLS_DECODER_EVENT_HANDSHAKE_INVALID_LENGTH);

    return -1;
}

static inline int TLSDecodeHSHelloExtensionEllipticCurves(SSLState *ssl_state,
                                          const uint8_t * const initial_input,
                                          const uint32_t input_len,
                                          JA3Buffer *ja3_elliptic_curves)
{
    uint8_t *input = (uint8_t *)initial_input;

    /* Empty extension */
    if (input_len == 0)
        return 0;

    if (!(HAS_SPACE(2)))
        goto invalid_length;

    uint16_t elliptic_curves_len = *input << 8 | *(input + 1);
    input += 2;

    if (!(HAS_SPACE(elliptic_curves_len)))
        goto invalid_length;

    if ((ssl_state->current_flags & SSL_AL_FLAG_STATE_CLIENT_HELLO) &&
            ssl_config.enable_ja3) {
        uint16_t ec_processed_len = 0;
        /* coverity[tainted_data] */
        while (ec_processed_len < elliptic_curves_len)
        {
            uint16_t elliptic_curve = *input << 8 | *(input + 1);
            input += 2;

            if (TLSDecodeValueIsGREASE(elliptic_curve) != 1) {
                int rc = Ja3BufferAddValue(&ja3_elliptic_curves,
                                           elliptic_curve);
                if (rc != 0)
                    return -1;
            }

            ec_processed_len += 2;
        }

    } else {
        /* Skip elliptic curves */
        input += elliptic_curves_len;
    }

    return (input - initial_input);

invalid_length:
    SCLogDebug("TLS handshake invalid length");
    SSLSetEvent(ssl_state,
                TLS_DECODER_EVENT_HANDSHAKE_INVALID_LENGTH);

    return -1;
}

static inline int TLSDecodeHSHelloExtensionEllipticCurvePF(SSLState *ssl_state,
                                            const uint8_t * const initial_input,
                                            const uint32_t input_len,
                                            JA3Buffer *ja3_elliptic_curves_pf)
{
    uint8_t *input = (uint8_t *)initial_input;

    /* Empty extension */
    if (input_len == 0)
        return 0;

    if (!(HAS_SPACE(1)))
        goto invalid_length;

    uint8_t ec_pf_len = *input;
    input += 1;

    if (!(HAS_SPACE(ec_pf_len)))
        goto invalid_length;

    if ((ssl_state->current_flags & SSL_AL_FLAG_STATE_CLIENT_HELLO) &&
            ssl_config.enable_ja3) {
        uint8_t ec_pf_processed_len = 0;
        /* coverity[tainted_data] */
        while (ec_pf_processed_len < ec_pf_len)
        {
            uint8_t elliptic_curve_pf = *input;
            input += 1;

            if (TLSDecodeValueIsGREASE(elliptic_curve_pf) != 1) {
                int rc = Ja3BufferAddValue(&ja3_elliptic_curves_pf,
                                           elliptic_curve_pf);
                if (rc != 0)
                    return -1;
            }

            ec_pf_processed_len += 1;
        }

    } else {
        /* Skip elliptic curve point formats */
        input += ec_pf_len;
    }

    return (input - initial_input);

invalid_length:
    SCLogDebug("TLS handshake invalid length");
    SSLSetEvent(ssl_state,
                TLS_DECODER_EVENT_HANDSHAKE_INVALID_LENGTH);

    return -1;
}

static inline int TLSDecodeHSHelloExtensions(SSLState *ssl_state,
                                         const uint8_t * const initial_input,
                                         const uint32_t input_len)
{
    uint8_t *input = (uint8_t *)initial_input;

    int ret;
    int rc;

    JA3Buffer *ja3_extensions = NULL;
    JA3Buffer *ja3_elliptic_curves = NULL;
    JA3Buffer *ja3_elliptic_curves_pf = NULL;

    if (ssl_config.enable_ja3) {
        ja3_extensions = Ja3BufferInit();
        if (ja3_extensions == NULL)
            goto error;

        if (ssl_state->current_flags & SSL_AL_FLAG_STATE_CLIENT_HELLO) {
            ja3_elliptic_curves = Ja3BufferInit();
            if (ja3_elliptic_curves == NULL)
                goto error;

            ja3_elliptic_curves_pf = Ja3BufferInit();
            if (ja3_elliptic_curves_pf == NULL)
                goto error;
        }
    }

    /* Extensions are optional (RFC5246 section 7.4.1.2) */
    if (!(HAS_SPACE(2)))
        goto end;

    uint16_t extensions_len = *input << 8 | *(input + 1);
    input += 2;

    if (!(HAS_SPACE(extensions_len)))
        goto invalid_length;

    uint16_t processed_len = 0;
    /* coverity[tainted_data] */
    while (processed_len < extensions_len)
    {
        if (!(HAS_SPACE(2)))
            goto invalid_length;

        uint16_t ext_type = *input << 8 | *(input + 1);
        input += 2;

        if (!(HAS_SPACE(2)))
            goto invalid_length;

        uint16_t ext_len = *input << 8 | *(input + 1);
        input += 2;

        if (!(HAS_SPACE(ext_len)))
            goto invalid_length;

        switch (ext_type) {
            case SSL_EXTENSION_SNI:
            {
                /* coverity[tainted_data] */
                ret = TLSDecodeHSHelloExtensionSni(ssl_state, input,
                                                   ext_len);
                if (ret < 0)
                    goto end;

                input += ret;

                break;
            }

            case SSL_EXTENSION_ELLIPTIC_CURVES:
            {
                /* coverity[tainted_data] */
                ret = TLSDecodeHSHelloExtensionEllipticCurves(ssl_state, input,
                                                              ext_len,
                                                              ja3_elliptic_curves);
                if (ret < 0)
                    goto end;

                input += ret;

                break;
            }

            case SSL_EXTENSION_EC_POINT_FORMATS:
            {
                /* coverity[tainted_data] */
                ret = TLSDecodeHSHelloExtensionEllipticCurvePF(ssl_state, input,
                                                               ext_len,
                                                               ja3_elliptic_curves_pf);
                if (ret < 0)
                    goto end;

                input += ret;

                break;
            }

            case SSL_EXTENSION_EARLY_DATA:
            {
                if (ssl_state->current_flags & SSL_AL_FLAG_STATE_CLIENT_HELLO) {
                    /* Used by 0-RTT to indicate that encrypted data will
                       be sent right after the ClientHello record. */
                    ssl_state->flags |= SSL_AL_FLAG_EARLY_DATA;
                }

                input += ext_len;

                break;
            }

            case SSL_EXTENSION_SUPPORTED_VERSIONS:
            {
                ret = TLSDecodeHSHelloExtensionSupportedVersions(ssl_state, input,
                                                                 ext_len);
                if (ret < 0)
                    goto end;

                input += ret;

                break;
            }

            case SSL_EXTENSION_SESSION_TICKET:
            {
                if (ssl_state->current_flags & SSL_AL_FLAG_STATE_CLIENT_HELLO) {
                    /* This has to be verified later on by checking if a
                       certificate record has been sent by the server. */
                    ssl_state->flags |= SSL_AL_FLAG_SESSION_RESUMED;
                }

                input += ext_len;

                break;
            }

            default:
            {
                input += ext_len;
                break;
            }
        }

        if (ssl_config.enable_ja3) {
            if (TLSDecodeValueIsGREASE(ext_type) != 1) {
                rc = Ja3BufferAddValue(&ja3_extensions, ext_type);
                if (rc != 0)
                    goto error;
            }
        }

        processed_len += ext_len + 4;
    }

end:
    if (ssl_config.enable_ja3) {
        rc = Ja3BufferAppendBuffer(&ssl_state->curr_connp->ja3_str,
                                   &ja3_extensions);
        if (rc == -1)
            goto error;

        if (ssl_state->current_flags & SSL_AL_FLAG_STATE_CLIENT_HELLO) {
            rc = Ja3BufferAppendBuffer(&ssl_state->curr_connp->ja3_str,
                                       &ja3_elliptic_curves);
            if (rc == -1)
                goto error;

            rc = Ja3BufferAppendBuffer(&ssl_state->curr_connp->ja3_str,
                                       &ja3_elliptic_curves_pf);
            if (rc == -1)
                goto error;
        }
    }

    return (input - initial_input);

invalid_length:
    SCLogDebug("TLS handshake invalid length");
    SSLSetEvent(ssl_state,
                TLS_DECODER_EVENT_HANDSHAKE_INVALID_LENGTH);

error:
    if (ja3_extensions != NULL)
        Ja3BufferFree(&ja3_extensions);
    if (ja3_elliptic_curves != NULL)
        Ja3BufferFree(&ja3_elliptic_curves);
    if (ja3_elliptic_curves_pf != NULL)
        Ja3BufferFree(&ja3_elliptic_curves_pf);

    return -1;
}

static int TLSDecodeHandshakeHello(SSLState *ssl_state,
                                   const uint8_t * const input,
                                   const uint32_t input_len)
{
    int ret;
    uint32_t parsed = 0;

    ret = TLSDecodeHSHelloVersion(ssl_state, input, input_len);
    if (ret < 0)
        goto end;

    parsed += ret;

    ret = TLSDecodeHSHelloRandom(ssl_state, input + parsed, input_len - parsed);
    if (ret < 0)
        goto end;

    parsed += ret;

    /* The session id field in the server hello record was removed in
       TLSv1.3 draft1, but was readded in draft22. */
    if ((ssl_state->current_flags & SSL_AL_FLAG_STATE_CLIENT_HELLO) ||
            ((ssl_state->current_flags & SSL_AL_FLAG_STATE_SERVER_HELLO) &&
            ((ssl_state->flags & SSL_AL_FLAG_LOG_WITHOUT_CERT) == 0))) {
        ret = TLSDecodeHSHelloSessionID(ssl_state, input + parsed,
                                        input_len - parsed);
        if (ret < 0)
            goto end;

        parsed += ret;
    }

    ret = TLSDecodeHSHelloCipherSuites(ssl_state, input + parsed,
                                       input_len - parsed);
    if (ret < 0)
        goto end;

    parsed += ret;

   /* The compression methods field in the server hello record was
      removed in TLSv1.3 draft1, but was readded in draft22. */
   if ((ssl_state->current_flags & SSL_AL_FLAG_STATE_CLIENT_HELLO) ||
              ((ssl_state->current_flags & SSL_AL_FLAG_STATE_SERVER_HELLO) &&
              ((ssl_state->flags & SSL_AL_FLAG_LOG_WITHOUT_CERT) == 0))) {
        ret = TLSDecodeHSHelloCompressionMethods(ssl_state, input + parsed,
                                                 input_len - parsed);
        if (ret < 0)
            goto end;

        parsed += ret;
    }

    ret = TLSDecodeHSHelloExtensions(ssl_state, input + parsed,
                                     input_len - parsed);
    if (ret < 0)
        goto end;

    if (ssl_config.enable_ja3 && ssl_state->curr_connp->ja3_hash == NULL) {
        ssl_state->curr_connp->ja3_hash = Ja3GenerateHash(ssl_state->curr_connp->ja3_str);
    }

end:
    ssl_state->curr_connp->hs_bytes_processed = 0;
    return 0;
}

static int SSLv3ParseHandshakeType(SSLState *ssl_state, uint8_t *input,
                                   uint32_t input_len, uint8_t direction)
{
    void *ptmp;
    uint8_t *initial_input = input;
    uint32_t parsed = 0;
    int rc;

    if (input_len == 0) {
        return 0;
    }

    switch (ssl_state->curr_connp->handshake_type) {
        case SSLV3_HS_CLIENT_HELLO:
            ssl_state->current_flags = SSL_AL_FLAG_STATE_CLIENT_HELLO;

            /* Only parse the message if it is complete */
            if (input_len >= ssl_state->curr_connp->message_length &&
                      input_len >= 40) {
                rc = TLSDecodeHandshakeHello(ssl_state, input, input_len);

                if (rc < 0)
                    return rc;
            }

            break;

        case SSLV3_HS_SERVER_HELLO:
            ssl_state->current_flags = SSL_AL_FLAG_STATE_SERVER_HELLO;

            /* Only parse the message if it is complete */
            if (input_len >= ssl_state->curr_connp->message_length &&
                    input_len >= 40) {
                rc = TLSDecodeHandshakeHello(ssl_state, input,
                                             ssl_state->curr_connp->message_length);

                if (rc < 0)
                    return rc;
            }

            break;

        case SSLV3_HS_SERVER_KEY_EXCHANGE:
            ssl_state->current_flags = SSL_AL_FLAG_STATE_SERVER_KEYX;
            break;

        case SSLV3_HS_CLIENT_KEY_EXCHANGE:
            ssl_state->current_flags = SSL_AL_FLAG_STATE_CLIENT_KEYX;
            break;

        case SSLV3_HS_CERTIFICATE:
            /* For now, only decode the server certificate */
            if (direction == 0) {
                SCLogDebug("Incorrect SSL Record type sent in the toserver "
                           "direction!");
                break;
            }
            if (ssl_state->curr_connp->trec == NULL) {
                ssl_state->curr_connp->trec_len =
                        2 * ssl_state->curr_connp->record_length +
                        SSLV3_RECORD_HDR_LEN + 1;
                ssl_state->curr_connp->trec =
                        SCMalloc(ssl_state->curr_connp->trec_len);
            }
            if (ssl_state->curr_connp->trec_pos + input_len >=
                    ssl_state->curr_connp->trec_len) {
                ssl_state->curr_connp->trec_len =
                        ssl_state->curr_connp->trec_len + 2 * input_len + 1;
                ptmp = SCRealloc(ssl_state->curr_connp->trec,
                        ssl_state->curr_connp->trec_len);

                if (unlikely(ptmp == NULL)) {
                    SCFree(ssl_state->curr_connp->trec);
                }

                ssl_state->curr_connp->trec = ptmp;
            }
            if (unlikely(ssl_state->curr_connp->trec == NULL)) {
                ssl_state->curr_connp->trec_len = 0;
                /* error, skip packet */
                parsed += input_len;
                (void)parsed; /* for scan-build */
                ssl_state->curr_connp->bytes_processed += input_len;
                return -1;
            }

            uint32_t write_len = 0;
            if ((ssl_state->curr_connp->bytes_processed + input_len) >
                    ssl_state->curr_connp->record_length +
                    (SSLV3_RECORD_HDR_LEN)) {
                if ((ssl_state->curr_connp->record_length +
                        SSLV3_RECORD_HDR_LEN) <
                        ssl_state->curr_connp->bytes_processed) {
                    SSLSetEvent(ssl_state,
                            TLS_DECODER_EVENT_INVALID_SSL_RECORD);
                    return -1;
                }
                write_len = (ssl_state->curr_connp->record_length +
                        SSLV3_RECORD_HDR_LEN) -
                        ssl_state->curr_connp->bytes_processed;
            } else {
                write_len = input_len;
            }

            memcpy(ssl_state->curr_connp->trec +
                    ssl_state->curr_connp->trec_pos, initial_input, write_len);
            ssl_state->curr_connp->trec_pos += write_len;

            rc = TlsDecodeHSCertificate(ssl_state, ssl_state->curr_connp->trec,
                                        ssl_state->curr_connp->trec_pos);

            if (rc > 0) {
                /* do not return normally if the packet was fragmented:
                   we would return the size of the _entire_ message,
                   while we expect only the number of bytes parsed bytes
                   from the _current_ fragment */
                if (write_len < (ssl_state->curr_connp->trec_pos - rc)) {
                    SSLSetEvent(ssl_state,
                            TLS_DECODER_EVENT_INVALID_SSL_RECORD);
                    return -1;
                }

                uint32_t diff = write_len -
                        (ssl_state->curr_connp->trec_pos - rc);
                ssl_state->curr_connp->bytes_processed += diff;

                ssl_state->curr_connp->trec_pos = 0;
                ssl_state->curr_connp->handshake_type = 0;
                ssl_state->curr_connp->hs_bytes_processed = 0;
                ssl_state->curr_connp->message_length = 0;

                return diff;
            } else {
                ssl_state->curr_connp->bytes_processed += write_len;
                parsed += write_len;
                return parsed;
            }

            break;
        case SSLV3_HS_HELLO_REQUEST:
        case SSLV3_HS_CERTIFICATE_REQUEST:
        case SSLV3_HS_CERTIFICATE_VERIFY:
        case SSLV3_HS_FINISHED:
        case SSLV3_HS_CERTIFICATE_URL:
        case SSLV3_HS_CERTIFICATE_STATUS:
            break;
        case SSLV3_HS_NEW_SESSION_TICKET:
            SCLogDebug("new session ticket");
            break;
        default:
            SSLSetEvent(ssl_state, TLS_DECODER_EVENT_INVALID_SSL_RECORD);
            return -1;
    }

    ssl_state->flags |= ssl_state->current_flags;

    uint32_t write_len = 0;
    if ((ssl_state->curr_connp->bytes_processed + input_len) >=
            ssl_state->curr_connp->record_length + (SSLV3_RECORD_HDR_LEN)) {
        if ((ssl_state->curr_connp->record_length + SSLV3_RECORD_HDR_LEN) <
                ssl_state->curr_connp->bytes_processed) {
            SSLSetEvent(ssl_state, TLS_DECODER_EVENT_INVALID_SSL_RECORD);
            return -1;
        }
        write_len = (ssl_state->curr_connp->record_length +
                SSLV3_RECORD_HDR_LEN) - ssl_state->curr_connp->bytes_processed;
    } else {
        write_len = input_len;
    }

    if ((ssl_state->curr_connp->trec_pos + write_len) >=
            ssl_state->curr_connp->message_length) {
        if (ssl_state->curr_connp->message_length <
                ssl_state->curr_connp->trec_pos) {
            SSLSetEvent(ssl_state, TLS_DECODER_EVENT_INVALID_SSL_RECORD);
            return -1;
        }
        parsed += ssl_state->curr_connp->message_length -
                ssl_state->curr_connp->trec_pos;

        ssl_state->curr_connp->bytes_processed +=
                ssl_state->curr_connp->message_length -
                ssl_state->curr_connp->trec_pos;

        ssl_state->curr_connp->handshake_type = 0;
        ssl_state->curr_connp->hs_bytes_processed = 0;
        ssl_state->curr_connp->message_length = 0;
        ssl_state->curr_connp->trec_pos = 0;

        return parsed;
    } else {
        ssl_state->curr_connp->trec_pos += write_len;
        ssl_state->curr_connp->bytes_processed += write_len;
        parsed += write_len;
        return parsed;
    }
}

static int SSLv3ParseHandshakeProtocol(SSLState *ssl_state, uint8_t *input,
                                       uint32_t input_len, uint8_t direction)
{
    uint8_t *initial_input = input;
    int retval;

    if (input_len == 0 || ssl_state->curr_connp->bytes_processed ==
            (ssl_state->curr_connp->record_length + SSLV3_RECORD_HDR_LEN)) {
        return 0;
    }

    switch (ssl_state->curr_connp->hs_bytes_processed) {
        case 0:
            ssl_state->curr_connp->handshake_type = *(input++);
            ssl_state->curr_connp->bytes_processed++;
            ssl_state->curr_connp->hs_bytes_processed++;
            if (--input_len == 0 || ssl_state->curr_connp->bytes_processed ==
                    (ssl_state->curr_connp->record_length +
                    SSLV3_RECORD_HDR_LEN)) {
                return (input - initial_input);
            }

            /* fall through */
        case 1:
            ssl_state->curr_connp->message_length = *(input++) << 16;
            ssl_state->curr_connp->bytes_processed++;
            ssl_state->curr_connp->hs_bytes_processed++;
            if (--input_len == 0 || ssl_state->curr_connp->bytes_processed ==
                    (ssl_state->curr_connp->record_length +
                    SSLV3_RECORD_HDR_LEN)) {
                return (input - initial_input);
            }

            /* fall through */
        case 2:
            ssl_state->curr_connp->message_length |= *(input++) << 8;
            ssl_state->curr_connp->bytes_processed++;
            ssl_state->curr_connp->hs_bytes_processed++;
            if (--input_len == 0 || ssl_state->curr_connp->bytes_processed ==
                    (ssl_state->curr_connp->record_length +
                    SSLV3_RECORD_HDR_LEN)) {
                return (input - initial_input);
            }

            /* fall through */
        case 3:
            ssl_state->curr_connp->message_length |= *(input++);
            ssl_state->curr_connp->bytes_processed++;
            ssl_state->curr_connp->hs_bytes_processed++;
            --input_len;

            /* fall through */
    }

    retval = SSLv3ParseHandshakeType(ssl_state, input, input_len, direction);
    if (retval < 0) {
        return retval;
    }

    input += retval;

    return (input - initial_input);
}

/**
 * \internal
 * \brief TLS Heartbeat parser (see RFC 6520)
 *
 * \param sslstate  Pointer to the SSL state.
 * \param input     Pointer to the received input data.
 * \param input_len Length in bytes of the received data.
 * \param direction 1 toclient, 0 toserver
 *
 * \retval The number of bytes parsed on success, 0 if nothing parsed, -1 on failure.
 */
static int SSLv3ParseHeartbeatProtocol(SSLState *ssl_state, uint8_t *input,
                                       uint32_t input_len, uint8_t direction)
{
    uint8_t hb_type;
    uint16_t payload_len;
    uint16_t padding_len;

    /* expect at least 3 bytes: heartbeat type (1) + length (2) */
    if (input_len < 3) {
        return 0;
    }

    hb_type = *input++;

    if (!(ssl_state->flags & SSL_AL_FLAG_CHANGE_CIPHER_SPEC)) {
        if (!(hb_type == TLS_HB_REQUEST || hb_type == TLS_HB_RESPONSE)) {
            SSLSetEvent(ssl_state, TLS_DECODER_EVENT_INVALID_HEARTBEAT);
            return -1;
        }
    }

    if ((ssl_state->flags & SSL_AL_FLAG_HB_INFLIGHT) == 0) {
        ssl_state->flags |= SSL_AL_FLAG_HB_INFLIGHT;

        if (direction) {
            SCLogDebug("HeartBeat Record type sent in the toclient direction!");
            ssl_state->flags |= SSL_AL_FLAG_HB_SERVER_INIT;
        } else {
            SCLogDebug("HeartBeat Record type sent in the toserver direction!");
            ssl_state->flags |= SSL_AL_FLAG_HB_CLIENT_INIT;
        }

        /* if we reach this point, then we can assume that the HB request
           is encrypted. If so, let's set the HB record length */
        if (ssl_state->flags & SSL_AL_FLAG_CHANGE_CIPHER_SPEC) {
            ssl_state->hb_record_len = ssl_state->curr_connp->record_length;
            SCLogDebug("Encrypted HeartBeat Request In-flight. Storing len %u",
                       ssl_state->hb_record_len);
            return (ssl_state->curr_connp->record_length - 3);
        }

        payload_len = (*input++) << 8;
        payload_len |= (*input++);

        /* check that the requested payload length is really present in
           the record (CVE-2014-0160) */
        if ((uint32_t)(payload_len+3) > ssl_state->curr_connp->record_length) {
            SCLogDebug("We have a short record in HeartBeat Request");
            SSLSetEvent(ssl_state, TLS_DECODER_EVENT_OVERFLOW_HEARTBEAT);
            return -1;
        }

        /* check the padding length. It must be at least 16 bytes
           (RFC 6520, section 4) */
        padding_len = ssl_state->curr_connp->record_length - payload_len - 3;
        if (padding_len < 16) {
            SCLogDebug("We have a short record in HeartBeat Request");
            SSLSetEvent(ssl_state, TLS_DECODER_EVENT_INVALID_HEARTBEAT);
            return -1;
        }

        /* we don't have the payload */
        if (input_len < payload_len + padding_len) {
            return 0;
        }

    /* OpenSSL still seems to discard multiple in-flight
       heartbeats although some tools send multiple at once */
    } else if (direction == 1 && (ssl_state->flags & SSL_AL_FLAG_HB_INFLIGHT) &&
            (ssl_state->flags & SSL_AL_FLAG_HB_SERVER_INIT)) {
        SCLogDebug("Multiple in-flight server initiated HeartBeats");
        SSLSetEvent(ssl_state, TLS_DECODER_EVENT_INVALID_HEARTBEAT);
        return -1;

    } else if (direction == 0 && (ssl_state->flags & SSL_AL_FLAG_HB_INFLIGHT) &&
            (ssl_state->flags & SSL_AL_FLAG_HB_CLIENT_INIT)) {
        SCLogDebug("Multiple in-flight client initiated HeartBeats");
        SSLSetEvent(ssl_state, TLS_DECODER_EVENT_INVALID_HEARTBEAT);
        return -1;

    } else {
        /* we have a HB record in the opposite direction of the request,
           let's reset our flags */
        ssl_state->flags &= ~SSL_AL_FLAG_HB_INFLIGHT;
        ssl_state->flags &= ~SSL_AL_FLAG_HB_SERVER_INIT;
        ssl_state->flags &= ~SSL_AL_FLAG_HB_CLIENT_INIT;

        /* if we reach this point, then we can assume that the HB request
           is encrypted. If so, let's set the HB record length */
        if (ssl_state->flags & SSL_AL_FLAG_CHANGE_CIPHER_SPEC) {
            /* check to see if the encrypted response is longer than the
               encrypted request */
            if (ssl_state->hb_record_len > 0 && ssl_state->hb_record_len <
                    ssl_state->curr_connp->record_length) {
                SCLogDebug("My heart is bleeding.. OpenSSL HeartBleed response (%u)",
                        ssl_state->hb_record_len);
                SSLSetEvent(ssl_state,
                        TLS_DECODER_EVENT_DATALEAK_HEARTBEAT_MISMATCH);
                ssl_state->hb_record_len = 0;
                return -1;
            }
        }

        /* reset the HB record length in case we have a legit HB followed
           by a bad one */
        ssl_state->hb_record_len = 0;
    }

    /* skip the HeartBeat, 3 bytes were already parsed,
       e.g |18 03 02| for TLS 1.2 */
    return (ssl_state->curr_connp->record_length - 3);
}

static int SSLv3ParseRecord(uint8_t direction, SSLState *ssl_state,
                            uint8_t *input, uint32_t input_len)
{
    uint8_t *initial_input = input;

    if (input_len == 0) {
        return 0;
    }

    uint8_t skip_version = 0;

    /* Only set SSL/TLS version here if it has not already been set in
       client/server hello. */
    if (direction == 0) {
        if ((ssl_state->flags & SSL_AL_FLAG_STATE_CLIENT_HELLO) &&
                (ssl_state->client_connp.version != TLS_VERSION_UNKNOWN)) {
            skip_version = 1;
        }
    } else {
        if ((ssl_state->flags & SSL_AL_FLAG_STATE_SERVER_HELLO) &&
                (ssl_state->server_connp.version != TLS_VERSION_UNKNOWN)) {
            skip_version = 1;
        }
    }

    switch (ssl_state->curr_connp->bytes_processed) {
        case 0:
            if (input_len >= 5) {
                ssl_state->curr_connp->content_type = input[0];
                if (!skip_version) {
                    ssl_state->curr_connp->version = input[1] << 8;
                    ssl_state->curr_connp->version |= input[2];
                }
                ssl_state->curr_connp->record_length = input[3] << 8;
                ssl_state->curr_connp->record_length |= input[4];
                ssl_state->curr_connp->bytes_processed += SSLV3_RECORD_HDR_LEN;
                return SSLV3_RECORD_HDR_LEN;
            } else {
                ssl_state->curr_connp->content_type = *(input++);
                if (--input_len == 0)
                    break;
            }

            /* fall through */
        case 1:
            if (!skip_version) {
                ssl_state->curr_connp->version = *(input++) << 8;
            } else {
                input++;
            }
            if (--input_len == 0)
                break;

            /* fall through */
        case 2:
            if (!skip_version) {
                ssl_state->curr_connp->version |= *(input++);
            } else {
                input++;
            }
            if (--input_len == 0)
                break;

            /* fall through */
        case 3:
            ssl_state->curr_connp->record_length = *(input++) << 8;
            if (--input_len == 0)
                break;

            /* fall through */
        case 4:
            ssl_state->curr_connp->record_length |= *(input++);
            if (--input_len == 0)
                break;

            /* fall through */
    }

    ssl_state->curr_connp->bytes_processed += (input - initial_input);

    return (input - initial_input);
}

static int SSLv2ParseRecord(uint8_t direction, SSLState *ssl_state,
                            uint8_t *input, uint32_t input_len)
{
    uint8_t *initial_input = input;

    if (input_len == 0) {
        return 0;
    }

    if (ssl_state->curr_connp->record_lengths_length == 2) {
        switch (ssl_state->curr_connp->bytes_processed) {
            case 0:
                if (input_len >= ssl_state->curr_connp->record_lengths_length + 1) {
                    ssl_state->curr_connp->record_length = (0x7f & input[0]) << 8 | input[1];
                    ssl_state->curr_connp->content_type = input[2];
                    ssl_state->curr_connp->version = SSL_VERSION_2;
                    ssl_state->curr_connp->bytes_processed += 3;
                    return 3;
                } else {
                    ssl_state->curr_connp->record_length = (0x7f & *(input++)) << 8;
                    if (--input_len == 0)
                        break;
                }

                /* fall through */
            case 1:
                ssl_state->curr_connp->record_length |= *(input++);
                if (--input_len == 0)
                    break;

                /* fall through */
            case 2:
                ssl_state->curr_connp->content_type = *(input++);
                ssl_state->curr_connp->version = SSL_VERSION_2;
                if (--input_len == 0)
                    break;

                /* fall through */
        }

    } else {
        switch (ssl_state->curr_connp->bytes_processed) {
            case 0:
                if (input_len >= ssl_state->curr_connp->record_lengths_length + 1) {
                    ssl_state->curr_connp->record_length = (0x3f & input[0]) << 8 | input[1];
                    ssl_state->curr_connp->content_type = input[3];
                    ssl_state->curr_connp->version = SSL_VERSION_2;
                    ssl_state->curr_connp->bytes_processed += 4;
                    return 4;
                } else {
                    ssl_state->curr_connp->record_length = (0x3f & *(input++)) << 8;
                    if (--input_len == 0)
                        break;
                }

                /* fall through */
            case 1:
                ssl_state->curr_connp->record_length |= *(input++);
                if (--input_len == 0)
                    break;

                /* fall through */
            case 2:
                /* padding */
                input++;
                if (--input_len == 0)
                    break;

                /* fall through */
            case 3:
                ssl_state->curr_connp->content_type = *(input++);
                ssl_state->curr_connp->version = SSL_VERSION_2;
                if (--input_len == 0)
                    break;

                /* fall through */
        }
    }

    ssl_state->curr_connp->bytes_processed += (input - initial_input);

    return (input - initial_input);
}

static int SSLv2Decode(uint8_t direction, SSLState *ssl_state,
                       AppLayerParserState *pstate, uint8_t *input,
                       uint32_t input_len)
{
    int retval = 0;
    uint8_t *initial_input = input;

    if (ssl_state->curr_connp->bytes_processed == 0) {
        if (input[0] & 0x80) {
            ssl_state->curr_connp->record_lengths_length = 2;
        } else {
            ssl_state->curr_connp->record_lengths_length = 3;
        }
    }

    /* the +1 is because we read one extra byte inside SSLv2ParseRecord
       to read the msg_type */
    if (ssl_state->curr_connp->bytes_processed <
            (ssl_state->curr_connp->record_lengths_length + 1)) {
        retval = SSLv2ParseRecord(direction, ssl_state, input, input_len);
        if (retval == -1) {
            SSLSetEvent(ssl_state, TLS_DECODER_EVENT_INVALID_SSLV2_HEADER);
            return -1;
        } else {
            input += retval;
            input_len -= retval;
        }
    }

    if (input_len == 0) {
        return (input - initial_input);
    }

    /* record_length should never be zero */
    if (ssl_state->curr_connp->record_length == 0) {
        SCLogDebug("SSLv2 record length is zero");
        SSLSetEvent(ssl_state, TLS_DECODER_EVENT_INVALID_SSLV2_HEADER);
        return -1;
    }

    /* record_lenghts_length should never be zero */
    if (ssl_state->curr_connp->record_lengths_length == 0) {
        SCLogDebug("SSLv2 record lengths length is zero");
        SSLSetEvent(ssl_state, TLS_DECODER_EVENT_INVALID_SSLV2_HEADER);
        return -1;
    }

    switch (ssl_state->curr_connp->content_type) {
        case SSLV2_MT_ERROR:
            SCLogDebug("SSLV2_MT_ERROR msg_type received. Error encountered "
                       "in establishing the sslv2 session, may be version");
            SSLSetEvent(ssl_state, TLS_DECODER_EVENT_ERROR_MSG_ENCOUNTERED);

            break;

        case SSLV2_MT_CLIENT_HELLO:
            ssl_state->current_flags = SSL_AL_FLAG_STATE_CLIENT_HELLO;
            ssl_state->current_flags |= SSL_AL_FLAG_SSL_CLIENT_HS;

            if (ssl_state->curr_connp->record_lengths_length == 3) {
                switch (ssl_state->curr_connp->bytes_processed) {
                    case 4:
                        if (input_len >= 6) {
                            ssl_state->curr_connp->session_id_length = input[4] << 8;
                            ssl_state->curr_connp->session_id_length |= input[5];
                            input += 6;
                            input_len -= 6;
                            ssl_state->curr_connp->bytes_processed += 6;
                            if (ssl_state->curr_connp->session_id_length == 0) {
                                ssl_state->current_flags |= SSL_AL_FLAG_SSL_NO_SESSION_ID;
                            }

                            break;
                        } else {
                            input++;
                            ssl_state->curr_connp->bytes_processed++;
                            if (--input_len == 0)
                                break;
                        }

                        /* fall through */
                    case 5:
                        input++;
                        ssl_state->curr_connp->bytes_processed++;
                        if (--input_len == 0)
                            break;

                        /* fall through */
                    case 6:
                        input++;
                        ssl_state->curr_connp->bytes_processed++;
                        if (--input_len == 0)
                            break;

                        /* fall through */
                    case 7:
                        input++;
                        ssl_state->curr_connp->bytes_processed++;
                        if (--input_len == 0)
                            break;

                        /* fall through */
                    case 8:
                        ssl_state->curr_connp->session_id_length = *(input++) << 8;
                        ssl_state->curr_connp->bytes_processed++;
                        if (--input_len == 0)
                            break;

                        /* fall through */
                    case 9:
                        ssl_state->curr_connp->session_id_length |= *(input++);
                        ssl_state->curr_connp->bytes_processed++;
                        if (--input_len == 0)
                            break;

                        /* fall through */
                }

            } else {
                switch (ssl_state->curr_connp->bytes_processed) {
                    case 3:
                        if (input_len >= 6) {
                            ssl_state->curr_connp->session_id_length = input[4] << 8;
                            ssl_state->curr_connp->session_id_length |= input[5];
                            input += 6;
                            input_len -= 6;
                            ssl_state->curr_connp->bytes_processed += 6;
                            if (ssl_state->curr_connp->session_id_length == 0) {
                                ssl_state->current_flags |= SSL_AL_FLAG_SSL_NO_SESSION_ID;
                            }

                            break;
                        } else {
                            input++;
                            ssl_state->curr_connp->bytes_processed++;
                            if (--input_len == 0)
                                break;
                        }

                        /* fall through */
                    case 4:
                        input++;
                        ssl_state->curr_connp->bytes_processed++;
                        if (--input_len == 0)
                            break;

                        /* fall through */
                    case 5:
                        input++;
                        ssl_state->curr_connp->bytes_processed++;
                        if (--input_len == 0)
                            break;

                        /* fall through */
                    case 6:
                        input++;
                        ssl_state->curr_connp->bytes_processed++;
                        if (--input_len == 0)
                            break;

                        /* fall through */
                    case 7:
                        ssl_state->curr_connp->session_id_length = *(input++) << 8;
                        ssl_state->curr_connp->bytes_processed++;
                        if (--input_len == 0)
                            break;

                        /* fall through */
                    case 8:
                        ssl_state->curr_connp->session_id_length |= *(input++);
                        ssl_state->curr_connp->bytes_processed++;
                        if (--input_len == 0)
                            break;

                        /* fall through */
                }
            }

            break;

        case SSLV2_MT_CLIENT_MASTER_KEY:
            if (!(ssl_state->flags & SSL_AL_FLAG_SSL_CLIENT_HS)) {
                SCLogDebug("Client hello is not seen before master key "
                           "message!");
            }
            ssl_state->current_flags = SSL_AL_FLAG_SSL_CLIENT_MASTER_KEY;

            break;

        case SSLV2_MT_CLIENT_CERTIFICATE:
            if (direction == 1) {
                SCLogDebug("Incorrect SSL Record type sent in the toclient "
                           "direction!");
            } else {
                ssl_state->current_flags = SSL_AL_FLAG_STATE_CLIENT_KEYX;
            }

            /* fall through */
        case SSLV2_MT_SERVER_VERIFY:
        case SSLV2_MT_SERVER_FINISHED:
            if (direction == 0 &&
                    !(ssl_state->curr_connp->content_type &
                    SSLV2_MT_CLIENT_CERTIFICATE)) {
                SCLogDebug("Incorrect SSL Record type sent in the toserver "
                           "direction!");
            }

            /* fall through */
        case SSLV2_MT_CLIENT_FINISHED:
        case SSLV2_MT_REQUEST_CERTIFICATE:
            /* both client hello and server hello must be seen */
            if ((ssl_state->flags & SSL_AL_FLAG_SSL_CLIENT_HS) &&
                    (ssl_state->flags & SSL_AL_FLAG_SSL_SERVER_HS)) {

                if (direction == 0) {
                    if (ssl_state->flags & SSL_AL_FLAG_SSL_NO_SESSION_ID) {
                        ssl_state->current_flags |= SSL_AL_FLAG_SSL_CLIENT_SSN_ENCRYPTED;
                        SCLogDebug("SSLv2 client side has started the encryption");
                    } else if (ssl_state->flags & SSL_AL_FLAG_SSL_CLIENT_MASTER_KEY) {
                        ssl_state->current_flags = SSL_AL_FLAG_SSL_CLIENT_SSN_ENCRYPTED;
                        SCLogDebug("SSLv2 client side has started the encryption");
                    }
                } else {
                    ssl_state->current_flags = SSL_AL_FLAG_SSL_SERVER_SSN_ENCRYPTED;
                    SCLogDebug("SSLv2 Server side has started the encryption");
                }

                if ((ssl_state->flags & SSL_AL_FLAG_SSL_CLIENT_SSN_ENCRYPTED) &&
                    (ssl_state->flags & SSL_AL_FLAG_SSL_SERVER_SSN_ENCRYPTED))
                {
                    if (ssl_config.encrypt_mode != SSL_CNF_ENC_HANDLE_FULL) {
                        AppLayerParserStateSetFlag(pstate,
                                APP_LAYER_PARSER_NO_INSPECTION);
                    }

                    if (ssl_config.encrypt_mode == SSL_CNF_ENC_HANDLE_BYPASS) {
                        AppLayerParserStateSetFlag(pstate, APP_LAYER_PARSER_NO_REASSEMBLY);
                        AppLayerParserStateSetFlag(pstate, APP_LAYER_PARSER_BYPASS_READY);
                    }
                    SCLogDebug("SSLv2 No reassembly & inspection has been set");
                }
            }

            break;

        case SSLV2_MT_SERVER_HELLO:
            ssl_state->current_flags = SSL_AL_FLAG_STATE_SERVER_HELLO;
            ssl_state->current_flags |= SSL_AL_FLAG_SSL_SERVER_HS;

            break;
    }

    ssl_state->flags |= ssl_state->current_flags;

    if (input_len + ssl_state->curr_connp->bytes_processed >=
            (ssl_state->curr_connp->record_length +
            ssl_state->curr_connp->record_lengths_length)) {

        /* looks like we have another record after this */
        uint32_t diff = ssl_state->curr_connp->record_length +
                ssl_state->curr_connp->record_lengths_length + -
                ssl_state->curr_connp->bytes_processed;
        input += diff;
        SSLParserReset(ssl_state);
        return (input - initial_input);

    /* we still don't have the entire record for the one we are
       currently parsing */
    } else {
        input += input_len;
        ssl_state->curr_connp->bytes_processed += input_len;
        return (input - initial_input);
    }
}

static int SSLv3Decode(uint8_t direction, SSLState *ssl_state,
                       AppLayerParserState *pstate, uint8_t *input,
                       uint32_t input_len)
{
    int retval = 0;
    uint32_t parsed = 0;

    if (ssl_state->curr_connp->bytes_processed < SSLV3_RECORD_HDR_LEN) {
        retval = SSLv3ParseRecord(direction, ssl_state, input, input_len);
        if (retval < 0) {
            SSLSetEvent(ssl_state, TLS_DECODER_EVENT_INVALID_TLS_HEADER);
            return -1;
        } else {
            parsed += retval;
            input_len -= retval;
        }
    }

    if (input_len == 0) {
        return parsed;
    }

    /* record_length should never be zero */
    if (ssl_state->curr_connp->record_length == 0) {
        SCLogDebug("SSLv3 Record length is 0");
        SSLSetEvent(ssl_state, TLS_DECODER_EVENT_INVALID_TLS_HEADER);
        return -1;
    }

    switch (ssl_state->curr_connp->content_type) {

        /* we don't need any data from these types */
        case SSLV3_CHANGE_CIPHER_SPEC:
            ssl_state->flags |= SSL_AL_FLAG_CHANGE_CIPHER_SPEC;

            if (direction) {
                ssl_state->flags |= SSL_AL_FLAG_SERVER_CHANGE_CIPHER_SPEC;
            } else {
                ssl_state->flags |= SSL_AL_FLAG_CLIENT_CHANGE_CIPHER_SPEC;
            }

            break;

        case SSLV3_ALERT_PROTOCOL:
            break;

        case SSLV3_APPLICATION_PROTOCOL:
            /* In TLSv1.3 early data (0-RTT) could be sent before the
               handshake is complete (rfc8446, section 2.3). We should
               therefore not mark the handshake as done before we have
               seen the ServerHello record. */
            if ((ssl_state->flags & SSL_AL_FLAG_EARLY_DATA) &&
                    ((ssl_state->flags & SSL_AL_FLAG_STATE_SERVER_HELLO) == 0))
                break;

            /* if we see (encrypted) aplication data, then this means the
               handshake must be done */
            ssl_state->flags |= SSL_AL_FLAG_HANDSHAKE_DONE;

            if (ssl_config.encrypt_mode != SSL_CNF_ENC_HANDLE_FULL) {
                SCLogDebug("setting APP_LAYER_PARSER_NO_INSPECTION_PAYLOAD");
                AppLayerParserStateSetFlag(pstate,
                        APP_LAYER_PARSER_NO_INSPECTION_PAYLOAD);
            }

            /* Encrypted data, reassembly not asked, bypass asked, let's sacrifice
             * heartbeat lke inspection to be able to be able to bypass the flow */
            if (ssl_config.encrypt_mode == SSL_CNF_ENC_HANDLE_BYPASS) {
                SCLogDebug("setting APP_LAYER_PARSER_NO_REASSEMBLY");
                AppLayerParserStateSetFlag(pstate,
                        APP_LAYER_PARSER_NO_REASSEMBLY);
                AppLayerParserStateSetFlag(pstate,
                        APP_LAYER_PARSER_NO_INSPECTION);
                AppLayerParserStateSetFlag(pstate,
                        APP_LAYER_PARSER_BYPASS_READY);
            }

            break;

        case SSLV3_HANDSHAKE_PROTOCOL:
            if (ssl_state->flags & SSL_AL_FLAG_CHANGE_CIPHER_SPEC) {
                /* In TLSv1.3, ChangeCipherSpec is only used for middlebox
                   compability (rfc8446, appendix D.4). */
                if ((ssl_state->client_connp.version > TLS_VERSION_12) &&
                       ((ssl_state->flags & SSL_AL_FLAG_STATE_SERVER_HELLO) == 0)) {
                    /* do nothing */
                } else {
                    break;
                }
            }

            if (ssl_state->curr_connp->record_length < 4) {
                SSLParserReset(ssl_state);
                SSLSetEvent(ssl_state, TLS_DECODER_EVENT_INVALID_SSL_RECORD);
                return -1;
            }

            retval = SSLv3ParseHandshakeProtocol(ssl_state, input + parsed,
                                                 input_len, direction);
            if (retval < 0) {
                SSLSetEvent(ssl_state,
                        TLS_DECODER_EVENT_INVALID_HANDSHAKE_MESSAGE);
                SSLSetEvent(ssl_state,
                        TLS_DECODER_EVENT_INVALID_SSL_RECORD);
                return -1;
            } else {
                if ((uint32_t)retval > input_len) {
                    SCLogDebug("Error parsing SSLv3.x. Reseting parser "
                               "state. Let's get outta here");
                    SSLParserReset(ssl_state);
                    SSLSetEvent(ssl_state,
                            TLS_DECODER_EVENT_INVALID_SSL_RECORD);
                    return -1;
                }

                parsed += retval;
                input_len -= retval;
                (void)input_len; /* for scan-build */

                if (ssl_state->curr_connp->bytes_processed ==
                        ssl_state->curr_connp->record_length +
                        SSLV3_RECORD_HDR_LEN) {
                    SSLParserReset(ssl_state);
                }

                SCLogDebug("trigger RAW! (post HS)");
                AppLayerParserTriggerRawStreamReassembly(ssl_state->f,
                        direction == 0 ? STREAM_TOSERVER : STREAM_TOCLIENT);
                return parsed;
            }

            break;

        case SSLV3_HEARTBEAT_PROTOCOL:
            retval = SSLv3ParseHeartbeatProtocol(ssl_state, input + parsed,
                                                 input_len, direction);
            if (retval < 0)
                return -1;

            break;

        default:
            /* \todo fix the event from invalid rule to unknown rule */
            SSLSetEvent(ssl_state, TLS_DECODER_EVENT_INVALID_RECORD_TYPE);
            SSLSetEvent(ssl_state, TLS_DECODER_EVENT_INVALID_SSL_RECORD);
            return -1;
    }

    if (input_len + ssl_state->curr_connp->bytes_processed >=
            ssl_state->curr_connp->record_length + SSLV3_RECORD_HDR_LEN) {
        if ((ssl_state->curr_connp->record_length + SSLV3_RECORD_HDR_LEN) <
                ssl_state->curr_connp->bytes_processed) {
            /* defensive checks. Something is wrong. */
            SSLSetEvent(ssl_state, TLS_DECODER_EVENT_INVALID_SSL_RECORD);
            return -1;
        }

        SCLogDebug("record complete, trigger RAW");
        AppLayerParserTriggerRawStreamReassembly(ssl_state->f,
                direction == 0 ? STREAM_TOSERVER : STREAM_TOCLIENT);

        /* looks like we have another record */
        uint32_t diff = ssl_state->curr_connp->record_length +
                SSLV3_RECORD_HDR_LEN - ssl_state->curr_connp->bytes_processed;
        parsed += diff;
        SSLParserReset(ssl_state);
        return parsed;

    /* we still don't have the entire record for the one we are
       currently parsing */
    } else {
        parsed += input_len;
        ssl_state->curr_connp->bytes_processed += input_len;
        return parsed;
    }

}

/**
 * \internal
 * \brief SSLv2, SSLv23, SSLv3, TLSv1.1, TLSv1.2, TLSv1.3 parser.
 *
 *        On parsing error, this should be the only function that should reset
 *        the parser state, to avoid multiple functions in the chain reseting
 *        the parser state.
 *
 * \param direction 0 for toserver, 1 for toclient.
 * \param alstate   Pointer to the state.
 * \param pstate    Application layer parser state for this session.
 * \param input     Pointer the received input data.
 * \param input_len Length in bytes of the received data.
 * \param output    Pointer to the list of parsed output elements.
 *
 * \todo On reaching an inconsistent state, check if the input has
 *  another new record, instead of just returning after the reset
 *
 * \retval >=0 On success.
 */
static int SSLDecode(Flow *f, uint8_t direction, void *alstate, AppLayerParserState *pstate,
                     uint8_t *input, uint32_t ilen)
{
    SSLState *ssl_state = (SSLState *)alstate;
    int retval = 0;
    uint32_t counter = 0;

    int32_t input_len = (int32_t)ilen;

    ssl_state->f = f;

    if (input == NULL &&
            AppLayerParserStateIssetFlag(pstate, APP_LAYER_PARSER_EOF)) {
        /* flag session as finished if APP_LAYER_PARSER_EOF is set */
        ssl_state->flags |= SSL_AL_FLAG_STATE_FINISHED;
        SCReturnInt(1);
    } else if (input == NULL || input_len == 0) {
        SCReturnInt(-1);
    }

    if (direction == 0)
        ssl_state->curr_connp = &ssl_state->client_connp;
    else
        ssl_state->curr_connp = &ssl_state->server_connp;

    /* If entering on a new record, reset the current flags. */
    if (ssl_state->curr_connp->bytes_processed == 0) {
        ssl_state->current_flags = 0;
    }

    /* if we have more than one record */
    uint32_t max_records = MAX((input_len / SSL_RECORD_MINIMUM_LENGTH),1);
    while (input_len > 0) {
        if (counter > max_records) {
            SCLogDebug("Looks like we have looped quite a bit. Reset state "
                       "and get out of here");
            SSLParserReset(ssl_state);
            SSLSetEvent(ssl_state,
                        TLS_DECODER_EVENT_TOO_MANY_RECORDS_IN_PACKET);
            return -1;
        }

        /* ssl_state->bytes_processed is zero for a fresh record or
           positive to indicate a record currently being parsed */
        switch (ssl_state->curr_connp->bytes_processed) {
            /* fresh record */
            case 0:
                /* only SSLv2, has one of the top 2 bits set */
                if ((input[0] & 0x80) || (input[0] & 0x40)) {
                    SCLogDebug("SSLv2 detected");
                    ssl_state->curr_connp->version = SSL_VERSION_2;
                    retval = SSLv2Decode(direction, ssl_state, pstate, input,
                                         input_len);
                    if (retval < 0) {
                        SCLogDebug("Error parsing SSLv2.x. Reseting parser "
                                   "state. Let's get outta here");
                        SSLParserReset(ssl_state);
                        SSLSetEvent(ssl_state,
                                TLS_DECODER_EVENT_INVALID_SSL_RECORD);
                        return -1;
                    } else {
                        input_len -= retval;
                        input += retval;
                    }
                } else {
                    SCLogDebug("SSLv3.x detected");
                    retval = SSLv3Decode(direction, ssl_state, pstate, input,
                                         input_len);
                    if (retval < 0) {
                        SCLogDebug("Error parsing SSLv3.x. Reseting parser "
                                   "state. Let's get outta here");
                        SSLParserReset(ssl_state);
                        SSLSetEvent(ssl_state,
                                TLS_DECODER_EVENT_INVALID_SSL_RECORD);
                        return -1;
                    } else {
                        input_len -= retval;
                        input += retval;
                        if (ssl_state->curr_connp->bytes_processed == SSLV3_RECORD_HDR_LEN
                                && ssl_state->curr_connp->record_length == 0) {
                            /* empty record */
                            SSLParserReset(ssl_state);
                        }
                    }
                }

                break;

            default:
                /* we would have established by now if we are dealing with
                 * SSLv2 or above */
                if (ssl_state->curr_connp->version == SSL_VERSION_2) {
                    SCLogDebug("Continuing parsing SSLv2 record from where we "
                               "previously left off");
                    retval = SSLv2Decode(direction, ssl_state, pstate, input,
                                         input_len);
                    if (retval < 0) {
                        SCLogDebug("Error parsing SSLv2.x.  Reseting parser "
                                   "state.  Let's get outta here");
                        SSLParserReset(ssl_state);
                        return 0;
                    } else {
                        input_len -= retval;
                        input += retval;
                    }
                } else {
                    SCLogDebug("Continuing parsing SSLv3.x record from where we "
                               "previously left off");
                    retval = SSLv3Decode(direction, ssl_state, pstate, input,
                                         input_len);
                    if (retval < 0) {
                        SCLogDebug("Error parsing SSLv3.x.  Reseting parser "
                                   "state.  Let's get outta here");
                        SSLParserReset(ssl_state);
                        return 0;
                    } else {
                        if (retval > input_len) {
                            SCLogDebug("Error parsing SSLv3.x.  Reseting parser "
                                       "state.  Let's get outta here");
                            SSLParserReset(ssl_state);
                        }
                        input_len -= retval;
                        input += retval;
                        if (ssl_state->curr_connp->bytes_processed == SSLV3_RECORD_HDR_LEN
                            && ssl_state->curr_connp->record_length == 0) {
                            /* empty record */
                            SSLParserReset(ssl_state);
                        }
                    }
                }

                break;
        } /* switch (ssl_state->curr_connp->bytes_processed) */

        counter++;
    } /* while (input_len) */

    /* mark handshake as done if we have subject and issuer */
    if (ssl_state->server_connp.cert0_subject &&
            ssl_state->server_connp.cert0_issuerdn)
        ssl_state->flags |= SSL_AL_FLAG_HANDSHAKE_DONE;

    /* flag session as finished if APP_LAYER_PARSER_EOF is set */
    if (AppLayerParserStateIssetFlag(pstate, APP_LAYER_PARSER_EOF))
        ssl_state->flags |= SSL_AL_FLAG_STATE_FINISHED;

    return 1;
}

static int SSLParseClientRecord(Flow *f, void *alstate, AppLayerParserState *pstate,
                         uint8_t *input, uint32_t input_len,
                         void *local_data, const uint8_t flags)
{
    return SSLDecode(f, 0 /* toserver */, alstate, pstate, input, input_len);
}

static int SSLParseServerRecord(Flow *f, void *alstate, AppLayerParserState *pstate,
                         uint8_t *input, uint32_t input_len,
                         void *local_data, const uint8_t flags)
{
    return SSLDecode(f, 1 /* toclient */, alstate, pstate, input, input_len);
}

/**
 * \internal
 * \brief Function to allocate the SSL state memory.
 */
static void *SSLStateAlloc(void)
{
    SSLState *ssl_state = SCMalloc(sizeof(SSLState));
    if (unlikely(ssl_state == NULL))
        return NULL;
    memset(ssl_state, 0, sizeof(SSLState));
    ssl_state->client_connp.cert_log_flag = 0;
    ssl_state->server_connp.cert_log_flag = 0;
    TAILQ_INIT(&ssl_state->server_connp.certs);

    return (void *)ssl_state;
}

/**
 * \internal
 * \brief Function to free the SSL state memory.
 */
static void SSLStateFree(void *p)
{
    SSLState *ssl_state = (SSLState *)p;
    SSLCertsChain *item;

    if (ssl_state->client_connp.trec)
        SCFree(ssl_state->client_connp.trec);
    if (ssl_state->client_connp.cert0_subject)
        SCFree(ssl_state->client_connp.cert0_subject);
    if (ssl_state->client_connp.cert0_issuerdn)
        SCFree(ssl_state->client_connp.cert0_issuerdn);
    if (ssl_state->server_connp.cert0_serial)
        SCFree(ssl_state->server_connp.cert0_serial);
    if (ssl_state->client_connp.cert0_fingerprint)
        SCFree(ssl_state->client_connp.cert0_fingerprint);
    if (ssl_state->client_connp.sni)
        SCFree(ssl_state->client_connp.sni);
    if (ssl_state->client_connp.session_id)
        SCFree(ssl_state->client_connp.session_id);

    if (ssl_state->server_connp.trec)
        SCFree(ssl_state->server_connp.trec);
    if (ssl_state->server_connp.cert0_subject)
        SCFree(ssl_state->server_connp.cert0_subject);
    if (ssl_state->server_connp.cert0_issuerdn)
        SCFree(ssl_state->server_connp.cert0_issuerdn);
    if (ssl_state->server_connp.cert0_fingerprint)
        SCFree(ssl_state->server_connp.cert0_fingerprint);
    if (ssl_state->server_connp.sni)
        SCFree(ssl_state->server_connp.sni);
    if (ssl_state->server_connp.session_id)
        SCFree(ssl_state->server_connp.session_id);

    if (ssl_state->client_connp.ja3_str)
        Ja3BufferFree(&ssl_state->client_connp.ja3_str);
    if (ssl_state->client_connp.ja3_hash)
        SCFree(ssl_state->client_connp.ja3_hash);
    if (ssl_state->server_connp.ja3_str)
        Ja3BufferFree(&ssl_state->server_connp.ja3_str);
    if (ssl_state->server_connp.ja3_hash)
        SCFree(ssl_state->server_connp.ja3_hash);

    AppLayerDecoderEventsFreeEvents(&ssl_state->decoder_events);

    if (ssl_state->de_state != NULL) {
        DetectEngineStateFree(ssl_state->de_state);
    }

    /* Free certificate chain */
    while ((item = TAILQ_FIRST(&ssl_state->server_connp.certs))) {
        TAILQ_REMOVE(&ssl_state->server_connp.certs, item, next);
        SCFree(item);
    }
    TAILQ_INIT(&ssl_state->server_connp.certs);

    SCFree(ssl_state);

    return;
}

static void SSLStateTransactionFree(void *state, uint64_t tx_id)
{
    /* do nothing */
}

static AppProto SSLProbingParser(Flow *f, uint8_t direction,
        uint8_t *input, uint32_t ilen, uint8_t *rdir)
{
    /* probably a rst/fin sending an eof */
    if (ilen < 3)
        return ALPROTO_UNKNOWN;

    /* for now just the 3 byte header ones */
    /* \todo Detect the 2 byte ones */
    if ((input[0] & 0x80) && (input[2] == 0x01)) {
        return ALPROTO_TLS;
    }

    return ALPROTO_FAILED;
}

static int SSLStateGetEventInfo(const char *event_name,
                         int *event_id, AppLayerEventType *event_type)
{
    *event_id = SCMapEnumNameToValue(event_name, tls_decoder_event_table);
    if (*event_id == -1) {
        SCLogError(SC_ERR_INVALID_ENUM_MAP, "event \"%s\" not present in "
                   "ssl's enum map table.",  event_name);
        /* yes this is fatal */
        return -1;
    }

    *event_type = APP_LAYER_EVENT_TYPE_TRANSACTION;

    return 0;
}

static int SSLStateGetEventInfoById(int event_id, const char **event_name,
                                    AppLayerEventType *event_type)
{
    *event_name = SCMapEnumValueToName(event_id, tls_decoder_event_table);
    if (*event_name == NULL) {
        SCLogError(SC_ERR_INVALID_ENUM_MAP, "event \"%d\" not present in "
                   "ssl's enum map table.",  event_id);
        /* yes this is fatal */
        return -1;
    }

    *event_type = APP_LAYER_EVENT_TYPE_TRANSACTION;

    return 0;
}

static int SSLRegisterPatternsForProtocolDetection(void)
{
    if (AppLayerProtoDetectPMRegisterPatternCS(IPPROTO_TCP, ALPROTO_TLS,
                                               "|01 00 02|", 5, 2, STREAM_TOSERVER) < 0)
    {
        return -1;
    }

    /** SSLv3 */
    if (AppLayerProtoDetectPMRegisterPatternCS(IPPROTO_TCP, ALPROTO_TLS,
                                               "|01 03 00|", 3, 0, STREAM_TOSERVER) < 0)
    {
        return -1;
    }
    if (AppLayerProtoDetectPMRegisterPatternCS(IPPROTO_TCP, ALPROTO_TLS,
                                               "|16 03 00|", 3, 0, STREAM_TOSERVER) < 0)
    {
        return -1;
    }

    /** TLSv1 */
    if (AppLayerProtoDetectPMRegisterPatternCS(IPPROTO_TCP, ALPROTO_TLS,
                                               "|01 03 01|", 3, 0, STREAM_TOSERVER) < 0)
    {
        return -1;
    }
    if (AppLayerProtoDetectPMRegisterPatternCS(IPPROTO_TCP, ALPROTO_TLS,
                                               "|16 03 01|", 3, 0, STREAM_TOSERVER) < 0)
    {
        return -1;
    }

    /** TLSv1.1 */
    if (AppLayerProtoDetectPMRegisterPatternCS(IPPROTO_TCP, ALPROTO_TLS,
                                               "|01 03 02|", 3, 0, STREAM_TOSERVER) < 0)
    {
        return -1;
    }
    if (AppLayerProtoDetectPMRegisterPatternCS(IPPROTO_TCP, ALPROTO_TLS,
                                               "|16 03 02|", 3, 0, STREAM_TOSERVER) < 0)
    {
        return -1;
    }

    /** TLSv1.2 */
    if (AppLayerProtoDetectPMRegisterPatternCS(IPPROTO_TCP, ALPROTO_TLS,
                                               "|01 03 03|", 3, 0, STREAM_TOSERVER) < 0)
    {
        return -1;
    }
    if (AppLayerProtoDetectPMRegisterPatternCS(IPPROTO_TCP, ALPROTO_TLS,
                                               "|16 03 03|", 3, 0, STREAM_TOSERVER) < 0)
    {
        return -1;
    }

    /***** toclient direction *****/

    if (AppLayerProtoDetectPMRegisterPatternCS(IPPROTO_TCP, ALPROTO_TLS,
                                               "|15 03 00|", 3, 0, STREAM_TOCLIENT) < 0)
    {
        return -1;
    }
    if (AppLayerProtoDetectPMRegisterPatternCS(IPPROTO_TCP, ALPROTO_TLS,
                                               "|16 03 00|", 3, 0, STREAM_TOCLIENT) < 0)
    {
        return -1;
    }
    if (AppLayerProtoDetectPMRegisterPatternCS(IPPROTO_TCP, ALPROTO_TLS,
                                               "|17 03 00|", 3, 0, STREAM_TOCLIENT) < 0)
    {
        return -1;
    }

    /** TLSv1 */
    if (AppLayerProtoDetectPMRegisterPatternCS(IPPROTO_TCP, ALPROTO_TLS,
                                               "|15 03 01|", 3, 0, STREAM_TOCLIENT) < 0)
    {
        return -1;
    }
    if (AppLayerProtoDetectPMRegisterPatternCS(IPPROTO_TCP, ALPROTO_TLS,
                                               "|16 03 01|", 3, 0, STREAM_TOCLIENT) < 0)
    {
        return -1;
    }
    if (AppLayerProtoDetectPMRegisterPatternCS(IPPROTO_TCP, ALPROTO_TLS,
                                               "|17 03 01|", 3, 0, STREAM_TOCLIENT) < 0)
    {
        return -1;
    }

    /** TLSv1.1 */
    if (AppLayerProtoDetectPMRegisterPatternCS(IPPROTO_TCP, ALPROTO_TLS,
                                               "|15 03 02|", 3, 0, STREAM_TOCLIENT) < 0)
    {
        return -1;
    }
    if (AppLayerProtoDetectPMRegisterPatternCS(IPPROTO_TCP, ALPROTO_TLS,
                                               "|16 03 02|", 3, 0, STREAM_TOCLIENT) < 0)
    {
        return -1;
    }
    if (AppLayerProtoDetectPMRegisterPatternCS(IPPROTO_TCP, ALPROTO_TLS,
                                               "|17 03 02|", 3, 0, STREAM_TOCLIENT) < 0)
    {
        return -1;
    }

    /** TLSv1.2 */
    if (AppLayerProtoDetectPMRegisterPatternCS(IPPROTO_TCP, ALPROTO_TLS,
                                               "|15 03 03|", 3, 0, STREAM_TOCLIENT) < 0)
    {
        return -1;
    }
    if (AppLayerProtoDetectPMRegisterPatternCS(IPPROTO_TCP, ALPROTO_TLS,
                                               "|16 03 03|", 3, 0, STREAM_TOCLIENT) < 0)
    {
        return -1;
    }
    if (AppLayerProtoDetectPMRegisterPatternCS(IPPROTO_TCP, ALPROTO_TLS,
                                               "|17 03 03|", 3, 0, STREAM_TOCLIENT) < 0)
    {
        return -1;
    }

    /* Subsection - SSLv2 style record by client, but informing the server
     * the max version it supports.
     * Updated by Anoop Saldanha.  Disabled it for now.  We'll get back to
     * it after some tests */
#if 0
    if (AppLayerProtoDetectPMRegisterPatternCS(IPPROTO_TCP, ALPROTO_TLS,
                                               "|01 03 00|", 5, 2, STREAM_TOSERVER) < 0)
    {
        return -1;
    }
    if (AppLayerProtoDetectPMRegisterPatternCS(IPPROTO_TCP, ALPROTO_TLS,
                                               "|00 02|", 7, 5, STREAM_TOCLIENT) < 0)
    {
        return -1;
    }
#endif

    return 0;
}

/**
 * \brief Function to register the SSL protocol parser and other functions
 */
void RegisterSSLParsers(void)
{
    const char *proto_name = "tls";

    /** SSLv2  and SSLv23*/
    if (AppLayerProtoDetectConfProtoDetectionEnabled("tcp", proto_name)) {
        AppLayerProtoDetectRegisterProtocol(ALPROTO_TLS, proto_name);

        if (SSLRegisterPatternsForProtocolDetection() < 0)
            return;

        if (RunmodeIsUnittests()) {
            AppLayerProtoDetectPPRegister(IPPROTO_TCP,
                                          "443",
                                          ALPROTO_TLS,
                                          0, 3,
                                          STREAM_TOSERVER,
                                          SSLProbingParser, NULL);
        } else {
            AppLayerProtoDetectPPParseConfPorts("tcp", IPPROTO_TCP,
                                                proto_name, ALPROTO_TLS,
                                                0, 3,
                                                SSLProbingParser, NULL);
        }
    } else {
        SCLogInfo("Protocol detection and parser disabled for %s protocol",
                  proto_name);
        return;
    }

    if (AppLayerParserConfParserEnabled("tcp", proto_name)) {
        AppLayerParserRegisterParser(IPPROTO_TCP, ALPROTO_TLS, STREAM_TOSERVER,
                                     SSLParseClientRecord);

        AppLayerParserRegisterParser(IPPROTO_TCP, ALPROTO_TLS, STREAM_TOCLIENT,
                                     SSLParseServerRecord);

        AppLayerParserRegisterGetEventInfo(IPPROTO_TCP, ALPROTO_TLS, SSLStateGetEventInfo);
        AppLayerParserRegisterGetEventInfoById(IPPROTO_TCP, ALPROTO_TLS, SSLStateGetEventInfoById);

        AppLayerParserRegisterStateFuncs(IPPROTO_TCP, ALPROTO_TLS, SSLStateAlloc, SSLStateFree);

        AppLayerParserRegisterParserAcceptableDataDirection(IPPROTO_TCP, ALPROTO_TLS, STREAM_TOSERVER);

        AppLayerParserRegisterTxFreeFunc(IPPROTO_TCP, ALPROTO_TLS, SSLStateTransactionFree);

        AppLayerParserRegisterGetEventsFunc(IPPROTO_TCP, ALPROTO_TLS, SSLGetEvents);

        AppLayerParserRegisterDetectStateFuncs(IPPROTO_TCP, ALPROTO_TLS,
                                               SSLGetTxDetectState, SSLSetTxDetectState);

        AppLayerParserRegisterGetTx(IPPROTO_TCP, ALPROTO_TLS, SSLGetTx);

        AppLayerParserRegisterGetTxCnt(IPPROTO_TCP, ALPROTO_TLS, SSLGetTxCnt);

        AppLayerParserRegisterGetStateProgressFunc(IPPROTO_TCP, ALPROTO_TLS, SSLGetAlstateProgress);

        AppLayerParserRegisterLoggerFuncs(IPPROTO_TCP, ALPROTO_TLS, SSLGetTxLogged, SSLSetTxLogged);
        AppLayerParserRegisterDetectFlagsFuncs(IPPROTO_TCP, ALPROTO_TLS,
                SSLGetTxDetectFlags, SSLSetTxDetectFlags);

        AppLayerParserRegisterGetStateProgressCompletionStatus(ALPROTO_TLS,
                                                               SSLGetAlstateProgressCompletionStatus);

        ConfNode *enc_handle = ConfGetNode("app-layer.protocols.tls.encryption-handling");
        if (enc_handle != NULL && enc_handle->val != NULL) {
            SCLogDebug("have app-layer.protocols.tls.encryption-handling = %s", enc_handle->val);
            if (strcmp(enc_handle->val, "full") == 0) {
                ssl_config.encrypt_mode = SSL_CNF_ENC_HANDLE_FULL;
            } else if (strcmp(enc_handle->val, "bypass") == 0) {
                ssl_config.encrypt_mode = SSL_CNF_ENC_HANDLE_BYPASS;
            } else if (strcmp(enc_handle->val, "default") == 0) {
                ssl_config.encrypt_mode = SSL_CNF_ENC_HANDLE_DEFAULT;
            } else {
                ssl_config.encrypt_mode = SSL_CNF_ENC_HANDLE_DEFAULT;
            }
        } else {
            /* Get the value of no reassembly option from the config file */
            if (ConfGetNode("app-layer.protocols.tls.no-reassemble") == NULL) {
                int value = 0;
                if (ConfGetBool("tls.no-reassemble", &value) == 1 && value == 1)
                    ssl_config.encrypt_mode = SSL_CNF_ENC_HANDLE_BYPASS;
            } else {
                int value = 0;
                if (ConfGetBool("app-layer.protocols.tls.no-reassemble", &value) == 1 && value == 1)
                    ssl_config.encrypt_mode = SSL_CNF_ENC_HANDLE_BYPASS;
            }
        }
        SCLogDebug("ssl_config.encrypt_mode %u", ssl_config.encrypt_mode);

        /* Check if we should generate JA3 fingerprints */
        if (ConfGetBool("app-layer.protocols.tls.ja3-fingerprints",
                        &ssl_config.enable_ja3) != 1) {
            ssl_config.enable_ja3 = SSL_CONFIG_DEFAULT_JA3;
        }

#ifndef HAVE_NSS
        if (ssl_config.enable_ja3) {
            SCLogWarning(SC_WARN_NO_JA3_SUPPORT,
                         "no MD5 calculation support built in, disabling JA3");
            ssl_config.enable_ja3 = 0;
        }
#else
        if (RunmodeIsUnittests()) {
            ssl_config.enable_ja3 = 1;
        }
#endif

    } else {
        SCLogInfo("Parsed disabled for %s protocol. Protocol detection"
                  "still on.", proto_name);
    }

#ifdef UNITTESTS
    AppLayerParserRegisterProtocolUnittests(IPPROTO_TCP, ALPROTO_TLS, SSLParserRegisterTests);
#endif
    return;
}

/***************************************Unittests******************************/

#ifdef UNITTESTS

/**
 *\test Send a get request in one chunk.
 */
static int SSLParserTest01(void)
{
    Flow f;
    uint8_t tlsbuf[] = { 0x16, 0x03, 0x01 };
    uint32_t tlslen = sizeof(tlsbuf);
    TcpSession ssn;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;
    f.alproto = ALPROTO_TLS;

    StreamTcpInitConfig(TRUE);

    FLOWLOCK_WRLOCK(&f);
    int r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_TLS,
                                STREAM_TOSERVER | STREAM_EOF, tlsbuf, tlslen);
    FLOWLOCK_UNLOCK(&f);
    FAIL_IF(r != 0);

    SSLState *ssl_state = f.alstate;
    FAIL_IF_NULL(ssl_state);

    FAIL_IF(ssl_state->client_connp.content_type != 0x16);

    FAIL_IF(ssl_state->client_connp.version != TLS_VERSION_10);

    AppLayerParserThreadCtxFree(alp_tctx);
    StreamTcpFreeConfig(TRUE);
    FLOW_DESTROY(&f);

    PASS;
}

/** \test Send a get request in two chunks. */
static int SSLParserTest02(void)
{
    Flow f;
    uint8_t tlsbuf1[] = { 0x16 };
    uint32_t tlslen1 = sizeof(tlsbuf1);
    uint8_t tlsbuf2[] = { 0x03, 0x01 };
    uint32_t tlslen2 = sizeof(tlsbuf2);
    TcpSession ssn;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));
    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;
    f.alproto = ALPROTO_TLS;

    StreamTcpInitConfig(TRUE);

    FLOWLOCK_WRLOCK(&f);
    int r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_TLS,
                                STREAM_TOSERVER, tlsbuf1, tlslen1);
    FLOWLOCK_UNLOCK(&f);
    FAIL_IF(r != 0);

    FLOWLOCK_WRLOCK(&f);
    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_TLS, STREAM_TOSERVER,
                            tlsbuf2, tlslen2);
    FLOWLOCK_UNLOCK(&f);
    FAIL_IF(r != 0);

    SSLState *ssl_state = f.alstate;
    FAIL_IF_NULL(ssl_state);

    FAIL_IF(ssl_state->client_connp.content_type != 0x16);

    FAIL_IF(ssl_state->client_connp.version != TLS_VERSION_10);

    AppLayerParserThreadCtxFree(alp_tctx);
    StreamTcpFreeConfig(TRUE);
    FLOW_DESTROY(&f);

    PASS;
}

/** \test Send a get request in three chunks. */
static int SSLParserTest03(void)
{
    Flow f;
    uint8_t tlsbuf1[] = { 0x16 };
    uint32_t tlslen1 = sizeof(tlsbuf1);
    uint8_t tlsbuf2[] = { 0x03 };
    uint32_t tlslen2 = sizeof(tlsbuf2);
    uint8_t tlsbuf3[] = { 0x01 };
    uint32_t tlslen3 = sizeof(tlsbuf3);
    TcpSession ssn;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));
    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;
    f.alproto = ALPROTO_TLS;

    StreamTcpInitConfig(TRUE);

    FLOWLOCK_WRLOCK(&f);
    int r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_TLS,
                                STREAM_TOSERVER, tlsbuf1, tlslen1);
    FLOWLOCK_UNLOCK(&f);
    FAIL_IF(r != 0);

    FLOWLOCK_WRLOCK(&f);
    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_TLS, STREAM_TOSERVER,
                            tlsbuf2, tlslen2);
    FLOWLOCK_UNLOCK(&f);
    FAIL_IF(r != 0);

    FLOWLOCK_WRLOCK(&f);
    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_TLS, STREAM_TOSERVER,
                            tlsbuf3, tlslen3);
    FLOWLOCK_UNLOCK(&f);
    FAIL_IF(r != 0);

    SSLState *ssl_state = f.alstate;
    FAIL_IF_NULL(ssl_state);

    FAIL_IF(ssl_state->client_connp.content_type != 0x16);

    FAIL_IF(ssl_state->client_connp.version != TLS_VERSION_10);

    AppLayerParserThreadCtxFree(alp_tctx);
    StreamTcpFreeConfig(TRUE);
    FLOW_DESTROY(&f);

    PASS;
}

/** \test Send a get request in three chunks + more data. */
static int SSLParserTest04(void)
{
    Flow f;
    uint8_t tlsbuf1[] = { 0x16 };
    uint32_t tlslen1 = sizeof(tlsbuf1);
    uint8_t tlsbuf2[] = { 0x03 };
    uint32_t tlslen2 = sizeof(tlsbuf2);
    uint8_t tlsbuf3[] = { 0x01 };
    uint32_t tlslen3 = sizeof(tlsbuf3);
    uint8_t tlsbuf4[] = { 0x01, 0x00, 0x00, 0xad, 0x03, 0x01 };
    uint32_t tlslen4 = sizeof(tlsbuf4);
    TcpSession ssn;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));
    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;
    f.alproto = ALPROTO_TLS;

    StreamTcpInitConfig(TRUE);

    FLOWLOCK_WRLOCK(&f);
    int r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_TLS,
                                STREAM_TOSERVER, tlsbuf1, tlslen1);
    FLOWLOCK_UNLOCK(&f);
    FAIL_IF(r != 0);

    FLOWLOCK_WRLOCK(&f);
    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_TLS, STREAM_TOSERVER,
                            tlsbuf2, tlslen2);
    FLOWLOCK_UNLOCK(&f);
    FAIL_IF(r != 0);

    FLOWLOCK_WRLOCK(&f);
    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_TLS, STREAM_TOSERVER,
                            tlsbuf3, tlslen3);
    FLOWLOCK_UNLOCK(&f);
    FAIL_IF(r != 0);

    FLOWLOCK_WRLOCK(&f);
    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_TLS, STREAM_TOSERVER,
                            tlsbuf4, tlslen4);
    FLOWLOCK_UNLOCK(&f);
    FAIL_IF(r != 0);

    SSLState *ssl_state = f.alstate;
    FAIL_IF_NULL(ssl_state);

    FAIL_IF(ssl_state->client_connp.content_type != 0x16);

    FAIL_IF(ssl_state->client_connp.version != TLS_VERSION_10);

    AppLayerParserThreadCtxFree(alp_tctx);
    StreamTcpFreeConfig(TRUE);
    FLOW_DESTROY(&f);

    PASS;
}

#if 0
/** \test   Test the setting up of no reassembly and no payload inspection flag
 *          after detection of the TLS handshake completion */
static int SSLParserTest05(void)
{
    int result = 1;
    Flow f;
    uint8_t tlsbuf[] = { 0x16, 0x03, 0x01, 0x00, 0x01 };
    uint32_t tlslen = sizeof(tlsbuf);
    TcpSession ssn;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));
    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;
    f.alproto = ALPROTO_TLS;

    StreamTcpInitConfig(TRUE);

    int r = AppLayerParserParse(alp_tctx, &f, ALPROTO_TLS, STREAM_TOSERVER, tlsbuf, tlslen);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        goto end;
    }

    r = AppLayerParserParse(alp_tctx, &f, ALPROTO_TLS, STREAM_TOCLIENT, tlsbuf, tlslen);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        goto end;
    }

    tlsbuf[0] = 0x14;

    r = AppLayerParserParse(alp_tctx, &f, ALPROTO_TLS, STREAM_TOSERVER, tlsbuf, tlslen);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        goto end;
    }

    tlsbuf[0] = 0x14;

    r = AppLayerParserParse(alp_tctx, &f, ALPROTO_TLS, STREAM_TOCLIENT, tlsbuf, tlslen);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        goto end;
    }

    tlsbuf[0] = 0x17;

    r = AppLayerParserParse(alp_tctx, &f, ALPROTO_TLS, STREAM_TOSERVER, tlsbuf, tlslen);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        goto end;
    }

    SSLState *ssl_state = f.alstate;
    if (ssl_state == NULL) {
        printf("no tls state: ");
        result = 0;
        goto end;
    }

    if (ssl_state->client_connp.content_type != 0x17) {
        printf("expected content_type %" PRIu8 ", got %" PRIu8 ": ", 0x17,
                ssl_state->client_connp.content_type);
        result = 0;
        goto end;
    }

    if (ssl_state->client_connp.version != TLS_VERSION_10) {
        printf("expected version %04" PRIu16 ", got %04" PRIu16 ": ",
                TLS_VERSION_10, ssl_state->client_connp.client_version);
        result = 0;
        goto end;
    }

    AppLayerParserStateStore *parser_state_store = (AppLayerParserStateStore *)
                                                    ssn.alparser;
    AppLayerParserState *parser_state = &parser_state_store->to_server;

    if (!(parser_state->flags & APP_LAYER_PARSER_NO_INSPECTION) &&
        !(ssn.client.flags & STREAMTCP_STREAM_FLAG_NOREASSEMBLY) &&
        !(ssn.server.flags & STREAMTCP_STREAM_FLAG_NOREASSEMBLY))
    {
        printf("The flags should be set\n");
        result = 0;
        goto end;
    }

    if (!(f.flags & FLOW_NOPAYLOAD_INSPECTION)) {
        printf("The flags should be set\n");
        result = 0;
        goto end;
    }

end:
    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
    StreamTcpFreeConfig(TRUE);
    FLOW_DESTROY(&f);
    return result;
}
#endif

#if 0
/** \test   Test the setting up of no reassembly and no payload inspection flag
 *          after detection of the valid TLS handshake completion, the rouge
 *          0x17 packet will not be considered in the detection process */
static int SSLParserTest06(void)
{
    int result = 1;
    Flow f;
    uint8_t tlsbuf[] = { 0x16, 0x03, 0x01, 0x00, 0x01 };
    uint32_t tlslen = sizeof(tlsbuf);
    TcpSession ssn;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));
    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;
    f.alproto = ALPROTO_TLS;

    StreamTcpInitConfig(TRUE);

    int r = AppLayerParserParse(alp_tctx, &f, ALPROTO_TLS, STREAM_TOSERVER, tlsbuf, tlslen);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        goto end;
    }

    r = AppLayerParserParse(alp_tctx, &f, ALPROTO_TLS, STREAM_TOCLIENT, tlsbuf, tlslen);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        goto end;
    }

    tlsbuf[0] = 0x14;

    r = AppLayerParserParse(alp_tctx, &f, ALPROTO_TLS, STREAM_TOSERVER, tlsbuf, tlslen);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        goto end;
    }

    tlsbuf[0] = 0x17;

    r = AppLayerParserParse(alp_tctx, &f, ALPROTO_TLS, STREAM_TOSERVER, tlsbuf, tlslen);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        goto end;
    }

    SSLState *ssl_state = f.alstate;
    if (ssl_state == NULL) {
        printf("no tls state: ");
        result = 0;
        goto end;
    }

    if (ssl_state->client_connp.content_type != 0x17) {
        printf("expected content_type %" PRIu8 ", got %" PRIu8 ": ", 0x17,
                ssl_state->client_connp._content_type);
        result = 0;
        goto end;
    }

    if (ssl_state->client_connp.version != TLS_VERSION_10) {
        printf("expected version %04" PRIu16 ", got %04" PRIu16 ": ",
                TLS_VERSION_10, ssl_state->client_connp.version);
        result = 0;
        goto end;
    }

    AppLayerParserStateStore *parser_state_store = (AppLayerParserStateStore *)
                                                    ssn.alparser;
    AppLayerParserState *parser_state = &parser_state_store->to_server;

    if ((parser_state->flags & APP_LAYER_PARSER_NO_INSPECTION) ||
            (ssn.client.flags & STREAMTCP_STREAM_FLAG_NOREASSEMBLY) ||
            (ssn.server.flags & STREAMTCP_STREAM_FLAG_NOREASSEMBLY)) {
        printf("The flags should not be set\n");
        result = 0;
        goto end;
    }

    tlsbuf[0] = 0x14;

    r = AppLayerParserParse(alp_tctx, &f, ALPROTO_TLS, STREAM_TOCLIENT, tlsbuf, tlslen);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        goto end;
    }

    tlsbuf[0] = 0x17;

    r = AppLayerParserParse(alp_tctx, &f, ALPROTO_TLS, STREAM_TOSERVER, tlsbuf, tlslen);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        goto end;
    }

    if (!(parser_state->flags & APP_LAYER_PARSER_NO_INSPECTION) &&
            !(ssn.client.flags & STREAMTCP_STREAM_FLAG_NOREASSEMBLY) &&
            !(ssn.server.flags & STREAMTCP_STREAM_FLAG_NOREASSEMBLY)) {
        printf("The flags should be set\n");
        result = 0;
        goto end;
    }

    if (!(f.flags & FLOW_NOPAYLOAD_INSPECTION)) {
        printf("The flags should be set\n");
        result = 0;
        goto end;
    }

end:
    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
    StreamTcpFreeConfig(TRUE);
    FLOW_DESTROY(&f);
    return result;
}
#endif

/** \test multimsg test */
static int SSLParserMultimsgTest01(void)
{
    Flow f;
    /* 3 msgs */
    uint8_t tlsbuf1[] = {
        0x16, 0x03, 0x01, 0x00, 0x86, 0x10, 0x00, 0x00,
        0x82, 0x00, 0x80, 0xd3, 0x6f, 0x1f, 0x63, 0x82,
        0x8d, 0x75, 0x77, 0x8c, 0x91, 0xbc, 0xa1, 0x3d,
        0xbb, 0xe1, 0xb5, 0xd3, 0x31, 0x92, 0x59, 0x2b,
        0x2c, 0x43, 0x96, 0xa3, 0xaa, 0x23, 0x92, 0xd0,
        0x91, 0x2a, 0x5e, 0x10, 0x5b, 0xc8, 0xc1, 0xe2,
        0xd3, 0x5c, 0x8b, 0x8c, 0x91, 0x9e, 0xc2, 0xf2,
        0x9c, 0x3c, 0x4f, 0x37, 0x1e, 0x20, 0x5e, 0x33,
        0xd5, 0xf0, 0xd6, 0xaf, 0x89, 0xf5, 0xcc, 0xb2,
        0xcf, 0xc1, 0x60, 0x3a, 0x46, 0xd5, 0x4e, 0x2a,
        0xb6, 0x6a, 0xb9, 0xfc, 0x32, 0x8b, 0xe0, 0x6e,
        0xa0, 0xed, 0x25, 0xa0, 0xa4, 0x82, 0x81, 0x73,
        0x90, 0xbf, 0xb5, 0xde, 0xeb, 0x51, 0x8d, 0xde,
        0x5b, 0x6f, 0x94, 0xee, 0xba, 0xe5, 0x69, 0xfa,
        0x1a, 0x80, 0x30, 0x54, 0xeb, 0x12, 0x01, 0xb9,
        0xfe, 0xbf, 0x82, 0x95, 0x01, 0x7b, 0xb0, 0x97,
        0x14, 0xc2, 0x06, 0x3c, 0x69, 0xfb, 0x1c, 0x66,
        0x47, 0x17, 0xd9, 0x14, 0x03, 0x01, 0x00, 0x01,
        0x01, 0x16, 0x03, 0x01, 0x00, 0x30, 0xf6, 0xbc,
        0x0d, 0x6f, 0xe8, 0xbb, 0xaa, 0xbf, 0x14, 0xeb,
        0x7b, 0xcc, 0x6c, 0x28, 0xb0, 0xfc, 0xa6, 0x01,
        0x2a, 0x97, 0x96, 0x17, 0x5e, 0xe8, 0xb4, 0x4e,
        0x78, 0xc9, 0x04, 0x65, 0x53, 0xb6, 0x93, 0x3d,
        0xeb, 0x44, 0xee, 0x86, 0xf9, 0x80, 0x49, 0x45,
        0x21, 0x34, 0xd1, 0xee, 0xc8, 0x9c
    };
    uint32_t tlslen1 = sizeof(tlsbuf1);
    TcpSession ssn;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));
    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;
    f.alproto = ALPROTO_TLS;

    StreamTcpInitConfig(TRUE);

    FLOWLOCK_WRLOCK(&f);
    int r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_TLS,
                                STREAM_TOSERVER, tlsbuf1, tlslen1);
    FLOWLOCK_UNLOCK(&f);
    FAIL_IF(r != 0);

    SSLState *ssl_state = f.alstate;
    FAIL_IF_NULL(ssl_state);

    FAIL_IF(ssl_state->client_connp.content_type != 0x16);

    FAIL_IF(ssl_state->client_connp.version != TLS_VERSION_10);

    AppLayerParserThreadCtxFree(alp_tctx);
    StreamTcpFreeConfig(TRUE);
    FLOW_DESTROY(&f);

    PASS;
}

/** \test multimsg test server */
static int SSLParserMultimsgTest02(void)
{
    Flow f;
    /* 3 msgs */
    uint8_t tlsbuf1[] = {
        0x16, 0x03, 0x01, 0x00, 0x86, 0x10, 0x00, 0x00,
        0x82, 0x00, 0x80, 0xd3, 0x6f, 0x1f, 0x63, 0x82,
        0x8d, 0x75, 0x77, 0x8c, 0x91, 0xbc, 0xa1, 0x3d,
        0xbb, 0xe1, 0xb5, 0xd3, 0x31, 0x92, 0x59, 0x2b,
        0x2c, 0x43, 0x96, 0xa3, 0xaa, 0x23, 0x92, 0xd0,
        0x91, 0x2a, 0x5e, 0x10, 0x5b, 0xc8, 0xc1, 0xe2,
        0xd3, 0x5c, 0x8b, 0x8c, 0x91, 0x9e, 0xc2, 0xf2,
        0x9c, 0x3c, 0x4f, 0x37, 0x1e, 0x20, 0x5e, 0x33,
        0xd5, 0xf0, 0xd6, 0xaf, 0x89, 0xf5, 0xcc, 0xb2,
        0xcf, 0xc1, 0x60, 0x3a, 0x46, 0xd5, 0x4e, 0x2a,
        0xb6, 0x6a, 0xb9, 0xfc, 0x32, 0x8b, 0xe0, 0x6e,
        0xa0, 0xed, 0x25, 0xa0, 0xa4, 0x82, 0x81, 0x73,
        0x90, 0xbf, 0xb5, 0xde, 0xeb, 0x51, 0x8d, 0xde,
        0x5b, 0x6f, 0x94, 0xee, 0xba, 0xe5, 0x69, 0xfa,
        0x1a, 0x80, 0x30, 0x54, 0xeb, 0x12, 0x01, 0xb9,
        0xfe, 0xbf, 0x82, 0x95, 0x01, 0x7b, 0xb0, 0x97,
        0x14, 0xc2, 0x06, 0x3c, 0x69, 0xfb, 0x1c, 0x66,
        0x47, 0x17, 0xd9, 0x14, 0x03, 0x01, 0x00, 0x01,
        0x01, 0x16, 0x03, 0x01, 0x00, 0x30, 0xf6, 0xbc,
        0x0d, 0x6f, 0xe8, 0xbb, 0xaa, 0xbf, 0x14, 0xeb,
        0x7b, 0xcc, 0x6c, 0x28, 0xb0, 0xfc, 0xa6, 0x01,
        0x2a, 0x97, 0x96, 0x17, 0x5e, 0xe8, 0xb4, 0x4e,
        0x78, 0xc9, 0x04, 0x65, 0x53, 0xb6, 0x93, 0x3d,
        0xeb, 0x44, 0xee, 0x86, 0xf9, 0x80, 0x49, 0x45,
        0x21, 0x34, 0xd1, 0xee, 0xc8, 0x9c
    };
    uint32_t tlslen1 = sizeof(tlsbuf1);
    TcpSession ssn;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));
    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;
    f.alproto = ALPROTO_TLS;

    StreamTcpInitConfig(TRUE);

    FLOWLOCK_WRLOCK(&f);
    int r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_TLS,
                                STREAM_TOCLIENT, tlsbuf1, tlslen1);
    FLOWLOCK_UNLOCK(&f);
    FAIL_IF(r != 0);

    SSLState *ssl_state = f.alstate;
    FAIL_IF_NULL(ssl_state);

    FAIL_IF(ssl_state->server_connp.content_type != 0x16);

    FAIL_IF(ssl_state->server_connp.version != 0x0301);

    AppLayerParserThreadCtxFree(alp_tctx);
    StreamTcpFreeConfig(TRUE);
    FLOW_DESTROY(&f);

    PASS;
}

/**
 *  \test   Test the detection of SSLv3 protocol from the given packet
 */
static int SSLParserTest07(void)
{
    Flow f;
    uint8_t tlsbuf[] = { 0x16, 0x03, 0x00, 0x00, 0x4c, 0x01,
            0x00, 0x00, 0x48, 0x03, 0x00, 0x57, 0x04, 0x9f,
            0x8c, 0x66, 0x61, 0xf6, 0x3d, 0x4f, 0xbf, 0xbb,
            0xa7, 0x47, 0x21, 0x76, 0x6c, 0x21, 0x08, 0x9f,
            0xef, 0x3d, 0x0e, 0x5f, 0x65, 0x1a, 0xe1, 0x93,
            0xb8, 0xaf, 0xd2, 0x82, 0xbd, 0x00, 0x00, 0x06,
            0x00, 0x0a, 0x00, 0x16, 0x00, 0xff, 0x01, 0x00,
            0x00, 0x19, 0x00, 0x00, 0x00, 0x15, 0x00, 0x13,
            0x00, 0x00, 0x10, 0x61, 0x62, 0x63, 0x64, 0x65,
            0x66, 0x67, 0x68, 0x2e, 0x65, 0x66, 0x67, 0x68,
            0x2e, 0x6e, 0x6f };
    uint32_t tlslen = sizeof(tlsbuf);
    TcpSession ssn;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));
    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;
    f.alproto = ALPROTO_TLS;

    StreamTcpInitConfig(TRUE);

    FLOWLOCK_WRLOCK(&f);
    int r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_TLS,
                                STREAM_TOSERVER, tlsbuf, tlslen);
    FLOWLOCK_UNLOCK(&f);
    FAIL_IF(r != 0);

    SSLState *ssl_state = f.alstate;
    FAIL_IF_NULL(ssl_state);

    FAIL_IF(ssl_state->client_connp.content_type != 0x16);

    FAIL_IF(ssl_state->client_connp.version != SSL_VERSION_3);

    AppLayerParserThreadCtxFree(alp_tctx);
    StreamTcpFreeConfig(TRUE);
    FLOW_DESTROY(&f);

    PASS;
}

#if 0
/** \test   Test the setting up of no reassembly and no payload inspection flag
 *          after detection of the SSLv3 handshake completion */
static int SSLParserTest08(void)
{
    int result = 1;
    Flow f;
    uint8_t tlsbuf[] = { 0x16, 0x03, 0x00, 0x00, 0x01 };
    uint32_t tlslen = sizeof(tlsbuf);
    TcpSession ssn;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));
    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;
    f.alproto = ALPROTO_TLS;

    StreamTcpInitConfig(TRUE);

    int r = AppLayerParserParse(alp_tctx, &f, ALPROTO_TLS, STREAM_TOSERVER, tlsbuf, tlslen);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        goto end;
    }

    r = AppLayerParserParse(alp_tctx, &f, ALPROTO_TLS, STREAM_TOCLIENT, tlsbuf, tlslen);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        goto end;
    }

    tlsbuf[0] = 0x14;

    r = AppLayerParserParse(alp_tctx, &f, ALPROTO_TLS, STREAM_TOSERVER, tlsbuf, tlslen);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        goto end;
    }

    tlsbuf[0] = 0x14;

    r = AppLayerParserParse(alp_tctx, &f, ALPROTO_TLS, STREAM_TOCLIENT, tlsbuf, tlslen);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        goto end;
    }

    tlsbuf[0] = 0x17;

    r = AppLayerParserParse(alp_tctx, &f, ALPROTO_TLS, STREAM_TOSERVER, tlsbuf, tlslen);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        goto end;
    }

    SSLState *ssl_state = f.alstate;
    if (ssl_state == NULL) {
        printf("no tls state: ");
        result = 0;
        goto end;
    }

    if (ssl_state->client_connp.content_type != 0x17) {
        printf("expected content_type %" PRIu8 ", got %" PRIu8 ": ", 0x17,
                ssl_state->client_connp.content_type);
        result = 0;
        goto end;
    }

    if (ssl_state->client_connp.version != SSL_VERSION_3) {
        printf("expected version %04" PRIu16 ", got %04" PRIu16 ": ",
                SSL_VERSION_3, ssl_state->client_connp.version);
        result = 0;
        goto end;
    }

    AppLayerParserStateStore *parser_state_store = (AppLayerParserStateStore *)
                                                    ssn.alparser;
    AppLayerParserState *parser_state = &parser_state_store->to_server;

    if (!(parser_state->flags & APP_LAYER_PARSER_NO_INSPECTION) &&
            !(ssn.client.flags & STREAMTCP_STREAM_FLAG_NOREASSEMBLY) &&
            !(ssn.server.flags & STREAMTCP_STREAM_FLAG_NOREASSEMBLY)) {
        printf("The flags should be set\n");
        result = 0;
        goto end;
    }

    if (!(f.flags & FLOW_NOPAYLOAD_INSPECTION)) {
        printf("The flags should be set\n");
        result = 0;
        goto end;
    }

end:
    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
    StreamTcpFreeConfig(TRUE);
    FLOW_DESTROY(&f);
    return result;
}

#endif

/**
 * \test Tests the parser for handling fragmented records.
 */
static int SSLParserTest09(void)
{
    Flow f;
    uint8_t buf1[] = {
            0x16,
    };
    uint32_t buf1_len = sizeof(buf1);

    uint8_t buf2[] = {
            0x03, 0x00, 0x00, 0x4c, 0x01,
            0x00, 0x00, 0x48, 0x03, 0x00, 0x57, 0x04, 0x9f,
            0x8c, 0x66, 0x61, 0xf6, 0x3d, 0x4f, 0xbf, 0xbb,
            0xa7, 0x47, 0x21, 0x76, 0x6c, 0x21, 0x08, 0x9f,
            0xef, 0x3d, 0x0e, 0x5f, 0x65, 0x1a, 0xe1, 0x93,
            0xb8, 0xaf, 0xd2, 0x82, 0xbd, 0x00, 0x00, 0x06,
            0x00, 0x0a, 0x00, 0x16, 0x00, 0xff, 0x01, 0x00,
            0x00, 0x19, 0x00, 0x00, 0x00, 0x15, 0x00, 0x13,
            0x00, 0x00, 0x10, 0x61, 0x62, 0x63, 0x64, 0x65,
            0x66, 0x67, 0x68, 0x2e, 0x65, 0x66, 0x67, 0x68,
            0x2e, 0x6e, 0x6f
    };
    uint32_t buf2_len = sizeof(buf2);
    TcpSession ssn;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));
    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;
    f.alproto = ALPROTO_TLS;

    StreamTcpInitConfig(TRUE);

    FLOWLOCK_WRLOCK(&f);
    int r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_TLS,
                                STREAM_TOSERVER, buf1, buf1_len);
    FLOWLOCK_UNLOCK(&f);
    FAIL_IF(r != 0);

    FLOWLOCK_WRLOCK(&f);
    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_TLS, STREAM_TOSERVER,
                            buf2, buf2_len);
    FLOWLOCK_UNLOCK(&f);
    FAIL_IF(r != 0);

    SSLState *ssl_state = f.alstate;
    FAIL_IF_NULL(ssl_state);

    FAIL_IF(ssl_state->client_connp.content_type != 0x16);

    FAIL_IF(ssl_state->client_connp.version != SSL_VERSION_3);

    AppLayerParserThreadCtxFree(alp_tctx);
    StreamTcpFreeConfig(TRUE);
    FLOW_DESTROY(&f);

    PASS;
}

/**
 * \test Tests the parser for handling fragmented records.
 */
static int SSLParserTest10(void)
{
    Flow f;
    uint8_t buf1[] = {
        0x16, 0x03,
    };
    uint32_t buf1_len = sizeof(buf1);

    uint8_t buf2[] = {
            0x00, 0x00, 0x4c, 0x01,
            0x00, 0x00, 0x48, 0x03, 0x00, 0x57, 0x04, 0x9f,
            0x8c, 0x66, 0x61, 0xf6, 0x3d, 0x4f, 0xbf, 0xbb,
            0xa7, 0x47, 0x21, 0x76, 0x6c, 0x21, 0x08, 0x9f,
            0xef, 0x3d, 0x0e, 0x5f, 0x65, 0x1a, 0xe1, 0x93,
            0xb8, 0xaf, 0xd2, 0x82, 0xbd, 0x00, 0x00, 0x06,
            0x00, 0x0a, 0x00, 0x16, 0x00, 0xff, 0x01, 0x00,
            0x00, 0x19, 0x00, 0x00, 0x00, 0x15, 0x00, 0x13,
            0x00, 0x00, 0x10, 0x61, 0x62, 0x63, 0x64, 0x65,
            0x66, 0x67, 0x68, 0x2e, 0x65, 0x66, 0x67, 0x68,
            0x2e, 0x6e, 0x6f
    };
    uint32_t buf2_len = sizeof(buf2);
    TcpSession ssn;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));
    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;
    f.alproto = ALPROTO_TLS;

    StreamTcpInitConfig(TRUE);

    FLOWLOCK_WRLOCK(&f);
    int r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_TLS,
                                STREAM_TOSERVER, buf1, buf1_len);
    FLOWLOCK_UNLOCK(&f);
    FAIL_IF(r != 0);

    FLOWLOCK_WRLOCK(&f);
    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_TLS, STREAM_TOSERVER,
                            buf2, buf2_len);
    FLOWLOCK_UNLOCK(&f);
    FAIL_IF(r != 0);

    SSLState *ssl_state = f.alstate;
    FAIL_IF_NULL(ssl_state);

    FAIL_IF(ssl_state->client_connp.content_type != 0x16);

    FAIL_IF(ssl_state->client_connp.version != SSL_VERSION_3);

    AppLayerParserThreadCtxFree(alp_tctx);
    StreamTcpFreeConfig(TRUE);
    FLOW_DESTROY(&f);

    PASS;
}

/**
 * \test Tests the parser for handling fragmented records.
 */
static int SSLParserTest11(void)
{
    Flow f;
    uint8_t buf1[] = {
            0x16, 0x03, 0x00, 0x00, 0x4c, 0x01,
    };
    uint32_t buf1_len = sizeof(buf1);

    uint8_t buf2[] = {
            0x00, 0x00, 0x48, 0x03, 0x00, 0x57, 0x04, 0x9f,
            0x8c, 0x66, 0x61, 0xf6, 0x3d, 0x4f, 0xbf, 0xbb,
            0xa7, 0x47, 0x21, 0x76, 0x6c, 0x21, 0x08, 0x9f,
            0xef, 0x3d, 0x0e, 0x5f, 0x65, 0x1a, 0xe1, 0x93,
            0xb8, 0xaf, 0xd2, 0x82, 0xbd, 0x00, 0x00, 0x06,
            0x00, 0x0a, 0x00, 0x16, 0x00, 0xff, 0x01, 0x00,
            0x00, 0x19, 0x00, 0x00, 0x00, 0x15, 0x00, 0x13,
            0x00, 0x00, 0x10, 0x61, 0x62, 0x63, 0x64, 0x65,
            0x66, 0x67, 0x68, 0x2e, 0x65, 0x66, 0x67, 0x68,
            0x2e, 0x6e, 0x6f
    };
    uint32_t buf2_len = sizeof(buf2);
    TcpSession ssn;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));
    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;
    f.alproto = ALPROTO_TLS;

    StreamTcpInitConfig(TRUE);

    FLOWLOCK_WRLOCK(&f);
    int r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_TLS,
                                STREAM_TOSERVER, buf1, buf1_len);
    FLOWLOCK_UNLOCK(&f);
    FAIL_IF(r != 0);

    FLOWLOCK_WRLOCK(&f);
    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_TLS, STREAM_TOSERVER,
                            buf2, buf2_len);
    FLOWLOCK_UNLOCK(&f);
    FAIL_IF(r != 0);

    SSLState *ssl_state = f.alstate;
    FAIL_IF_NULL(ssl_state);

    FAIL_IF(ssl_state->client_connp.content_type != 0x16);

    FAIL_IF(ssl_state->client_connp.version != SSL_VERSION_3);

    AppLayerParserThreadCtxFree(alp_tctx);
    StreamTcpFreeConfig(TRUE);
    FLOW_DESTROY(&f);

    PASS;
}

/**
 * \test Tests the parser for handling fragmented records.
 */
static int SSLParserTest12(void)
{
    Flow f;
    uint8_t buf1[] = {
            0x16, 0x03, 0x00, 0x00, 0x4c, 0x01,
    };
    uint32_t buf1_len = sizeof(buf1);

    uint8_t buf2[] = {
            0x00, 0x00, 0x48,
    };
    uint32_t buf2_len = sizeof(buf2);

    uint8_t buf3[] = {
            0x03, 0x00, 0x57, 0x04, 0x9f,
            0x8c, 0x66, 0x61, 0xf6, 0x3d, 0x4f, 0xbf, 0xbb,
            0xa7, 0x47, 0x21, 0x76, 0x6c, 0x21, 0x08, 0x9f,
            0xef, 0x3d, 0x0e, 0x5f, 0x65, 0x1a, 0xe1, 0x93,
            0xb8, 0xaf, 0xd2, 0x82, 0xbd, 0x00, 0x00, 0x06,
            0x00, 0x0a, 0x00, 0x16, 0x00, 0xff, 0x01, 0x00,
            0x00, 0x19, 0x00, 0x00, 0x00, 0x15, 0x00, 0x13,
            0x00, 0x00, 0x10, 0x61, 0x62, 0x63, 0x64, 0x65,
            0x66, 0x67, 0x68, 0x2e, 0x65, 0x66, 0x67, 0x68,
            0x2e, 0x6e, 0x6f
    };
    uint32_t buf3_len = sizeof(buf2);
    TcpSession ssn;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));
    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;
    f.alproto = ALPROTO_TLS;

    StreamTcpInitConfig(TRUE);

    FLOWLOCK_WRLOCK(&f);
    int r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_TLS,
                                STREAM_TOSERVER, buf1, buf1_len);
    FLOWLOCK_UNLOCK(&f);
    FAIL_IF(r != 0);

    FLOWLOCK_WRLOCK(&f);
    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_TLS, STREAM_TOSERVER,
                            buf2, buf2_len);
    FLOWLOCK_UNLOCK(&f);
    FAIL_IF(r != 0);

    FLOWLOCK_WRLOCK(&f);
    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_TLS, STREAM_TOSERVER,
                            buf3, buf3_len);
    FLOWLOCK_UNLOCK(&f);
    FAIL_IF(r != 0);

    SSLState *ssl_state = f.alstate;
    FAIL_IF_NULL(ssl_state);

    FAIL_IF(ssl_state->client_connp.content_type != 0x16);

    FAIL_IF(ssl_state->client_connp.version != SSL_VERSION_3);

    AppLayerParserThreadCtxFree(alp_tctx);
    StreamTcpFreeConfig(TRUE);
    FLOW_DESTROY(&f);

    PASS;
}

/**
 * \test Tests the parser for handling fragmented records.
 */
static int SSLParserTest13(void)
{
    Flow f;
    uint8_t buf1[] = {
            0x16, 0x03, 0x00, 0x00, 0x4c, 0x01,
    };
    uint32_t buf1_len = sizeof(buf1);

    uint8_t buf2[] = {
            0x00, 0x00, 0x48,
    };
    uint32_t buf2_len = sizeof(buf2);

    uint8_t buf3[] = {
            0x03, 0x00, 0x57, 0x04, 0x9f,
            0x8c, 0x66, 0x61, 0xf6, 0x3d, 0x4f,
    };
    uint32_t buf3_len = sizeof(buf3);

    uint8_t buf4[] = {
            0xbf, 0xbb,
            0xa7, 0x47, 0x21, 0x76, 0x6c, 0x21, 0x08, 0x9f,
            0xef, 0x3d, 0x0e, 0x5f, 0x65, 0x1a, 0xe1, 0x93,
            0xb8, 0xaf, 0xd2, 0x82, 0xbd, 0x00, 0x00, 0x06,
            0x00, 0x0a, 0x00, 0x16, 0x00, 0xff, 0x01, 0x00,
            0x00, 0x19, 0x00, 0x00, 0x00, 0x15, 0x00, 0x13,
            0x00, 0x00, 0x10, 0x61, 0x62, 0x63, 0x64, 0x65,
            0x66, 0x67, 0x68, 0x2e, 0x65, 0x66, 0x67, 0x68,
            0x2e, 0x6e, 0x6f
    };
    uint32_t buf4_len = sizeof(buf4);
    TcpSession ssn;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));
    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;
    f.alproto = ALPROTO_TLS;

    StreamTcpInitConfig(TRUE);

    FLOWLOCK_WRLOCK(&f);
    int r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_TLS,
                                STREAM_TOSERVER, buf1, buf1_len);
    FLOWLOCK_UNLOCK(&f);
    FAIL_IF(r != 0);

    FLOWLOCK_WRLOCK(&f);
    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_TLS, STREAM_TOSERVER,
                            buf2, buf2_len);
    FLOWLOCK_UNLOCK(&f);
    FAIL_IF(r != 0);

    FLOWLOCK_WRLOCK(&f);
    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_TLS, STREAM_TOSERVER,
                            buf3, buf3_len);
    FLOWLOCK_UNLOCK(&f);
    FAIL_IF(r != 0);

    FLOWLOCK_WRLOCK(&f);
    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_TLS, STREAM_TOSERVER,
                            buf4, buf4_len);
    FLOWLOCK_UNLOCK(&f);
    FAIL_IF(r != 0);

    SSLState *ssl_state = f.alstate;
    FAIL_IF_NULL(ssl_state);

    FAIL_IF(ssl_state->client_connp.content_type != 0x16);

    FAIL_IF(ssl_state->client_connp.version != SSL_VERSION_3);

    AppLayerParserThreadCtxFree(alp_tctx);
    StreamTcpFreeConfig(TRUE);
    FLOW_DESTROY(&f);

    PASS;
}

/**
 * \test Tests the parser for handling fragmented records.
 */
static int SSLParserTest14(void)
{
    Flow f;

    uint8_t buf1[] = {
        0x16, 0x03, 0x00, 0x00, 0x00,
    };
    uint32_t buf1_len = sizeof(buf1);

    uint8_t buf2[] = {
        0x16, 0x03, 0x00, 0x00, 0x00,
    };
    uint32_t buf2_len = sizeof(buf2);

    TcpSession ssn;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));
    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;
    f.alproto = ALPROTO_TLS;

    StreamTcpInitConfig(TRUE);

    FLOWLOCK_WRLOCK(&f);
    int r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_TLS,
                                STREAM_TOSERVER, buf1, buf1_len);
    FLOWLOCK_UNLOCK(&f);
    FAIL_IF(r != 0);

    FLOWLOCK_WRLOCK(&f);
    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_TLS, STREAM_TOSERVER,
                            buf2, buf2_len);
    FLOWLOCK_UNLOCK(&f);
    FAIL_IF(r != 0);

    SSLState *ssl_state = f.alstate;
    FAIL_IF_NULL(ssl_state);

    AppLayerParserThreadCtxFree(alp_tctx);
    StreamTcpFreeConfig(TRUE);
    FLOW_DESTROY(&f);

    PASS;
}

/**
 * \test Tests the parser for handling fragmented records.
 */
static int SSLParserTest15(void)
{
    Flow f;

    uint8_t buf1[] = {
        0x16, 0x03, 0x00, 0x00, 0x01, 0x01,
    };
    uint32_t buf1_len = sizeof(buf1);

    TcpSession ssn;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));
    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;
    f.alproto = ALPROTO_TLS;

    StreamTcpInitConfig(TRUE);

    FLOWLOCK_WRLOCK(&f);
    int r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_TLS,
                                STREAM_TOSERVER, buf1, buf1_len);
    FLOWLOCK_UNLOCK(&f);
    FAIL_IF(r == 0);

    AppLayerParserThreadCtxFree(alp_tctx);
    StreamTcpFreeConfig(TRUE);
    FLOW_DESTROY(&f);

    PASS;
}

/**
 * \test Tests the parser for handling fragmented records.
 */
static int SSLParserTest16(void)
{
    Flow f;

    uint8_t buf1[] = {
        0x16, 0x03, 0x00, 0x00, 0x02, 0x01, 0x00
    };
    uint32_t buf1_len = sizeof(buf1);

    TcpSession ssn;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));
    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;
    f.alproto = ALPROTO_TLS;

    StreamTcpInitConfig(TRUE);

    FLOWLOCK_WRLOCK(&f);
    int r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_TLS,
                                STREAM_TOSERVER, buf1, buf1_len);
    FLOWLOCK_UNLOCK(&f);
    FAIL_IF(r == 0);

    AppLayerParserThreadCtxFree(alp_tctx);
    StreamTcpFreeConfig(TRUE);
    FLOW_DESTROY(&f);

    PASS;
}

/**
 * \test Tests the parser for handling fragmented records.
 */
static int SSLParserTest17(void)
{
    Flow f;

    uint8_t buf1[] = {
        0x16, 0x03, 0x00, 0x00, 0x03, 0x01, 0x00, 0x00
    };
    uint32_t buf1_len = sizeof(buf1);

    TcpSession ssn;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));
    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;
    f.alproto = ALPROTO_TLS;

    StreamTcpInitConfig(TRUE);

    FLOWLOCK_WRLOCK(&f);
    int r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_TLS,
                                STREAM_TOSERVER, buf1, buf1_len);
    FLOWLOCK_UNLOCK(&f);
    FAIL_IF(r == 0);

    AppLayerParserThreadCtxFree(alp_tctx);
    StreamTcpFreeConfig(TRUE);
    FLOW_DESTROY(&f);

    PASS;
}

/**
 * \test Tests the parser for handling fragmented records.
 */
static int SSLParserTest18(void)
{
    Flow f;

    uint8_t buf1[] = {
        0x16, 0x03, 0x00, 0x00, 0x04, 0x01, 0x00, 0x00,
        0x6b,
    };
    uint32_t buf1_len = sizeof(buf1);

    uint8_t buf2[] = {
        0x16, 0x03, 0x00, 0x00, 0x00,
    };
    uint32_t buf2_len = sizeof(buf2);

    TcpSession ssn;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));
    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;
    f.alproto = ALPROTO_TLS;

    StreamTcpInitConfig(TRUE);

    FLOWLOCK_WRLOCK(&f);
    int r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_TLS,
                                STREAM_TOSERVER, buf1, buf1_len);
    FLOWLOCK_UNLOCK(&f);
    FAIL_IF(r != 0);

    FLOWLOCK_WRLOCK(&f);
    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_TLS, STREAM_TOSERVER,
                            buf2, buf2_len);
    FLOWLOCK_UNLOCK(&f);
    FAIL_IF(r != 0);

    SSLState *ssl_state = f.alstate;
    FAIL_IF_NULL(ssl_state);

    AppLayerParserThreadCtxFree(alp_tctx);
    StreamTcpFreeConfig(TRUE);
    FLOW_DESTROY(&f);

    PASS;
}

/**
 * \test Tests the parser for handling fragmented records.
 */
static int SSLParserTest19(void)
{
    Flow f;

    uint8_t buf1[] = {
        0x16, 0x03, 0x00, 0x00, 0x04, 0x01, 0x00, 0x00,
        0x6b, 0x16, 0x03, 0x00, 0x00, 0x00,
    };
    uint32_t buf1_len = sizeof(buf1);

    TcpSession ssn;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));
    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;
    f.alproto = ALPROTO_TLS;

    StreamTcpInitConfig(TRUE);

    FLOWLOCK_WRLOCK(&f);
    int r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_TLS,
                                STREAM_TOSERVER, buf1, buf1_len);
    FLOWLOCK_UNLOCK(&f);
    FAIL_IF(r != 0);

    SSLState *ssl_state = f.alstate;
    FAIL_IF_NULL(ssl_state);

    AppLayerParserThreadCtxFree(alp_tctx);
    StreamTcpFreeConfig(TRUE);
    FLOW_DESTROY(&f);

    PASS;
}

/**
 * \test Tests the parser for handling fragmented records.
 */
static int SSLParserTest20(void)
{
    Flow f;

    uint8_t buf1[] = {
        0x16, 0x03, 0x00, 0x00, 0x03, 0x01, 0x00, 0x00,
        0x16, 0x03, 0x00, 0x00, 0x00,
    };
    uint32_t buf1_len = sizeof(buf1);

    TcpSession ssn;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));
    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;
    f.alproto = ALPROTO_TLS;

    StreamTcpInitConfig(TRUE);

    FLOWLOCK_WRLOCK(&f);
    int r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_TLS,
                                STREAM_TOSERVER, buf1, buf1_len);
    FLOWLOCK_UNLOCK(&f);
    FAIL_IF(r == 0);

    AppLayerParserThreadCtxFree(alp_tctx);
    StreamTcpFreeConfig(TRUE);
    FLOW_DESTROY(&f);

    PASS;
}

/**
 * \test SSLv2 Record parsing.
 */
static int SSLParserTest21(void)
{
    Flow f;
    uint8_t buf[] = {
        0x80, 0x31, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00,
        0x01,
    };
    uint32_t buf_len = sizeof(buf);

    TcpSession ssn;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;
    f.alproto = ALPROTO_TLS;

    StreamTcpInitConfig(TRUE);

    FLOWLOCK_WRLOCK(&f);
    int r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_TLS,
                                STREAM_TOSERVER | STREAM_EOF, buf, buf_len);
    FLOWLOCK_UNLOCK(&f);
    FAIL_IF(r != 0);

    SSLState *app_state = f.alstate;
    FAIL_IF_NULL(app_state);

    FAIL_IF(app_state->client_connp.content_type != SSLV2_MT_CLIENT_HELLO);

    FAIL_IF(app_state->client_connp.version != SSL_VERSION_2);

    AppLayerParserThreadCtxFree(alp_tctx);
    StreamTcpFreeConfig(TRUE);
    FLOW_DESTROY(&f);

    PASS;
}

/**
 * \test SSLv2 Record parsing.
 */
static int SSLParserTest22(void)
{
    Flow f;
    uint8_t buf[] = {
        0x80, 0x31, 0x04, 0x00, 0x01, 0x00,
        0x02, 0x00, 0x00, 0x00, 0x10, 0x07, 0x00, 0xc0,
        0x05, 0x00, 0x80, 0x03, 0x00, 0x80, 0x01, 0x00,
        0x80, 0x08, 0x00, 0x80, 0x06, 0x00, 0x40, 0x04,
        0x00, 0x80, 0x02, 0x00, 0x80, 0x76, 0x64, 0x75,
        0x2d, 0xa7, 0x98, 0xfe, 0xc9, 0x12, 0x92, 0xc1,
        0x2f, 0x34, 0x84, 0x20, 0xc5};
    uint32_t buf_len = sizeof(buf);
    TcpSession ssn;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    //AppLayerDetectProtoThreadInit();

    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;
    f.alproto = ALPROTO_TLS;

    StreamTcpInitConfig(TRUE);

    FLOWLOCK_WRLOCK(&f);
    int r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_TLS,
                                STREAM_TOCLIENT | STREAM_EOF, buf, buf_len);
    FLOWLOCK_UNLOCK(&f);
    FAIL_IF(r != 0);

    SSLState *app_state = f.alstate;
    FAIL_IF_NULL(app_state);

    FAIL_IF(app_state->server_connp.content_type != SSLV2_MT_SERVER_HELLO);

    FAIL_IF(app_state->server_connp.version != SSL_VERSION_2);

    AppLayerParserThreadCtxFree(alp_tctx);
    StreamTcpFreeConfig(TRUE);
    FLOW_DESTROY(&f);

    PASS;
}

/**
 * \test SSLv2 Record parsing.
 */
static int SSLParserTest23(void)
{
    Flow f;
    uint8_t chello_buf[] = {
        0x80, 0x67, 0x01, 0x03, 0x00, 0x00, 0x4e, 0x00,
        0x00, 0x00, 0x10, 0x01, 0x00, 0x80, 0x03, 0x00,
        0x80, 0x07, 0x00, 0xc0, 0x06, 0x00, 0x40, 0x02,
        0x00, 0x80, 0x04, 0x00, 0x80, 0x00, 0x00, 0x39,
        0x00, 0x00, 0x38, 0x00, 0x00, 0x35, 0x00, 0x00,
        0x33, 0x00, 0x00, 0x32, 0x00, 0x00, 0x04, 0x00,
        0x00, 0x05, 0x00, 0x00, 0x2f, 0x00, 0x00, 0x16,
        0x00, 0x00, 0x13, 0x00, 0xfe, 0xff, 0x00, 0x00,
        0x0a, 0x00, 0x00, 0x15, 0x00, 0x00, 0x12, 0x00,
        0xfe, 0xfe, 0x00, 0x00, 0x09, 0x00, 0x00, 0x64,
        0x00, 0x00, 0x62, 0x00, 0x00, 0x03, 0x00, 0x00,
        0x06, 0xa8, 0xb8, 0x93, 0xbb, 0x90, 0xe9, 0x2a,
        0xa2, 0x4d, 0x6d, 0xcc, 0x1c, 0xe7, 0x2a, 0x80,
        0x21
    };
    uint32_t chello_buf_len = sizeof(chello_buf);

    uint8_t shello_buf[] = {
        0x16, 0x03, 0x00, 0x00, 0x4a, 0x02,
        0x00, 0x00, 0x46, 0x03, 0x00, 0x44, 0x4c, 0x94,
        0x8f, 0xfe, 0x81, 0xed, 0x93, 0x65, 0x02, 0x88,
        0xa3, 0xf8, 0xeb, 0x63, 0x86, 0x0e, 0x2c, 0xf6,
        0x8d, 0xd0, 0x0f, 0x2c, 0x2a, 0xd6, 0x4f, 0xcd,
        0x2d, 0x3c, 0x16, 0xd7, 0xd6, 0x20, 0xa0, 0xfb,
        0x60, 0x86, 0x3d, 0x1e, 0x76, 0xf3, 0x30, 0xfe,
        0x0b, 0x01, 0xfd, 0x1a, 0x01, 0xed, 0x95, 0xf6,
        0x7b, 0x8e, 0xc0, 0xd4, 0x27, 0xbf, 0xf0, 0x6e,
        0xc7, 0x56, 0xb1, 0x47, 0xce, 0x98, 0x00, 0x35,
        0x00, 0x16, 0x03, 0x00, 0x03, 0x44, 0x0b, 0x00,
        0x03, 0x40, 0x00, 0x03, 0x3d, 0x00, 0x03, 0x3a,
        0x30, 0x82, 0x03, 0x36, 0x30, 0x82, 0x02, 0x9f,
        0xa0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x01, 0x01,
        0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86,
        0xf7, 0x0d, 0x01, 0x01, 0x04, 0x05, 0x00, 0x30,
        0x81, 0xa9, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03,
        0x55, 0x04, 0x06, 0x13, 0x02, 0x58, 0x59, 0x31,
        0x15, 0x30, 0x13, 0x06, 0x03, 0x55, 0x04, 0x08,
        0x13, 0x0c, 0x53, 0x6e, 0x61, 0x6b, 0x65, 0x20,
        0x44, 0x65, 0x73, 0x65, 0x72, 0x74, 0x31, 0x13,
        0x30, 0x11, 0x06, 0x03, 0x55, 0x04, 0x07, 0x13,
        0x0a, 0x53, 0x6e, 0x61, 0x6b, 0x65, 0x20, 0x54,
        0x6f, 0x77, 0x6e, 0x31, 0x17, 0x30, 0x15, 0x06,
        0x03, 0x55, 0x04, 0x0a, 0x13, 0x0e, 0x53, 0x6e,
        0x61, 0x6b, 0x65, 0x20, 0x4f, 0x69, 0x6c, 0x2c,
        0x20, 0x4c, 0x74, 0x64, 0x31, 0x1e, 0x30, 0x1c,
        0x06, 0x03, 0x55, 0x04, 0x0b, 0x13, 0x15, 0x43,
        0x65, 0x72, 0x74, 0x69, 0x66, 0x69, 0x63, 0x61,
        0x74, 0x65, 0x20, 0x41, 0x75, 0x74, 0x68, 0x6f,
        0x72, 0x69, 0x74, 0x79, 0x31, 0x15, 0x30, 0x13,
        0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x0c, 0x53,
        0x6e, 0x61, 0x6b, 0x65, 0x20, 0x4f, 0x69, 0x6c,
        0x20, 0x43, 0x41, 0x31, 0x1e, 0x30, 0x1c, 0x06,
        0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01,
        0x09, 0x01, 0x16, 0x0f, 0x63, 0x61, 0x40, 0x73,
        0x6e, 0x61, 0x6b, 0x65, 0x6f, 0x69, 0x6c, 0x2e,
        0x64, 0x6f, 0x6d, 0x30, 0x1e, 0x17, 0x0d, 0x30,
        0x33, 0x30, 0x33, 0x30, 0x35, 0x31, 0x36, 0x34,
        0x37, 0x34, 0x35, 0x5a, 0x17, 0x0d, 0x30, 0x38,
        0x30, 0x33, 0x30, 0x33, 0x31, 0x36, 0x34, 0x37,
        0x34, 0x35, 0x5a, 0x30, 0x81, 0xa7, 0x31, 0x0b,
        0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13,
        0x02, 0x58, 0x59, 0x31, 0x15, 0x30, 0x13, 0x06,
        0x03, 0x55, 0x04, 0x08, 0x13, 0x0c, 0x53, 0x6e,
        0x61, 0x6b, 0x65, 0x20, 0x44, 0x65, 0x73, 0x65,
        0x72, 0x74, 0x31, 0x13, 0x30, 0x11, 0x06, 0x03,
        0x55, 0x04, 0x07, 0x13, 0x0a, 0x53, 0x6e, 0x61,
        0x6b, 0x65, 0x20, 0x54, 0x6f, 0x77, 0x6e, 0x31,
        0x17, 0x30, 0x15, 0x06, 0x03, 0x55, 0x04, 0x0a,
        0x13, 0x0e, 0x53, 0x6e, 0x61, 0x6b, 0x65, 0x20,
        0x4f, 0x69, 0x6c, 0x2c, 0x20, 0x4c, 0x74, 0x64,
        0x31, 0x17, 0x30, 0x15, 0x06, 0x03, 0x55, 0x04,
        0x0b, 0x13, 0x0e, 0x57, 0x65, 0x62, 0x73, 0x65,
        0x72, 0x76, 0x65, 0x72, 0x20, 0x54, 0x65, 0x61,
        0x6d, 0x31, 0x19, 0x30, 0x17, 0x06, 0x03, 0x55,
        0x04, 0x03, 0x13, 0x10, 0x77, 0x77, 0x77, 0x2e,
        0x73, 0x6e, 0x61, 0x6b, 0x65, 0x6f, 0x69, 0x6c,
        0x2e, 0x64, 0x6f, 0x6d, 0x31, 0x1f, 0x30, 0x1d,
        0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d,
        0x01, 0x09, 0x01, 0x16, 0x10, 0x77, 0x77, 0x77,
        0x40, 0x73, 0x6e, 0x61, 0x6b, 0x65, 0x6f, 0x69,
        0x6c, 0x2e, 0x64, 0x6f, 0x6d, 0x30, 0x81, 0x9f,
        0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86,
        0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00, 0x03,
        0x81, 0x8d, 0x00, 0x30, 0x81, 0x89, 0x02, 0x81,
        0x81, 0x00, 0xa4, 0x6e, 0x53, 0x14, 0x0a, 0xde,
        0x2c, 0xe3, 0x60, 0x55, 0x9a, 0xf2, 0x42, 0xa6,
        0xaf, 0x47, 0x12, 0x2f, 0x17, 0xce, 0xfa, 0xba,
        0xdc, 0x4e, 0x63, 0x56, 0x34, 0xb9, 0xba, 0x73,
        0x4b, 0x78, 0x44, 0x3d, 0xc6, 0x6c, 0x69, 0xa4,
        0x25, 0xb3, 0x61, 0x02, 0x9d, 0x09, 0x04, 0x3f,
        0x72, 0x3d, 0xd8, 0x27, 0xd3, 0xb0, 0x5a, 0x45,
        0x77, 0xb7, 0x36, 0xe4, 0x26, 0x23, 0xcc, 0x12,
        0xb8, 0xae, 0xde, 0xa7, 0xb6, 0x3a, 0x82, 0x3c,
        0x7c, 0x24, 0x59, 0x0a, 0xf8, 0x96, 0x43, 0x8b,
        0xa3, 0x29, 0x36, 0x3f, 0x91, 0x7f, 0x5d, 0xc7,
        0x23, 0x94, 0x29, 0x7f, 0x0a, 0xce, 0x0a, 0xbd,
        0x8d, 0x9b, 0x2f, 0x19, 0x17, 0xaa, 0xd5, 0x8e,
        0xec, 0x66, 0xa2, 0x37, 0xeb, 0x3f, 0x57, 0x53,
        0x3c, 0xf2, 0xaa, 0xbb, 0x79, 0x19, 0x4b, 0x90,
        0x7e, 0xa7, 0xa3, 0x99, 0xfe, 0x84, 0x4c, 0x89,
        0xf0, 0x3d, 0x02, 0x03, 0x01, 0x00, 0x01, 0xa3,
        0x6e, 0x30, 0x6c, 0x30, 0x1b, 0x06, 0x03, 0x55,
        0x1d, 0x11, 0x04, 0x14, 0x30, 0x12, 0x81, 0x10,
        0x77, 0x77, 0x77, 0x40, 0x73, 0x6e, 0x61, 0x6b,
        0x65, 0x6f, 0x69, 0x6c, 0x2e, 0x64, 0x6f, 0x6d,
        0x30, 0x3a, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01,
        0x86, 0xf8, 0x42, 0x01, 0x0d, 0x04, 0x2d, 0x16,
        0x2b, 0x6d, 0x6f, 0x64, 0x5f, 0x73, 0x73, 0x6c,
        0x20, 0x67, 0x65, 0x6e, 0x65, 0x72, 0x61, 0x74,
        0x65, 0x64, 0x20, 0x63, 0x75, 0x73, 0x74, 0x6f,
        0x6d, 0x20, 0x73, 0x65, 0x72, 0x76, 0x65, 0x72,
        0x20, 0x63, 0x65, 0x72, 0x74, 0x69, 0x66, 0x69,
        0x63, 0x61, 0x74, 0x65, 0x30, 0x11, 0x06, 0x09,
        0x60, 0x86, 0x48, 0x01, 0x86, 0xf8, 0x42, 0x01,
        0x01, 0x04, 0x04, 0x03, 0x02, 0x06, 0x40, 0x30,
        0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7,
        0x0d, 0x01, 0x01, 0x04, 0x05, 0x00, 0x03, 0x81,
        0x81, 0x00, 0xae, 0x79, 0x79, 0x22, 0x90, 0x75,
        0xfd, 0xa6, 0xd5, 0xc4, 0xb8, 0xc4, 0x99, 0x4e,
        0x1c, 0x05, 0x7c, 0x91, 0x59, 0xbe, 0x89, 0x0d,
        0x3d, 0xc6, 0x8c, 0xa3, 0xcf, 0xf6, 0xba, 0x23,
        0xdf, 0xb8, 0xae, 0x44, 0x68, 0x8a, 0x8f, 0xb9,
        0x8b, 0xcb, 0x12, 0xda, 0xe6, 0xa2, 0xca, 0xa5,
        0xa6, 0x55, 0xd9, 0xd2, 0xa1, 0xad, 0xba, 0x9b,
        0x2c, 0x44, 0x95, 0x1d, 0x4a, 0x90, 0x59, 0x7f,
        0x83, 0xae, 0x81, 0x5e, 0x3f, 0x92, 0xe0, 0x14,
        0x41, 0x82, 0x4e, 0x7f, 0x53, 0xfd, 0x10, 0x23,
        0xeb, 0x8a, 0xeb, 0xe9, 0x92, 0xea, 0x61, 0xf2,
        0x8e, 0x19, 0xa1, 0xd3, 0x49, 0xc0, 0x84, 0x34,
        0x1e, 0x2e, 0x6e, 0xf6, 0x98, 0xe2, 0x87, 0x53,
        0xd6, 0x55, 0xd9, 0x1a, 0x8a, 0x92, 0x5c, 0xad,
        0xdc, 0x1e, 0x1c, 0x30, 0xa7, 0x65, 0x9d, 0xc2,
        0x4f, 0x60, 0xd2, 0x6f, 0xdb, 0xe0, 0x9f, 0x9e,
        0xbc, 0x41, 0x16, 0x03, 0x00, 0x00, 0x04, 0x0e,
        0x00, 0x00, 0x00
    };
    uint32_t shello_buf_len = sizeof(shello_buf);

    uint8_t client_change_cipher_spec_buf[] = {
        0x16, 0x03, 0x00, 0x00, 0x84, 0x10, 0x00, 0x00,
        0x80, 0x65, 0x51, 0x2d, 0xa6, 0xd4, 0xa7, 0x38,
        0xdf, 0xac, 0x79, 0x1f, 0x0b, 0xd9, 0xb2, 0x61,
        0x7d, 0x73, 0x88, 0x32, 0xd9, 0xf2, 0x62, 0x3a,
        0x8b, 0x11, 0x04, 0x75, 0xca, 0x42, 0xff, 0x4e,
        0xd9, 0xcc, 0xb9, 0xfa, 0x86, 0xf3, 0x16, 0x2f,
        0x09, 0x73, 0x51, 0x66, 0xaa, 0x29, 0xcd, 0x80,
        0x61, 0x0f, 0xe8, 0x13, 0xce, 0x5b, 0x8e, 0x0a,
        0x23, 0xf8, 0x91, 0x5e, 0x5f, 0x54, 0x70, 0x80,
        0x8e, 0x7b, 0x28, 0xef, 0xb6, 0x69, 0xb2, 0x59,
        0x85, 0x74, 0x98, 0xe2, 0x7e, 0xd8, 0xcc, 0x76,
        0x80, 0xe1, 0xb6, 0x45, 0x4d, 0xc7, 0xcd, 0x84,
        0xce, 0xb4, 0x52, 0x79, 0x74, 0xcd, 0xe6, 0xd7,
        0xd1, 0x9c, 0xad, 0xef, 0x63, 0x6c, 0x0f, 0xf7,
        0x05, 0xe4, 0x4d, 0x1a, 0xd3, 0xcb, 0x9c, 0xd2,
        0x51, 0xb5, 0x61, 0xcb, 0xff, 0x7c, 0xee, 0xc7,
        0xbc, 0x5e, 0x15, 0xa3, 0xf2, 0x52, 0x0f, 0xbb,
        0x32, 0x14, 0x03, 0x00, 0x00, 0x01, 0x01, 0x16,
        0x03, 0x00, 0x00, 0x40, 0xa9, 0xd8, 0xd7, 0x35,
        0xbc, 0x39, 0x56, 0x98, 0xad, 0x87, 0x61, 0x2a,
        0xc4, 0x8f, 0xcc, 0x03, 0xcb, 0x93, 0x80, 0x81,
        0xb0, 0x4a, 0xc4, 0xd2, 0x09, 0x71, 0x3e, 0x90,
        0x3c, 0x8d, 0xe0, 0x95, 0x44, 0xfe, 0x56, 0xd1,
        0x7e, 0x88, 0xe2, 0x48, 0xfd, 0x76, 0x70, 0x76,
        0xe2, 0xcd, 0x06, 0xd0, 0xf3, 0x9d, 0x13, 0x79,
        0x67, 0x1e, 0x37, 0xf6, 0x98, 0xbe, 0x59, 0x18,
        0x4c, 0xfc, 0x75, 0x56
    };
    uint32_t client_change_cipher_spec_buf_len =
        sizeof(client_change_cipher_spec_buf);

    uint8_t server_change_cipher_spec_buf[] = {
        0x14, 0x03, 0x00, 0x00, 0x01, 0x01, 0x16, 0x03,
        0x00, 0x00, 0x40, 0xce, 0x7c, 0x92, 0x43, 0x59,
        0xcc, 0x3d, 0x90, 0x91, 0x9c, 0x58, 0xf0, 0x7a,
        0xce, 0xae, 0x0d, 0x08, 0xe0, 0x76, 0xb4, 0x86,
        0xb1, 0x15, 0x5b, 0x32, 0xb8, 0x77, 0x53, 0xe7,
        0xa6, 0xf9, 0xd0, 0x95, 0x5f, 0xaa, 0x07, 0xc3,
        0x96, 0x7c, 0xc9, 0x88, 0xc2, 0x7a, 0x20, 0x89,
        0x4f, 0xeb, 0xeb, 0xb6, 0x19, 0xef, 0xaa, 0x27,
        0x73, 0x9d, 0xa6, 0xb4, 0x9f, 0xeb, 0x34, 0xe2,
        0x4d, 0x9f, 0x6b
    };
    uint32_t server_change_cipher_spec_buf_len =
        sizeof(server_change_cipher_spec_buf);

    uint8_t toserver_app_data_buf[] = {
        0x17, 0x03, 0x00, 0x01, 0xb0, 0x4a, 0xc3, 0x3e,
        0x9d, 0x77, 0x78, 0x01, 0x2c, 0xb4, 0xbc, 0x4c,
        0x9a, 0x84, 0xd7, 0xb9, 0x90, 0x0c, 0x21, 0x10,
        0xf0, 0xfa, 0x00, 0x7c, 0x16, 0xbb, 0x77, 0xfb,
        0x72, 0x42, 0x4f, 0xad, 0x50, 0x4a, 0xd0, 0xaa,
        0x6f, 0xaa, 0x44, 0x6c, 0x62, 0x94, 0x1b, 0xc5,
        0xfe, 0xe9, 0x1c, 0x5e, 0xde, 0x85, 0x0b, 0x0e,
        0x05, 0xe4, 0x18, 0x6e, 0xd2, 0xd3, 0xb5, 0x20,
        0xab, 0x81, 0xfd, 0x18, 0x9a, 0x73, 0xb8, 0xd7,
        0xef, 0xc3, 0xdd, 0x74, 0xd7, 0x9c, 0x1e, 0x6f,
        0x21, 0x6d, 0xf8, 0x24, 0xca, 0x3c, 0x70, 0x78,
        0x36, 0x12, 0x7a, 0x8a, 0x9c, 0xac, 0x4e, 0x1c,
        0xa8, 0xfb, 0x27, 0x30, 0xba, 0x9a, 0xf4, 0x2f,
        0x0a, 0xab, 0x80, 0x6a, 0xa1, 0x60, 0x74, 0xf0,
        0xe3, 0x91, 0x84, 0xe7, 0x90, 0x88, 0xcc, 0xf0,
        0x95, 0x7b, 0x0a, 0x22, 0xf2, 0xf9, 0x27, 0xe0,
        0xdd, 0x38, 0x0c, 0xfd, 0xe9, 0x03, 0x71, 0xdc,
        0x70, 0xa4, 0x6e, 0xdf, 0xe3, 0x72, 0x9e, 0xa1,
        0xf0, 0xc9, 0x00, 0xd6, 0x03, 0x55, 0x6a, 0x67,
        0x5d, 0x9c, 0xb8, 0x75, 0x01, 0xb0, 0x01, 0x9f,
        0xe6, 0xd2, 0x44, 0x18, 0xbc, 0xca, 0x7a, 0x10,
        0x39, 0xa6, 0xcf, 0x15, 0xc7, 0xf5, 0x35, 0xd4,
        0xb3, 0x6d, 0x91, 0x23, 0x84, 0x99, 0xba, 0xb0,
        0x7e, 0xd0, 0xc9, 0x4c, 0xbf, 0x3f, 0x33, 0x68,
        0x37, 0xb7, 0x7d, 0x44, 0xb0, 0x0b, 0x2c, 0x0f,
        0xd0, 0x75, 0xa2, 0x6b, 0x5b, 0xe1, 0x9f, 0xd4,
        0x69, 0x9a, 0x14, 0xc8, 0x29, 0xb7, 0xd9, 0x10,
        0xbb, 0x99, 0x30, 0x9a, 0xfb, 0xcc, 0x13, 0x1f,
        0x76, 0x4e, 0xe6, 0xdf, 0x14, 0xaa, 0xd5, 0x60,
        0xbf, 0x91, 0x49, 0x0d, 0x64, 0x42, 0x29, 0xa8,
        0x64, 0x27, 0xd4, 0x5e, 0x1b, 0x18, 0x03, 0xa8,
        0x73, 0xd6, 0x05, 0x6e, 0xf7, 0x50, 0xb0, 0x09,
        0x6b, 0x69, 0x7a, 0x12, 0x28, 0x58, 0xef, 0x5a,
        0x86, 0x11, 0xde, 0x71, 0x71, 0x9f, 0xca, 0xbd,
        0x79, 0x2a, 0xc2, 0xe5, 0x9b, 0x5e, 0x32, 0xe7,
        0xcb, 0x97, 0x6e, 0xa0, 0xea, 0xa4, 0xa4, 0x6a,
        0x32, 0xf9, 0x37, 0x39, 0xd8, 0x37, 0x6d, 0x63,
        0xf3, 0x08, 0x1c, 0xdd, 0x06, 0xdd, 0x2c, 0x2b,
        0x9f, 0x04, 0x88, 0x5f, 0x36, 0x42, 0xc1, 0xb1,
        0xc7, 0xe8, 0x2d, 0x5d, 0xa4, 0x6c, 0xe5, 0x60,
        0x94, 0xae, 0xd0, 0x90, 0x1e, 0x88, 0xa0, 0x87,
        0x52, 0xfb, 0xed, 0x97, 0xa5, 0x25, 0x5a, 0xb7,
        0x55, 0xc5, 0x13, 0x07, 0x85, 0x27, 0x40, 0xed,
        0xb8, 0xa0, 0x26, 0x13, 0x44, 0x0c, 0xfc, 0xcc,
        0x5a, 0x09, 0xe5, 0x44, 0xb5, 0x63, 0xa1, 0x43,
        0x51, 0x23, 0x4f, 0x17, 0x21, 0x89, 0x2e, 0x58,
        0xfd, 0xf9, 0x63, 0x74, 0x04, 0x70, 0x1e, 0x7d,
        0xd0, 0x66, 0xba, 0x40, 0x5e, 0x45, 0xdc, 0x39,
        0x7c, 0x53, 0x0f, 0xa8, 0x38, 0xb2, 0x13, 0x99,
        0x27, 0xd9, 0x4a, 0x51, 0xe9, 0x9f, 0x2a, 0x92,
        0xbb, 0x9c, 0x90, 0xab, 0xfd, 0xf1, 0xb7, 0x40,
        0x05, 0xa9, 0x7a, 0x20, 0x63, 0x36, 0xc1, 0xef,
        0xb9, 0xad, 0xa2, 0xe0, 0x1d, 0x20, 0x4f, 0xb2,
        0x34, 0xbd, 0xea, 0x07, 0xac, 0x21, 0xce, 0xf6,
        0x8a, 0xa2, 0x9e, 0xcd, 0xfa
    };
    uint32_t toserver_app_data_buf_len = sizeof(toserver_app_data_buf);

    TcpSession ssn;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    //AppLayerDetectProtoThreadInit();

    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;
    f.alproto = ALPROTO_TLS;

    StreamTcpInitConfig(TRUE);

    FLOWLOCK_WRLOCK(&f);
    int r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_TLS,
                                STREAM_TOSERVER | STREAM_START, chello_buf,
                                chello_buf_len);
    FLOWLOCK_UNLOCK(&f);
    FAIL_IF(r != 0);

    SSLState *app_state = f.alstate;
    FAIL_IF_NULL(app_state);

    FAIL_IF(app_state->client_connp.content_type != SSLV2_MT_CLIENT_HELLO);

    FAIL_IF(app_state->client_connp.version != SSL_VERSION_2);

    FAIL_IF((app_state->flags & SSL_AL_FLAG_STATE_CLIENT_HELLO) == 0);
    FAIL_IF((app_state->flags & SSL_AL_FLAG_SSL_CLIENT_HS) == 0);
    FAIL_IF((app_state->flags & SSL_AL_FLAG_SSL_NO_SESSION_ID) == 0);

    FLOWLOCK_WRLOCK(&f);
    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_TLS, STREAM_TOCLIENT,
                            shello_buf, shello_buf_len);
    FLOWLOCK_UNLOCK(&f);
    FAIL_IF(r != 0);

    FAIL_IF(app_state->server_connp.content_type != SSLV3_HANDSHAKE_PROTOCOL);

    FAIL_IF(app_state->server_connp.version != SSL_VERSION_3);

    FAIL_IF((app_state->flags & SSL_AL_FLAG_STATE_CLIENT_HELLO) == 0);
    FAIL_IF((app_state->flags & SSL_AL_FLAG_SSL_CLIENT_HS) == 0);
    FAIL_IF((app_state->flags & SSL_AL_FLAG_SSL_NO_SESSION_ID) == 0);
    FAIL_IF((app_state->flags & SSL_AL_FLAG_STATE_SERVER_HELLO) == 0);

    FLOWLOCK_WRLOCK(&f);
    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_TLS, STREAM_TOSERVER,
                            client_change_cipher_spec_buf,
                            client_change_cipher_spec_buf_len);
    FLOWLOCK_UNLOCK(&f);
    FAIL_IF(r != 0);

    /* with multiple records the client content type hold the type from the last
     * record */
    FAIL_IF(app_state->client_connp.content_type != SSLV3_HANDSHAKE_PROTOCOL);

    FAIL_IF((app_state->flags & SSL_AL_FLAG_STATE_CLIENT_HELLO) == 0);
    FAIL_IF((app_state->flags & SSL_AL_FLAG_SSL_CLIENT_HS) == 0);
    FAIL_IF((app_state->flags & SSL_AL_FLAG_SSL_NO_SESSION_ID) == 0);
    FAIL_IF((app_state->flags & SSL_AL_FLAG_STATE_SERVER_HELLO) == 0);
    FAIL_IF((app_state->flags & SSL_AL_FLAG_STATE_CLIENT_KEYX) == 0);
    FAIL_IF((app_state->flags & SSL_AL_FLAG_CLIENT_CHANGE_CIPHER_SPEC) == 0);
    FAIL_IF((app_state->flags & SSL_AL_FLAG_CHANGE_CIPHER_SPEC) == 0);

    FLOWLOCK_WRLOCK(&f);
    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_TLS, STREAM_TOCLIENT,
                            server_change_cipher_spec_buf,
                            server_change_cipher_spec_buf_len);
    FLOWLOCK_UNLOCK(&f);
    FAIL_IF(r != 0);

    /* with multiple records the serve content type hold the type from the last
     * record */
    FAIL_IF(app_state->server_connp.content_type != SSLV3_HANDSHAKE_PROTOCOL);

    FAIL_IF(app_state->server_connp.version != SSL_VERSION_3);

    FAIL_IF((app_state->flags & SSL_AL_FLAG_STATE_CLIENT_HELLO) == 0);
    FAIL_IF((app_state->flags & SSL_AL_FLAG_SSL_CLIENT_HS) == 0);
    FAIL_IF((app_state->flags & SSL_AL_FLAG_SSL_NO_SESSION_ID) == 0);
    FAIL_IF((app_state->flags & SSL_AL_FLAG_STATE_SERVER_HELLO) == 0);
    FAIL_IF((app_state->flags & SSL_AL_FLAG_STATE_CLIENT_KEYX) == 0);
    FAIL_IF((app_state->flags & SSL_AL_FLAG_CLIENT_CHANGE_CIPHER_SPEC) == 0);
    FAIL_IF((app_state->flags & SSL_AL_FLAG_SERVER_CHANGE_CIPHER_SPEC) == 0);
    FAIL_IF((app_state->flags & SSL_AL_FLAG_CHANGE_CIPHER_SPEC) == 0);

    FLOWLOCK_WRLOCK(&f);
    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_TLS, STREAM_TOSERVER,
                            toserver_app_data_buf, toserver_app_data_buf_len);
    FLOWLOCK_UNLOCK(&f);
    FAIL_IF(r != 0);

    FAIL_IF(app_state->client_connp.content_type != SSLV3_APPLICATION_PROTOCOL);

    FAIL_IF((app_state->flags & SSL_AL_FLAG_STATE_CLIENT_HELLO) == 0);
    FAIL_IF((app_state->flags & SSL_AL_FLAG_SSL_CLIENT_HS) == 0);
    FAIL_IF((app_state->flags & SSL_AL_FLAG_SSL_NO_SESSION_ID) == 0);
    FAIL_IF((app_state->flags & SSL_AL_FLAG_STATE_SERVER_HELLO) == 0);
    FAIL_IF((app_state->flags & SSL_AL_FLAG_STATE_CLIENT_KEYX) == 0);
    FAIL_IF((app_state->flags & SSL_AL_FLAG_CLIENT_CHANGE_CIPHER_SPEC) == 0);
    FAIL_IF((app_state->flags & SSL_AL_FLAG_SERVER_CHANGE_CIPHER_SPEC) == 0);
    FAIL_IF((app_state->flags & SSL_AL_FLAG_CHANGE_CIPHER_SPEC) == 0);

    FAIL_IF_NOT(f.flags & FLOW_NOPAYLOAD_INSPECTION);

    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
    StreamTcpFreeConfig(TRUE);
    FLOW_DESTROY(&f);

    PASS;
}

/**
 * \test Tests the parser for handling fragmented records.
 */
static int SSLParserTest24(void)
{
    Flow f;
    uint8_t buf1[] = {
        0x16, 0x03, 0x00, 0x00, 0x6f, 0x01, 0x00, 0x00,
        0x6b, 0x03,
    };
    uint32_t buf1_len = sizeof(buf1);

    uint8_t buf2[] = {
        0x00, 0x4b, 0x2f, 0xdc,
        0x4e, 0xe6, 0x95, 0xf1, 0xa0, 0xc7, 0xcf, 0x8e,
        0xf6, 0xeb, 0x22, 0x6d, 0xce, 0x9c, 0x44, 0xfb,
        0xc8, 0xa0, 0x44, 0x31, 0x15, 0x4c, 0xe9, 0x97,
        0xa7, 0xa1, 0xfe, 0xea, 0xcc, 0x20, 0x4b, 0x5d,
        0xfb, 0xa5, 0x63, 0x7a, 0x73, 0x95, 0xf7, 0xff,
        0x42, 0xac, 0x8f, 0x46, 0xed, 0xe4, 0xb1, 0x35,
        0x35, 0x78, 0x1a, 0x9d, 0xaf, 0x10, 0xc5, 0x52,
        0xf3, 0x7b, 0xfb, 0xb5, 0xe9, 0xa8, 0x00, 0x24,
        0x00, 0x88, 0x00, 0x87, 0x00, 0x39, 0x00, 0x38,
        0x00, 0x84, 0x00, 0x35, 0x00, 0x45, 0x00, 0x44,
        0x00, 0x33, 0x00, 0x32, 0x00, 0x96, 0x00, 0x41,
        0x00, 0x2f, 0x00, 0x16, 0x00, 0x13, 0xfe, 0xff,
        0x00, 0x0a, 0x00, 0x02, 0x01, 0x00
    };
    uint32_t buf2_len = sizeof(buf2);
    TcpSession ssn;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));
    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;
    f.alproto = ALPROTO_TLS;

    StreamTcpInitConfig(TRUE);

    FLOWLOCK_WRLOCK(&f);
    int r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_TLS,
                                STREAM_TOSERVER, buf1, buf1_len);
    FLOWLOCK_UNLOCK(&f);
    FAIL_IF(r != 0);

    FLOWLOCK_WRLOCK(&f);
    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_TLS, STREAM_TOSERVER,
                            buf2, buf2_len);
    FLOWLOCK_UNLOCK(&f);
    FAIL_IF(r != 0);

    SSLState *ssl_state = f.alstate;
    FAIL_IF_NULL(ssl_state);

    FAIL_IF(ssl_state->client_connp.content_type != 0x16);

    FAIL_IF(ssl_state->client_connp.version != SSL_VERSION_3);

    AppLayerParserThreadCtxFree(alp_tctx);
    StreamTcpFreeConfig(TRUE);
    FLOW_DESTROY(&f);

    PASS;
}

/**
 * \test Test for bug #955 and CVE-2013-5919.  The data is from the
 *       pcap that was used to report this issue.
 */
static int SSLParserTest25(void)
{
    Flow f;
    uint8_t client_hello[] = {
        0x16, 0x03, 0x01, 0x00, 0xd3, 0x01, 0x00, 0x00,
        0xcf, 0x03, 0x01, 0x51, 0x60, 0xc2, 0x15, 0x36,
        0x73, 0xf5, 0xb8, 0x58, 0x55, 0x3b, 0x68, 0x12,
        0x7d, 0xe3, 0x28, 0xa3, 0xe1, 0x02, 0x79, 0x2d,
        0x12, 0xe1, 0xf4, 0x24, 0x12, 0xa2, 0x9e, 0xf1,
        0x08, 0x49, 0x68, 0x20, 0x0e, 0x96, 0x46, 0x3d,
        0x84, 0x5a, 0xc6, 0x55, 0xeb, 0x3b, 0x53, 0x77,
        0xf4, 0x8e, 0xf4, 0xd2, 0x8b, 0xec, 0xd6, 0x99,
        0x63, 0x64, 0x62, 0xf8, 0x3f, 0x3b, 0xd5, 0x35,
        0x45, 0x1b, 0x16, 0xac, 0x00, 0x46, 0x00, 0x04,
        0x00, 0x05, 0x00, 0x2f, 0x00, 0x35, 0xc0, 0x02,
        0xc0, 0x04, 0xc0, 0x05, 0xc0, 0x0c, 0xc0, 0x0e,
        0xc0, 0x0f, 0xc0, 0x07, 0xc0, 0x09, 0xc0, 0x0a,
        0xc0, 0x11, 0xc0, 0x13, 0xc0, 0x14, 0x00, 0x33,
        0x00, 0x39, 0x00, 0x32, 0x00, 0x38, 0x00, 0x0a,
        0xc0, 0x03, 0xc0, 0x0d, 0xc0, 0x08, 0xc0, 0x12,
        0x00, 0x16, 0x00, 0x13, 0x00, 0x09, 0x00, 0x15,
        0x00, 0x12, 0x00, 0x03, 0x00, 0x08, 0x00, 0x14,
        0x00, 0x11, 0x00, 0xff, 0x01, 0x00, 0x00, 0x40,
        0x00, 0x0b, 0x00, 0x04, 0x03, 0x00, 0x01, 0x02,
        0x00, 0x0a, 0x00, 0x34, 0x00, 0x32, 0x00, 0x0e,
        0x00, 0x0d, 0x00, 0x19, 0x00, 0x0b, 0x00, 0x0c,
        0x00, 0x18, 0x00, 0x09, 0x00, 0x0a, 0x00, 0x16,
        0x00, 0x17, 0x00, 0x08, 0x00, 0x06, 0x00, 0x07,
        0x00, 0x14, 0x00, 0x15, 0x00, 0x04, 0x00, 0x05,
        0x00, 0x12, 0x00, 0x13, 0x00, 0x01, 0x00, 0x02,
        0x00, 0x03, 0x00, 0x0f, 0x00, 0x10, 0x00, 0x11
    };
    uint32_t client_hello_len = sizeof(client_hello);

    uint8_t server_hello_certificate_done[] = {
        0x16, 0x03, 0x01, 0x00, 0x51, 0x02, 0x00, 0x00,
        0x4d, 0x03, 0x01, 0x51, 0x60, 0xc2, 0x17, 0xb7,
        0x81, 0xaa, 0x27, 0xa1, 0xd5, 0xfa, 0x14, 0xc1,
        0xe0, 0x05, 0xab, 0x75, 0xf2, 0x51, 0xe7, 0x6e,
        0xe6, 0xf9, 0xc4, 0x8f, 0x16, 0x08, 0x26, 0x6c,
        0x1b, 0x86, 0x90, 0x20, 0x0a, 0x38, 0x90, 0x2d,
        0x17, 0x7d, 0xb7, 0x6b, 0x6b, 0xe5, 0xeb, 0x61,
        0x90, 0x35, 0xf8, 0xcd, 0xb1, 0x2a, 0x69, 0x6e,
        0x0e, 0x3e, 0x5f, 0x90, 0xdc, 0x2f, 0x51, 0x45,
        0x68, 0x63, 0xe3, 0xb3, 0x00, 0x05, 0x00, 0x00,
        0x05, 0xff, 0x01, 0x00, 0x01, 0x00, 0x16, 0x03,
        0x01, 0x07, 0x60, 0x0b, 0x00, 0x07, 0x5c, 0x00,
        0x07, 0x59, 0x00, 0x03, 0xcc, 0x30, 0x82, 0x03,
        0xc8, 0x30, 0x82, 0x03, 0x31, 0xa0, 0x03, 0x02,
        0x01, 0x02, 0x02, 0x10, 0x01, 0x7f, 0x77, 0xde,
        0xb3, 0xbc, 0xbb, 0x23, 0x5d, 0x44, 0xcc, 0xc7,
        0xdb, 0xa6, 0x2e, 0x72, 0x30, 0x0d, 0x06, 0x09,
        0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01,
        0x05, 0x05, 0x00, 0x30, 0x81, 0xba, 0x31, 0x1f,
        0x30, 0x1d, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x13,
        0x16, 0x56, 0x65, 0x72, 0x69, 0x53, 0x69, 0x67,
        0x6e, 0x20, 0x54, 0x72, 0x75, 0x73, 0x74, 0x20,
        0x4e, 0x65, 0x74, 0x77, 0x6f, 0x72, 0x6b, 0x31,
        0x17, 0x30, 0x15, 0x06, 0x03, 0x55, 0x04, 0x0b,
        0x13, 0x0e, 0x56, 0x65, 0x72, 0x69, 0x53, 0x69,
        0x67, 0x6e, 0x2c, 0x20, 0x49, 0x6e, 0x63, 0x2e,
        0x31, 0x33, 0x30, 0x31, 0x06, 0x03, 0x55, 0x04,
        0x0b, 0x13, 0x2a, 0x56, 0x65, 0x72, 0x69, 0x53,
        0x69, 0x67, 0x6e, 0x20, 0x49, 0x6e, 0x74, 0x65,
        0x72, 0x6e, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x61,
        0x6c, 0x20, 0x53, 0x65, 0x72, 0x76, 0x65, 0x72,
        0x20, 0x43, 0x41, 0x20, 0x2d, 0x20, 0x43, 0x6c,
        0x61, 0x73, 0x73, 0x20, 0x33, 0x31, 0x49, 0x30,
        0x47, 0x06, 0x03, 0x55, 0x04, 0x0b, 0x13, 0x40,
        0x77, 0x77, 0x77, 0x2e, 0x76, 0x65, 0x72, 0x69,
        0x73, 0x69, 0x67, 0x6e, 0x2e, 0x63, 0x6f, 0x6d,
        0x2f, 0x43, 0x50, 0x53, 0x20, 0x49, 0x6e, 0x63,
        0x6f, 0x72, 0x70, 0x2e, 0x62, 0x79, 0x20, 0x52,
        0x65, 0x66, 0x2e, 0x20, 0x4c, 0x49, 0x41, 0x42,
        0x49, 0x4c, 0x49, 0x54, 0x59, 0x20, 0x4c, 0x54,
        0x44, 0x2e, 0x28, 0x63, 0x29, 0x39, 0x37, 0x20,
        0x56, 0x65, 0x72, 0x69, 0x53, 0x69, 0x67, 0x6e,
        0x30, 0x1e, 0x17, 0x0d, 0x31, 0x32, 0x30, 0x36,
        0x32, 0x31, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
        0x5a, 0x17, 0x0d, 0x31, 0x33, 0x31, 0x32, 0x33,
        0x31, 0x32, 0x33, 0x35, 0x39, 0x35, 0x39, 0x5a,
        0x30, 0x68, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03,
        0x55, 0x04, 0x06, 0x13, 0x02, 0x55, 0x53, 0x31,
        0x13, 0x30, 0x11, 0x06, 0x03, 0x55, 0x04, 0x08,
        0x13, 0x0a, 0x43, 0x61, 0x6c, 0x69, 0x66, 0x6f,
        0x72, 0x6e, 0x69, 0x61, 0x31, 0x12, 0x30, 0x10,
        0x06, 0x03, 0x55, 0x04, 0x07, 0x13, 0x09, 0x50,
        0x61, 0x6c, 0x6f, 0x20, 0x41, 0x6c, 0x74, 0x6f,
        0x31, 0x17, 0x30, 0x15, 0x06, 0x03, 0x55, 0x04,
        0x0a, 0x13, 0x0e, 0x46, 0x61, 0x63, 0x65, 0x62,
        0x6f, 0x6f, 0x6b, 0x2c, 0x20, 0x49, 0x6e, 0x63,
        0x2e, 0x31, 0x17, 0x30, 0x15, 0x06, 0x03, 0x55,
        0x04, 0x02, 0x14, 0x0e, 0x2a, 0x2e, 0x66, 0x61,
        0x63, 0x65, 0x62, 0x6f, 0x6f, 0x6b, 0x2e, 0x63,
        0x6f, 0x6d, 0x30, 0x81, 0x9f, 0x30, 0x0d, 0x06,
        0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01,
        0x01, 0x01, 0x05, 0x00, 0x03, 0x81, 0x8d, 0x00,
        0x30, 0x81, 0x89, 0x02, 0x81, 0x81, 0x00, 0xae,
        0x94, 0xb1, 0x71, 0xe2, 0xde, 0xcc, 0xc1, 0x69,
        0x3e, 0x05, 0x10, 0x63, 0x24, 0x01, 0x02, 0xe0,
        0x68, 0x9a, 0xe8, 0x3c, 0x39, 0xb6, 0xb3, 0xe7,
        0x4b, 0x97, 0xd4, 0x8d, 0x7b, 0x23, 0x68, 0x91,
        0x00, 0xb0, 0xb4, 0x96, 0xee, 0x62, 0xf0, 0xe6,
        0xd3, 0x56, 0xbc, 0xf4, 0xaa, 0x0f, 0x50, 0x64,
        0x34, 0x02, 0xf5, 0xd1, 0x76, 0x6a, 0xa9, 0x72,
        0x83, 0x5a, 0x75, 0x64, 0x72, 0x3f, 0x39, 0xbb,
        0xef, 0x52, 0x90, 0xde, 0xd9, 0xbc, 0xdb, 0xf9,
        0xd3, 0xd5, 0x5d, 0xfa, 0xd2, 0x3a, 0xa0, 0x3d,
        0xc6, 0x04, 0xc5, 0x4d, 0x29, 0xcf, 0x1d, 0x4b,
        0x3b, 0xdb, 0xd1, 0xa8, 0x09, 0xcf, 0xae, 0x47,
        0xb4, 0x4c, 0x7e, 0xae, 0x17, 0xc5, 0x10, 0x9b,
        0xee, 0x24, 0xa9, 0xcf, 0x4a, 0x8d, 0x91, 0x1b,
        0xb0, 0xfd, 0x04, 0x15, 0xae, 0x4c, 0x3f, 0x43,
        0x0a, 0xa1, 0x2a, 0x55, 0x7e, 0x2a, 0xe1, 0x02,
        0x03, 0x01, 0x00, 0x01, 0xa3, 0x82, 0x01, 0x1e,
        0x30, 0x82, 0x01, 0x1a, 0x30, 0x09, 0x06, 0x03,
        0x55, 0x1d, 0x13, 0x04, 0x02, 0x30, 0x00, 0x30,
        0x44, 0x06, 0x03, 0x55, 0x1d, 0x20, 0x04, 0x3d,
        0x30, 0x3b, 0x30, 0x39, 0x06, 0x0b, 0x60, 0x86,
        0x48, 0x01, 0x86, 0xf8, 0x45, 0x01, 0x07, 0x17,
        0x03, 0x30, 0x2a, 0x30, 0x28, 0x06, 0x08, 0x2b,
        0x06, 0x01, 0x05, 0x05, 0x07, 0x00, 0x01, 0x16,
        0x1c, 0x68, 0x74, 0x74, 0x70, 0x73, 0x3a, 0x2f,
        0x2f, 0x77, 0x77, 0x77, 0x2e, 0x76, 0x65, 0x72,
        0x69, 0x73, 0x69, 0x67, 0x6e, 0x2e, 0x63, 0x6f,
        0x6d, 0x2f, 0x72, 0x70, 0x61, 0x30, 0x3c, 0x06,
        0x03, 0x55, 0x1d, 0x1f, 0x04, 0x35, 0x30, 0x33,
        0x30, 0x31, 0xa0, 0x2f, 0xa0, 0x2d, 0x86, 0x2b,
        0x68, 0x74, 0x74, 0x70, 0x3a, 0x2f, 0x2f, 0x53,
        0x56, 0x52, 0x49, 0x6e, 0x74, 0x6c, 0x2d, 0x63,
        0x72, 0x6c, 0x2e, 0x76, 0x65, 0x72, 0x69, 0x73,
        0x69, 0x67, 0x6e, 0x2e, 0x63, 0x6f, 0x6d, 0x2f,
        0x53, 0x56, 0x52, 0x49, 0x6e, 0x74, 0x6c, 0x2e,
        0x63, 0x72, 0x6c, 0x30, 0x1d, 0x06, 0x03, 0x55,
        0x1d, 0x25, 0x04, 0x16, 0x30, 0x14, 0x06, 0x08,
        0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01,
        0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07,
        0x03, 0x02, 0x30, 0x0b, 0x06, 0x03, 0x55, 0x1d,
        0x0f, 0x04, 0x04, 0x03, 0x02, 0x05, 0xa0, 0x30,
        0x34, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05,
        0x07, 0x01, 0x01, 0x04, 0x28, 0x30, 0x26, 0x30,
        0x24, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05,
        0x07, 0x30, 0x01, 0x86, 0x18, 0x68, 0x74, 0x74,
        0x70, 0x3a, 0x2f, 0x2f, 0x6f, 0x63, 0x73, 0x70,
        0x2e, 0x76, 0x65, 0x72, 0x69, 0x73, 0x69, 0x67,
        0x6e, 0x2e, 0x63, 0x6f, 0x6d, 0x30, 0x27, 0x06,
        0x03, 0x55, 0x1d, 0x11, 0x04, 0x20, 0x30, 0x1e,
        0x82, 0x0e, 0x2a, 0x2e, 0x66, 0x61, 0x63, 0x65,
        0x62, 0x6f, 0x6f, 0x6b, 0x2e, 0x63, 0x6f, 0x6d,
        0x82, 0x0c, 0x66, 0x61, 0x63, 0x65, 0x62, 0x6f,
        0x6f, 0x6b, 0x2e, 0x63, 0x6f, 0x6d, 0x30, 0x0d,
        0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d,
        0x01, 0x01, 0x05, 0x05, 0x00, 0x03, 0x81, 0x81,
        0x00, 0x5b, 0x6c, 0x2b, 0x75, 0xf8, 0xed, 0x30,
        0xaa, 0x51, 0xaa, 0xd3, 0x6a, 0xba, 0x59, 0x5e,
        0x55, 0x51, 0x41, 0x95, 0x1f, 0x81, 0xa5, 0x3b,
        0x44, 0x79, 0x10, 0xac, 0x1f, 0x76, 0xff, 0x78,
        0xfc, 0x27, 0x81, 0x61, 0x6b, 0x58, 0xf3, 0x12,
        0x2a, 0xfc, 0x1c, 0x87, 0x01, 0x04, 0x25, 0xe9,
        0xed, 0x43, 0xdf, 0x1a, 0x7b, 0xa6, 0x49, 0x80,
        0x60, 0x67, 0xe2, 0x68, 0x8a, 0xf0, 0x3d, 0xb5,
        0x8c, 0x7d, 0xf4, 0xee, 0x03, 0x30, 0x9a, 0x6a,
        0xfc, 0x24, 0x7c, 0xcb, 0x13, 0x4d, 0xc3, 0x3e,
        0x54, 0xc6, 0xbc, 0x1d, 0x51, 0x33, 0xa5, 0x32,
        0xa7, 0x32, 0x73, 0xb1, 0xd7, 0x9c, 0xad, 0xc0,
        0x8e, 0x7e, 0x1a, 0x83, 0x11, 0x6d, 0x34, 0x52,
        0x33, 0x40, 0xb0, 0x30, 0x54, 0x27, 0xa2, 0x17,
        0x42, 0x82, 0x7c, 0x98, 0x91, 0x66, 0x98, 0xee,
        0x7e, 0xaf, 0x8c, 0x3b, 0xdd, 0x71, 0x70, 0x08,
        0x17, 0x00, 0x03, 0x87, 0x30, 0x82, 0x03, 0x83,
        0x30, 0x82, 0x02, 0xec, 0xa0, 0x03, 0x02, 0x01,
        0x02, 0x02, 0x10, 0x46, 0xfc, 0xeb, 0xba, 0xb4,
        0xd0, 0x2f, 0x0f, 0x92, 0x60, 0x98, 0x23, 0x3f,
        0x93, 0x07, 0x8f, 0x30, 0x0d, 0x06, 0x09, 0x2a,
        0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x05,
        0x05, 0x00, 0x30, 0x5f, 0x31, 0x0b, 0x30, 0x09,
        0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x55,
        0x53, 0x31, 0x17, 0x30, 0x15, 0x06, 0x03, 0x55,
        0x04, 0x0a, 0x13, 0x0e, 0x56, 0x65, 0x72, 0x69,
        0x53, 0x69, 0x67, 0x6e, 0x2c, 0x20, 0x49, 0x6e,
        0x63, 0x2e, 0x31, 0x37, 0x30, 0x35, 0x06, 0x03,
        0x55, 0x04, 0x0b, 0x13, 0x2e, 0x43, 0x6c, 0x61,
        0x73, 0x73, 0x20, 0x33, 0x20, 0x50, 0x75, 0x62,
        0x6c, 0x69, 0x63, 0x20, 0x50, 0x72, 0x69, 0x6d,
        0x61, 0x72, 0x79, 0x20, 0x43, 0x65, 0x72, 0x74,
        0x69, 0x66, 0x69, 0x63, 0x61, 0x74, 0x69, 0x6f,
        0x6e, 0x20, 0x41, 0x75, 0x64, 0x68, 0x6f, 0x72,
        0x69, 0x74, 0x79, 0x30, 0x1e, 0x17, 0x0d, 0x39,
        0x37, 0x30, 0x34, 0x31, 0x37, 0x30, 0x30, 0x30,
        0x30, 0x30, 0x30, 0x5a, 0x17, 0x0d, 0x31, 0x36,
        0x31, 0x30, 0x32, 0x34, 0x32, 0x33, 0x35, 0x39,
        0x35, 0x39, 0x5a, 0x30, 0x81, 0xba, 0x31, 0x1f,
        0x30, 0x1d, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x13,
        0x16, 0x56, 0x65, 0x72, 0x69, 0x53, 0x69, 0x67,
        0x6e, 0x20, 0x54, 0x72, 0x75, 0x73, 0x74, 0x20,
        0x4e, 0x65, 0x74, 0x77, 0x6f, 0x72, 0x6b, 0x31,
        0x17, 0x30, 0x15, 0x06, 0x03, 0x55, 0x04, 0x0b,
        0x13, 0x0e, 0x56, 0x65, 0x72, 0x69, 0x53, 0x69,
        0x67, 0x6e, 0x2c, 0x20, 0x49, 0x6e, 0x63, 0x2e,
        0x31, 0x33, 0x30, 0x31, 0x06, 0x03, 0x55, 0x04,
        0x0b, 0x13, 0x2a, 0x56, 0x65, 0x72, 0x69, 0x53,
        0x69, 0x67, 0x6e, 0x20, 0x49, 0x6e, 0x74, 0x65,
        0x72, 0x6e, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x61,
        0x6c, 0x20, 0x53, 0x65, 0x72, 0x76, 0x65, 0x72,
        0x20, 0x43, 0x41, 0x20, 0x2d, 0x20, 0x43, 0x6c,
        0x61, 0x73, 0x73, 0x20, 0x33, 0x31, 0x49, 0x30,
        0x47, 0x06, 0x03, 0x55, 0x04, 0x0b, 0x13, 0x40,
        0x77, 0x77, 0x77, 0x2e, 0x76, 0x65, 0x72, 0x69,
        0x73, 0x69,
        0x67, 0x6e, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x43,
        0x50, 0x53, 0x20, 0x49, 0x6e, 0x63, 0x6f, 0x72,
        0x70, 0x2e, 0x62, 0x79, 0x20, 0x52, 0x65, 0x66,
        0x2e, 0x20, 0x4c, 0x49, 0x41, 0x42, 0x49, 0x4c,
        0x49, 0x54, 0x59, 0x20, 0x4c, 0x54, 0x44, 0x2e,
        0x28, 0x63, 0x29, 0x39, 0x37, 0x20, 0x56, 0x65,
        0x72, 0x69, 0x53, 0x69, 0x67, 0x6e, 0x30, 0x81,
        0x9f, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48,
        0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00,
        0x03, 0x81, 0x8d, 0x00, 0x30, 0x81, 0x89, 0x02,
        0x81, 0x81, 0x00, 0xd8, 0x82, 0x80, 0xe8, 0xd6,
        0x19, 0x02, 0x7d, 0x1f, 0x85, 0x18, 0x39, 0x25,
        0xa2, 0x65, 0x2b, 0xe1, 0xbf, 0xd4, 0x05, 0xd3,
        0xbc, 0xe6, 0x36, 0x3b, 0xaa, 0xf0, 0x4c, 0x6c,
        0x5b, 0xb6, 0xe7, 0xaa, 0x3c, 0x73, 0x45, 0x55,
        0xb2, 0xf1, 0xbd, 0xea, 0x97, 0x42, 0xed, 0x9a,
        0x34, 0x0a, 0x15, 0xd4, 0xa9, 0x5c, 0xf5, 0x40,
        0x25, 0xdd, 0xd9, 0x07, 0xc1, 0x32, 0xb2, 0x75,
        0x6c, 0xc4, 0xca, 0xbb, 0xa3, 0xfe, 0x56, 0x27,
        0x71, 0x43, 0xaa, 0x63, 0xf5, 0x30, 0x3e, 0x93,
        0x28, 0xe5, 0xfa, 0xf1, 0x09, 0x3b, 0xf3, 0xb7,
        0x4d, 0x4e, 0x39, 0xf7, 0x5c, 0x49, 0x5a, 0xb8,
        0xc1, 0x1d, 0xd3, 0xb2, 0x8a, 0xfe, 0x70, 0x30,
        0x95, 0x42, 0xcb, 0xfe, 0x2b, 0x51, 0x8b, 0x5a,
        0x3c, 0x3a, 0xf9, 0x22, 0x4f, 0x90, 0xb2, 0x02,
        0xa7, 0x53, 0x9c, 0x4f, 0x34, 0xe7, 0xab, 0x04,
        0xb2, 0x7b, 0x6f, 0x02, 0x03, 0x01, 0x00, 0x01,
        0xa3, 0x81, 0xe3, 0x30, 0x81, 0xe0, 0x30, 0x0f,
        0x06, 0x03, 0x55, 0x1d, 0x13, 0x04, 0x08, 0x30,
        0x06, 0x01, 0x01, 0xff, 0x02, 0x01, 0x00, 0x30,
        0x44, 0x06, 0x03, 0x55, 0x1d, 0x20, 0x04, 0x3d,
        0x30, 0x3b, 0x30, 0x39, 0x06, 0x0b, 0x60, 0x86,
        0x48, 0x01, 0x86, 0xf8, 0x45, 0x01, 0x07, 0x01,
        0x01, 0x30, 0x2a, 0x30, 0x28, 0x06, 0x08, 0x2b,
        0x06, 0x01, 0x05, 0x05, 0x07, 0x02, 0x01, 0x16,
        0x1c, 0x68, 0x74, 0x74, 0x70, 0x73, 0x3a, 0x2f,
        0x2f, 0x77, 0x77, 0x77, 0x2e, 0x76, 0x65, 0x72,
        0x69, 0x73, 0x69, 0x67, 0x6e, 0x2e, 0x63, 0x6f,
        0x6d, 0x2f, 0x43, 0x50, 0x53, 0x30, 0x34, 0x06,
        0x03, 0x55, 0x1d, 0x25, 0x04, 0x2d, 0x30, 0x2b,
        0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07,
        0x03, 0x01, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05,
        0x05, 0x07, 0x03, 0x02, 0x06, 0x09, 0x60, 0x86,
        0x48, 0x01, 0x86, 0xf8, 0x42, 0x04, 0x01, 0x06,
        0x0a, 0x60, 0x86, 0x48, 0x01, 0x86, 0xf8, 0x45,
        0x01, 0x08, 0x01, 0x30, 0x0b, 0x06, 0x03, 0x55,
        0x1d, 0x0f, 0x04, 0x04, 0x03, 0x02, 0x01, 0x06,
        0x30, 0x11, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01,
        0x86, 0xf8, 0x42, 0x01, 0x01, 0x04, 0x04, 0x03,
        0x02, 0x01, 0x06, 0x30, 0x31, 0x06, 0x03, 0x55,
        0x1d, 0x1f, 0x04, 0x2a, 0x30, 0x28, 0x30, 0x26,
        0xa0, 0x24, 0xa0, 0x22, 0x86, 0x20, 0x68, 0x74,
        0x74, 0x70, 0x3a, 0x2f, 0x2f, 0x63, 0x72, 0x6c,
        0x2e, 0x76, 0x65, 0x72, 0x69, 0x73, 0x69, 0x67,
        0x6e, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x70, 0x63,
        0x61, 0x33, 0x2e, 0x63, 0x72, 0x6c, 0x30, 0x0d,
        0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d,
        0x01, 0x01, 0x05, 0x05, 0x00, 0x03, 0x81, 0x81,
        0x00, 0x40, 0x8e, 0x49, 0x97, 0x96, 0x8a, 0x73,
        0xdd, 0x8e, 0x4d, 0xef, 0x3e, 0x61, 0xb7, 0xca,
        0xa0, 0x62, 0xad, 0xf4, 0x0e, 0x0a, 0xbb, 0x75,
        0x3d, 0xe2, 0x6e, 0xd8, 0x2c, 0xc7, 0xbf, 0xf4,
        0xb9, 0x8c, 0x36, 0x9b, 0xca, 0xa2, 0xd0, 0x9c,
        0x72, 0x46, 0x39, 0xf6, 0xa6, 0x82, 0x03, 0x65,
        0x11, 0xc4, 0xbc, 0xbf, 0x2d, 0xa6, 0xf5, 0xd9,
        0x3b, 0x0a, 0xb5, 0x98, 0xfa, 0xb3, 0x78, 0xb9,
        0x1e, 0xf2, 0x2b, 0x4c, 0x62, 0xd5, 0xfd, 0xb2,
        0x7a, 0x1d, 0xdf, 0x33, 0xfd, 0x73, 0xf9, 0xa5,
        0xd8, 0x2d, 0x8c, 0x2a, 0xea, 0xd1, 0xfc, 0xb0,
        0x28, 0xb6, 0xe9, 0x49, 0x48, 0x13, 0x4b, 0x83,
        0x8a, 0x1b, 0x48, 0x7b, 0x24, 0xf7, 0x38, 0xde,
        0x6f, 0x41, 0x54, 0xb8, 0xab, 0x57, 0x6b, 0x06,
        0xdf, 0xc7, 0xa2, 0xd4, 0xa9, 0xf6, 0xf1, 0x36,
        0x62, 0x80, 0x88, 0xf2, 0x8b, 0x75, 0xd6, 0x80,
        0x75, 0x16, 0x03, 0x01, 0x00, 0x04, 0x0e, 0x00,
        0x00, 0x00
    };
    uint32_t server_hello_certificate_done_len = sizeof(server_hello_certificate_done);

    uint8_t client_key_exchange_cipher_enc_hs[] = {
        0x16, 0x03, 0x01, 0x00, 0x86, 0x10, 0x00, 0x00,
        0x80, 0x00, 0x80, 0x14, 0x2b, 0x2f, 0x9f, 0x02,
        0x1d, 0x4e, 0x0d, 0xa7, 0x41, 0x0f, 0x99, 0xc5,
        0xe9, 0x49, 0x22, 0x14, 0xa0, 0x42, 0x7b, 0xb4,
        0x6d, 0x4f, 0x82, 0x3c, 0x3a, 0x6e, 0xed, 0xd5,
        0x6e, 0x72, 0x71, 0xae, 0x00, 0x4a, 0x9a, 0xc9,
        0x0e, 0x2d, 0x08, 0xa2, 0xd3, 0x3a, 0xb0, 0xb2,
        0x1a, 0x56, 0x01, 0x7c, 0x9a, 0xfa, 0xfb, 0x1a,
        0xd7, 0x7e, 0x20, 0x68, 0x51, 0xd0, 0xfe, 0xd9,
        0xdc, 0xa7, 0x0b, 0xeb, 0x1a, 0xb6, 0xd3, 0xc7,
        0x17, 0x1f, 0xf3, 0x6e, 0x91, 0xdd, 0x06, 0x0d,
        0x48, 0xde, 0xcd, 0x0c, 0x36, 0x8c, 0x83, 0x29,
        0x9a, 0x40, 0x03, 0xcd, 0xf3, 0x1b, 0xdb, 0xd8,
        0x44, 0x6b, 0x75, 0xf3, 0x5a, 0x9f, 0x26, 0x1a,
        0xc4, 0x16, 0x35, 0x8f, 0xc1, 0x15, 0x19, 0xa9,
        0xdf, 0x07, 0xa9, 0xe5, 0x56, 0x45, 0x6d, 0xca,
        0x20, 0x3c, 0xcf, 0x8e, 0xbe, 0x44, 0x68, 0x73,
        0xc8, 0x0b, 0xc7, 0x14, 0x03, 0x01, 0x00, 0x01,
        0x01, 0x16, 0x03, 0x01, 0x00, 0x24, 0xf9, 0x7e,
        0x28, 0x77, 0xa9, 0x9a, 0x08, 0x0c, 0x2e, 0xa9,
        0x09, 0x15, 0x27, 0xcd, 0x93, 0x5f, 0xc0, 0x32,
        0x0a, 0x8d, 0x62, 0xd3, 0x54, 0x79, 0x6b, 0x51,
        0xd7, 0xba, 0x02, 0xd6, 0xdb, 0x66, 0xe8, 0x97,
        0x5d, 0x7a
    };
    uint32_t client_key_exchange_cipher_enc_hs_len = sizeof(client_key_exchange_cipher_enc_hs);

    TcpSession ssn;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));
    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;
    f.alproto = ALPROTO_TLS;

    StreamTcpInitConfig(TRUE);

    FLOWLOCK_WRLOCK(&f);
    int r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_TLS,
                                STREAM_TOSERVER, client_hello,
                                client_hello_len);
    FLOWLOCK_UNLOCK(&f);
    FAIL_IF(r != 0);

    SSLState *ssl_state = f.alstate;
    FAIL_IF_NULL(ssl_state);

    FAIL_IF(ssl_state->client_connp.bytes_processed != 0);
    FAIL_IF(ssl_state->client_connp.hs_bytes_processed != 0);

    FLOWLOCK_WRLOCK(&f);
    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_TLS, STREAM_TOCLIENT,
                            server_hello_certificate_done,
                            server_hello_certificate_done_len);
    FLOWLOCK_UNLOCK(&f);
    FAIL_IF(r != 0);

    FAIL_IF(ssl_state->client_connp.bytes_processed != 0);
    FAIL_IF(ssl_state->client_connp.hs_bytes_processed != 0);

    FLOWLOCK_WRLOCK(&f);
    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_TLS, STREAM_TOSERVER,
                            client_key_exchange_cipher_enc_hs,
                            client_key_exchange_cipher_enc_hs_len);
    FLOWLOCK_UNLOCK(&f);
    FAIL_IF(r != 0);

    /* The reason hs_bytes_processed is 2 is because, the record
     * immediately after the client key exchange is 2 bytes long,
     * and next time we see a new handshake, it is after we have
     * seen a change cipher spec.  Hence when we process the
     * handshake, we immediately break and don't parse the pdu from
     * where we left off, and leave the hs_bytes_processed var
     * isn't reset. */
    FAIL_IF(ssl_state->client_connp.bytes_processed != 0);
    FAIL_IF(ssl_state->client_connp.hs_bytes_processed != 2);

    AppLayerParserThreadCtxFree(alp_tctx);
    StreamTcpFreeConfig(TRUE);
    FLOW_DESTROY(&f);

    PASS;
}

static int SSLParserTest26(void)
{
    Flow f;
    uint8_t client_hello[] = {
        0x16, 0x03, 0x01, 0x02, 0x0e, 0x01, 0x00, 0x02,
        0x0a, 0x03, 0x03, 0x58, 0x36, 0x15, 0x03, 0x8e,
        0x07, 0xf9, 0xad, 0x2a, 0xb7, 0x56, 0xbf, 0xe2,
        0xa2, 0xf8, 0x21, 0xe0, 0xbb, 0x69, 0xc2, 0xd6,
        0x76, 0xe6, 0x77, 0xfe, 0x09, 0xff, 0x8e, 0xac,
        0x80, 0xb5, 0x27, 0x20, 0xb7, 0xbb, 0x90, 0x35,
        0x7a, 0xdd, 0xd9, 0x67, 0xdf, 0x79, 0xd6, 0x16,
        0x90, 0xf6, 0xd7, 0x5c, 0xd3, 0x07, 0x19, 0x20,
        0x01, 0x39, 0x76, 0x25, 0x12, 0x32, 0x71, 0xa1,
        0x84, 0x8d, 0x2d, 0xea, 0x00, 0x88, 0xc0, 0x30,
        0xc0, 0x2c, 0xc0, 0x28, 0xc0, 0x24, 0xc0, 0x14,
        0xc0, 0x0a, 0x00, 0xa3, 0x00, 0x9f, 0x00, 0x6b,
        0x00, 0x6a, 0x00, 0x39, 0x00, 0x38, 0x00, 0x88,
        0x00, 0x87, 0xc0, 0x32, 0xc0, 0x2e, 0xc0, 0x2a,
        0xc0, 0x26, 0xc0, 0x0f, 0xc0, 0x05, 0x00, 0x9d,
        0x00, 0x3d, 0x00, 0x35, 0x00, 0x84, 0xc0, 0x12,
        0xc0, 0x08, 0x00, 0x16, 0x00, 0x13, 0xc0, 0x0d,
        0xc0, 0x03, 0x00, 0x0a, 0xc0, 0x2f, 0xc0, 0x2b,
        0xc0, 0x27, 0xc0, 0x23, 0xc0, 0x13, 0xc0, 0x09,
        0x00, 0xa2, 0x00, 0x9e, 0x00, 0x67, 0x00, 0x40,
        0x00, 0x33, 0x00, 0x32, 0x00, 0x9a, 0x00, 0x99,
        0x00, 0x45, 0x00, 0x44, 0xc0, 0x31, 0xc0, 0x2d,
        0xc0, 0x29, 0xc0, 0x25, 0xc0, 0x0e, 0xc0, 0x04,
        0x00, 0x9c, 0x00, 0x3c, 0x00, 0x2f, 0x00, 0x96,
        0x00, 0x41, 0xc0, 0x11, 0xc0, 0x07, 0xc0, 0x0c,
        0xc0, 0x02, 0x00, 0x05, 0x00, 0x04, 0x00, 0x15,
        0x00, 0x12, 0x00, 0x09, 0x00, 0xff, 0x01, 0x00,
        0x01, 0x39, 0x00, 0x00, 0x00, 0x14, 0x00, 0x12,
        0x00, 0x00, 0x0f, 0x77, 0x77, 0x77, 0x2e, 0x79,
        0x6f, 0x75, 0x74, 0x75, 0x62, 0x65, 0x2e, 0x63,
        0x6f, 0x6d, 0x00, 0x0b, 0x00, 0x04, 0x03, 0x00,
        0x01, 0x02, 0x00, 0x0a, 0x00, 0x34, 0x00, 0x32,
        0x00, 0x0e, 0x00, 0x0d, 0x00, 0x19, 0x00, 0x0b,
        0x00, 0x0c, 0x00, 0x18, 0x00, 0x09, 0x00, 0x0a,
        0x00, 0x16, 0x00, 0x17, 0x00, 0x08, 0x00, 0x06,
        0x00, 0x07, 0x00, 0x14, 0x00, 0x15, 0x00, 0x04,
        0x00, 0x05, 0x00, 0x12, 0x00, 0x13, 0x00, 0x01,
        0x00, 0x02, 0x00, 0x03, 0x00, 0x0f, 0x00, 0x10,
        0x00, 0x11, 0x00, 0x23, 0x00, 0xb4, 0x05, 0x6c,
        0xfa, 0x27, 0x6f, 0x12, 0x2f, 0x2a, 0xe5, 0x56,
        0xcb, 0x42, 0x62, 0x44, 0xf2, 0xd7, 0xd1, 0x05,
        0x87, 0xd4, 0x52, 0x02, 0x10, 0x85, 0xa4, 0xa6,
        0x82, 0x6f, 0x6d, 0x7b, 0xaf, 0x11, 0xbe, 0x21,
        0x7e, 0x7c, 0x36, 0x03, 0x20, 0x29, 0xd8, 0xf9,
        0xe5, 0x2b, 0xe2, 0x26, 0xb2, 0x27, 0xc7, 0xb9,
        0xda, 0x59, 0xd7, 0xdc, 0xfd, 0x74, 0x74, 0x76,
        0xd0, 0x5e, 0xe4, 0xfe, 0x9d, 0xb7, 0x1b, 0x13,
        0x81, 0xce, 0x63, 0x75, 0x2b, 0x2f, 0x98, 0x3a,
        0x84, 0x46, 0xd3, 0x0c, 0xb3, 0x01, 0xdb, 0x62,
        0x51, 0x97, 0x92, 0x1c, 0xa5, 0x94, 0x60, 0xef,
        0xa6, 0xd8, 0xb2, 0x2f, 0x02, 0x42, 0x5c, 0xac,
        0xb4, 0xd9, 0x10, 0x2f, 0x7e, 0x89, 0xab, 0xa5,
        0xd7, 0x56, 0x6d, 0x03, 0xd2, 0x5f, 0x20, 0x2c,
        0xb6, 0x99, 0x2b, 0x66, 0xbd, 0xd4, 0xde, 0x53,
        0x76, 0x5c, 0x78, 0xf0, 0xe9, 0x6d, 0xa5, 0xc3,
        0x1a, 0x9e, 0x61, 0xb2, 0x45, 0xb0, 0xb3, 0x61,
        0xee, 0xa1, 0x07, 0xab, 0x2f, 0x84, 0xea, 0x43,
        0x76, 0x4b, 0x3d, 0xb0, 0xbe, 0xa4, 0xb4, 0x21,
        0xe1, 0xd3, 0xfd, 0x91, 0xe2, 0xe7, 0xf3, 0x38,
        0x9c, 0x56, 0x5f, 0xa1, 0xde, 0xa8, 0x2f, 0x0a,
        0x49, 0x6d, 0x44, 0x8e, 0xb7, 0xef, 0x4a, 0x6f,
        0x79, 0xb2, 0x00, 0x0d, 0x00, 0x20, 0x00, 0x1e,
        0x06, 0x01, 0x06, 0x02, 0x06, 0x03, 0x05, 0x01,
        0x05, 0x02, 0x05, 0x03, 0x04, 0x01, 0x04, 0x02,
        0x04, 0x03, 0x03, 0x01, 0x03, 0x02, 0x03, 0x03,
        0x02, 0x01, 0x02, 0x02, 0x02, 0x03, 0x00, 0x0f,
        0x00, 0x01, 0x01
    };
    uint32_t client_hello_len = sizeof(client_hello);

    uint8_t server_hello_change_cipher_spec[] = {
        0x16, 0x03, 0x03, 0x00, 0x57, 0x02, 0x00, 0x00,
        0x53, 0x03, 0x03, 0x58, 0x36, 0x15, 0x03, 0x9f,
        0x3b, 0xf3, 0x11, 0x96, 0x2b, 0xc3, 0xae, 0x91,
        0x8c, 0x5f, 0x8b, 0x3f, 0x90, 0xbd, 0xa9, 0x26,
        0x26, 0xb2, 0xfd, 0x12, 0xc5, 0xc5, 0x7b, 0xe4,
        0xd1, 0x3e, 0x81, 0x20, 0xb7, 0xbb, 0x90, 0x35,
        0x7a, 0xdd, 0xd9, 0x67, 0xdf, 0x79, 0xd6, 0x16,
        0x90, 0xf6, 0xd7, 0x5c, 0xd3, 0x07, 0x19, 0x20,
        0x01, 0x39, 0x76, 0x25, 0x12, 0x32, 0x71, 0xa1,
        0x84, 0x8d, 0x2d, 0xea, 0xc0, 0x2b, 0x00, 0x00,
        0x0b, 0xff, 0x01, 0x00, 0x01, 0x00, 0x00, 0x0b,
        0x00, 0x02, 0x01, 0x00, 0x14, 0x03, 0x03, 0x00,
        0x01, 0x01, 0x16, 0x03, 0x03, 0x00, 0x28, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06,
        0x66, 0xfe, 0x07, 0x08, 0x33, 0x4d, 0xc2, 0x83,
        0x8e, 0x05, 0x8b, 0xf8, 0xd1, 0xb1, 0xa7, 0x16,
        0x4b, 0x42, 0x5c, 0x3a, 0xa4, 0x31, 0x0f, 0xba,
        0x84, 0x06, 0xcb, 0x9d, 0xc6, 0xc4, 0x66
    };
    uint32_t server_hello_change_cipher_spec_len = sizeof(server_hello_change_cipher_spec);

    TcpSession ssn;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));
    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;
    f.alproto = ALPROTO_TLS;

    StreamTcpInitConfig(TRUE);

    FLOWLOCK_WRLOCK(&f);
    int r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_TLS,
                                STREAM_TOSERVER, client_hello,
                                client_hello_len);
    FLOWLOCK_UNLOCK(&f);
    FAIL_IF(r != 0);

    SSLState *ssl_state = f.alstate;
    FAIL_IF_NULL(ssl_state);

    FAIL_IF((ssl_state->flags & SSL_AL_FLAG_STATE_CLIENT_HELLO) == 0);
    FAIL_IF_NULL(ssl_state->client_connp.session_id);

    FLOWLOCK_WRLOCK(&f);
    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_TLS, STREAM_TOCLIENT,
                            server_hello_change_cipher_spec,
                            server_hello_change_cipher_spec_len);
    FLOWLOCK_UNLOCK(&f);
    FAIL_IF(r != 0);

    FAIL_IF((ssl_state->flags & SSL_AL_FLAG_SERVER_CHANGE_CIPHER_SPEC) == 0);
    FAIL_IF((ssl_state->flags & SSL_AL_FLAG_SESSION_RESUMED) == 0);

    AppLayerParserThreadCtxFree(alp_tctx);
    StreamTcpFreeConfig(TRUE);
    FLOW_DESTROY(&f);

    PASS;
}

#endif /* UNITTESTS */

void SSLParserRegisterTests(void)
{
#ifdef UNITTESTS
    UtRegisterTest("SSLParserTest01", SSLParserTest01);
    UtRegisterTest("SSLParserTest02", SSLParserTest02);
    UtRegisterTest("SSLParserTest03", SSLParserTest03);
    UtRegisterTest("SSLParserTest04", SSLParserTest04);
    /* Updated by Anoop Saldanha.  Faulty tests.  Disable it for now */
    //UtRegisterTest("SSLParserTest05", SSLParserTest05, 1);
    //UtRegisterTest("SSLParserTest06", SSLParserTest06, 1);
    UtRegisterTest("SSLParserTest07", SSLParserTest07);
    //UtRegisterTest("SSLParserTest08", SSLParserTest08, 1);
    UtRegisterTest("SSLParserTest09", SSLParserTest09);
    UtRegisterTest("SSLParserTest10", SSLParserTest10);
    UtRegisterTest("SSLParserTest11", SSLParserTest11);
    UtRegisterTest("SSLParserTest12", SSLParserTest12);
    UtRegisterTest("SSLParserTest13", SSLParserTest13);

    UtRegisterTest("SSLParserTest14", SSLParserTest14);
    UtRegisterTest("SSLParserTest15", SSLParserTest15);
    UtRegisterTest("SSLParserTest16", SSLParserTest16);
    UtRegisterTest("SSLParserTest17", SSLParserTest17);
    UtRegisterTest("SSLParserTest18", SSLParserTest18);
    UtRegisterTest("SSLParserTest19", SSLParserTest19);
    UtRegisterTest("SSLParserTest20", SSLParserTest20);
    UtRegisterTest("SSLParserTest21", SSLParserTest21);
    UtRegisterTest("SSLParserTest22", SSLParserTest22);
    UtRegisterTest("SSLParserTest23", SSLParserTest23);
    UtRegisterTest("SSLParserTest24", SSLParserTest24);
    UtRegisterTest("SSLParserTest25", SSLParserTest25);
    UtRegisterTest("SSLParserTest26", SSLParserTest26);

    UtRegisterTest("SSLParserMultimsgTest01", SSLParserMultimsgTest01);
    UtRegisterTest("SSLParserMultimsgTest02", SSLParserMultimsgTest02);
#endif /* UNITTESTS */

    return;
}
