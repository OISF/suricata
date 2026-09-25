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
 * \author Anoop Saldanha <anoopsaldanha@gmail.com>
 * \author Pierre Chifflier <pierre.chifflier@ssi.gouv.fr>
 * \author Mats Klepsland <mats.klepsland@gmail.com>
 *
 */

#include "suricata-common.h"
#include "decode.h"

#include "app-layer.h"
#include "app-layer-detect-proto.h"
#include "app-layer-protos.h"
#include "app-layer-parser.h"
#include "app-layer-frames.h"
#include "app-layer-events.h"
#include "app-layer-ssl.h"

#include "conf.h"

#include "feature.h"

#include "util-debug.h"
#include "util-ja3.h"
#include "util-enum.h"
#include "util-validate.h"

static SCEnumCharMap tls_state_client_table[] = {
    {
            "client_started",
            TLS_STATE_CLIENT_STARTED,
    },
    {
            "client_hello",
            TLS_STATE_CLIENT_HELLO,
    },
    {
            "client_cert",
            TLS_STATE_CLIENT_CERT,
    },
    {
            "client_data",
            TLS_STATE_CLIENT_DATA,
    },
    {
            "client_finished",
            TLS_STATE_CLIENT_FINISHED,
    },
    { NULL, -1 },
};

static SCEnumCharMap tls_state_server_table[] = {
    {
            "server_started",
            TLS_STATE_SERVER_STARTED,
    },
    {
            "server_hello",
            TLS_STATE_SERVER_HELLO,
    },
    {
            "server_cert",
            TLS_STATE_SERVER_CERT,
    },
    {
            "server_data",
            TLS_STATE_SERVER_DATA,
    },
    {
            "server_finished",
            TLS_STATE_SERVER_FINISHED,
    },
    { NULL, -1 },
};

SCEnumCharMap tls_frame_table[] = {
    {
            "pdu",
            TLS_FRAME_PDU,
    },
    {
            "hdr",
            TLS_FRAME_HDR,
    },
    {
            "data",
            TLS_FRAME_DATA,
    },
    {
            "alert",
            TLS_FRAME_ALERT_DATA,
    },
    {
            "heartbeat",
            TLS_FRAME_HB_DATA,
    },
    {
            "ssl2.hdr",
            TLS_FRAME_SSLV2_HDR,
    },
    {
            "ssl2.pdu",
            TLS_FRAME_SSLV2_PDU,
    },
    { NULL, -1 },
};

SCEnumCharMap tls_decoder_event_table[] = {
    /* TLS protocol messages */
    { "INVALID_SSLV2_HEADER", TLS_DECODER_EVENT_INVALID_SSLV2_HEADER },
    { "INVALID_TLS_HEADER", TLS_DECODER_EVENT_INVALID_TLS_HEADER },
    { "INVALID_RECORD_VERSION", TLS_DECODER_EVENT_INVALID_RECORD_VERSION },
    { "INVALID_RECORD_TYPE", TLS_DECODER_EVENT_INVALID_RECORD_TYPE },
    { "INVALID_RECORD_LENGTH", TLS_DECODER_EVENT_INVALID_RECORD_LENGTH },
    { "INVALID_HANDSHAKE_MESSAGE", TLS_DECODER_EVENT_INVALID_HANDSHAKE_MESSAGE },
    { "HEARTBEAT_MESSAGE", TLS_DECODER_EVENT_HEARTBEAT },
    { "INVALID_HEARTBEAT_MESSAGE", TLS_DECODER_EVENT_INVALID_HEARTBEAT },
    { "OVERFLOW_HEARTBEAT_MESSAGE", TLS_DECODER_EVENT_OVERFLOW_HEARTBEAT },
    { "DATALEAK_HEARTBEAT_MISMATCH", TLS_DECODER_EVENT_DATALEAK_HEARTBEAT_MISMATCH },
    { "HANDSHAKE_INVALID_LENGTH", TLS_DECODER_EVENT_HANDSHAKE_INVALID_LENGTH },
    { "MULTIPLE_SNI_EXTENSIONS", TLS_DECODER_EVENT_MULTIPLE_SNI_EXTENSIONS },
    { "INVALID_SNI_TYPE", TLS_DECODER_EVENT_INVALID_SNI_TYPE },
    { "INVALID_SNI_LENGTH", TLS_DECODER_EVENT_INVALID_SNI_LENGTH },
    { "TOO_MANY_RECORDS_IN_PACKET", TLS_DECODER_EVENT_TOO_MANY_RECORDS_IN_PACKET },
    { "INVALID_ALERT_MESSAGE", TLS_DECODER_EVENT_INVALID_ALERT },
    /* certificate decoding messages */
    { "INVALID_CERTIFICATE", TLS_DECODER_EVENT_INVALID_CERTIFICATE },
    { "CERTIFICATE_INVALID_LENGTH", TLS_DECODER_EVENT_CERTIFICATE_INVALID_LENGTH },
    { "CERTIFICATE_INVALID_VERSION", TLS_DECODER_EVENT_CERTIFICATE_INVALID_VERSION },
    { "CERTIFICATE_INVALID_SERIAL", TLS_DECODER_EVENT_CERTIFICATE_INVALID_SERIAL },
    { "CERTIFICATE_INVALID_ALGORITHMIDENTIFIER",
            TLS_DECODER_EVENT_CERTIFICATE_INVALID_ALGORITHMIDENTIFIER },
    { "CERTIFICATE_INVALID_X509NAME", TLS_DECODER_EVENT_CERTIFICATE_INVALID_X509NAME },
    { "CERTIFICATE_INVALID_DATE", TLS_DECODER_EVENT_CERTIFICATE_INVALID_DATE },
    { "CERTIFICATE_INVALID_EXTENSIONS", TLS_DECODER_EVENT_CERTIFICATE_INVALID_EXTENSIONS },
    { "CERTIFICATE_INVALID_DER", TLS_DECODER_EVENT_CERTIFICATE_INVALID_DER },
    { "CERTIFICATE_INVALID_SUBJECT", TLS_DECODER_EVENT_CERTIFICATE_INVALID_SUBJECT },
    { "CERTIFICATE_INVALID_ISSUER", TLS_DECODER_EVENT_CERTIFICATE_INVALID_ISSUER },
    { "CERTIFICATE_INVALID_VALIDITY", TLS_DECODER_EVENT_CERTIFICATE_INVALID_VALIDITY },
    { "ERROR_MESSAGE_ENCOUNTERED", TLS_DECODER_EVENT_ERROR_MSG_ENCOUNTERED },
    { "TOO_MANY_SUBJECT_ALTERNATIVE_NAMES", TLS_DECODER_EVENT_TOO_MANY_SUBJECT_ALTERNATIVE_NAMES },
    /* used as a generic error event */
    { "INVALID_SSL_RECORD", TLS_DECODER_EVENT_INVALID_SSL_RECORD },
    { NULL, -1 },
};

enum {
    /* X.509 error codes, returned by decoder
     * THESE CONSTANTS MUST MATCH rust/src/x509/mod.rs ! */
    ERR_INVALID_CERTIFICATE=1,
    ERR_INVALID_LENGTH,
    ERR_INVALID_VERSION,
    ERR_INVALID_SERIAL,
    ERR_INVALID_ALGORITHMIDENTIFIER,
    ERR_INVALID_X509NAME,
    ERR_INVALID_DATE,
    ERR_INVALID_EXTENSIONS,
    ERR_INVALID_DER,

    /* error getting data */
    ERR_EXTRACT_SUBJECT,
    ERR_EXTRACT_ISSUER,
    ERR_EXTRACT_VALIDITY,
};

/* JA3 and JA4 fingerprints are disabled by default */
#define SSL_CONFIG_DEFAULT_JA3 0
#ifdef HAVE_JA4
#define SSL_CONFIG_DEFAULT_JA4 0
#endif

enum SslConfigEncryptHandling {
    SSL_CNF_ENC_HANDLE_TRACK_ONLY = 0, /**< disable raw content, continue tracking */
    SSL_CNF_ENC_HANDLE_BYPASS = 1,     /**< skip processing of flow, bypass if possible */
    SSL_CNF_ENC_HANDLE_FULL = 2,       /**< handle fully like any other proto */
};

typedef struct SslConfig_ {
    enum SslConfigEncryptHandling encrypt_mode;
    /** dynamic setting for ja3 and ja4: can be enabled on demand if not
     *  explicitly disabled. */
    SC_ATOMIC_DECLARE(int, enable_ja3);
    bool disable_ja3; /**< ja3 explicitly disabled. Don't enable on demand. */
    SC_ATOMIC_DECLARE(int, enable_ja4);
    bool disable_ja4; /**< ja4 explicitly disabled. Don't enable on demand. */
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

#define SSLV3_RECORD_HDR_LEN 5
/** max length according to RFC 5246 6.2.2 is 2^14 + 1024 */
#define SSLV3_RECORD_MAX_LEN ((1 << 14) + 1024)

#define SSLV3_CLIENT_HELLO_VERSION_LEN  2
#define SSLV3_CLIENT_HELLO_RANDOM_LEN  32

/* TLS heartbeat protocol types */
#define TLS_HB_REQUEST                  1
#define TLS_HB_RESPONSE                 2

#define SSL_RECORD_MINIMUM_LENGTH       6

#define SHA1_STRING_LENGTH             60

#define HAS_SPACE(n) ((uint64_t)(input - initial_input) + (uint64_t)(n) <= (uint64_t)(input_len))

struct SSLDecoderResult {
    int retval;      // nr bytes consumed from input, or < 0 on error
    uint32_t needed; // more bytes needed
};
#define SSL_DECODER_ERROR(e)                                                                       \
    (struct SSLDecoderResult)                                                                      \
    {                                                                                              \
        (e), 0                                                                                     \
    }
#define SSL_DECODER_OK(c)                                                                          \
    (struct SSLDecoderResult)                                                                      \
    {                                                                                              \
        (uint32_t)(c), 0                                                                           \
    }
#define SSL_DECODER_INCOMPLETE(c, n)                                                               \
    (struct SSLDecoderResult)                                                                      \
    {                                                                                              \
        (uint32_t)(c), (n)                                                                         \
    }

static inline int SafeMemcpy(void *dst, size_t dst_offset, size_t dst_size,
        const void *src, size_t src_offset, size_t src_size, size_t src_tocopy) WARN_UNUSED;

static inline int SafeMemcpy(void *dst, size_t dst_offset, size_t dst_size,
        const void *src, size_t src_offset, size_t src_size, size_t src_tocopy)
{
    DEBUG_VALIDATE_BUG_ON(dst_offset >= dst_size);
    DEBUG_VALIDATE_BUG_ON(src_offset >= src_size);
    DEBUG_VALIDATE_BUG_ON(src_tocopy > (src_size - src_offset));
    DEBUG_VALIDATE_BUG_ON(src_tocopy > (dst_size - dst_offset));

    if (dst_offset < dst_size && src_offset < src_size &&
        src_tocopy <= (src_size - src_offset) &&
        src_tocopy <= (dst_size - dst_offset)) {
        memcpy(dst + dst_offset, src + src_offset, src_tocopy);
        return 0;
    }
    return -1;
}

#ifdef DEBUG_VALIDATION
#define ValidateRecordState(connp)                                              \
    do {                                                                        \
        DEBUG_VALIDATE_BUG_ON(((connp)->record_length + SSLV3_RECORD_HDR_LEN) < \
                (connp)->bytes_processed);                                      \
    } while(0);
#else
#define ValidateRecordState(...)
#endif

#define SSLParserHSReset(connp)                                                                    \
    do {                                                                                           \
        (connp)->handshake_type = 0;                                                               \
        (connp)->message_length = 0;                                                               \
    } while (0)

#define SSLParserReset(state)                       \
    do {                                            \
        SCLogDebug("resetting state");              \
        (state)->curr_connp->bytes_processed = 0;   \
        SSLParserHSReset((state)->curr_connp);      \
    } while(0)

#define SSLSetEvent(ssl_state, event)                                                              \
    do {                                                                                           \
        SCLogDebug("setting event %u", (event));                                                   \
        if ((ssl_state) == NULL) {                                                                 \
            SCLogDebug("could not set decoder event %u", event);                                   \
        } else {                                                                                   \
            SCAppLayerDecoderEventsSetEventRaw(&(ssl_state)->tx_data.events, (event));             \
            (ssl_state)->events++;                                                                 \
        }                                                                                          \
    } while (0)

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

static void UpdateClientState(SSLState *ssl_state, enum TlsStateClient s)
{
    /* monotonic: a late app-data write must not move the state back */
    if (s > ssl_state->client_state) {
#ifdef DEBUG
        enum TlsStateClient old = ssl_state->client_state;
#endif
        ssl_state->client_state = s;
#ifdef DEBUG
        SCLogDebug("toserver: state updated to %u from %u", s, old);
#endif
    }
}

static void UpdateServerState(SSLState *ssl_state, enum TlsStateServer s)
{
    /* monotonic: a late app-data write must not move the state back */
    if (s > ssl_state->server_state) {
#ifdef DEBUG
        enum TlsStateServer old = ssl_state->server_state;
#endif
        ssl_state->server_state = s;
#ifdef DEBUG
        SCLogDebug("toclient: state updated to %u from %u", s, old);
#endif
    }
}

static int SSLGetAlstateProgress(void *tx, uint8_t direction)
{
    SSLState *ssl_state = (SSLState *)tx;
    if (direction & STREAM_TOCLIENT) {
        return ssl_state->server_state;
    } else {
        return ssl_state->client_state;
    }
}

static AppLayerTxData *SSLGetTxData(void *vtx)
{
    SSLState *ssl_state = (SSLState *)vtx;
    return &ssl_state->tx_data;
}

static AppLayerStateData *SSLGetStateData(void *vstate)
{
    SSLState *ssl_state = (SSLState *)vstate;
    return &ssl_state->state_data;
}

static void TlsDecodeHSCertificateErrSetEvent(SSLState *ssl_state, uint32_t err)
{
    switch(err) {
        case ERR_EXTRACT_VALIDITY:
            SSLSetEvent(ssl_state, TLS_DECODER_EVENT_CERTIFICATE_INVALID_VALIDITY);
            break;
        case ERR_EXTRACT_ISSUER:
            SSLSetEvent(ssl_state, TLS_DECODER_EVENT_CERTIFICATE_INVALID_ISSUER);
            break;
        case ERR_EXTRACT_SUBJECT:
            SSLSetEvent(ssl_state, TLS_DECODER_EVENT_CERTIFICATE_INVALID_SUBJECT);
            break;
        case ERR_INVALID_DER:
            SSLSetEvent(ssl_state, TLS_DECODER_EVENT_CERTIFICATE_INVALID_DER);
            break;
        case ERR_INVALID_EXTENSIONS:
            SSLSetEvent(ssl_state, TLS_DECODER_EVENT_CERTIFICATE_INVALID_EXTENSIONS);
            break;
        case ERR_INVALID_DATE:
            SSLSetEvent(ssl_state, TLS_DECODER_EVENT_CERTIFICATE_INVALID_DATE);
            break;
        case ERR_INVALID_X509NAME:
            SSLSetEvent(ssl_state, TLS_DECODER_EVENT_CERTIFICATE_INVALID_X509NAME);
            break;
        case ERR_INVALID_ALGORITHMIDENTIFIER:
            SSLSetEvent(ssl_state, TLS_DECODER_EVENT_CERTIFICATE_INVALID_ALGORITHMIDENTIFIER);
            break;
        case ERR_INVALID_SERIAL:
            SSLSetEvent(ssl_state, TLS_DECODER_EVENT_CERTIFICATE_INVALID_SERIAL);
            break;
        case ERR_INVALID_VERSION:
            SSLSetEvent(ssl_state, TLS_DECODER_EVENT_CERTIFICATE_INVALID_VERSION);
            break;
        case ERR_INVALID_LENGTH:
            SSLSetEvent(ssl_state, TLS_DECODER_EVENT_CERTIFICATE_INVALID_LENGTH);
            break;
        case ERR_INVALID_CERTIFICATE:
        default:
            SSLSetEvent(ssl_state, TLS_DECODER_EVENT_INVALID_CERTIFICATE);
            break;
    }
}

static inline int TlsDecodeHSCertificateFingerprint(
        SSLStateConnp *connp, const uint8_t *input, uint32_t cert_len)
{
    if (unlikely(connp->cert0_fingerprint != NULL))
        return 0;

    connp->cert0_fingerprint = SCCalloc(1, SHA1_STRING_LENGTH);
    if (connp->cert0_fingerprint == NULL)
        return -1;

    uint8_t hash[SC_SHA1_LEN];
    if (SCSha1HashBuffer(input, cert_len, hash, sizeof(hash)) == 1) {
        SCToHex_sep(
                (uint8_t *)connp->cert0_fingerprint, SHA1_STRING_LENGTH, ':', hash, SC_SHA1_LEN);
    }
    return 0;
}

static inline int TlsDecodeHSCertificateAddCertToChain(
        SSLStateConnp *connp, const uint8_t *input, uint32_t cert_len)
{
    SSLCertsChain *cert = SCCalloc(1, sizeof(SSLCertsChain));
    if (cert == NULL)
        return -1;

    cert->cert_data = (uint8_t *)input;
    cert->cert_len = cert_len;
    TAILQ_INSERT_TAIL(&connp->certs, cert, next);

    return 0;
}

static int TlsDecodeHSCertificate(SSLState *ssl_state, SSLStateConnp *connp,
        const uint8_t *const initial_input, const uint32_t input_len, const int certn,
        bool *extract_event_sent)
{
    const uint8_t *input = (uint8_t *)initial_input;
    uint32_t err_code = 0;
    X509 *x509 = NULL;
    int rc = 0;

    /* stashed cert0 extraction: published to connp only when the whole
     * certificate decodes (see the cert0 fill below) */
    uint8_t *st_subject = NULL, *st_issuer = NULL, *st_serial = NULL;
    SSLSubjectAltName *st_sans = NULL;
    uint32_t st_subject_len = 0, st_issuer_len = 0, st_serial_len = 0;
    uint16_t st_sans_num = 0;
    int64_t st_not_before = 0, st_not_after = 0;

    if (!(HAS_SPACE(3)))
        goto invalid_cert;

    uint32_t cert_len = *input << 16 | *(input + 1) << 8 | *(input + 2);
    input += 3;

    if (!(HAS_SPACE(cert_len)))
        goto invalid_cert;

    /* only store fields from the first certificate in the chain */
    if (certn == 0 && connp->cert0_subject == NULL && connp->cert0_issuerdn == NULL &&
            connp->cert0_serial == NULL) {
        x509 = SCX509Decode(input, cert_len, &err_code);
        if (x509 == NULL) {
            /* an undecodable certificate: report it once and let the
             * caller skip it - the rest of the chain must still be
             * decoded */
            TlsDecodeHSCertificateErrSetEvent(ssl_state, err_code);
            goto fail;
        }

        /* extract into the stashes and publish to connp->cert0_* only
         * when the whole certificate yields every field: a partial fill
         * would otherwise block the next certificate from completing the
         * fields */
        SCX509GetSubject(x509, &st_subject, &st_subject_len);
        if (st_subject == NULL) {
            err_code = ERR_EXTRACT_SUBJECT;
            goto error;
        }

        SCX509GetIssuer(x509, &st_issuer, &st_issuer_len);
        if (st_issuer == NULL) {
            err_code = ERR_EXTRACT_ISSUER;
            goto error;
        }

        st_sans_num = SCX509GetSubjectAltNameLen(x509);
        if (st_sans_num == TLS_MAX_SAN && !*extract_event_sent) {
            SSLSetEvent(ssl_state, TLS_DECODER_EVENT_TOO_MANY_SUBJECT_ALTERNATIVE_NAMES);
            *extract_event_sent = true;
        }
        if (st_sans_num > 0) {
            st_sans = SCCalloc(st_sans_num, sizeof(SSLSubjectAltName));
            if (st_sans == NULL) {
                st_sans_num = 0;
                goto error;
            }
            for (uint16_t i = 0; i < st_sans_num; i++) {
                SCX509GetSubjectAltNameAt(x509, i, &st_sans[i].san, &st_sans[i].san_len);
            }
        }

        SCX509GetSerial(x509, &st_serial, &st_serial_len);
        if (st_serial == NULL) {
            err_code = ERR_INVALID_SERIAL;
            goto error;
        }

        rc = SCX509GetValidity(x509, &st_not_before, &st_not_after);
        if (rc != 0) {
            err_code = ERR_EXTRACT_VALIDITY;
            goto error;
        }

        rc = TlsDecodeHSCertificateFingerprint(connp, input, cert_len);
        if (rc != 0) {
            SCLogDebug("TlsDecodeHSCertificateFingerprint failed with %d", rc);
            goto error;
        }

        /* the certificate yielded every field: publish it */
        connp->cert0_subject = st_subject;
        connp->cert0_subject_len = st_subject_len;
        connp->cert0_issuerdn = st_issuer;
        connp->cert0_issuerdn_len = st_issuer_len;
        connp->cert0_sans = st_sans;
        connp->cert0_sans_num = st_sans_num;
        connp->cert0_serial = st_serial;
        connp->cert0_serial_len = st_serial_len;
        connp->cert0_not_before = st_not_before;
        connp->cert0_not_after = st_not_after;
        st_subject = st_issuer = st_serial = NULL;
        st_sans = NULL;

        SCX509Free(x509);
        x509 = NULL;
    }

    /* every certificate of the chain is kept, also for certn > 0 */
    rc = TlsDecodeHSCertificateAddCertToChain(connp, input, cert_len);
    if (rc != 0) {
        SCLogDebug("TlsDecodeHSCertificateAddCertToChain failed with %d", rc);
        goto error;
    }

    input += cert_len;
    return (int)(input - initial_input);

error:
    if (err_code != 0 && !*extract_event_sent) {
        /* the message no longer aborts at the first failing certificate:
         * report the first extraction failure once */
        TlsDecodeHSCertificateErrSetEvent(ssl_state, err_code);
        *extract_event_sent = true;
    }
    /* the certificate did not fully decode: nothing was published, release
     * the stashed extraction so the next certificate can fill cert0 */
    if (st_subject != NULL)
        SCX509ArrayFree(st_subject, st_subject_len);
    if (st_issuer != NULL)
        SCX509ArrayFree(st_issuer, st_issuer_len);
    if (st_serial != NULL)
        SCX509ArrayFree(st_serial, st_serial_len);
    if (st_sans != NULL) {
        for (uint16_t i = 0; i < st_sans_num; i++)
            SCX509ArrayFree(st_sans[i].san, st_sans[i].san_len);
        SCFree(st_sans);
    }
    if (x509 != NULL)
        SCX509Free(x509);
    return -1;

fail:
    return -1;

invalid_cert:
    SCLogDebug("TLS invalid certificate");
    SSLSetEvent(ssl_state, TLS_DECODER_EVENT_INVALID_CERTIFICATE);
    return -1;
}

/** \internal
 * \brief parse cert data in a certificate handshake message
 *        will be called with all data.
 * \retval consumed bytes consumed or -1 on error
 */
static int TlsDecodeHSCertificates(SSLState *ssl_state, SSLStateConnp *connp,
        const uint8_t *const initial_input, const uint32_t input_len)
{
    const uint8_t *input = (uint8_t *)initial_input;

    if (!(HAS_SPACE(3)))
        return -1;

    const uint32_t cert_chain_len = *input << 16 | *(input + 1) << 8 | *(input + 2);
    input += 3;

    if (!(HAS_SPACE(cert_chain_len)))
        return -1;

    if (connp->certs_buffer != NULL) {
        /* one-shot buffer: a second certificate message must not
         * overwrite or invalidate the data of the first one (base
         * semantics, renegotiation re-sends the same certificate) */
        return -1;
    }

    /* this connp's certificate message: until it decodes fully the
     * certificate data is incomplete - only a fully decoded certificate
     * message completes it, never a later handshake message */
    connp->cert_data_incomplete = true;

    connp->certs_buffer = SCCalloc(1, cert_chain_len);
    if (connp->certs_buffer == NULL) {
        return -1;
    }
    connp->certs_buffer_size = cert_chain_len;
    memcpy(connp->certs_buffer, input, cert_chain_len);

    int cert_cnt = 0;
    uint32_t processed_len = 0;
    bool cert_failed = false;
    bool extract_event_sent = false;
    /* coverity[tainted_data] */
    while (processed_len < cert_chain_len) {
        int rc = TlsDecodeHSCertificate(ssl_state, connp, connp->certs_buffer + processed_len,
                connp->certs_buffer_size - processed_len, cert_cnt, &extract_event_sent);
        if (rc > 0) {
            DEBUG_VALIDATE_BUG_ON(processed_len + (uint32_t)rc > cert_chain_len);
            if (processed_len + (uint32_t)rc > cert_chain_len) {
                return -1;
            }
            processed_len += (uint32_t)rc;
            continue;
        }

        /* a certificate failed to decode: skip its bytes so the rest
         * of the chain is still decoded; an invalid length aborts the
         * message */
        const uint8_t *cert = connp->certs_buffer + processed_len;
        if (processed_len + 3 > cert_chain_len)
            return -1;
        const uint32_t skip = cert[0] << 16 | cert[1] << 8 | cert[2];
        if (processed_len + 3 + skip > cert_chain_len)
            return -1;
        processed_len += 3 + skip;
        cert_failed = true;
    }

    if (cert_failed) {
        /* the message contains an undecodable certificate: the phase
         * data is incomplete, so the caller suppresses the cert phase;
         * the decoded rest of the chain is kept */
        return -1;
    }
    connp->cert_data_incomplete = false;
    connp->cert_chain_final = true;
    return processed_len + 3;
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

    uint16_t version = (uint16_t)(*input << 8) | *(input + 1);
    ssl_state->curr_connp->version = version;

    if (ssl_state->current_flags &
            (SSL_AL_FLAG_STATE_CLIENT_HELLO | SSL_AL_FLAG_STATE_SERVER_HELLO)) {
        SCTLSHandshakeSetTLSVersion(ssl_state->curr_connp->hs, version);
    }

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

    if (SC_ATOMIC_GET(ssl_config.enable_ja3) && ssl_state->curr_connp->ja3_str == NULL) {
        ssl_state->curr_connp->ja3_str = Ja3BufferInit();
        if (ssl_state->curr_connp->ja3_str == NULL)
            return -1;

        int rc = Ja3BufferAddValue(&ssl_state->curr_connp->ja3_str, version);
        if (rc != 0)
            return -1;
    }

    input += SSLV3_CLIENT_HELLO_VERSION_LEN;

    return (int)(input - initial_input);
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

    if (ssl_state->current_flags & SSL_AL_FLAG_STATE_SERVER_HELLO) {
        memcpy(ssl_state->server_connp.random, input, TLS_RANDOM_LEN);
        ssl_state->flags |= TLS_TS_RANDOM_SET;
    } else if (ssl_state->current_flags & SSL_AL_FLAG_STATE_CLIENT_HELLO) {
        memcpy(ssl_state->client_connp.random, input, TLS_RANDOM_LEN);
        ssl_state->flags |= TLS_TC_RANDOM_SET;
    }

    /* Skip random */
    input += SSLV3_CLIENT_HELLO_RANDOM_LEN;

    return (int)(input - initial_input);
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

        if (SafeMemcpy(ssl_state->curr_connp->session_id, 0, session_id_length,
                    input, 0, input_len, session_id_length) != 0) {
            return -1;
        }
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

    return (int)(input - initial_input);

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
    const uint8_t *input = initial_input;

    if (!(HAS_SPACE(2)))
        goto invalid_length;

    uint16_t cipher_suites_length;

    if (ssl_state->current_flags & SSL_AL_FLAG_STATE_SERVER_HELLO) {
        cipher_suites_length = 2;
    } else if (ssl_state->current_flags & SSL_AL_FLAG_STATE_CLIENT_HELLO) {
        cipher_suites_length = (uint16_t)(*input << 8) | *(input + 1);
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

    const bool enable_ja3 =
            SC_ATOMIC_GET(ssl_config.enable_ja3) && ssl_state->curr_connp->ja3_hash == NULL;

    JA3Buffer *ja3_cipher_suites = NULL;

    if (enable_ja3) {
        ja3_cipher_suites = Ja3BufferInit();
        if (ja3_cipher_suites == NULL)
            return -1;
    }

    uint16_t processed_len = 0;
    /* coverity[tainted_data] */
    while (processed_len < cipher_suites_length) {
        if (!(HAS_SPACE(2))) {
            if (enable_ja3) {
                Ja3BufferFree(&ja3_cipher_suites);
            }
            goto invalid_length;
        }

        uint16_t cipher_suite = (uint16_t)(*input << 8) | *(input + 1);
        input += 2;

        if (TLSDecodeValueIsGREASE(cipher_suite) != 1) {
            if (ssl_state->current_flags &
                    (SSL_AL_FLAG_STATE_CLIENT_HELLO | SSL_AL_FLAG_STATE_SERVER_HELLO)) {
                SCTLSHandshakeAddCipher(ssl_state->curr_connp->hs, cipher_suite);
            }
            if (enable_ja3) {
                int rc = Ja3BufferAddValue(&ja3_cipher_suites, cipher_suite);
                if (rc != 0) {
                    return -1;
                }
            }
        }
        processed_len += 2;
    }

    if (enable_ja3) {
        int rc = Ja3BufferAppendBuffer(&ssl_state->curr_connp->ja3_str, &ja3_cipher_suites);
        if (rc == -1) {
            return -1;
        }
    }

    return (int)(input - initial_input);

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
    const uint8_t *input = initial_input;

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

    return (int)(input - initial_input);

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

    uint16_t sni_len = (uint16_t)(*input << 8) | *(input + 1);
    input += 2;

    /* host_name contains the fully qualified domain name,
       and should therefore be limited by the maximum domain
       name length. */
    if (!(HAS_SPACE(sni_len)) || sni_len > 255 || sni_len == 0) {
        SSLSetEvent(ssl_state,
                TLS_DECODER_EVENT_INVALID_SNI_LENGTH);
        return -1;
    }

    /* There must not be more than one extension of the same
       type (RFC5246 section 7.4.1.4). */
    if (ssl_state->curr_connp->sni) {
        SCLogDebug("Multiple SNI extensions");
        SSLSetEvent(ssl_state,
                TLS_DECODER_EVENT_MULTIPLE_SNI_EXTENSIONS);
        input += sni_len;
        return (int)(input - initial_input);
    }

    ssl_state->curr_connp->sni_len = sni_len;
    ssl_state->curr_connp->sni = SCMalloc(sni_len);
    if (unlikely(ssl_state->curr_connp->sni == NULL))
        return -1;

    const size_t consumed = input - initial_input;
    if (SafeMemcpy(ssl_state->curr_connp->sni, 0, sni_len, initial_input, consumed, input_len,
                sni_len) != 0) {
        SCFree(ssl_state->curr_connp->sni);
        ssl_state->curr_connp->sni = NULL;
        return -1;
    }
    input += sni_len;

    return (int)(input - initial_input);

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
    const uint8_t *input = initial_input;

    /* Empty extension */
    if (input_len == 0)
        return 0;

    if (ssl_state->current_flags & SSL_AL_FLAG_STATE_CLIENT_HELLO) {
        if (!(HAS_SPACE(1)))
            goto invalid_length;

        uint8_t supported_ver_len = *input;
        input += 1;

        if (supported_ver_len < 2)
            goto invalid_length;

        if (!(HAS_SPACE(supported_ver_len)))
            goto invalid_length;

        /* Use the first (and preferred) valid version as client version,
         * skip over GREASE and other possible noise. */
        uint16_t i = 0;
        while (i + 1 < (uint16_t)supported_ver_len) {
            uint16_t ver = (uint16_t)(input[i] << 8) | input[i + 1];
            if (TLSVersionValid(ver)) {
                ssl_state->curr_connp->version = ver;
                SCTLSHandshakeSetTLSVersion(ssl_state->curr_connp->hs, ver);
                break;
            }
            i += 2;
        }

        /* Set a flag to indicate that we have seen this extension */
        ssl_state->flags |= SSL_AL_FLAG_CH_VERSION_EXTENSION;

        input += supported_ver_len;
    }
    else if (ssl_state->current_flags & SSL_AL_FLAG_STATE_SERVER_HELLO) {
        if (!(HAS_SPACE(2)))
            goto invalid_length;

        uint16_t ver = (uint16_t)(*input << 8) | *(input + 1);

        if ((ssl_state->flags & SSL_AL_FLAG_CH_VERSION_EXTENSION) &&
                (ver > TLS_VERSION_12)) {
            ssl_state->flags |= SSL_AL_FLAG_LOG_WITHOUT_CERT;
        }

        ssl_state->curr_connp->version = ver;
        input += 2;
    }

    return (int)(input - initial_input);

invalid_length:
    SCLogDebug("TLS handshake invalid length");
    SSLSetEvent(ssl_state,
                TLS_DECODER_EVENT_HANDSHAKE_INVALID_LENGTH);

    return -1;
}

static inline int TLSDecodeHSHelloExtensionEllipticCurves(SSLState *ssl_state,
        const uint8_t *const initial_input, const uint32_t input_len,
        JA3Buffer **ja3_elliptic_curves)
{
    const uint8_t *input = initial_input;

    /* Empty extension */
    if (input_len == 0)
        return 0;

    if (!(HAS_SPACE(2)))
        goto invalid_length;

    uint16_t elliptic_curves_len = (uint16_t)(*input << 8) | *(input + 1);
    input += 2;

    if (!(HAS_SPACE(elliptic_curves_len)))
        goto invalid_length;

    if ((ssl_state->current_flags & SSL_AL_FLAG_STATE_CLIENT_HELLO) &&
            *ja3_elliptic_curves != NULL) {
        uint16_t ec_processed_len = 0;
        /* coverity[tainted_data] */
        while (ec_processed_len < elliptic_curves_len)
        {
            if (!(HAS_SPACE(2)))
                goto invalid_length;

            uint16_t elliptic_curve = (uint16_t)(*input << 8) | *(input + 1);
            input += 2;

            if (TLSDecodeValueIsGREASE(elliptic_curve) != 1) {
                int rc = Ja3BufferAddValue(ja3_elliptic_curves, elliptic_curve);
                if (rc != 0)
                    return -1;
            }

            ec_processed_len += 2;
        }

    } else {
        /* Skip elliptic curves */
        input += elliptic_curves_len;
    }

    return (int)(input - initial_input);

invalid_length:
    SCLogDebug("TLS handshake invalid length");
    SSLSetEvent(ssl_state,
                TLS_DECODER_EVENT_HANDSHAKE_INVALID_LENGTH);

    return -1;
}

static inline int TLSDecodeHSHelloExtensionEllipticCurvePF(SSLState *ssl_state,
        const uint8_t *const initial_input, const uint32_t input_len,
        JA3Buffer **ja3_elliptic_curves_pf)
{
    const uint8_t *input = initial_input;

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
            *ja3_elliptic_curves_pf != NULL) {
        uint8_t ec_pf_processed_len = 0;
        /* coverity[tainted_data] */
        while (ec_pf_processed_len < ec_pf_len)
        {
            uint8_t elliptic_curve_pf = *input;
            input += 1;

            if (TLSDecodeValueIsGREASE(elliptic_curve_pf) != 1) {
                int rc = Ja3BufferAddValue(ja3_elliptic_curves_pf, elliptic_curve_pf);
                if (rc != 0)
                    return -1;
            }

            ec_pf_processed_len += 1;
        }

    } else {
        /* Skip elliptic curve point formats */
        input += ec_pf_len;
    }

    return (int)(input - initial_input);

invalid_length:
    SCLogDebug("TLS handshake invalid length");
    SSLSetEvent(ssl_state,
                TLS_DECODER_EVENT_HANDSHAKE_INVALID_LENGTH);

    return -1;
}

static inline int TLSDecodeHSHelloExtensionSigAlgorithms(
        SSLState *ssl_state, const uint8_t *const initial_input, const uint32_t input_len)
{
    const uint8_t *input = initial_input;

    /* Empty extension */
    if (input_len == 0)
        return 0;

    if (!(HAS_SPACE(2)))
        goto invalid_length;

    uint16_t sigalgo_len = (uint16_t)(*input << 8) | *(input + 1);
    input += 2;

    /* Signature algorithms length should always be divisible by 2 */
    if ((sigalgo_len % 2) != 0) {
        goto invalid_length;
    }

    if (!(HAS_SPACE(sigalgo_len)))
        goto invalid_length;

    if (ssl_state->current_flags & SSL_AL_FLAG_STATE_CLIENT_HELLO) {
        uint16_t sigalgo_processed_len = 0;
        while (sigalgo_processed_len < sigalgo_len) {
            uint16_t sigalgo = (uint16_t)(*input << 8) | *(input + 1);
            input += 2;
            sigalgo_processed_len += 2;

            SCTLSHandshakeAddSigAlgo(ssl_state->curr_connp->hs, sigalgo);
        }
    } else {
        /* Skip signature algorithms */
        input += sigalgo_len;
    }

    return (int)(input - initial_input);

invalid_length:
    SCLogDebug("Signature algorithm list invalid length");
    SSLSetEvent(ssl_state, TLS_DECODER_EVENT_HANDSHAKE_INVALID_LENGTH);

    return -1;
}

static inline int TLSDecodeHSHelloExtensionALPN(
        SSLState *ssl_state, const uint8_t *const initial_input, const uint32_t input_len)
{
    const uint8_t *input = initial_input;

    /* Empty extension */
    if (input_len == 0)
        return 0;

    if (!(HAS_SPACE(2)))
        goto invalid_length;

    uint16_t alpn_len = (uint16_t)(*input << 8) | *(input + 1);
    input += 2;

    if (!(HAS_SPACE(alpn_len)))
        goto invalid_length;

    /* We use 32 bits here to avoid potentially overflowing a value that
       needs to be compared to an unsigned 16-bit value. */
    uint32_t alpn_processed_len = 0;
    while (alpn_processed_len < alpn_len) {
        uint8_t protolen = *input;
        input += 1;
        alpn_processed_len += 1;

        if (!(HAS_SPACE(protolen)))
            goto invalid_length;

        /* Check if reading another protolen bytes would exceed the
           overall ALPN length; if so, skip and continue */
        if (alpn_processed_len + protolen > ((uint32_t)alpn_len)) {
            input += alpn_len - alpn_processed_len;
            break;
        }
        SCTLSHandshakeAddALPN(ssl_state->curr_connp->hs, (const char *)input, protolen);

        alpn_processed_len += protolen;
        input += protolen;
    }

    return (int)(input - initial_input);

invalid_length:
    SCLogDebug("ALPN list invalid length");
    SSLSetEvent(ssl_state, TLS_DECODER_EVENT_HANDSHAKE_INVALID_LENGTH);

    return -1;
}

static inline int TLSDecodeHSHelloExtensions(SSLState *ssl_state,
                                         const uint8_t * const initial_input,
                                         const uint32_t input_len)
{
    const uint8_t *input = initial_input;

    int ret;
    int rc;
    // if ja3_hash is already computed, do not use new hello to augment ja3_str
    const bool ja3 =
            (SC_ATOMIC_GET(ssl_config.enable_ja3) == 1) && ssl_state->curr_connp->ja3_hash == NULL;

    JA3Buffer *ja3_extensions = NULL;
    JA3Buffer *ja3_elliptic_curves = NULL;
    JA3Buffer *ja3_elliptic_curves_pf = NULL;

    if (ja3) {
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

    uint16_t extensions_len = (uint16_t)(*input << 8) | *(input + 1);
    input += 2;

    if (!(HAS_SPACE(extensions_len)))
        goto invalid_length;

    uint32_t processed_len = 0;
    /* coverity[tainted_data] */
    while (processed_len < (uint32_t)extensions_len) {
        if (!(HAS_SPACE(2)))
            goto invalid_length;

        uint16_t ext_type = (uint16_t)(*input << 8) | *(input + 1);
        input += 2;

        if (!(HAS_SPACE(2)))
            goto invalid_length;

        uint16_t ext_len = (uint16_t)(*input << 8) | *(input + 1);
        input += 2;

        if (!(HAS_SPACE(ext_len)))
            goto invalid_length;

        if (processed_len + 4UL + (uint32_t)ext_len > (uint32_t)extensions_len)
            goto invalid_length;

        switch (ext_type) {
            case SSL_EXTENSION_SNI:
            {
                /* coverity[tainted_data] */
                ret = TLSDecodeHSHelloExtensionSni(ssl_state, input,
                                                   ext_len);
                if (ret < 0)
                    goto end;

                input += ext_len;

                break;
            }

            case SSL_EXTENSION_ELLIPTIC_CURVES:
            {
                /* coverity[tainted_data] */
                ret = TLSDecodeHSHelloExtensionEllipticCurves(
                        ssl_state, input, ext_len, &ja3_elliptic_curves);
                if (ret < 0)
                    goto error;

                input += ext_len;

                break;
            }

            case SSL_EXTENSION_EC_POINT_FORMATS:
            {
                /* coverity[tainted_data] */
                ret = TLSDecodeHSHelloExtensionEllipticCurvePF(
                        ssl_state, input, ext_len, &ja3_elliptic_curves_pf);
                if (ret < 0)
                    goto error;

                input += ext_len;

                break;
            }

            case SSL_EXTENSION_SIGNATURE_ALGORITHMS: {
                /* coverity[tainted_data] */
                ret = TLSDecodeHSHelloExtensionSigAlgorithms(ssl_state, input, ext_len);
                if (ret < 0)
                    goto end;

                input += ext_len;

                break;
            }

            case SSL_EXTENSION_ALPN: {
                /* coverity[tainted_data] */
                ret = TLSDecodeHSHelloExtensionALPN(ssl_state, input, ext_len);
                if (ret < 0)
                    goto end;

                input += ext_len;

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

                input += ext_len;

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

        if (ja3) {
            if (TLSDecodeValueIsGREASE(ext_type) != 1) {
                rc = Ja3BufferAddValue(&ja3_extensions, ext_type);
                if (rc != 0)
                    goto error;
            }
        }

        if (ssl_state->current_flags &
                (SSL_AL_FLAG_STATE_CLIENT_HELLO | SSL_AL_FLAG_STATE_SERVER_HELLO)) {
            if (TLSDecodeValueIsGREASE(ext_type) != 1) {
                SCTLSHandshakeAddExtension(ssl_state->curr_connp->hs, ext_type);
            }
        }

        processed_len += (uint32_t)ext_len + 4UL;
    }

end:
    if (ja3) {
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

    return (int)(input - initial_input);

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

    /* a failed sub-decode must not fail the parse: the message bytes are
     * consumed either way. The phase advance that follows relies on a
     * fully parsed message, so suppress it via the connp flag instead. */

    ret = TLSDecodeHSHelloVersion(ssl_state, input, input_len);
    if (ret < 0)
        goto fail;

    parsed += ret;

    ret = TLSDecodeHSHelloRandom(ssl_state, input + parsed, input_len - parsed);
    if (ret < 0)
        goto fail;

    parsed += ret;

    /* The session id field in the server hello record was removed in
       TLSv1.3 draft1, but was readded in draft22. */
    if ((ssl_state->current_flags & SSL_AL_FLAG_STATE_CLIENT_HELLO) ||
            ((ssl_state->current_flags & SSL_AL_FLAG_STATE_SERVER_HELLO) &&
            ((ssl_state->flags & SSL_AL_FLAG_LOG_WITHOUT_CERT) == 0))) {
        ret = TLSDecodeHSHelloSessionID(ssl_state, input + parsed,
                                        input_len - parsed);
        if (ret < 0)
            goto fail;

        parsed += ret;
    }

    ret = TLSDecodeHSHelloCipherSuites(ssl_state, input + parsed,
                                       input_len - parsed);
    if (ret < 0)
        goto fail;

    parsed += ret;

   /* The compression methods field in the server hello record was
      removed in TLSv1.3 draft1, but was readded in draft22. */
   if ((ssl_state->current_flags & SSL_AL_FLAG_STATE_CLIENT_HELLO) ||
              ((ssl_state->current_flags & SSL_AL_FLAG_STATE_SERVER_HELLO) &&
              ((ssl_state->flags & SSL_AL_FLAG_LOG_WITHOUT_CERT) == 0))) {
        ret = TLSDecodeHSHelloCompressionMethods(ssl_state, input + parsed,
                                                 input_len - parsed);
        if (ret < 0)
            goto fail;

        parsed += ret;
    }

    ret = TLSDecodeHSHelloExtensions(ssl_state, input + parsed,
                                     input_len - parsed);
    if (ret < 0)
        goto fail;

    if (SC_ATOMIC_GET(ssl_config.enable_ja3) && ssl_state->curr_connp->ja3_hash == NULL) {
        ssl_state->curr_connp->ja3_hash = Ja3GenerateHash(ssl_state->curr_connp->ja3_str);
    }
    return 0;

fail:
    ssl_state->curr_connp->phase_suppressed = true;
    return 0;
}

#ifdef DEBUG_VALIDATION
static inline bool
RecordAlreadyProcessed(const SSLStateConnp *curr_connp)
{
    return ((curr_connp->record_length + SSLV3_RECORD_HDR_LEN) <
            curr_connp->bytes_processed);
}
#endif

static inline int SSLv3ParseHandshakeTypeCertificate(SSLState *ssl_state, SSLStateConnp *connp,
        const uint8_t *const initial_input, const uint32_t input_len)
{
    int rc = TlsDecodeHSCertificates(ssl_state, connp, initial_input, input_len);
    SCLogDebug("rc %d", rc);
    if (rc > 0) {
        DEBUG_VALIDATE_BUG_ON(rc > (int)input_len);
        SSLParserHSReset(connp);
    } else if (rc < 0) {
        SCLogDebug("error parsing cert, reset state");
        SSLParserHSReset(connp);
        /* the certificate data is incomplete (an undecodable certificate);
         * the track is already in the certificate phase (entered at the
         * message header), so nothing to suppress - only the data phase
         * is gated (cert_data_incomplete) */
    }
    return input_len;
}

static int SupportedHandshakeType(const uint8_t type)
{
    switch (type) {
        case SSLV3_HS_CLIENT_HELLO:
        case SSLV3_HS_SERVER_HELLO:
        case SSLV3_HS_SERVER_KEY_EXCHANGE:
        case SSLV3_HS_CLIENT_KEY_EXCHANGE:
        case SSLV3_HS_CERTIFICATE:
        case SSLV3_HS_HELLO_REQUEST:
        case SSLV3_HS_CERTIFICATE_REQUEST:
        case SSLV3_HS_CERTIFICATE_VERIFY:
        case SSLV3_HS_FINISHED:
        case SSLV3_HS_CERTIFICATE_URL:
        case SSLV3_HS_CERTIFICATE_STATUS:
        case SSLV3_HS_NEW_SESSION_TICKET:
        case SSLV3_HS_SERVER_HELLO_DONE:
            return true;
            break;

        default:
            return false;
            break;
    }
}

/**
 *  \param input_len length of bytes after record header. Can be 0 (e.g. for server hello done).
 *  \retval parsed number of consumed bytes
 *  \retval < 0 error
 */
static int SSLv3ParseHandshakeType(SSLState *ssl_state, const uint8_t *input,
                                   uint32_t input_len, uint8_t direction)
{
    const uint8_t *initial_input = input;
    int rc;

    DEBUG_VALIDATE_BUG_ON(RecordAlreadyProcessed(ssl_state->curr_connp));

    switch (ssl_state->curr_connp->handshake_type) {
        case SSLV3_HS_CLIENT_HELLO:
            ssl_state->current_flags = SSL_AL_FLAG_STATE_CLIENT_HELLO;

            if (ssl_state->curr_connp->hs == NULL)
                ssl_state->curr_connp->hs = SCTLSHandshakeNew();

            rc = TLSDecodeHandshakeHello(ssl_state, input, input_len);
            if (rc < 0)
                return rc;
            break;

        case SSLV3_HS_SERVER_HELLO:
            ssl_state->current_flags = SSL_AL_FLAG_STATE_SERVER_HELLO;

            DEBUG_VALIDATE_BUG_ON(ssl_state->curr_connp->message_length != input_len);
            if (ssl_state->curr_connp->hs == NULL)
                ssl_state->curr_connp->hs = SCTLSHandshakeNew();

            rc = TLSDecodeHandshakeHello(ssl_state, input, input_len);
            if (rc < 0)
                return rc;
            break;

        case SSLV3_HS_SERVER_KEY_EXCHANGE:
            ssl_state->current_flags = SSL_AL_FLAG_STATE_SERVER_KEYX;
            break;

        case SSLV3_HS_CLIENT_KEY_EXCHANGE:
            ssl_state->current_flags = SSL_AL_FLAG_STATE_CLIENT_KEYX;
            break;

        case SSLV3_HS_CERTIFICATE:
            rc = SSLv3ParseHandshakeTypeCertificate(ssl_state,
                    direction ? &ssl_state->server_connp : &ssl_state->client_connp, initial_input,
                    input_len);
            if (rc < 0)
                return rc;
            break;

        case SSLV3_HS_HELLO_REQUEST:
            break;
        case SSLV3_HS_CERTIFICATE_REQUEST:
            if (direction) {
                ssl_state->current_flags = SSL_AL_FLAG_NEED_CLIENT_CERT;
            }
            break;
        case SSLV3_HS_CERTIFICATE_VERIFY:
        case SSLV3_HS_FINISHED:
        case SSLV3_HS_CERTIFICATE_URL:
        case SSLV3_HS_CERTIFICATE_STATUS:
        case SSLV3_HS_SERVER_HELLO_DONE:
            break;
        case SSLV3_HS_NEW_SESSION_TICKET:
            SCLogDebug("new session ticket");
            break;
        default:
            SSLSetEvent(ssl_state, TLS_DECODER_EVENT_INVALID_SSL_RECORD);
            return -1;
    }

    ssl_state->flags |= ssl_state->current_flags;

    SCLogDebug("message: length %u", ssl_state->curr_connp->message_length);
    SCLogDebug("input_len %u ssl_state->curr_connp->bytes_processed %u", input_len, ssl_state->curr_connp->bytes_processed);

    return input_len;
}

/* the phase of a message is entered when the message starts, so all of its
 * fragments belong to it (HTTP1: request_line starts at the first byte of the
 * line, not when the line is complete) */
static void SSLv3HandshakePhaseEnter(SSLState *ssl_state, const uint8_t hs_type)
{
    /* one message is one phase: the flag is per message, reset at its
     * start (the header is read once per message) */
    ssl_state->curr_connp->phase_suppressed = false;
    if (ssl_state->curr_connp == &ssl_state->client_connp) {
        if (hs_type == SSLV3_HS_CLIENT_HELLO)
            UpdateClientState(ssl_state, TLS_STATE_CLIENT_HELLO);
        else if (hs_type == SSLV3_HS_CERTIFICATE)
            UpdateClientState(ssl_state, TLS_STATE_CLIENT_CERT);
    } else if (hs_type == SSLV3_HS_SERVER_HELLO) {
        UpdateServerState(ssl_state, TLS_STATE_SERVER_HELLO);
    } else if (hs_type == SSLV3_HS_CERTIFICATE) {
        UpdateServerState(ssl_state, TLS_STATE_SERVER_CERT);
    }
}

/* a complete hello hands the track over to the certificate phase, before any
 * certificate byte arrives (HTTP1: request_line -> request_headers at line
 * completion). A hello that failed to decode keeps the track in the hello
 * phase: its data never existed */
static void SSLv3HandshakePhaseLeave(SSLState *ssl_state, const uint8_t hs_type)
{
    /* some handshake messages (certificates) clear the connp handshake
     * type before returning, so the message type is passed in */
    if (ssl_state->curr_connp->phase_suppressed)
        return;
    if (ssl_state->curr_connp == &ssl_state->client_connp) {
        if (hs_type == SSLV3_HS_CLIENT_HELLO)
            UpdateClientState(ssl_state, TLS_STATE_CLIENT_CERT);
    } else if (hs_type == SSLV3_HS_SERVER_HELLO) {
        UpdateServerState(ssl_state, TLS_STATE_SERVER_CERT);
    }
}

static int SSLv3ParseHandshakeProtocol(SSLState *ssl_state, const uint8_t *input,
                                       uint32_t input_len, uint8_t direction)
{
    const uint8_t *initial_input = input;

    if (input_len == 0 || ssl_state->curr_connp->bytes_processed ==
            (ssl_state->curr_connp->record_length + SSLV3_RECORD_HDR_LEN)) {
        SCReturnInt(0);
    }

    while (input_len) {
        SCLogDebug("input_len %u", input_len);

        if (ssl_state->curr_connp->hs_buffer != NULL) {
            SCLogDebug("partial handshake record in place");
            const uint32_t need = ssl_state->curr_connp->hs_buffer_message_size -
                                  ssl_state->curr_connp->hs_buffer_offset;
            const uint32_t add = MIN(need, input_len);

            /* grow buffer to next multiple of 4k that fits all data we have */
            if (ssl_state->curr_connp->hs_buffer_offset + add >
                    ssl_state->curr_connp->hs_buffer_size) {
                const uint32_t avail = ssl_state->curr_connp->hs_buffer_offset + add;
                const uint32_t new_size = avail + (4096 - (avail % 4096));
                SCLogDebug("new_size %u, avail %u", new_size, avail);
                void *ptr = SCRealloc(ssl_state->curr_connp->hs_buffer, new_size);
                if (ptr == NULL)
                    return -1;
                ssl_state->curr_connp->hs_buffer = ptr;
                ssl_state->curr_connp->hs_buffer_size = new_size;
            }

            SCLogDebug("ssl_state->curr_connp->hs_buffer_offset %u "
                       "ssl_state->curr_connp->hs_buffer_size %u",
                    ssl_state->curr_connp->hs_buffer_offset, ssl_state->curr_connp->hs_buffer_size);
            SCLogDebug("to add %u total %u", add, ssl_state->curr_connp->hs_buffer_offset + add);

            if (SafeMemcpy(ssl_state->curr_connp->hs_buffer,
                        ssl_state->curr_connp->hs_buffer_offset,
                        ssl_state->curr_connp->hs_buffer_size, input, 0, add, add) != 0) {
                SCLogDebug("copy failed");
                return -1;
            }
            ssl_state->curr_connp->hs_buffer_offset += add;

            if (ssl_state->curr_connp->hs_buffer_message_size <=
                    ssl_state->curr_connp->hs_buffer_offset) {
                DEBUG_VALIDATE_BUG_ON(ssl_state->curr_connp->hs_buffer_message_size !=
                                      ssl_state->curr_connp->hs_buffer_offset);

                ssl_state->curr_connp->handshake_type =
                        ssl_state->curr_connp->hs_buffer_message_type;
                ssl_state->curr_connp->message_length =
                        ssl_state->curr_connp->hs_buffer_message_size;

                SCLogDebug("got all data now: handshake_type %u message_length %u",
                        ssl_state->curr_connp->handshake_type,
                        ssl_state->curr_connp->message_length);

                int retval = SSLv3ParseHandshakeType(ssl_state, ssl_state->curr_connp->hs_buffer,
                        ssl_state->curr_connp->hs_buffer_offset, direction);
                if (retval < 0) {
                    SSLParserHSReset(ssl_state->curr_connp);
                    return (retval);
                }
                SCLogDebug("retval %d", retval);

                SSLv3HandshakePhaseLeave(ssl_state, ssl_state->curr_connp->hs_buffer_message_type);

                /* data processed, reset buffer */
                SCFree(ssl_state->curr_connp->hs_buffer);
                ssl_state->curr_connp->hs_buffer = NULL;
                ssl_state->curr_connp->hs_buffer_size = 0;
                ssl_state->curr_connp->hs_buffer_message_size = 0;
                ssl_state->curr_connp->hs_buffer_message_type = 0;
                ssl_state->curr_connp->hs_buffer_offset = 0;
            } else {
                SCLogDebug("partial data");
            }

            input += add;
            input_len -= add;
            SCLogDebug("input_len %u", input_len);
            SSLParserHSReset(ssl_state->curr_connp);
            continue;
        }

        SCLogDebug("bytes_processed %u", ssl_state->curr_connp->bytes_processed);
        SCLogDebug("input %p input_len %u", input, input_len);

        if (input_len < 4) {
            SSLSetEvent(ssl_state, TLS_DECODER_EVENT_INVALID_SSL_RECORD);
            SCReturnInt(-1);
        }

        ssl_state->curr_connp->handshake_type = input[0];
        ssl_state->curr_connp->message_length = input[1] << 16 | input[2] << 8 | input[3];
        /* the fragments of this message all belong to its phase */
        SSLv3HandshakePhaseEnter(ssl_state, ssl_state->curr_connp->handshake_type);
        SCLogDebug("handshake_type %u message len %u input %p input_len %u",
                ssl_state->curr_connp->handshake_type, ssl_state->curr_connp->message_length, input,
                input_len);
        input += 4;
        input_len -= 4;

        const uint32_t record_len = ssl_state->curr_connp->message_length;
        /* see if we support this type. We check here to not use the fragment
         * handling on things we don't support. */
        const bool supported_type = SupportedHandshakeType(ssl_state->curr_connp->handshake_type);
        SCLogDebug("supported_type %s handshake_type %u/%02x", supported_type ? "true" : "false",
                ssl_state->curr_connp->handshake_type, ssl_state->curr_connp->handshake_type);
        if (!supported_type) {
            uint32_t avail_record_len = MIN(input_len, record_len);
            input += avail_record_len;
            input_len -= avail_record_len;

            SSLParserHSReset(ssl_state->curr_connp);

            if ((direction && (ssl_state->flags & SSL_AL_FLAG_SERVER_CHANGE_CIPHER_SPEC)) ||
                    (!direction && (ssl_state->flags & SSL_AL_FLAG_CLIENT_CHANGE_CIPHER_SPEC))) {
                // after Change Cipher Spec we get Encrypted Handshake Messages
            } else {
                SSLSetEvent(ssl_state, TLS_DECODER_EVENT_INVALID_HANDSHAKE_MESSAGE);
            }
            continue;
        }

        /* if the message length exceeds our input_len, we have a tls fragment. */
        if (record_len > input_len) {
            const uint32_t avail = input_len;
            const uint32_t size = avail + (4096 - (avail % 4096));
            SCLogDebug("initial buffer size %u, based on input %u", size, avail);
            ssl_state->curr_connp->hs_buffer = SCCalloc(1, size);
            if (ssl_state->curr_connp->hs_buffer == NULL) {
                return -1;
            }
            ssl_state->curr_connp->hs_buffer_size = size;
            ssl_state->curr_connp->hs_buffer_message_size = record_len;
            ssl_state->curr_connp->hs_buffer_message_type = ssl_state->curr_connp->handshake_type;

            if (input_len > 0) {
                if (SafeMemcpy(ssl_state->curr_connp->hs_buffer, 0,
                            ssl_state->curr_connp->hs_buffer_size, input, 0, input_len,
                            input_len) != 0) {
                    return -1;
                }
                ssl_state->curr_connp->hs_buffer_offset = input_len;
            }
            SCLogDebug("opened record buffer %p size %u offset %u type %u msg_size %u",
                    ssl_state->curr_connp->hs_buffer, ssl_state->curr_connp->hs_buffer_size,
                    ssl_state->curr_connp->hs_buffer_offset,
                    ssl_state->curr_connp->hs_buffer_message_type,
                    ssl_state->curr_connp->hs_buffer_message_size);
            input += input_len;
            SSLParserHSReset(ssl_state->curr_connp);
            return (int)(input - initial_input);

        } else {
            /* full record, parse it now */
            const uint8_t full_record_hs_type = ssl_state->curr_connp->handshake_type;
            int retval = SSLv3ParseHandshakeType(
                    ssl_state, input, ssl_state->curr_connp->message_length, direction);
            if (retval < 0 || retval > (int)input_len) {
                DEBUG_VALIDATE_BUG_ON(retval > (int)input_len);
                if (retval < 0)
                    SSLParserHSReset(ssl_state->curr_connp);
                return (retval);
            }
            SCLogDebug("retval %d input_len %u", retval, input_len);
            SSLv3HandshakePhaseLeave(ssl_state, full_record_hs_type);
            input += retval;
            input_len -= retval;

            SSLParserHSReset(ssl_state->curr_connp);
        }
        SCLogDebug("input_len left %u", input_len);
    }
    return (int)(input - initial_input);
}

/**
 * \internal
 * \brief TLS Alert parser
 *
 * \param sslstate  Pointer to the SSL state.
 * \param input     Pointer to the received input data.
 * \param input_len Length in bytes of the received data.
 * \param direction 1 toclient, 0 toserver
 *
 * \retval The number of bytes parsed on success, 0 if nothing parsed, -1 on failure.
 */
static int SSLv3ParseAlertProtocol(
        SSLState *ssl_state, const uint8_t *input, uint32_t input_len, uint8_t direction)
{
    if (input_len < 2) {
        SSLSetEvent(ssl_state, TLS_DECODER_EVENT_INVALID_ALERT);
        return -1;
    }

    /* assume a record > 2 to be an encrypted alert record */
    if (input_len == 2) {
        uint8_t level = input[0];
        // uint8_t desc = input[1];

        /* if level Fatal, we consider the tx finished */
        if (level == 2) {
            UpdateClientState(ssl_state, TLS_STATE_CLIENT_FINISHED);
            UpdateServerState(ssl_state, TLS_STATE_SERVER_FINISHED);
        }
    }
    return 0;
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
static int SSLv3ParseHeartbeatProtocol(SSLState *ssl_state, const uint8_t *input,
                                       uint32_t input_len, uint8_t direction)
{
    uint8_t hb_type;
    uint16_t payload_len;
    uint32_t padding_len;

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

        payload_len = (uint16_t)(*input << 8) | *(input + 1);

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
                            const uint8_t *input, uint32_t input_len)
{
    const uint8_t *initial_input = input;

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
                    ssl_state->curr_connp->version = (uint16_t)(input[1] << 8) | input[2];
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
                ssl_state->curr_connp->version = (uint16_t)(*(input++) << 8);
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

    return (int)(input - initial_input);
}

static int SSLv2ParseRecord(uint8_t direction, SSLState *ssl_state,
                            const uint8_t *input, uint32_t input_len)
{
    const uint8_t *initial_input = input;

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

    return (int)(input - initial_input);
}

static struct SSLDecoderResult SSLv2Decode(uint8_t direction, SSLState *ssl_state,
        AppLayerParserState *pstate, const uint8_t *input, uint32_t input_len,
        const StreamSlice stream_slice)
{
    const uint8_t *initial_input = input;

    if (ssl_state->curr_connp->bytes_processed == 0) {
        if (input[0] & 0x80) {
            ssl_state->curr_connp->record_lengths_length = 2;
        } else {
            ssl_state->curr_connp->record_lengths_length = 3;
        }

        SCLogDebug("record start: ssl2.hdr frame");
        AppLayerFrameNewByPointer(ssl_state->f, &stream_slice, input,
                ssl_state->curr_connp->record_lengths_length + 1, direction, TLS_FRAME_SSLV2_HDR);
    }

    SCLogDebug("direction %u ssl_state->curr_connp->record_lengths_length + 1 %u, "
               "ssl_state->curr_connp->bytes_processed %u",
            direction, ssl_state->curr_connp->record_lengths_length + 1,
            ssl_state->curr_connp->bytes_processed);
    /* the +1 is because we read one extra byte inside SSLv2ParseRecord
       to read the msg_type */
    if (ssl_state->curr_connp->bytes_processed <
            (ssl_state->curr_connp->record_lengths_length + 1)) {
        const int retval = SSLv2ParseRecord(direction, ssl_state, input, input_len);
        SCLogDebug("retval %d ssl_state->curr_connp->record_length %u", retval,
                ssl_state->curr_connp->record_length);
        if (retval < 0 || retval > (int)input_len) {
            DEBUG_VALIDATE_BUG_ON(retval > (int)input_len);
            SSLSetEvent(ssl_state, TLS_DECODER_EVENT_INVALID_SSLV2_HEADER);
            return SSL_DECODER_ERROR(-1);
        }

        AppLayerFrameNewByPointer(ssl_state->f, &stream_slice, input,
                ssl_state->curr_connp->record_lengths_length + ssl_state->curr_connp->record_length,
                direction, TLS_FRAME_SSLV2_PDU);
        SCLogDebug("record start: ssl2.pdu frame");

        input += retval;
        input_len -= retval;
    }

    /* if we don't have the full record, we return incomplete */
    if (ssl_state->curr_connp->record_lengths_length + ssl_state->curr_connp->record_length >
            input_len + ssl_state->curr_connp->bytes_processed) {
        uint32_t needed = ssl_state->curr_connp->record_length;
        SCLogDebug("record len %u input_len %u parsed %u: need %u bytes more data",
                ssl_state->curr_connp->record_length, input_len, (uint32_t)(input - initial_input),
                needed);
        return SSL_DECODER_INCOMPLETE((input - initial_input), needed);
    }

    if (input_len == 0) {
        return SSL_DECODER_OK((input - initial_input));
    }

    /* record_length should never be zero */
    if (ssl_state->curr_connp->record_length == 0) {
        SCLogDebug("SSLv2 record length is zero");
        SSLSetEvent(ssl_state, TLS_DECODER_EVENT_INVALID_SSLV2_HEADER);
        return SSL_DECODER_ERROR(-1);
    }

    /* record_lengths_length should never be zero */
    if (ssl_state->curr_connp->record_lengths_length == 0) {
        SCLogDebug("SSLv2 record lengths length is zero");
        SSLSetEvent(ssl_state, TLS_DECODER_EVENT_INVALID_SSLV2_HEADER);
        return SSL_DECODER_ERROR(-1);
    }

    switch (ssl_state->curr_connp->content_type) {
        case SSLV2_MT_ERROR:
            SCLogDebug("SSLV2_MT_ERROR msg_type received. Error encountered "
                       "in establishing the sslv2 session, may be version");
            SSLSetEvent(ssl_state, TLS_DECODER_EVENT_ERROR_MSG_ENCOUNTERED);

            break;

        case SSLV2_MT_CLIENT_HELLO:
            /* record_length does not count the msg_type byte.  CLIENT_HELLO
             * body starts with 3 fixed fields: client_version (2) +
             * cipher_spec_length (2) + session_id_length (2).  We need at
             * least those 6 bytes after the msg_type, so record_length
             * must be >= 7. */
            if (input_len < 6 || ssl_state->curr_connp->record_length < 7) {
                SSLSetEvent(ssl_state, TLS_DECODER_EVENT_INVALID_SSL_RECORD);
                return SSL_DECODER_ERROR(-1);
            }

            ssl_state->current_flags = SSL_AL_FLAG_STATE_CLIENT_HELLO;
            ssl_state->current_flags |= SSL_AL_FLAG_SSL_CLIENT_HS;
            UpdateClientState(ssl_state, TLS_STATE_CLIENT_HELLO);

            const uint16_t version = (uint16_t)(input[0] << 8) | input[1];
            SCLogDebug("SSLv2: version %04x", version);
            ssl_state->curr_connp->version = version;
            uint16_t session_id_length = (input[5]) | (uint16_t)(input[4] << 8);
            input += 6;
            input_len -= 6;
            ssl_state->curr_connp->bytes_processed += 6;
            if (session_id_length == 0) {
                ssl_state->current_flags |= SSL_AL_FLAG_SSL_NO_SESSION_ID;
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
                /* a v2 client certificate message names the client's
                 * certificate phase, even if the v2 certificate payload is
                 * not extracted */
                UpdateClientState(ssl_state, TLS_STATE_CLIENT_CERT);
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
                        SCAppLayerParserStateSetFlag(pstate, APP_LAYER_PARSER_NO_INSPECTION);
                    }

                    if (ssl_config.encrypt_mode == SSL_CNF_ENC_HANDLE_BYPASS) {
                        SCAppLayerParserStateSetFlag(pstate, APP_LAYER_PARSER_NO_REASSEMBLY);
                        SCAppLayerParserStateSetFlag(pstate, APP_LAYER_PARSER_BYPASS_READY);
                    }
                    SCLogDebug("SSLv2 No reassembly & inspection has been set");
                }
            }

            break;

        case SSLV2_MT_SERVER_HELLO:
            ssl_state->current_flags = SSL_AL_FLAG_STATE_SERVER_HELLO;
            ssl_state->current_flags |= SSL_AL_FLAG_SSL_SERVER_HS;
            UpdateServerState(ssl_state, TLS_STATE_SERVER_HELLO);

            break;
    }

    ssl_state->flags |= ssl_state->current_flags;

    if (ssl_state->curr_connp->bytes_processed >
            ssl_state->curr_connp->record_length + ssl_state->curr_connp->record_lengths_length) {
        SCLogDebug("SSLv2 bytes_processed (%u) exceeds record+hdr "
                   "len (record_length=%u, lengths_length=%u)",
                ssl_state->curr_connp->bytes_processed, ssl_state->curr_connp->record_length,
                ssl_state->curr_connp->record_lengths_length);
        SSLSetEvent(ssl_state, TLS_DECODER_EVENT_INVALID_SSL_RECORD);
        return SSL_DECODER_ERROR(-1);
    }

    if (input_len + ssl_state->curr_connp->bytes_processed >=
            (ssl_state->curr_connp->record_length +
            ssl_state->curr_connp->record_lengths_length)) {

        /* looks like we have another record after this */
        uint32_t diff = ssl_state->curr_connp->record_length +
                ssl_state->curr_connp->record_lengths_length + -
                ssl_state->curr_connp->bytes_processed;
        input += diff;
        SSLParserReset(ssl_state);

        /* we still don't have the entire record for the one we are
           currently parsing */
    } else {
        input += input_len;
        ssl_state->curr_connp->bytes_processed += input_len;
    }
    return SSL_DECODER_OK((input - initial_input));
}

static struct SSLDecoderResult SSLv3Decode(uint8_t direction, SSLState *ssl_state,
        AppLayerParserState *pstate, const uint8_t *input, const uint32_t input_len,
        const StreamSlice stream_slice)
{
    uint32_t parsed = 0;
    uint32_t record_len; /* slice of input_len for the current record */
    const bool first_call = (ssl_state->curr_connp->bytes_processed == 0);

    if (ssl_state->curr_connp->bytes_processed < SSLV3_RECORD_HDR_LEN) {
        const uint16_t prev_version = ssl_state->curr_connp->version;

        int retval = SSLv3ParseRecord(direction, ssl_state, input, input_len);
        if (retval < 0 || retval > (int)input_len) {
            DEBUG_VALIDATE_BUG_ON(retval > (int)input_len);
            SCLogDebug("SSLv3ParseRecord returned %d", retval);
            SSLSetEvent(ssl_state, TLS_DECODER_EVENT_INVALID_TLS_HEADER);
            return SSL_DECODER_ERROR(-1);
        }
        parsed = retval;

        SCLogDebug("%s input %p record_length %u", (direction == 0) ? "toserver" : "toclient",
                input, ssl_state->curr_connp->record_length);

        /* first the hdr frame at our first chance */
        if (first_call) {
            AppLayerFrameNewByPointer(ssl_state->f, &stream_slice, input, SSLV3_RECORD_HDR_LEN,
                    direction, TLS_FRAME_HDR);
        }

        /* parser is streaming for the initial header, then switches to incomplete
         * API: so if we don't have the hdr yet, return consumed bytes and wait
         * until we are called again with new data. */
        if (ssl_state->curr_connp->bytes_processed < SSLV3_RECORD_HDR_LEN) {
            SCLogDebug(
                    "incomplete header, return %u bytes consumed and wait for more data", parsed);
            return SSL_DECODER_OK(parsed);
        }

        /* pdu frame needs record length, so only create it when hdr fully parsed. */
        AppLayerFrameNewByPointer(ssl_state->f, &stream_slice, input,
                ssl_state->curr_connp->record_length + retval, direction, TLS_FRAME_PDU);
        record_len = MIN(input_len - parsed, ssl_state->curr_connp->record_length);
        SCLogDebug(
                "record_len %u (input_len %u, parsed %u, ssl_state->curr_connp->record_length %u)",
                record_len, input_len, parsed, ssl_state->curr_connp->record_length);

        bool unknown_record = false;
        switch (ssl_state->curr_connp->content_type) {
            case SSLV3_CHANGE_CIPHER_SPEC:
            case SSLV3_ALERT_PROTOCOL:
            case SSLV3_HANDSHAKE_PROTOCOL:
            case SSLV3_APPLICATION_PROTOCOL:
            case SSLV3_HEARTBEAT_PROTOCOL:
                break;
            default:
                unknown_record = true;
                break;
        }

        /* unknown record type. For TLS 1.0, 1.1 and 1.2 this is ok. For the rest it is fatal. Based
         * on Wireshark logic. */
        if (prev_version == TLS_VERSION_10 || prev_version == TLS_VERSION_11) {
            if (unknown_record) {
                SCLogDebug("unknown record, ignore it");
                SSLSetEvent(ssl_state, TLS_DECODER_EVENT_INVALID_RECORD_TYPE);

                ssl_state->curr_connp->bytes_processed = 0; // TODO review this reset logic
                ssl_state->curr_connp->content_type = 0;
                ssl_state->curr_connp->record_length = 0;
                // restore last good version
                ssl_state->curr_connp->version = prev_version;
                return SSL_DECODER_OK(input_len); // consume everything
            }
        } else {
            if (unknown_record) {
                SCLogDebug("unknown record, fatal");
                SSLSetEvent(ssl_state, TLS_DECODER_EVENT_INVALID_RECORD_TYPE);
                return SSL_DECODER_ERROR(-1);
            }
        }

        /* record_length should never be zero */
        if (ssl_state->curr_connp->record_length == 0) {
            SCLogDebug("SSLv3 Record length is 0");
            SSLSetEvent(ssl_state, TLS_DECODER_EVENT_INVALID_RECORD_LENGTH);
            return SSL_DECODER_ERROR(-1);
        }

        if (!TLSVersionValid(ssl_state->curr_connp->version)) {
            SCLogDebug("ssl_state->curr_connp->version %04x", ssl_state->curr_connp->version);
            SSLSetEvent(ssl_state, TLS_DECODER_EVENT_INVALID_RECORD_VERSION);
            return SSL_DECODER_ERROR(-1);
        }

        if (ssl_state->curr_connp->bytes_processed == SSLV3_RECORD_HDR_LEN &&
                ssl_state->curr_connp->record_length > SSLV3_RECORD_MAX_LEN) {
            SSLSetEvent(ssl_state, TLS_DECODER_EVENT_INVALID_RECORD_LENGTH);
            return SSL_DECODER_ERROR(-1);
        }
        DEBUG_VALIDATE_BUG_ON(ssl_state->curr_connp->bytes_processed > SSLV3_RECORD_HDR_LEN);
    } else {
        ValidateRecordState(ssl_state->curr_connp);

        record_len = (ssl_state->curr_connp->record_length + SSLV3_RECORD_HDR_LEN)- ssl_state->curr_connp->bytes_processed;
        record_len = MIN(input_len, record_len);
    }
    SCLogDebug("record length %u processed %u got %u",
            ssl_state->curr_connp->record_length, ssl_state->curr_connp->bytes_processed, record_len);

    /* if we don't have the full record, we return incomplete */
    if (ssl_state->curr_connp->record_length > input_len - parsed) {
        /* no need to use incomplete api buffering for application
         * records that we'll not use anyway. */
        if (ssl_state->curr_connp->content_type == SSLV3_APPLICATION_PROTOCOL) {
            SCLogDebug("application record");
        } else {
            uint32_t needed = ssl_state->curr_connp->record_length;
            SCLogDebug("record len %u input_len %u parsed %u: need %u bytes more data",
                    ssl_state->curr_connp->record_length, input_len, parsed, needed);
            DEBUG_VALIDATE_BUG_ON(needed > SSLV3_RECORD_MAX_LEN);
            return SSL_DECODER_INCOMPLETE(parsed, needed);
        }
    }

    if (record_len == 0) {
        return SSL_DECODER_OK(parsed);
    }

    AppLayerFrameNewByPointer(ssl_state->f, &stream_slice, input + parsed,
            ssl_state->curr_connp->record_length, direction, TLS_FRAME_DATA);

    switch (ssl_state->curr_connp->content_type) {
        /* we don't need any data from these types */
        case SSLV3_CHANGE_CIPHER_SPEC:
            ssl_state->flags |= SSL_AL_FLAG_CHANGE_CIPHER_SPEC;

            if (direction) {
                ssl_state->flags |= SSL_AL_FLAG_SERVER_CHANGE_CIPHER_SPEC;
            } else {
                ssl_state->flags |= SSL_AL_FLAG_CLIENT_CHANGE_CIPHER_SPEC;

                // TODO TLS 1.3
                UpdateClientState(ssl_state, TLS_STATE_CLIENT_DATA);
            }
            break;

        case SSLV3_ALERT_PROTOCOL: {
            AppLayerFrameNewByPointer(ssl_state->f, &stream_slice, input + parsed,
                    ssl_state->curr_connp->record_length, direction, TLS_FRAME_ALERT_DATA);

            int retval = SSLv3ParseAlertProtocol(ssl_state, input + parsed, record_len, direction);
            if (retval < 0) {
                SCLogDebug("SSLv3ParseAlertProtocol returned %d", retval);
                return SSL_DECODER_ERROR(-1);
            }
            break;
        }
        case SSLV3_APPLICATION_PROTOCOL:
            /* In TLSv1.3 early data (0-RTT) could be sent before the
               handshake is complete (rfc8446, section 2.3). We should
               therefore not mark the handshake as done before we have
               seen the ServerHello record. */
            if ((ssl_state->flags & SSL_AL_FLAG_EARLY_DATA) &&
                    ((ssl_state->flags & SSL_AL_FLAG_STATE_SERVER_HELLO) == 0))
                break;

            /* if we see (encrypted) application data, then this means the
               handshake must be done */
            if (ssl_state->curr_connp == &ssl_state->client_connp) {
                UpdateClientState(ssl_state, TLS_STATE_CLIENT_DATA);
            } else {
                UpdateServerState(ssl_state, TLS_STATE_SERVER_DATA);
            }

            if (ssl_config.encrypt_mode != SSL_CNF_ENC_HANDLE_FULL) {
                SCLogDebug("setting APP_LAYER_PARSER_NO_INSPECTION_PAYLOAD");
                SCAppLayerParserStateSetFlag(pstate, APP_LAYER_PARSER_NO_INSPECTION_PAYLOAD);
            }

            /* Encrypted data, reassembly not asked, bypass asked, let's sacrifice
             * heartbeat lke inspection to be able to be able to bypass the flow */
            if (ssl_config.encrypt_mode == SSL_CNF_ENC_HANDLE_BYPASS) {
                SCLogDebug("setting APP_LAYER_PARSER_NO_REASSEMBLY");
                SCAppLayerParserStateSetFlag(pstate, APP_LAYER_PARSER_NO_REASSEMBLY);
                SCAppLayerParserStateSetFlag(pstate, APP_LAYER_PARSER_NO_INSPECTION);
                SCAppLayerParserStateSetFlag(pstate, APP_LAYER_PARSER_BYPASS_READY);
            }
            break;

        case SSLV3_HANDSHAKE_PROTOCOL: {
            if (ssl_state->flags & SSL_AL_FLAG_CHANGE_CIPHER_SPEC) {
                /* In TLSv1.3, ChangeCipherSpec is only used for middlebox
                   compatibility (rfc8446, appendix D.4). */
                // Client hello flags is needed to have a valid version
                if ((ssl_state->flags & SSL_AL_FLAG_STATE_CLIENT_HELLO) &&
                        (ssl_state->client_connp.version > TLS_VERSION_12) &&
                        ((ssl_state->flags & SSL_AL_FLAG_STATE_SERVER_HELLO) == 0)) {
                    /* do nothing */
                } else {
                    // if we started parsing this, we must stop
                    break;
                }
            }

            if (ssl_state->curr_connp->record_length < 4) {
                SSLParserReset(ssl_state);
                SSLSetEvent(ssl_state, TLS_DECODER_EVENT_INVALID_SSL_RECORD);
                SCLogDebug("record len < 4 => %u", ssl_state->curr_connp->record_length);
                return SSL_DECODER_ERROR(-1);
            }

            int retval = SSLv3ParseHandshakeProtocol(ssl_state, input + parsed,
                                                     record_len, direction);
            SCLogDebug("retval %d", retval);
            if (retval < 0 || retval > (int)record_len) {
                DEBUG_VALIDATE_BUG_ON(retval > (int)record_len);
                SSLSetEvent(ssl_state, TLS_DECODER_EVENT_INVALID_HANDSHAKE_MESSAGE);
                SCLogDebug("SSLv3ParseHandshakeProtocol returned %d", retval);
                return SSL_DECODER_ERROR(-1);
            }
            ValidateRecordState(ssl_state->curr_connp);
            break;
        }
        case SSLV3_HEARTBEAT_PROTOCOL: {
            AppLayerFrameNewByPointer(ssl_state->f, &stream_slice, input + parsed,
                    ssl_state->curr_connp->record_length, direction, TLS_FRAME_HB_DATA);
            int retval = SSLv3ParseHeartbeatProtocol(ssl_state, input + parsed,
                                                 record_len, direction);
            if (retval < 0) {
                SCLogDebug("SSLv3ParseHeartbeatProtocol returned %d", retval);
                return SSL_DECODER_ERROR(-1);
            }
            break;
        }
        default:
            // should be unreachable now that we check after header parsing
            DEBUG_VALIDATE_BUG_ON(1);
            SCLogDebug("unsupported record type");
            return SSL_DECODER_ERROR(-1);
    }

    parsed += record_len;
    ssl_state->curr_connp->bytes_processed += record_len;

    if (ssl_state->curr_connp->bytes_processed >=
            ssl_state->curr_connp->record_length + SSLV3_RECORD_HDR_LEN) {
        SCLogDebug("record complete, trigger RAW");
        SCAppLayerParserTriggerRawStreamInspection(
                ssl_state->f, direction == 0 ? STREAM_TOSERVER : STREAM_TOCLIENT);
        SSLParserReset(ssl_state);
        ValidateRecordState(ssl_state->curr_connp);
        return SSL_DECODER_OK(parsed);

    } else {
        /* we still don't have the entire record for the one we are
           currently parsing */
        ValidateRecordState(ssl_state->curr_connp);
        return SSL_DECODER_OK(parsed);
    }
}

/**
 * \internal
 * \brief SSLv2, SSLv23, SSLv3, TLSv1.1, TLSv1.2, TLSv1.3 parser.
 *
 *        On parsing error, this should be the only function that should reset
 *        the parser state, to avoid multiple functions in the chain resetting
 *        the parser state.
 *
 * \param direction 0 for toserver, 1 for toclient.
 * \param alstate   Pointer to the state.
 * \param pstate    Application layer parser state for this session.
 * \param output    Pointer to the list of parsed output elements.
 *
 * \todo On reaching an inconsistent state, check if the input has
 *  another new record, instead of just returning after the reset
 *
 * \retval >=0 On success.
 */
static AppLayerResult SSLDecode(Flow *f, uint8_t direction, void *alstate,
        AppLayerParserState *pstate, StreamSlice stream_slice)
{
    SSLState *ssl_state = (SSLState *)alstate;
    ssl_state->tx_data.updated_tc = true;
    ssl_state->tx_data.updated_ts = true;
    uint32_t counter = 0;
    ssl_state->f = f;
    const uint8_t *input = StreamSliceGetData(&stream_slice);
    const uint8_t *init_input = input;
    int32_t input_len = (int32_t)StreamSliceGetDataLen(&stream_slice);

    if ((input == NULL || input_len == 0) &&
            ((direction == 0 && SCAppLayerParserStateIssetFlag(pstate, APP_LAYER_PARSER_EOF_TS)) ||
                    (direction == 1 &&
                            SCAppLayerParserStateIssetFlag(pstate, APP_LAYER_PARSER_EOF_TC)))) {
        /* flag session as finished if APP_LAYER_PARSER_EOF is set */
        if (direction == 0)
            UpdateClientState(ssl_state, TLS_STATE_CLIENT_FINISHED);
        else
            UpdateServerState(ssl_state, TLS_STATE_SERVER_FINISHED);
        SCReturnStruct(APP_LAYER_OK);
    } else if (input == NULL || input_len == 0) {
        SCReturnStruct(APP_LAYER_ERROR);
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
            return APP_LAYER_ERROR;
        }

        /* ssl_state->bytes_processed is zero for a fresh record or
           positive to indicate a record currently being parsed */

        if (ssl_state->curr_connp->bytes_processed == 0) {
            if ((input[0] & 0x80) || (input[0] & 0x40)) {
                /* only SSLv2, has one of the top 2 bits set */
                ssl_state->curr_connp->version = SSL_VERSION_2;
                SCLogDebug("SSLv2 detected");
            } else if (ssl_state->curr_connp->version == SSL_VERSION_2) {
                ssl_state->curr_connp->version = TLS_VERSION_UNKNOWN;
                SCLogDebug("SSL/TLS version reset");
            }
        }
        SCLogDebug("record %u: bytes_processed %u, version %02X, input_len %u", counter,
                ssl_state->curr_connp->bytes_processed, ssl_state->curr_connp->version, input_len);

        if (ssl_state->curr_connp->version == SSL_VERSION_2) {
            if (ssl_state->curr_connp->bytes_processed == 0) {
                SCLogDebug("New SSLv2 record parsing");
            } else {
                SCLogDebug("Continuing parsing SSLv2 record");
            }
            struct SSLDecoderResult r =
                    SSLv2Decode(direction, ssl_state, pstate, input, input_len, stream_slice);
            if (r.retval < 0 || r.retval > input_len) {
                DEBUG_VALIDATE_BUG_ON(r.retval > input_len);
                SCLogDebug("Error parsing SSLv2. Resetting parser "
                           "state. Let's get outta here");
                SSLParserReset(ssl_state);
                SSLSetEvent(ssl_state,
                        TLS_DECODER_EVENT_INVALID_SSL_RECORD);
                return APP_LAYER_ERROR;
            } else if (r.needed) {
                input += r.retval;
                SCLogDebug("returning consumed %" PRIuMAX " needed %u",
                        (uintmax_t)(input - init_input), r.needed);
                SCReturnStruct(APP_LAYER_INCOMPLETE((uint32_t)(input - init_input), r.needed));
            }
            input_len -= r.retval;
            input += r.retval;
            SCLogDebug("SSLv2 decoder consumed %d bytes: %u left", r.retval, input_len);
        } else {
            if (ssl_state->curr_connp->bytes_processed == 0) {
                SCLogDebug("New TLS record: record_length %u",
                        ssl_state->curr_connp->record_length);
            } else {
                SCLogDebug("Continuing parsing TLS record: record_length %u, bytes_processed %u",
                        ssl_state->curr_connp->record_length, ssl_state->curr_connp->bytes_processed);
            }
            struct SSLDecoderResult r =
                    SSLv3Decode(direction, ssl_state, pstate, input, input_len, stream_slice);
            if (r.retval < 0 || r.retval > input_len) {
                DEBUG_VALIDATE_BUG_ON(r.retval > input_len);
                SCLogDebug("Error parsing TLS. Resetting parser "
                           "state.  Let's get outta here");
                SSLParserReset(ssl_state);
                return APP_LAYER_ERROR;
            } else if (r.needed) {
                input += r.retval;
                SCLogDebug("returning consumed %" PRIuMAX " needed %u",
                        (uintmax_t)(input - init_input), r.needed);
                SCReturnStruct(APP_LAYER_INCOMPLETE((uint32_t)(input - init_input), r.needed));
            }
            input_len -= r.retval;
            input += r.retval;
            SCLogDebug("TLS decoder consumed %d bytes: %u left", r.retval, input_len);

            if (ssl_state->curr_connp->bytes_processed == SSLV3_RECORD_HDR_LEN
                    && ssl_state->curr_connp->record_length == 0) {
                SCLogDebug("TLS empty record");
                /* empty record */
                SSLParserReset(ssl_state);
            }
        }
        counter++;
    } /* while (input_len) */

    /* mark handshake as done if we have subject and issuer; the
     * certificate data must be complete - a certificate message whose
     * decode failed (even with the rest of the chain decoded) leaves the
     * data incomplete until a certificate message decodes fully, so the
     * tracks must not cross the cert phase on partial data */
    if ((ssl_state->flags & SSL_AL_FLAG_NEED_CLIENT_CERT) &&
            !ssl_state->client_connp.cert_data_incomplete &&
            ssl_state->client_connp.cert0_subject && ssl_state->client_connp.cert0_issuerdn) {
        /* per track: a track's own certificate data decides its own track;
         * pushing the peer track unconditionally would jump it over the
         * certificate phase before its own certificate is parsed (and
         * progression is monotonic, so the phase could never be visited
         * afterwards) */
        UpdateClientState(ssl_state, TLS_STATE_CLIENT_DATA);
        /* an mTLS handshake is complete with the client certificate: by
         * the flight order the server certificate phase was entered
         * already, so advancing the server track skips nothing (matters
         * when its own chain decode failed and no server app data
         * follows) */
        if (ssl_state->server_state >= TLS_STATE_SERVER_CERT) {
            UpdateServerState(ssl_state, TLS_STATE_SERVER_DATA);
        }
    }
    if (!ssl_state->server_connp.cert_data_incomplete && ssl_state->server_connp.cert0_subject &&
            ssl_state->server_connp.cert0_issuerdn) {
        UpdateServerState(ssl_state, TLS_STATE_SERVER_DATA);
    }

    /* flag session as finished if APP_LAYER_PARSER_EOF is set */
    if (SCAppLayerParserStateIssetFlag(pstate, APP_LAYER_PARSER_EOF_TS) &&
            SCAppLayerParserStateIssetFlag(pstate, APP_LAYER_PARSER_EOF_TC)) {
        /* update both sides to keep existing behavior */
        UpdateClientState(ssl_state, TLS_STATE_CLIENT_FINISHED);
        UpdateServerState(ssl_state, TLS_STATE_SERVER_FINISHED);
    }

    return APP_LAYER_OK;
}

/* tls event content readiness: everything the logger may emit must be
 * final. cert0 fields are final as soon as any certificate decoded
 * into the slot - a later undecodable one in the same message does not
 * invalidate them (base parity: the old completion teleport logged on
 * fields alone). Where fields stay empty (resumption, a fully-garbage
 * chain), the track advance beyond the certificate phase makes the
 * data final; a track stuck below it can only end at close, where the
 * end-of-file pass logs. The cert_data_incomplete flag is not needed
 * here: it only gates phase advancement, and loggers run between
 * parses, never during one. A client certificate only matters when
 * one was requested: the CertificateRequest message carries the
 * NEED_CLIENT_CERT flag, so the decision is known from the server
 * flight alone. */
static bool TlsConnpLogReady(const SSLStateConnp *connp, const uint8_t track_done)
{
    if (connp->cert0_subject && connp->cert0_issuerdn) {
        return true;
    }
    return track_done;
}

bool SSLV3TxLogReady(void *tx)
{
    SSLState *ssl_state = (SSLState *)tx;

    if (!TlsConnpLogReady(
                &ssl_state->server_connp, ssl_state->server_state >= TLS_STATE_SERVER_DATA)) {
        return false;
    }
    if (ssl_state->flags & SSL_AL_FLAG_NEED_CLIENT_CERT) {
        if (!TlsConnpLogReady(
                    &ssl_state->client_connp, ssl_state->client_state >= TLS_STATE_CLIENT_DATA)) {
            return false;
        }
    }
    return true;
}

static AppLayerResult SSLParseClientRecord(Flow *f, void *alstate, AppLayerParserState *pstate,
        StreamSlice stream_slice, void *local_data)
{
    return SSLDecode(f, 0 /* toserver */, alstate, pstate, stream_slice);
}

static AppLayerResult SSLParseServerRecord(Flow *f, void *alstate, AppLayerParserState *pstate,
        StreamSlice stream_slice, void *local_data)
{
    return SSLDecode(f, 1 /* toclient */, alstate, pstate, stream_slice);
}

/**
 * \internal
 * \brief Function to allocate the SSL state memory.
 */
static void *SSLStateAlloc(void *orig_state, AppProto proto_orig)
{
    SSLState *ssl_state = SCCalloc(1, sizeof(SSLState));
    if (unlikely(ssl_state == NULL))
        return NULL;
    TAILQ_INIT(&ssl_state->server_connp.certs);
    TAILQ_INIT(&ssl_state->client_connp.certs);

    return (void *)ssl_state;
}

static void SSLStateCertSANFree(SSLStateConnp *connp)
{
    if (connp->cert0_sans) {
        for (uint16_t i = 0; i < connp->cert0_sans_num; i++) {
            SCX509ArrayFree(connp->cert0_sans[i].san, connp->cert0_sans[i].san_len);
        }
        SCFree(connp->cert0_sans);
    }
}

/**
 * \internal
 * \brief Function to free the SSL state memory.
 */
static void SSLStateFree(void *p)
{
    SSLState *ssl_state = (SSLState *)p;
    SSLCertsChain *item;

    if (ssl_state->client_connp.cert0_subject)
        SCX509ArrayFree(
                ssl_state->client_connp.cert0_subject, ssl_state->client_connp.cert0_subject_len);
    if (ssl_state->client_connp.cert0_issuerdn)
        SCX509ArrayFree(
                ssl_state->client_connp.cert0_issuerdn, ssl_state->client_connp.cert0_issuerdn_len);
    if (ssl_state->client_connp.cert0_serial)
        SCX509ArrayFree(
                ssl_state->client_connp.cert0_serial, ssl_state->client_connp.cert0_serial_len);
    if (ssl_state->client_connp.cert0_fingerprint)
        SCFree(ssl_state->client_connp.cert0_fingerprint);
    if (ssl_state->client_connp.sni)
        SCFree(ssl_state->client_connp.sni);
    if (ssl_state->client_connp.session_id)
        SCFree(ssl_state->client_connp.session_id);
    if (ssl_state->client_connp.hs_buffer)
        SCFree(ssl_state->client_connp.hs_buffer);

    if (ssl_state->server_connp.cert0_subject)
        SCX509ArrayFree(
                ssl_state->server_connp.cert0_subject, ssl_state->server_connp.cert0_subject_len);
    if (ssl_state->server_connp.cert0_issuerdn)
        SCX509ArrayFree(
                ssl_state->server_connp.cert0_issuerdn, ssl_state->server_connp.cert0_issuerdn_len);
    if (ssl_state->server_connp.cert0_serial)
        SCX509ArrayFree(
                ssl_state->server_connp.cert0_serial, ssl_state->server_connp.cert0_serial_len);
    if (ssl_state->server_connp.cert0_fingerprint)
        SCFree(ssl_state->server_connp.cert0_fingerprint);
    if (ssl_state->server_connp.sni)
        SCFree(ssl_state->server_connp.sni);
    if (ssl_state->server_connp.session_id)
        SCFree(ssl_state->server_connp.session_id);

    if (ssl_state->client_connp.hs)
        SCTLSHandshakeFree(ssl_state->client_connp.hs);
    if (ssl_state->client_connp.ja3_str)
        Ja3BufferFree(&ssl_state->client_connp.ja3_str);
    if (ssl_state->client_connp.ja3_hash)
        SCFree(ssl_state->client_connp.ja3_hash);
    if (ssl_state->server_connp.hs)
        SCTLSHandshakeFree(ssl_state->server_connp.hs);
    if (ssl_state->server_connp.ja3_str)
        Ja3BufferFree(&ssl_state->server_connp.ja3_str);
    if (ssl_state->server_connp.ja3_hash)
        SCFree(ssl_state->server_connp.ja3_hash);
    if (ssl_state->server_connp.hs_buffer)
        SCFree(ssl_state->server_connp.hs_buffer);

    SSLStateCertSANFree(&ssl_state->server_connp);
    SSLStateCertSANFree(&ssl_state->client_connp);

    SCAppLayerTxDataCleanup(&ssl_state->tx_data);

    /* Free certificate chain */
    if (ssl_state->server_connp.certs_buffer)
        SCFree(ssl_state->server_connp.certs_buffer);
    while ((item = TAILQ_FIRST(&ssl_state->server_connp.certs))) {
        TAILQ_REMOVE(&ssl_state->server_connp.certs, item, next);
        SCFree(item);
    }
    TAILQ_INIT(&ssl_state->server_connp.certs);
    /* Free certificate chain */
    if (ssl_state->client_connp.certs_buffer)
        SCFree(ssl_state->client_connp.certs_buffer);
    while ((item = TAILQ_FIRST(&ssl_state->client_connp.certs))) {
        TAILQ_REMOVE(&ssl_state->client_connp.certs, item, next);
        SCFree(item);
    }
    TAILQ_INIT(&ssl_state->client_connp.certs);

    SCFree(ssl_state);
}

static void SSLStateTransactionFree(void *state, uint64_t tx_id)
{
    /* do nothing */
}

static AppProto SSLProbingParser(
        const Flow *f, uint8_t direction, const uint8_t *input, uint32_t ilen, uint8_t *rdir)
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

static int SSLStateGetStateIdByName(const char *name, const uint8_t direction)
{
    SCEnumCharMap *map =
            direction == STREAM_TOSERVER ? tls_state_client_table : tls_state_server_table;

    int id = SCMapEnumNameToValue(name, map);
    if (id < 0) {
        return -1;
    }
    return id;
}

static const char *SSLStateGetStateNameById(const int id, const uint8_t direction)
{
    SCEnumCharMap *map =
            direction == STREAM_TOSERVER ? tls_state_client_table : tls_state_server_table;
    const char *name = SCMapEnumValueToName(id, map);
    return name;
}

static int SSLStateGetFrameIdByName(const char *frame_name)
{
    int id = SCMapEnumNameToValue(frame_name, tls_frame_table);
    if (id < 0) {
        return -1;
    }
    return id;
}

static const char *SSLStateGetFrameNameById(const uint8_t frame_id)
{
    const char *name = SCMapEnumValueToName(frame_id, tls_frame_table);
    return name;
}

static int SSLStateGetEventInfo(
        const char *event_name, uint8_t *event_id, AppLayerEventType *event_type)
{
    if (SCAppLayerGetEventIdByName(event_name, tls_decoder_event_table, event_id) == 0) {
        *event_type = APP_LAYER_EVENT_TYPE_TRANSACTION;
        return 0;
    }
    return -1;
}

static int SSLStateGetEventInfoById(
        uint8_t event_id, const char **event_name, AppLayerEventType *event_type)
{
    *event_name = SCMapEnumValueToName(event_id, tls_decoder_event_table);
    if (*event_name == NULL) {
        SCLogError("event \"%d\" not present in "
                   "ssl's enum map table.",
                event_id);
        /* yes this is fatal */
        return -1;
    }

    *event_type = APP_LAYER_EVENT_TYPE_TRANSACTION;

    return 0;
}

static int SSLRegisterPatternsForProtocolDetection(void)
{
    if (SCAppLayerProtoDetectPMRegisterPatternCSwPP(IPPROTO_TCP, ALPROTO_TLS, "|01 00 02|", 5, 2,
                STREAM_TOSERVER, SSLProbingParser, 0, 3) < 0) {
        return -1;
    }

    /** SSLv3 */
    if (SCAppLayerProtoDetectPMRegisterPatternCS(
                IPPROTO_TCP, ALPROTO_TLS, "|01 03 00|", 3, 0, STREAM_TOSERVER) < 0) {
        return -1;
    }
    if (SCAppLayerProtoDetectPMRegisterPatternCS(
                IPPROTO_TCP, ALPROTO_TLS, "|16 03 00|", 3, 0, STREAM_TOSERVER) < 0) {
        return -1;
    }

    /** TLSv1 */
    if (SCAppLayerProtoDetectPMRegisterPatternCS(
                IPPROTO_TCP, ALPROTO_TLS, "|01 03 01|", 3, 0, STREAM_TOSERVER) < 0) {
        return -1;
    }
    if (SCAppLayerProtoDetectPMRegisterPatternCS(
                IPPROTO_TCP, ALPROTO_TLS, "|16 03 01|", 3, 0, STREAM_TOSERVER) < 0) {
        return -1;
    }

    /** TLSv1.1 */
    if (SCAppLayerProtoDetectPMRegisterPatternCS(
                IPPROTO_TCP, ALPROTO_TLS, "|01 03 02|", 3, 0, STREAM_TOSERVER) < 0) {
        return -1;
    }
    if (SCAppLayerProtoDetectPMRegisterPatternCS(
                IPPROTO_TCP, ALPROTO_TLS, "|16 03 02|", 3, 0, STREAM_TOSERVER) < 0) {
        return -1;
    }

    /** TLSv1.2 */
    if (SCAppLayerProtoDetectPMRegisterPatternCS(
                IPPROTO_TCP, ALPROTO_TLS, "|01 03 03|", 3, 0, STREAM_TOSERVER) < 0) {
        return -1;
    }
    if (SCAppLayerProtoDetectPMRegisterPatternCS(
                IPPROTO_TCP, ALPROTO_TLS, "|16 03 03|", 3, 0, STREAM_TOSERVER) < 0) {
        return -1;
    }

    /***** toclient direction *****/

    if (SCAppLayerProtoDetectPMRegisterPatternCS(
                IPPROTO_TCP, ALPROTO_TLS, "|15 03 00|", 3, 0, STREAM_TOCLIENT) < 0) {
        return -1;
    }
    if (SCAppLayerProtoDetectPMRegisterPatternCS(
                IPPROTO_TCP, ALPROTO_TLS, "|16 03 00|", 3, 0, STREAM_TOCLIENT) < 0) {
        return -1;
    }
    if (SCAppLayerProtoDetectPMRegisterPatternCS(
                IPPROTO_TCP, ALPROTO_TLS, "|17 03 00|", 3, 0, STREAM_TOCLIENT) < 0) {
        return -1;
    }

    /** TLSv1 */
    if (SCAppLayerProtoDetectPMRegisterPatternCS(
                IPPROTO_TCP, ALPROTO_TLS, "|15 03 01|", 3, 0, STREAM_TOCLIENT) < 0) {
        return -1;
    }
    if (SCAppLayerProtoDetectPMRegisterPatternCS(
                IPPROTO_TCP, ALPROTO_TLS, "|16 03 01|", 3, 0, STREAM_TOCLIENT) < 0) {
        return -1;
    }
    if (SCAppLayerProtoDetectPMRegisterPatternCS(
                IPPROTO_TCP, ALPROTO_TLS, "|17 03 01|", 3, 0, STREAM_TOCLIENT) < 0) {
        return -1;
    }

    /** TLSv1.1 */
    if (SCAppLayerProtoDetectPMRegisterPatternCS(
                IPPROTO_TCP, ALPROTO_TLS, "|15 03 02|", 3, 0, STREAM_TOCLIENT) < 0) {
        return -1;
    }
    if (SCAppLayerProtoDetectPMRegisterPatternCS(
                IPPROTO_TCP, ALPROTO_TLS, "|16 03 02|", 3, 0, STREAM_TOCLIENT) < 0) {
        return -1;
    }
    if (SCAppLayerProtoDetectPMRegisterPatternCS(
                IPPROTO_TCP, ALPROTO_TLS, "|17 03 02|", 3, 0, STREAM_TOCLIENT) < 0) {
        return -1;
    }

    /** TLSv1.2 */
    if (SCAppLayerProtoDetectPMRegisterPatternCS(
                IPPROTO_TCP, ALPROTO_TLS, "|15 03 03|", 3, 0, STREAM_TOCLIENT) < 0) {
        return -1;
    }
    if (SCAppLayerProtoDetectPMRegisterPatternCS(
                IPPROTO_TCP, ALPROTO_TLS, "|16 03 03|", 3, 0, STREAM_TOCLIENT) < 0) {
        return -1;
    }
    if (SCAppLayerProtoDetectPMRegisterPatternCS(
                IPPROTO_TCP, ALPROTO_TLS, "|17 03 03|", 3, 0, STREAM_TOCLIENT) < 0) {
        return -1;
    }

    /* Subsection - SSLv2 style record by client, but informing the server
     * the max version it supports.
     * Updated by Anoop Saldanha.  Disabled it for now.  We'll get back to
     * it after some tests */
#if 0
    if (SCAppLayerProtoDetectPMRegisterPatternCS(IPPROTO_TCP, ALPROTO_TLS,
                                               "|01 03 00|", 5, 2, STREAM_TOSERVER) < 0)
    {
        return -1;
    }
    if (SCAppLayerProtoDetectPMRegisterPatternCS(IPPROTO_TCP, ALPROTO_TLS,
                                               "|00 02|", 7, 5, STREAM_TOCLIENT) < 0)
    {
        return -1;
    }
#endif

    return 0;
}

#ifdef HAVE_JA3
static void CheckJA3Enabled(void)
{
    const char *strval = NULL;
    /* Check if we should generate JA3 fingerprints */
    int enable_ja3 = SSL_CONFIG_DEFAULT_JA3;
    if (SCConfGetNonNull("app-layer.protocols.tls.ja3-fingerprints", &strval) != 1) {
        enable_ja3 = SSL_CONFIG_DEFAULT_JA3;
    } else if (strcmp(strval, "auto") == 0) {
        enable_ja3 = SSL_CONFIG_DEFAULT_JA3;
    } else if (SCConfValIsFalse(strval)) {
        enable_ja3 = 0;
        ssl_config.disable_ja3 = true;
    } else if (SCConfValIsTrue(strval)) {
        enable_ja3 = true;
    }
    SC_ATOMIC_SET(ssl_config.enable_ja3, enable_ja3);
    if (!ssl_config.disable_ja3 && !g_disable_hashing) {
        /* The feature is available, i.e. _could_ be activated by a rule or
            even is enabled in the configuration. */
        ProvidesFeature(FEATURE_JA3);
    }
}
#endif /* HAVE_JA3 */

#ifdef HAVE_JA4
static void CheckJA4Enabled(void)
{
    const char *strval = NULL;
    /* Check if we should generate JA4 fingerprints */
    int enable_ja4 = SSL_CONFIG_DEFAULT_JA4;
    if (SCConfGetNonNull("app-layer.protocols.tls.ja4-fingerprints", &strval) != 1) {
        enable_ja4 = SSL_CONFIG_DEFAULT_JA4;
    } else if (strcmp(strval, "auto") == 0) {
        enable_ja4 = SSL_CONFIG_DEFAULT_JA4;
    } else if (SCConfValIsFalse(strval)) {
        enable_ja4 = 0;
        ssl_config.disable_ja4 = true;
    } else if (SCConfValIsTrue(strval)) {
        enable_ja4 = true;
    }
    SC_ATOMIC_SET(ssl_config.enable_ja4, enable_ja4);
    if (!ssl_config.disable_ja4 && !g_disable_hashing) {
        /* The feature is available, i.e. _could_ be activated by a rule or
            even is enabled in the configuration. */
        ProvidesFeature(FEATURE_JA4);
    }
}
#endif /* HAVE_JA4 */

/**
 * \brief Function to register the SSL protocol parser and other functions
 */
#ifdef UNITTESTS
void SSLStateParserRegisterTests(void);
#endif /* UNITTESTS */

void RegisterSSLParsers(void)
{
    const char *proto_name = "tls";

    SC_ATOMIC_INIT(ssl_config.enable_ja3);

    /** SSLv2  and SSLv23*/
    if (SCAppLayerProtoDetectConfProtoDetectionEnabled("tcp", proto_name)) {
        AppLayerProtoDetectRegisterProtocol(ALPROTO_TLS, proto_name);

        if (SSLRegisterPatternsForProtocolDetection() < 0)
            return;

        if (RunmodeIsUnittests()) {
            SCAppLayerProtoDetectPPRegister(
                    IPPROTO_TCP, "443", ALPROTO_TLS, 0, 3, STREAM_TOSERVER, SSLProbingParser, NULL);
        } else {
            if (SCAppLayerProtoDetectPPParseConfPorts("tcp", IPPROTO_TCP, proto_name, ALPROTO_TLS,
                        0, 3, SSLProbingParser, NULL) == 0) {
                SCLogConfig("no TLS config found, "
                            "enabling TLS detection on port 443.");
                SCAppLayerProtoDetectPPRegister(IPPROTO_TCP, "443", ALPROTO_TLS, 0, 3,
                        STREAM_TOSERVER, SSLProbingParser, NULL);
            }
        }
    } else {
        SCLogConfig("Protocol detection and parser disabled for %s protocol",
                  proto_name);
        return;
    }

    if (SCAppLayerParserConfParserEnabled("tcp", proto_name)) {
        AppLayerParserRegisterParser(IPPROTO_TCP, ALPROTO_TLS, STREAM_TOSERVER,
                                     SSLParseClientRecord);

        AppLayerParserRegisterParser(IPPROTO_TCP, ALPROTO_TLS, STREAM_TOCLIENT,
                                     SSLParseServerRecord);
        AppLayerParserRegisterGetStateFuncs(
                IPPROTO_TCP, ALPROTO_TLS, SSLStateGetStateIdByName, SSLStateGetStateNameById);
        AppLayerParserRegisterGetFrameFuncs(
                IPPROTO_TCP, ALPROTO_TLS, SSLStateGetFrameIdByName, SSLStateGetFrameNameById);
        AppLayerParserRegisterGetEventInfo(IPPROTO_TCP, ALPROTO_TLS, SSLStateGetEventInfo);
        AppLayerParserRegisterGetEventInfoById(IPPROTO_TCP, ALPROTO_TLS, SSLStateGetEventInfoById);

        AppLayerParserRegisterStateFuncs(IPPROTO_TCP, ALPROTO_TLS, SSLStateAlloc, SSLStateFree);

        SCAppLayerParserRegisterParserAcceptableDataDirection(
                IPPROTO_TCP, ALPROTO_TLS, STREAM_TOSERVER);

        AppLayerParserRegisterTxFreeFunc(IPPROTO_TCP, ALPROTO_TLS, SSLStateTransactionFree);

        AppLayerParserRegisterGetTx(IPPROTO_TCP, ALPROTO_TLS, SSLGetTx);
        AppLayerParserRegisterTxDataFunc(IPPROTO_TCP, ALPROTO_TLS, SSLGetTxData);
        AppLayerParserRegisterStateDataFunc(IPPROTO_TCP, ALPROTO_TLS, SSLGetStateData);

        AppLayerParserRegisterGetTxCnt(IPPROTO_TCP, ALPROTO_TLS, SSLGetTxCnt);

        AppLayerParserRegisterGetStateProgressFunc(IPPROTO_TCP, ALPROTO_TLS, SSLGetAlstateProgress);

        AppLayerParserRegisterStateProgressCompletionStatus(
                ALPROTO_TLS, TLS_STATE_CLIENT_FINISHED, TLS_STATE_SERVER_FINISHED);

#ifdef UNITTESTS
        AppLayerParserRegisterProtocolUnittests(
                IPPROTO_TCP, ALPROTO_TLS, SSLStateParserRegisterTests);
#endif /* UNITTESTS */

        SCConfNode *enc_handle = SCConfGetNode("app-layer.protocols.tls.encryption-handling");
        if (enc_handle != NULL && enc_handle->val != NULL) {
            SCLogDebug("have app-layer.protocols.tls.encryption-handling = %s", enc_handle->val);
            if (strcmp(enc_handle->val, "full") == 0) {
                ssl_config.encrypt_mode = SSL_CNF_ENC_HANDLE_FULL;
            } else if (strcmp(enc_handle->val, "bypass") == 0) {
                ssl_config.encrypt_mode = SSL_CNF_ENC_HANDLE_BYPASS;
            } else if (strcmp(enc_handle->val, "track-only") == 0) {
                ssl_config.encrypt_mode = SSL_CNF_ENC_HANDLE_TRACK_ONLY;
            } else if (strcmp(enc_handle->val, "default") == 0) {
                SCLogWarning("app-layer.protocols.tls.encryption-handling = default is deprecated "
                             "and will be removed in Suricata 9, use \"track-only\" instead, "
                             "(see ticket #7642)");
                ssl_config.encrypt_mode = SSL_CNF_ENC_HANDLE_TRACK_ONLY;
            } else {
                ssl_config.encrypt_mode = SSL_CNF_ENC_HANDLE_TRACK_ONLY;
            }
        } else {
            /* Get the value of no reassembly option from the config file */
            if (SCConfGetNode("app-layer.protocols.tls.no-reassemble") == NULL) {
                int value = 0;
                if (SCConfGetBool("tls.no-reassemble", &value) == 1 && value == 1)
                    ssl_config.encrypt_mode = SSL_CNF_ENC_HANDLE_BYPASS;
            } else {
                int value = 0;
                if (SCConfGetBool("app-layer.protocols.tls.no-reassemble", &value) == 1 &&
                        value == 1)
                    ssl_config.encrypt_mode = SSL_CNF_ENC_HANDLE_BYPASS;
            }
        }
        SCLogDebug("ssl_config.encrypt_mode %u", ssl_config.encrypt_mode);

#ifdef HAVE_JA3
        CheckJA3Enabled();
#endif /* HAVE_JA3 */
#ifdef HAVE_JA4
        CheckJA4Enabled();
#endif /* HAVE_JA4 */

        if (g_disable_hashing) {
            if (SC_ATOMIC_GET(ssl_config.enable_ja3)) {
                SCLogWarning("MD5 calculation has been disabled, disabling JA3");
                SC_ATOMIC_SET(ssl_config.enable_ja3, 0);
            }
            if (SC_ATOMIC_GET(ssl_config.enable_ja4)) {
                SCLogWarning("Hashing has been disabled, disabling JA4");
                SC_ATOMIC_SET(ssl_config.enable_ja4, 0);
            }
        } else {
            if (RunmodeIsUnittests()) {
#ifdef HAVE_JA3
                SC_ATOMIC_SET(ssl_config.enable_ja3, 1);
#endif /* HAVE_JA3 */
#ifdef HAVE_JA4
                SC_ATOMIC_SET(ssl_config.enable_ja4, 1);
#endif /* HAVE_JA4 */
            }
        }
    } else {
        SCLogConfig("Parser disabled for %s protocol. Protocol detection still on.", proto_name);
    }
}

/**
 * \brief if not explicitly disabled in config, enable ja3 support
 *
 * Implemented using atomic to allow rule reloads to do this at
 * runtime.
 */
void SSLEnableJA3(void)
{
    if (g_disable_hashing || ssl_config.disable_ja3) {
        return;
    }
    if (SC_ATOMIC_GET(ssl_config.enable_ja3)) {
        return;
    }
    SC_ATOMIC_SET(ssl_config.enable_ja3, 1);
}

/**
 * \brief if not explicitly disabled in config, enable ja4 support
 *
 * Implemented using atomic to allow rule reloads to do this at
 * runtime.
 */
void SSLEnableJA4(void)
{
    // only caller has #ifdef HAVE_JA4
    if (g_disable_hashing || ssl_config.disable_ja4) {
        return;
    }
    if (SC_ATOMIC_GET(ssl_config.enable_ja4)) {
        return;
    }
    SC_ATOMIC_SET(ssl_config.enable_ja4, 1);
}

/**
 * \brief return whether ja3 is effectively enabled
 *
 * This means that it either has been enabled explicitly or has been
 * enabled by having loaded a rule while not being explicitly disabled.
 *
 * \retval true if enabled, false otherwise
 */
bool SSLJA3IsEnabled(void)
{
    return SC_ATOMIC_GET(ssl_config.enable_ja3);
}

/**
 * \brief return whether ja4 is effectively enabled
 *
 * This means that it either has been enabled explicitly or has been
 * enabled by having loaded a rule while not being explicitly disabled.
 *
 * \retval true if enabled, false otherwise
 */
bool SSLJA4IsEnabled(void)
{
    return SC_ATOMIC_GET(ssl_config.enable_ja4);
}

#ifdef UNITTESTS
static int TLSPhaseStateTestClient(void)
{
    const char *names[] = { "client_started", "client_hello", "client_cert", "client_data",
        "client_finished" };
    for (int i = 0; i < 5; i++) {
        FAIL_IF(AppLayerParserGetStateIdByName(
                        IPPROTO_TCP, ALPROTO_TLS, names[i], STREAM_TOSERVER) != i);
        FAIL_IF(strcmp(AppLayerParserGetStateNameById(IPPROTO_TCP, ALPROTO_TLS, i, STREAM_TOSERVER),
                        names[i]) != 0);
    }
    PASS;
}

static int TLSPhaseStateTestServer(void)
{
    const char *names[] = { "server_started", "server_hello", "server_cert", "server_data",
        "server_finished" };
    for (int i = 0; i < 5; i++) {
        FAIL_IF(AppLayerParserGetStateIdByName(
                        IPPROTO_TCP, ALPROTO_TLS, names[i], STREAM_TOCLIENT) != i);
        FAIL_IF(strcmp(AppLayerParserGetStateNameById(IPPROTO_TCP, ALPROTO_TLS, i, STREAM_TOCLIENT),
                        names[i]) != 0);
    }
    PASS;
}

static int TLSPhaseStateTestOldNamesGone(void)
{
    const char *old_client[] = { "client_in_progress", "client_hello_done", "client_cert_done",
        "client_handshake_done" };
    const char *old_server[] = { "server_in_progress", "server_hello_done", "server_cert_done",
        "server_handshake_done" };
    for (int i = 0; i < 4; i++) {
        FAIL_IF(AppLayerParserGetStateIdByName(
                        IPPROTO_TCP, ALPROTO_TLS, old_client[i], STREAM_TOSERVER) >= 0);
        FAIL_IF(AppLayerParserGetStateIdByName(
                        IPPROTO_TCP, ALPROTO_TLS, old_server[i], STREAM_TOCLIENT) >= 0);
    }
    PASS;
}

static int TLSPhaseStateTestCompletion(void)
{
    FAIL_IF(AppLayerParserGetStateProgressCompletionStatus(ALPROTO_TLS, STREAM_TOSERVER) != 4);
    FAIL_IF(AppLayerParserGetStateProgressCompletionStatus(ALPROTO_TLS, STREAM_TOCLIENT) != 4);
    /* progression is monotonic: a backwards write is a no-op (a peer track
     * shortcut must never undo a phase), an equal write passes */
    SSLState *ssl_state = SSLStateAlloc(NULL, ALPROTO_TLS);
    FAIL_IF(ssl_state == NULL);
    UpdateServerState(ssl_state, TLS_STATE_SERVER_DATA);
    UpdateServerState(ssl_state, TLS_STATE_SERVER_CERT);
    FAIL_IF(ssl_state->server_state != TLS_STATE_SERVER_DATA);
    UpdateServerState(ssl_state, TLS_STATE_SERVER_DATA);
    FAIL_IF(ssl_state->server_state != TLS_STATE_SERVER_DATA);
    SSLStateFree(ssl_state);
    PASS;
}

/* Drive a truncated ClientHello, a valid ServerHello and a garbage
 * Certificate through the handshake parser: a message enters its phase
 * at its start, a failed decode blocks only the hand-over to the next
 * phase - the bytes are consumed, the next message parses normally, and
 * a hello failure keeps the track in the hello phase. */
static int TLSPhaseSuppressionTest(void)
{
    SSLState *ssl_state = SSLStateAlloc(NULL, ALPROTO_TLS);
    if (ssl_state == NULL)
        return 0;

    /* P4: ClientHello, message length 6 - version parses, random
     * truncated */
    const uint8_t p4[] = { 0x01, 0x00, 0x00, 0x06, 0x03, 0x03, 0x01, 0x02, 0x03, 0x04 };
    /* P5: valid ServerHello (version, random, session id, selected
     * cipher, compression; no extensions - optional per RFC5246) */
    uint8_t p5[4 + 2 + 32 + 1 + 1 + 2 + 1];
    int i;
    int rc;

    p5[0] = 0x02;
    p5[1] = 0;
    p5[2] = 0;
    p5[3] = 39;
    p5[4] = 0x03;
    p5[5] = 0x03;
    for (i = 0; i < 32; i++)
        p5[6 + i] = (uint8_t)i;
    p5[38] = 1;    /* session id length */
    p5[39] = 0xaa; /* session id */
    p5[40] = 0x13;
    p5[41] = 0x01; /* selected cipher suite */
    p5[42] = 0x00; /* compression */
    /* P6: Certificate with a 10-byte garbage body (not ASN.1) */
    const uint8_t p6[] = { 0x0b, 0x00, 0x00, 0x10, 0x00, 0x00, 0x0d, 0x00, 0x00, 0x0a, 0x41, 0x41,
        0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41 };

    /* truncated hello: entered at its start, the failed decode blocks
     * the hand-over, so the client stays in client_hello */
    ssl_state->curr_connp = &ssl_state->client_connp;
    ssl_state->curr_connp->record_length = sizeof(p4);
    ssl_state->curr_connp->bytes_processed = 0;
    ssl_state->curr_connp->version = 0x0303;
    rc = SSLv3ParseHandshakeProtocol(ssl_state, p4, sizeof(p4), 0);
    FAIL_IF(rc < 0);
    FAIL_IF(!ssl_state->client_connp.phase_suppressed);
    FAIL_IF(ssl_state->client_state != TLS_STATE_CLIENT_HELLO);

    /* valid hello: the flag is reset per message, completion hands the
     * track to the cert phase */
    ssl_state->curr_connp = &ssl_state->server_connp;
    ssl_state->curr_connp->record_length = sizeof(p5);
    ssl_state->curr_connp->bytes_processed = 0;
    ssl_state->curr_connp->version = 0x0303;
    rc = SSLv3ParseHandshakeProtocol(ssl_state, p5, sizeof(p5), 1);
    FAIL_IF(rc < 0);
    FAIL_IF(ssl_state->server_connp.phase_suppressed);
    FAIL_IF(ssl_state->server_state != TLS_STATE_SERVER_CERT);
    /* the cert phase is entered with the hello, the chain is not
     * parsed yet: chain content is not final */
    FAIL_IF(ssl_state->server_connp.cert_chain_final);

    /* garbage certificate: the cert phase was entered at the message
     * header, the failed decode keeps the track in it; the suppression
     * flag is hello-specific */
    ssl_state->curr_connp = &ssl_state->server_connp;
    ssl_state->curr_connp->record_length = sizeof(p6);
    ssl_state->curr_connp->bytes_processed = 0;
    rc = SSLv3ParseHandshakeProtocol(ssl_state, p6, sizeof(p6), 1);
    FAIL_IF(rc < 0);
    FAIL_IF(ssl_state->server_connp.phase_suppressed);
    FAIL_IF(!ssl_state->server_connp.cert_data_incomplete);
    FAIL_IF(ssl_state->server_state != TLS_STATE_SERVER_CERT);
    FAIL_IF(ssl_state->server_connp.cert_chain_final);

    SSLStateFree(ssl_state);
    PASS;
}

/* A Certificate message whose first certificate is undecodable but whose
 * remaining certificates are valid: the bad leaf is skipped (one decoder
 * event), the rest of the chain is kept and the cert0 fields are filled
 * from the first decodable certificate (compared against a direct
 * extraction from the fixture). The message enters the cert phase at its
 * start; the incomplete-data condition is sticky - a following
 * ServerHelloDone resets the per-message suppression but the track stays
 * in the cert phase, out of the data phase. The valid certificate body
 * is the same fixture as the sv test ruletype-firewall-153 client
 * certificate. */
static int TLSPhaseCertChainSkipTest(void)
{
    static const uint8_t valid_cert[] = { 0x30, 0x82, 0x03, 0x0b, 0x30, 0x82, 0x01, 0xf3, 0xa0,
        0x03, 0x02, 0x01, 0x02, 0x02, 0x14, 0x16, 0x1b, 0x77, 0xa9, 0xae, 0xe9, 0xea, 0xaa, 0x2d,
        0xf9, 0xbb, 0xd6, 0xda, 0x13, 0x92, 0xf8, 0x73, 0xf8, 0x93, 0xa0, 0x30, 0x0d, 0x06, 0x09,
        0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b, 0x05, 0x00, 0x30, 0x15, 0x31, 0x13,
        0x30, 0x11, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x0a, 0x63, 0x6c, 0x69, 0x65, 0x6e, 0x74,
        0x74, 0x65, 0x73, 0x74, 0x30, 0x1e, 0x17, 0x0d, 0x32, 0x36, 0x30, 0x39, 0x31, 0x38, 0x30,
        0x33, 0x34, 0x38, 0x35, 0x36, 0x5a, 0x17, 0x0d, 0x32, 0x36, 0x30, 0x39, 0x32, 0x30, 0x30,
        0x33, 0x34, 0x38, 0x35, 0x36, 0x5a, 0x30, 0x15, 0x31, 0x13, 0x30, 0x11, 0x06, 0x03, 0x55,
        0x04, 0x03, 0x0c, 0x0a, 0x63, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x74, 0x65, 0x73, 0x74, 0x30,
        0x82, 0x01, 0x22, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01,
        0x01, 0x05, 0x00, 0x03, 0x82, 0x01, 0x0f, 0x00, 0x30, 0x82, 0x01, 0x0a, 0x02, 0x82, 0x01,
        0x01, 0x00, 0xc7, 0xdc, 0x32, 0x3c, 0x76, 0x5d, 0x86, 0x02, 0xbd, 0x3e, 0xc0, 0x8e, 0x6f,
        0x34, 0x7e, 0xa2, 0x2c, 0x66, 0xe4, 0x20, 0x2f, 0x1c, 0xf4, 0x6c, 0x4d, 0xb6, 0x8e, 0xed,
        0x5c, 0xdf, 0x36, 0xdb, 0xa8, 0xea, 0xf9, 0x01, 0xbe, 0x20, 0x92, 0x85, 0x72, 0x9c, 0x5d,
        0x19, 0xf5, 0xa1, 0xa6, 0xdf, 0x60, 0x17, 0xc3, 0xba, 0xb7, 0xed, 0x57, 0x99, 0x19, 0x46,
        0xee, 0xb2, 0x04, 0xfe, 0x18, 0x17, 0x65, 0x62, 0xe2, 0xd7, 0x45, 0xb1, 0x0f, 0x0c, 0xc8,
        0x6b, 0xe4, 0x63, 0x4a, 0x6b, 0xd9, 0x30, 0xae, 0xf5, 0x81, 0xc5, 0xac, 0x50, 0x51, 0xc6,
        0x91, 0x5c, 0x78, 0xc0, 0x74, 0x2a, 0x47, 0x6b, 0xae, 0xc3, 0x4b, 0x7d, 0x54, 0x66, 0x0d,
        0xd7, 0xa1, 0x81, 0x07, 0x80, 0x44, 0xba, 0x30, 0x02, 0xeb, 0x82, 0x3c, 0x78, 0xbb, 0x9f,
        0x2b, 0xeb, 0x1b, 0x1c, 0x30, 0x41, 0x02, 0xeb, 0xf5, 0x9c, 0xb3, 0xef, 0x43, 0x52, 0x4b,
        0x54, 0x1f, 0xf3, 0x0d, 0xeb, 0xcc, 0x25, 0x97, 0xda, 0x52, 0x07, 0xdf, 0x54, 0x35, 0x4b,
        0x85, 0x63, 0x67, 0xd6, 0x60, 0x9f, 0x0f, 0x88, 0xbf, 0x7e, 0xc9, 0x44, 0x2f, 0x34, 0xd6,
        0x28, 0xad, 0x2d, 0x59, 0x7e, 0x56, 0xb6, 0x73, 0x5a, 0xe0, 0xb0, 0x1c, 0xc9, 0x23, 0x5f,
        0x2a, 0x3c, 0x46, 0x1c, 0x27, 0x7f, 0x0e, 0x25, 0x16, 0x19, 0xb0, 0x03, 0x71, 0x05, 0xd5,
        0xc6, 0xed, 0x49, 0x7c, 0x90, 0xca, 0x94, 0xfb, 0xe4, 0x75, 0x23, 0x67, 0x17, 0x37, 0x08,
        0x05, 0xb8, 0x58, 0x7f, 0x61, 0x16, 0x24, 0x91, 0xeb, 0x0c, 0x1c, 0x05, 0x0d, 0xa5, 0x45,
        0x55, 0x03, 0x2e, 0x60, 0x15, 0xc4, 0x6b, 0xcb, 0x68, 0x1f, 0xec, 0xbe, 0x59, 0xbf, 0x4a,
        0x93, 0x0b, 0xa3, 0x08, 0x86, 0xe0, 0xe9, 0x5c, 0x08, 0x23, 0x3b, 0x0f, 0xbd, 0xc9, 0x91,
        0xa1, 0x48, 0xf9, 0x02, 0x03, 0x01, 0x00, 0x01, 0xa3, 0x53, 0x30, 0x51, 0x30, 0x1d, 0x06,
        0x03, 0x55, 0x1d, 0x0e, 0x04, 0x16, 0x04, 0x14, 0xae, 0xed, 0xef, 0x6c, 0xe0, 0xf6, 0xb7,
        0xe3, 0x8c, 0xd9, 0x37, 0x7f, 0x0b, 0x53, 0x36, 0x96, 0x06, 0x5d, 0x0f, 0x09, 0x30, 0x1f,
        0x06, 0x03, 0x55, 0x1d, 0x23, 0x04, 0x18, 0x30, 0x16, 0x80, 0x14, 0xae, 0xed, 0xef, 0x6c,
        0xe0, 0xf6, 0xb7, 0xe3, 0x8c, 0xd9, 0x37, 0x7f, 0x0b, 0x53, 0x36, 0x96, 0x06, 0x5d, 0x0f,
        0x09, 0x30, 0x0f, 0x06, 0x03, 0x55, 0x1d, 0x13, 0x01, 0x01, 0xff, 0x04, 0x05, 0x30, 0x03,
        0x01, 0x01, 0xff, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01,
        0x0b, 0x05, 0x00, 0x03, 0x82, 0x01, 0x01, 0x00, 0x08, 0x2e, 0x15, 0x02, 0x17, 0xcb, 0xf8,
        0x5b, 0x4b, 0x31, 0x47, 0xf4, 0x8d, 0x55, 0x53, 0xa4, 0x05, 0x46, 0x73, 0xb7, 0x6a, 0x79,
        0xfc, 0x02, 0xe4, 0x89, 0x09, 0xb9, 0x3d, 0x8c, 0xda, 0x98, 0x0d, 0x67, 0x83, 0x30, 0x00,
        0xe5, 0x3b, 0xc4, 0x7c, 0xc4, 0x63, 0xa7, 0x20, 0x97, 0x74, 0x8d, 0x18, 0xfa, 0xb1, 0xe7,
        0x67, 0x13, 0x48, 0x55, 0x99, 0xde, 0xca, 0x70, 0xe4, 0x7a, 0x3a, 0x65, 0x28, 0x08, 0xce,
        0xc3, 0x93, 0xbb, 0x95, 0x15, 0x10, 0x25, 0x67, 0x7a, 0xad, 0xe8, 0xbc, 0xfb, 0xee, 0x94,
        0xfa, 0x09, 0x6a, 0x3e, 0xa6, 0xb9, 0x9b, 0xd7, 0x01, 0xe4, 0x4f, 0x53, 0x69, 0x92, 0x8a,
        0xf4, 0x52, 0xbf, 0x44, 0xfd, 0x26, 0x80, 0xb3, 0xed, 0x9d, 0x25, 0xa8, 0x99, 0x24, 0x1e,
        0xd7, 0x29, 0xde, 0xa3, 0x08, 0x63, 0x44, 0x2a, 0xb9, 0x94, 0x19, 0x73, 0xb9, 0xf3, 0xee,
        0x67, 0xc1, 0x81, 0xdd, 0x78, 0x2f, 0x8c, 0x1d, 0x7e, 0xb5, 0x06, 0x97, 0x24, 0x60, 0xfb,
        0x27, 0xf1, 0x4d, 0x85, 0x2d, 0x1e, 0x8c, 0x13, 0x95, 0x2b, 0x5c, 0x12, 0x3a, 0xe3, 0x31,
        0x55, 0x07, 0xdd, 0xf2, 0x85, 0xc5, 0x2e, 0x28, 0x2a, 0x9b, 0x3a, 0x89, 0xef, 0xd6, 0xba,
        0x00, 0x55, 0xc2, 0x61, 0x74, 0xaf, 0xcc, 0xfd, 0x44, 0x7c, 0xae, 0xd8, 0xbb, 0xa7, 0xb7,
        0x93, 0xc1, 0x3a, 0x0d, 0xef, 0x7e, 0x14, 0x67, 0x3a, 0x0b, 0x62, 0x57, 0x5e, 0x78, 0x58,
        0x5c, 0x63, 0x2b, 0x79, 0x2d, 0x81, 0x61, 0x4d, 0xd2, 0xdb, 0x41, 0xe9, 0xbd, 0x00, 0xc8,
        0x26, 0xd3, 0xea, 0x6b, 0x10, 0xa9, 0x8e, 0xab, 0x64, 0x85, 0x6a, 0x55, 0xc1, 0x78, 0x65,
        0x31, 0x9b, 0x4d, 0x44, 0x84, 0xea, 0x60, 0x15, 0x52, 0x6b, 0x9d, 0x4b, 0x14, 0x5c, 0xba,
        0x4f, 0xa2, 0x53, 0x8f, 0x2a, 0x2c, 0xda, 0x36, 0x96

    };

    /* a garbage first certificate (10 bytes, not ASN.1) followed by the
     * valid one */
    const uint32_t bad_len = 10;
    const uint32_t good_len = sizeof(valid_cert);
    const uint32_t chain_len = 3 + bad_len + 3 + good_len;
    const uint32_t hs_len = 3 + chain_len;
    const uint32_t msg_len = 4 + 3 + 3 + bad_len + 3 + good_len;
    uint8_t msg[msg_len];

    msg[0] = 0x0b;
    msg[1] = 0;
    msg[2] = (hs_len >> 8) & 0xff;
    msg[3] = hs_len & 0xff;
    msg[4] = 0;
    msg[5] = (chain_len >> 8) & 0xff;
    msg[6] = chain_len & 0xff;
    msg[7] = 0;
    msg[8] = 0;
    msg[9] = bad_len;
    for (uint32_t k = 0; k < bad_len; k++)
        msg[10 + k] = 0x41;
    const uint32_t off = 10 + bad_len;
    msg[off] = 0;
    msg[off + 1] = (good_len >> 8) & 0xff;
    msg[off + 2] = good_len & 0xff;
    memcpy(msg + off + 3, valid_cert, good_len);

    SSLState *ssl_state = SSLStateAlloc(NULL, ALPROTO_TLS);
    if (ssl_state == NULL)
        return 0;

    ssl_state->curr_connp = &ssl_state->server_connp;
    ssl_state->curr_connp->record_length = msg_len;
    ssl_state->curr_connp->bytes_processed = 0;
    ssl_state->curr_connp->version = 0x0303;

    /* the bytes are consumed (rc > 0) and the cert phase is entered at
     * the header; the incomplete data keeps the track out of the data
     * phase (the record level shortcut requires complete certificate
     * data); the suppression flag is hello-specific */
    int rc = SSLv3ParseHandshakeProtocol(ssl_state, msg, msg_len, 1);
    FAIL_IF(rc < 0);
    FAIL_IF(ssl_state->server_connp.phase_suppressed);
    FAIL_IF(!ssl_state->server_connp.cert_data_incomplete);
    FAIL_IF(ssl_state->server_state != TLS_STATE_SERVER_CERT);
    /* the rest of the chain survived: the valid certificate is in the
     * chain and the cert0 fields come from the first decodable cert */
    SSLCertsChain *item = TAILQ_FIRST(&ssl_state->server_connp.certs);
    FAIL_IF(item == NULL);
    FAIL_IF(item->cert_len != good_len);
    FAIL_IF(ssl_state->server_connp.cert0_subject == NULL);
    FAIL_IF(ssl_state->server_connp.cert0_issuerdn == NULL);

    /* the certificate data comes from the valid (second) certificate:
     * compare the fields against a direct extraction from the fixture */
    uint32_t errc = 0;
    X509 *ref = SCX509Decode(valid_cert, sizeof(valid_cert), &errc);
    FAIL_IF(ref == NULL);
    uint8_t *subj = NULL;
    uint32_t subj_len = 0;
    uint8_t *iss = NULL;
    uint32_t iss_len = 0;
    SCX509GetSubject(ref, &subj, &subj_len);
    SCX509GetIssuer(ref, &iss, &iss_len);
    FAIL_IF(subj == NULL || iss == NULL);
    FAIL_IF(ssl_state->server_connp.cert0_subject_len != subj_len);
    FAIL_IF(memcmp(ssl_state->server_connp.cert0_subject, subj, subj_len) != 0);
    FAIL_IF(ssl_state->server_connp.cert0_issuerdn_len != iss_len);
    FAIL_IF(memcmp(ssl_state->server_connp.cert0_issuerdn, iss, iss_len) != 0);
    if (subj != NULL)
        SCX509ArrayFree(subj, subj_len);
    if (iss != NULL)
        SCX509ArrayFree(iss, iss_len);
    SCX509Free(ref);

    /* the incomplete-certificate-data condition is sticky: a later
     * handshake message resets the per-message suppression but does not
     * complete the certificate data (only a fully decoded certificate
     * message does), so the track stays in the cert phase, out of the
     * data phase */
    const uint8_t shd[] = { 0x0e, 0x00, 0x00, 0x00 };
    ssl_state->curr_connp = &ssl_state->server_connp;
    ssl_state->curr_connp->record_length = sizeof(shd);
    ssl_state->curr_connp->bytes_processed = 0;
    rc = SSLv3ParseHandshakeProtocol(ssl_state, shd, sizeof(shd), 1);
    FAIL_IF(rc < 0);
    FAIL_IF(ssl_state->server_connp.phase_suppressed);
    FAIL_IF(!ssl_state->server_connp.cert_data_incomplete);
    FAIL_IF(ssl_state->server_state != TLS_STATE_SERVER_CERT);

    /* a fully decodable first certificate message clears the incomplete
     * flag and enters the cert phase at its start: the preconditions for
     * the record level data shortcut (the shortcut itself is pinned by
     * sv ruletype-firewall-51). On the client connp: its one-shot buffer
     * is untouched here */
    const uint32_t mlen = 4 + 3 + 3 + sizeof(valid_cert);
    uint8_t full[mlen];
    memset(full, 0, sizeof(full));
    full[0] = 0x0b;
    full[1] = ((3 + 3 + good_len) >> 16) & 0xff;
    full[2] = ((3 + 3 + good_len) >> 8) & 0xff;
    full[3] = (3 + 3 + good_len) & 0xff;
    full[4] = ((3 + good_len) >> 16) & 0xff;
    full[5] = ((3 + good_len) >> 8) & 0xff;
    full[6] = (3 + good_len) & 0xff;
    full[7] = (good_len >> 16) & 0xff;
    full[8] = (good_len >> 8) & 0xff;
    full[9] = good_len & 0xff;
    memcpy(full + 10, valid_cert, good_len);
    ssl_state->curr_connp = &ssl_state->client_connp;
    ssl_state->curr_connp->record_length = mlen;
    ssl_state->curr_connp->bytes_processed = 0;
    rc = SSLv3ParseHandshakeProtocol(ssl_state, full, mlen, 0);
    FAIL_IF(rc < 0);
    FAIL_IF(ssl_state->client_connp.cert_data_incomplete);
    FAIL_IF(ssl_state->client_connp.cert0_subject == NULL);
    FAIL_IF(ssl_state->client_state != TLS_STATE_CLIENT_CERT);
    FAIL_IF(!ssl_state->client_connp.cert_chain_final);

    /* the one-shot buffer latches: a second server certificate message
     * is not decoded and cannot clear the incomplete flag (base
     * semantics, renegotiation re-sends the same certificate) */
    ssl_state->curr_connp = &ssl_state->server_connp;
    ssl_state->curr_connp->record_length = mlen;
    ssl_state->curr_connp->bytes_processed = 0;
    rc = SSLv3ParseHandshakeProtocol(ssl_state, full, mlen, 1);
    FAIL_IF(rc < 0);
    FAIL_IF(!ssl_state->server_connp.cert_data_incomplete);

    SSLStateFree(ssl_state);
    PASS;
}

void SSLStateParserRegisterTests(void)
{
    UtRegisterTest("TLSPhaseStateTestClient", TLSPhaseStateTestClient);
    UtRegisterTest("TLSPhaseStateTestServer", TLSPhaseStateTestServer);
    UtRegisterTest("TLSPhaseStateTestOldNamesGone", TLSPhaseStateTestOldNamesGone);
    UtRegisterTest("TLSPhaseStateTestCompletion", TLSPhaseStateTestCompletion);
    UtRegisterTest("TLSPhaseSuppressionTest", TLSPhaseSuppressionTest);
    UtRegisterTest("TLSPhaseCertChainSkipTest", TLSPhaseCertChainSkipTest);
}
#endif /* UNITTESTS */
