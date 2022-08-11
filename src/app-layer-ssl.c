/* Copyright (C) 2007-2020 Open Information Security Foundation
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
#include "app-layer-detect-proto.h"
#include "app-layer-protos.h"
#include "app-layer-parser.h"
#include "app-layer-frames.h"
#include "app-layer-ssl.h"

#include "decode-events.h"
#include "conf.h"

#include "util-spm.h"
#include "util-unittest.h"
#include "util-debug.h"
#include "util-print.h"
#include "util-pool.h"
#include "util-byte.h"
#include "util-ja3.h"
#include "util-enum.h"
#include "flow-util.h"
#include "flow-private.h"
#include "util-validate.h"

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

/* JA3 fingerprints are disabled by default */
#define SSL_CONFIG_DEFAULT_JA3 0

enum SslConfigEncryptHandling {
    SSL_CNF_ENC_HANDLE_DEFAULT = 0, /**< disable raw content, continue tracking */
    SSL_CNF_ENC_HANDLE_BYPASS = 1,  /**< skip processing of flow, bypass if possible */
    SSL_CNF_ENC_HANDLE_FULL = 2,    /**< handle fully like any other proto */
};

typedef struct SslConfig_ {
    enum SslConfigEncryptHandling encrypt_mode;
    /** dynamic setting for ja3: can be enabled on demand if not explicitly
     *  disabled. */
    SC_ATOMIC_DECLARE(int, enable_ja3);
    bool disable_ja3; /**< ja3 explicitly disabled. Don't enable on demand. */
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
#define SSLV3_RECORD_MAX_LEN            1 << 14

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
        (c), 0                                                                                     \
    }
#define SSL_DECODER_INCOMPLETE(c, n)                                                               \
    (struct SSLDecoderResult)                                                                      \
    {                                                                                              \
        (c), (n)                                                                                   \
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
            AppLayerDecoderEventsSetEventRaw(&(ssl_state)->tx_data.events, (event));               \
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

static AppLayerTxData *SSLGetTxData(void *vtx)
{
    SSLState *ssl_state = (SSLState *)vtx;
    return &ssl_state->tx_data;
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

    uint8_t hash[SC_SHA1_LEN];
    if (SCSha1HashBuffer(input, cert_len, hash, sizeof(hash)) == 1) {
        rs_to_hex_sep((uint8_t *)ssl_state->server_connp.cert0_fingerprint, SHA1_STRING_LENGTH, ':',
                hash, SC_SHA1_LEN);
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

/** \retval consumed bytes consumed or -1 on error */
static int TlsDecodeHSCertificate(SSLState *ssl_state,
                                  const uint8_t * const initial_input,
                                  const uint32_t input_len)
{
    const uint8_t *input = (uint8_t *)initial_input;
    uint32_t err_code = 0;
    X509 *x509 = NULL;

    if (!(HAS_SPACE(3)))
        return 0;

    uint32_t cert_chain_len = *input << 16 | *(input + 1) << 8 | *(input + 2);
    input += 3;

    if (!(HAS_SPACE(cert_chain_len)))
        return 0;

    uint32_t processed_len = 0;
    /* coverity[tainted_data] */
    while (processed_len < cert_chain_len)
    {
        err_code = 0;
        int rc = 0;

        if (!(HAS_SPACE(3)))
            goto invalid_cert;

        uint32_t cert_len = *input << 16 | *(input + 1) << 8 | *(input + 2);
        input += 3;

        if (!(HAS_SPACE(cert_len)))
            goto invalid_cert;

        /* only store fields from the first certificate in the chain */
        if (processed_len == 0 &&
                ssl_state->server_connp.cert0_subject == NULL &&
                ssl_state->server_connp.cert0_issuerdn == NULL &&
                ssl_state->server_connp.cert0_serial == NULL)
        {
            int64_t not_before, not_after;

            x509 = rs_x509_decode(input, cert_len, &err_code);
            if (x509 == NULL) {
                TlsDecodeHSCertificateErrSetEvent(ssl_state, err_code);
                goto next;
            }

            char *str = rs_x509_get_subject(x509);
            if (str == NULL) {
                err_code = ERR_EXTRACT_SUBJECT;
                goto error;
            }
            ssl_state->server_connp.cert0_subject = str;

            str = rs_x509_get_issuer(x509);
            if (str == NULL) {
                err_code = ERR_EXTRACT_ISSUER;
                goto error;
            }
            ssl_state->server_connp.cert0_issuerdn = str;

            str = rs_x509_get_serial(x509);
            if (str == NULL) {
                err_code = ERR_INVALID_SERIAL;
                goto error;
            }
            ssl_state->server_connp.cert0_serial = str;

            rc = rs_x509_get_validity(x509, &not_before, &not_after);
            if (rc != 0) {
                err_code = ERR_EXTRACT_VALIDITY;
                goto error;
            }
            ssl_state->server_connp.cert0_not_before = (time_t)not_before;
            ssl_state->server_connp.cert0_not_after = (time_t)not_after;

            rs_x509_free(x509);
            x509 = NULL;

            rc = TlsDecodeHSCertificateFingerprint(ssl_state, input, cert_len);
            if (rc != 0) {
                SCLogDebug("TlsDecodeHSCertificateFingerprint failed with %d", rc);
                goto error;
            }
        }

        rc = TlsDecodeHSCertificateAddCertToChain(ssl_state, input, cert_len);
        if (rc != 0) {
            SCLogDebug("TlsDecodeHSCertificateAddCertToChain failed with %d", rc);
            goto error;
        }

next:
        input += cert_len;
        processed_len += cert_len + 3;
    }

    return (input - initial_input);

error:
    if (err_code != 0)
        TlsDecodeHSCertificateErrSetEvent(ssl_state, err_code);
    if (x509 != NULL)
        rs_x509_free(x509);
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

    uint16_t version = (uint16_t)(*input << 8) | *(input + 1);
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

    if (SC_ATOMIC_GET(ssl_config.enable_ja3) && ssl_state->curr_connp->ja3_str == NULL) {
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

    if (SC_ATOMIC_GET(ssl_config.enable_ja3)) {
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

            uint16_t cipher_suite = (uint16_t)(*input << 8) | *(input + 1);
            input += 2;

            if (TLSDecodeValueIsGREASE(cipher_suite) != 1) {
                int rc = Ja3BufferAddValue(&ja3_cipher_suites, cipher_suite);
                if (rc != 0) {
                    return -1;
                }
            }

            processed_len += 2;
        }

        int rc = Ja3BufferAppendBuffer(&ssl_state->curr_connp->ja3_str,
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
        return (input - initial_input);
    }

    const size_t sni_strlen = sni_len + 1;
    ssl_state->curr_connp->sni = SCMalloc(sni_strlen);
    if (unlikely(ssl_state->curr_connp->sni == NULL))
        return -1;

    const size_t consumed = input - initial_input;
    if (SafeMemcpy(ssl_state->curr_connp->sni, 0, sni_strlen,
                initial_input, consumed, input_len, sni_len) != 0) {
        SCFree(ssl_state->curr_connp->sni);
        ssl_state->curr_connp->sni = NULL;
        return -1;
    }
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

        /* Use the first (and prefered) version as client version */
        ssl_state->curr_connp->version = (uint16_t)(*input << 8) | *(input + 1);

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
            SC_ATOMIC_GET(ssl_config.enable_ja3)) {
        uint16_t ec_processed_len = 0;
        /* coverity[tainted_data] */
        while (ec_processed_len < elliptic_curves_len)
        {
            if (!(HAS_SPACE(2)))
                goto invalid_length;

            uint16_t elliptic_curve = (uint16_t)(*input << 8) | *(input + 1);
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
            SC_ATOMIC_GET(ssl_config.enable_ja3)) {
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
    const uint8_t *input = initial_input;

    int ret;
    int rc;
    const bool ja3 = (SC_ATOMIC_GET(ssl_config.enable_ja3) == 1);

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

    uint16_t processed_len = 0;
    /* coverity[tainted_data] */
    while (processed_len < extensions_len)
    {
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

        if (ja3) {
            if (TLSDecodeValueIsGREASE(ext_type) != 1) {
                rc = Ja3BufferAddValue(&ja3_extensions, ext_type);
                if (rc != 0)
                    goto error;
            }
        }

        processed_len += ext_len + 4;
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

    if (SC_ATOMIC_GET(ssl_config.enable_ja3) && ssl_state->curr_connp->ja3_hash == NULL) {
        ssl_state->curr_connp->ja3_hash = Ja3GenerateHash(ssl_state->curr_connp->ja3_str);
    }

end:
    return 0;
}

/** \internal
 *  \brief Get Certificates len
 */
static uint32_t GetCertsLen(SSLStateConnp *curr_connp, const uint8_t *input,
        const uint32_t input_len)
{
    uint32_t len = (*input << 16 | *(input + 1) << 8 | *(input + 2)) + 3;
    SCLogDebug("length %u", len);
    return len;
}

#ifdef DEBUG_VALIDATION
static inline bool
RecordAlreadyProcessed(const SSLStateConnp *curr_connp)
{
    return ((curr_connp->record_length + SSLV3_RECORD_HDR_LEN) <
            curr_connp->bytes_processed);
}
#endif

static inline int SSLv3ParseHandshakeTypeCertificate(SSLState *ssl_state,
        const uint8_t * const initial_input,
        const uint32_t input_len)
{
    const uint32_t certs_len = GetCertsLen(ssl_state->curr_connp, initial_input, input_len);
    SCLogDebug("certs_len %u", certs_len);

    int rc = TlsDecodeHSCertificate(ssl_state, initial_input, certs_len);
    SCLogDebug("rc %d", rc);
    if (rc > 0) {
        DEBUG_VALIDATE_BUG_ON(rc != (int)certs_len);
        SSLParserHSReset(ssl_state->curr_connp);
    } else if (rc < 0) {
        SCLogDebug("error parsing cert, reset state");
        SSLParserHSReset(ssl_state->curr_connp);
        /* fall through to still consume the cert bytes */
    }
    return certs_len;
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
 *  \retval parsed number of consumed bytes
 *  \retval < 0 error
 */
static int SSLv3ParseHandshakeType(SSLState *ssl_state, const uint8_t *input,
                                   uint32_t input_len, uint8_t direction)
{
    const uint8_t *initial_input = input;
    int rc;

    if (input_len == 0) {
        return 0;
    }
    DEBUG_VALIDATE_BUG_ON(RecordAlreadyProcessed(ssl_state->curr_connp));

    switch (ssl_state->curr_connp->handshake_type) {
        case SSLV3_HS_CLIENT_HELLO:
            ssl_state->current_flags = SSL_AL_FLAG_STATE_CLIENT_HELLO;

            rc = TLSDecodeHandshakeHello(ssl_state, input, input_len);
            if (rc < 0)
                return rc;
            break;

        case SSLV3_HS_SERVER_HELLO:
            ssl_state->current_flags = SSL_AL_FLAG_STATE_SERVER_HELLO;

            rc = TLSDecodeHandshakeHello(ssl_state, input, ssl_state->curr_connp->message_length);
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
            /* For now, only decode the server certificate */
            if (direction == 0) {
                SCLogDebug("Incorrect SSL Record type sent in the toserver "
                           "direction!");
                break;
            }

            rc = SSLv3ParseHandshakeTypeCertificate(ssl_state,
                    initial_input, input_len);
            if (rc < 0)
                return rc;
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
        case SSLV3_HS_SERVER_HELLO_DONE:
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
                    ssl_state->curr_connp->hs_buffer_offset + input_len) {

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
            SSLSetEvent(ssl_state, TLS_DECODER_EVENT_INVALID_HANDSHAKE_MESSAGE);
            continue;
        }

        /* if the message lenght exceeds our input_len, we have a tls fragment. */
        if (record_len > input_len) {
            const uint32_t avail = input_len;
            const uint32_t size = avail + (4096 - (avail % 4096));
            SCLogDebug("initial buffer size %u, based on input %u", size, avail);
            ssl_state->curr_connp->hs_buffer = SCCalloc(1, size);
            BUG_ON(ssl_state->curr_connp->hs_buffer == NULL);
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
            return (input - initial_input);

        } else {
            /* full record, parse it now */
            int retval = SSLv3ParseHandshakeType(
                    ssl_state, input, ssl_state->curr_connp->message_length, direction);
            if (retval < 0 || retval > (int)input_len) {
                DEBUG_VALIDATE_BUG_ON(retval > (int)input_len);
                return (retval);
            }
            SCLogDebug("retval %d input_len %u", retval, input_len);
            input += retval;
            input_len -= retval;

            SSLParserHSReset(ssl_state->curr_connp);
        }
        SCLogDebug("input_len left %u", input_len);
    }
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

    return (input - initial_input);
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

    return (input - initial_input);
}

static int SSLv2Decode(uint8_t direction, SSLState *ssl_state, AppLayerParserState *pstate,
        const uint8_t *input, uint32_t input_len, const StreamSlice stream_slice)
{
    int retval = 0;
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
        retval = SSLv2ParseRecord(direction, ssl_state, input, input_len);
        SCLogDebug("retval %d ssl_state->curr_connp->record_length %u", retval,
                ssl_state->curr_connp->record_length);
        if (retval < 0 || retval > (int)input_len) {
            DEBUG_VALIDATE_BUG_ON(retval > (int)input_len);
            SSLSetEvent(ssl_state, TLS_DECODER_EVENT_INVALID_SSLV2_HEADER);
            return -1;
        }

        AppLayerFrameNewByPointer(ssl_state->f, &stream_slice, input,
                ssl_state->curr_connp->record_lengths_length + ssl_state->curr_connp->record_length,
                direction, TLS_FRAME_SSLV2_PDU);
        SCLogDebug("record start: ssl2.pdu frame");

        input += retval;
        input_len -= retval;
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

    /* record_lengths_length should never be zero */
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
                            uint16_t session_id_length = (input[5]) | (uint16_t)(input[4] << 8);
                            input += 6;
                            input_len -= 6;
                            ssl_state->curr_connp->bytes_processed += 6;
                            if (session_id_length == 0) {
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
                        ssl_state->curr_connp->bytes_processed++;
                        if (--input_len == 0)
                            break;

                        /* fall through */
                    case 9:
                        ssl_state->curr_connp->bytes_processed++;
                        if (--input_len == 0)
                            break;

                        /* fall through */
                }

            } else {
                switch (ssl_state->curr_connp->bytes_processed) {
                    case 3:
                        if (input_len >= 6) {
                            uint16_t session_id_length = (input[5]) | (uint16_t)(input[4] << 8);
                            input += 6;
                            input_len -= 6;
                            ssl_state->curr_connp->bytes_processed += 6;
                            if (session_id_length == 0) {
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
                        ssl_state->curr_connp->bytes_processed++;
                        if (--input_len == 0)
                            break;

                        /* fall through */
                    case 8:
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

static struct SSLDecoderResult SSLv3Decode(uint8_t direction, SSLState *ssl_state,
        AppLayerParserState *pstate, const uint8_t *input, const uint32_t input_len,
        const StreamSlice stream_slice)
{
    uint32_t parsed = 0;
    uint32_t record_len; /* slice of input_len for the current record */

    if (ssl_state->curr_connp->bytes_processed < SSLV3_RECORD_HDR_LEN) {
        int retval = SSLv3ParseRecord(direction, ssl_state, input, input_len);
        if (retval < 0 || retval > (int)input_len) {
            DEBUG_VALIDATE_BUG_ON(retval > (int)input_len);
            SCLogDebug("SSLv3ParseRecord returned %d", retval);
            SSLSetEvent(ssl_state, TLS_DECODER_EVENT_INVALID_TLS_HEADER);
            return SSL_DECODER_ERROR(-1);
        }
        SCLogDebug("%s input %p record_length %u", (direction == 0) ? "toserver" : "toclient",
                input, ssl_state->curr_connp->record_length);
        AppLayerFrameNewByPointer(ssl_state->f, &stream_slice, input,
                ssl_state->curr_connp->record_length + retval, direction, TLS_FRAME_PDU);
        AppLayerFrameNewByPointer(
                ssl_state->f, &stream_slice, input, SSLV3_RECORD_HDR_LEN, direction, TLS_FRAME_HDR);
        parsed = retval;
        record_len = MIN(input_len - parsed, ssl_state->curr_connp->record_length);
        SCLogDebug("record_len %u (input_len %u, parsed %u, ssl_state->curr_connp->record_length %u)",
                record_len, input_len, parsed, ssl_state->curr_connp->record_length);

        /* records are not supposed to exceed 16384, but the length field is 16 bits. */
        if (ssl_state->curr_connp->bytes_processed == SSLV3_RECORD_HDR_LEN &&
                ssl_state->curr_connp->record_length > SSLV3_RECORD_MAX_LEN) {
            SSLSetEvent(ssl_state, TLS_DECODER_EVENT_INVALID_RECORD_LENGTH);
        }
    } else {
        ValidateRecordState(ssl_state->curr_connp);

        record_len = (ssl_state->curr_connp->record_length + SSLV3_RECORD_HDR_LEN)- ssl_state->curr_connp->bytes_processed;
        record_len = MIN(input_len, record_len);
    }
    SCLogDebug("record length %u processed %u got %u",
            ssl_state->curr_connp->record_length, ssl_state->curr_connp->bytes_processed, record_len);

    /* if we don't have the full record, we return incomplete */
    if (ssl_state->curr_connp->record_length > input_len - parsed) {
        uint32_t needed = ssl_state->curr_connp->record_length;
        SCLogDebug("record len %u input_len %u parsed %u: need %u bytes more data",
                ssl_state->curr_connp->record_length, input_len, parsed, needed);
        return SSL_DECODER_INCOMPLETE(parsed, needed);
    }

    if (record_len == 0) {
        return SSL_DECODER_OK(parsed);
    }

    /* record_length should never be zero */
    if (ssl_state->curr_connp->record_length == 0) {
        SCLogDebug("SSLv3 Record length is 0");
        SSLSetEvent(ssl_state, TLS_DECODER_EVENT_INVALID_TLS_HEADER);
        return SSL_DECODER_ERROR(-1);
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
            }
            break;

        case SSLV3_ALERT_PROTOCOL:
            AppLayerFrameNewByPointer(ssl_state->f, &stream_slice, input + parsed,
                    ssl_state->curr_connp->record_length, direction, TLS_FRAME_ALERT_DATA);
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

        case SSLV3_HANDSHAKE_PROTOCOL: {
            if (ssl_state->flags & SSL_AL_FLAG_CHANGE_CIPHER_SPEC) {
                /* In TLSv1.3, ChangeCipherSpec is only used for middlebox
                   compability (rfc8446, appendix D.4). */
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
            SSLSetEvent(ssl_state, TLS_DECODER_EVENT_INVALID_RECORD_TYPE);
            SCLogDebug("unsupported record type");
            return SSL_DECODER_ERROR(-1);
    }

    parsed += record_len;
    ssl_state->curr_connp->bytes_processed += record_len;

    if (ssl_state->curr_connp->bytes_processed >=
            ssl_state->curr_connp->record_length + SSLV3_RECORD_HDR_LEN) {
        SCLogDebug("record complete, trigger RAW");
        AppLayerParserTriggerRawStreamReassembly(
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
 *        the parser state, to avoid multiple functions in the chain reseting
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
    uint32_t counter = 0;
    ssl_state->f = f;
    const uint8_t *input = StreamSliceGetData(&stream_slice);
    const uint8_t *init_input = input;
    int32_t input_len = (int32_t)StreamSliceGetDataLen(&stream_slice);

    if (input == NULL &&
            ((direction == 0 && AppLayerParserStateIssetFlag(pstate, APP_LAYER_PARSER_EOF_TS)) ||
                    (direction == 1 &&
                            AppLayerParserStateIssetFlag(pstate, APP_LAYER_PARSER_EOF_TC)))) {
        /* flag session as finished if APP_LAYER_PARSER_EOF is set */
        ssl_state->flags |= SSL_AL_FLAG_STATE_FINISHED;
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
            int retval = SSLv2Decode(direction, ssl_state, pstate, input, input_len, stream_slice);
            if (retval < 0 || retval > input_len) {
                DEBUG_VALIDATE_BUG_ON(retval > input_len);
                SCLogDebug("Error parsing SSLv2. Reseting parser "
                        "state. Let's get outta here");
                SSLParserReset(ssl_state);
                SSLSetEvent(ssl_state,
                        TLS_DECODER_EVENT_INVALID_SSL_RECORD);
                return APP_LAYER_OK;
            }
            input_len -= retval;
            input += retval;
            SCLogDebug("SSLv2 decoder consumed %d bytes: %u left", retval, input_len);
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
                SCLogDebug("Error parsing TLS. Reseting parser "
                        "state.  Let's get outta here");
                SSLParserReset(ssl_state);
                return APP_LAYER_ERROR;
            } else if (r.needed) {
                input += r.retval;
                SCLogDebug("returning consumed %" PRIuMAX " needed %u",
                        (uintmax_t)(input - init_input), r.needed);
                SCReturnStruct(APP_LAYER_INCOMPLETE(input - init_input, r.needed));
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

    /* mark handshake as done if we have subject and issuer */
    if (ssl_state->server_connp.cert0_subject &&
            ssl_state->server_connp.cert0_issuerdn) {
        SCLogDebug("SSL_AL_FLAG_HANDSHAKE_DONE");
        ssl_state->flags |= SSL_AL_FLAG_HANDSHAKE_DONE;
    }

    /* flag session as finished if APP_LAYER_PARSER_EOF is set */
    if (AppLayerParserStateIssetFlag(pstate, APP_LAYER_PARSER_EOF_TS) &&
        AppLayerParserStateIssetFlag(pstate, APP_LAYER_PARSER_EOF_TC)) {
        SCLogDebug("SSL_AL_FLAG_STATE_FINISHED");
        ssl_state->flags |= SSL_AL_FLAG_STATE_FINISHED;
    }

    return APP_LAYER_OK;
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

    if (ssl_state->client_connp.cert0_subject)
        rs_cstring_free(ssl_state->client_connp.cert0_subject);
    if (ssl_state->client_connp.cert0_issuerdn)
        rs_cstring_free(ssl_state->client_connp.cert0_issuerdn);
    if (ssl_state->client_connp.cert0_serial)
        rs_cstring_free(ssl_state->client_connp.cert0_serial);
    if (ssl_state->client_connp.cert0_fingerprint)
        SCFree(ssl_state->client_connp.cert0_fingerprint);
    if (ssl_state->client_connp.sni)
        SCFree(ssl_state->client_connp.sni);
    if (ssl_state->client_connp.session_id)
        SCFree(ssl_state->client_connp.session_id);
    if (ssl_state->client_connp.hs_buffer)
        SCFree(ssl_state->client_connp.hs_buffer);

    if (ssl_state->server_connp.cert0_subject)
        rs_cstring_free(ssl_state->server_connp.cert0_subject);
    if (ssl_state->server_connp.cert0_issuerdn)
        rs_cstring_free(ssl_state->server_connp.cert0_issuerdn);
    if (ssl_state->server_connp.cert0_serial)
        rs_cstring_free(ssl_state->server_connp.cert0_serial);
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
    if (ssl_state->server_connp.hs_buffer)
        SCFree(ssl_state->server_connp.hs_buffer);

    AppLayerDecoderEventsFreeEvents(&ssl_state->tx_data.events);

    if (ssl_state->tx_data.de_state != NULL) {
        DetectEngineStateFree(ssl_state->tx_data.de_state);
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
        const uint8_t *input, uint32_t ilen, uint8_t *rdir)
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
    if (AppLayerProtoDetectPMRegisterPatternCSwPP(IPPROTO_TCP, ALPROTO_TLS, "|01 00 02|", 5, 2,
                STREAM_TOSERVER, SSLProbingParser, 0, 3) < 0) {
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

    SC_ATOMIC_INIT(ssl_config.enable_ja3);

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
            if (AppLayerProtoDetectPPParseConfPorts("tcp", IPPROTO_TCP,
                                                    proto_name, ALPROTO_TLS,
                                                    0, 3,
                                                    SSLProbingParser, NULL) == 0) {
                SCLogConfig("no TLS config found, "
                            "enabling TLS detection on port 443.");
                AppLayerProtoDetectPPRegister(IPPROTO_TCP,
                                              "443",
                                              ALPROTO_TLS,
                                              0, 3,
                                              STREAM_TOSERVER,
                                              SSLProbingParser, NULL);
            }
        }
    } else {
        SCLogConfig("Protocol detection and parser disabled for %s protocol",
                  proto_name);
        return;
    }

    if (AppLayerParserConfParserEnabled("tcp", proto_name)) {
        AppLayerParserRegisterParser(IPPROTO_TCP, ALPROTO_TLS, STREAM_TOSERVER,
                                     SSLParseClientRecord);

        AppLayerParserRegisterParser(IPPROTO_TCP, ALPROTO_TLS, STREAM_TOCLIENT,
                                     SSLParseServerRecord);

        AppLayerParserRegisterGetFrameFuncs(
                IPPROTO_TCP, ALPROTO_TLS, SSLStateGetFrameIdByName, SSLStateGetFrameNameById);
        AppLayerParserRegisterGetEventInfo(IPPROTO_TCP, ALPROTO_TLS, SSLStateGetEventInfo);
        AppLayerParserRegisterGetEventInfoById(IPPROTO_TCP, ALPROTO_TLS, SSLStateGetEventInfoById);

        AppLayerParserRegisterStateFuncs(IPPROTO_TCP, ALPROTO_TLS, SSLStateAlloc, SSLStateFree);

        AppLayerParserRegisterParserAcceptableDataDirection(IPPROTO_TCP, ALPROTO_TLS, STREAM_TOSERVER);

        AppLayerParserRegisterTxFreeFunc(IPPROTO_TCP, ALPROTO_TLS, SSLStateTransactionFree);

        AppLayerParserRegisterGetTx(IPPROTO_TCP, ALPROTO_TLS, SSLGetTx);
        AppLayerParserRegisterTxDataFunc(IPPROTO_TCP, ALPROTO_TLS, SSLGetTxData);

        AppLayerParserRegisterGetTxCnt(IPPROTO_TCP, ALPROTO_TLS, SSLGetTxCnt);

        AppLayerParserRegisterGetStateProgressFunc(IPPROTO_TCP, ALPROTO_TLS, SSLGetAlstateProgress);

        AppLayerParserRegisterStateProgressCompletionStatus(
                ALPROTO_TLS, TLS_STATE_FINISHED, TLS_STATE_FINISHED);

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
        int enable_ja3 = SSL_CONFIG_DEFAULT_JA3;
        const char *strval = NULL;
        if (ConfGet("app-layer.protocols.tls.ja3-fingerprints", &strval) != 1) {
            enable_ja3 = SSL_CONFIG_DEFAULT_JA3;
        } else if (strcmp(strval, "auto") == 0) {
            enable_ja3 = SSL_CONFIG_DEFAULT_JA3;
        } else if (ConfValIsFalse(strval)) {
            enable_ja3 = 0;
            ssl_config.disable_ja3 = true;
        } else if (ConfValIsTrue(strval)) {
            enable_ja3 = true;
        }
        SC_ATOMIC_SET(ssl_config.enable_ja3, enable_ja3);

        if (g_disable_hashing) {
            if (SC_ATOMIC_GET(ssl_config.enable_ja3)) {
                SCLogWarning(
                        SC_WARN_NO_JA3_SUPPORT, "MD5 calculation has been disabled, disabling JA3");
                SC_ATOMIC_SET(ssl_config.enable_ja3, 0);
            }
        } else {
            if (RunmodeIsUnittests()) {
                SC_ATOMIC_SET(ssl_config.enable_ja3, 1);
            }
        }
    } else {
        SCLogConfig("Parsed disabled for %s protocol. Protocol detection"
                  "still on.", proto_name);
    }

    return;
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

bool SSLJA3IsEnabled(void)
{
    if (SC_ATOMIC_GET(ssl_config.enable_ja3)) {
        return true;
    }
    return false;
}
