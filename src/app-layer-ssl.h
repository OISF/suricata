/* Copyright (C) 2007-2022 Open Information Security Foundation
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
 *
 */

#ifndef __APP_LAYER_SSL_H__
#define __APP_LAYER_SSL_H__

#include "util-ja3.h"
#include "rust.h"

enum TlsFrameTypes {
    TLS_FRAME_PDU = 0, /**< whole PDU, so header + data */
    TLS_FRAME_HDR,     /**< only header portion */
    TLS_FRAME_DATA,    /**< only data portion */
    TLS_FRAME_ALERT_DATA,
    TLS_FRAME_HB_DATA,
    TLS_FRAME_SSLV2_HDR,
    TLS_FRAME_SSLV2_PDU,
};

enum {
    /* TLS protocol messages */
    TLS_DECODER_EVENT_INVALID_SSLV2_HEADER,
    TLS_DECODER_EVENT_INVALID_TLS_HEADER,
    TLS_DECODER_EVENT_INVALID_RECORD_VERSION,
    TLS_DECODER_EVENT_INVALID_RECORD_TYPE,
    TLS_DECODER_EVENT_INVALID_HANDSHAKE_MESSAGE,
    TLS_DECODER_EVENT_HEARTBEAT,
    TLS_DECODER_EVENT_INVALID_HEARTBEAT,
    TLS_DECODER_EVENT_OVERFLOW_HEARTBEAT,
    TLS_DECODER_EVENT_DATALEAK_HEARTBEAT_MISMATCH,
    TLS_DECODER_EVENT_HANDSHAKE_INVALID_LENGTH,
    TLS_DECODER_EVENT_MULTIPLE_SNI_EXTENSIONS,
    TLS_DECODER_EVENT_INVALID_SNI_TYPE,
    TLS_DECODER_EVENT_INVALID_SNI_LENGTH,
    TLS_DECODER_EVENT_TOO_MANY_RECORDS_IN_PACKET,
    /* Certificates decoding messages */
    TLS_DECODER_EVENT_INVALID_CERTIFICATE,
    TLS_DECODER_EVENT_CERTIFICATE_INVALID_LENGTH,
    TLS_DECODER_EVENT_CERTIFICATE_INVALID_VERSION,
    TLS_DECODER_EVENT_CERTIFICATE_INVALID_SERIAL,
    TLS_DECODER_EVENT_CERTIFICATE_INVALID_ALGORITHMIDENTIFIER,
    TLS_DECODER_EVENT_CERTIFICATE_INVALID_X509NAME,
    TLS_DECODER_EVENT_CERTIFICATE_INVALID_DATE,
    TLS_DECODER_EVENT_CERTIFICATE_INVALID_EXTENSIONS,
    TLS_DECODER_EVENT_CERTIFICATE_INVALID_DER,
    TLS_DECODER_EVENT_CERTIFICATE_INVALID_SUBJECT,
    TLS_DECODER_EVENT_CERTIFICATE_INVALID_ISSUER,
    TLS_DECODER_EVENT_CERTIFICATE_INVALID_VALIDITY,
    TLS_DECODER_EVENT_ERROR_MSG_ENCOUNTERED,
    TLS_DECODER_EVENT_INVALID_SSL_RECORD,
};

enum {
    TLS_STATE_IN_PROGRESS = 0,
    TLS_STATE_CERT_READY = 1,
    TLS_HANDSHAKE_DONE = 2,
    TLS_STATE_FINISHED = 3
};

/* Flag to indicate that server will now on send encrypted msgs */
#define SSL_AL_FLAG_SERVER_CHANGE_CIPHER_SPEC   BIT_U32(0)
/* Flag to indicate that client will now on send encrypted msgs */
#define SSL_AL_FLAG_CLIENT_CHANGE_CIPHER_SPEC   BIT_U32(1)
#define SSL_AL_FLAG_CHANGE_CIPHER_SPEC          BIT_U32(2)

/* SSL related flags */
#define SSL_AL_FLAG_SSL_CLIENT_HS               BIT_U32(3)
#define SSL_AL_FLAG_SSL_SERVER_HS               BIT_U32(4)
#define SSL_AL_FLAG_SSL_CLIENT_MASTER_KEY       BIT_U32(5)
#define SSL_AL_FLAG_SSL_CLIENT_SSN_ENCRYPTED    BIT_U32(6)
#define SSL_AL_FLAG_SSL_SERVER_SSN_ENCRYPTED    BIT_U32(7)
#define SSL_AL_FLAG_SSL_NO_SESSION_ID           BIT_U32(8)

/* flags specific to detect-ssl-state keyword */
#define SSL_AL_FLAG_STATE_CLIENT_HELLO          BIT_U32(9)
#define SSL_AL_FLAG_STATE_SERVER_HELLO          BIT_U32(10)
#define SSL_AL_FLAG_STATE_CLIENT_KEYX           BIT_U32(11)
#define SSL_AL_FLAG_STATE_SERVER_KEYX           BIT_U32(12)
#define SSL_AL_FLAG_STATE_UNKNOWN               BIT_U32(13)

/* flag to indicate that session is finished */
#define SSL_AL_FLAG_STATE_FINISHED              BIT_U32(14)

/* flags specific to HeartBeat state */
#define SSL_AL_FLAG_HB_INFLIGHT                 BIT_U32(15)
#define SSL_AL_FLAG_HB_CLIENT_INIT              BIT_U32(16)
#define SSL_AL_FLAG_HB_SERVER_INIT              BIT_U32(17)

/* flag to indicate that handshake is done */
#define SSL_AL_FLAG_HANDSHAKE_DONE              BIT_U32(18)

/* A session ID in the Client Hello message, indicating the client
   wants to resume a session */
#define SSL_AL_FLAG_SSL_CLIENT_SESSION_ID       BIT_U32(19)
/* Session resumed without a full handshake */
#define SSL_AL_FLAG_SESSION_RESUMED             BIT_U32(20)

/* Encountered a supported_versions extension in client hello */
#define SSL_AL_FLAG_CH_VERSION_EXTENSION        BIT_U32(21)

/* Log the session even without ever seeing a certificate. This is used
   to log TLSv1.3 sessions. */
#define SSL_AL_FLAG_LOG_WITHOUT_CERT            BIT_U32(22)

/* Encountered a early data extension in client hello. This extension is
   used by 0-RTT. */
#define SSL_AL_FLAG_EARLY_DATA                  BIT_U32(23)

/* flag to indicate that server random was filled */
#define TLS_TS_RANDOM_SET BIT_U32(24)

/* flag to indicate that client random was filled */
#define TLS_TC_RANDOM_SET BIT_U32(25)

/* config flags */
#define SSL_TLS_LOG_PEM                         (1 << 0)

/* extensions */
#define SSL_EXTENSION_SNI                       0x0000
#define SSL_EXTENSION_ELLIPTIC_CURVES           0x000a
#define SSL_EXTENSION_EC_POINT_FORMATS          0x000b
#define SSL_EXTENSION_SESSION_TICKET            0x0023
#define SSL_EXTENSION_EARLY_DATA                0x002a
#define SSL_EXTENSION_SUPPORTED_VERSIONS        0x002b

/* SNI types */
#define SSL_SNI_TYPE_HOST_NAME                  0

/* Max string length of the TLS version string */
#define SSL_VERSION_MAX_STRLEN 20

/* TLS random bytes for the sticky buffer */
#define TLS_RANDOM_LEN 32

/* SSL versions.  We'll use a unified format for all, with the top byte
 * holding the major version and the lower byte the minor version */
enum {
    TLS_VERSION_UNKNOWN = 0x0000,
    SSL_VERSION_2 = 0x0200,
    SSL_VERSION_3 = 0x0300,
    TLS_VERSION_10 = 0x0301,
    TLS_VERSION_11 = 0x0302,
    TLS_VERSION_12 = 0x0303,
    TLS_VERSION_13 = 0x0304,
    TLS_VERSION_13_DRAFT28 = 0x7f1c,
    TLS_VERSION_13_DRAFT27 = 0x7f1b,
    TLS_VERSION_13_DRAFT26 = 0x7f1a,
    TLS_VERSION_13_DRAFT25 = 0x7f19,
    TLS_VERSION_13_DRAFT24 = 0x7f18,
    TLS_VERSION_13_DRAFT23 = 0x7f17,
    TLS_VERSION_13_DRAFT22 = 0x7f16,
    TLS_VERSION_13_DRAFT21 = 0x7f15,
    TLS_VERSION_13_DRAFT20 = 0x7f14,
    TLS_VERSION_13_DRAFT19 = 0x7f13,
    TLS_VERSION_13_DRAFT18 = 0x7f12,
    TLS_VERSION_13_DRAFT17 = 0x7f11,
    TLS_VERSION_13_DRAFT16 = 0x7f10,
    TLS_VERSION_13_PRE_DRAFT16 = 0x7f01,
    TLS_VERSION_13_DRAFT20_FB = 0xfb14,
    TLS_VERSION_13_DRAFT21_FB = 0xfb15,
    TLS_VERSION_13_DRAFT22_FB = 0xfb16,
    TLS_VERSION_13_DRAFT23_FB = 0xfb17,
    TLS_VERSION_13_DRAFT26_FB = 0xfb1a,
};

static inline bool TLSVersionValid(const uint16_t version)
{
    switch (version) {
        case TLS_VERSION_13:
        case TLS_VERSION_12:
        case TLS_VERSION_11:
        case TLS_VERSION_10:
        case SSL_VERSION_3:

        case TLS_VERSION_13_DRAFT28:
        case TLS_VERSION_13_DRAFT27:
        case TLS_VERSION_13_DRAFT26:
        case TLS_VERSION_13_DRAFT25:
        case TLS_VERSION_13_DRAFT24:
        case TLS_VERSION_13_DRAFT23:
        case TLS_VERSION_13_DRAFT22:
        case TLS_VERSION_13_DRAFT21:
        case TLS_VERSION_13_DRAFT20:
        case TLS_VERSION_13_DRAFT19:
        case TLS_VERSION_13_DRAFT18:
        case TLS_VERSION_13_DRAFT17:
        case TLS_VERSION_13_DRAFT16:
        case TLS_VERSION_13_PRE_DRAFT16:
        case TLS_VERSION_13_DRAFT20_FB:
        case TLS_VERSION_13_DRAFT21_FB:
        case TLS_VERSION_13_DRAFT22_FB:
        case TLS_VERSION_13_DRAFT23_FB:
        case TLS_VERSION_13_DRAFT26_FB:
            return true;
    }
    return false;
}

typedef struct SSLCertsChain_ {
    uint8_t *cert_data;
    uint32_t cert_len;
    TAILQ_ENTRY(SSLCertsChain_) next;
} SSLCertsChain;


typedef struct SSLStateConnp_ {
    /* record length */
    uint32_t record_length;
    /* record length's length for SSLv2 */
    uint32_t record_lengths_length;

    /* offset of the beginning of the current message (including header) */
    uint32_t message_start;
    uint32_t message_length;

    uint16_t version;
    uint8_t content_type;

    uint8_t handshake_type;
    uint32_t handshake_length;

    /* the no of bytes processed in the currently parsed record */
    uint32_t bytes_processed;
    /* the no of bytes processed in the currently parsed handshake */
    uint16_t hs_bytes_processed;

    uint16_t session_id_length;

    uint8_t random[TLS_RANDOM_LEN];
    char *cert0_subject;
    char *cert0_issuerdn;
    char *cert0_serial;
    time_t cert0_not_before;
    time_t cert0_not_after;
    char *cert0_fingerprint;

    /* ssl server name indication extension */
    char *sni;

    char *session_id;

    TAILQ_HEAD(, SSLCertsChain_) certs;

    uint32_t cert_log_flag;

    JA3Buffer *ja3_str;
    char *ja3_hash;

    /* buffer for the tls record.
     * We use a malloced buffer, if the record is fragmented */
    uint8_t *trec;
    uint32_t trec_len;
    uint32_t trec_pos;
} SSLStateConnp;

/**
 * \brief SSLv[2.0|3.[0|1|2|3]] state structure.
 *
 *        Structure to store the SSL state values.
 */
typedef struct SSLState_ {
    Flow *f;

    AppLayerTxData tx_data;

    /* holds some state flags we need */
    uint32_t flags;

    /* there might be a better place to store this*/
    uint32_t hb_record_len;

    uint16_t events;

    uint32_t current_flags;

    SSLStateConnp *curr_connp;

    SSLStateConnp client_connp;
    SSLStateConnp server_connp;
} SSLState;

void RegisterSSLParsers(void);
void SSLParserRegisterTests(void);
void SSLVersionToString(uint16_t, char *);
void SSLEnableJA3(void);
bool SSLJA3IsEnabled(void);

#endif /* __APP_LAYER_SSL_H__ */
