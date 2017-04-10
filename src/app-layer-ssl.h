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
 *
 */

#ifndef __APP_LAYER_SSL_H__
#define __APP_LAYER_SSL_H__

#include "app-layer-protos.h"
#include "app-layer-parser.h"
#include "decode-events.h"
#include "queue.h"

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
    TLS_DECODER_EVENT_CERTIFICATE_MISSING_ELEMENT,
    TLS_DECODER_EVENT_CERTIFICATE_UNKNOWN_ELEMENT,
    TLS_DECODER_EVENT_CERTIFICATE_INVALID_LENGTH,
    TLS_DECODER_EVENT_CERTIFICATE_INVALID_STRING,
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
#define SSL_AL_FLAG_SERVER_CHANGE_CIPHER_SPEC   0x0001
/* Flag to indicate that client will now on send encrypted msgs */
#define SSL_AL_FLAG_CLIENT_CHANGE_CIPHER_SPEC   0x0002
#define SSL_AL_FLAG_CHANGE_CIPHER_SPEC          0x0004

/* SSL related flags */
#define SSL_AL_FLAG_SSL_CLIENT_HS               0x0008
#define SSL_AL_FLAG_SSL_SERVER_HS               0x0010
#define SSL_AL_FLAG_SSL_CLIENT_MASTER_KEY       0x0020
#define SSL_AL_FLAG_SSL_CLIENT_SSN_ENCRYPTED    0x0040
#define SSL_AL_FLAG_SSL_SERVER_SSN_ENCRYPTED    0x0080
#define SSL_AL_FLAG_SSL_NO_SESSION_ID           0x0100

/* flags specific to detect-ssl-state keyword */
#define SSL_AL_FLAG_STATE_CLIENT_HELLO          0x0200
#define SSL_AL_FLAG_STATE_SERVER_HELLO          0x0400
#define SSL_AL_FLAG_STATE_CLIENT_KEYX           0x0800
#define SSL_AL_FLAG_STATE_SERVER_KEYX           0x1000
#define SSL_AL_FLAG_STATE_UNKNOWN               0x2000

/* flag to indicate that session is finished */
#define SSL_AL_FLAG_STATE_FINISHED              0x4000

/* flags specific to HeartBeat state */
#define SSL_AL_FLAG_HB_INFLIGHT                 0x8000
#define SSL_AL_FLAG_HB_CLIENT_INIT              0x10000
#define SSL_AL_FLAG_HB_SERVER_INIT              0x20000

/* flag to indicate that handshake is done */
#define SSL_AL_FLAG_HANDSHAKE_DONE              0x80000

/* A session ID in the Client Hello message, indicating the client
   wants to resume a session */
#define SSL_AL_FLAG_SSL_CLIENT_SESSION_ID       0x100000
/* Session resumed without a full handshake */
#define SSL_AL_FLAG_SESSION_RESUMED             0x200000

/* config flags */
#define SSL_TLS_LOG_PEM                         (1 << 0)

/* extensions */
#define SSL_EXTENSION_SNI                       0x0000

/* SNI types */
#define SSL_SNI_TYPE_HOST_NAME                  0

/* SSL versions.  We'll use a unified format for all, with the top byte
 * holding the major version and the lower byte the minor version */
enum {
    TLS_VERSION_UNKNOWN = 0x0000,
    SSL_VERSION_2 = 0x0200,
    SSL_VERSION_3 = 0x0300,
    TLS_VERSION_10 = 0x0301,
    TLS_VERSION_11 = 0x0302,
    TLS_VERSION_12 = 0x0303,
};

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
    uint16_t bytes_processed;
    /* the no of bytes processed in the currently parsed handshake */
    uint16_t hs_bytes_processed;

    /* sslv2 client hello session id length */
    uint16_t session_id_length;

    char *cert0_subject;
    char *cert0_issuerdn;
    char *cert0_serial;
    time_t cert0_not_before;
    time_t cert0_not_after;
    char *cert0_fingerprint;

    /* ssl server name indication extension */
    char *sni;

    uint8_t *cert_input;
    uint32_t cert_input_len;

    TAILQ_HEAD(, SSLCertsChain_) certs;

    uint32_t cert_log_flag;

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

    /* holds some state flags we need */
    uint32_t flags;

    /* specifies which loggers are done logging */
    uint32_t logged;

    /* MPM/prefilter Id's */
    uint64_t mpm_ids;

    /* there might be a better place to store this*/
    uint16_t hb_record_len;

    uint16_t events;

    uint32_t current_flags;

    SSLStateConnp *curr_connp;

    SSLStateConnp client_connp;
    SSLStateConnp server_connp;

    DetectEngineState *de_state;
    AppLayerDecoderEvents *decoder_events;
} SSLState;

void RegisterSSLParsers(void);
void SSLParserRegisterTests(void);
void SSLSetEvent(SSLState *ssl_state, uint8_t event);

#endif /* __APP_LAYER_SSL_H__ */
