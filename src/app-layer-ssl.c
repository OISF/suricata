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

#include "suricata-common.h"
#include "debug.h"
#include "decode.h"
#include "threads.h"

#include "util-print.h"
#include "util-pool.h"

#include "stream-tcp-private.h"
#include "stream-tcp-reassemble.h"
#include "stream-tcp.h"
#include "stream.h"

#include "app-layer.h"
#include "app-layer-protos.h"
#include "app-layer-parser.h"
#include "app-layer-ssl.h"

#include "app-layer-tls-handshake.h"

#include "decode-events.h"
#include "conf.h"

#include "util-spm.h"
#include "util-unittest.h"
#include "util-debug.h"
#include "flow-util.h"
#include "flow-private.h"

#include "util-byte.h"

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
    /* Certificates decoding messages */
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

typedef struct SslConfig_ {
    int no_reassemble;
} SslConfig;

SslConfig ssl_config;

/* SSLv3 record types */
#define SSLV3_CHANGE_CIPHER_SPEC      20
#define SSLV3_ALERT_PROTOCOL          21
#define SSLV3_HANDSHAKE_PROTOCOL      22
#define SSLV3_APPLICATION_PROTOCOL    23
#define SSLV3_HEARTBEAT_PROTOCOL      24

/* SSLv3 handshake protocol types */
#define SSLV3_HS_HELLO_REQUEST        0
#define SSLV3_HS_CLIENT_HELLO         1
#define SSLV3_HS_SERVER_HELLO         2
#define SSLV3_HS_NEW_SESSION_TICKET   4
#define SSLV3_HS_CERTIFICATE         11
#define SSLV3_HS_SERVER_KEY_EXCHANGE 12
#define SSLV3_HS_CERTIFICATE_REQUEST 13
#define SSLV3_HS_SERVER_HELLO_DONE   14
#define SSLV3_HS_CERTIFICATE_VERIFY  15
#define SSLV3_HS_CLIENT_KEY_EXCHANGE 16
#define SSLV3_HS_FINISHED            20
#define SSLV3_HS_CERTIFICATE_URL     21
#define SSLV3_HS_CERTIFICATE_STATUS  22

/* SSLv2 protocol message types */
#define SSLV2_MT_ERROR                0
#define SSLV2_MT_CLIENT_HELLO         1
#define SSLV2_MT_CLIENT_MASTER_KEY    2
#define SSLV2_MT_CLIENT_FINISHED      3
#define SSLV2_MT_SERVER_HELLO         4
#define SSLV2_MT_SERVER_VERIFY        5
#define SSLV2_MT_SERVER_FINISHED      6
#define SSLV2_MT_REQUEST_CERTIFICATE  7
#define SSLV2_MT_CLIENT_CERTIFICATE   8

#define SSLV3_RECORD_HDR_LEN 5
#define SSLV3_MESSAGE_HDR_LEN 4

#define SSLV3_CLIENT_HELLO_VERSION_LEN 2
#define SSLV3_CLIENT_HELLO_RANDOM_LEN 32

/* TLS heartbeat protocol types */
#define TLS_HB_REQUEST              1
#define TLS_HB_RESPONSE             2

#define HAS_SPACE(n) ((uint32_t)((input) + (n) - (initial_input)) > (uint32_t)(input_len)) ?  0 : 1

static void SSLParserReset(SSLState *ssl_state)
{
    ssl_state->curr_connp->bytes_processed = 0;
}

static int SSLv3ParseHandshakeType(SSLState *ssl_state, uint8_t *input,
                                   uint32_t input_len)
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
            ssl_state->flags |= SSL_AL_FLAG_STATE_CLIENT_HELLO;

            /* skip version */
            input += SSLV3_CLIENT_HELLO_VERSION_LEN;

            /* skip random */
            input += SSLV3_CLIENT_HELLO_RANDOM_LEN;

            if (!(HAS_SPACE(1)))
                goto end;

            /* skip session id */
            uint8_t session_id_length = *(input++);

            input += session_id_length;

            if (!(HAS_SPACE(2)))
                goto end;

            /* skip cipher suites */
            uint16_t cipher_suites_length = ntohs(*(uint16_t *)input);
            input += 2;

            input += cipher_suites_length;

            if (!(HAS_SPACE(1)))
                goto end;

            /* skip compression methods */
            uint8_t compression_methods_length = *(input++);

            input += compression_methods_length;

            if (!(HAS_SPACE(2)))
                goto end;

            uint16_t extensions_len = ntohs(*(uint16_t *)input);
            input += 2;

            uint16_t processed_len = 0;
            while (processed_len < extensions_len)
            {
                if (!(HAS_SPACE(2)))
                    goto end;

                uint16_t ext_type = ntohs(*(uint16_t *)input);
                input += 2;

                if (!(HAS_SPACE(2)))
                    goto end;

                uint16_t ext_len = ntohs(*(uint16_t *)input);
                input += 2;


                switch (ext_type) {
                    case SSL_EXTENSION_SNI:
                    {
                        /* skip sni_list_length and sni_type */
                        input += 3;

                        if (!(HAS_SPACE(2)))
                            goto end;

                        uint16_t sni_len = ntohs(*(uint16_t *)input);
                        input += 2;

                        size_t sni_strlen = sni_len + 1;
                        ssl_state->curr_connp->sni = SCMalloc(sni_strlen);

                        if (unlikely(ssl_state->curr_connp->sni == NULL))
                            goto end;

                        if (!(HAS_SPACE(sni_len)))
                            goto end;

                        memcpy(ssl_state->curr_connp->sni, input,
                               sni_strlen - 1);
                        ssl_state->curr_connp->sni[sni_strlen-1] = 0;

                        input += sni_len;
                        break;
                    }
                    default:
                    {
                        input += ext_len;
                        break;
                    }
                }
                processed_len += ext_len + 4;
            }
end:
            break;

        case SSLV3_HS_SERVER_HELLO:
            ssl_state->flags |= SSL_AL_FLAG_STATE_SERVER_HELLO;
            break;

        case SSLV3_HS_SERVER_KEY_EXCHANGE:
            ssl_state->flags |= SSL_AL_FLAG_STATE_SERVER_KEYX;
            break;

        case SSLV3_HS_CLIENT_KEY_EXCHANGE:
            ssl_state->flags |= SSL_AL_FLAG_STATE_CLIENT_KEYX;
            break;

        case SSLV3_HS_CERTIFICATE:
            if (ssl_state->curr_connp->trec == NULL) {
                ssl_state->curr_connp->trec_len = 2 * ssl_state->curr_connp->record_length + SSLV3_RECORD_HDR_LEN + 1;
                ssl_state->curr_connp->trec = SCMalloc( ssl_state->curr_connp->trec_len );
            }
            if (ssl_state->curr_connp->trec_pos + input_len >= ssl_state->curr_connp->trec_len) {
                ssl_state->curr_connp->trec_len = ssl_state->curr_connp->trec_len + 2 * input_len + 1;
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
                ssl_state->curr_connp->bytes_processed += input_len;
                return -1;
            }

            uint32_t write_len = 0;
            if ((ssl_state->curr_connp->bytes_processed + input_len) > ssl_state->curr_connp->record_length + (SSLV3_RECORD_HDR_LEN)) {
                if ((ssl_state->curr_connp->record_length + SSLV3_RECORD_HDR_LEN) < ssl_state->curr_connp->bytes_processed) {
                    AppLayerDecoderEventsSetEvent(ssl_state->f, TLS_DECODER_EVENT_INVALID_SSL_RECORD);
                    return -1;
                }
                write_len = (ssl_state->curr_connp->record_length + SSLV3_RECORD_HDR_LEN) - ssl_state->curr_connp->bytes_processed;
            } else {
                write_len = input_len;
            }
            memcpy(ssl_state->curr_connp->trec + ssl_state->curr_connp->trec_pos, initial_input, write_len);
            ssl_state->curr_connp->trec_pos += write_len;

            rc = DecodeTLSHandshakeServerCertificate(ssl_state, ssl_state->curr_connp->trec, ssl_state->curr_connp->trec_pos);
            if (rc > 0) {
                /* do not return normally if the packet was fragmented:
                 * we would return the size of the *entire* message,
                 * while we expect only the number of bytes parsed bytes
                 * from the *current* fragment
                 */
                if (write_len < (ssl_state->curr_connp->trec_pos - rc)) {
                    AppLayerDecoderEventsSetEvent(ssl_state->f, TLS_DECODER_EVENT_INVALID_SSL_RECORD);
                    return -1;
                }
                uint32_t diff = write_len - (ssl_state->curr_connp->trec_pos - rc);
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
            AppLayerDecoderEventsSetEvent(ssl_state->f, TLS_DECODER_EVENT_INVALID_SSL_RECORD);
            return -1;
    }

    uint32_t write_len = 0;
    if ((ssl_state->curr_connp->bytes_processed + input_len) >= ssl_state->curr_connp->record_length + (SSLV3_RECORD_HDR_LEN)) {
        if ((ssl_state->curr_connp->record_length + SSLV3_RECORD_HDR_LEN) < ssl_state->curr_connp->bytes_processed) {
            AppLayerDecoderEventsSetEvent(ssl_state->f, TLS_DECODER_EVENT_INVALID_SSL_RECORD);
            return -1;
        }
        write_len = (ssl_state->curr_connp->record_length + SSLV3_RECORD_HDR_LEN) - ssl_state->curr_connp->bytes_processed;
    } else {
        write_len = input_len;
    }
    if ((ssl_state->curr_connp->trec_pos + write_len) >= ssl_state->curr_connp->message_length) {
        if (ssl_state->curr_connp->message_length < ssl_state->curr_connp->trec_pos) {
            AppLayerDecoderEventsSetEvent(ssl_state->f, TLS_DECODER_EVENT_INVALID_SSL_RECORD);
            return -1;
        }
        parsed += ssl_state->curr_connp->message_length - ssl_state->curr_connp->trec_pos;

        ssl_state->curr_connp->bytes_processed += ssl_state->curr_connp->message_length - ssl_state->curr_connp->trec_pos;

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
                                       uint32_t input_len)
{
    uint8_t *initial_input = input;
    int retval;

    if (input_len == 0 ||
        ssl_state->curr_connp->bytes_processed ==
        (ssl_state->curr_connp->record_length + SSLV3_RECORD_HDR_LEN))
    {
        return 0;
    }

    switch (ssl_state->curr_connp->hs_bytes_processed) {
        case 0:
            ssl_state->curr_connp->handshake_type = *(input++);
            ssl_state->curr_connp->bytes_processed++;
            ssl_state->curr_connp->hs_bytes_processed++;
            if (--input_len == 0 ||
                ssl_state->curr_connp->bytes_processed ==
                (ssl_state->curr_connp->record_length + SSLV3_RECORD_HDR_LEN))
            {
                return (input - initial_input);
            }
            /* fall through */
        case 1:
            ssl_state->curr_connp->message_length = *(input++) << 16;
            ssl_state->curr_connp->bytes_processed++;
            ssl_state->curr_connp->hs_bytes_processed++;
            if (--input_len == 0 ||
                ssl_state->curr_connp->bytes_processed ==
                (ssl_state->curr_connp->record_length + SSLV3_RECORD_HDR_LEN))
            {
                return (input - initial_input);
            }
            /* fall through */
        case 2:
            ssl_state->curr_connp->message_length |= *(input++) << 8;
            ssl_state->curr_connp->bytes_processed++;
            ssl_state->curr_connp->hs_bytes_processed++;
            if (--input_len == 0 ||
                ssl_state->curr_connp->bytes_processed ==
                (ssl_state->curr_connp->record_length + SSLV3_RECORD_HDR_LEN))
            {
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

    retval = SSLv3ParseHandshakeType(ssl_state, input, input_len);
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
 * \param input     Pointer the received input data.
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

    // expect at least 3 bytes, heartbeat type (1) + length (2)
    if (input_len < 3) {
        return 0;
    }
    hb_type = *input++;

    if (!(ssl_state->flags & SSL_AL_FLAG_CHANGE_CIPHER_SPEC)) {
        if (!(hb_type == TLS_HB_REQUEST || hb_type == TLS_HB_RESPONSE)) {
            AppLayerDecoderEventsSetEvent(ssl_state->f,
                    TLS_DECODER_EVENT_INVALID_HEARTBEAT);
            return -1;
        }
    }

    if ((ssl_state->flags & SSL_AL_FLAG_HB_INFLIGHT) == 0) {
        ssl_state->flags |= SSL_AL_FLAG_HB_INFLIGHT;

        if (direction) {
            ssl_state->flags |= SSL_AL_FLAG_HB_SERVER_INIT;
            SCLogDebug("HeartBeat Record type sent in the toclient "
                       "direction!");
        } else {
            ssl_state->flags |= SSL_AL_FLAG_HB_CLIENT_INIT;
            SCLogDebug("HeartBeat Record type sent in the toserver "
                       "direction!");
        }
        /* if we reach this poin then can we assume that the HB request
         * is encrypted if so lets set the heartbeat record len */
        if (ssl_state->flags & SSL_AL_FLAG_CHANGE_CIPHER_SPEC) {
            ssl_state->hb_record_len = ssl_state->curr_connp->record_length;
            SCLogDebug("Encrypted HeartBeat Request In-flight. Storing len %u", ssl_state->hb_record_len);
            return (ssl_state->curr_connp->record_length - 3);
        }

        payload_len = (*input++) << 8;
        payload_len |= (*input++);

        // check that the requested payload length is really present in record (CVE-2014-0160)
        if ((uint32_t)(payload_len+3) > ssl_state->curr_connp->record_length) {
            SCLogDebug("We have a short record in HeartBeat Request");
            AppLayerDecoderEventsSetEvent(ssl_state->f, TLS_DECODER_EVENT_OVERFLOW_HEARTBEAT);
            return -1;
        }

        // check the padding length
        // it must be at least 16 bytes (RFC 6520, section 4)
        padding_len = ssl_state->curr_connp->record_length - payload_len - 3;
        if (padding_len < 16) {
            SCLogDebug("We have a short record in HeartBeat Request");
            AppLayerDecoderEventsSetEvent(ssl_state->f, TLS_DECODER_EVENT_INVALID_HEARTBEAT);
            return -1;
        }

        if (input_len < payload_len+padding_len) { // we don't have the payload
            return 0;
        }

    /* OpenSSL still seems to discard multiple in-flight
     * heartbeats although some tools send multiple at once */
    } else if (direction == 1 && (ssl_state->flags & SSL_AL_FLAG_HB_INFLIGHT) &&
            (ssl_state->flags & SSL_AL_FLAG_HB_SERVER_INIT)) {
        SCLogDebug("Multiple In-Flight Server Intiated HeartBeats");
        AppLayerDecoderEventsSetEvent(ssl_state->f, TLS_DECODER_EVENT_INVALID_HEARTBEAT);
        return -1;
    } else if (direction == 0 && (ssl_state->flags & SSL_AL_FLAG_HB_INFLIGHT) &&
            (ssl_state->flags & SSL_AL_FLAG_HB_CLIENT_INIT)) {
        SCLogDebug("Multiple In-Flight Client Intiated HeartBeats");
        AppLayerDecoderEventsSetEvent(ssl_state->f, TLS_DECODER_EVENT_INVALID_HEARTBEAT);
        return -1;
    } else {
        /* we have a HB record in the opposite direction of the request
         * lets reset our flags */
        ssl_state->flags &= ~SSL_AL_FLAG_HB_INFLIGHT;
        ssl_state->flags &= ~SSL_AL_FLAG_HB_SERVER_INIT;
        ssl_state->flags &= ~SSL_AL_FLAG_HB_CLIENT_INIT;

        /* if we reach this poin then can we assume that the HB request is
         *encrypted if so lets set the heartbeat record len */
        if (ssl_state->flags & SSL_AL_FLAG_CHANGE_CIPHER_SPEC) {
            /* check to see if the encrypted response is longer than the
             * encrypted request */
            if (ssl_state->hb_record_len > 0 &&
                ssl_state->hb_record_len < ssl_state->curr_connp->record_length)
            {
                SCLogDebug("My Heart It's Bleeding.. OpenSSL HeartBleed Response (%u)",
                        ssl_state->hb_record_len);
                AppLayerDecoderEventsSetEvent(ssl_state->f,
                        TLS_DECODER_EVENT_DATALEAK_HEARTBEAT_MISMATCH);
                ssl_state->hb_record_len = 0;
                return -1;
            }
        }
        /* reset the hb record len in-case we have legit hb's followed by a bad one */
        ssl_state->hb_record_len = 0;
    }

    /* skip the heartbeat, 3 bytes were already parsed, e.g |18 03 02| for TLS 1.2 */
    return (ssl_state->curr_connp->record_length - 3);
}

static int SSLv3ParseRecord(uint8_t direction, SSLState *ssl_state,
                            uint8_t *input, uint32_t input_len)
{
    uint8_t *initial_input = input;

    if (input_len == 0) {
        return 0;
    }

    switch (ssl_state->curr_connp->bytes_processed) {
        case 0:
            if (input_len >= 5) {
                ssl_state->curr_connp->content_type = input[0];
                ssl_state->curr_connp->version = input[1] << 8;
                ssl_state->curr_connp->version |= input[2];
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
            ssl_state->curr_connp->version = *(input++) << 8;
            if (--input_len == 0)
                break;
            /* fall through */
        case 2:
            ssl_state->curr_connp->version |= *(input++);
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
    } /* switch (ssl_state->curr_connp->bytes_processed) */

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
        } /* switch (ssl_state->curr_connp->bytes_processed) */

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
        } /* switch (ssl_state->curr_connp->bytes_processed) */
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

    /* the + 1 because, we also read one extra byte inside SSLv2ParseRecord
     * to read the msg_type */
    if (ssl_state->curr_connp->bytes_processed < (ssl_state->curr_connp->record_lengths_length + 1)) {
        retval = SSLv2ParseRecord(direction, ssl_state, input, input_len);
        if (retval == -1) {
            AppLayerDecoderEventsSetEvent(ssl_state->f, TLS_DECODER_EVENT_INVALID_SSLV2_HEADER);
            return -1;
        } else {
            input += retval;
            input_len -= retval;
        }
    }

    if (input_len == 0) {
        return (input - initial_input);
    }

    switch (ssl_state->curr_connp->content_type) {
        case SSLV2_MT_ERROR:
            SCLogDebug("SSLV2_MT_ERROR msg_type received.  "
                       "Error encountered in establishing the sslv2 "
                       "session, may be version");
            AppLayerDecoderEventsSetEvent(ssl_state->f, TLS_DECODER_EVENT_ERROR_MSG_ENCOUNTERED);

            break;

        case SSLV2_MT_CLIENT_HELLO:
            ssl_state->flags |= SSL_AL_FLAG_STATE_CLIENT_HELLO;
            ssl_state->flags |= SSL_AL_FLAG_SSL_CLIENT_HS;

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
                                ssl_state->flags |= SSL_AL_FLAG_SSL_NO_SESSION_ID;
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
                } /* switch (ssl_state->curr_connp->bytes_processed) */

                /* ssl_state->curr_connp->record_lengths_length is 3 */
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
                                ssl_state->flags |= SSL_AL_FLAG_SSL_NO_SESSION_ID;
                            }
                            break;
                        } else {
                            input++;
                            ssl_state->curr_connp->bytes_processed++;
                            if (--input_len == 0)
                                break;
                        }
                    case 4:
                        input++;
                        ssl_state->curr_connp->bytes_processed++;
                        if (--input_len == 0)
                            break;
                    case 5:
                        input++;
                        ssl_state->curr_connp->bytes_processed++;
                        if (--input_len == 0)
                            break;
                    case 6:
                        input++;
                        ssl_state->curr_connp->bytes_processed++;
                        if (--input_len == 0)
                            break;
                    case 7:
                        ssl_state->curr_connp->session_id_length = *(input++) << 8;
                        ssl_state->curr_connp->bytes_processed++;
                        if (--input_len == 0)
                            break;
                    case 8:
                        ssl_state->curr_connp->session_id_length |= *(input++);
                        ssl_state->curr_connp->bytes_processed++;
                        if (--input_len == 0)
                            break;
                } /* switch (ssl_state->curr_connp->bytes_processed) */
            } /* else - if (ssl_state->curr_connp->record_lengths_length == 3) */

            break;

        case SSLV2_MT_CLIENT_MASTER_KEY:
            if ( !(ssl_state->flags & SSL_AL_FLAG_SSL_CLIENT_HS)) {
                SCLogDebug("Client hello is not seen before master key "
                           "message!!");
            }
            ssl_state->flags |= SSL_AL_FLAG_SSL_CLIENT_MASTER_KEY;

            break;

        case SSLV2_MT_CLIENT_CERTIFICATE:
            if (direction == 1) {
                SCLogDebug("Incorrect SSL Record type sent in the toclient "
                           "direction!");
            } else {
                ssl_state->flags |= SSL_AL_FLAG_STATE_CLIENT_KEYX;
            }
            /* fall through */
        case SSLV2_MT_SERVER_VERIFY:
        case SSLV2_MT_SERVER_FINISHED:
            if (direction == 0 &&
                !(ssl_state->curr_connp->content_type & SSLV2_MT_CLIENT_CERTIFICATE)) {
                SCLogDebug("Incorrect SSL Record type sent in the toserver "
                           "direction!");
            }
            /* fall through */
        case SSLV2_MT_CLIENT_FINISHED:
        case SSLV2_MT_REQUEST_CERTIFICATE:
            /* both ways hello seen */
            if ((ssl_state->flags & SSL_AL_FLAG_SSL_CLIENT_HS) &&
                (ssl_state->flags & SSL_AL_FLAG_SSL_SERVER_HS)) {

                if (direction == 0) {
                    if (ssl_state->flags & SSL_AL_FLAG_SSL_NO_SESSION_ID) {
                        ssl_state->flags |= SSL_AL_FLAG_SSL_CLIENT_SSN_ENCRYPTED;
                        SCLogDebug("SSLv2 client side has started the encryption");
                    } else if (ssl_state->flags & SSL_AL_FLAG_SSL_CLIENT_MASTER_KEY) {
                        ssl_state->flags |= SSL_AL_FLAG_SSL_CLIENT_SSN_ENCRYPTED;
                        SCLogDebug("SSLv2 client side has started the encryption");
                    }
                } else {
                    ssl_state->flags |= SSL_AL_FLAG_SSL_SERVER_SSN_ENCRYPTED;
                    SCLogDebug("SSLv2 Server side has started the encryption");
                }

                if ((ssl_state->flags & SSL_AL_FLAG_SSL_CLIENT_SSN_ENCRYPTED) &&
                    (ssl_state->flags & SSL_AL_FLAG_SSL_SERVER_SSN_ENCRYPTED)) {
                    AppLayerParserStateSetFlag(pstate,
                                                     APP_LAYER_PARSER_NO_INSPECTION);
                    if (ssl_config.no_reassemble == 1)
                        AppLayerParserStateSetFlag(pstate, APP_LAYER_PARSER_NO_REASSEMBLY);
                    SCLogDebug("SSLv2 No reassembly & inspection has been set");
                }
            }

            break;

        case SSLV2_MT_SERVER_HELLO:
            ssl_state->flags |= SSL_AL_FLAG_STATE_SERVER_HELLO;
            ssl_state->flags |= SSL_AL_FLAG_SSL_SERVER_HS;

            break;
    }

    if (input_len + ssl_state->curr_connp->bytes_processed >=
        (ssl_state->curr_connp->record_length + ssl_state->curr_connp->record_lengths_length)) {
        /* looks like we have another record after this*/
        uint32_t diff = ssl_state->curr_connp->record_length +
            ssl_state->curr_connp->record_lengths_length + - ssl_state->curr_connp->bytes_processed;
        input += diff;
        SSLParserReset(ssl_state);
        return (input - initial_input);

        /* we still don't have the entire record for the one we are
         * currently parsing */
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
            AppLayerDecoderEventsSetEvent(ssl_state->f, TLS_DECODER_EVENT_INVALID_TLS_HEADER);
            return -1;
        } else {
            parsed += retval;
            input_len -= retval;
        }
    }

    if (input_len == 0) {
        return parsed;
    }

    /* check record version */
    if (ssl_state->curr_connp->version < SSL_VERSION_3 ||
        ssl_state->curr_connp->version > TLS_VERSION_12) {

        AppLayerDecoderEventsSetEvent(ssl_state->f,
                TLS_DECODER_EVENT_INVALID_RECORD_VERSION);
        return -1;
    }

    switch (ssl_state->curr_connp->content_type) {

        /* we don't need any data from these types */
        case SSLV3_CHANGE_CIPHER_SPEC:
            ssl_state->flags |= SSL_AL_FLAG_CHANGE_CIPHER_SPEC;

            if (direction)
                ssl_state->flags |= SSL_AL_FLAG_SERVER_CHANGE_CIPHER_SPEC;
            else
                ssl_state->flags |= SSL_AL_FLAG_CLIENT_CHANGE_CIPHER_SPEC;

            break;

        case SSLV3_ALERT_PROTOCOL:
            break;
        case SSLV3_APPLICATION_PROTOCOL:
            if ((ssl_state->flags & SSL_AL_FLAG_CLIENT_CHANGE_CIPHER_SPEC) &&
                (ssl_state->flags & SSL_AL_FLAG_SERVER_CHANGE_CIPHER_SPEC)) {
                /*
                AppLayerParserStateSetFlag(pstate, APP_LAYER_PARSER_NO_INSPECTION);
                if (ssl_config.no_reassemble == 1)
                    AppLayerParserStateSetFlag(pstate, APP_LAYER_PARSER_NO_REASSEMBLY);
                */
                AppLayerParserStateSetFlag(pstate,APP_LAYER_PARSER_NO_INSPECTION_PAYLOAD);
            }

            break;

        case SSLV3_HANDSHAKE_PROTOCOL:
            if (ssl_state->flags & SSL_AL_FLAG_CHANGE_CIPHER_SPEC)
                break;

            if (ssl_state->curr_connp->record_length < 4) {
                SSLParserReset(ssl_state);
                AppLayerDecoderEventsSetEvent(ssl_state->f, TLS_DECODER_EVENT_INVALID_SSL_RECORD);
                return -1;
            }

            retval = SSLv3ParseHandshakeProtocol(ssl_state, input + parsed, input_len);
            if (retval < 0) {
                AppLayerDecoderEventsSetEvent(ssl_state->f, TLS_DECODER_EVENT_INVALID_HANDSHAKE_MESSAGE);
                AppLayerDecoderEventsSetEvent(ssl_state->f, TLS_DECODER_EVENT_INVALID_SSL_RECORD);
                return -1;
            } else {
                if ((uint32_t)retval > input_len) {
                    SCLogDebug("Error parsing SSLv3.x.  Reseting parser "
                            "state.  Let's get outta here");
                    SSLParserReset(ssl_state);
                    AppLayerDecoderEventsSetEvent(ssl_state->f, TLS_DECODER_EVENT_INVALID_SSL_RECORD);
                    return -1;
                }
                parsed += retval;
                input_len -= retval;
                if (ssl_state->curr_connp->bytes_processed == ssl_state->curr_connp->record_length + SSLV3_RECORD_HDR_LEN) {
                    SSLParserReset(ssl_state);
                }

                SCLogDebug("trigger RAW! (post HS)");
                AppLayerParserTriggerRawStreamReassembly(ssl_state->f);
                return parsed;
            }

            break;
        case SSLV3_HEARTBEAT_PROTOCOL:
            retval = SSLv3ParseHeartbeatProtocol(ssl_state, input + parsed, input_len, direction);
            if (retval < 0)
                return -1;
            break;

        default:
            /* \todo fix the event from invalid rule to unknown rule */
            AppLayerDecoderEventsSetEvent(ssl_state->f, TLS_DECODER_EVENT_INVALID_RECORD_TYPE);
            AppLayerDecoderEventsSetEvent(ssl_state->f, TLS_DECODER_EVENT_INVALID_SSL_RECORD);
            return -1;
    }

    if (input_len + ssl_state->curr_connp->bytes_processed >= ssl_state->curr_connp->record_length + SSLV3_RECORD_HDR_LEN) {
        if ((ssl_state->curr_connp->record_length + SSLV3_RECORD_HDR_LEN) < ssl_state->curr_connp->bytes_processed) {
            /* defensive checks.  Something's wrong. */
            AppLayerDecoderEventsSetEvent(ssl_state->f, TLS_DECODER_EVENT_INVALID_SSL_RECORD);
            return -1;
        }

        SCLogDebug("record complete, trigger RAW");
        AppLayerParserTriggerRawStreamReassembly(ssl_state->f);

        /* looks like we have another record */
        uint32_t diff = ssl_state->curr_connp->record_length + SSLV3_RECORD_HDR_LEN - ssl_state->curr_connp->bytes_processed;
        parsed += diff;
        SSLParserReset(ssl_state);
        return parsed;

        /* we still don't have the entire record for the one we are
         * currently parsing */
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
    uint8_t counter = 0;

    int32_t input_len = (int32_t)ilen;

    ssl_state->f = f;

    if (input == NULL && AppLayerParserStateIssetFlag(pstate, APP_LAYER_PARSER_EOF)) {
        SCReturnInt(1);
    } else if (input == NULL || input_len == 0) {
        SCReturnInt(-1);
    }

    if (direction == 0)
        ssl_state->curr_connp = &ssl_state->client_connp;
    else
        ssl_state->curr_connp = &ssl_state->server_connp;

    /* if we have more than one record */
    while (input_len > 0) {
        if (counter++ == 30) {
            SCLogDebug("Looks like we have looped quite a bit.  Reset state "
                       "and get out of here");
            SSLParserReset(ssl_state);
            AppLayerDecoderEventsSetEvent(ssl_state->f, TLS_DECODER_EVENT_INVALID_SSL_RECORD);
            return -1;
        }

        /* ssl_state->bytes_processed is 0 for a
         * fresh record or positive to indicate a record currently being
         * parsed */
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
                        SCLogDebug("Error parsing SSLv2.x.  Reseting parser "
                                   "state.  Let's get outta here");
                        SSLParserReset(ssl_state);
                        AppLayerDecoderEventsSetEvent(ssl_state->f, TLS_DECODER_EVENT_INVALID_SSL_RECORD);
                        return -1;
                    } else {
                        input_len -= retval;
                        input += retval;
                    }
                } else {
                    SCLogDebug("SSLv3.x detected");
                    /* we will keep it this way till our record parser tells
                     * us what exact version it is */
                    ssl_state->curr_connp->version = TLS_VERSION_UNKNOWN;
                    retval = SSLv3Decode(direction, ssl_state, pstate, input,
                                         input_len);
                    if (retval < 0) {
                        SCLogDebug("Error parsing SSLv3.x.  Reseting parser "
                                   "state.  Let's get outta here");
                        SSLParserReset(ssl_state);
                        AppLayerDecoderEventsSetEvent(ssl_state->f, TLS_DECODER_EVENT_INVALID_SSL_RECORD);
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
                    if (retval == -1) {
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
    } /* while (input_len) */

    return 1;
}

int SSLParseClientRecord(Flow *f, void *alstate, AppLayerParserState *pstate,
                         uint8_t *input, uint32_t input_len,
                         void *local_data)
{
    return SSLDecode(f, 0 /* toserver */, alstate, pstate, input, input_len);
}

int SSLParseServerRecord(Flow *f, void *alstate, AppLayerParserState *pstate,
                         uint8_t *input, uint32_t input_len,
                         void *local_data)
{
    return SSLDecode(f, 1 /* toclient */, alstate, pstate, input, input_len);
}

/**
 * \internal
 * \brief Function to allocate the SSL state memory.
 */
void *SSLStateAlloc(void)
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
void SSLStateFree(void *p)
{
    SSLState *ssl_state = (SSLState *)p;
    SSLCertsChain *item;

    if (ssl_state->client_connp.trec)
        SCFree(ssl_state->client_connp.trec);
    if (ssl_state->client_connp.cert0_subject)
        SCFree(ssl_state->client_connp.cert0_subject);
    if (ssl_state->client_connp.cert0_issuerdn)
        SCFree(ssl_state->client_connp.cert0_issuerdn);
    if (ssl_state->client_connp.cert0_fingerprint)
        SCFree(ssl_state->client_connp.cert0_fingerprint);
    if (ssl_state->client_connp.sni)
        SCFree(ssl_state->client_connp.sni);

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

    /* Free certificate chain */
    while ((item = TAILQ_FIRST(&ssl_state->server_connp.certs))) {
        TAILQ_REMOVE(&ssl_state->server_connp.certs, item, next);
        SCFree(item);
    }
    TAILQ_INIT(&ssl_state->server_connp.certs);

    SCFree(ssl_state);

    return;
}

static uint16_t SSLProbingParser(uint8_t *input, uint32_t ilen, uint32_t *offset)
{
    /* probably a rst/fin sending an eof */
    if (ilen == 0)
        return ALPROTO_UNKNOWN;

    /* for now just the 3 byte header ones */
    /* \todo Detect the 2 byte ones */
    if ((input[0] & 0x80) && (input[2] == 0x01)) {
        return ALPROTO_TLS;
    }

    return ALPROTO_FAILED;
}

int SSLStateGetEventInfo(const char *event_name,
                         int *event_id, AppLayerEventType *event_type)
{
    *event_id = SCMapEnumNameToValue(event_name, tls_decoder_event_table);
    if (*event_id == -1) {
        SCLogError(SC_ERR_INVALID_ENUM_MAP, "event \"%s\" not present in "
                   "ssl's enum map table.",  event_name);
        /* yes this is fatal */
        return -1;
    }

    *event_type = APP_LAYER_EVENT_TYPE_GENERAL;

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
    char *proto_name = "tls";

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
                                          SSLProbingParser);
        } else {
            AppLayerProtoDetectPPParseConfPorts("tcp", IPPROTO_TCP,
                                                proto_name, ALPROTO_TLS,
                                                0, 3,
                                                SSLProbingParser);
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

        AppLayerParserRegisterStateFuncs(IPPROTO_TCP, ALPROTO_TLS, SSLStateAlloc, SSLStateFree);
        AppLayerParserRegisterParserAcceptableDataDirection(IPPROTO_TCP, ALPROTO_TLS, STREAM_TOSERVER);

        /* Get the value of no reassembly option from the config file */
        if (ConfGetNode("app-layer.protocols.tls.no-reassemble") == NULL) {
            if (ConfGetBool("tls.no-reassemble", &ssl_config.no_reassemble) != 1)
                ssl_config.no_reassemble = 1;
        } else {
            if (ConfGetBool("app-layer.protocols.tls.no-reassemble", &ssl_config.no_reassemble) != 1)
                ssl_config.no_reassemble = 1;
        }
    } else {
        SCLogInfo("Parsed disabled for %s protocol. Protocol detection"
                  "still on.", proto_name);
    }

#ifdef UNITTESTS
    AppLayerParserRegisterProtocolUnittests(IPPROTO_TCP, ALPROTO_TLS, SSLParserRegisterTests);
#endif

    /* Get the value of no reassembly option from the config file */
    if (ConfGetBool("tls.no-reassemble", &ssl_config.no_reassemble) != 1)
        ssl_config.no_reassemble = 1;

    return;
}

/***************************************Unittests******************************/

#ifdef UNITTESTS

/**
 *\test Send a get request in one chunk.
 */
static int SSLParserTest01(void)
{
    int result = 1;
    Flow f;
    uint8_t tlsbuf[] = { 0x16, 0x03, 0x01 };
    uint32_t tlslen = sizeof(tlsbuf);
    TcpSession ssn;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;

    StreamTcpInitConfig(TRUE);

    SCMutexLock(&f.m);
    int r = AppLayerParserParse(alp_tctx, &f, ALPROTO_TLS, STREAM_TOSERVER | STREAM_EOF, tlsbuf, tlslen);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);

    SSLState *ssl_state = f.alstate;
    if (ssl_state == NULL) {
        printf("no tls state: ");
        result = 0;
        goto end;
    }

    if (ssl_state->client_connp.content_type != 0x16) {
        printf("expected content_type %" PRIu8 ", got %" PRIu8 ": ", 0x16,
                ssl_state->client_connp.content_type);
        result = 0;
        goto end;
    }

    if (ssl_state->client_connp.version != TLS_VERSION_10) {
        printf("expected version %04" PRIu16 ", got %04" PRIu16 ": ",
                TLS_VERSION_10, ssl_state->client_connp.version);
        result = 0;
        goto end;
    }
end:
    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
    StreamTcpFreeConfig(TRUE);
    return result;
}

/** \test Send a get request in two chunks. */
static int SSLParserTest02(void)
{
    int result = 1;
    Flow f;
    uint8_t tlsbuf1[] = { 0x16 };
    uint32_t tlslen1 = sizeof(tlsbuf1);
    uint8_t tlsbuf2[] = { 0x03, 0x01 };
    uint32_t tlslen2 = sizeof(tlsbuf2);
    TcpSession ssn;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;

    StreamTcpInitConfig(TRUE);

    SCMutexLock(&f.m);
    int r = AppLayerParserParse(alp_tctx, &f, ALPROTO_TLS, STREAM_TOSERVER, tlsbuf1, tlslen1);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);

    SCMutexLock(&f.m);
    r = AppLayerParserParse(alp_tctx, &f, ALPROTO_TLS, STREAM_TOSERVER, tlsbuf2, tlslen2);
    if (r != 0) {
        printf("toserver chunk 2 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);

    SSLState *ssl_state = f.alstate;
    if (ssl_state == NULL) {
        printf("no tls state: ");
        result = 0;
        goto end;
    }

    if (ssl_state->client_connp.content_type != 0x16) {
        printf("expected content_type %" PRIu8 ", got %" PRIu8 ": ", 0x16,
                ssl_state->client_connp.content_type);
        result = 0;
        goto end;
    }

    if (ssl_state->client_connp.version != TLS_VERSION_10) {
        printf("expected version %04" PRIu16 ", got %04" PRIu16 ": ",
                TLS_VERSION_10, ssl_state->client_connp.version);
        result = 0;
        goto end;
    }
end:
    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
    StreamTcpFreeConfig(TRUE);
    return result;
}

/** \test Send a get request in three chunks. */
static int SSLParserTest03(void)
{
    int result = 1;
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
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;

    StreamTcpInitConfig(TRUE);

    SCMutexLock(&f.m);
    int r = AppLayerParserParse(alp_tctx, &f, ALPROTO_TLS, STREAM_TOSERVER, tlsbuf1, tlslen1);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);

    SCMutexLock(&f.m);
    r = AppLayerParserParse(alp_tctx, &f, ALPROTO_TLS, STREAM_TOSERVER, tlsbuf2, tlslen2);
    if (r != 0) {
        printf("toserver chunk 2 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);

    SCMutexLock(&f.m);
    r = AppLayerParserParse(alp_tctx, &f, ALPROTO_TLS, STREAM_TOSERVER, tlsbuf3, tlslen3);
    if (r != 0) {
        printf("toserver chunk 3 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);

    SSLState *ssl_state = f.alstate;
    if (ssl_state == NULL) {
        printf("no tls state: ");
        result = 0;
        goto end;
    }

    if (ssl_state->client_connp.content_type != 0x16) {
        printf("expected content_type %" PRIu8 ", got %" PRIu8 ": ", 0x16,
                ssl_state->client_connp.content_type);
        result = 0;
        goto end;
    }

    if (ssl_state->client_connp.version != TLS_VERSION_10) {
        printf("expected version %04" PRIu16 ", got %04" PRIu16 ": ",
                TLS_VERSION_10, ssl_state->client_connp.version);
        result = 0;
        goto end;
    }
end:
    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
    StreamTcpFreeConfig(TRUE);
    return result;
}

/** \test Send a get request in three chunks + more data. */
static int SSLParserTest04(void)
{
    int result = 1;
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
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;

    StreamTcpInitConfig(TRUE);

    SCMutexLock(&f.m);
    int r = AppLayerParserParse(alp_tctx, &f, ALPROTO_TLS, STREAM_TOSERVER, tlsbuf1, tlslen1);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);

    SCMutexLock(&f.m);
    r = AppLayerParserParse(alp_tctx, &f, ALPROTO_TLS, STREAM_TOSERVER, tlsbuf2, tlslen2);
    if (r != 0) {
        printf("toserver chunk 2 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);

    SCMutexLock(&f.m);
    r = AppLayerParserParse(alp_tctx, &f, ALPROTO_TLS, STREAM_TOSERVER, tlsbuf3, tlslen3);
    if (r != 0) {
        printf("toserver chunk 3 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);

    SCMutexLock(&f.m);
    r = AppLayerParserParse(alp_tctx, &f, ALPROTO_TLS, STREAM_TOSERVER, tlsbuf4, tlslen4);
    if (r != 0) {
        printf("toserver chunk 4 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);

    SSLState *ssl_state = f.alstate;
    if (ssl_state == NULL) {
        printf("no tls state: ");
        result = 0;
        goto end;
    }

    if (ssl_state->client_connp.content_type != 0x16) {
        printf("expected content_type %" PRIu8 ", got %" PRIu8 ": ", 0x16,
                ssl_state->client_connp.content_type);
        result = 0;
        goto end;
    }

    if (ssl_state->client_connp.version != TLS_VERSION_10) {
        printf("expected version %04" PRIu16 ", got %04" PRIu16 ": ",
                TLS_VERSION_10, ssl_state->client_connp.version);
        result = 0;
        goto end;
    }
end:
    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
    StreamTcpFreeConfig(TRUE);
    return result;
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
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;

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
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;

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
    return result;
}
#endif

/** \test multimsg test */
static int SSLParserMultimsgTest01(void)
{
    int result = 1;
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
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;

    StreamTcpInitConfig(TRUE);

    SCMutexLock(&f.m);
    int r = AppLayerParserParse(alp_tctx, &f, ALPROTO_TLS, STREAM_TOSERVER, tlsbuf1, tlslen1);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);

    SSLState *ssl_state = f.alstate;
    if (ssl_state == NULL) {
        printf("no tls state: ");
        result = 0;
        goto end;
    }

    if (ssl_state->client_connp.content_type != 0x16) {
        printf("expected content_type %" PRIu8 ", got %" PRIu8 ": ", 0x16,
                ssl_state->client_connp.content_type);
        result = 0;
        goto end;
    }

    if (ssl_state->client_connp.version != TLS_VERSION_10) {
        printf("expected version %04" PRIu16 ", got %04" PRIu16 ": ",
               TLS_VERSION_10, ssl_state->client_connp.version);
        result = 0;
        goto end;
    }
end:
    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
    StreamTcpFreeConfig(TRUE);
    return result;
}

/** \test multimsg test server */
static int SSLParserMultimsgTest02(void)
{
    int result = 1;
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
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;

    StreamTcpInitConfig(TRUE);

    SCMutexLock(&f.m);
    int r = AppLayerParserParse(alp_tctx, &f, ALPROTO_TLS, STREAM_TOCLIENT, tlsbuf1, tlslen1);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);

    SSLState *ssl_state = f.alstate;
    if (ssl_state == NULL) {
        printf("no tls state: ");
        result = 0;
        goto end;
    }

    if (ssl_state->server_connp.content_type != 0x16) {
        printf("expected content_type %" PRIu8 ", got %" PRIu8 ": ", 0x16,
                ssl_state->server_connp.content_type);
        result = 0;
        goto end;
    }

    if (ssl_state->server_connp.version != 0x0301) {
        printf("expected version %04" PRIu16 ", got %04" PRIu16 ": ", 0x0301,
                ssl_state->server_connp.version);
        result = 0;
        goto end;
    }
end:
    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
    StreamTcpFreeConfig(TRUE);
    return result;
}

/**
 *  \test   Test the detection of SSLv3 protocol from the given packet
 */
static int SSLParserTest07(void)
{
    int result = 1;
    Flow f;
    uint8_t tlsbuf[] = { 0x16, 0x03, 0x00, 0x00, 0x6f, 0x01,
            0x00, 0x00, 0x6b, 0x03, 0x00, 0x4b, 0x2f, 0xdc,
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
            0x00, 0x0a, 0x00, 0x02, 0x01, 0x00 };
    uint32_t tlslen = sizeof(tlsbuf);
    TcpSession ssn;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;

    StreamTcpInitConfig(TRUE);

    SCMutexLock(&f.m);
    int r = AppLayerParserParse(alp_tctx, &f, ALPROTO_TLS, STREAM_TOSERVER, tlsbuf, tlslen);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);

    SSLState *ssl_state = f.alstate;
    if (ssl_state == NULL) {
        printf("no tls state: ");
        result = 0;
        goto end;
    }

    if (ssl_state->client_connp.content_type != 0x16) {
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

end:
    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
    StreamTcpFreeConfig(TRUE);
    return result;
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
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;

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
    return result;
}

#endif

/**
 * \test Tests the parser for handling fragmented records.
 */
static int SSLParserTest09(void)
{
    int result = 1;
    Flow f;
    uint8_t buf1[] = {
        0x16,
    };
    uint32_t buf1_len = sizeof(buf1);

    uint8_t buf2[] = {
        0x03, 0x00, 0x00, 0x6f, 0x01,
        0x00, 0x00, 0x6b, 0x03, 0x00, 0x4b, 0x2f, 0xdc,
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
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;

    StreamTcpInitConfig(TRUE);

    SCMutexLock(&f.m);
    int r = AppLayerParserParse(alp_tctx, &f, ALPROTO_TLS, STREAM_TOSERVER, buf1, buf1_len);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);

    SCMutexLock(&f.m);
    r = AppLayerParserParse(alp_tctx, &f, ALPROTO_TLS, STREAM_TOSERVER, buf2, buf2_len);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);

    SSLState *ssl_state = f.alstate;
    if (ssl_state == NULL) {
        printf("no tls state: ");
        result = 0;
        goto end;
    }

    if (ssl_state->client_connp.content_type != 0x16) {
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

end:
    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
    StreamTcpFreeConfig(TRUE);
    return result;
}

/**
 * \test Tests the parser for handling fragmented records.
 */
static int SSLParserTest10(void)
{
    int result = 1;
    Flow f;
    uint8_t buf1[] = {
        0x16, 0x03,
    };
    uint32_t buf1_len = sizeof(buf1);

    uint8_t buf2[] = {
        0x00, 0x00, 0x6f, 0x01,
        0x00, 0x00, 0x6b, 0x03, 0x00, 0x4b, 0x2f, 0xdc,
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
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;

    StreamTcpInitConfig(TRUE);

    SCMutexLock(&f.m);
    int r = AppLayerParserParse(alp_tctx, &f, ALPROTO_TLS, STREAM_TOSERVER, buf1, buf1_len);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);

    SCMutexLock(&f.m);
    r = AppLayerParserParse(alp_tctx, &f, ALPROTO_TLS, STREAM_TOSERVER, buf2, buf2_len);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);

    SSLState *ssl_state = f.alstate;
    if (ssl_state == NULL) {
        printf("no tls state: ");
        result = 0;
        goto end;
    }

    if (ssl_state->client_connp.content_type != 0x16) {
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

end:
    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
    StreamTcpFreeConfig(TRUE);
    return result;
}

/**
 * \test Tests the parser for handling fragmented records.
 */
static int SSLParserTest11(void)
{
    int result = 1;
    Flow f;
    uint8_t buf1[] = {
        0x16, 0x03, 0x00, 0x00, 0x6f, 0x01,
    };
    uint32_t buf1_len = sizeof(buf1);

    uint8_t buf2[] = {
        0x00, 0x00, 0x6b, 0x03, 0x00, 0x4b, 0x2f, 0xdc,
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
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;

    StreamTcpInitConfig(TRUE);

    SCMutexLock(&f.m);
    int r = AppLayerParserParse(alp_tctx, &f, ALPROTO_TLS, STREAM_TOSERVER, buf1, buf1_len);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);

    SCMutexLock(&f.m);
    r = AppLayerParserParse(alp_tctx, &f, ALPROTO_TLS, STREAM_TOSERVER, buf2, buf2_len);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);

    SSLState *ssl_state = f.alstate;
    if (ssl_state == NULL) {
        printf("no tls state: ");
        result = 0;
        goto end;
    }

    if (ssl_state->client_connp.content_type != 0x16) {
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

end:
    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
    StreamTcpFreeConfig(TRUE);
    return result;
}

/**
 * \test Tests the parser for handling fragmented records.
 */
static int SSLParserTest12(void)
{
    int result = 1;
    Flow f;
    uint8_t buf1[] = {
        0x16, 0x03, 0x00, 0x00, 0x6f, 0x01,
    };
    uint32_t buf1_len = sizeof(buf1);

    uint8_t buf2[] = {
        0x00, 0x00, 0x6b,
    };
    uint32_t buf2_len = sizeof(buf2);

    uint8_t buf3[] = {
        0x03, 0x00, 0x4b, 0x2f, 0xdc,
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
    uint32_t buf3_len = sizeof(buf2);
    TcpSession ssn;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;

    StreamTcpInitConfig(TRUE);

    SCMutexLock(&f.m);
    int r = AppLayerParserParse(alp_tctx, &f, ALPROTO_TLS, STREAM_TOSERVER, buf1, buf1_len);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);

    SCMutexLock(&f.m);
    r = AppLayerParserParse(alp_tctx, &f, ALPROTO_TLS, STREAM_TOSERVER, buf2, buf2_len);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);

    SCMutexLock(&f.m);
    r = AppLayerParserParse(alp_tctx, &f, ALPROTO_TLS, STREAM_TOSERVER, buf3, buf3_len);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);

    SSLState *ssl_state = f.alstate;
    if (ssl_state == NULL) {
        printf("no tls state: ");
        result = 0;
        goto end;
    }

    if (ssl_state->client_connp.content_type != 0x16) {
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

end:
    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
    StreamTcpFreeConfig(TRUE);
    return result;
}

/**
 * \test Tests the parser for handling fragmented records.
 */
static int SSLParserTest13(void)
{
    int result = 1;
    Flow f;
    uint8_t buf1[] = {
        0x16, 0x03, 0x00, 0x00, 0x6f, 0x01,
    };
    uint32_t buf1_len = sizeof(buf1);

    uint8_t buf2[] = {
        0x00, 0x00, 0x6b,
    };
    uint32_t buf2_len = sizeof(buf2);

    uint8_t buf3[] = {
        0x03, 0x00, 0x4b, 0x2f, 0xdc,
        0x4e, 0xe6, 0x95, 0xf1, 0xa0, 0xc7,
    };
    uint32_t buf3_len = sizeof(buf3);

    uint8_t buf4[] = {
        0xcf, 0x8e,
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
    uint32_t buf4_len = sizeof(buf4);
    TcpSession ssn;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;

    StreamTcpInitConfig(TRUE);

    SCMutexLock(&f.m);
    int r = AppLayerParserParse(alp_tctx, &f, ALPROTO_TLS, STREAM_TOSERVER, buf1, buf1_len);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);

    SCMutexLock(&f.m);
    r = AppLayerParserParse(alp_tctx, &f, ALPROTO_TLS, STREAM_TOSERVER, buf2, buf2_len);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);

    SCMutexLock(&f.m);
    r = AppLayerParserParse(alp_tctx, &f, ALPROTO_TLS, STREAM_TOSERVER, buf3, buf3_len);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);

    SCMutexLock(&f.m);
    r = AppLayerParserParse(alp_tctx, &f, ALPROTO_TLS, STREAM_TOSERVER, buf4, buf4_len);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);

    SSLState *ssl_state = f.alstate;
    if (ssl_state == NULL) {
        printf("no tls state: ");
        result = 0;
        goto end;
    }

    if (ssl_state->client_connp.content_type != 0x16) {
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

end:
    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
    StreamTcpFreeConfig(TRUE);
    return result;
}

/**
 * \test Tests the parser for handling fragmented records.
 */
static int SSLParserTest14(void)
{
    int result = 1;
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
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;

    StreamTcpInitConfig(TRUE);

    SCMutexLock(&f.m);
    int r = AppLayerParserParse(alp_tctx, &f, ALPROTO_TLS, STREAM_TOSERVER, buf1, buf1_len);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);

    SCMutexLock(&f.m);
    r = AppLayerParserParse(alp_tctx, &f, ALPROTO_TLS, STREAM_TOSERVER, buf2, buf2_len);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);

    SSLState *ssl_state = f.alstate;
    if (ssl_state == NULL) {
        printf("no tls state: ");
        result = 0;
        goto end;
    }

end:
    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
    StreamTcpFreeConfig(TRUE);
    return result;
}

/**
 * \test Tests the parser for handling fragmented records.
 */
static int SSLParserTest15(void)
{
    int result = 1;
    Flow f;

    uint8_t buf1[] = {
        0x16, 0x03, 0x00, 0x00, 0x01, 0x01,
    };
    uint32_t buf1_len = sizeof(buf1);

    TcpSession ssn;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;

    StreamTcpInitConfig(TRUE);

    SCMutexLock(&f.m);
    int r = AppLayerParserParse(alp_tctx, &f, ALPROTO_TLS, STREAM_TOSERVER, buf1, buf1_len);
    if (r == 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);

end:
    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
    StreamTcpFreeConfig(TRUE);
    return result;
}

/**
 * \test Tests the parser for handling fragmented records.
 */
static int SSLParserTest16(void)
{
    int result = 1;
    Flow f;

    uint8_t buf1[] = {
        0x16, 0x03, 0x00, 0x00, 0x02, 0x01, 0x00
    };
    uint32_t buf1_len = sizeof(buf1);

    TcpSession ssn;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;

    StreamTcpInitConfig(TRUE);

    SCMutexLock(&f.m);
    int r = AppLayerParserParse(alp_tctx, &f, ALPROTO_TLS, STREAM_TOSERVER, buf1, buf1_len);
    if (r == 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);

end:
    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
    StreamTcpFreeConfig(TRUE);
    return result;
}

/**
 * \test Tests the parser for handling fragmented records.
 */
static int SSLParserTest17(void)
{
    int result = 1;
    Flow f;

    uint8_t buf1[] = {
        0x16, 0x03, 0x00, 0x00, 0x03, 0x01, 0x00, 0x00
    };
    uint32_t buf1_len = sizeof(buf1);

    TcpSession ssn;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;

    StreamTcpInitConfig(TRUE);

    SCMutexLock(&f.m);
    int r = AppLayerParserParse(alp_tctx, &f, ALPROTO_TLS, STREAM_TOSERVER, buf1, buf1_len);
    if (r == 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);

end:
    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
    StreamTcpFreeConfig(TRUE);
    return result;
}

/**
 * \test Tests the parser for handling fragmented records.
 */
static int SSLParserTest18(void)
{
    int result = 1;
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
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;

    StreamTcpInitConfig(TRUE);

    SCMutexLock(&f.m);
    int r = AppLayerParserParse(alp_tctx, &f, ALPROTO_TLS, STREAM_TOSERVER, buf1, buf1_len);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);

    SCMutexLock(&f.m);
    r = AppLayerParserParse(alp_tctx, &f, ALPROTO_TLS, STREAM_TOSERVER, buf2, buf2_len);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);

    SSLState *ssl_state = f.alstate;
    if (ssl_state == NULL) {
        printf("no tls state: ");
        result = 0;
        goto end;
    }

end:
    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
    StreamTcpFreeConfig(TRUE);
    return result;
}

/**
 * \test Tests the parser for handling fragmented records.
 */
static int SSLParserTest19(void)
{
    int result = 1;
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
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;

    StreamTcpInitConfig(TRUE);

    SCMutexLock(&f.m);
    int r = AppLayerParserParse(alp_tctx, &f, ALPROTO_TLS, STREAM_TOSERVER, buf1, buf1_len);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);

    SSLState *ssl_state = f.alstate;
    if (ssl_state == NULL) {
        printf("no tls state: ");
        result = 0;
        goto end;
    }

end:
    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
    StreamTcpFreeConfig(TRUE);
    return result;
}

/**
 * \test Tests the parser for handling fragmented records.
 */
static int SSLParserTest20(void)
{
    int result = 1;
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
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;

    StreamTcpInitConfig(TRUE);

    SCMutexLock(&f.m);
    int r = AppLayerParserParse(alp_tctx, &f, ALPROTO_TLS, STREAM_TOSERVER, buf1, buf1_len);
    if (r == 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);

end:
    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
    StreamTcpFreeConfig(TRUE);
    return result;
}

/**
 * \test SSLv2 Record parsing.
 */
static int SSLParserTest21(void)
{
    int result = 0;
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

    StreamTcpInitConfig(TRUE);

    SCMutexLock(&f.m);
    int r = AppLayerParserParse(alp_tctx, &f, ALPROTO_TLS, STREAM_TOSERVER | STREAM_EOF, buf,
                                buf_len);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);

    SSLState *app_state = f.alstate;
    if (app_state == NULL) {
        printf("no ssl state: ");
        goto end;
    }

    if (app_state->client_connp.content_type != SSLV2_MT_CLIENT_HELLO) {
        printf("expected content_type %" PRIu8 ", got %" PRIu8 ": ",
               SSLV2_MT_SERVER_HELLO, app_state->client_connp.content_type);
        goto end;
    }

    if (app_state->client_connp.version != SSL_VERSION_2) {
        printf("expected version %04" PRIu16 ", got %04" PRIu16 ": ",
               SSL_VERSION_2, app_state->client_connp.version);
        goto end;
    }

    result = 1;
end:
    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
    StreamTcpFreeConfig(TRUE);
    FLOW_DESTROY(&f);
    return result;
}

/**
 * \test SSLv2 Record parsing.
 */
static int SSLParserTest22(void)
{
    int result = 1;
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

    StreamTcpInitConfig(TRUE);

    SCMutexLock(&f.m);
    int r = AppLayerParserParse(alp_tctx, &f, ALPROTO_TLS, STREAM_TOCLIENT | STREAM_EOF, buf,
                                buf_len);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);

    SSLState *app_state = f.alstate;
    if (app_state == NULL) {
        printf("no ssl state: ");
        result = 0;
        goto end;
    }

    if (app_state->server_connp.content_type != SSLV2_MT_SERVER_HELLO) {
        printf("expected content_type %" PRIu8 ", got %" PRIu8 ": ",
               SSLV2_MT_SERVER_HELLO, app_state->server_connp.content_type);
        result = 0;
        goto end;
    }

    if (app_state->server_connp.version != SSL_VERSION_2) {
        printf("expected version %04" PRIu16 ", got %04" PRIu16 ": ",
                SSL_VERSION_2, app_state->server_connp.version);
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

/**
 * \test SSLv2 Record parsing.
 */
static int SSLParserTest23(void)
{
    int result = 1;
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

    StreamTcpInitConfig(TRUE);

    SCMutexLock(&f.m);
    int r = AppLayerParserParse(alp_tctx, &f, ALPROTO_TLS, STREAM_TOSERVER | STREAM_START, chello_buf,
                                chello_buf_len);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);

    SSLState *app_state = f.alstate;
    if (app_state == NULL) {
        printf("no ssl state: ");
        result = 0;
        goto end;
    }

    if (app_state->client_connp.content_type != SSLV2_MT_CLIENT_HELLO) {
        printf("expected content_type %" PRIu8 ", got %" PRIu8 ": ",
               SSLV2_MT_CLIENT_HELLO, app_state->client_connp.content_type);
        result = 0;
        goto end;
    }

    if (app_state->client_connp.version != SSL_VERSION_2) {
        printf("expected version %04" PRIu16 ", got %04" PRIu16 ": ",
                SSL_VERSION_2, app_state->client_connp.version);
        result = 0;
        goto end;
    }

    if (app_state->flags !=
        (SSL_AL_FLAG_STATE_CLIENT_HELLO | SSL_AL_FLAG_SSL_CLIENT_HS |
         SSL_AL_FLAG_SSL_NO_SESSION_ID)) {
        printf("flags not set\n");
        result = 0;
        goto end;
    }


    SCMutexLock(&f.m);
    r = AppLayerParserParse(alp_tctx, &f, ALPROTO_TLS, STREAM_TOCLIENT, shello_buf,
                            shello_buf_len);
    if (r != 0) {
        printf("toclient chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);

    if (app_state->server_connp.content_type != SSLV3_HANDSHAKE_PROTOCOL) {
        printf("expected content_type %" PRIu8 ", got %" PRIu8 ": ",
               SSLV3_HANDSHAKE_PROTOCOL, app_state->server_connp.content_type);
        result = 0;
        goto end;
    }

    if (app_state->server_connp.version != SSL_VERSION_3) {
        printf("expected version %04" PRIu16 ", got %04" PRIu16 ": ",
                SSL_VERSION_3, app_state->server_connp.version);
        result = 0;
        goto end;
    }

    if (app_state->flags !=
        (SSL_AL_FLAG_STATE_CLIENT_HELLO | SSL_AL_FLAG_SSL_CLIENT_HS |
         SSL_AL_FLAG_SSL_NO_SESSION_ID | SSL_AL_FLAG_STATE_SERVER_HELLO)) {
        printf("flags not set\n");
        result = 0;
        goto end;
    }

    SCMutexLock(&f.m);
    r = AppLayerParserParse(alp_tctx, &f, ALPROTO_TLS, STREAM_TOSERVER, client_change_cipher_spec_buf,
                            client_change_cipher_spec_buf_len);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);

    /* with multiple records the client content type hold the type from the last
     * record */
    if (app_state->client_connp.content_type != SSLV3_HANDSHAKE_PROTOCOL) {
        printf("expected content_type %" PRIu8 ", got %" PRIu8 ": ",
               SSLV3_HANDSHAKE_PROTOCOL, app_state->client_connp.content_type);
        result = 0;
        goto end;
    }

    if (app_state->client_connp.version != SSL_VERSION_3) {
        printf("expected version %04" PRIu16 ", got %04" PRIu16 ": ",
                SSL_VERSION_3, app_state->client_connp.version);
        result = 0;
        goto end;
    }

    if (app_state->flags !=
        (SSL_AL_FLAG_STATE_CLIENT_HELLO | SSL_AL_FLAG_SSL_CLIENT_HS |
         SSL_AL_FLAG_SSL_NO_SESSION_ID | SSL_AL_FLAG_STATE_SERVER_HELLO |
         SSL_AL_FLAG_STATE_CLIENT_KEYX | SSL_AL_FLAG_CLIENT_CHANGE_CIPHER_SPEC |
         SSL_AL_FLAG_CHANGE_CIPHER_SPEC)) {
        printf("flags not set\n");
        result = 0;
        goto end;
    }

    SCMutexLock(&f.m);
    r = AppLayerParserParse(alp_tctx, &f, ALPROTO_TLS, STREAM_TOCLIENT, server_change_cipher_spec_buf,
                            server_change_cipher_spec_buf_len);
    if (r != 0) {
        printf("toclient chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);

    /* with multiple records the serve content type hold the type from the last
     * record */
    if (app_state->server_connp.content_type != SSLV3_HANDSHAKE_PROTOCOL) {
        printf("expected content_type %" PRIu8 ", got %" PRIu8 ": ",
               SSLV3_HANDSHAKE_PROTOCOL, app_state->server_connp.content_type);
        result = 0;
        goto end;
    }

    if (app_state->server_connp.version != SSL_VERSION_3) {
        printf("expected version %04" PRIu16 ", got %04" PRIu16 ": ",
                SSL_VERSION_3, app_state->server_connp.version);
        result = 0;
        goto end;
    }

    if (app_state->flags !=
        (SSL_AL_FLAG_STATE_CLIENT_HELLO | SSL_AL_FLAG_SSL_CLIENT_HS |
         SSL_AL_FLAG_SSL_NO_SESSION_ID | SSL_AL_FLAG_STATE_SERVER_HELLO |
         SSL_AL_FLAG_STATE_CLIENT_KEYX | SSL_AL_FLAG_CLIENT_CHANGE_CIPHER_SPEC |
         SSL_AL_FLAG_CHANGE_CIPHER_SPEC | SSL_AL_FLAG_SERVER_CHANGE_CIPHER_SPEC |
         SSL_AL_FLAG_CHANGE_CIPHER_SPEC)) {
        printf("flags not set\n");
        result = 0;
        goto end;
    }

    SCMutexLock(&f.m);
    r = AppLayerParserParse(alp_tctx, &f, ALPROTO_TLS, STREAM_TOSERVER, toserver_app_data_buf,
                            toserver_app_data_buf_len);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);

    if (app_state->client_connp.content_type != SSLV3_APPLICATION_PROTOCOL) {
        printf("expected content_type %" PRIu8 ", got %" PRIu8 ": ",
               SSLV3_APPLICATION_PROTOCOL, app_state->client_connp.content_type);
        result = 0;
        goto end;
    }

    if (app_state->client_connp.version != SSL_VERSION_3) {
        printf("expected version %04" PRIu16 ", got %04" PRIu16 ": ",
                SSL_VERSION_3, app_state->client_connp.version);
        result = 0;
        goto end;
    }

    if (app_state->flags !=
        (SSL_AL_FLAG_STATE_CLIENT_HELLO | SSL_AL_FLAG_SSL_CLIENT_HS |
         SSL_AL_FLAG_SSL_NO_SESSION_ID | SSL_AL_FLAG_STATE_SERVER_HELLO |
         SSL_AL_FLAG_STATE_CLIENT_KEYX | SSL_AL_FLAG_CLIENT_CHANGE_CIPHER_SPEC |
         SSL_AL_FLAG_CHANGE_CIPHER_SPEC | SSL_AL_FLAG_SERVER_CHANGE_CIPHER_SPEC |
         SSL_AL_FLAG_CHANGE_CIPHER_SPEC)) {
        printf("flags not set\n");
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

/**
 * \test Tests the parser for handling fragmented records.
 */
static int SSLParserTest24(void)
{
    int result = 1;
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
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;

    StreamTcpInitConfig(TRUE);

    SCMutexLock(&f.m);
    int r = AppLayerParserParse(alp_tctx, &f, ALPROTO_TLS, STREAM_TOSERVER, buf1, buf1_len);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);

    SCMutexLock(&f.m);
    r = AppLayerParserParse(alp_tctx, &f, ALPROTO_TLS, STREAM_TOSERVER, buf2, buf2_len);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);

    SSLState *ssl_state = f.alstate;
    if (ssl_state == NULL) {
        printf("no tls state: ");
        result = 0;
        goto end;
    }

    if (ssl_state->client_connp.content_type != 0x16) {
        printf("expected content_type %" PRIu8 ", got %" PRIu8 ": ", 0x16,
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

end:
    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
    StreamTcpFreeConfig(TRUE);
    return result;
}

/**
 * \test Test for bug #955 and CVE-2013-5919.  The data is from the
 *       pcap that was used to report this issue.
 */
static int SSLParserTest25(void)
{
    int result = 0;
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
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;

    StreamTcpInitConfig(TRUE);

    SCMutexLock(&f.m);
    int r = AppLayerParserParse(alp_tctx, &f, ALPROTO_TLS, STREAM_TOSERVER, client_hello, client_hello_len);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);

    SSLState *ssl_state = f.alstate;
    if (ssl_state == NULL) {
        printf("no tls state: ");
        goto end;
    }

    if (ssl_state->client_connp.bytes_processed != 0 ||
        ssl_state->client_connp.hs_bytes_processed != 0)
    {
        printf("client_hello error\n");
        goto end;
    }

    SCMutexLock(&f.m);
    r = AppLayerParserParse(alp_tctx, &f, ALPROTO_TLS, STREAM_TOCLIENT,
                            server_hello_certificate_done,
                            server_hello_certificate_done_len);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);

    if (ssl_state->client_connp.bytes_processed != 0 ||
        ssl_state->client_connp.hs_bytes_processed != 0)
    {
        printf("server_hello_certificate_done error\n");
        goto end;
    }

    SCMutexLock(&f.m);
    r = AppLayerParserParse(alp_tctx, &f, ALPROTO_TLS, STREAM_TOSERVER,
                            client_key_exchange_cipher_enc_hs,
                            client_key_exchange_cipher_enc_hs_len);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);

    /* The reason hs_bytes_processed is 2 is because, the record
     * immediately after the client key exchange is 2 bytes long,
     * and next time we see a new handshake, it is after we have
     * seen a change cipher spec.  Hence when we process the
     * handshake, we immediately break and don't parse the pdu from
     * where we left off, and leave the hs_bytes_processed var
     * isn't reset. */
    if (ssl_state->client_connp.bytes_processed != 0 ||
        ssl_state->client_connp.hs_bytes_processed != 2)
    {
        printf("client_key_exchange_cipher_enc_hs error\n");
        goto end;
    }

    result = 1;
end:
    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
    StreamTcpFreeConfig(TRUE);
    return result;
}

#endif /* UNITTESTS */

void SSLParserRegisterTests(void)
{
#ifdef UNITTESTS
    UtRegisterTest("SSLParserTest01", SSLParserTest01, 1);
    UtRegisterTest("SSLParserTest02", SSLParserTest02, 1);
    UtRegisterTest("SSLParserTest03", SSLParserTest03, 1);
    UtRegisterTest("SSLParserTest04", SSLParserTest04, 1);
    /* Updated by Anoop Saldanha.  Faulty tests.  Disable it for now */
    //UtRegisterTest("SSLParserTest05", SSLParserTest05, 1);
    //UtRegisterTest("SSLParserTest06", SSLParserTest06, 1);
    UtRegisterTest("SSLParserTest07", SSLParserTest07, 1);
    //UtRegisterTest("SSLParserTest08", SSLParserTest08, 1);
    UtRegisterTest("SSLParserTest09", SSLParserTest09, 1);
    UtRegisterTest("SSLParserTest10", SSLParserTest10, 1);
    UtRegisterTest("SSLParserTest11", SSLParserTest11, 1);
    UtRegisterTest("SSLParserTest12", SSLParserTest12, 1);
    UtRegisterTest("SSLParserTest13", SSLParserTest13, 1);

    UtRegisterTest("SSLParserTest14", SSLParserTest14, 1);
    UtRegisterTest("SSLParserTest15", SSLParserTest15, 1);
    UtRegisterTest("SSLParserTest16", SSLParserTest16, 1);
    UtRegisterTest("SSLParserTest17", SSLParserTest17, 1);
    UtRegisterTest("SSLParserTest18", SSLParserTest18, 1);
    UtRegisterTest("SSLParserTest19", SSLParserTest19, 1);
    UtRegisterTest("SSLParserTest20", SSLParserTest20, 1);
    UtRegisterTest("SSLParserTest21", SSLParserTest21, 1);
    UtRegisterTest("SSLParserTest22", SSLParserTest22, 1);
    UtRegisterTest("SSLParserTest23", SSLParserTest23, 1);
    UtRegisterTest("SSLParserTest24", SSLParserTest24, 1);
    UtRegisterTest("SSLParserTest25", SSLParserTest25, 1);

    UtRegisterTest("SSLParserMultimsgTest01", SSLParserMultimsgTest01, 1);
    UtRegisterTest("SSLParserMultimsgTest02", SSLParserMultimsgTest02, 1);
#endif /* UNITTESTS */

    return;
}
