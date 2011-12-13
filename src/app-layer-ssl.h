/* Copyright (C) 2007-2010 Open Information Security Foundation
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
 *
 */

#ifndef __APP_LAYER_SSL_H__
#define __APP_LAYER_SSL_H__

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

/**
 * \brief SSLv[2.0|3.[0|1|2|3]] state structure.
 *
 *        Structure to store the SSL state values.
 */
typedef struct SSLState_ {
    /* record length */
    uint32_t record_length;
    /* record length's length for SSLv2 */
    uint32_t record_lengths_length;

    /* holds some state flags we need */
    uint32_t flags;

    uint16_t client_version;
    uint16_t server_version;
    uint8_t client_content_type;
    uint8_t server_content_type;

    /* dummy var.  You can replace this if you want to */
    uint8_t pad0;

    uint8_t cur_content_type;
    uint32_t handshake_length;
    uint16_t handshake_client_hello_ssl_version;
    uint16_t handshake_server_hello_ssl_version;
    /* the no of bytes processed in the currently parsed record */
    uint16_t bytes_processed;

    uint16_t cur_ssl_version;
    uint8_t handshake_type;

    /* sslv2 client hello session id length */
    uint16_t session_id_length;
} SSLState;

void RegisterSSLParsers(void);
void SSLParserRegisterTests(void);

#endif /* __APP_LAYER_SSL_H__ */
