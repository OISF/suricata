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
 * \author Gurvinder Singh <gurvindersinghdahiya@gmail.com>
 */

#ifndef _APP_LAYER_SSL_H
#define	_APP_LAYER_SSL_H

#define SSL_CLIENT_VERSION			0x0002
#define SSL_SERVER_VERSION			0x0002

/* SSL state flags */
#define SSL_FLAG_CLIENT_HS              0x01
#define SSL_FLAG_SERVER_HS              0x02
#define SSL_FLAG_CLIENT_MASTER_KEY      0x04
#define SSL_FLAG_CLIENT_SSN_ENCRYPTED   0x08
#define SSL_FLAG_SERVER_SSN_ENCRYPTED   0x10
#define SSL_FLAG_NO_SESSION_ID          0x20

/* SSL message types */
#define SSL_ERROR			0
#define SSL_CLIENT_HELLO		1
#define SSL_CLIENT_MASTER_KEY		2
#define SSL_CLIENT_FINISHED		3
#define SSL_SERVER_HELLO		4
#define SSL_SERVER_VERIFY		5
#define SSL_SERVER_FINISHED		6
#define SSL_REQUEST_CERTIFICATE		7
#define SSL_CLIENT_CERTIFICATE		8

/* structure to store the SSL state values */
typedef struct SslState_ {
    uint8_t client_content_type;    /**< Client content type storage field */
    uint16_t client_version;        /**< Client SSL version storage field */

    uint8_t server_content_type;    /**< Server content type storage field */
    uint16_t server_version;        /**< Server SSL version storage field */

    uint8_t flags;                  /**< Flags to indicate the current SSL
                                         sessoin state */
} SslState;

typedef struct SslClient_ {
    uint16_t length;        /**< Length of the received message */
    uint8_t msg_type;
    uint8_t minor_ver;
    uint8_t major_ver;
    uint16_t cipher_spec_len;
    uint16_t session_id_len;
} SslClient;

typedef struct SslServer_ {
    uint16_t lentgth;
    uint8_t msg_type;
    uint8_t session_id;
    uint8_t cert;
    uint8_t minor_ver;
    uint8_t major_ver;
} SslServer;

void RegisterSSLParsers(void);
void SSLParserRegisterTests(void);

#endif	/* _APP_LAYER_SSL_H */

