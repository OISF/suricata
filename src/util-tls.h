/* Copyright (C) 2017-2018 Open Information Security Foundation
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
 * \author Pierre Chifflier <chifflier@wzdftpd.net>
 *
 */

#ifndef __UTIL_TLS_H__
#define __UTIL_TLS_H__

enum TlsHandshakeDataType {
    TLS_HS_INVALID=0,
    TLS_HS_CIPHERSUITE_CS,
    TLS_HS_CIPHERSUITE_KX,
    TLS_HS_CIPHERSUITE_AU,
    TLS_HS_CIPHERSUITE_ENC,
    TLS_HS_CIPHERSUITE_ENC_MODE,
    TLS_HS_CIPHERSUITE_ENC_SIZE,
    TLS_HS_CIPHERSUITE_MAC,
    TLS_HS_CIPHERSUITE_MAC_SIZE,
    TLS_HS_CIPHERSUITE_PRF,
    TLS_HS_CIPHERSUITE_PRF_SIZE,
    TLS_HS_CIPHERSUITE_RFC,
    TLS_HS_CIPHERSUITE_EXP,
    TLS_HS_CIPHERSUITE_CS_NAME,
    TLS_HS_CIPHERSUITE_OPENSSL_NAME,
    TLS_HS_CIPHERSUITE_MIN_VERSION,
    TLS_HS_CIPHERSUITE_MAX_VERSION,
};

struct TlsCiphersuiteDefinition {
    uint16_t   cs;
    const char *kx;
    const char *au;
    const char *enc;
    const char *enc_mode;
    uint16_t   enc_size;
    const char *mac;
    uint16_t   mac_size;
    const char *prf;
    uint16_t   prf_size;
    const char *rfc;
    uint8_t    exp;
    const char *cs_name;
    const char *openssl_name;
    uint16_t   minversion;
    uint16_t   maxversion;
} __attribute((packed,aligned(4)));

const struct TlsCiphersuiteDefinition *TlsCiphersuiteGetById(uint16_t id);

const char *TlsCiphersuiteIdToName(uint16_t id);

int TlsCiphersuiteMatchGroup(uint16_t id, enum TlsHandshakeDataType key, const char *group, char op);

void TlsCiphersInit(void);

#endif /* __UTIL_TLS_H__ */
