/*
 * Copyright (C) 2011-2014 ANSSI
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL
 * THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
 * OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 * ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/**
 * \file
 *
 * \author Pierre Chifflier <pierre.chifflier@ssi.gouv.fr>
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

struct tls_ciphersuite_definition {
    uint16_t  cs;
    char      *kx;
    char      *au;
    char      *enc;
    char      *enc_mode;
    uint16_t   enc_size;
    char       *mac;
    uint16_t   mac_size;
    char       *prf;
    uint16_t   prf_size;
    uint16_t   rfc;
    uint8_t    exp;
    char       *cs_name;
    char       *openssl_name;
    uint16_t   minversion;
    uint16_t   maxversion;
} __attribute((packed,aligned(4)));

const struct tls_ciphersuite_definition *tls_ciphersuite_get_by_id(uint16_t id);

const char *tls_ciphersuite_id_to_name(uint16_t id);

int tls_ciphersuite_match_group(uint16_t id, enum TlsHandshakeDataType key, const char *group, char op);

void TlsCiphersInit(void);

#endif /* __UTIL_TLS_H__ */
