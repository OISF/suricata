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
 * TLS utility functions: conversions from cipher ID to name, groups, etc.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <inttypes.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "suricata-common.h"
#include "conf.h"
#include "util-byte.h"
#include "util-rohash.h"

#include "util-tls.h"

static HashTable * g_tls_hash = NULL;

static int CompareIntegers(uint32_t a, uint32_t b, char op)
{
    switch (op) {
    case '=':
        return a == b;
    case '<':
        return a < b;
    case '>':
        return a > b;
    default:
        return -1;
    }
}

const struct TlsCiphersuiteDefinition *TlsCiphersuiteGetById(uint16_t id)
{
    const struct TlsCiphersuiteDefinition *cipher;
    struct TlsCiphersuiteDefinition dummy;

    memset(&dummy, 0, sizeof(dummy));

    dummy.cs = id;
    cipher = HashTableLookup(g_tls_hash, &dummy, sizeof(struct TlsCiphersuiteDefinition));

    return cipher;
}

const char *TlsCiphersuiteIdToName(uint16_t id)
{
    const struct TlsCiphersuiteDefinition *def;

    def = TlsCiphersuiteGetById(id);

    if (def != NULL)
        return def->cs_name;

    return NULL;
}

int TlsCiphersuiteMatchGroup(uint16_t id, enum TlsHandshakeDataType key, const char *group, char op)
{
    const struct TlsCiphersuiteDefinition *cipher = TlsCiphersuiteGetById(id);
    int ret;
    uint32_t ui;

    if (cipher == NULL)
        return 0;

    switch (key) {
        case TLS_HS_CIPHERSUITE_AU:
            if (strcmp(cipher->au, group)==0)
                return 1;
            break;
        case TLS_HS_CIPHERSUITE_CS:
            ret = ByteExtractStringUint32(&ui, 10, 0, group);
            if (ret <= 0)
                return 0;
            if (CompareIntegers(cipher->cs,ui,op))
                return 1;
            break;
        case TLS_HS_CIPHERSUITE_CS_NAME:
            if (strcmp(cipher->cs_name, group)==0)
                return 1;
            break;
        case TLS_HS_CIPHERSUITE_ENC:
            if (strcmp(cipher->enc, group)==0)
                return 1;
            break;
        case TLS_HS_CIPHERSUITE_ENC_MODE:
            if (strcmp(cipher->enc_mode, group)==0)
                return 1;
            break;
        case TLS_HS_CIPHERSUITE_ENC_SIZE:
            ret = ByteExtractStringUint32(&ui, 10, 0, group);
            if (ret <= 0)
                return 0;
            if (CompareIntegers(cipher->enc_size,ui,op))
                return 1;
            break;
        case TLS_HS_CIPHERSUITE_EXP:
            ret = ByteExtractStringUint32(&ui, 10, 0, group);
            if (ret <= 0)
                return 0;
            if (CompareIntegers(cipher->exp,ui,op))
                return 1;
            break;
        case TLS_HS_CIPHERSUITE_KX:
            if (strcmp(cipher->kx, group)==0)
                return 1;
            break;
        case TLS_HS_CIPHERSUITE_MAC:
            if (strcmp(cipher->mac, group)==0)
                return 1;
            break;
        case TLS_HS_CIPHERSUITE_MAC_SIZE:
            ret = ByteExtractStringUint32(&ui, 10, 0, group);
            if (ret <= 0)
                return 0;
            if (CompareIntegers(cipher->mac_size,ui,op))
                return 1;
            break;
        case TLS_HS_CIPHERSUITE_MIN_VERSION:
            ret = ByteExtractStringUint32(&ui, 10, 0, group);
            if (ret <= 0)
                return 0;
            if (CompareIntegers(cipher->minversion,ui,op))
                return 1;
            break;
        case TLS_HS_CIPHERSUITE_MAX_VERSION:
            ret = ByteExtractStringUint32(&ui, 10, 0, group);
            if (ret <= 0)
                return 0;
            if (CompareIntegers(cipher->maxversion,ui,op))
                return 1;
            break;
        case TLS_HS_CIPHERSUITE_PRF:
            if (strcmp(cipher->prf, group)==0)
                return 1;
            break;
        case TLS_HS_CIPHERSUITE_PRF_SIZE:
            ret = ByteExtractStringUint32(&ui, 10, 0, group);
            if (ret <= 0)
                return 0;
            if (CompareIntegers(cipher->prf_size,ui,op))
                return 1;
            break;
        case TLS_HS_CIPHERSUITE_OPENSSL_NAME:
            if (strcmp(cipher->openssl_name, group)==0)
                return 1;
            break;
        case TLS_HS_CIPHERSUITE_RFC:
            ret = ByteExtractStringUint32(&ui, 10, 0, group);
            if (ret <= 0)
                return 0;
            if (CompareIntegers(cipher->rfc,ui,op))
                return 1;
            break;
        default:
            break;
    }

    return 0;
}

static uint32_t TlsCiphersuiteHash(struct HashTable_ *h, void *data, uint16_t size)
{
    struct TlsCiphersuiteDefinition *cipher = data;
    uint32_t hash;

    // ensure that hash value does not exceed maximum hash size (512)
    hash = cipher->cs;
    if (hash > 0xff) {
        hash = 0x100 + (hash & 0xff);
    }
    return hash;
}

static char TlsCiphersuiteCompare(void *data1, uint16_t size1, void *data2, uint16_t size2)
{
    struct TlsCiphersuiteDefinition *cipher1 = data1;
    struct TlsCiphersuiteDefinition *cipher2 = data2;
    uint16_t cs1 = (uint16_t)cipher1->cs;
    uint16_t cs2 = (uint16_t)cipher2->cs;

    if (cs1 == cs2)
        return 1;
    return 0;
}

void TlsCiphersuiteFree(void *data)
{
    struct TlsCiphersuiteDefinition *cipher = data;

    SCFree(cipher->kx);
    SCFree(cipher->au);
    SCFree(cipher->enc);
    SCFree(cipher->enc_mode);
    SCFree(cipher->mac);
    SCFree(cipher->prf);
    SCFree(cipher->cs_name);
    SCFree(cipher->openssl_name);

    SCFree(cipher);
}

static struct TlsCiphersuiteDefinition * TlsParseCiphersuiteFromConf(ConfNode *node)
{
    char *val;
    struct TlsCiphersuiteDefinition *cipher;
    unsigned long ul;
    intmax_t im;
    char *end;
    int ret;

    cipher = SCMalloc(sizeof(struct TlsCiphersuiteDefinition));
    if (cipher == NULL)
        return NULL;
    memset(cipher, 0, sizeof(struct TlsCiphersuiteDefinition));

    ConfGetChildValueWithDefault(node, NULL, "cs", &val);
    if (val == NULL)
        goto tls_parse_cipher_error;

    ul = strtoul(val, &end, 16);
    if (end == NULL || *end != '\0')
        goto tls_parse_cipher_error;

    cipher->cs = ul;

    ConfGetChildValueWithDefault(node, NULL, "name", &val);
    cipher->cs_name = val;

    ConfGetChildValueWithDefault(node, NULL, "openssl-name", &val);
    cipher->openssl_name = val;

    ConfGetChildValueWithDefault(node, NULL, "kx", &val);
    cipher->kx = val;

    ConfGetChildValueWithDefault(node, NULL, "au", &val);
    cipher->au = val;

    ConfGetChildValueWithDefault(node, NULL, "enc", &val);
    cipher->enc = val;

    ConfGetChildValueWithDefault(node, NULL, "enc-mode", &val);
    cipher->enc_mode = val;

    ret = ConfGetChildValueInt(node, "enc-size", &im);
    if (!ret)
        goto tls_parse_cipher_error;
    cipher->enc_size = im;

    ConfGetChildValueWithDefault(node, NULL, "mac", &val);
    cipher->mac = val;

    ret = ConfGetChildValueInt(node, "mac-size", &im);
    if (!ret)
        goto tls_parse_cipher_error;
    cipher->mac_size = im;

    ConfGetChildValueWithDefault(node, NULL, "prf", &val);
    cipher->prf = val;

    ret = ConfGetChildValueInt(node, "prf-size", &im);
    if (!ret)
        goto tls_parse_cipher_error;
    cipher->prf_size = im;

    ret = ConfGetChildValueInt(node, "rfc", &im);
    if (!ret)
        goto tls_parse_cipher_error;
    cipher->rfc = im;

    ret = ConfGetChildValueInt(node, "export", &im);
    if (!ret)
        goto tls_parse_cipher_error;
    cipher->exp = im;

    ret = ConfGetChildValueInt(node, "minversion", &im);
    if (!ret)
        goto tls_parse_cipher_error;
    cipher->minversion = im;

    ret = ConfGetChildValueInt(node, "maxversion", &im);
    if (!ret)
        goto tls_parse_cipher_error;
    cipher->maxversion = im;

    return cipher;
tls_parse_cipher_error:
    SCFree(cipher);
    return NULL;
}

void TlsCiphersInit(void)
{
    ConfNode * conf;
    ConfNode * child;
    struct TlsCiphersuiteDefinition *tls_cipher;
    int ret;

    conf = ConfGetNode("tls-ciphersuites");
    if (conf == NULL)
        return;

    g_tls_hash = HashTableInit(512, &TlsCiphersuiteHash,
            &TlsCiphersuiteCompare,
            &TlsCiphersuiteFree);
    if (g_tls_hash == NULL)
        return;

    TAILQ_FOREACH(child, &conf->head, next) {
        tls_cipher = TlsParseCiphersuiteFromConf(child);
        if (tls_cipher == NULL) {
            SCLogWarning(SC_ERR_INVALID_VALUE, "Could not parse cipher %s\n",
                    child->name);
            break;
        }
        ret = HashTableAdd(g_tls_hash,
                tls_cipher,
                sizeof(struct TlsCiphersuiteDefinition)
                );
        if (ret < 0) {
            SCLogError(SC_ERR_FATAL, "Could not insert ciphersuites in hash table");
            exit(EXIT_FAILURE);
        }

    }
}

