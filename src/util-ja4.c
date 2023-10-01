/* Copyright (C) 2023 Open Information Security Foundation
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
 * \author Sascha Steinbiss <sascha@steinbiss.name>
 */

#include "suricata-common.h"
#include "suricata.h"
#include "detect-engine.h"
#include "util-ja4.h"
#include "util-unittest.h"
#include "util-unittest-helper.h"
#include "util-validate.h"
#include <stdlib.h>
#include <string.h>
#include "rust.h"

struct JA4_ {
    bool finalized;
    const char *tls_version;
    char proto, alpn[2], sni, ja4[37];
    uint16_t nof_ciphers, nof_exts;
    size_t len_cipher, len_ext, len_sigs, cap_cipher, cap_ext, cap_sigs;
    char *exts, *ciphers, *sigs;
};

#define JA4_INITIAL_BUFSIZE 64

static int Ja4HexCompare(const void *a, const void *b)
{
    return strncmp((const char *)a, (const char *)b, 4 * sizeof(char));
}

static inline int JA4ExtendBuffer(char **buf, size_t *cap)
{
    size_t newcap = *cap * 2;
    char *new = SCRealloc(*buf, newcap);
    if (new == NULL) {
        SCLogError("Error resizing JA4 buffer");
        return -1;
    }
    *buf = new;
    *cap = newcap;
    return 0;
}

static inline bool JA4IsGREASE(const uint16_t value)
{
    switch (value) {
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
            return true;
        default:
            return false;
    }
}

JA4 *Ja4Init(void)
{
    JA4 *j = NULL;
    j = SCCalloc(1, sizeof(*j));
    if (unlikely(j == NULL)) {
        SCLogError("Unable to allocate JA4 memory");
        return NULL;
    }
    j->cap_cipher = j->cap_ext = j->cap_sigs = JA4_INITIAL_BUFSIZE;
    j->ciphers = SCCalloc(j->cap_cipher, sizeof(char));
    j->exts = SCCalloc(j->cap_ext, sizeof(char));
    j->sigs = SCCalloc(j->cap_sigs, sizeof(char));
    Ja4Reset(j);
    return j;
}

void Ja4SetQUIC(JA4 *j)
{
    DEBUG_VALIDATE_BUG_ON(j == NULL);
    j->proto = 'q';
}

void Ja4SetTLSVersion(JA4 *j, uint16_t v)
{
    DEBUG_VALIDATE_BUG_ON(j == NULL);
    if (JA4IsGREASE(v))
        return;
    switch (v) {
        case 0x0304:
            j->tls_version = "13";
            break;
        case 0x0303:
            j->tls_version = "12";
            break;
        case 0x0302:
            j->tls_version = "11";
            break;
        case 0x0301:
            j->tls_version = "10";
            break;
        case 0x0300:
            j->tls_version = "s3";
            break;
        case 0x0200:
            j->tls_version = "s2";
            break;
        case 0x0100:
            j->tls_version = "s1";
            break;
        default:
            j->tls_version = "00";
    }
}

void Ja4SetALPN(JA4 *j, const uint8_t *val, uint8_t len)
{
    DEBUG_VALIDATE_BUG_ON(j == NULL);
    if (len > 1) {
        uint16_t testval = (val[0] << 8) | val[1];
        if (JA4IsGREASE(testval))
            return;
        j->alpn[0] = val[0];
        j->alpn[1] = val[len - 1];
    }
}

void Ja4AddCipher(JA4 *j, const uint16_t cipher)
{
    int ret;
    DEBUG_VALIDATE_BUG_ON(j == NULL);
    if (JA4IsGREASE(cipher))
        return;
    if (j->len_cipher + 4 > j->cap_cipher) {
        ret = JA4ExtendBuffer(&(j->ciphers), &(j->cap_cipher));
        if (ret < 0) {
            /* XXX TODO Handle */
            return;
        }
    }
    (void)sprintf(j->ciphers + j->len_cipher, "%04x", cipher);
    j->len_cipher += 4;
    j->nof_ciphers++;
}

void Ja4AddExtension(JA4 *j, const uint16_t ext)
{
    int ret;
    DEBUG_VALIDATE_BUG_ON(j == NULL);
    if (JA4IsGREASE(ext))
        return;
    /* skip SNI and ALPN */
    if (ext == 0x0000) {
        j->sni = 'd';
        j->nof_exts++;
        return;
    }
    if (ext == 0x0010) {
        j->nof_exts++;
        return;
    }
    if (j->len_ext + 4 > j->cap_ext) {
        ret = JA4ExtendBuffer(&(j->exts), &(j->cap_ext));
        if (ret < 0) {
            /* XXX TODO Handle */
            return;
        }
    }
    (void)sprintf(j->exts + j->len_ext, "%04x", ext);
    j->len_ext += 4;
    j->nof_exts++;
}

void Ja4AddSigAlgo(JA4 *j, const uint16_t sigalgo)
{
    int ret;
    DEBUG_VALIDATE_BUG_ON(j == NULL);
    if (JA4IsGREASE(sigalgo))
        return;
    if (j->len_sigs + 4 > j->cap_sigs) {
        ret = JA4ExtendBuffer(&(j->sigs), &(j->cap_sigs));
        if (ret < 0) {
            /* XXX TODO Handle */
            return;
        }
    }
    (void)sprintf(j->sigs + j->len_sigs, "%04x", sigalgo);
    j->len_sigs += 4;
}

static inline void Ja4BuildHash(JA4 *j)
{
    uint16_t i;
    char ja4_a[32];
    char buf[10];
    DEBUG_VALIDATE_BUG_ON(j == NULL);
    (void)snprintf(ja4_a, 32, "%c%s%c%02u%02u%c%c", j->proto, j->tls_version, j->sni,
            j->nof_ciphers > 99 ? 99 : j->nof_ciphers, j->nof_exts > 99 ? 99 : j->nof_exts,
            j->alpn[0], j->alpn[1]);
    SCLogDebug("JA4_a: %s", ja4_a);

    DEBUG_VALIDATE_BUG_ON(j->len_cipher % 4 != 0);
    (void)qsort(j->ciphers, j->len_cipher / 4, 4, Ja4HexCompare);
    SCSha256 *sha256_ctx = SCSha256New();
    for (i = 0; i < j->len_cipher; i += 4) {
        (void)snprintf(buf, 10, "%.4s%s", j->ciphers + i, i == j->len_cipher - 4 ? "" : ",");
        SCLogDebug("%d/%lu: updating with cipher %s", i, j->len_cipher, buf);
        SCSha256Update(sha256_ctx, (unsigned char *)buf, strlen(buf));
    }
    char ja4_b_full[65];
    SCSha256FinalizeToHex(sha256_ctx, ja4_b_full, 65);
    SCLogDebug("JA4_b: %.12s", ja4_b_full);

    sha256_ctx = SCSha256New();
    DEBUG_VALIDATE_BUG_ON(j->len_ext % 4 != 0);
    (void)qsort(j->exts, j->len_ext / 4, 4, Ja4HexCompare);
    for (i = 0; i < j->len_ext; i += 4) {
        (void)snprintf(buf, 10, "%.4s%s", j->exts + i, i == j->len_ext - 4 ? "" : ",");
        SCLogDebug("%d/%lu: updating with ext %s", i, j->len_ext, buf);
        SCSha256Update(sha256_ctx, (unsigned char *)buf, strlen(buf));
    }
    SCSha256Update(sha256_ctx, (const uint8_t *)"_", 1);
    DEBUG_VALIDATE_BUG_ON(j->len_sigs % 4 != 0);
    for (i = 0; i < j->len_sigs; i += 4) {
        (void)snprintf(buf, 10, "%.4s%s", j->sigs + i, i == j->len_sigs - 4 ? "" : ",");
        SCLogDebug("%d/%lu: updating with sig %s", i, j->len_sigs, buf);
        SCSha256Update(sha256_ctx, (unsigned char *)buf, strlen(buf));
    }
    char ja4_c_full[65];
    SCSha256FinalizeToHex(sha256_ctx, ja4_c_full, 65);
    SCLogDebug("JA4_c: %.12s", ja4_c_full);

    (void)snprintf(j->ja4, 37, "%.10s_%.12s_%.12s", ja4_a, ja4_b_full, ja4_c_full);
    SCLogDebug("JA4: %s", j->ja4);
    j->finalized = true;
}

const char *Ja4GetHash(JA4 *j)
{
    DEBUG_VALIDATE_BUG_ON(j == NULL);
    if (!j->finalized)
        Ja4BuildHash(j);
    return (const char *)j->ja4;
}

void Ja4Reset(JA4 *j)
{
    DEBUG_VALIDATE_BUG_ON(j == NULL);
    j->finalized = false;
    j->proto = 't';
    j->sni = 'i';
    j->tls_version = "00";
    j->len_cipher = j->len_ext = j->len_sigs = 0;
    j->nof_ciphers = j->nof_exts = 0;
    j->alpn[0] = j->alpn[1] = '0';
}

void Ja4Free(JA4 **j)
{
    if (j == NULL)
        return;
    if (*j == NULL)
        return;
    SCFree((*j)->sigs);
    SCFree((*j)->ciphers);
    SCFree((*j)->exts);
    SCFree(*j);
    *j = NULL;
}
