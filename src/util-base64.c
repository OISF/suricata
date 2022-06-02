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
 * \author David Abarbanel <david.abarbanel@baesystems.com>
 *
 */

#include "util-base64.h"
#include "util-unittest.h"
/* Constants */
#define BASE64_TABLE_MAX  122

/* Base64 character to index conversion table */
/* Characters are mapped as "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/" */
static const int b64table[] = { -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, 62, -1, -1, -1, 63, 52, 53,
        54, 55, 56, 57, 58, 59, 60, 61, -1, -1,
        -1, -1, -1, -1, -1, 0, 1, 2, 3, 4,
        5, 6, 7, 8, 9, 10, 11, 12, 13, 14,
        15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
        25, -1, -1, -1, -1, -1, -1, 26, 27, 28,
        29, 30, 31, 32, 33, 34, 35, 36, 37, 38,
        39, 40, 41, 42, 43, 44, 45, 46, 47, 48,
        49, 50, 51 };

/**
 * \brief Gets a base64-decoded value from an encoded character
 *
 * \param c The encoded character
 *
 * \return The decoded value (0 or above), or -1 if the parameter is invalid
 */
static inline int GetBase64Value(uint8_t c)
{
    int val = -1;

    /* Pull from conversion table */
    if (c <= BASE64_TABLE_MAX) {
        val = b64table[(int) c];
    }

    return val;
}

/**
 * \brief Decodes a 4-byte base64-encoded block into a 3-byte ascii-encoded block
 *
 * \param ascii the 3-byte ascii output block
 * \param b64 the 4-byte base64 input block
 *
 * \return none
 */
static inline void DecodeBase64Block(uint8_t ascii[ASCII_BLOCK], uint8_t b64[B64_BLOCK])
{
    ascii[0] = (uint8_t) (b64[0] << 2) | (b64[1] >> 4);
    ascii[1] = (uint8_t) (b64[1] << 4) | (b64[2] >> 2);
    ascii[2] = (uint8_t) (b64[2] << 6) | (b64[3]);
}

/**
 * \brief Decodes a base64-encoded string buffer into an ascii-encoded byte buffer
 *
 * \param dest The destination byte buffer
 * \param dest_size The destination byte buffer size
 * \param src The source string
 * \param len The length of the source string
 * \param consumed_bytes The bytes that were actually processed/consumed
 * \param decoded_bytes The bytes that were decoded
 * \param mode The mode in which decoding should happen
 *
 * \return Error code indicating success or failures with parsing
 */
Base64Ecode DecodeBase64(uint8_t *dest, uint32_t dest_size, const uint8_t *src, uint32_t len,
        uint32_t *consumed_bytes, uint32_t *decoded_bytes, Base64Mode mode)
{
    int val;
    uint32_t padding = 0, bbidx = 0, sp = 0, leading_sp = 0;
    uint8_t *dptr = dest;
    uint8_t b64[B64_BLOCK] = { 0,0,0,0 };
    bool valid = true;
    Base64Ecode ecode = BASE64_ECODE_OK;
    *decoded_bytes = 0;
    /* Traverse through each alpha-numeric letter in the source array */
    for (uint32_t i = 0; i < len && src[i] != 0; i++) {
        /* Get decimal representation */
        val = GetBase64Value(src[i]);
        if (val < 0) {
            if ((mode == BASE64_MODE_RFC2045) && (src[i] == ' ')) {
                if (bbidx == 0) {
                    /* Special case where last block of data has a leading space */
                    leading_sp++;
                }
                sp++;
                continue;
            }
            /* Invalid character found, so decoding fails */
            if (src[i] != '=') {
                valid = false;
                if (mode != BASE64_MODE_RELAX) {
                    *decoded_bytes = 0;
                }
                ecode = BASE64_ECODE_ERR;
                break;
            }
            padding++;
        }

        /* For each alpha-numeric letter in the source array, find the numeric
         * value */
        b64[bbidx++] = (val > 0 ? (uint8_t)val : 0);

        /* Decode every 4 base64 bytes into 3 ascii bytes */
        if (bbidx == B64_BLOCK) {

            /* For every 4 bytes, add 3 bytes but deduct the '=' padded blocks */
            uint32_t numDecoded_blk = ASCII_BLOCK - (padding < B64_BLOCK ? padding : ASCII_BLOCK);
            if (dest_size < *decoded_bytes + numDecoded_blk) {
                SCLogDebug("Destination buffer full");
                ecode = BASE64_ECODE_BUF;
                break;
            }

            /* Decode base-64 block into ascii block and move pointer */
            DecodeBase64Block(dptr, b64);
            dptr += ASCII_BLOCK;
            *decoded_bytes += numDecoded_blk;
            /* Reset base-64 block and index */
            bbidx = 0;
            padding = 0;
            *consumed_bytes += B64_BLOCK + sp;
            sp = 0;
            leading_sp = 0;
            memset(&b64, 0, sizeof(b64));
        }
    }
    /* Finish remaining b64 bytes by padding */
    if (valid && bbidx > 0 && (mode != BASE64_MODE_RFC2045)) {
        /* Decode remaining */
        *decoded_bytes += ASCII_BLOCK - (B64_BLOCK - bbidx);
        DecodeBase64Block(dptr, b64);
    }

    if (*decoded_bytes == 0) {
        SCLogDebug("base64 decoding failed");
    }

    *consumed_bytes += leading_sp;
    return ecode;
}

#ifdef UNITTESTS
static int B64DecodeCompleteString(void)
{
    /*
     * SGVsbG8gV29ybGR6 : Hello Worldz
     * */
    const char *src = "SGVsbG8gV29ybGR6";
    const char *fin_str = "Hello Worldz";
    uint32_t consumed_bytes = 0, num_decoded = 0;
    uint8_t dst[strlen(fin_str)];
    Base64Ecode code = DecodeBase64(dst, strlen(fin_str), (const uint8_t *)src, strlen(src),
            &consumed_bytes, &num_decoded, BASE64_MODE_RFC2045);
    FAIL_IF(code != BASE64_ECODE_OK);
    FAIL_IF(memcmp(dst, fin_str, strlen(fin_str)) != 0);
    FAIL_IF(num_decoded != 12);
    FAIL_IF(consumed_bytes != strlen(src));
    PASS;
}

static int B64DecodeInCompleteString(void)
{
    /*
     * SGVsbG8gV29ybGR6 : Hello Worldz
     * */
    const char *src = "SGVsbG8gV29ybGR";
    const char *fin_str = "Hello Wor"; // bc it'll error out on last 3 bytes
    uint32_t consumed_bytes = 0, num_decoded = 0;
    uint8_t dst[strlen(fin_str)];
    Base64Ecode code = DecodeBase64(dst, strlen(fin_str), (const uint8_t *)src, strlen(src),
            &consumed_bytes, &num_decoded, BASE64_MODE_RFC2045);
    FAIL_IF(code != BASE64_ECODE_OK);
    FAIL_IF(memcmp(dst, fin_str, strlen(fin_str)) != 0);
    FAIL_IF(num_decoded != 9);
    FAIL_IF(consumed_bytes == strlen(src));
    PASS;
}

static int B64DecodeCompleteStringWSp(void)
{
    /*
     * SGVsbG8gV29ybGQ= : Hello World
     * */

    const char *src = "SGVs bG8 gV29y bGQ=";
    const char *fin_str = "Hello World";
    uint8_t dst[strlen(fin_str) + 1]; // 1 for the padding byte
    uint32_t consumed_bytes = 0, num_decoded = 0;
    Base64Ecode code = DecodeBase64(dst, strlen(fin_str), (const uint8_t *)src, strlen(src),
            &consumed_bytes, &num_decoded, BASE64_MODE_RFC2045);
    FAIL_IF(code != BASE64_ECODE_OK);
    FAIL_IF(memcmp(dst, fin_str, strlen(fin_str)) != 0);
    FAIL_IF(num_decoded != 11);
    FAIL_IF(consumed_bytes != strlen(src));
    PASS;
}

static int B64DecodeInCompleteStringWSp(void)
{
    /*
     * SGVsbG8gV29ybGQ= : Hello World
     * Special handling for this case (sp in remainder) done in ProcessBase64Remainder
     * */

    const char *src = "SGVs bG8 gV29y bGQ";
    const char *fin_str = "Hello Wor";
    uint32_t consumed_bytes = 0, num_decoded = 0;
    uint8_t dst[strlen(fin_str)];
    Base64Ecode code = DecodeBase64(dst, strlen(fin_str), (const uint8_t *)src, strlen(src),
            &consumed_bytes, &num_decoded, BASE64_MODE_RFC2045);
    FAIL_IF(code != BASE64_ECODE_OK);
    FAIL_IF(memcmp(dst, fin_str, strlen(fin_str)) != 0);
    FAIL_IF(num_decoded != 9); // bc we don't put padding in RFC2045 mode
    FAIL_IF(consumed_bytes != strlen(src) - 3);
    PASS;
}

static int B64DecodeStringBiggerThanBuffer(void)
{
    /*
     * SGVsbG8gV29ybGQ= : Hello World
     * */

    const char *src = "SGVs bG8 gV29y bGQ=";
    const char *fin_str = "Hello Wor";
    uint32_t consumed_bytes = 0, num_decoded = 0;
    uint8_t dst[strlen(fin_str)];
    Base64Ecode code = DecodeBase64(dst, strlen(fin_str), (const uint8_t *)src, strlen(src),
            &consumed_bytes, &num_decoded, BASE64_MODE_RFC2045);
    FAIL_IF(code != BASE64_ECODE_BUF);
    FAIL_IF(memcmp(dst, fin_str, strlen(fin_str)) != 0);
    FAIL_IF(num_decoded != 9); // dest buf is 10, so 9 got consumed
    FAIL_IF(consumed_bytes != 15);
    PASS;
}

void Base64RegisterTests(void)
{
    UtRegisterTest("B64DecodeCompleteStringWSp", B64DecodeCompleteStringWSp);
    UtRegisterTest("B64DecodeInCompleteStringWSp", B64DecodeInCompleteStringWSp);
    UtRegisterTest("B64DecodeCompleteString", B64DecodeCompleteString);
    UtRegisterTest("B64DecodeInCompleteString", B64DecodeInCompleteString);
    UtRegisterTest("B64DecodeStringBiggerThanBuffer", B64DecodeStringBiggerThanBuffer);
}
#endif
