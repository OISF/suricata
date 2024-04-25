/* Copyright (C) 2007-2024 Open Information Security Foundation
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
#include "util-debug.h"
#include "util-validate.h"
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
 * \brief Checks if the given char in a byte array is Base64 alphabet
 *
 * \param Char that needs to be checked
 *
 * \return True if the char was Base64 alphabet, False otherwise
 */
bool IsBase64Alphabet(uint8_t encoded_byte)
{
    if (GetBase64Value(encoded_byte) < 0 && encoded_byte != '=') {
        return false;
    }
    return true;
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
 * \brief Decode a base64 encoded string as per RFC 2045.
 *        RFC 2045 states that any characters that do not fall under the Base64
 *        alphabet must be skipped by the decoding software.
 *        Following are some important considerations:
 *        1. This Decoding algorithm is used by MIME parser currently.
 *        2. The number of decoded bytes are constrained by the destination buffer size.
 *        3. The leftover bytes are not handled by the decoder but the caller.
 *
 * \param dest destination buffer
 * \param dest_size destination buffer size
 * \param src base64 encoded string
 * \param len length of the base64 encoded string
 * \param consumed_bytes number of bytes successfully consumed by the decoder
 * \param decoded_bytes number of bytes successfully decoded by the decoder
 *
 * \return Base64Ecode BASE64_ECODE_OK if all went well
 *                     BASE64_ECODE_BUF if destination buffer got full before all could be decoded
 */
static inline Base64Ecode DecodeBase64RFC2045(uint8_t *dest, uint32_t dest_size, const uint8_t *src,
        uint32_t len, uint32_t *consumed_bytes, uint32_t *decoded_bytes)
{
    int val;
    uint32_t padding = 0, bbidx = 0, non_b64_chars = 0;
    uint8_t *dptr = dest;
    uint8_t b64[B64_BLOCK] = { 0, 0, 0, 0 };

    for (uint32_t i = 0; i < len; i++) {
        val = GetBase64Value(src[i]);
        if (val < 0) {
            if (src[i] != '=') {
                non_b64_chars++;
                continue;
            } else {
                padding++;
            }
        }

        /* For each alpha-numeric letter in the source array, find the numeric value */
        b64[bbidx++] = val > 0 ? (uint8_t)val : 0;

        /* Decode every 4 base64 bytes into 3 ascii bytes */
        if (bbidx == B64_BLOCK) {
            /* For every 4 bytes, add 3 bytes but deduct the '=' padded blocks */
            uint32_t numDecoded_blk = ASCII_BLOCK - (padding < B64_BLOCK ? padding : ASCII_BLOCK);
            if (dest_size < *decoded_bytes + numDecoded_blk) {
                SCLogDebug("Destination buffer full");
                return BASE64_ECODE_BUF;
            }
            /* Decode base-64 block into ascii block and move pointer */
            DecodeBase64Block(dptr, b64);
            dptr += numDecoded_blk;
            *decoded_bytes += numDecoded_blk;
            /* Reset base-64 block and index */
            bbidx = 0;
            padding = 0;
            *consumed_bytes += B64_BLOCK + non_b64_chars;
            non_b64_chars = 0;
            memset(&b64, 0, sizeof(b64));
        }
    }

    DEBUG_VALIDATE_BUG_ON(*consumed_bytes > len);
    DEBUG_VALIDATE_BUG_ON(bbidx == B64_BLOCK);
    /* Any leftover bytes must be handled by the caller */
    return BASE64_ECODE_OK;
}

/**
 * \brief Decode a base64 encoded string as per RFC 4648.
 *        RFC 4648 states that if a character is encountered that does not fall under
 *        the Base64 alphabet, the decoding software should stop processing the string further.
 *        Following are some important considerations:
 *        1. This Decoding algorithm is used by base64_decode keyword currently.
 *        2. This Decoding algorithm in strict mode is used by datasets currently.
 *        3. The number of decoded bytes are constrained by the destination buffer size.
 *        4. The leftover bytes are handled by the decoder.
 *
 * \param dest destination buffer
 * \param dest_size destination buffer size
 * \param src base64 encoded string
 * \param len length of the base64 encoded string
 * \param consumed_bytes number of bytes successfully consumed by the decoder
 * \param decoded_bytes number of bytes successfully decoded by the decoder
 * \param strict whether an invalid base64 encoding should be strictly rejected
 *
 * \return Base64Ecode BASE64_ECODE_OK if all went well
 *                     BASE64_ECODE_BUF if destination buffer got full before all could be decoded
 *                     BASE64_ECODE_ERR if an invalid char was found in strict mode or nothing was
 * decoded
 */
static inline Base64Ecode DecodeBase64RFC4648(uint8_t *dest, uint32_t dest_size, const uint8_t *src,
        uint32_t len, uint32_t *consumed_bytes, uint32_t *decoded_bytes, bool strict)
{
    int val;
    uint32_t padding = 0, bbidx = 0;
    uint8_t *dptr = dest;
    uint8_t b64[B64_BLOCK] = { 0, 0, 0, 0 };

    for (uint32_t i = 0; i < len; i++) {
        val = GetBase64Value(src[i]);
        if (val < 0) {
            if (src[i] != '=') {
                if (strict) {
                    *decoded_bytes = 0;
                    return BASE64_ECODE_ERR;
                }
                break;
            }
            padding++;
        }
        /* For each alpha-numeric letter in the source array, find the numeric value */
        b64[bbidx++] = (val > 0 ? (uint8_t)val : 0);

        /* Decode every 4 base64 bytes into 3 ascii bytes */
        if (bbidx == B64_BLOCK) {
            /* For every 4 bytes, add 3 bytes but deduct the '=' padded blocks */
            uint32_t numDecoded_blk = ASCII_BLOCK - (padding < B64_BLOCK ? padding : ASCII_BLOCK);
            if (dest_size < *decoded_bytes + numDecoded_blk) {
                SCLogDebug("Destination buffer full");
                return BASE64_ECODE_BUF;
            }

            /* Decode base-64 block into ascii block and move pointer */
            DecodeBase64Block(dptr, b64);
            dptr += numDecoded_blk;
            *decoded_bytes += numDecoded_blk;
            /* Reset base-64 block and index */
            bbidx = 0;
            padding = 0;
            *consumed_bytes += B64_BLOCK;
            memset(&b64, 0, sizeof(b64));
        }
    }

    DEBUG_VALIDATE_BUG_ON(bbidx == B64_BLOCK);

    /* Handle any leftover bytes by adding padding to them as long as they do not
     * violate the destination buffer size */
    if (bbidx > 0) {
        /*
         * --------------------
         * | bbidx  | padding |
         * --------------------
         * |   1    |    2    |
         * |   2    |    2    |
         * |   3    |    1    |
         * --------------------
         * Note: Padding for 1 byte is set to 2 to have at least one
         * decoded byte while calculating numDecoded_blk
         * This does not affect the decoding as the b64 array is already
         * populated with all padding bytes unless overwritten.
         * */
        padding = bbidx > 1 ? B64_BLOCK - bbidx : 2;
        uint32_t numDecoded_blk = ASCII_BLOCK - padding;
        if (dest_size < *decoded_bytes + numDecoded_blk) {
            SCLogDebug("Destination buffer full");
            return BASE64_ECODE_BUF;
        }
        /* Decode base-64 block into ascii block and move pointer */
        DecodeBase64Block(dptr, b64);
        *decoded_bytes += numDecoded_blk;
        /* Consumed bytes should not have the padding bytes added by us */
        *consumed_bytes += bbidx;
    }
    if (*decoded_bytes == 0)
        return BASE64_ECODE_ERR;

    DEBUG_VALIDATE_BUG_ON(*consumed_bytes > len);
    return BASE64_ECODE_OK;
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
    *decoded_bytes = 0;
    Base64Ecode ret = BASE64_ECODE_OK;
    switch (mode) {
        case BASE64_MODE_RFC4648:
            ret = DecodeBase64RFC4648(
                    dest, dest_size, src, len, consumed_bytes, decoded_bytes, false);
            break;
        case BASE64_MODE_RFC2045:
            ret = DecodeBase64RFC2045(dest, dest_size, src, len, consumed_bytes, decoded_bytes);
            break;
        case BASE64_MODE_STRICT:
            ret = DecodeBase64RFC4648(
                    dest, dest_size, src, len, consumed_bytes, decoded_bytes, true);
            break;
        default:
            return BASE64_ECODE_ERR;
    }
    return ret;
}

#ifdef UNITTESTS

#define TEST_RFC2045(src, fin_str, dest_size, exp_decoded, exp_consumed, ecode)                    \
    {                                                                                              \
        uint32_t consumed_bytes = 0, num_decoded = 0;                                              \
        uint8_t dst[dest_size];                                                                    \
        Base64Ecode code = DecodeBase64(dst, dest_size, (const uint8_t *)src, strlen(src),         \
                &consumed_bytes, &num_decoded, BASE64_MODE_RFC2045);                               \
        FAIL_IF(code != ecode);                                                                    \
        FAIL_IF(memcmp(dst, fin_str, strlen(fin_str)) != 0);                                       \
        FAIL_IF(num_decoded != exp_decoded);                                                       \
        FAIL_IF(consumed_bytes != exp_consumed);                                                   \
    }

#define TEST_RFC4648(src, fin_str, dest_size, exp_decoded, exp_consumed, ecode)                    \
    {                                                                                              \
        uint32_t consumed_bytes = 0, num_decoded = 0;                                              \
        uint8_t dst[dest_size];                                                                    \
        Base64Ecode code = DecodeBase64(dst, dest_size, (const uint8_t *)src, strlen(src),         \
                &consumed_bytes, &num_decoded, BASE64_MODE_RFC4648);                               \
        FAIL_IF(code != ecode);                                                                    \
        FAIL_IF(memcmp(dst, fin_str, strlen(fin_str)) != 0);                                       \
        FAIL_IF(num_decoded != exp_decoded);                                                       \
        FAIL_IF(consumed_bytes != exp_consumed);                                                   \
    }

static int B64DecodeCompleteString(void)
{
    /*
     * SGVsbG8gV29ybGR6 : Hello Worldz
     * */
    const char *src = "SGVsbG8gV29ybGR6";
    const char *fin_str = "Hello Worldz";
    TEST_RFC2045(src, fin_str, 12, 12, 16, BASE64_ECODE_OK);
    PASS;
}

static int B64DecodeInCompleteString(void)
{
    /*
     * SGVsbG8gV29ybGR6 : Hello Worldz
     * */
    const char *src = "SGVsbG8gV29ybGR";
    const char *fin_str = "Hello Wor";
    TEST_RFC2045(src, fin_str, 9, 9, 12, BASE64_ECODE_OK);
    PASS;
}

static int B64DecodeCompleteStringWSp(void)
{
    /*
     * SGVsbG8gV29ybGQ= : Hello World
     * */

    const char *src = "SGVs bG8 gV29y bGQ=";
    const char *fin_str = "Hello World";
    TEST_RFC2045(src, fin_str, 14, 11, 19, BASE64_ECODE_OK);
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
    TEST_RFC2045(src, fin_str, 9, 9, 14, BASE64_ECODE_OK);
    PASS;
}

static int B64DecodeStringBiggerThanBuffer(void)
{
    /*
     * SGVsbG8gV29ybGQ= : Hello World
     * */

    const char *src = "SGVs bG8 gV29y bGQ=";
    const char *fin_str = "Hello Wor";
    TEST_RFC2045(src, fin_str, 10, 9, 14, BASE64_ECODE_BUF);
    PASS;
}

static int B64DecodeStringEndingSpaces(void)
{
    const char *src = "0YPhA d H";
    uint32_t consumed_bytes = 0, num_decoded = 0;
    uint8_t dst[10];
    Base64Ecode code = DecodeBase64(dst, sizeof(dst), (const uint8_t *)src, 9, &consumed_bytes,
            &num_decoded, BASE64_MODE_RFC2045);
    FAIL_IF(code != BASE64_ECODE_OK);
    FAIL_IF(num_decoded != 3);
    FAIL_IF(consumed_bytes != 4);
    PASS;
}

static int B64TestVectorsRFC2045(void)
{
    const char *src1 = "";
    const char *fin_str1 = "";

    const char *src2 = "Zg==";
    const char *fin_str2 = "f";

    const char *src3 = "Zm8=";
    const char *fin_str3 = "fo";

    const char *src4 = "Zm9v";
    const char *fin_str4 = "foo";

    const char *src5 = "Zm9vYg==";
    const char *fin_str5 = "foob";

    const char *src6 = "Zm9vYmE=";
    const char *fin_str6 = "fooba";

    const char *src7 = "Zm9vYmFy";
    const char *fin_str7 = "foobar";

    const char *src8 = "Zm 9v Ym Fy";
    const char *fin_str8 = "foobar";

    const char *src9 = "Zm$9vYm.Fy";
    const char *fin_str9 = "foobar";

    const char *src10 = "Y21Wd2IzSjBaVzFoYVd4bWNtRjFaRUJoZEc4dVoyOTJMbUYxOmpqcHh4b3Rhb2w%5";
    const char *fin_str10 = "cmVwb3J0ZW1haWxmcmF1ZEBhdG8uZ292LmF1:jjpxxotaol9";

    const char *src11 = "Zm 9v Ym Fy        7fy";
    const char *fin_str11 = "foobar";

    TEST_RFC2045(src1, fin_str1, ASCII_BLOCK * 2, strlen(fin_str1), strlen(src1), BASE64_ECODE_OK);
    TEST_RFC2045(src2, fin_str2, ASCII_BLOCK * 2, strlen(fin_str2), strlen(src2), BASE64_ECODE_OK);
    TEST_RFC2045(src3, fin_str3, ASCII_BLOCK * 2, strlen(fin_str3), strlen(src3), BASE64_ECODE_OK);
    TEST_RFC2045(src4, fin_str4, ASCII_BLOCK * 2, strlen(fin_str4), strlen(src4), BASE64_ECODE_OK);
    TEST_RFC2045(src5, fin_str5, ASCII_BLOCK * 2, strlen(fin_str5), strlen(src5), BASE64_ECODE_OK);
    TEST_RFC2045(src6, fin_str6, ASCII_BLOCK * 2, strlen(fin_str6), strlen(src6), BASE64_ECODE_OK);
    TEST_RFC2045(src7, fin_str7, ASCII_BLOCK * 2, strlen(fin_str7), strlen(src7), BASE64_ECODE_OK);
    TEST_RFC2045(src8, fin_str8, ASCII_BLOCK * 2, strlen(fin_str8), strlen(src8), BASE64_ECODE_OK);
    TEST_RFC2045(src9, fin_str9, ASCII_BLOCK * 2, strlen(fin_str9), strlen(src9), BASE64_ECODE_OK);
    TEST_RFC2045(src10, fin_str10, 50, 48, 65, BASE64_ECODE_OK);
    TEST_RFC2045(src11, fin_str11, ASCII_BLOCK * 2, 6, 11, BASE64_ECODE_OK);
    PASS;
}

static int B64TestVectorsRFC4648(void)
{
    const char *src1 = "";
    const char *fin_str1 = "";

    const char *src2 = "Zg==";
    const char *fin_str2 = "f";

    const char *src3 = "Zm8=";
    const char *fin_str3 = "fo";

    const char *src4 = "Zm9v";
    const char *fin_str4 = "foo";

    const char *src5 = "Zm9vYg==";
    const char *fin_str5 = "foob";

    const char *src6 = "Zm9vYmE=";
    const char *fin_str6 = "fooba";

    const char *src7 = "Zm9vYmFy";
    const char *fin_str7 = "foobar";

    const char *src8 = "Zm 9v Ym Fy";
    const char *fin_str8 = "f";

    const char *src9 = "Zm$9vYm.Fy";
    const char *fin_str9 = "f";

    const char *src10 = "Y21Wd2IzSjBaVzFoYVd4bWNtRjFaRUJoZEc4dVoyOTJMbUYxOmpqcHh4b3Rhb2w%3D";
    const char *fin_str10 = "cmVwb3J0ZW1haWxmcmF1ZEBhdG8uZ292LmF1:jjpxxotaol";

    const char *src11 = "Zm9vYg==";
    const char *fin_str11 = "foo";

    TEST_RFC4648(src1, fin_str1, ASCII_BLOCK * 2, strlen(fin_str1), strlen(src1), BASE64_ECODE_ERR);
    TEST_RFC4648(src2, fin_str2, ASCII_BLOCK * 2, strlen(fin_str2), strlen(src2), BASE64_ECODE_OK);
    TEST_RFC4648(src3, fin_str3, ASCII_BLOCK * 2, strlen(fin_str3), strlen(src3), BASE64_ECODE_OK);
    TEST_RFC4648(src4, fin_str4, ASCII_BLOCK * 2, strlen(fin_str4), strlen(src4), BASE64_ECODE_OK);
    TEST_RFC4648(src5, fin_str5, ASCII_BLOCK * 2, strlen(fin_str5), strlen(src5), BASE64_ECODE_OK);
    TEST_RFC4648(src6, fin_str6, ASCII_BLOCK * 2, strlen(fin_str6), strlen(src6), BASE64_ECODE_OK);
    TEST_RFC4648(src7, fin_str7, ASCII_BLOCK * 2, strlen(fin_str7), strlen(src7), BASE64_ECODE_OK);
    TEST_RFC4648(src8, fin_str8, ASCII_BLOCK * 2, 1 /* f */, 2 /* Zm */, BASE64_ECODE_OK);
    TEST_RFC4648(src9, fin_str9, ASCII_BLOCK * 2, 1 /* f */, 2 /* Zm */, BASE64_ECODE_OK);
    TEST_RFC4648(src10, fin_str10, 48, 47, 63, BASE64_ECODE_OK);
    TEST_RFC4648(src11, fin_str11, 3, 3, 4, BASE64_ECODE_BUF);
    PASS;
}

void Base64RegisterTests(void)
{
    UtRegisterTest("B64DecodeCompleteStringWSp", B64DecodeCompleteStringWSp);
    UtRegisterTest("B64DecodeInCompleteStringWSp", B64DecodeInCompleteStringWSp);
    UtRegisterTest("B64DecodeCompleteString", B64DecodeCompleteString);
    UtRegisterTest("B64DecodeInCompleteString", B64DecodeInCompleteString);
    UtRegisterTest("B64DecodeStringBiggerThanBuffer", B64DecodeStringBiggerThanBuffer);
    UtRegisterTest("B64DecodeStringEndingSpaces", B64DecodeStringEndingSpaces);
    UtRegisterTest("B64TestVectorsRFC2045", B64TestVectorsRFC2045);
    UtRegisterTest("B64TestVectorsRFC4648", B64TestVectorsRFC4648);
}
#endif
