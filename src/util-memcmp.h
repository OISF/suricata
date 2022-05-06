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
 * \author Victor Julien <victor@inliniac.net>
 *
 * Memcmp implementations for SSE3, SSE4.1, SSE4.2 and AVX2.
 *
 * Both SCMemcmp and SCMemcmpLowercase return 0 on a exact match,
 * 1 on a failed match.
 */

#ifndef SURICATA_UTIL_MEMCMP_H
#define SURICATA_UTIL_MEMCMP_H

#include "suricata-common.h"
#include "util-optimize.h"

/** \brief compare two patterns, converting the 2nd to lowercase
 *  \warning *ONLY* the 2nd pattern is converted to lowercase
 */

static inline int SCMemcmpLT32(const void *s1, const void *s2, size_t len);
static inline int SCMemcmpLowercaseLT32(const void *s1, const void *s2, size_t len);

static inline int
MemcmpLowercase(const void *s1, const void *s2, size_t n)
{
    for (size_t i = 0; i < n; i++) {
        if (((uint8_t *)s1)[i] != u8_tolower(((uint8_t *)s2)[i]))
            return 1;
    }

    return 0;
}

#if defined(__AVX512VL__) && defined(__AVX512BW__)
#include <immintrin.h>
#define SCMEMCMP_BYTES 16
static inline int SCMemcmpAVX512_128(const void *s1, const void *s2, size_t len)
{
    size_t offset = 0;
    do {
        if (likely(len - offset < SCMEMCMP_BYTES)) {
            return memcmp(s1, s2, len - offset) ? 1 : 0;
        }

        /* unaligned loads */
        __m128i b1 = _mm_lddqu_si128((const __m128i *)s1);
        __m128i b2 = _mm_lddqu_si128((const __m128i *)s2);
        if (_mm_cmpeq_epi8_mask(b1, b2) != 0x0000FFFF) {
            return 1;
        }

        offset += SCMEMCMP_BYTES;
        s1 += SCMEMCMP_BYTES;
        s2 += SCMEMCMP_BYTES;
    } while (len > offset);

    return 0;
}
#undef SCMEMCMP_BYTES
#define SCMEMCMP_BYTES 32
static inline int SCMemcmpAVX512_256(const void *s1, const void *s2, size_t len)
{
    size_t offset = 0;
    do {
        if (likely(len - offset < SCMEMCMP_BYTES)) {
            return SCMemcmpAVX512_128(s1, s2, len - offset);
        }

        /* unaligned loads */
        __m256i b1 = _mm256_lddqu_si256((const __m256i *)s1);
        __m256i b2 = _mm256_lddqu_si256((const __m256i *)s2);
        if (_mm256_cmpeq_epi8_mask(b1, b2) != UINT32_MAX) {
            return 1;
        }

        offset += SCMEMCMP_BYTES;
        s1 += SCMEMCMP_BYTES;
        s2 += SCMEMCMP_BYTES;
    } while (len > offset);

    return 0;
}
#undef SCMEMCMP_BYTES
#define SCMEMCMP_BYTES 64
static inline int SCMemcmpAVX512_512(const void *s1, const void *s2, size_t len)
{
    size_t offset = 0;
    do {
        if (likely(len - offset < SCMEMCMP_BYTES)) {
            return SCMemcmpAVX512_256(s1, s2, len - offset);
        }

        /* unaligned loads */
        __m512i b1 = _mm512_loadu_si512((const __m512i *)s1);
        __m512i b2 = _mm512_loadu_si512((const __m512i *)s2);
        if (_mm512_cmpeq_epi8_mask(b1, b2) != UINT64_MAX) {
            return 1;
        }

        offset += SCMEMCMP_BYTES;
        s1 += SCMEMCMP_BYTES;
        s2 += SCMEMCMP_BYTES;
    } while (len > offset);

    return 0;
}
#undef SCMEMCMP_BYTES
#endif

#if defined(__AVX512VL__) && defined(__AVX512BW__)
#include <immintrin.h>
#define SCMEMCMP_BYTES 32
// clang-format off
static char scmemcmp_avx512_space32[32] __attribute__((aligned(32))) = {
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
};
static char scmemcmp_avx512_upper_low32[32] __attribute__((aligned(32))) = {
    0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40,
    0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40,
    0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40,
    0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40,
};
static char scmemcmp_avx512_upper_hi32[32] __attribute__((aligned(32))) = {
    0x5b, 0x5b, 0x5b, 0x5b, 0x5b, 0x5b, 0x5b, 0x5b,
    0x5b, 0x5b, 0x5b, 0x5b, 0x5b, 0x5b, 0x5b, 0x5b,
    0x5b, 0x5b, 0x5b, 0x5b, 0x5b, 0x5b, 0x5b, 0x5b,
    0x5b, 0x5b, 0x5b, 0x5b, 0x5b, 0x5b, 0x5b, 0x5b,
};
// clang-format on

static inline int SCMemcmpLowercaseAVX512_256(const void *s1, const void *s2, size_t len)
{
    size_t offset = 0;
    __m256i b1, b2, mask1, mask2, upper1, upper2, uplow;

    upper1 = _mm256_load_si256((const __m256i *)scmemcmp_avx512_upper_low32);
    upper2 = _mm256_load_si256((const __m256i *)scmemcmp_avx512_upper_hi32);
    uplow = _mm256_load_si256((const __m256i *)scmemcmp_avx512_space32);

    do {
        if (likely(len - offset < SCMEMCMP_BYTES)) {
            return SCMemcmpLowercaseLT32(s1, s2, len - offset);
        }

        /* unaligned loading of the bytes to compare */
        b1 = _mm256_lddqu_si256((const __m256i *)s1);
        b2 = _mm256_lddqu_si256((const __m256i *)s2);

        /* mark all chars bigger than upper1 */
        mask1 = _mm256_cmpgt_epi8(b2, upper1);
        /* mark all chars lower than upper2 */
        mask2 = _mm256_cmpgt_epi8(upper2, b2);
        /* merge the two, leaving only those that are true in both */
        mask1 = _mm256_cmpeq_epi8(mask1, mask2);
        /* Next we use that mask to create a new: this one has 0x20 for
         * the uppercase chars, 00 for all other. */
        mask1 = _mm256_and_si256(uplow, mask1);

        /* add to b2, converting uppercase to lowercase */
        b2 = _mm256_add_epi8(b2, mask1);

        /* now all is lowercase, let's do the actual compare */
        int32_t r = _mm256_cmpeq_epi8_mask(b1, b2);
        if (r != -1) {
            return 1;
        }

        offset += SCMEMCMP_BYTES;
        s1 += SCMEMCMP_BYTES;
        s2 += SCMEMCMP_BYTES;
    } while (len > offset);

    return 0;
}
#undef SCMEMCMP_BYTES
#define SCMEMCMP_BYTES 64
// clang-format off
static char scmemcmp_space64[64] __attribute__((aligned(64))) = {
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
};
static char scmemcmp_upper_low64[64] __attribute__((aligned(64))) = {
    0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40,
    0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40,
    0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40,
    0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40,
    0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40,
    0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40,
    0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40,
    0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40,
};
static char scmemcmp_upper_hi64[64] __attribute__((aligned(64))) = {
    0x5b, 0x5b, 0x5b, 0x5b, 0x5b, 0x5b, 0x5b, 0x5b,
    0x5b, 0x5b, 0x5b, 0x5b, 0x5b, 0x5b, 0x5b, 0x5b,
    0x5b, 0x5b, 0x5b, 0x5b, 0x5b, 0x5b, 0x5b, 0x5b,
    0x5b, 0x5b, 0x5b, 0x5b, 0x5b, 0x5b, 0x5b, 0x5b,
    0x5b, 0x5b, 0x5b, 0x5b, 0x5b, 0x5b, 0x5b, 0x5b,
    0x5b, 0x5b, 0x5b, 0x5b, 0x5b, 0x5b, 0x5b, 0x5b,
    0x5b, 0x5b, 0x5b, 0x5b, 0x5b, 0x5b, 0x5b, 0x5b,
    0x5b, 0x5b, 0x5b, 0x5b, 0x5b, 0x5b, 0x5b, 0x5b,
};
// clang-format on

static inline int SCMemcmpLowercaseAVX512_512(const void *s1, const void *s2, size_t len)
{
    size_t offset = 0;
    __m512i upper1 = _mm512_load_si512((const __m512i *)scmemcmp_upper_low64);
    __m512i upper2 = _mm512_load_si512((const __m512i *)scmemcmp_upper_hi64);

    do {
        if (likely(len - offset < SCMEMCMP_BYTES)) {
            return SCMemcmpLowercaseAVX512_256(s1, s2, len - offset);
        }

        /* unaligned loading of the bytes to compare */
        __m512i b1 = _mm512_loadu_si512((const __m512i *)s1);
        __m512i b2 = _mm512_loadu_si512((const __m512i *)s2);

        /* mark all chars bigger than upper1 */
        uint64_t m1 = _mm512_cmp_epi8_mask(upper1, b2, _MM_CMPINT_LT);
        /* mark all chars lower than upper2 */
        uint64_t m2 = _mm512_cmp_epi8_mask(b2, upper2, _MM_CMPINT_LT);
        /* merge the two, leaving only those that are true in both */
        uint64_t m3 = m1 & m2;
        /* use mask to create array of 0x20 and 0x00's */
        __m512i uplow = _mm512_mask_loadu_epi8(
                _mm512_setzero_si512(), m3, (const __m512i *)scmemcmp_space64);
        /* use it to create the lowercase'd buffer */
        b2 = _mm512_add_epi8(b2, uplow);
        /* now all is lowercase, let's do the actual compare */
        uint64_t r = _mm512_cmpeq_epi8_mask(b1, b2);
        if (r != UINT64_MAX) {
            return 1;
        }

        offset += SCMEMCMP_BYTES;
        s1 += SCMEMCMP_BYTES;
        s2 += SCMEMCMP_BYTES;
    } while (len > offset);

    return 0;
}
#undef SCMEMCMP_BYTES
#endif
#if defined(__AVX2__)
#include <immintrin.h>
#define SCMEMCMP_BYTES 32

static inline int SCMemcmpAVX2(const void *s1, const void *s2, size_t len)
{
    size_t offset = 0;

    do {
        if (likely(len - offset < SCMEMCMP_BYTES)) {
            return SCMemcmpLT32(s1, s2, len - offset);
        }

        __m256i b1 = _mm256_lddqu_si256((const __m256i *)((const uint8_t *)s1 + offset));
        __m256i b2 = _mm256_lddqu_si256((const __m256i *)((const uint8_t *)s2 + offset));
        __m256i c = _mm256_cmpeq_epi8(b1, b2);

        int r = _mm256_movemask_epi8(c);
        if (r != -1) {
            return 1;
        }

        offset += SCMEMCMP_BYTES;
    } while (len > offset);

    return 0;
}
#undef SCMEMCMP_BYTES
#endif

#if defined(__AVX2__)
#include <immintrin.h>
#define SCMEMCMP_BYTES 32
// clang-format off
static char scmemcmp_space32[32] __attribute__((aligned(32))) = {
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
};
static char scmemcmp_upper_low32[32] __attribute__((aligned(32))) = {
    0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40,
    0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40,
    0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40,
    0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40,
};
static char scmemcmp_upper_hi32[32] __attribute__((aligned(32))) = {
    0x5b, 0x5b, 0x5b, 0x5b, 0x5b, 0x5b, 0x5b, 0x5b,
    0x5b, 0x5b, 0x5b, 0x5b, 0x5b, 0x5b, 0x5b, 0x5b,
    0x5b, 0x5b, 0x5b, 0x5b, 0x5b, 0x5b, 0x5b, 0x5b,
    0x5b, 0x5b, 0x5b, 0x5b, 0x5b, 0x5b, 0x5b, 0x5b,
};
// clang-format on

static inline int SCMemcmpLowercaseAVX2(const void *s1, const void *s2, size_t len)
{
    size_t offset = 0;
    __m256i upper1 = _mm256_load_si256((const __m256i *)scmemcmp_upper_low32);
    __m256i upper2 = _mm256_load_si256((const __m256i *)scmemcmp_upper_hi32);
    __m256i uplow = _mm256_load_si256((const __m256i *)scmemcmp_space32);

    do {
        if (likely(len - offset < SCMEMCMP_BYTES)) {
            return SCMemcmpLowercaseLT32(s1, s2, len - offset);
        }

        /* unaligned loading of the bytes to compare */
        __m256i b1 = _mm256_lddqu_si256((const __m256i *)((const uint8_t *)s1 + offset));
        __m256i b2 = _mm256_lddqu_si256((const __m256i *)((const uint8_t *)s2 + offset));

        /* mark all chars bigger than upper1 */
        __m256i mask1 = _mm256_cmpgt_epi8(b2, upper1);
        /* mark all chars lower than upper2 */
        __m256i mask2 = _mm256_cmpgt_epi8(upper2, b2);
        /* merge the two, leaving only those that are true in both */
        mask1 = _mm256_cmpeq_epi8(mask1, mask2);
        /* Next we use that mask to create a new: this one has 0x20 for
         * the uppercase chars, 00 for all other. */
        mask1 = _mm256_and_si256(uplow, mask1);
        /* add to b2, converting uppercase to lowercase */
        b2 = _mm256_add_epi8(b2, mask1);
        /* now all is lowercase, let's do the actual compare (reuse mask1 reg) */
        mask1 = _mm256_cmpeq_epi8(b1, b2);

        int r = _mm256_movemask_epi8(mask1);
        if (r != -1) {
            return 1;
        }

        offset += SCMEMCMP_BYTES;
    } while (len > offset);

    return 0;
}
#undef SCMEMCMP_BYTES
#endif

#if defined(__SSE4_2__)
#include <nmmintrin.h>
#define SCMEMCMP_BYTES 16

static inline int SCMemcmpSSE42(const void *s1, const void *s2, size_t n)
{
    int r = 0;
    /* counter for how far we already matched in the buffer */
    size_t m = 0;
    do {
        if (likely(n - m < SCMEMCMP_BYTES)) {
            return memcmp(s1, s2, n - m) ? 1 : 0;
        }

        /* load the buffers into the 128bit vars */
        __m128i b1 = _mm_lddqu_si128((const __m128i *)s1);
        __m128i b2 = _mm_lddqu_si128((const __m128i *)s2);

        /* do the actual compare: _mm_cmpestri() returns the number of matching bytes */
        r = _mm_cmpestri(b1, SCMEMCMP_BYTES, b2, SCMEMCMP_BYTES,
                _SIDD_CMP_EQUAL_EACH | _SIDD_MASKED_NEGATIVE_POLARITY);
        m += r;
        s1 += SCMEMCMP_BYTES;
        s2 += SCMEMCMP_BYTES;
    } while (r == SCMEMCMP_BYTES);

    return ((m == n) ? 0 : 1);
}
#undef SCMEMCMP_BYTES
#endif

#if defined(__SSE4_2__)
#include <nmmintrin.h>
#define SCMEMCMP_BYTES 16
/* Range of values of uppercase characters. We only use the first 2 bytes. */
// clang-format off
static char scmemcmp_uppercase[16] __attribute__((aligned(16))) = {
    'A', 'Z', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, };
static char scmemcmp_space[16] __attribute__((aligned(16))) = {
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
};
// clang-format on

/** \brief compare two buffers in a case insensitive way
 *  \param s1 buffer already in lowercase
 *  \param s2 buffer with mixed upper and lowercase
 */
static inline int SCMemcmpLowercaseSSE42(const void *s1, const void *s2, size_t n)
{
    /* counter for how far we already matched in the buffer */
    size_t m = 0;
    int r = 0;
    __m128i ucase = _mm_load_si128((const __m128i *) scmemcmp_uppercase);
    __m128i uplow = _mm_load_si128((const __m128i *)scmemcmp_space);

    do {
        const size_t len = n - m;
        if (likely(len < SCMEMCMP_BYTES)) {
            return MemcmpLowercase(s1, s2, len);
        }

        __m128i b1 = _mm_lddqu_si128((const __m128i *)s1);
        __m128i b2 = _mm_lddqu_si128((const __m128i *)s2);
        /* The first step is creating a mask that is FF for all uppercase
         * characters, 00 for all others */
        __m128i mask = _mm_cmpestrm(ucase, 2, b2, len, _SIDD_CMP_RANGES | _SIDD_UNIT_MASK);
        /* Next we use that mask to create a new: this one has 0x20 for
         * the uppercase chars, 00 for all other. */
        mask = _mm_and_si128(uplow, mask);
        /* finally, merge the mask and the buffer converting the
         * uppercase to lowercase */
        b2 = _mm_add_epi8(b2, mask);
        /* search using our converted buffer, return number of matching bytes */
        r = _mm_cmpestri(b1, SCMEMCMP_BYTES, b2, SCMEMCMP_BYTES,
                _SIDD_CMP_EQUAL_EACH | _SIDD_MASKED_NEGATIVE_POLARITY);
        m += r;
        s1 += SCMEMCMP_BYTES;
        s2 += SCMEMCMP_BYTES;
    } while (r == SCMEMCMP_BYTES);

    return ((m == n) ? 0 : 1);
}
#undef SCMEMCMP_BYTES
#endif

#if defined(__SSE4_1__)
#include <smmintrin.h>
#define SCMEMCMP_BYTES  16

static inline int SCMemcmpSSE41(const void *s1, const void *s2, size_t len)
{
    size_t offset = 0;
    do {
        if (likely(len - offset < SCMEMCMP_BYTES)) {
            return memcmp(s1, s2, len - offset) ? 1 : 0;
        }

        /* unaligned loads */
        __m128i b1 = _mm_lddqu_si128((const __m128i *)s1);
        __m128i b2 = _mm_lddqu_si128((const __m128i *)s2);
        __m128i c = _mm_cmpeq_epi8(b1, b2);

        if (_mm_movemask_epi8(c) != 0x0000FFFF) {
            return 1;
        }

        offset += SCMEMCMP_BYTES;
        s1 += SCMEMCMP_BYTES;
        s2 += SCMEMCMP_BYTES;
    } while (len > offset);

    return 0;
}
#undef SCMEMCMP_BYTES
#endif

#if defined(__SSE4_1__)
#include <smmintrin.h>
#define SCMEMCMP_BYTES 16
#define UPPER_LOW   0x40 /* "A" - 1 */
#define UPPER_HIGH  0x5B /* "Z" + 1 */

// clang-format off
static char scmemcmp_sse41_ul[16] __attribute__((aligned(16))) = {
    0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40,
    0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40,
};
static char scmemcmp_sse41_uh[16] __attribute__((aligned(16))) = {
    0x5b, 0x5b, 0x5b, 0x5b, 0x5b, 0x5b, 0x5b, 0x5b,
    0x5b, 0x5b, 0x5b, 0x5b, 0x5b, 0x5b, 0x5b, 0x5b,
};
static char scmemcmp_sse41_sp[16] __attribute__((aligned(16))) = {
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
};
// clang-format on

static inline int SCMemcmpLowercaseSSE41(const void *s1, const void *s2, size_t len)
{
    size_t offset = 0;

    /* setup registers for upper to lower conversion */
    __m128i upper1 = _mm_load_si128((const __m128i *)scmemcmp_sse41_ul);
    __m128i upper2 = _mm_load_si128((const __m128i *)scmemcmp_sse41_uh);
    __m128i uplow = _mm_load_si128((const __m128i *)scmemcmp_sse41_sp);

    do {
        if (likely(len - offset < SCMEMCMP_BYTES)) {
            return MemcmpLowercase(s1, s2, len - offset);
        }

        /* unaligned loading of the bytes to compare */
        __m128i b2 = _mm_lddqu_si128((const __m128i *)s2);

        /* mark all chars bigger than upper1 */
        __m128i mask1 = _mm_cmpgt_epi8(b2, upper1);
        /* mark all chars lower than upper2 */
        __m128i mask2 = _mm_cmplt_epi8(b2, upper2);
        /* merge the two, leaving only those that are true in both */
        mask1 = _mm_cmpeq_epi8(mask1, mask2);
        /* Next we use that mask to create a new: this one has 0x20 for
         * the uppercase chars, 00 for all other. */
        mask1 = _mm_and_si128(uplow, mask1);
        /* add to b2, converting uppercase to lowercase */
        b2 = _mm_add_epi8(b2, mask1);
        /* now all is lowercase, let's do the actual compare (reuse mask1 reg) */
        __m128i b1 = _mm_lddqu_si128((const __m128i *)s1);
        mask1 = _mm_cmpeq_epi8(b1, b2);

        if (_mm_movemask_epi8(mask1) != 0x0000FFFF) {
            return 1;
        }

        offset += SCMEMCMP_BYTES;
        s1 += SCMEMCMP_BYTES;
        s2 += SCMEMCMP_BYTES;
    } while (len > offset);

    return 0;
}
#undef SCMEMCMP_BYTES
#endif

#if defined(__SSE3__)
#include <pmmintrin.h> /* for SSE3 */
#define SCMEMCMP_BYTES  16

static inline int SCMemcmpSSE3(const void *s1, const void *s2, size_t len)
{
    size_t offset = 0;
    __m128i b1, b2, c;

    do {
        if (likely(len - offset < SCMEMCMP_BYTES)) {
            return memcmp(s1, s2, len - offset) ? 1 : 0;
        }

        /* unaligned loads */
        b1 = _mm_loadu_si128((const __m128i *) s1);
        b2 = _mm_loadu_si128((const __m128i *) s2);
        c = _mm_cmpeq_epi8(b1, b2);

        if (_mm_movemask_epi8(c) != 0x0000FFFF) {
            return 1;
        }

        offset += SCMEMCMP_BYTES;
        s1 += SCMEMCMP_BYTES;
        s2 += SCMEMCMP_BYTES;
    } while (len > offset);

    return 0;
}

#define UPPER_LOW   0x40 /* "A" - 1 */
#define UPPER_HIGH  0x5B /* "Z" + 1 */
#define UPPER_DELTA 0xDF /* 0xFF - 0x20 */

// clang-format off
static char scmemcmp_sse3_ul[16] __attribute__((aligned(16))) = {
    0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40,
    0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40,
};
static char scmemcmp_sse3_uh[16] __attribute__((aligned(16))) = {
    0x5b, 0x5b, 0x5b, 0x5b, 0x5b, 0x5b, 0x5b, 0x5b,
    0x5b, 0x5b, 0x5b, 0x5b, 0x5b, 0x5b, 0x5b, 0x5b,
};
static char scmemcmp_sse3_dt[16] __attribute__((aligned(16))) = {
    0xdf, 0xdf, 0xdf, 0xdf, 0xdf, 0xdf, 0xdf, 0xdf,
    0xdf, 0xdf, 0xdf, 0xdf, 0xdf, 0xdf, 0xdf, 0xdf,
};
static char scmemcmp_sse3_sp[16] __attribute__((aligned(16))) = {
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
};
// clang-format on

/* use subs delta */
static inline int SCMemcmpLowercaseSSE3(const void *s1, const void *s2, size_t len)
{
    size_t offset = 0;
    /* setup registers for upper to lower conversion */
    __m128i upper1 = _mm_load_si128((const __m128i *)scmemcmp_sse3_ul);
    __m128i upper2 = _mm_load_si128((const __m128i *)scmemcmp_sse3_uh);
    __m128i delta = _mm_load_si128((const __m128i *)scmemcmp_sse3_dt);

    do {
        if (likely(len - offset < SCMEMCMP_BYTES)) {
            return MemcmpLowercase(s1, s2, len - offset);
        }

        /* unaligned loading of the bytes to compare */
        __m128i b2 = _mm_lddqu_si128((const __m128i *)s2);

        /* mark all chars bigger than upper1 */
        __m128i mask1 = _mm_cmpgt_epi8(b2, upper1);
        /* mark all chars lower than upper2 */
        __m128i mask2 = _mm_cmplt_epi8(b2, upper2);
        /* merge the two, leaving only those that are true in both */
        mask1 = _mm_cmpeq_epi8(mask1, mask2);
        /* sub delta leaves 0x20 only for uppercase positions, the
           rest is 0x00 due to the saturation (reuse mask1 reg)*/
        mask1 = _mm_subs_epu8(mask1, delta);
        /* add to b2, converting uppercase to lowercase */
        b2 = _mm_add_epi8(b2, mask1);

        /* now all is lowercase, let's do the actual compare (reuse mask1 reg) */
        __m128i b1 = _mm_lddqu_si128((const __m128i *)s1);
        mask1 = _mm_cmpeq_epi8(b1, b2);

        if (_mm_movemask_epi8(mask1) != 0x0000FFFF) {
            return 1;
        }

        offset += SCMEMCMP_BYTES;
        s1 += SCMEMCMP_BYTES;
        s2 += SCMEMCMP_BYTES;
    } while (len > offset);

    return 0;
}

/* use sp and */
static inline int SCMemcmpLowercaseSSE3and(const void *s1, const void *s2, size_t len)
{
    size_t offset = 0;
    __m128i b1, b2, mask1, mask2, upper1, upper2, zero20;

    do {
        if (likely(len - offset < SCMEMCMP_BYTES)) {
            return MemcmpLowercase(s1, s2, len - offset);
        }

        /* unaligned loading of the bytes to compare */
        b2 = _mm_lddqu_si128((const __m128i *)s2);
        /* setup registers for upper to lower conversion */
        upper1 = _mm_load_si128((const __m128i *)scmemcmp_sse3_ul);
        upper2 = _mm_load_si128((const __m128i *)scmemcmp_sse3_uh);
        zero20 = _mm_load_si128((const __m128i *)scmemcmp_sse3_sp);

        /* mark all chars bigger than upper1 */
        mask1 = _mm_cmpgt_epi8(b2, upper1);
        /* mark all chars lower than upper2 */
        mask2 = _mm_cmplt_epi8(b2, upper2);
        /* merge the two, leaving only those that are true in both */
        mask1 = _mm_cmpeq_epi8(mask1, mask2);
        /* sub delta leaves 0x20 only for uppercase positions, the
           rest is 0x00 due to the saturation (reuse mask1 reg)*/
        mask1 = _mm_and_si128(zero20, mask1);
        /* add to b2, converting uppercase to lowercase */
        b2 = _mm_add_epi8(b2, mask1);

        /* now all is lowercase, let's do the actual compare (reuse mask1 reg) */
        b1 = _mm_lddqu_si128((const __m128i *)s1);
        mask1 = _mm_cmpeq_epi8(b1, b2);

        if (_mm_movemask_epi8(mask1) != 0x0000FFFF) {
            return 1;
        }

        offset += SCMEMCMP_BYTES;
        s1 += SCMEMCMP_BYTES;
        s2 += SCMEMCMP_BYTES;
    } while (len > offset);

    return 0;
}

/* sp and + loadu */
static inline int SCMemcmpLowercaseSSE3andload(const void *s1, const void *s2, size_t len)
{
    size_t offset = 0;
    __m128i b1, b2, mask1, mask2, upper1, upper2, zero20;

    do {
        if (likely(len - offset < SCMEMCMP_BYTES)) {
            return MemcmpLowercase(s1, s2, len - offset);
        }

        /* unaligned loading of the bytes to compare */
        b2 = _mm_loadu_si128((const __m128i *)s2);
        /* setup registers for upper to lower conversion */
        upper1 = _mm_load_si128((const __m128i *)scmemcmp_sse3_ul);
        upper2 = _mm_load_si128((const __m128i *)scmemcmp_sse3_uh);
        zero20 = _mm_load_si128((const __m128i *)scmemcmp_sse3_sp);

        /* mark all chars bigger than upper1 */
        mask1 = _mm_cmpgt_epi8(b2, upper1);
        /* mark all chars lower than upper2 */
        mask2 = _mm_cmplt_epi8(b2, upper2);
        /* merge the two, leaving only those that are true in both */
        mask1 = _mm_cmpeq_epi8(mask1, mask2);
        /* sub delta leaves 0x20 only for uppercase positions, the
           rest is 0x00 due to the saturation (reuse mask1 reg)*/
        mask1 = _mm_and_si128(zero20, mask1);
        /* add to b2, converting uppercase to lowercase */
        b2 = _mm_add_epi8(b2, mask1);

        /* now all is lowercase, let's do the actual compare (reuse mask1 reg) */
        b1 = _mm_loadu_si128((const __m128i *)s1);
        mask1 = _mm_cmpeq_epi8(b1, b2);

        if (_mm_movemask_epi8(mask1) != 0x0000FFFF) {
            return 1;
        }

        offset += SCMEMCMP_BYTES;
        s1 += SCMEMCMP_BYTES;
        s2 += SCMEMCMP_BYTES;
    } while (len > offset);

    return 0;
}
#undef SCMEMCMP_BYTES
#endif

/* No SIMD support, fall back to plain memcmp and a home grown lowercase one */

static inline int SCMemcmpLT32(const void *s1, const void *s2, size_t len)
{
    if (len < 16) {
        return memcmp(s1, s2, len) == 0 ? 0 : 1;
    }

#if defined(__AVX512VL__) && defined(__AVX512BW__)
    return SCMemcmpAVX512_128(s1, s2, len);
#elif defined(__SSE4_2__)
    return SCMemcmpSSE42(s1, s2, len);
#elif defined(__SSE4_1__)
    return SCMemcmpSSE41(s1, s2, len);
#elif defined(__SSE3__)
    return SCMemcmpSSE3(s1, s2, len);
#else
    return memcmp(s1, s2, len) == 0 ? 0 : 1;
#endif
}

static inline int SCMemcmpLT64(const void *s1, const void *s2, size_t len)
{
    if (len < 32) {
        return SCMemcmpLT32(s1, s2, len);
    }
#if defined(__AVX512VL__) && defined(__AVX512BW__)
    return SCMemcmpAVX512_256(s1, s2, len);
#elif defined(__AVX2__)
    return SCMemcmpAVX2(s1, s2, len);
#elif defined(__SSE4_2__)
    return SCMemcmpSSE42(s1, s2, len);
#elif defined(__SSE4_1__)
    return SCMemcmpSSE41(s1, s2, len);
#elif defined(__SSE3__)
    return SCMemcmpSSE3(s1, s2, len);
#else
    return memcmp(s1, s2, len) == 0 ? 0 : 1;
#endif
}

/* wrapper around memcmp to match the retvals of the SIMD implementations */
static inline int SCMemcmp(const void *s1, const void *s2, size_t len)
{
#if defined(__AVX512VL__) && defined(__AVX512BW__)
    if (len < 64) {
        return SCMemcmpLT64(s1, s2, len);
    }
    return SCMemcmpAVX512_256(s1, s2, len);
#elif defined(__AVX2__)
    if (len < 32) {
        return SCMemcmpLT32(s1, s2, len);
    }
    return SCMemcmpAVX2(s1, s2, len);
#elif defined(__SSE4_2__)
    return SCMemcmpSSE42(s1, s2, len);
#elif defined(__SSE4_1__)
    return SCMemcmpSSE41(s1, s2, len);
#elif defined(__SSE3__)
    return SCMemcmpSSE3(s1, s2, len);
#else
    return memcmp(s1, s2, len) == 0 ? 0 : 1;
#endif
}

static inline int SCMemcmpLowercaseLT32(const void *s1, const void *s2, size_t len)
{
    if (len < 16) {
        return MemcmpLowercase(s1, s2, len);
    }
#if defined(__SSE4_2__)
    return SCMemcmpLowercaseSSE42(s1, s2, len);
#elif defined(__SSE4_1__)
    return SCMemcmpLowercaseSSE41(s1, s2, len);
#elif defined(__SSE3__)
    return SCMemcmpLowercaseSSE3(s1, s2, len);
#else
    return MemcmpLowercase(s1, s2, len);
#endif
}

static inline int SCMemcmpLowercaseLT64(const void *s1, const void *s2, size_t len)
{
    if (len < 32) {
        return SCMemcmpLowercaseLT32(s1, s2, len);
    }
#if defined(__AVX512VL__) && defined(__AVX512BW__)
    return SCMemcmpLowercaseAVX512_256(s1, s2, len);
#elif defined(__AVX2__)
    return SCMemcmpLowercaseAVX2(s1, s2, len);
#elif defined(__SSE4_2__)
    return SCMemcmpLowercaseSSE42(s1, s2, len);
#elif defined(__SSE4_1__)
    return SCMemcmpLowercaseSSE41(s1, s2, len);
#elif defined(__SSE3__)
    return SCMemcmpLowercaseSSE3(s1, s2, len);
#else
    return MemcmpLowercase(s1, s2, len);
#endif
}

static inline int SCMemcmpLowercase(const void *s1, const void *s2, size_t len)
{
#if defined(__AVX512VL__) && defined(__AVX512BW__)
    if (len < 64) {
        return SCMemcmpLowercaseLT64(s1, s2, len);
    }
    return SCMemcmpLowercaseAVX512_512(s1, s2, len);
#elif defined(__AVX2__)
    if (len < 32) {
        return SCMemcmpLowercaseLT32(s1, s2, len);
    }
    return SCMemcmpLowercaseAVX2(s1, s2, len);
#elif defined(__SSE4_2__)
    return SCMemcmpLowercaseSSE42(s1, s2, len);
#elif defined(__SSE4_1__)
    return SCMemcmpLowercaseSSE41(s1, s2, len);
#elif defined(__SSE3__)
    return SCMemcmpLowercaseSSE3(s1, s2, len);
#else
    return MemcmpLowercase(s1, s2, len);
#endif
}

static inline int SCBufferCmp(const void *s1, size_t len1, const void *s2, size_t len2)
{
    if (len1 == len2) {
        return SCMemcmp(s1, s2, len1);
    } else if (len1 < len2) {
        return -1;
    }
    return 1;
}

#ifdef UNITTESTS
void MemcmpRegisterTests(void);
#endif
#endif /* SURICATA_UTIL_MEMCMP_H */
