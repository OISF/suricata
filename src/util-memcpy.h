/* Copyright (C) 2014-2024 Open Information Security Foundation
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

#ifndef SURICATA_UTIL_MEMCPY_H
#define SURICATA_UTIL_MEMCPY_H

#include "suricata-common.h"
static inline void MemcpyToLower(uint8_t *d, const uint8_t *s, size_t len);

#if defined(__AVX512VL__) && defined(__AVX512BW__)
#include <immintrin.h>
#define TOLOWER_BYTES 64
static inline void MemcpyToLowerLT64(uint8_t *d, const uint8_t *s, size_t n);

static inline void MemcpyToLowerAVX512(uint8_t *dst, const uint8_t *src, size_t n)
{
    size_t offset = 0;
    __m512i upper1 = _mm512_load_si512((const __m512i *)scmemcmp_upper_low64);
    __m512i upper2 = _mm512_load_si512((const __m512i *)scmemcmp_upper_hi64);

    do {
        const size_t len = n - offset;
        if (likely(len < TOLOWER_BYTES)) {
            return MemcpyToLowerLT64(dst + offset, src + offset, len);
        }

        /* unaligned loading of the bytes to compare */
        __m512i b = _mm512_loadu_si512((const __m512i *)(src + offset));

        /* mark all chars bigger than upper1 */
        uint64_t m1 = _mm512_cmp_epi8_mask(upper1, b, _MM_CMPINT_LT);
        /* mark all chars lower than upper2 */
        uint64_t m2 = _mm512_cmp_epi8_mask(b, upper2, _MM_CMPINT_LT);
        /* merge the two, leaving only those that are true in both */
        uint64_t m3 = m1 & m2;
        __m512i uplow = _mm512_mask_loadu_epi8(
                _mm512_setzero_si512(), m3, (const __m512i *)scmemcmp_space64);
        /* add to b2, converting uppercase to lowercase */
        b = _mm512_add_epi8(b, uplow);
        /* store back into the buffer */
        _mm512_storeu_si512((__m512i *)(dst + offset), b);

        offset += TOLOWER_BYTES;
    } while (offset < n);
}

#if defined(__AVX2__)
static inline void MemcmpyToLowerAVX2(uint8_t *dst, const uint8_t *src, size_t n);
#endif
#if defined(__SSE4_2__)
static inline void MemcpyToLowerSSE42(uint8_t *dst, const uint8_t *src, size_t n);
#endif

static inline void MemcpyToLowerLT64(uint8_t *d, const uint8_t *s, size_t n)
{
#if defined(__AVX2__)
    if (n >= 32) {
        return MemcmpyToLowerAVX2(d, s, n);
    }
#endif
#if defined(__SSE4_2__)
    if (n >= 16) {
        return MemcpyToLowerSSE42(d, s, n);
    }
#endif
    for (size_t i = 0; i < n; i++)
        d[i] = u8_tolower(s[i]);
}
#undef TOLOWER_BYTES
#endif

#if defined(__AVX2__)
#include <immintrin.h>
#define TOLOWER_BYTES 32

static inline void MemcmpyToLowerAVX2(uint8_t *dst, const uint8_t *src, size_t n)
{
    size_t offset = 0;
    __m256i upper1 = _mm256_load_si256((const __m256i *)scmemcmp_upper_low32);
    __m256i upper2 = _mm256_load_si256((const __m256i *)scmemcmp_upper_hi32);
    __m256i uplow = _mm256_load_si256((const __m256i *)scmemcmp_space32);

    do {
        const size_t len = n - offset;
        if (likely(len < TOLOWER_BYTES)) {
            return MemcpyToLower(dst + offset, src + offset, len);
        }

        /* unaligned loading of the bytes to compare */
        __m256i b = _mm256_lddqu_si256((const __m256i *)(src + offset));

        /* mark all chars bigger than upper1 */
        __m256i mask1 = _mm256_cmpgt_epi8(b, upper1);
        /* mark all chars lower than upper2 */
        __m256i mask2 = _mm256_cmpgt_epi8(upper2, b);
        /* merge the two, leaving only those that are true in both */
        mask1 = _mm256_cmpeq_epi8(mask1, mask2);
        /* Next we use that mask to create a new: this one has 0x20 for
         * the uppercase chars, 00 for all other. */
        mask1 = _mm256_and_si256(uplow, mask1);

        /* add to b2, converting uppercase to lowercase */
        b = _mm256_add_epi8(b, mask1);

        _mm256_storeu_si256((__m256i *)(dst + offset), b);

        offset += TOLOWER_BYTES;
    } while (offset < n);
}
#undef TOLOWER_BYTES
#endif

#if defined(__SSE4_2__)
#include <nmmintrin.h>
#define TOLOWER_BYTES 16

static inline void MemcpyToLowerSSE42(uint8_t *dst, const uint8_t *src, size_t n)
{
    size_t offset = 0;
    __m128i ucase = _mm_load_si128((const __m128i *)scmemcmp_uppercase);
    __m128i uplow = _mm_set1_epi8(0x20);

    do {
        const size_t len = n - offset;
        if (likely(len < TOLOWER_BYTES)) {
            return MemcpyToLower(dst + offset, src + offset, len);
        }

        __m128i b = _mm_loadu_si128((const __m128i *)(src + offset));
        /* The first step is creating a mask that is FF for all uppercase
         * characters, 00 for all others */
        __m128i mask = _mm_cmpestrm(ucase, 2, b, len, _SIDD_CMP_RANGES | _SIDD_UNIT_MASK);
        /* Next we use that mask to create a new: this one has 0x20 for
         * the uppercase chars, 00 for all other. */
        mask = _mm_and_si128(uplow, mask);
        /* merge the mask and the buffer converting the
         * uppercase to lowercase */
        b = _mm_add_epi8(b, mask);
        /* store the result back in the buffer */
        _mm_storeu_si128((__m128i *)(dst + offset), b);

        offset += TOLOWER_BYTES;
    } while (offset < n);
}
#endif /* SSE 4.2 */

/**
 * \internal
 * \brief Does a memcpy of the input string to lowercase.
 *
 * \param d   Pointer to the target area for memcpy.
 * \param s   Pointer to the src string for memcpy.
 * \param len len of the string sent in s.
 */
static inline void MemcpyToLower(uint8_t *d, const uint8_t *s, size_t n)
{
#if defined(__AVX512VL__) && defined(__AVX512BW__)
    if (n >= 64) {
        return MemcpyToLowerAVX512(d, s, n);
    }
#endif
#if defined(__AVX2__)
    if (n >= 32) {
        return MemcmpyToLowerAVX2(d, s, n);
    }
#endif
#if defined(__SSE4_2__)
    if (n >= 16) {
        return MemcpyToLowerSSE42(d, s, n);
    }
#endif
    for (size_t i = 0; i < n; i++)
        d[i] = u8_tolower(s[i]);
}

#endif /* SURICATA_UTIL_MEMCPY_H */
