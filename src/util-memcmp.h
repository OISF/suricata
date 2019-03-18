/* Copyright (C) 2007-2013 Open Information Security Foundation
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
 * Memcmp implementations for SSE3, SSE4.1, SSE4.2 and TILE-Gx SIMD.
 *
 * Both SCMemcmp and SCMemcmpLowercase return 0 on a exact match,
 * 1 on a failed match.
 */

#ifndef __UTIL_MEMCMP_H__
#define __UTIL_MEMCMP_H__

#include "util-optimize.h"

/** \brief compare two patterns, converting the 2nd to lowercase
 *  \warning *ONLY* the 2nd pattern is converted to lowercase
 */
static inline int SCMemcmpLowercase(const void *, const void *, size_t);

void MemcmpRegisterTests(void);

static inline int
MemcmpLowercase(const void *s1, const void *s2, size_t n)
{
    ssize_t i;

    /* check backwards because we already tested the first
     * 2 to 4 chars. This way we are more likely to detect
     * a miss and thus speed up a little... */
    for (i = n - 1; i >= 0; i--) {
        if (((uint8_t *)s1)[i] != u8_tolower(*(((uint8_t *)s2)+i)))
            return 1;
    }

    return 0;
}

#if defined(__SSE4_2__)

#include <nmmintrin.h>

/* No SIMD support, fall back to plain memcmp and a home grown lowercase one */

static inline int SCMemcmp(const void *s1, const void *s2, size_t n)
{
    __m128i b1, b2;

    int r;
    /* counter for how far we already matched in the buffer */
    size_t m = 0;

    do {
        /* apparently we can't just read 16 bytes even though
         * it almost always works fine :) */
        if (likely(n - m < 16)) {
            return memcmp(s1, s2, n - m) ? 1 : 0;
        }

        /* load the buffers into the 128bit vars */
        b1 = _mm_loadu_si128((const __m128i *) s1);
        b2 = _mm_loadu_si128((const __m128i *) s2);

        /* do the actual compare */
        m += (r = _mm_cmpestri(b1, n - m, b2, 16,
                    _SIDD_CMP_EQUAL_EACH | _SIDD_MASKED_NEGATIVE_POLARITY));

        s1 += 16;
        s2 += 16;
    } while (r == 16);

    return ((m == n) ? 0 : 1);
}

/* Range of values of uppercase characters. We only use the first 2 bytes. */
static char scmemcmp_uppercase[16] __attribute__((aligned(16))) = {
    'A', 'Z', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, };

/** \brief compare two buffers in a case insensitive way
 *  \param s1 buffer already in lowercase
 *  \param s2 buffer with mixed upper and lowercase
 */
static inline int SCMemcmpLowercase(const void *s1, const void *s2, size_t n)
{
    __m128i b1, b2, mask;

    int r;
    /* counter for how far we already matched in the buffer */
    size_t m = 0;

    __m128i ucase = _mm_load_si128((const __m128i *) scmemcmp_uppercase);
    __m128i nulls = _mm_setzero_si128();
    __m128i uplow = _mm_set1_epi8(0x20);

    do {
        /* apparently we can't just read 16 bytes even though
         * it almost always works fine :) */
        if (likely(n - m < 16)) {
            return MemcmpLowercase(s1, s2, n - m);
        }

        b1 = _mm_loadu_si128((const __m128i *) s1);
        b2 = _mm_loadu_si128((const __m128i *) s2);
        size_t len = n - m;

        /* The first step is creating a mask that is FF for all uppercase
         * characters, 00 for all others */
        mask = _mm_cmpestrm(ucase, 2, b2, len, _SIDD_CMP_RANGES | _SIDD_UNIT_MASK);
        /* Next we use that mask to create a new: this one has 0x20 for
         * the uppercase chars, 00 for all other. */
        mask = _mm_blendv_epi8(nulls, uplow, mask);
        /* finally, merge the mask and the buffer converting the
         * uppercase to lowercase */
        b2 = _mm_add_epi8(b2, mask);

        /* search using our converted buffer */
        m += (r = _mm_cmpestri(b1, len, b2, 16,
                    _SIDD_CMP_EQUAL_EACH | _SIDD_MASKED_NEGATIVE_POLARITY));

        s1 += 16;
        s2 += 16;
    } while (r == 16);

    return ((m == n) ? 0 : 1);
}

#elif defined(__SSE4_1__)

#include <smmintrin.h>

#define SCMEMCMP_BYTES  16

static inline int SCMemcmp(const void *s1, const void *s2, size_t len)
{
    size_t offset = 0;
    __m128i b1, b2, c;

    do {
        /* apparently we can't just read 16 bytes even though
         * it almost always works fine :) */
        if (likely(len - offset < 16)) {
            return memcmp(s1, s2, len - offset) ? 1 : 0;
        }

        /* do unaligned loads using _mm_loadu_si128. On my Core2 E6600 using
         * _mm_lddqu_si128 was about 2% slower even though it's supposed to
         * be faster. */
        b1 = _mm_loadu_si128((const __m128i *) s1);
        b2 = _mm_loadu_si128((const __m128i *) s2);
        c = _mm_cmpeq_epi8(b1, b2);

        int diff = len - offset;
        if (diff < 16) {
            int rmask = ~(0xFFFFFFFF << diff);

            if ((_mm_movemask_epi8(c) & rmask) != rmask) {
                return 1;
            }
        } else {
            if (_mm_movemask_epi8(c) != 0x0000FFFF) {
                return 1;
            }
        }

        offset += SCMEMCMP_BYTES;
        s1 += SCMEMCMP_BYTES;
        s2 += SCMEMCMP_BYTES;
    } while (len > offset);

    return 0;
}

#define UPPER_LOW   0x40 /* "A" - 1 */
#define UPPER_HIGH  0x5B /* "Z" + 1 */

static inline int SCMemcmpLowercase(const void *s1, const void *s2, size_t len)
{
    size_t offset = 0;
    __m128i b1, b2, mask1, mask2, upper1, upper2, nulls, uplow;

    /* setup registers for upper to lower conversion */
    upper1 = _mm_set1_epi8(UPPER_LOW);
    upper2 = _mm_set1_epi8(UPPER_HIGH);
    nulls = _mm_setzero_si128();
    uplow = _mm_set1_epi8(0x20);

    do {
        /* apparently we can't just read 16 bytes even though
         * it almost always works fine :) */
        if (likely(len - offset < 16)) {
            return MemcmpLowercase(s1, s2, len - offset);
        }

        /* unaligned loading of the bytes to compare */
        b1 = _mm_loadu_si128((const __m128i *) s1);
        b2 = _mm_loadu_si128((const __m128i *) s2);

        /* mark all chars bigger than upper1 */
        mask1 = _mm_cmpgt_epi8(b2, upper1);
        /* mark all chars lower than upper2 */
        mask2 = _mm_cmplt_epi8(b2, upper2);
        /* merge the two, leaving only those that are true in both */
        mask1 = _mm_cmpeq_epi8(mask1, mask2);
        /* Next we use that mask to create a new: this one has 0x20 for
         * the uppercase chars, 00 for all other. */
        mask1 = _mm_blendv_epi8(nulls, uplow, mask1);

        /* add to b2, converting uppercase to lowercase */
        b2 = _mm_add_epi8(b2, mask1);

        /* now all is lowercase, let's do the actual compare (reuse mask1 reg) */
        mask1 = _mm_cmpeq_epi8(b1, b2);

        int diff = len - offset;
        if (diff < 16) {
            int rmask = ~(0xFFFFFFFF << diff);

            if ((_mm_movemask_epi8(mask1) & rmask) != rmask) {
                return 1;
            }
        } else {
            if (_mm_movemask_epi8(mask1) != 0x0000FFFF) {
                return 1;
            }
        }

        offset += SCMEMCMP_BYTES;
        s1 += SCMEMCMP_BYTES;
        s2 += SCMEMCMP_BYTES;
    } while (len > offset);

    return 0;
}



#elif defined(__SSE3__)

#include <pmmintrin.h> /* for SSE3 */

#define SCMEMCMP_BYTES  16

static inline int SCMemcmp(const void *s1, const void *s2, size_t len)
{
    size_t offset = 0;
    __m128i b1, b2, c;

    do {
        /* apparently we can't just read 16 bytes even though
         * it almost always works fine :) */
        if (likely(len - offset < 16)) {
            return memcmp(s1, s2, len - offset) ? 1 : 0;
        }

        /* do unaligned loads using _mm_loadu_si128. On my Core2 E6600 using
         * _mm_lddqu_si128 was about 2% slower even though it's supposed to
         * be faster. */
        b1 = _mm_loadu_si128((const __m128i *) s1);
        b2 = _mm_loadu_si128((const __m128i *) s2);
        c = _mm_cmpeq_epi8(b1, b2);

        int diff = len - offset;
        if (diff < 16) {
            int rmask = ~(0xFFFFFFFF << diff);

            if ((_mm_movemask_epi8(c) & rmask) != rmask) {
                return 1;
            }
        } else {
            if (_mm_movemask_epi8(c) != 0x0000FFFF) {
                return 1;
            }
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

static inline int SCMemcmpLowercase(const void *s1, const void *s2, size_t len)
{
    size_t offset = 0;
    __m128i b1, b2, mask1, mask2, upper1, upper2, delta;

    /* setup registers for upper to lower conversion */
    upper1 = _mm_set1_epi8(UPPER_LOW);
    upper2 = _mm_set1_epi8(UPPER_HIGH);
    delta  = _mm_set1_epi8(UPPER_DELTA);

    do {
        /* apparently we can't just read 16 bytes even though
         * it almost always works fine :) */
        if (likely(len - offset < 16)) {
            return MemcmpLowercase(s1, s2, len - offset);
        }

        /* unaligned loading of the bytes to compare */
        b1 = _mm_loadu_si128((const __m128i *) s1);
        b2 = _mm_loadu_si128((const __m128i *) s2);

        /* mark all chars bigger than upper1 */
        mask1 = _mm_cmpgt_epi8(b2, upper1);
        /* mark all chars lower than upper2 */
        mask2 = _mm_cmplt_epi8(b2, upper2);
        /* merge the two, leaving only those that are true in both */
        mask1 = _mm_cmpeq_epi8(mask1, mask2);

        /* sub delta leaves 0x20 only for uppercase positions, the
           rest is 0x00 due to the saturation (reuse mask1 reg)*/
        mask1 = _mm_subs_epu8(mask1, delta);

        /* add to b2, converting uppercase to lowercase */
        b2 = _mm_add_epi8(b2, mask1);

        /* now all is lowercase, let's do the actual compare (reuse mask1 reg) */
        mask1 = _mm_cmpeq_epi8(b1, b2);

        int diff = len - offset;
        if (diff < 16) {
            int rmask = ~(0xFFFFFFFF << diff);

            if ((_mm_movemask_epi8(mask1) & rmask) != rmask) {
                return 1;
            }
        } else {
            if (_mm_movemask_epi8(mask1) != 0x0000FFFF) {
                return 1;
            }
        }

        offset += SCMEMCMP_BYTES;
        s1 += SCMEMCMP_BYTES;
        s2 += SCMEMCMP_BYTES;
    } while (len > offset);

    return 0;
}

#else

/* No SIMD support, fall back to plain memcmp and a home grown lowercase one */

/* wrapper around memcmp to match the retvals of the SIMD implementations */
#define SCMemcmp(a,b,c) ({ \
    memcmp((a), (b), (c)) ? 1 : 0; \
})

static inline int SCMemcmpLowercase(const void *s1, const void *s2, size_t len)
{
    return MemcmpLowercase(s1, s2, len);
}

#endif /* SIMD */

#endif /* __UTIL_MEMCMP_H__ */

