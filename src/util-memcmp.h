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
 * \author Victor Julien <victor@inliniac.net>
 *
 * Memcmp implementations.
 */

#ifndef __UTIL_MEMCMP_H__
#define __UTIL_MEMCMP_H__

void MemcmpRegisterTests(void);

#if defined(__SSE3__)

#include <pmmintrin.h> /* for SSE3 */

#define SCMEMCMP_BYTES  16

static inline int SCMemcmp(void *, void *, size_t);
static inline int SCMemcmpLowercase(void *, void *, size_t);

static inline int SCMemcmp(void *s1, void *s2, size_t len) {
    size_t offset = 0;
    __m128i b1, b2, c;

    do {
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

static inline int SCMemcmpLowercase(void *s1, void *s2, size_t len) {
    size_t offset = 0;
    __m128i b1, b2, mask1, mask2, upper1, upper2, delta;

    /* setup registers for upper to lower conversion */
    upper1 = _mm_set1_epi8(UPPER_LOW);
    upper2 = _mm_set1_epi8(UPPER_HIGH);
    delta  = _mm_set1_epi8(UPPER_DELTA);

    do {
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

/* No SIMD support */

#define SCMemcmp memcmp

static inline int
SCMemcmpLowercase(void *s1, void *s2, size_t n) {
    size_t i;

    /* check backwards because we already tested the first
     * 2 to 4 chars. This way we are more likely to detect
     * a miss and thus speed up a little... */
    for (i = n - 1; i; i--) {
        if (((uint8_t *)s1)[i] != u8_tolower(*(((uint8_t *)s2)+i)))
            return 1;
    }

    return 0;
}

#endif /* __SSE3__ */

#endif /* __UTIL_MEMCMP_H__ */

