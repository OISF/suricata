/* Copyright (C) 2013 Open Information Security Foundation
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
 * Basic detection engine
 */

#include "suricata-common.h"
#include "detect.h"

#include "util-unittest.h"
#include "util-unittest-helper.h"
#include "util-vector.h"

/* Included into detect.c */



#ifdef UNITTESTS
#include "flow-util.h"
#include "stream-tcp-reassemble.h"
#include "util-var-name.h"

///   SCLogInfo("%s %u %u %u %u", #v, (v).dw[0], (v).dw[1], (v).dw[2], (v).dw[3]);
#define VECTOR_SCLogInfo(v) { \
   SCLogInfo("%s %08X %08X %08X %08X", #v, (v).dw[0], (v).dw[1], (v).dw[2], (v).dw[3]); \
}

/**
 *  \test Test 32 bit SIMD code.
 */
static int SigTestSIMDMask01(void)
{
#if defined (__SSE3__)
    Vector pm, sm, r1, r2;
    uint32_t bm = 0;

    uint8_t *mask = SCMallocAligned(32, 16);
    memset(mask, 0xEF, 32);
    mask[31] = 0xFF;
    printf("\n");
    pm.v = _mm_set1_epi8(0xEF);
    VECTOR_SCLogInfo(pm);

    /* load a batch of masks */
    sm.v = _mm_load_si128((const __m128i *)&mask[0]);
    VECTOR_SCLogInfo(sm);

    /* logical AND them with the packet's mask */
    r1.v = _mm_and_si128(pm.v, sm.v);
    VECTOR_SCLogInfo(r1);
    /* compare the result with the original mask */
    r2.v = _mm_cmpeq_epi8(sm.v, r1.v);
    VECTOR_SCLogInfo(r2);
    /* convert into a bitarray */
    bm = ((uint32_t) _mm_movemask_epi8(r2.v));

    SCLogInfo("bm %08x", bm);

    /* load a batch of masks */
    sm.v = _mm_load_si128((const __m128i *)&mask[16]);
    VECTOR_SCLogInfo(sm);
    /* logical AND them with the packet's mask */
    r1.v = _mm_and_si128(pm.v, sm.v);
    VECTOR_SCLogInfo(r1);
    /* compare the result with the original mask */
    r2.v = _mm_cmpeq_epi8(sm.v, r1.v);
    VECTOR_SCLogInfo(r2);
    /* convert into a bitarray */
    bm |= ((uint32_t) _mm_movemask_epi8(r2.v)) << 16;

    SCLogInfo("bm %08x", bm);

    int b = 0;
    for ( ; b < 32; b++){
        if (bm & (1 << b)) {
            SCLogInfo("b %02d, set", b);
        } else {
            SCLogInfo("b %02d, not set", b);

        }
    }

    if (!(bm & (1 << 31))) {
        return 1;
    }
    return 0;
#else
    return 1;
#endif
}

/**
 *  \test Test 32 bit SIMD code.
 */
static int SigTestSIMDMask02(void)
{
#if defined (__SSE3__)
    Vector pm, sm, r1, r2;
    uint32_t bm = 0;

    uint8_t *mask = SCMallocAligned(32, 16);
    memset(mask, 0x01, 32);
    mask[31] = 0;
    pm.v = _mm_set1_epi8(0x02);
    VECTOR_SCLogInfo(pm);

    /* load a batch of masks */
    sm.v = _mm_load_si128((const __m128i *)&mask[0]);
    VECTOR_SCLogInfo(sm);

    /* logical AND them with the packet's mask */
    r1.v = _mm_and_si128(pm.v, sm.v);
    VECTOR_SCLogInfo(r1);
    /* compare the result with the original mask */
    r2.v = _mm_cmpeq_epi8(sm.v, r1.v);
    VECTOR_SCLogInfo(r2);
    /* convert into a bitarray */
    bm = ((uint32_t) _mm_movemask_epi8(r2.v));

    SCLogInfo("bm %08x", bm);

    /* load a batch of masks */
    sm.v = _mm_load_si128((const __m128i *)&mask[16]);
    VECTOR_SCLogInfo(sm);
    /* logical AND them with the packet's mask */
    r1.v = _mm_and_si128(pm.v, sm.v);
    VECTOR_SCLogInfo(r1);
    /* compare the result with the original mask */
    r2.v = _mm_cmpeq_epi8(sm.v, r1.v);
    VECTOR_SCLogInfo(r2);
    /* convert into a bitarray */
    bm |= ((uint32_t) _mm_movemask_epi8(r2.v)) << 16;

    SCLogInfo("bm %08x", bm);

    int b = 0;
    for ( ; b < 32; b++){
        if (bm & (1 << b)) {
            SCLogInfo("b %02d, set", b);
        } else {
            SCLogInfo("b %02d, not set", b);

        }
    }

    if (bm & (1 << 31)) {
        return 1;
    }
    return 0;
#else
    return 1;
#endif
}

/**
 *  \test Test 64 bit SIMD code.
 */
static int SigTestSIMDMask03(void)
{
#if defined (__SSE3__)
    Vector pm, sm, r1, r2;
    uint64_t bm = 0;
    uint8_t *mask = SCMallocAligned(64, 16);
    memset(mask, 0xEF, 64);
    mask[31] = 0xFF;
    mask[62] = 0xFF;
    printf("\n");
    pm.v = _mm_set1_epi8(0xEF);
    VECTOR_SCLogInfo(pm);

    /* load a batch of masks */
    sm.v = _mm_load_si128((const __m128i *)&mask[0]);
    VECTOR_SCLogInfo(sm);
    /* logical AND them with the packet's mask */
    r1.v = _mm_and_si128(pm.v, sm.v);
    VECTOR_SCLogInfo(r1);
    /* compare the result with the original mask */
    r2.v = _mm_cmpeq_epi8(sm.v, r1.v);
    VECTOR_SCLogInfo(r2);
    /* convert into a bitarray */
    bm = ((uint64_t) _mm_movemask_epi8(r2.v));

    SCLogInfo("bm1 %"PRIxMAX, (uintmax_t)bm);

    /* load a batch of masks */
    sm.v = _mm_load_si128((const __m128i *)&mask[16]);
    VECTOR_SCLogInfo(sm);
    /* logical AND them with the packet's mask */
    r1.v = _mm_and_si128(pm.v, sm.v);
    VECTOR_SCLogInfo(r1);
    /* compare the result with the original mask */
    r2.v = _mm_cmpeq_epi8(sm.v, r1.v);
    VECTOR_SCLogInfo(r2);
    /* convert into a bitarray */
    bm |= ((uint64_t) _mm_movemask_epi8(r2.v)) << 16;

    SCLogInfo("bm2 %"PRIxMAX, (uintmax_t)bm);

    /* load a batch of masks */
    sm.v = _mm_load_si128((const __m128i *)&mask[32]);
    VECTOR_SCLogInfo(sm);
    /* logical AND them with the packet's mask */
    r1.v = _mm_and_si128(pm.v, sm.v);
    VECTOR_SCLogInfo(r1);
    /* compare the result with the original mask */
    r2.v = _mm_cmpeq_epi8(sm.v, r1.v);
    VECTOR_SCLogInfo(r2);
    /* convert into a bitarray */
    bm |= ((uint64_t) _mm_movemask_epi8(r2.v)) << 32;

    SCLogInfo("bm3 %"PRIxMAX, (uintmax_t)bm);

    /* load a batch of masks */
    sm.v = _mm_load_si128((const __m128i *)&mask[48]);
    VECTOR_SCLogInfo(sm);
    /* logical AND them with the packet's mask */
    r1.v = _mm_and_si128(pm.v, sm.v);
    VECTOR_SCLogInfo(r1);
    /* compare the result with the original mask */
    r2.v = _mm_cmpeq_epi8(sm.v, r1.v);
    VECTOR_SCLogInfo(r2);
    /* convert into a bitarray */
    bm |= ((uint64_t) _mm_movemask_epi8(r2.v)) << 48;

    SCLogInfo("bm4 %"PRIxMAX, (uintmax_t)bm);

    int b = 0;
    for ( ; b < 64; b++){
        if (bm & ((uint64_t)1 << b)) {
            SCLogInfo("b %02d, set", b);
        } else {
            SCLogInfo("b %02d, not set", b);

        }
    }

    if (!(bm & ((uint64_t)1 << 31)) && !(bm & ((uint64_t)1 << 62))) {
        return 1;
    }
    return 0;
#else
    return 1;
#endif
}

/**
 *  \test Test 64 bit SIMD code.
 */
static int SigTestSIMDMask04(void)
{
#if defined (__SSE3__)
    Vector pm, sm, r1, r2;
    uint64_t bm = 0;

    uint8_t *mask = SCMallocAligned(64, 16);
    memset(mask, 0x01, 64);
    mask[31] = 0;
    mask[62] = 0;
    pm.v = _mm_set1_epi8(0x02);
    VECTOR_SCLogInfo(pm);

    /* load a batch of masks */
    sm.v = _mm_load_si128((const __m128i *)&mask[0]);
    VECTOR_SCLogInfo(sm);
    /* logical AND them with the packet's mask */
    r1.v = _mm_and_si128(pm.v, sm.v);
    VECTOR_SCLogInfo(r1);
    /* compare the result with the original mask */
    r2.v = _mm_cmpeq_epi8(sm.v, r1.v);
    VECTOR_SCLogInfo(r2);
    /* convert into a bitarray */
    bm = ((uint64_t) _mm_movemask_epi8(r2.v));

    SCLogInfo("bm1 %"PRIxMAX, (uintmax_t)bm);

    /* load a batch of masks */
    sm.v = _mm_load_si128((const __m128i *)&mask[16]);
    VECTOR_SCLogInfo(sm);
    /* logical AND them with the packet's mask */
    r1.v = _mm_and_si128(pm.v, sm.v);
    VECTOR_SCLogInfo(r1);
    /* compare the result with the original mask */
    r2.v = _mm_cmpeq_epi8(sm.v, r1.v);
    VECTOR_SCLogInfo(r2);
    /* convert into a bitarray */
    bm |= ((uint64_t) _mm_movemask_epi8(r2.v)) << 16;

    SCLogInfo("bm2 %"PRIxMAX, (uintmax_t)bm);

    /* load a batch of masks */
    sm.v = _mm_load_si128((const __m128i *)&mask[32]);
    VECTOR_SCLogInfo(sm);
    /* logical AND them with the packet's mask */
    r1.v = _mm_and_si128(pm.v, sm.v);
    VECTOR_SCLogInfo(r1);
    /* compare the result with the original mask */
    r2.v = _mm_cmpeq_epi8(sm.v, r1.v);
    VECTOR_SCLogInfo(r2);
    /* convert into a bitarray */
    bm |= ((uint64_t) _mm_movemask_epi8(r2.v)) << 32;

    SCLogInfo("bm3 %"PRIxMAX, (uintmax_t)bm);

    /* load a batch of masks */
    sm.v = _mm_load_si128((const __m128i *)&mask[48]);
    VECTOR_SCLogInfo(sm);
    /* logical AND them with the packet's mask */
    r1.v = _mm_and_si128(pm.v, sm.v);
    VECTOR_SCLogInfo(r1);
    /* compare the result with the original mask */
    r2.v = _mm_cmpeq_epi8(sm.v, r1.v);
    VECTOR_SCLogInfo(r2);
    /* convert into a bitarray */
    bm |= (((uint64_t) _mm_movemask_epi8(r2.v)) << 48);

    SCLogInfo("bm4-total %"PRIxMAX, (uintmax_t)bm);

    int b = 0;
    for ( ; b < 64; b++){
        if (bm & ((uint64_t)1 << b)) {
            SCLogInfo("b %02d, set", b);
        } else {
            SCLogInfo("b %02d, not set", b);

        }
    }

    if ((bm & ((uint64_t)1 << 31)) && (bm & ((uint64_t)1 << 62))) {
        return 1;
    }
    return 0;
#else
    return 1;
#endif
}
#endif /* UNITTESTS */

void DetectSimdRegisterTests(void)
{
#ifdef UNITTESTS
    UtRegisterTest("SigTestSIMDMask01", SigTestSIMDMask01, 1);
    UtRegisterTest("SigTestSIMDMask02", SigTestSIMDMask02, 1);
    UtRegisterTest("SigTestSIMDMask03", SigTestSIMDMask03, 1);
    UtRegisterTest("SigTestSIMDMask04", SigTestSIMDMask04, 1);
#endif /* UNITTESTS */
}
