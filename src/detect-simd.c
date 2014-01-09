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

#if defined(__SSE3__)

/**
 *  \brief SIMD implementation of mask prefiltering.
 *
 *  Mass mask matching is done creating a bitmap of signatures that need
 *  futher inspection.
 *
 *  On 32 bit systems we inspect in 32 sig batches, creating a u32 with flags.
 *  On 64 bit systems we inspect in 64 sig batches, creating a u64 with flags.
 *  The size of a register is leading here.
 */
void SigMatchSignaturesBuildMatchArray(DetectEngineThreadCtx *det_ctx,
                                       Packet *p, SignatureMask mask, AppProto alproto)
{
    uint32_t u;
    SigIntId x;
    int bitno = 0;
#if __WORDSIZE == 32
    register uint32_t bm; /* bit mask, 32 bits used */

    Vector pm, sm, r1, r2;
    /* load the packet mask into each byte of the vector */
    pm.v = _mm_set1_epi8(mask);

    /* reset previous run */
    det_ctx->match_array_cnt = 0;

    for (u = 0; u < det_ctx->sgh->sig_cnt; u += 32) {
        /* load a batch of masks */
        sm.v = _mm_load_si128((const __m128i *)&det_ctx->sgh->mask_array[u]);
        /* logical AND them with the packet's mask */
        r1.v = _mm_and_si128(pm.v, sm.v);
        /* compare the result with the original mask */
        r2.v = _mm_cmpeq_epi8(sm.v, r1.v);
        /* convert into a bitarray */
        bm = ((uint32_t) _mm_movemask_epi8(r2.v));

        SCLogDebug("bm1 %08x", bm);

        /* load a batch of masks */
        sm.v = _mm_load_si128((const __m128i *)&det_ctx->sgh->mask_array[u+16]);
        /* logical AND them with the packet's mask */
        r1.v = _mm_and_si128(pm.v, sm.v);
        /* compare the result with the original mask */
        r2.v = _mm_cmpeq_epi8(sm.v, r1.v);
        /* convert into a bitarray */
        bm |= ((uint32_t) _mm_movemask_epi8(r2.v) << 16);

        SCLogDebug("bm2 %08x", bm);

        if (bm == 0) {
            continue;
        }

        /* Check each bit in the bit map. Little endian is assumed (SSE is x86),
         * so the bits are in memory backwards, 0 is on the right edge,
         * 31 on the left edge. This is why above we store the output of the
         * _mm_movemask_epi8 in this order as well */
        bitno = 0;
        for (x = u; x < det_ctx->sgh->sig_cnt && bitno < 32; x++, bitno++) {
            if (bm & (1 << bitno)) {
                SignatureHeader *s = &det_ctx->sgh->head_array[x];

                if (SigMatchSignaturesBuildMatchArrayAddSignature(det_ctx, p, s, alproto) == 1) {
                    /* okay, store it */
                    det_ctx->match_array[det_ctx->match_array_cnt] = s->full_sig;
                    det_ctx->match_array_cnt++;
                }
            }
        }
    }
#elif __WORDSIZE == 64
    register uint64_t bm; /* bit mask, 64 bits used */

    Vector pm, sm, r1, r2;
    /* load the packet mask into each byte of the vector */
    pm.v = _mm_set1_epi8(mask);

    /* reset previous run */
    det_ctx->match_array_cnt = 0;

    for (u = 0; u < det_ctx->sgh->sig_cnt; u += 64) {
        /* load a batch of masks */
        sm.v = _mm_load_si128((const __m128i *)&det_ctx->sgh->mask_array[u]);
        /* logical AND them with the packet's mask */
        r1.v = _mm_and_si128(pm.v, sm.v);
        /* compare the result with the original mask */
        r2.v = _mm_cmpeq_epi8(sm.v, r1.v);
        /* convert into a bitarray */
        bm = ((uint64_t) _mm_movemask_epi8(r2.v));

        SCLogDebug("bm1 %08"PRIx64, bm);

        /* load a batch of masks */
        sm.v = _mm_load_si128((const __m128i *)&det_ctx->sgh->mask_array[u+16]);
        /* logical AND them with the packet's mask */
        r1.v = _mm_and_si128(pm.v, sm.v);
        /* compare the result with the original mask */
        r2.v = _mm_cmpeq_epi8(sm.v, r1.v);
        /* convert into a bitarray */
        bm |= ((uint64_t) _mm_movemask_epi8(r2.v)) << 16;

        /* load a batch of masks */
        sm.v = _mm_load_si128((const __m128i *)&det_ctx->sgh->mask_array[u+32]);
        /* logical AND them with the packet's mask */
        r1.v = _mm_and_si128(pm.v, sm.v);
        /* compare the result with the original mask */
        r2.v = _mm_cmpeq_epi8(sm.v, r1.v);
        /* convert into a bitarray */
        bm |= ((uint64_t) _mm_movemask_epi8(r2.v)) << 32;

        /* load a batch of masks */
        sm.v = _mm_load_si128((const __m128i *)&det_ctx->sgh->mask_array[u+48]);
        /* logical AND them with the packet's mask */
        r1.v = _mm_and_si128(pm.v, sm.v);
        /* compare the result with the original mask */
        r2.v = _mm_cmpeq_epi8(sm.v, r1.v);
        /* convert into a bitarray */
        bm |= ((uint64_t) _mm_movemask_epi8(r2.v)) << 48;

        SCLogDebug("bm2 %08"PRIx64, bm);

        if (bm == 0) {
            continue;
        }

        /* Check each bit in the bit map. Little endian is assumed (SSE is x86-64),
         * so the bits are in memory backwards, 0 is on the right edge,
         * 63 on the left edge. This is why above we store the output of the
         * _mm_movemask_epi8 in this order as well */
        bitno = 0;
        for (x = u; x < det_ctx->sgh->sig_cnt && bitno < 64; x++, bitno++) {
            if (bm & ((uint64_t)1 << bitno)) {
                SignatureHeader *s = &det_ctx->sgh->head_array[x];

                if (SigMatchSignaturesBuildMatchArrayAddSignature(det_ctx, p, s, alproto) == 1) {
                    /* okay, store it */
                    det_ctx->match_array[det_ctx->match_array_cnt] = s->full_sig;
                    det_ctx->match_array_cnt++;
                }
            }
        }
    }
#else
#error Wordsize (__WORDSIZE) neither 32 or 64.
#endif
}
 /* end defined(__SSE3__) */
#elif defined(__tile__)

/**
 *  \brief SIMD implementation of mask prefiltering for TILE-Gx
 *
 *  Mass mask matching is done creating a bitmap of signatures that need
 *  futher inspection.
 */
void SigMatchSignaturesBuildMatchArray(DetectEngineThreadCtx *det_ctx,
                                       Packet *p, SignatureMask mask, AppProto alproto)
{
    uint32_t u;
    register uint64_t bm; /* bit mask, 64 bits used */

    /* Keep local copies of variables that don't change during this function. */
    uint64_t *mask_vector = (uint64_t*)det_ctx->sgh->mask_array;
    uint32_t sig_cnt = det_ctx->sgh->sig_cnt;
    SignatureHeader *head_array = det_ctx->sgh->head_array;

    Signature **match_array = det_ctx->match_array;
    uint32_t match_count = 0;

    /* Replicate the packet mask into each byte of the vector. */
    uint64_t pm = __insn_shufflebytes(mask, 0, 0);

    /* u is the signature index. */
    for (u = 0; u < sig_cnt; u += 8) {
        /* Load 8 masks */
        uint64_t sm = *mask_vector++;
        /* Binary AND 8 masks with the packet's mask */
        uint64_t r1 = pm & sm;
        /* Compare the result with the original mask
         * Result if equal puts a 1 in LSB of bytes that match.
         */
        bm = __insn_v1cmpeq(sm, r1);

        /* Check the LSB bit of each byte in the bit map. Little endian is assumed,
         * so the LSB byte is index 0. Uses count trailing zeros to find least
         * significant bit that is set. */
        while (bm) {
            /* Find first bit set starting from LSB. */
            unsigned int first_bit = __insn_ctz(bm);
            unsigned int first_byte = first_bit >> 3;
            unsigned int x = u + first_byte;
            if (x >= sig_cnt)
                break;
            SignatureHeader *s = &head_array[x];

            /* Clear the first bit set, so it is not found again. */
            bm -= (1UL << first_bit);

            if (SigMatchSignaturesBuildMatchArrayAddSignature(det_ctx, p, s, alproto) == 1) {
                /* okay, store it */
                *match_array++ = s->full_sig;
                match_count++;
            }
        }
    }
    det_ctx->match_array_cnt = match_count;
}
#endif /* defined(__tile__) */


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
