/* Copyright (C) 2013-2014 Open Information Security Foundation
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
 * \author Ken Steele <suricata@tilera.com>

 * Included by util-mpm-ac-ks.c with different SLOAD, SINDEX and
 * FUNC_NAME
 *
 */

/* Only included into util-mpm-ac-ks.c, which defines FUNC_NAME
 *
 */
#ifdef FUNC_NAME

/* This function handles (ctx->state_count < 32767) */
uint32_t FUNC_NAME(const SCACTileSearchCtx *ctx, MpmThreadCtx *mpm_thread_ctx,
                   PrefilterRuleStore *pmq, const uint8_t *buf, uint32_t buflen)
{
    uint32_t i = 0;
    int matches = 0;

    uint8_t mpm_bitarray[ctx->mpm_bitarray_size];
    memset(mpm_bitarray, 0, ctx->mpm_bitarray_size);

    const uint8_t* restrict xlate = ctx->translate_table;
    STYPE *state_table = (STYPE*)ctx->state_table;
    STYPE state = 0;
    int c = xlate[buf[0]];
    /* If buflen at least 4 bytes and buf 4-byte aligned. */
    if (buflen >= (4 + EXTRA) && ((uintptr_t)buf & 0x3) == 0) {
        BUF_TYPE data = *(BUF_TYPE* restrict)(&buf[0]);
        uint64_t index = 0;
        /* Process 4*floor(buflen/4) bytes. */
        i = 0;
        while ((i + EXTRA) < (buflen & ~0x3)) {
            BUF_TYPE data1 = *(BUF_TYPE* restrict)(&buf[i + 4]);
            index = SINDEX(index, state);
            state = SLOAD(state_table + index + c);
            c = xlate[BYTE1(data)];
            if (unlikely(SCHECK(state))) {
                matches = CheckMatch(ctx, pmq, buf, buflen, state, i, matches, mpm_bitarray);
            }
            i++;
            index = SINDEX(index, state);
            state = SLOAD(state_table + index + c);
            c = xlate[BYTE2(data)];
            if (unlikely(SCHECK(state))) {
                matches = CheckMatch(ctx, pmq, buf, buflen, state, i, matches, mpm_bitarray);
            }
            i++;
            index = SINDEX(index, state);
            state = SLOAD(state_table + index + c);
            c = xlate[BYTE3(data)];
            if (unlikely(SCHECK(state))) {
                matches = CheckMatch(ctx, pmq, buf, buflen, state, i, matches, mpm_bitarray);
            }
            data = data1;
            i++;
            index = SINDEX(index, state);
            state = SLOAD(state_table + index + c);
            c = xlate[BYTE0(data)];
            if (unlikely(SCHECK(state))) {
                matches = CheckMatch(ctx, pmq, buf, buflen, state, i, matches, mpm_bitarray);
            }
            i++;
        }
    }
    /* Process buflen % 4 bytes. */
    for (; i < buflen; i++) {
        size_t index = 0 ;
        index = SINDEX(index, state);
        state = SLOAD(state_table + index + c);
        if (likely(i+1 < buflen))
            c = xlate[buf[i+1]];
        if (unlikely(SCHECK(state))) {
            matches = CheckMatch(ctx, pmq, buf, buflen, state, i, matches, mpm_bitarray);
        }
    } /* for (i = 0; i < buflen; i++) */

    return matches;
}

#endif /* FUNC_NAME */
