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
 */

#ifndef __UTIL_MPM_WUMANBER_H__
#define __UTIL_MPM_WUMANBER_H__

#include "util-mpm.h"
#include "util-bloomfilter.h"

//#define WUMANBER_COUNTERS

typedef struct WmPattern_ {
    uint8_t *cs; /* case sensitive */
    uint8_t *ci; /* case INsensitive */
    uint16_t len;
    struct WmPattern_ *next;
    uint16_t prefix_ci;
    uint16_t prefix_cs;
    uint8_t flags;
    uint32_t id; /* global pattern id */

    /* sid(s) for this pattern */
    uint32_t sids_size;
    SigIntId *sids;

} WmPattern;

typedef struct WmHashItem_ {
    uint8_t flags;
    uint16_t idx;
    struct WmHashItem_ *nxt;
} WmHashItem;

typedef struct WmCtx_ {
    /* hash used during ctx initialization */
    WmPattern **init_hash;

    uint16_t shiftlen;

    uint32_t hash_size;
    WmHashItem **hash;
    BloomFilter **bloom;
    uint8_t *pminlen; /* array containing the minimal length
                               of the patters in a hash bucket. Used
                               for the BloomFilter. */
    WmHashItem hash1[256];

    /* we store our own search func ptr here for WmSearch1 */
    uint32_t (*Search)(struct MpmCtx_ *, struct MpmThreadCtx_ *, PatternMatcherQueue *, uint8_t *, uint16_t);
    /* we store our own multi byte search func ptr here for WmSearch1 */
    uint32_t (*MBSearch)(struct MpmCtx_ *, struct MpmThreadCtx_ *, PatternMatcherQueue *, uint8_t *, uint16_t);

    /* pattern arrays */
    WmPattern **parray;

    /* only used for multibyte pattern search */
    uint16_t *shifttable;
} WmCtx;

typedef struct WmThreadCtx_ {
#ifdef WUMANBER_COUNTERS
    uint32_t stat_pminlen_calls;
    uint32_t stat_pminlen_total;
    uint32_t stat_bloom_calls;
    uint32_t stat_bloom_hits;
    uint32_t stat_shift_null;
    uint32_t stat_loop_match;
    uint32_t stat_loop_no_match;
    uint32_t stat_num_shift;
    uint32_t stat_total_shift;
#endif /* WUMANBER_COUNTERS */
} WmThreadCtx;

void MpmWuManberRegister(void);

#endif /* __UTIL_MPM_WUMANBER_H__ */

