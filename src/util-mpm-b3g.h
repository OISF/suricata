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

#ifndef __UTIL_MPM_B3G_H__
#define __UTIL_MPM_B3G_H__

#include "util-mpm.h"
#include "util-bloomfilter.h"

#define B3G_HASHSHIFT_MAX      8
#define B3G_HASHSHIFT_MAX2     5
#define B3G_HASHSHIFT_HIGHER   7
#define B3G_HASHSHIFT_HIGHER2  4
#define B3G_HASHSHIFT_HIGH     6
#define B3G_HASHSHIFT_HIGH2    3
#define B3G_HASHSHIFT_MEDIUM   5
#define B3G_HASHSHIFT_MEDIUM2  2
#define B3G_HASHSHIFT_LOW      4
#define B3G_HASHSHIFT_LOW2     1
#define B3G_HASHSHIFT_LOWEST   3
#define B3G_HASHSHIFT_LOWEST2  1

#define B3G_TYPE uint32_t
//#define B3G_TYPE uint16_t
//#define B3G_TYPE uint8_t
//#define B3G_WORD_SIZE 16
//#define B3G_WORD_SIZE 8
#define B3G_WORD_SIZE     32

#define B3G_Q             3

//#define B3G_SEARCHFUNC      B3gSearch
#define B3G_SEARCHFUNC      B3gSearchBNDMq

//#define B3G_COUNTERS

typedef struct B3gPattern_ {
    uint8_t *cs; /* case sensitive */
    uint8_t *ci; /* case INsensitive */
    uint16_t len;
    uint8_t flags;
    uint32_t id;

    /* sid(s) for this pattern */
    uint32_t sids_size;
    SigIntId *sids;

    struct B3gPattern_ *next;

} B3gPattern;

typedef struct B3gHashItem_ {
    uint8_t flags;
    uint16_t idx;
    struct B3gHashItem_ *nxt;
} B3gHashItem;

typedef struct B3gCtx_ {
    /* hash used during ctx initialization */
    B3gPattern **init_hash;

    B3G_TYPE m;
    B3G_TYPE *B3G;

    uint8_t s0;

    uint16_t pat_1_cnt;
    uint16_t pat_2_cnt;
    uint16_t pat_x_cnt;

    uint32_t hash_size;
    B3gHashItem **hash;
    BloomFilter **bloom;
    uint8_t *pminlen; /* array containing the minimal length
                               of the patters in a hash bucket. Used
                               for the BloomFilter. */
    B3gHashItem hash1[256];
    B3gHashItem **hash2;

    uint32_t (*Search)(struct MpmCtx_ *, struct MpmThreadCtx_ *, PatternMatcherQueue *, uint8_t *, uint16_t);

    /* we store our own multi byte search func ptr here for B3gSearch1 */
    uint32_t (*MBSearch2)(struct MpmCtx_ *, struct MpmThreadCtx_ *, PatternMatcherQueue *, uint8_t *, uint16_t);
    uint32_t (*MBSearch)(struct MpmCtx_ *, struct MpmThreadCtx_ *, PatternMatcherQueue *, uint8_t *, uint16_t);

    /* pattern arrays */
    B3gPattern **parray;
} B3gCtx;

typedef struct B3gThreadCtx_ {
#ifdef B3G_COUNTERS
    uint32_t stat_pminlen_calls;
    uint32_t stat_pminlen_total;
    uint32_t stat_bloom_calls;
    uint32_t stat_bloom_hits;
    uint32_t stat_calls;
    uint32_t stat_m_total;
    uint32_t stat_d0;
    uint32_t stat_d0_hashloop;
    uint32_t stat_loop_match;
    uint32_t stat_loop_no_match;
    uint32_t stat_num_shift;
    uint32_t stat_total_shift;
#endif /* B3G_COUNTERS */
} B3gThreadCtx;

void MpmB3gRegister(void);

#endif

