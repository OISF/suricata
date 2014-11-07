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

#ifndef __UTIL_MPM_B2G_H__
#define __UTIL_MPM_B2G_H__

#include "util-mpm.h"
#include "util-bloomfilter.h"

#define B2G_HASHSHIFT_MAX      8
#define B2G_HASHSHIFT_HIGHER   7
#define B2G_HASHSHIFT_HIGH     6
#define B2G_HASHSHIFT_MEDIUM   5
#define B2G_HASHSHIFT_LOW      4
#define B2G_HASHSHIFT_LOWEST   3

//#define B2G_TYPE uint64_t
#define B2G_TYPE uint32_t
//#define B2G_TYPE uint16_t
//#define B2G_TYPE uint8_t
//#define B2G_WORD_SIZE 64
#define B2G_WORD_SIZE 32
//#define B2G_WORD_SIZE 16
//#define B2G_WORD_SIZE 8

#define B2G_Q           2

#define B2G_SEARCHFUNC B2gSearchBNDMq
//#define B2G_SEARCHFUNC B2gSearch

//#define B2G_SEARCH2
//#define B2G_COUNTERS

typedef struct B2gPattern_ {
    uint16_t len; /**< \todo we're limited to 32/64 byte lengths, uint8_t would be fine here */
    uint8_t flags;
    uint8_t pad0;
    uint32_t id;
    uint8_t *original_pat;
    uint8_t *ci; /* case INsensitive */
    uint8_t *cs; /* case sensitive */

    /* sid(s) for this pattern */
    uint32_t sids_size;
    SigIntId *sids;

    struct B2gPattern_ *next;
} B2gPattern;

typedef struct B2gCtx_ {
    B2G_TYPE *B2G;
    B2G_TYPE m;
    BloomFilter **bloom;
    uint8_t *pminlen; /* array containing the minimal length
                               of the patters in a hash bucket. Used
                               for the BloomFilter. */
    /* pattern arrays */
    B2gPattern **parray;

    uint16_t pat_1_cnt;
#ifdef B2G_SEARCH2
    uint16_t pat_2_cnt;
#endif
    uint16_t pat_x_cnt;

    uint32_t hash_size;
    B2gPattern **hash;
    B2gPattern hash1[256];
#ifdef B2G_SEARCH2
    B2gHashItem **hash2;
#endif

    /* hash used during ctx initialization */
    B2gPattern **init_hash;

    uint8_t s0;

    /* we store our own multi byte search func ptr here for B2gSearch1 */
    uint32_t (*Search)(struct MpmCtx_ *, struct MpmThreadCtx_ *, PatternMatcherQueue *, uint8_t *, uint16_t);

    /* we store our own multi byte search func ptr here for B2gSearch1 */
    uint32_t (*MBSearch2)(struct MpmCtx_ *, struct MpmThreadCtx_ *, PatternMatcherQueue *, uint8_t *, uint16_t);
    uint32_t (*MBSearch)(struct MpmCtx_ *, struct MpmThreadCtx_ *, PatternMatcherQueue *, uint8_t *, uint16_t);
} B2gCtx;

typedef struct B2gThreadCtx_ {
#ifdef B2G_COUNTERS
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
#endif /* B2G_COUNTERS */
} B2gThreadCtx;

void MpmB2gRegister(void);


#endif

