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

#ifndef __UTIL_MPM_B2GM_H__
#define __UTIL_MPM_B2GM_H__

#include "util-mpm.h"
#include "util-bloomfilter.h"

#define B2GM_HASHSHIFT_MAX      8
#define B2GM_HASHSHIFT_HIGHER   7
#define B2GM_HASHSHIFT_HIGH     6
#define B2GM_HASHSHIFT_MEDIUM   5
#define B2GM_HASHSHIFT_LOW      4
#define B2GM_HASHSHIFT_LOWEST   3

//#define B2GM_TYPE uint64_t
#define B2GM_TYPE uint32_t
//#define B2GM_TYPE uint16_t
//#define B2GM_TYPE uint8_t

//#define B2GM_WORD_SIZE 64
#define B2GM_WORD_SIZE 32
//#define B2GM_WORD_SIZE 16
//#define B2GM_WORD_SIZE 8

#define B2GM_Q           2

#define B2GM_SEARCHFUNC B2gmSearchBNDMq
//#define B2GM_SEARCHFUNC B2gmSearch

//#define B2GM_COUNTERS

#define B2GM_FLAG_NOCASE    0x01
#define B2GM_FLAG_FINAL     0x02

typedef struct B2gmPattern_ {
    uint8_t len;
    uint8_t flags;
    uint16_t id;
#if __WORDSIZE == 64
    uint32_t pad;
#endif
    uint8_t *pat;
    struct B2gmPattern_ *next;
} B2gmPattern;

typedef struct B2gmPattern1_ {
    uint8_t flags;
    uint8_t pat;
    uint16_t id;
} B2gmPattern1;

typedef struct B2gmLookup_ {
    uint16_t pminlen;
    uint8_t pminlenb; /* bloom */
    uint8_t pad0;
#if __WORDSIZE == 64
    uint32_t pad1;
#endif
    BloomFilter *bloom;
    B2gmPattern *hash;
} B2gmLookup;

typedef struct B2gmCtx_ {
    /* we store our own multi byte search func ptr here for B2gmSearch1 */
    uint32_t (*Search)(struct MpmCtx_ *, struct MpmThreadCtx_ *, PatternMatcherQueue *, uint8_t *, uint16_t);

    /* hash for looking up the idx in the pattern array */
    uint16_t *ha1;
    uint8_t *patterns1;

    /* we store our own multi byte search func ptr here for B2gmSearch1 */
    //uint32_t (*MBSearch2)(struct MpmCtx_ *, struct MpmThreadCtx_ *, PatternMatcherQueue *, uint8_t *, uint16_t);
    uint32_t (*MBSearch)(struct MpmCtx_ *, struct MpmThreadCtx_ *, PatternMatcherQueue *, uint8_t *, uint16_t);

    uint16_t pat_1_cnt;
    uint16_t pat_x_cnt;
#if __WORDSIZE == 64
    uint32_t pad1;
#endif

    B2GM_TYPE *B2GM;
    B2GM_TYPE m;
#if __WORDSIZE == 64
    uint32_t pad0;
#endif

    B2gmLookup *lookup;

    /* pattern arrays */
    B2gmPattern **parray;

    /* hash used during ctx initialization */
    B2gmPattern **init_hash;
    //uint8_t s0;
    uint32_t hash_size;
} B2gmCtx;

typedef struct B2gmThreadCtx_ {
#ifdef B2GM_COUNTERS
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
    uint32_t stat_test_buf;
    uint32_t stat_test_buf_ok;
    uint32_t stat_test_buf_fail;
#endif /* B2GM_COUNTERS */
} B2gmThreadCtx;

void MpmB2gmRegister(void);

#endif /* __UTIL_MPM_B2GM_H__ */

