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

#ifndef __UTIL_MPM_B2GC_H__
#define __UTIL_MPM_B2GC_H__

#include "util-mpm.h"
#include "util-bloomfilter.h"

#define B2GC_HASHSHIFT_MAX      8
#define B2GC_HASHSHIFT_HIGHER   7
#define B2GC_HASHSHIFT_HIGH     6
#define B2GC_HASHSHIFT_MEDIUM   5
#define B2GC_HASHSHIFT_LOW      4
#define B2GC_HASHSHIFT_LOWEST   3

//#define B2GC_HASHSHIFT 8
//#define B2GC_HASHSHIFT 7
//#define B2GC_HASHSHIFT 6
//#define B2GC_HASHSHIFT 5
#define B2GC_HASHSHIFT 4
//#define B2GC_HASHSHIFT 3

//#define B2GC_TYPE uint64_t
#define B2GC_TYPE uint32_t
//#define B2GC_TYPE uint16_t
//#define B2GC_TYPE uint8_t
//#define B2GC_WORD_SIZE 64
#define B2GC_WORD_SIZE 32
//#define B2GC_WORD_SIZE 16
//#define B2GC_WORD_SIZE 8

#define B2GC_Q           2

#define B2GC_SEARCHFUNC B2gcSearchBNDMq
//#define B2GC_SEARCHFUNC B2gcSearch

//#define B2GC_SEARCH2
//#define B2GC_COUNTERS

#define B2GC_FLAG_NOCASE    0x01
#define B2GC_FLAG_FINAL     0x02
#define B2GC_FLAG_RES1      0x04
#define B2GC_FLAG_RES2      0x08

/* Bits
 *   flg  len          id                     pat
 * |xxxx|xxxx xxxx xx|xx xxxx xxxx xxxx xxxx|xx..xx|
 */

typedef struct B2gcPatternHdr_ {
    uint32_t np_offset; /* offset of the next pattern */
    uint8_t len;
    uint8_t flags;
    PatIntId id;
} B2gcPatternHdr;

#define B2GC_GET_FLAGS(hdr)         ((hdr)->flags)
#define B2GC_GET_LEN(hdr)           ((hdr)->len)
#define B2GC_GET_ID(hdr)            ((hdr)->id)

/* 1 byte pattern structure fitting in a double word.
 *  flg  id                     pad pat/char
 * |xxxx|xxxx xxxx xxxx xxxx xx|xx|xxxx xxxx|
 */

typedef struct B2gcPattern1_ {
    uint8_t flags;
    uint8_t pat;
    PatIntId id;
} B2gcPattern1;

#define B2GC1_GET_FLAGS(hdr)         ((hdr)->flags)
#define B2GC1_GET_LEN(hdr)           1
#define B2GC1_GET_ID(hdr)            ((hdr)->id)
#define B2GC1_GET_CHAR(hdr)          ((hdr)->pat)

typedef struct B2gcPattern_ {
    uint16_t len;
    uint8_t flags;
    uint8_t pad0;
    PatIntId id;
    uint8_t *pat;
} B2gcPattern;

typedef struct B2gcCtx_ {
    /* we store our own multi byte search func ptr here for B2gcSearch1 */
    uint32_t (*Search)(struct MpmCtx_ *, struct MpmThreadCtx_ *, PatternMatcherQueue *, uint8_t *, uint16_t);
    /* hash for looking up the idx in the pattern array */
    uint16_t *ha1;
    uint8_t *patterns1;
    uint32_t pat_x_cnt;
    uint32_t pat_1_cnt;
    /* we store our own multi byte search func ptr here for B2gcSearch1 */
    uint32_t (*MBSearch)(struct MpmCtx_ *, struct MpmThreadCtx_ *, PatternMatcherQueue *, uint8_t *, uint16_t);

    B2GC_TYPE m;
    uint32_t hash_size;

    B2GC_TYPE *B2GC;

    uint8_t *pminlen; /* array containing the minimal length */
    BloomFilter **bloom;

    uint32_t *ha;
    /* patterns in the format |hdr|pattern|hdr|pattern|... */
    uint8_t *patterns;

    HashListTable *b2gc_init_hash;
} B2gcCtx;

typedef struct B2gcThreadCtx_ {
#ifdef B2GC_COUNTERS
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
#endif /* B2GC_COUNTERS */
} B2gcThreadCtx;

void MpmB2gcRegister(void);


#endif

