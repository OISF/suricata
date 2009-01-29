/* Copyright (c) 2008 Victor Julien <victor@inliniac.net> */

#ifndef __UTIL_MPM_WUMANBER_H__
#define __UTIL_MPM_WUMANBER_H__

#include "util-mpm.h"
#include "util-bloomfilter.h"

#define WUMANBER_NOCASE 0x01
#define WUMANBER_SCAN   0x02

#define WUMANBER_BLOOMSIZE 1024

//#define WUMANBER_COUNTERS

typedef struct _WmPattern {
    u_int8_t *cs; /* case sensitive */
    u_int8_t *ci; /* case INsensitive */
    u_int16_t len;
    struct _WmPattern *next;
    u_int16_t prefix_ci;
    u_int16_t prefix_cs;
    u_int8_t flags;
    MpmEndMatch *em;
} WmPattern;

typedef struct _WmHashItem_ {
    u_int8_t flags;
    u_int16_t idx;
    struct _WmHashItem_ *nxt;
} WmHashItem;

typedef struct _WmCtx {
    /* hash used during ctx initialization */
    WmPattern **init_hash;

    u_int16_t scan_shiftlen;
    u_int16_t search_shiftlen;

    u_int32_t scan_hash_size;
    WmHashItem **scan_hash;
    BloomFilter **scan_bloom;
    u_int8_t *scan_pminlen; /* array containing the minimal length
                               of the patters in a hash bucket. Used
                               for the BloomFilter. */
    WmHashItem scan_hash1[256];
    u_int32_t search_hash_size;
    WmHashItem **search_hash;
    WmHashItem search_hash1[256];

    /* we store our own multi byte scan ptr here for WmSearch1 */
    u_int32_t (*MBScan)(struct _MpmCtx *, struct _MpmThreadCtx *, PatternMatcherQueue *, u_int8_t *, u_int16_t);
    /* we store our own multi byte search ptr here for WmSearch1 */
    u_int32_t (*MBSearch)(struct _MpmCtx *, struct _MpmThreadCtx *, PatternMatcherQueue *, u_int8_t *, u_int16_t);

    /* pattern arrays */
    WmPattern **parray;

    /* only used for multibyte pattern search */
    u_int16_t *scan_shifttable;
    u_int16_t *search_shifttable;
} WmCtx;

typedef struct _WmThreadCtx {
#ifdef WUMANBER_COUNTERS
    u_int32_t scan_stat_pminlen_calls;
    u_int32_t scan_stat_pminlen_total;
    u_int32_t scan_stat_bloom_calls;
    u_int32_t scan_stat_bloom_hits;
    u_int32_t scan_stat_shift_null;
    u_int32_t scan_stat_loop_match;
    u_int32_t scan_stat_loop_no_match;
    u_int32_t scan_stat_num_shift;
    u_int32_t scan_stat_total_shift;

    u_int32_t search_stat_shift_null;
    u_int32_t search_stat_loop_match;
    u_int32_t search_stat_loop_no_match;
    u_int32_t search_stat_num_shift;
    u_int32_t search_stat_total_shift;
#endif /* WUMANBER_COUNTERS */
} WmThreadCtx;

void MpmWuManberRegister(void);

#endif /* __UTIL_MPM_WUMANBER_H__ */

