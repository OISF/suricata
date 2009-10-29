/* Copyright (c) 2008 Victor Julien <victor@inliniac.net> */

#ifndef __UTIL_MPM_WUMANBER_H__
#define __UTIL_MPM_WUMANBER_H__

#include "util-mpm.h"
#include "util-bloomfilter.h"

#define WUMANBER_NOCASE 0x01
#define WUMANBER_SCAN   0x02

#define WUMANBER_BLOOMSIZE 1024

//#define WUMANBER_COUNTERS

typedef struct WmPattern_ {
    uint8_t *cs; /* case sensitive */
    uint8_t *ci; /* case INsensitive */
    uint16_t len;
    struct WmPattern_ *next;
    uint16_t prefix_ci;
    uint16_t prefix_cs;
    uint8_t flags;
    MpmEndMatch *em;
} WmPattern;

typedef struct WmHashItem_ {
    uint8_t flags;
    uint16_t idx;
    struct WmHashItem_ *nxt;
} WmHashItem;

typedef struct WmCtx_ {
    /* hash used during ctx initialization */
    WmPattern **init_hash;

    uint16_t scan_shiftlen;
    uint16_t search_shiftlen;

    uint32_t scan_hash_size;
    WmHashItem **scan_hash;
    BloomFilter **scan_bloom;
    uint8_t *scan_pminlen; /* array containing the minimal length
                               of the patters in a hash bucket. Used
                               for the BloomFilter. */
    WmHashItem scan_hash1[256];
    uint32_t search_hash_size;
    WmHashItem **search_hash;
    WmHashItem search_hash1[256];

    /* we store our own scan ptr here for WmSearch1 */
    uint32_t (*Scan)(struct MpmCtx_ *, struct MpmThreadCtx_ *, PatternMatcherQueue *, uint8_t *, uint16_t);
    /* we store our own search ptr here for WmSearch1 */
    uint32_t (*Search)(struct MpmCtx_ *, struct MpmThreadCtx_ *, PatternMatcherQueue *, uint8_t *, uint16_t);
    /* we store our own multi byte scan ptr here for WmSearch1 */
    uint32_t (*MBScan)(struct MpmCtx_ *, struct MpmThreadCtx_ *, PatternMatcherQueue *, uint8_t *, uint16_t);
    /* we store our own multi byte search ptr here for WmSearch1 */
    uint32_t (*MBSearch)(struct MpmCtx_ *, struct MpmThreadCtx_ *, PatternMatcherQueue *, uint8_t *, uint16_t);

    /* pattern arrays */
    WmPattern **parray;

    /* only used for multibyte pattern search */
    uint16_t *scan_shifttable;
    uint16_t *search_shifttable;
} WmCtx;

typedef struct WmThreadCtx_ {
#ifdef WUMANBER_COUNTERS
    uint32_t scan_stat_pminlen_calls;
    uint32_t scan_stat_pminlen_total;
    uint32_t scan_stat_bloom_calls;
    uint32_t scan_stat_bloom_hits;
    uint32_t scan_stat_shift_null;
    uint32_t scan_stat_loop_match;
    uint32_t scan_stat_loop_no_match;
    uint32_t scan_stat_num_shift;
    uint32_t scan_stat_total_shift;

    uint32_t search_stat_shift_null;
    uint32_t search_stat_loop_match;
    uint32_t search_stat_loop_no_match;
    uint32_t search_stat_num_shift;
    uint32_t search_stat_total_shift;
#endif /* WUMANBER_COUNTERS */
} WmThreadCtx;

void MpmWuManberRegister(void);

#endif /* __UTIL_MPM_WUMANBER_H__ */

