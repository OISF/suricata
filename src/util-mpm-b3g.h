#ifndef __UTIL_MPM_B3G_H__
#define __UTIL_MPM_B3G_H__

#include "util-mpm.h"
#include "util-bloomfilter.h"

#define B3G_NOCASE 0x01
#define B3G_SCAN   0x02

//#define B3G_HASHSIZE 65536
//#define B3G_HASHSIZE 32768
//#define B3G_HASHSIZE 16384
//#define B3G_HASHSIZE 8192
#define B3G_HASHSIZE 4096

//#define B3G_HASHSHIFT 8
//#define B3G_HASHSHIFT 7
//#define B3G_HASHSHIFT 6
//#define B3G_HASHSHIFT 5
#define B3G_HASHSHIFT 4

#define B3G_TYPE u_int32_t
//#define B3G_TYPE u_int16_t
//#define B3G_TYPE u_int8_t
//#define B3G_WORD_SIZE 16
//#define B3G_WORD_SIZE 8
#define B3G_WORD_SIZE     32

#define B3G_BLOOMSIZE     1024

#define B3G_HASH(a,b,c)   (((a)<<B3G_HASHSHIFT) | (b)<<(B3G_HASHSHIFT-3) |(c))
#define B3G_Q             3

//#define B3G_SCANFUNC      B3gScan
#define B3G_SCANFUNC      B3gScanBNDMq

//#define B3G_SEARCHFUNC    B3gSearch
#define B3G_SEARCHFUNC    B3gSearchBNDMq

//#define B3G_COUNTERS

typedef struct B3gPattern_ {
    u_int8_t *cs; /* case sensitive */
    u_int8_t *ci; /* case INsensitive */
    u_int16_t len;
    struct B3gPattern_ *next;
    u_int8_t flags;
    MpmEndMatch *em;
} B3gPattern;

typedef struct B3gHashItem_ {
    u_int8_t flags;
    u_int16_t idx;
    struct B3gHashItem_ *nxt;
} B3gHashItem;

typedef struct B3gCtx_ {
    /* hash used during ctx initialization */
    B3gPattern **init_hash;

    B3G_TYPE scan_m;
    B3G_TYPE search_m;
    B3G_TYPE *scan_B3G;
    B3G_TYPE *search_B3G;

    u_int8_t scan_s0;
    u_int8_t search_s0;

    u_int16_t scan_1_pat_cnt;
    u_int16_t scan_2_pat_cnt;
    u_int16_t scan_x_pat_cnt;

    u_int16_t search_1_pat_cnt;
    u_int16_t search_2_pat_cnt;
    u_int16_t search_x_pat_cnt;

    u_int32_t scan_hash_size;
    B3gHashItem **scan_hash;
    BloomFilter **scan_bloom;
    u_int8_t *scan_pminlen; /* array containing the minimal length
                               of the patters in a hash bucket. Used
                               for the BloomFilter. */
    B3gHashItem scan_hash1[256];
    B3gHashItem **scan_hash2;

    u_int32_t search_hash_size;
    B3gHashItem **search_hash;
    BloomFilter **search_bloom;
    u_int8_t *search_pminlen; /* array containing the minimal length
                               of the patters in a hash bucket. Used
                               for the BloomFilter. */
    B3gHashItem search_hash1[256];
    B3gHashItem **search_hash2;

    /* we store our own multi byte scan ptr here for B3gSearch1 */
    u_int32_t (*MBScan2)(struct MpmCtx_ *, struct MpmThreadCtx_ *, PatternMatcherQueue *, u_int8_t *, u_int16_t);
    u_int32_t (*MBScan)(struct MpmCtx_ *, struct MpmThreadCtx_ *, PatternMatcherQueue *, u_int8_t *, u_int16_t);
    /* we store our own multi byte search ptr here for B3gSearch1 */
    u_int32_t (*MBSearch2)(struct MpmCtx_ *, struct MpmThreadCtx_ *, PatternMatcherQueue *, u_int8_t *, u_int16_t);
    u_int32_t (*MBSearch)(struct MpmCtx_ *, struct MpmThreadCtx_ *, PatternMatcherQueue *, u_int8_t *, u_int16_t);

    /* pattern arrays */
    B3gPattern **parray;
} B3gCtx;

typedef struct B3gThreadCtx_ {
#ifdef B3G_COUNTERS
    u_int32_t scan_stat_pminlen_calls;
    u_int32_t scan_stat_pminlen_total;
    u_int32_t scan_stat_bloom_calls;
    u_int32_t scan_stat_bloom_hits;
    u_int32_t scan_stat_calls;
    u_int32_t scan_stat_m_total;
    u_int32_t scan_stat_d0;
    u_int32_t scan_stat_d0_hashloop;
    u_int32_t scan_stat_loop_match;
    u_int32_t scan_stat_loop_no_match;
    u_int32_t scan_stat_num_shift;
    u_int32_t scan_stat_total_shift;

    u_int32_t search_stat_d0;
    u_int32_t search_stat_loop_match;
    u_int32_t search_stat_loop_no_match;
    u_int32_t search_stat_num_shift;
    u_int32_t search_stat_total_shift;
#endif /* B3G_COUNTERS */
} B3gThreadCtx;

void MpmB3gRegister(void);


#endif

