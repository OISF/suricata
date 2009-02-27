#ifndef __UTIL_MPM_B2G_H__
#define __UTIL_MPM_B2G_H__

#include "util-mpm.h"
#include "util-bloomfilter.h"

#define B2G_NOCASE 0x01
#define B2G_SCAN   0x02

//#define B2G_HASHSIZE 65536
//#define B2G_HASHSIZE 32768
//#define B2G_HASHSIZE 16384
//#define B2G_HASHSIZE 8192
#define B2G_HASHSIZE 4096
//#define B2G_HASHSIZE 2048

//#define B2G_HASHSHIFT 8
//#define B2G_HASHSHIFT 7
//#define B2G_HASHSHIFT 6
//#define B2G_HASHSHIFT 5
#define B2G_HASHSHIFT 4
//#define B2G_HASHSHIFT 3

//#define B2G_TYPE u_int64_t
#define B2G_TYPE u_int32_t
//#define B2G_TYPE u_int16_t
//#define B2G_TYPE u_int8_t
//#define B2G_WORD_SIZE 64
#define B2G_WORD_SIZE 32
//#define B2G_WORD_SIZE 16
//#define B2G_WORD_SIZE 8

#define B2G_BLOOMSIZE 1024

#define B2G_HASH16(a,b) (((a)<<B2G_HASHSHIFT) | (b))
#define B2G_Q           2

#define B2G_SCANFUNC B2gScanBNDMq
//#define B2G_SCANFUNC B2gScan

#define B2G_SEARCHFUNC B2gSearchBNDMq
//#define B2G_SEARCHFUNC B2gSearch

//#define B2G_SCAN2
//#define B2G_COUNTERS

typedef struct _B2gPattern {
    u_int8_t flags;
    u_int16_t len;
    u_int8_t *cs; /* case sensitive */
    u_int8_t *ci; /* case INsensitive */
    struct _B2gPattern *next;
    MpmEndMatch *em;
} B2gPattern;

typedef struct _B2gHashItem_ {
    u_int16_t idx;
    struct _B2gHashItem_ *nxt;
    u_int8_t flags;
} B2gHashItem;

typedef struct _B2gCtx {
    B2G_TYPE *scan_B2G;
    B2G_TYPE scan_m;
    BloomFilter **scan_bloom;
    u_int8_t *scan_pminlen; /* array containing the minimal length
                               of the patters in a hash bucket. Used
                               for the BloomFilter. */
    /* pattern arrays */
    B2gPattern **parray;

    B2G_TYPE search_m;
    B2G_TYPE *search_B2G;

    u_int16_t scan_1_pat_cnt;
#ifdef B2G_SCAN2
    u_int16_t scan_2_pat_cnt;
#endif
    u_int16_t scan_x_pat_cnt;

    u_int32_t scan_hash_size;
    B2gHashItem **scan_hash;
    B2gHashItem scan_hash1[256];
#ifdef B2G_SCAN2
    B2gHashItem **scan_hash2;
#endif
    u_int32_t search_hash_size;
    BloomFilter **search_bloom;
    u_int8_t *search_pminlen; /* array containing the minimal length
                                 of the patters in a hash bucket. Used
                                 for the BloomFilter. */
    B2gHashItem **search_hash;
    B2gHashItem search_hash1[256];

    /* hash used during ctx initialization */
    B2gPattern **init_hash;

    u_int8_t scan_s0;
    u_int8_t search_s0;

    /* we store our own multi byte scan ptr here for B2gSearch1 */
    u_int32_t (*MBScan2)(struct _MpmCtx *, struct _MpmThreadCtx *, PatternMatcherQueue *, u_int8_t *, u_int16_t);
    u_int32_t (*MBScan)(struct _MpmCtx *, struct _MpmThreadCtx *, PatternMatcherQueue *, u_int8_t *, u_int16_t);
    /* we store our own multi byte search ptr here for B2gSearch1 */
    u_int32_t (*MBSearch)(struct _MpmCtx *, struct _MpmThreadCtx *, PatternMatcherQueue *, u_int8_t *, u_int16_t);

} B2gCtx;

typedef struct _B2gThreadCtx {
#ifdef B2G_COUNTERS
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
#endif /* B2G_COUNTERS */
} B2gThreadCtx;

void MpmB2gRegister(void);


#endif

