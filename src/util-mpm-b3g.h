#ifndef __UTIL_MPM_B3G_H__
#define __UTIL_MPM_B3G_H__

#include "util-mpm.h"
#include "util-bloomfilter.h"

//#define B3G_HASHSHIFT 8
//#define B3G_HASHSHIFT 7
//#define B3G_HASHSHIFT 6
//#define B3G_HASHSHIFT 5
#define B3G_HASHSHIFT 4

#define B3G_TYPE uint32_t
//#define B3G_TYPE uint16_t
//#define B3G_TYPE uint8_t
//#define B3G_WORD_SIZE 16
//#define B3G_WORD_SIZE 8
#define B3G_WORD_SIZE     32

#define B3G_HASH(a,b,c)   (((a)<<B3G_HASHSHIFT) | (b)<<(B3G_HASHSHIFT-3) |(c))
#define B3G_Q             3

//#define B3G_SEARCHFUNC      B3gSearch
#define B3G_SEARCHFUNC      B3gSearchBNDMq

//#define B3G_COUNTERS

typedef struct B3gPattern_ {
    uint8_t *cs; /* case sensitive */
    uint8_t *ci; /* case INsensitive */
    uint16_t len;
    struct B3gPattern_ *next;
    uint8_t flags;
    MpmEndMatch *em;
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

