/**
 * Copyright (c) 2009 Open Information Security Foundation.
 *
 * \author Anoop Saldanha <poonaatsoc@gmail.com>
 */

#ifndef __UTIL_MPM_B2G_CUDA_H__
#define __UTIL_MPM_B2G_CUDA_H__

#include <cuda.h>
#include "decode.h"
#include "util-mpm.h"
#include "util-bloomfilter.h"

#define B2G_CUDA_NOCASE 0x01
#define B2G_CUDA_SCAN   0x02

#define B2G_CUDA_HASHSIZE  4096
#define B2G_CUDA_HASHSHIFT 4
#define B2G_CUDA_TYPE      uint32_t
#define B2G_CUDA_WORD_SIZE 32
#define B2G_CUDA_BLOOMSIZE 1024
#define B2G_CUDA_Q         2

#define B2G_CUDA_HASH16(a, b) (((a) << B2G_CUDA_HASHSHIFT) | (b))

#define B2G_CUDA_SCANFUNC_NAME   "B2gCudaScanBNDMq"
#define B2G_CUDA_SEARCHFUNC_NAME "B2gCudaSearchBNDMq"

#define B2G_CUDA_SCANFUNC B2gCudaScanBNDMq
#define B2G_CUDA_SEARCHFUNC B2gCudaSearchBNDMq

typedef struct B2gCudaPattern_ {
    uint8_t flags;
    /** \todo we're limited to 32/64 byte lengths, uint8_t would be fine here */
    uint16_t len;
    /* case sensitive */
    uint8_t *cs;
    /* case INsensitive */
    uint8_t *ci;
    struct B2gCudaPattern_ *next;
    MpmEndMatch *em;
} B2gCudaPattern;

typedef struct B2gCudaHashItem_ {
    uint16_t idx;
    uint8_t flags;
    struct B2gCudaHashItem_ *nxt;
} B2gCudaHashItem;

typedef struct B2gCudaCtx_ {
    int module_handle;

    CUcontext cuda_context;
    CUmodule cuda_module;

    CUfunction cuda_search_kernel;
    CUfunction cuda_scan_kernel;

    CUdeviceptr cuda_g_u8_lowercasetable;
    CUdeviceptr cuda_search_B2G;
    CUdeviceptr cuda_scan_B2G;

    B2G_CUDA_TYPE *scan_B2G;
    B2G_CUDA_TYPE scan_m;
    BloomFilter **scan_bloom;
    /* array containing the minimal length of the patters in a hash bucket.
     * Used for the BloomFilter. */
    uint8_t *scan_pminlen;
    /* pattern arrays */
    B2gCudaPattern **parray;

    B2G_CUDA_TYPE search_m;
    B2G_CUDA_TYPE *search_B2G;

    uint16_t scan_1_pat_cnt;
#ifdef B2G_CUDA_SCAN2
    uint16_t scan_2_pat_cnt;
#endif
    uint16_t scan_x_pat_cnt;

    uint32_t scan_hash_size;
    B2gCudaHashItem **scan_hash;
    B2gCudaHashItem scan_hash1[256];
#ifdef B2G_CUDA_SCAN2
    B2gHashItem **scan_hash2;
#endif
    uint32_t search_hash_size;
    BloomFilter **search_bloom;
    /* array containing the minimal length of the patters in a hash bucket.
     * Used for the BloomFilter. */
    uint8_t *search_pminlen;

    B2gCudaHashItem **search_hash;
    B2gCudaHashItem search_hash1[256];

    /* hash used during ctx initialization */
    B2gCudaPattern **init_hash;

    uint8_t scan_s0;
    uint8_t search_s0;

    /* we store our own multi byte scan ptr here for B2gCudaSearch1 */
    uint32_t (*Scan)(struct MpmCtx_ *, struct MpmThreadCtx_ *,
                     PatternMatcherQueue *, uint8_t *, uint16_t);
    /* we store our own multi byte search ptr here for B2gCudaSearch1 */
    uint32_t (*Search)(struct MpmCtx_ *, struct MpmThreadCtx_ *,
                       PatternMatcherQueue *, uint8_t *, uint16_t);

    /* we store our own multi byte scan ptr here for B2gCudaSearch1 */
    uint32_t (*MBScan2)(struct MpmCtx_ *, struct MpmThreadCtx_ *,
                        PatternMatcherQueue *, uint8_t *, uint16_t);
    uint32_t (*MBScan)(struct MpmCtx_ *, struct MpmThreadCtx_ *,
                       PatternMatcherQueue *, uint8_t *, uint16_t);
    /* we store our own multi byte search ptr here for B2gCudaSearch1 */
    uint32_t (*MBSearch)(struct MpmCtx_ *, struct MpmThreadCtx_ *,
                         PatternMatcherQueue *, uint8_t *, uint16_t);

} B2gCudaCtx;

typedef struct B2gCudaThreadCtx_ {
#ifdef B2G_CUDA_COUNTERS
    uint32_t scan_stat_pminlen_calls;
    uint32_t scan_stat_pminlen_total;
    uint32_t scan_stat_bloom_calls;
    uint32_t scan_stat_bloom_hits;
    uint32_t scan_stat_calls;
    uint32_t scan_stat_m_total;
    uint32_t scan_stat_d0;
    uint32_t scan_stat_d0_hashloop;
    uint32_t scan_stat_loop_match;
    uint32_t scan_stat_loop_no_match;
    uint32_t scan_stat_num_shift;
    uint32_t scan_stat_total_shift;

    uint32_t search_stat_d0;
    uint32_t search_stat_loop_match;
    uint32_t search_stat_loop_no_match;
    uint32_t search_stat_num_shift;
    uint32_t search_stat_total_shift;
#endif /* B2G_CUDA_COUNTERS */
} B2gCudaThreadCtx;

void MpmB2gCudaRegister(void);

void TmModuleCudaMpmB2gRegister(void);

int B2gCudaStartDispatcherThreadRC(const char *);
int B2gCudaStartDispatcherThreadAPC(const char *);

void B2gCudaKillDispatcherThreadRC(void);
void B2gCudaKillDispatcherThreadAPC(void);

void B2gCudaPushPacketTo_tv_CMB2_RC(Packet *);
void B2gCudaPushPacketTo_tv_CMB2_APC(Packet *);

#endif /* __UTIL_MPM_B2G_CUDA_H__ */
