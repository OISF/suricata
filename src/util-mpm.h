/* Copyright (C) 2007-2014 Open Information Security Foundation
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

#ifndef __UTIL_MPM_H__
#define __UTIL_MPM_H__
#include "suricata-common.h"

#define MPM_ENDMATCH_SINGLE     0x01    /**< A single match is sufficient. No
                                             depth, offset, etc settings. */
#define MPM_ENDMATCH_OFFSET     0x02    /**< has offset setting */
#define MPM_ENDMATCH_DEPTH      0x04    /**< has depth setting */
#define MPM_ENDMATCH_NOSEARCH   0x08    /**< if this matches, no search is
                                             required (for this pattern) */

#define HASHSIZE_LOWEST         2048    /**< Lowest hash size for the multi
                                             pattern matcher algorithms */
#define HASHSIZE_LOW            4096    /**< Low hash size for the multi
                                             pattern matcher algorithms */
#define HASHSIZE_MEDIUM         8192    /**< Medium hash size for the multi
                                             pattern matcher algorithms */
#define HASHSIZE_HIGH           16384   /**< High hash size for the multi
                                             pattern matcher algorithms */
#define HASHSIZE_HIGHER         32768   /**< Higher hash size for the multi
                                             pattern matcher algorithms */
#define HASHSIZE_MAX            65536   /**< Max hash size for the multi
                                             pattern matcher algorithms */
#define BLOOMSIZE_LOW           512     /*<* Low bloomfilter size for the multi
                                            pattern matcher algorithms */
#define BLOOMSIZE_MEDIUM        1024    /**< Medium bloomfilter size for the multi
                                             pattern matcher algorithms */
#define BLOOMSIZE_HIGH          2048    /**< High bloomfilter size for the multi
                                             pattern matcher algorithms */

enum {
    MPM_NOTSET = 0,

    /* wumanber as the name suggests */
    MPM_WUMANBER,
    /* bndmq 2 gram */
    MPM_B2G,
    /* bndmq 3 gram */
    MPM_B3G,
    MPM_B2GC,
    MPM_B2GM,

    /* aho-corasick */
    MPM_AC,
#ifdef __SC_CUDA_SUPPORT__
    MPM_AC_CUDA,
#endif
    /* aho-corasick-goto-failure state based */
    MPM_AC_GFBS,
    MPM_AC_BS,
    MPM_AC_TILE,
    /* table size */
    MPM_TABLE_SIZE,
};

#ifdef __tile__
#define DEFAULT_MPM   MPM_AC_TILE
#else
#define DEFAULT_MPM   MPM_AC
#endif

/* Internal Pattern Index: 0 to pattern_cnt-1 */
typedef uint32_t MpmPatternIndex;

typedef struct MpmMatchBucket_ {
    uint32_t len;
} MpmMatchBucket;

typedef struct MpmThreadCtx_ {
    void *ctx;

    uint32_t memory_cnt;
    uint32_t memory_size;

} MpmThreadCtx;

/** \brief helper structure for the pattern matcher engine. The Pattern Matcher
 *         thread has this and passes a pointer to it to the pattern matcher.
 *         The actual pattern matcher will fill the structure. */
typedef struct PatternMatcherQueue_ {
    uint32_t *pattern_id_array;     /** array with pattern id's that had a
                                        pattern match. These will be inspected
                                        futher by the detection engine. */
    uint32_t pattern_id_array_cnt;  /**< Number currently stored */
    uint32_t pattern_id_array_size; /**< Allocated size in bytes */

    uint8_t *pattern_id_bitarray;   /** bitarray with pattern id matches */
    uint32_t pattern_id_bitarray_size; /**< size in bytes */

    /* used for storing rule id's */
    /* Array of rule IDs found. */
    SigIntId *rule_id_array;
    /* Number of rule IDs in the array. */
    uint32_t rule_id_array_cnt;
    /* The number of slots allocated for storing rule IDs */
    uint32_t rule_id_array_size;

} PatternMatcherQueue;

typedef struct MpmCtx_ {
    void *ctx;
    uint16_t mpm_type;

    /* Indicates if this a global mpm_ctx.  Global mpm_ctx is the one that
     * is instantiated when we use "single".  Non-global is "full", i.e.
     * one per sgh.  We are using a uint16_t here to avoiding using a pad.
     * You can use a uint8_t here as well. */
    uint16_t global;

    /* unique patterns */
    uint32_t pattern_cnt;

    uint16_t minlen;
    uint16_t maxlen;

    uint32_t memory_cnt;
    uint32_t memory_size;
} MpmCtx;

/* if we want to retrieve an unique mpm context from the mpm context factory
 * we should supply this as the key */
#define MPM_CTX_FACTORY_UNIQUE_CONTEXT -1

#define MPM_CTX_FACTORY_FLAGS_PREPARE_WITH_SIG_GROUP_BUILD 0x01

typedef struct MpmCtxFactoryItem_ {
    char *name;
    MpmCtx *mpm_ctx_ts;
    MpmCtx *mpm_ctx_tc;
    int32_t id;
    uint8_t flags;
} MpmCtxFactoryItem;

typedef struct MpmCtxFactoryContainer_ {
    MpmCtxFactoryItem *items;
    int32_t no_of_items;
} MpmCtxFactoryContainer;

/** pattern is case insensitive */
#define MPM_PATTERN_FLAG_NOCASE     0x01
/** pattern is negated */
#define MPM_PATTERN_FLAG_NEGATED    0x02
/** pattern has a depth setting */
#define MPM_PATTERN_FLAG_DEPTH      0x04
/** pattern has an offset setting */
#define MPM_PATTERN_FLAG_OFFSET     0x08
/** one byte pattern (used in b2g) */
#define MPM_PATTERN_ONE_BYTE        0x10

typedef struct MpmTableElmt_ {
    char *name;
    uint8_t max_pattern_length;
    void (*InitCtx)(struct MpmCtx_ *);
    void (*InitThreadCtx)(struct MpmCtx_ *, struct MpmThreadCtx_ *, uint32_t);
    void (*DestroyCtx)(struct MpmCtx_ *);
    void (*DestroyThreadCtx)(struct MpmCtx_ *, struct MpmThreadCtx_ *);

    /** function pointers for adding patterns to the mpm ctx.
     *
     *  \param mpm_ctx Mpm context to add the pattern to
     *  \param pattern pointer to the pattern
     *  \param pattern_len length of the pattern in bytes
     *  \param offset pattern offset setting
     *  \param depth pattern depth setting
     *  \param pid pattern id
     *  \param sid signature _internal_ id
     *  \param flags pattern flags
     */
    int  (*AddPattern)(struct MpmCtx_ *, uint8_t *, uint16_t, uint16_t, uint16_t, uint32_t, SigIntId, uint8_t);
    int  (*AddPatternNocase)(struct MpmCtx_ *, uint8_t *, uint16_t, uint16_t, uint16_t, uint32_t, SigIntId, uint8_t);
    int  (*Prepare)(struct MpmCtx_ *);
    uint32_t (*Search)(struct MpmCtx_ *, struct MpmThreadCtx_ *, PatternMatcherQueue *, uint8_t *, uint16_t);
    void (*Cleanup)(struct MpmThreadCtx_ *);
    void (*PrintCtx)(struct MpmCtx_ *);
    void (*PrintThreadCtx)(struct MpmThreadCtx_ *);
    void (*RegisterUnittests)(void);
    uint8_t flags;
} MpmTableElmt;

MpmTableElmt mpm_table[MPM_TABLE_SIZE];

/* macros decides if cuda is enabled for the platform or not */
#ifdef __SC_CUDA_SUPPORT__

/* the min size limit of a payload(or any other data) to be buffered */
#define UTIL_MPM_CUDA_DATA_BUFFER_SIZE_MIN_LIMIT_DEFAULT 0
/* the max size limit of a payload(or any other data) to be buffered */
#define UTIL_MPM_CUDA_DATA_BUFFER_SIZE_MAX_LIMIT_DEFAULT 1500
/* Default value for data buffer used by cuda mpm engine for CudaBuffer reg */
#define UTIL_MPM_CUDA_CUDA_BUFFER_DBUFFER_SIZE_DEFAULT 500 * 1024 * 1024
/* Default value for the max data chunk that would be sent to gpu */
#define UTIL_MPM_CUDA_GPU_TRANSFER_SIZE 50 * 1024 * 1024
/* Default value for offset/pointer buffer to be used by cuda mpm
 * engine for CudaBuffer reg */
#define UTIL_MPM_CUDA_CUDA_BUFFER_OPBUFFER_ITEMS_DEFAULT 500000
#define UTIL_MPM_CUDA_BATCHING_TIMEOUT_DEFAULT 2000
#define UTIL_MPM_CUDA_CUDA_STREAMS_DEFAULT 2
#define UTIL_MPM_CUDA_DEVICE_ID_DEFAULT 0

/**
 * \brief Cuda configuration for "mpm" profile.  We can further extend this
 *        to have conf for specific mpms.  For now its common for all mpms.
 */
typedef struct MpmCudaConf_ {
    uint16_t data_buffer_size_min_limit;
    uint16_t data_buffer_size_max_limit;
    uint32_t cb_buffer_size;
    uint32_t gpu_transfer_size;
    int batching_timeout;
    int device_id;
    int cuda_streams;
} MpmCudaConf;

void MpmCudaEnvironmentSetup();

#endif /* __SC_CUDA_SUPPORT__ */

struct DetectEngineCtx_;

int32_t MpmFactoryRegisterMpmCtxProfile(struct DetectEngineCtx_ *, const char *, uint8_t);
void MpmFactoryReClaimMpmCtx(struct DetectEngineCtx_ *, MpmCtx *);
MpmCtx *MpmFactoryGetMpmCtxForProfile(struct DetectEngineCtx_ *, int32_t, int);
void MpmFactoryDeRegisterAllMpmCtxProfiles(struct DetectEngineCtx_ *);
int32_t MpmFactoryIsMpmCtxAvailable(struct DetectEngineCtx_ *, MpmCtx *);

int PmqSetup(PatternMatcherQueue *, uint32_t);
void PmqMerge(PatternMatcherQueue *src, PatternMatcherQueue *dst);
void PmqReset(PatternMatcherQueue *);
void PmqCleanup(PatternMatcherQueue *);
void PmqFree(PatternMatcherQueue *);

void MpmTableSetup(void);
void MpmRegisterTests(void);

int MpmVerifyMatch(MpmThreadCtx *thread_ctx, PatternMatcherQueue *pmq, uint32_t patid,
                   uint8_t *bitarray, SigIntId *sids, uint32_t sids_size);
void MpmInitCtx(MpmCtx *mpm_ctx, uint16_t matcher);
void MpmInitThreadCtx(MpmThreadCtx *mpm_thread_ctx, uint16_t, uint32_t);
uint32_t MpmGetHashSize(const char *);
uint32_t MpmGetBloomSize(const char *);

int MpmAddPatternCS(struct MpmCtx_ *mpm_ctx, uint8_t *pat, uint16_t patlen,
                    uint16_t offset, uint16_t depth,
                    uint32_t pid, SigIntId sid, uint8_t flags);
int MpmAddPatternCI(struct MpmCtx_ *mpm_ctx, uint8_t *pat, uint16_t patlen,
                    uint16_t offset, uint16_t depth,
                    uint32_t pid, SigIntId sid, uint8_t flags);

/* Resize Signature ID array. Only called from MpmAddSids(). */
int MpmAddSidsResize(PatternMatcherQueue *pmq, uint32_t new_size);

/** \brief Add array of Signature IDs to rule ID array.
 *
 *   Checks size of the array first. Calls MpmAddSidsResize to increase
 *   The size of the array, since that is the slow path.
 *
 *  \param pmq storage for match results
 *  \param sids pointer to array of Signature IDs
 *  \param sids_size number of Signature IDs in sids array.
 *
 */
static inline void
MpmAddSids(PatternMatcherQueue *pmq, SigIntId *sids, uint32_t sids_size)
{
    if (sids_size == 0)
        return;

    uint32_t new_size = pmq->rule_id_array_cnt + sids_size;
    if (new_size > pmq->rule_id_array_size) {
        if (MpmAddSidsResize(pmq, new_size) == 0) {
            // Failed to allocate larger memory for all the SIDS, but
            // keep as many as we can.
            sids_size = pmq->rule_id_array_size - pmq->rule_id_array_cnt;
        }
    }
    SCLogDebug("Adding %u sids", sids_size);
    // Add SIDs for this pattern to the end of the array
    SigIntId *ptr = pmq->rule_id_array + pmq->rule_id_array_cnt;
    SigIntId *end = ptr + sids_size;
    do {
        *ptr++ = *sids++;
    } while (ptr != end);
    pmq->rule_id_array_cnt += sids_size;
}

/* Resize Pattern ID array. Only called from MpmAddPid(). */
int MpmAddPidResize(PatternMatcherQueue *pmq, uint32_t new_size);

static inline void
MpmAddPid(PatternMatcherQueue *pmq, uint32_t patid)
{
    uint32_t new_size = pmq->pattern_id_array_cnt + 1;
    if (new_size > pmq->pattern_id_array_size)  {
        if (MpmAddPidResize(pmq, new_size) == 0)
            return;
    }
    pmq->pattern_id_array[pmq->pattern_id_array_cnt] = patid;
    pmq->pattern_id_array_cnt = new_size;
    SCLogDebug("pattern_id_array_cnt %u", pmq->pattern_id_array_cnt);
}
#endif /* __UTIL_MPM_H__ */
