/* Copyright (C) 2007-2016 Open Information Security Foundation
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
 *
 * thash -> thread hash. Hash table with locking handling.
 */

#ifndef __THASH_H__
#define __THASH_H__


/** Spinlocks or Mutex for the buckets. */
//#define HRLOCK_SPIN
#define HRLOCK_MUTEX

#ifdef HRLOCK_SPIN
    #ifdef HRLOCK_MUTEX
        #error Cannot enable both HRLOCK_SPIN and HRLOCK_MUTEX
    #endif
#endif

#ifdef HRLOCK_SPIN
    #define HRLOCK_TYPE SCSpinlock
    #define HRLOCK_INIT(fb) SCSpinInit(&(fb)->lock, 0)
    #define HRLOCK_DESTROY(fb) SCSpinDestroy(&(fb)->lock)
    #define HRLOCK_LOCK(fb) SCSpinLock(&(fb)->lock)
    #define HRLOCK_TRYLOCK(fb) SCSpinTrylock(&(fb)->lock)
    #define HRLOCK_UNLOCK(fb) SCSpinUnlock(&(fb)->lock)
#elif defined HRLOCK_MUTEX
    #define HRLOCK_TYPE SCMutex
    #define HRLOCK_INIT(fb) SCMutexInit(&(fb)->lock, NULL)
    #define HRLOCK_DESTROY(fb) SCMutexDestroy(&(fb)->lock)
    #define HRLOCK_LOCK(fb) SCMutexLock(&(fb)->lock)
    #define HRLOCK_TRYLOCK(fb) SCMutexTrylock(&(fb)->lock)
    #define HRLOCK_UNLOCK(fb) SCMutexUnlock(&(fb)->lock)
#else
    #error Enable HRLOCK_SPIN or HRLOCK_MUTEX
#endif

/** Spinlocks or Mutex for the queues. */
//#define HQLOCK_SPIN
#define HQLOCK_MUTEX

#ifdef HQLOCK_SPIN
    #ifdef HQLOCK_MUTEX
        #error Cannot enable both HQLOCK_SPIN and HQLOCK_MUTEX
    #endif
#endif

#ifdef HQLOCK_SPIN
    #define HQLOCK_INIT(q) SCSpinInit(&(q)->s, 0)
    #define HQLOCK_DESTROY(q) SCSpinDestroy(&(q)->s)
    #define HQLOCK_LOCK(q) SCSpinLock(&(q)->s)
    #define HQLOCK_TRYLOCK(q) SCSpinTrylock(&(q)->s)
    #define HQLOCK_UNLOCK(q) SCSpinUnlock(&(q)->s)
#elif defined HQLOCK_MUTEX
    #define HQLOCK_INIT(q) SCMutexInit(&(q)->m, NULL)
    #define HQLOCK_DESTROY(q) SCMutexDestroy(&(q)->m)
    #define HQLOCK_LOCK(q) SCMutexLock(&(q)->m)
    #define HQLOCK_TRYLOCK(q) SCMutexTrylock(&(q)->m)
    #define HQLOCK_UNLOCK(q) SCMutexUnlock(&(q)->m)
#else
    #error Enable HQLOCK_SPIN or HQLOCK_MUTEX
#endif

typedef struct THashData_ {
    /** ippair mutex */
    SCMutex m;

    /** use cnt, reference counter */
    SC_ATOMIC_DECLARE(unsigned int, use_cnt);

    void *data;

    struct THashData_ *next;
    struct THashData_ *prev;
} THashData;

typedef struct THashHashRow_ {
    HRLOCK_TYPE lock;
    THashData *head;
    THashData *tail;
} __attribute__((aligned(CLS))) THashHashRow;

typedef struct THashDataQueue_
{
    THashData *top;
    THashData *bot;
    uint32_t len;
#ifdef DBG_PERF
    uint32_t dbg_maxlen;
#endif /* DBG_PERF */
#ifdef HQLOCK_MUTEX
    SCMutex m;
#elif defined HQLOCK_SPIN
    SCSpinlock s;
#else
    #error Enable HQLOCK_SPIN or HQLOCK_MUTEX
#endif
} THashDataQueue;

#define THASH_VERBOSE    0
#define THASH_QUIET      1

typedef int (*THashOutputFunc)(void *output_ctx, const uint8_t *data, const uint32_t data_len);
typedef int (*THashFormatFunc)(const void *in_data, char *output, size_t output_size);

typedef struct THashDataConfig_ {
    uint64_t memcap;
    uint32_t hash_rand;
    uint32_t hash_size;
    uint32_t prealloc;

    uint32_t data_size;
    int (*DataSet)(void *dst, void *src);
    void (*DataFree)(void *);
    uint32_t (*DataHash)(void *);
    bool (*DataCompare)(void *, void *);
} THashConfig;

#define THASH_DATA_SIZE(ctx) (sizeof(THashData) + (ctx)->config.data_size)

typedef struct THashTableContext_ {
    /* array of rows indexed by the hash value % hash size */
    THashHashRow *array;

    SC_ATOMIC_DECLARE(uint64_t, memuse);
    SC_ATOMIC_DECLARE(uint32_t, counter);
    SC_ATOMIC_DECLARE(uint32_t, prune_idx);

    THashDataQueue spare_q;

    THashConfig config;

    /* flag set if memcap was reached at least once. */
    SC_ATOMIC_DECLARE(bool, memcap_reached);
} THashTableContext;

/** \brief check if a memory alloc would fit in the memcap
 *
 *  \param size memory allocation size to check
 *
 *  \retval 1 it fits
 *  \retval 0 no fit
 */
#define THASH_CHECK_MEMCAP(ctx, size) \
    ((((uint64_t)SC_ATOMIC_GET((ctx)->memuse) + (uint64_t)(size)) <= (ctx)->config.memcap))

#define THashIncrUsecnt(h) \
    (void)SC_ATOMIC_ADD((h)->use_cnt, 1)
#define THashDecrUsecnt(h) \
    (void)SC_ATOMIC_SUB((h)->use_cnt, 1)

#define THashReference(dst_h_ptr, h) do {            \
        if ((h) != NULL) {                          \
            THashIncrUsecnt((h));                    \
            *(dst_h_ptr) = h;                       \
        }                                           \
    } while (0)

#define THashDeReference(src_h_ptr) do {               \
        if (*(src_h_ptr) != NULL) {                   \
            THashDecrUsecnt(*(src_h_ptr));             \
            *(src_h_ptr) = NULL;                      \
        }                                             \
    } while (0)

THashTableContext *THashInit(const char *cnf_prefix, size_t data_size,
        int (*DataSet)(void *dst, void *src), void (*DataFree)(void *),
        uint32_t (*DataHash)(void *), bool (*DataCompare)(void *, void *), bool reset_memcap,
        uint64_t memcap, uint32_t hashsize);

void THashShutdown(THashTableContext *ctx);

static inline void THashDataLock(THashData *d)
{
    SCMutexLock(&d->m);
}

static inline void THashDataUnlock(THashData *d)
{
    SCMutexUnlock(&d->m);
}

struct THashDataGetResult {
    THashData *data;
    bool is_new;
};

struct THashDataGetResult THashGetFromHash (THashTableContext *ctx, void *data);
THashData *THashLookupFromHash (THashTableContext *ctx, void *data);
THashDataQueue *THashDataQueueNew(void);
void THashCleanup(THashTableContext *ctx);
int THashWalk(THashTableContext *, THashFormatFunc, THashOutputFunc, void *);
int THashRemoveFromHash (THashTableContext *ctx, void *data);
void THashConsolidateMemcap(THashTableContext *ctx);
void THashDataMoveToSpare(THashTableContext *ctx, THashData *h);

#endif /* __THASH_H__ */
