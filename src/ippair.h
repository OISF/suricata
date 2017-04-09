/* Copyright (C) 2007-2013 Open Information Security Foundation
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

#ifndef __IPPAIR_H__
#define __IPPAIR_H__

#include "decode.h"
#include "util-storage.h"

/** Spinlocks or Mutex for the flow buckets. */
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

typedef struct IPPair_ {
    /** ippair mutex */
    SCMutex m;

    /** ippair addresses -- ipv4 or ipv6 */
    Address a[2];

    /** use cnt, reference counter */
    SC_ATOMIC_DECLARE(unsigned int, use_cnt);

    /** storage api handle */
    Storage *storage;

    /** hash pointers, protected by hash row mutex/spin */
    struct IPPair_ *hnext;
    struct IPPair_ *hprev;

    /** list pointers, protected by ippair-queue mutex/spin */
    struct IPPair_ *lnext;
    struct IPPair_ *lprev;
} IPPair;

typedef struct IPPairHashRow_ {
    HRLOCK_TYPE lock;
    IPPair *head;
    IPPair *tail;
} __attribute__((aligned(CLS))) IPPairHashRow;

/** ippair hash table */
IPPairHashRow *ippair_hash;

#define IPPAIR_VERBOSE    0
#define IPPAIR_QUIET      1

typedef struct IPPairConfig_ {
    uint64_t memcap;
    uint32_t hash_rand;
    uint32_t hash_size;
    uint32_t prealloc;
} IPPairConfig;

/** \brief check if a memory alloc would fit in the memcap
 *
 *  \param size memory allocation size to check
 *
 *  \retval 1 it fits
 *  \retval 0 no fit
 */
#define IPPAIR_CHECK_MEMCAP(size) \
    ((((uint64_t)SC_ATOMIC_GET(ippair_memuse) + (uint64_t)(size)) <= ippair_config.memcap))

#define IPPairIncrUsecnt(h) \
    (void)SC_ATOMIC_ADD((h)->use_cnt, 1)
#define IPPairDecrUsecnt(h) \
    (void)SC_ATOMIC_SUB((h)->use_cnt, 1)

#define IPPairReference(dst_h_ptr, h) do {            \
        if ((h) != NULL) {                          \
            IPPairIncrUsecnt((h));                    \
            *(dst_h_ptr) = h;                       \
        }                                           \
    } while (0)

#define IPPairDeReference(src_h_ptr) do {               \
        if (*(src_h_ptr) != NULL) {                   \
            IPPairDecrUsecnt(*(src_h_ptr));             \
            *(src_h_ptr) = NULL;                      \
        }                                             \
    } while (0)

IPPairConfig ippair_config;
SC_ATOMIC_DECLARE(uint64_t,ippair_memuse);
SC_ATOMIC_DECLARE(uint32_t,ippair_counter);
SC_ATOMIC_DECLARE(uint32_t,ippair_prune_idx);

void IPPairInitConfig(char quiet);
void IPPairShutdown(void);
void IPPairCleanup(void);

IPPair *IPPairLookupIPPairFromHash (Address *, Address *);
IPPair *IPPairGetIPPairFromHash (Address *, Address *);
void IPPairRelease(IPPair *);
void IPPairLock(IPPair *);
void IPPairClearMemory(IPPair *);
void IPPairMoveToSpare(IPPair *);
uint32_t IPPairSpareQueueGetSize(void);
void IPPairPrintStats (void);

void IPPairRegisterUnittests(void);

IPPair *IPPairAlloc(void);
void IPPairFree(IPPair *);

void IPPairLock(IPPair *);
void IPPairUnlock(IPPair *);

#endif /* __IPPAIR_H__ */
