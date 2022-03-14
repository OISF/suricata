/* Copyright (C) 2007-2012 Open Information Security Foundation
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

#ifndef __DEFRAG_HASH_H__
#define __DEFRAG_HASH_H__

#include "decode.h"
#include "defrag.h"

/** Spinlocks or Mutex for the flow buckets. */
//#define DRLOCK_SPIN
#define DRLOCK_MUTEX

#ifdef DRLOCK_SPIN
    #ifdef DRLOCK_MUTEX
        #error Cannot enable both DRLOCK_SPIN and DRLOCK_MUTEX
    #endif
#endif

#ifdef DRLOCK_SPIN
    #define DRLOCK_TYPE SCSpinlock
    #define DRLOCK_INIT(fb) SCSpinInit(&(fb)->lock, 0)
    #define DRLOCK_DESTROY(fb) SCSpinDestroy(&(fb)->lock)
    #define DRLOCK_LOCK(fb) SCSpinLock(&(fb)->lock)
    #define DRLOCK_TRYLOCK(fb) SCSpinTrylock(&(fb)->lock)
    #define DRLOCK_UNLOCK(fb) SCSpinUnlock(&(fb)->lock)
#elif defined DRLOCK_MUTEX
    #define DRLOCK_TYPE SCMutex
    #define DRLOCK_INIT(fb) SCMutexInit(&(fb)->lock, NULL)
    #define DRLOCK_DESTROY(fb) SCMutexDestroy(&(fb)->lock)
    #define DRLOCK_LOCK(fb) SCMutexLock(&(fb)->lock)
    #define DRLOCK_TRYLOCK(fb) SCMutexTrylock(&(fb)->lock)
    #define DRLOCK_UNLOCK(fb) SCMutexUnlock(&(fb)->lock)
#else
    #error Enable DRLOCK_SPIN or DRLOCK_MUTEX
#endif

typedef struct DefragTrackerHashRow_ {
    DRLOCK_TYPE lock;
    DefragTracker *head;
    DefragTracker *tail;
} DefragTrackerHashRow;

/** defrag tracker hash table */
extern DefragTrackerHashRow *defragtracker_hash;

#define DEFRAG_VERBOSE    0
#define DEFRAG_QUIET      1

typedef struct DefragConfig_ {
    SC_ATOMIC_DECLARE(uint64_t, memcap);
    uint32_t hash_rand;
    uint32_t hash_size;
    uint32_t prealloc;
    enum ExceptionPolicy memcap_policy;
} DefragConfig;

/** \brief check if a memory alloc would fit in the memcap
 *
 *  \param size memory allocation size to check
 *
 *  \retval 1 it fits
 *  \retval 0 no fit
 */
#define DEFRAG_CHECK_MEMCAP(size) \
    ((((uint64_t)SC_ATOMIC_GET(defrag_memuse) + (uint64_t)(size)) <= SC_ATOMIC_GET(defrag_config.memcap)))

extern DefragConfig defrag_config;
SC_ATOMIC_EXTERN(uint64_t,defrag_memuse);
SC_ATOMIC_EXTERN(unsigned int,defragtracker_counter);
SC_ATOMIC_EXTERN(unsigned int,defragtracker_prune_idx);

void DefragInitConfig(char quiet);
void DefragHashShutdown(void);

DefragTracker *DefragLookupTrackerFromHash (Packet *);
DefragTracker *DefragGetTrackerFromHash (Packet *);
void DefragTrackerRelease(DefragTracker *);
void DefragTrackerClearMemory(DefragTracker *);
void DefragTrackerMoveToSpare(DefragTracker *);
uint32_t DefragTrackerSpareQueueGetSize(void);

int DefragTrackerSetMemcap(uint64_t);
uint64_t DefragTrackerGetMemcap(void);
uint64_t DefragTrackerGetMemuse(void);

#endif /* __DEFRAG_HASH_H__ */

