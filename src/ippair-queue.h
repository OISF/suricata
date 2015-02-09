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

#ifndef __IPPAIR_QUEUE_H__
#define __IPPAIR_QUEUE_H__

#include "suricata-common.h"
#include "ippair.h"

/** Spinlocks or Mutex for the ippair queues. */
//#define HQLOCK_SPIN
#define HQLOCK_MUTEX

#ifdef HQLOCK_SPIN
    #ifdef HQLOCK_MUTEX
        #error Cannot enable both HQLOCK_SPIN and HQLOCK_MUTEX
    #endif
#endif

/* Define a queue for storing ippairs */
typedef struct IPPairQueue_
{
    IPPair *top;
    IPPair *bot;
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
} IPPairQueue;

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

/* prototypes */
IPPairQueue *IPPairQueueNew();
IPPairQueue *IPPairQueueInit(IPPairQueue *);
void IPPairQueueDestroy (IPPairQueue *);

void IPPairEnqueue (IPPairQueue *, IPPair *);
IPPair *IPPairDequeue (IPPairQueue *);
uint32_t IPPairQueueLen(IPPairQueue *);

#endif /* __IPPAIR_QUEUE_H__ */
