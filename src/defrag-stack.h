/* Copyright (C) 2007-2024 Open Information Security Foundation
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

#ifndef SURICATA_DEFRAG_QUEUE_H
#define SURICATA_DEFRAG_QUEUE_H

#include "suricata-common.h"
#include "defrag.h"

/** Spinlocks or Mutex for the defrag tracker queues. */
//#define DQLOCK_SPIN
#define DQLOCK_MUTEX

#ifdef DQLOCK_SPIN
#ifdef DQLOCK_MUTEX
#error Cannot enable both DQLOCK_SPIN and DQLOCK_MUTEX
#endif
#endif

/* Define a queue for storing defrag trackers */
typedef struct DefragTrackerStack_ {
    DefragTracker *s;
    uint32_t len;
#ifdef DBG_PERF
    uint32_t dbg_maxlen;
#endif /* DBG_PERF */
#ifdef DQLOCK_MUTEX
    SCMutex m;
#elif defined DQLOCK_SPIN
    SCSpinlock s;
#else
#error Enable DQLOCK_SPIN or DQLOCK_MUTEX
#endif
} DefragTrackerStack;

#ifdef DQLOCK_SPIN
#define DQLOCK_INIT(q)    SCSpinInit(&(q)->s, 0)
#define DQLOCK_DESTROY(q) SCSpinDestroy(&(q)->s)
#define DQLOCK_LOCK(q)    SCSpinLock(&(q)->s)
#define DQLOCK_TRYLOCK(q) SCSpinTrylock(&(q)->s)
#define DQLOCK_UNLOCK(q)  SCSpinUnlock(&(q)->s)
#elif defined DQLOCK_MUTEX
#define DQLOCK_INIT(q)    SCMutexInit(&(q)->m, NULL)
#define DQLOCK_DESTROY(q) SCMutexDestroy(&(q)->m)
#define DQLOCK_LOCK(q)    SCMutexLock(&(q)->m)
#define DQLOCK_TRYLOCK(q) SCMutexTrylock(&(q)->m)
#define DQLOCK_UNLOCK(q)  SCMutexUnlock(&(q)->m)
#else
#error Enable DQLOCK_SPIN or DQLOCK_MUTEX
#endif

/* prototypes */
DefragTrackerStack *DefragTrackerStackInit(DefragTrackerStack *);
void DefragTrackerStackDestroy(DefragTrackerStack *);

void DefragTrackerEnqueue(DefragTrackerStack *, DefragTracker *);
DefragTracker *DefragTrackerDequeue(DefragTrackerStack *);
uint32_t DefragTrackerStackSize(DefragTrackerStack *q);

#endif /* SURICATA_DEFRAG_QUEUE_H */
