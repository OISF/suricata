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
 *  \file
 *
 *  \author Victor Julien <victor@inliniac.net>
 */

#ifndef __FLOW_HASH_H__
#define __FLOW_HASH_H__

#include "flow.h"

/** Spinlocks or Mutex for the flow buckets. */
//#define FBLOCK_SPIN
#define FBLOCK_MUTEX

#ifdef FBLOCK_SPIN
    #ifdef FBLOCK_MUTEX
        #error Cannot enable both FBLOCK_SPIN and FBLOCK_MUTEX
    #endif
#endif

/* flow hash bucket -- the hash is basically an array of these buckets.
 * Each bucket contains a flow or list of flows. All these flows have
 * the same hashkey (the hash is a chained hash). When doing modifications
 * to the list, the entire bucket is locked. */
typedef struct FlowBucket_ {
    /** head of the list of active flows for this row. */
    Flow *head;
    /** head of the list of evicted flows for this row. Waiting to be
     *  collected by the Flow Manager. */
    Flow *evicted;
#ifdef FBLOCK_MUTEX
    SCMutex m;
#elif defined FBLOCK_SPIN
    SCSpinlock s;
#else
    #error Enable FBLOCK_SPIN or FBLOCK_MUTEX
#endif
    /** timestamp in seconds of the earliest possible moment a flow
     *  will time out in this row. Set by the flow manager. Cleared
     *  to 0 by workers, either when new flows are added or when a
     *  flow state changes. The flow manager sets this to INT_MAX for
     *  empty buckets. */
    SC_ATOMIC_DECLARE(int32_t, next_ts);
} __attribute__((aligned(CLS))) FlowBucket;

#ifdef FBLOCK_SPIN
    #define FBLOCK_INIT(fb) SCSpinInit(&(fb)->s, 0)
    #define FBLOCK_DESTROY(fb) SCSpinDestroy(&(fb)->s)
    #define FBLOCK_LOCK(fb) SCSpinLock(&(fb)->s)
    #define FBLOCK_TRYLOCK(fb) SCSpinTrylock(&(fb)->s)
    #define FBLOCK_UNLOCK(fb) SCSpinUnlock(&(fb)->s)
#elif defined FBLOCK_MUTEX
    #define FBLOCK_INIT(fb) SCMutexInit(&(fb)->m, NULL)
    #define FBLOCK_DESTROY(fb) SCMutexDestroy(&(fb)->m)
    #define FBLOCK_LOCK(fb) SCMutexLock(&(fb)->m)
    #define FBLOCK_TRYLOCK(fb) SCMutexTrylock(&(fb)->m)
    #define FBLOCK_UNLOCK(fb) SCMutexUnlock(&(fb)->m)
#else
    #error Enable FBLOCK_SPIN or FBLOCK_MUTEX
#endif

/* prototypes */

Flow *FlowGetFlowFromHash(ThreadVars *tv, FlowLookupStruct *tctx, Packet *, Flow **);

Flow *FlowGetFromFlowKey(FlowKey *key, struct timespec *ttime, const uint32_t hash);
Flow *FlowGetExistingFlowFromFlowId(int64_t flow_id);
uint32_t FlowKeyGetHash(FlowKey *flow_key);

/** \note f->fb must be locked */
static inline void RemoveFromHash(Flow *f, Flow *prev_f)
{
    FlowBucket *fb = f->fb;

    /* remove from the hash */
    if (prev_f != NULL) {
        prev_f->next = f->next;
    } else {
        fb->head = f->next;
    }

    f->next = NULL;
    f->fb = NULL;
}

#endif /* __FLOW_HASH_H__ */

