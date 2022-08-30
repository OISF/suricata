/* Copyright (C) 2007-2022 Open Information Security Foundation
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

#ifndef __FLOW_QUEUE_H__
#define __FLOW_QUEUE_H__

#include "suricata-common.h"
#include "flow.h"

/** Spinlocks or Mutex for the flow queues. */
//#define FQLOCK_SPIN
#define FQLOCK_MUTEX

#ifdef FQLOCK_SPIN
    #ifdef FQLOCK_MUTEX
        #error Cannot enable both FQLOCK_SPIN and FQLOCK_MUTEX
    #endif
#endif

typedef struct FlowQueuePrivate_
{
    Flow *top;
    Flow *bot;
    uint32_t len;
} FlowQueuePrivate;

/* Define a queue for storing flows */
typedef struct FlowQueue_
{
    FlowQueuePrivate priv;
    SC_ATOMIC_DECLARE(bool,non_empty);
#ifdef FQLOCK_MUTEX
    SCMutex m;
#elif defined FQLOCK_SPIN
    SCSpinlock s;
#else
    #error Enable FQLOCK_SPIN or FQLOCK_MUTEX
#endif
} FlowQueue;
#define qtop priv.top
#define qbot priv.bot
#define qlen priv.len

#ifdef FQLOCK_SPIN
    #define FQLOCK_INIT(q) SCSpinInit(&(q)->s, 0)
    #define FQLOCK_DESTROY(q) SCSpinDestroy(&(q)->s)
    #define FQLOCK_LOCK(q) SCSpinLock(&(q)->s)
    #define FQLOCK_TRYLOCK(q) SCSpinTrylock(&(q)->s)
    #define FQLOCK_UNLOCK(q) SCSpinUnlock(&(q)->s)
#elif defined FQLOCK_MUTEX
    #define FQLOCK_INIT(q) SCMutexInit(&(q)->m, NULL)
    #define FQLOCK_DESTROY(q) SCMutexDestroy(&(q)->m)
    #define FQLOCK_LOCK(q) SCMutexLock(&(q)->m)
    #define FQLOCK_TRYLOCK(q) SCMutexTrylock(&(q)->m)
    #define FQLOCK_UNLOCK(q) SCMutexUnlock(&(q)->m)
#else
    #error Enable FQLOCK_SPIN or FQLOCK_MUTEX
#endif

/* prototypes */
FlowQueue *FlowQueueNew(void);
FlowQueue *FlowQueueInit(FlowQueue *);
void FlowQueueDestroy (FlowQueue *);

void FlowEnqueue (FlowQueue *, Flow *);
Flow *FlowDequeue (FlowQueue *);
void FlowQueueRemove(FlowQueue *fq, Flow *f);
void FlowQueueRemoveLock(FlowQueue *fq, Flow *f);

void FlowQueuePrivateAppendFlow(FlowQueuePrivate *fqc, Flow *f);
void FlowQueuePrivatePrependFlow(FlowQueuePrivate *fqc, Flow *f);

void FlowQueueAppendPrivate(FlowQueue *fq, FlowQueuePrivate *fqp);
void FlowQueuePrivateAppendPrivate(FlowQueuePrivate *dest, FlowQueuePrivate *src);
FlowQueuePrivate FlowQueueExtractPrivate(FlowQueue *fq);
Flow *FlowQueuePrivateGetFromTop(FlowQueuePrivate *fqp);

#endif /* __FLOW_QUEUE_H__ */

