/* Copyright (C) 2007-2010 Open Information Security Foundation
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
 * Flow queue handler functions
 */

#include "suricata-common.h"
#include "threads.h"
#include "debug.h"
#include "flow-private.h"
#include "flow-queue.h"
#include "flow-util.h"
#include "util-error.h"
#include "util-debug.h"
#include "util-print.h"
#include <string.h>

FlowQueue *FlowQueueNew() {
    FlowQueue *q = (FlowQueue *)SCMalloc(sizeof(FlowQueue));
    if (q == NULL) {
        SCLogError(SC_ERR_FATAL, "Fatal error encountered in FlowQueueNew. Exiting...");
        exit(EXIT_SUCCESS);
    }
    q = FlowQueueInit(q);
    return q;
}

FlowQueue *FlowQueueInit (FlowQueue *q) {
    if (q != NULL) {
        memset(q, 0, sizeof(FlowQueue));
        SCMutexInit(&q->mutex_q, NULL);
        SCCondInit(&q->cond_q, NULL);
    }
    return q;
}

/**
 *  \brief Destroy a flow queue
 *
 *  \param q the flow queue to destroy
 */
void FlowQueueDestroy (FlowQueue *q) {
    SCMutexDestroy(&q->mutex_q);
    SCCondDestroy(&q->cond_q);
}

/**
 *  \brief add a flow to a queue
 *
 *  \param q queue
 *  \param f flow
 */
void FlowEnqueue (FlowQueue *q, Flow *f) {
#ifdef DEBUG
    BUG_ON(q == NULL || f == NULL);
#endif

    SCMutexLock(&q->mutex_q);
    /* more flows in queue */
    if (q->top != NULL) {
        f->lnext = q->top;
        q->top->lprev = f;
        q->top = f;
    /* only flow */
    } else {
        q->top = f;
        q->bot = f;
    }
    q->len++;
#ifdef DBG_PERF
    if (q->len > q->dbg_maxlen)
        q->dbg_maxlen = q->len;
#endif /* DBG_PERF */
    SCMutexUnlock(&q->mutex_q);
}

/**
 *  \brief remove a flow from the queue
 *
 *  \param q queue
 *
 *  \retval f flow or NULL if empty list.
 */
Flow *FlowDequeue (FlowQueue *q) {
    SCMutexLock(&q->mutex_q);

    Flow *f = q->bot;
    if (f == NULL) {
        SCMutexUnlock(&q->mutex_q);
        return NULL;
    }

    /* more packets in queue */
    if (q->bot->lprev != NULL) {
        q->bot = q->bot->lprev;
        q->bot->lnext = NULL;
    /* just the one we remove, so now empty */
    } else {
        q->top = NULL;
        q->bot = NULL;
    }

#ifdef DEBUG
    BUG_ON(q->len == 0);
#endif
    if (q->len > 0)
        q->len--;

    f->lnext = NULL;
    f->lprev = NULL;

    SCMutexUnlock(&q->mutex_q);
    return f;
}

/**
 *  \brief Transfer a flow from one queue to another
 *
 *  \param f the flow to be transfered
 *  \param srcq the source queue, where the flow will be removed.
 *  \param dstq the dest queue where the flow will be placed
 *
 *  \note srcq and dstq must be different queues.
 */
void FlowRequeue(Flow *f, FlowQueue *srcq, FlowQueue *dstq)
{
#ifdef DEBUG
    BUG_ON(srcq == NULL || dstq == NULL || srcq == dstq);
#endif /* DEBUG */

    SCMutexLock(&srcq->mutex_q);

    /* remove from old queue */
    if (srcq->top == f)
        srcq->top = f->lnext;       /* remove from queue top */
    if (srcq->bot == f)
        srcq->bot = f->lprev;       /* remove from queue bot */
    if (f->lprev != NULL)
        f->lprev->lnext = f->lnext; /* remove from flow prev */
    if (f->lnext != NULL)
        f->lnext->lprev = f->lprev; /* remove from flow next */

#ifdef DEBUG
    BUG_ON(srcq->len == 0);
#endif
    if (srcq->len > 0)
        srcq->len--; /* adjust len */

    f->lnext = NULL;
    f->lprev = NULL;

    SCMutexUnlock(&srcq->mutex_q);

    SCMutexLock(&dstq->mutex_q);

    /* add to new queue (append) */
    f->lprev = dstq->bot;
    if (f->lprev != NULL)
        f->lprev->lnext = f;
    f->lnext = NULL;
    dstq->bot = f;
    if (dstq->top == NULL)
        dstq->top = f;

    dstq->len++;
#ifdef DBG_PERF
    if (dstq->len > dstq->dbg_maxlen)
        dstq->dbg_maxlen = dstq->len;
#endif /* DBG_PERF */

    SCMutexUnlock(&dstq->mutex_q);
}

/**
 *  \brief Move flow to bottom of queue
 *
 *  \param f the flow to be transfered
 *  \param q the queue
 */
void FlowRequeueMoveToBot(Flow *f, FlowQueue *q)
{
#ifdef DEBUG
    BUG_ON(q == NULL || f == NULL);
#endif /* DEBUG */

    SCMutexLock(&q->mutex_q);

    /* remove from the queue */
    if (q->top == f)
        q->top = f->lnext;       /* remove from queue top */
    if (q->bot == f)
        q->bot = f->lprev;       /* remove from queue bot */
    if (f->lprev != NULL)
        f->lprev->lnext = f->lnext; /* remove from flow prev */
    if (f->lnext != NULL)
        f->lnext->lprev = f->lprev; /* remove from flow next */

    /* readd to the queue (append) */
    f->lprev = q->bot;

    if (f->lprev != NULL)
        f->lprev->lnext = f;

    f->lnext = NULL;

    q->bot = f;

    if (q->top == NULL)
        q->top = f;

    SCMutexUnlock(&q->mutex_q);
}

/**
 *  \brief Transfer a flow from a queue to the spare queue
 *
 *  \param f the flow to be transfered
 *  \param q the source queue, where the flow will be removed. This queue is locked.
 *
 *  \note spare queue needs locking
 */
void FlowRequeueMoveToSpare(Flow *f, FlowQueue *q)
{
#ifdef DEBUG
    BUG_ON(q == NULL || f == NULL);
#endif /* DEBUG */

    /* remove from old queue */
    if (q->top == f)
        q->top = f->lnext;       /* remove from queue top */
    if (q->bot == f)
        q->bot = f->lprev;       /* remove from queue bot */
    if (f->lprev != NULL)
        f->lprev->lnext = f->lnext; /* remove from flow prev */
    if (f->lnext != NULL)
        f->lnext->lprev = f->lprev; /* remove from flow next */
#ifdef DEBUG
    BUG_ON(q->len == 0);
#endif
    if (q->len > 0)
        q->len--; /* adjust len */

    f->lnext = NULL;
    f->lprev = NULL;

    /* now put it in spare */
    SCMutexLock(&flow_spare_q.mutex_q);

    /* add to new queue (append) */
    f->lprev = flow_spare_q.bot;
    if (f->lprev != NULL)
        f->lprev->lnext = f;
    f->lnext = NULL;
    flow_spare_q.bot = f;
    if (flow_spare_q.top == NULL)
        flow_spare_q.top = f;

    flow_spare_q.len++;
#ifdef DBG_PERF
    if (flow_spare_q.len > flow_spare_q.dbg_maxlen)
        flow_spare_q.dbg_maxlen = flow_spare_q.len;
#endif /* DBG_PERF */

    SCMutexUnlock(&flow_spare_q.mutex_q);
}

