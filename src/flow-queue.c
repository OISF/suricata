/* Copyright (C) 2007-2020 Open Information Security Foundation
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
#include "flow-private.h"
#include "flow-queue.h"

FlowQueue *FlowQueueNew()
{
    FlowQueue *q = (FlowQueue *)SCMalloc(sizeof(FlowQueue));
    if (q == NULL) {
        SCLogError(SC_ERR_FATAL, "Fatal error encountered in FlowQueueNew. Exiting...");
        exit(EXIT_SUCCESS);
    }
    q = FlowQueueInit(q);
    return q;
}

FlowQueue *FlowQueueInit (FlowQueue *q)
{
    if (q != NULL) {
        memset(q, 0, sizeof(FlowQueue));
        FQLOCK_INIT(q);
    }
    return q;
}

/**
 *  \brief Destroy a flow queue
 *
 *  \param q the flow queue to destroy
 */
void FlowQueueDestroy (FlowQueue *q)
{
    FQLOCK_DESTROY(q);
}

void FlowQueuePrivateAppendFlow(FlowQueuePrivate *fqc, Flow *f)
{
    if (fqc->top == NULL) {
        fqc->top = fqc->bot = f;
        fqc->len = 1;
    } else {
        fqc->bot->next = f;
        fqc->bot = f;
        fqc->len++;
    }
    f->next = NULL;
}

void FlowQueuePrivatePrependFlow(FlowQueuePrivate *fqc, Flow *f)
{
    f->next = fqc->top;
    fqc->top = f;
    if (f->next == NULL) {
        fqc->bot = f;
    }
    fqc->len++;
}

void FlowQueuePrivateAppendPrivate(FlowQueuePrivate *dest, FlowQueuePrivate *src)
{
    if (src->top == NULL)
        return;

    if (dest->bot == NULL) {
        dest->top = src->top;
        dest->bot = src->bot;
        dest->len = src->len;
    } else {
        dest->bot->next = src->top;
        dest->bot = src->bot;
        dest->len += src->len;
    }
    src->top = src->bot = NULL;
    src->len = 0;
}

static inline void FlowQueueAtomicSetNonEmpty(FlowQueue *fq)
{
    if (SC_ATOMIC_GET(fq->non_empty) == false) {
        SC_ATOMIC_SET(fq->non_empty, true);
    }
}
static inline void FlowQueueAtomicSetEmpty(FlowQueue *fq)
{
    if (SC_ATOMIC_GET(fq->non_empty) == true) {
        SC_ATOMIC_SET(fq->non_empty, false);
    }
}

void FlowQueueAppendPrivate(FlowQueue *fq, FlowQueuePrivate *fqc)
{
    if (fqc->top == NULL)
        return;

    FQLOCK_LOCK(fq);
    if (fq->qbot == NULL) {
        fq->qtop = fqc->top;
        fq->qbot = fqc->bot;
        fq->qlen = fqc->len;
    } else {
        fq->qbot->next = fqc->top;
        fq->qbot = fqc->bot;
        fq->qlen += fqc->len;
    }
    FlowQueueAtomicSetNonEmpty(fq);
    FQLOCK_UNLOCK(fq);
    fqc->top = fqc->bot = NULL;
    fqc->len = 0;
}

FlowQueuePrivate FlowQueueExtractPrivate(FlowQueue *fq)
{
    FQLOCK_LOCK(fq);
    FlowQueuePrivate fqc = fq->priv;
    fq->qtop = fq->qbot = NULL;
    fq->qlen = 0;
    FlowQueueAtomicSetEmpty(fq);
    FQLOCK_UNLOCK(fq);
    return fqc;
}

Flow *FlowQueuePrivateGetFromTop(FlowQueuePrivate *fqc)
{
    Flow *f = fqc->top;
    if (f == NULL) {
        return NULL;
    }

    fqc->top = f->next;
    f->next = NULL;
    fqc->len--;
    if (fqc->top == NULL) {
        fqc->bot = NULL;
    }
    return f;
}

/**
 *  \brief add a flow to a queue
 *
 *  \param q queue
 *  \param f flow
 */
void FlowEnqueue (FlowQueue *q, Flow *f)
{
#ifdef DEBUG
    BUG_ON(q == NULL || f == NULL);
#endif
    FQLOCK_LOCK(q);
    FlowQueuePrivateAppendFlow(&q->priv, f);
    FlowQueueAtomicSetNonEmpty(q);
    FQLOCK_UNLOCK(q);
}

/**
 *  \brief remove a flow from the queue
 *
 *  \param q queue
 *
 *  \retval f flow or NULL if empty list.
 */
Flow *FlowDequeue (FlowQueue *q)
{
    FQLOCK_LOCK(q);
    Flow *f = FlowQueuePrivateGetFromTop(&q->priv);
    if (f == NULL)
        FlowQueueAtomicSetEmpty(q);
    FQLOCK_UNLOCK(q);
    return f;
}
