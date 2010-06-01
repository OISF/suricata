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
 * Simple queue handler
 */

#include "suricata.h"
#include "packet-queue.h"
#include "decode.h"
#include "threads.h"
#include "threadvars.h"

#include "tm-queuehandlers.h"

Packet *TmqhInputSimple(ThreadVars *t);
void TmqhOutputSimple(ThreadVars *t, Packet *p);
void TmqhInputSimpleShutdownHandler(ThreadVars *);

void TmqhSimpleRegister (void) {
    tmqh_table[TMQH_SIMPLE].name = "simple";
    tmqh_table[TMQH_SIMPLE].InHandler = TmqhInputSimple;
    tmqh_table[TMQH_SIMPLE].InShutdownHandler = TmqhInputSimpleShutdownHandler;
    tmqh_table[TMQH_SIMPLE].OutHandler = TmqhOutputSimple;
}

Packet *TmqhInputSimple(ThreadVars *t)
{
    PacketQueue *q = &trans_q[t->inq->id];

    SCMutexLock(&q->mutex_q);

    if (q->len == 0) {
        /* if we have no packets in queue, wait... */
        SCondWait(&q->cond_q, &q->mutex_q);
    }

    if (t->sc_perf_pctx.perf_flag == 1)
        SCPerfUpdateCounterArray(t->sc_perf_pca, &t->sc_perf_pctx, 0);

    if (q->len > 0) {
        Packet *p = PacketDequeue(q);
        SCMutexUnlock(&q->mutex_q);
        return p;
    } else {
        /* return NULL if we have no pkt. Should only happen on signals. */
        SCMutexUnlock(&q->mutex_q);
        return NULL;
    }
}

void TmqhInputSimpleShutdownHandler(ThreadVars *tv) {
    int i;

    if (tv == NULL || tv->inq == NULL) {
        return;
    }

    for (i = 0; i < (tv->inq->reader_cnt + tv->inq->writer_cnt); i++)
        SCCondSignal(&trans_q[tv->inq->id].cond_q);
}

void TmqhOutputSimple(ThreadVars *t, Packet *p)
{
    SCLogDebug("Packet %p, p->root %p, alloced %s", p, p->root, p->flags & PKT_ALLOC ? "true":"false");

    PacketQueue *q = &trans_q[t->outq->id];

    SCMutexLock(&q->mutex_q);
    PacketEnqueue(q, p);
    SCCondSignal(&q->cond_q);
    SCMutexUnlock(&q->mutex_q);
}

/**
 * \brief Public version of TmqhInputSimple from the tmqh-simple queue
 *        handler, except that it is a generic version that is directly
 *        tied to a PacketQueue instance.
 *
 *        Retrieves a packet from the queue.  If the queue is empty, it waits
 *        on the queue, till a packet is enqueued into the queue.
 *
 * \param q The PacketQueue instance to wait on.
 *
 * \retval p The returned packet from the queue.
 */
Packet *TmqhInputSimpleOnQ(PacketQueue *q)
{
    SCMutexLock(&q->mutex_q);
    if (q->len == 0) {
        /* if we have no packets in queue, wait... */
        SCondWait(&q->cond_q, &q->mutex_q);
    }

    if (q->len > 0) {
        Packet *p = PacketDequeue(q);
        SCMutexUnlock(&q->mutex_q);
        return p;
    } else {
        /* return NULL if we have no pkt. Should only happen on signals. */
        SCMutexUnlock(&q->mutex_q);
        return NULL;
    }
}

/**
 * \brief Public version of TmqhOutputSimple from the tmqh-simple queue
 *        handler, except that it is a generic version that is directly
 *        tied to a PacketQueue instance.
 *
 *        Enqueues a packet into the packet queue.
 *
 * \param q The PacketQueue instance to enqueue the packet into.
 * \param p The packet to be enqueued into the above queue.
 */
void TmqhOutputSimpleOnQ(PacketQueue *q, Packet *p)
{
    SCMutexLock(&q->mutex_q);
    PacketEnqueue(q, p);
    SCCondSignal(&q->cond_q);
    SCMutexUnlock(&q->mutex_q);
}
