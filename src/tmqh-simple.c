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
 *
 * Simple queue handler
 */

#include "suricata.h"
#include "packet-queue.h"
#include "decode.h"
#include "threads.h"
#include "threadvars.h"

#include "tm-queuehandlers.h"
#include "tmqh-simple.h"

Packet *TmqhInputSimple(ThreadVars *t);
void TmqhOutputSimple(ThreadVars *t, Packet *p);
void TmqhInputSimpleShutdownHandler(ThreadVars *);

void TmqhSimpleRegister (void)
{
    tmqh_table[TMQH_SIMPLE].name = "simple";
    tmqh_table[TMQH_SIMPLE].InHandler = TmqhInputSimple;
    tmqh_table[TMQH_SIMPLE].InShutdownHandler = TmqhInputSimpleShutdownHandler;
    tmqh_table[TMQH_SIMPLE].OutHandler = TmqhOutputSimple;
}

Packet *TmqhInputSimple(ThreadVars *t)
{
    PacketQueue *q = &trans_q[t->inq->id];

    StatsSyncCountersIfSignalled(t);

    SCMutexLock(&q->mutex_q);

    if (q->len == 0) {
        /* if we have no packets in queue, wait... */
        SCCondWait(&q->cond_q, &q->mutex_q);
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

void TmqhInputSimpleShutdownHandler(ThreadVars *tv)
{
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

/*******************************Generic-Q-Handlers*****************************/

/**
 * \brief Public version of TmqhInputSimple from the tmqh-simple queue
 *        handler, except that it is a generic version that is directly
 *        tied to a "SCDQDataQueue" instance(sent as an arg).
 *
 *        Retrieves a data_instance from the queue.  If the queue is empty, it
 *        waits on the queue, till a data_instance is enqueued into the queue
 *        by some other module.
 *
 *        All references to "data_instance" means a reference to a data structure
 *        instance that implements the template "struct SCDQGenericQData_".
 *
 * \param q The SCDQDataQueue instance to wait on.
 *
 * \retval p The returned packet from the queue.
 * \retval data The returned data_instance from the queue.
 */
SCDQGenericQData *TmqhInputSimpleOnQ(SCDQDataQueue *q)
{
    SCMutexLock(&q->mutex_q);
    if (q->len == 0) {
        /* if we have no packets in queue, wait... */
        SCCondWait(&q->cond_q, &q->mutex_q);
    }

    if (q->len > 0) {
        SCDQGenericQData *data = SCDQDataDequeue(q);
        SCMutexUnlock(&q->mutex_q);
        return data;
    } else {
        /* return NULL if we have no data in the queue. Should only happen
         * on signals. */
        SCMutexUnlock(&q->mutex_q);
        return NULL;
    }
}

/**
 * \brief Public version of TmqhOutputSimple from the tmqh-simple queue
 *        handler, except that it is a generic version that is directly
 *        tied to a SCDQDataQueue instance(sent as an arg).
 *
 *        Pumps out a data_instance into the queue.  If the queue is empty, it
 *        waits on the queue, till a data_instance is enqueued into the queue.
 *
 *        All references to "data_instance" means a reference to a data structure
 *        instance that implements the template "struct SCDQGenericQData_".
 *
 * \param q    The SCDQDataQueue instance to pump the data into.
 * \param data The data instance to be enqueued.
 */
void TmqhOutputSimpleOnQ(SCDQDataQueue *q, SCDQGenericQData *data)
{
    SCMutexLock(&q->mutex_q);
    SCDQDataEnqueue(q, data);
    SCCondSignal(&q->cond_q);
    SCMutexUnlock(&q->mutex_q);

    return;
}
