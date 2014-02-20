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
 * Packet Queue portion of the engine.
 */

#include "suricata-common.h"
#include "decode.h"
#include "packet-queue.h"
#include "threads.h"
#include "suricata.h"
#include "util-var.h"
#include "pkt-var.h"
#include "host.h"
#include "util-profiling.h"

#ifdef DEBUG
void PacketQueueValidateDebug(PacketQueue *q) {
    SCLogDebug("q->len %u, q->top %p, q->bot %p", q->len, q->top, q->bot);

    if (q->len == 0) {
        BUG_ON(q->top != NULL);
        BUG_ON(q->bot != NULL);
    } else if(q->len == 1) {
        SCLogDebug("q->top->next %p, q->top->prev %p", q->top->next, q->top->prev);
        SCLogDebug("q->bot->next %p, q->bot->prev %p", q->bot->next, q->bot->prev);

        BUG_ON(q->top != q->bot);
        BUG_ON(q->top->next != NULL);
        BUG_ON(q->bot->next != NULL);
        BUG_ON(q->top->prev != NULL);
        BUG_ON(q->bot->prev != NULL);
    } else if (q->len == 2) {
        SCLogDebug("q->top->next %p, q->top->prev %p", q->top->next, q->top->prev);
        SCLogDebug("q->bot->next %p, q->bot->prev %p", q->bot->next, q->bot->prev);

        BUG_ON(q->top == NULL);
        BUG_ON(q->bot == NULL);

        BUG_ON(q->top == q->bot);

        BUG_ON(q->top->prev != NULL);
        BUG_ON(q->top->next != q->bot);

        BUG_ON(q->bot->prev != q->top);
        BUG_ON(q->bot->next != NULL);
    } else {
        BUG_ON(q->top == NULL);
        BUG_ON(q->bot == NULL);

        SCLogDebug("q->top->next %p, q->top->prev %p", q->top->next, q->top->prev);
        SCLogDebug("q->bot->next %p, q->bot->prev %p", q->bot->next, q->bot->prev);

        BUG_ON(q->top == q->bot);
        BUG_ON(q->top->prev != NULL);
        BUG_ON(q->bot->next != NULL);

        BUG_ON(q->top->next == q->bot);
        BUG_ON(q->bot->prev == q->top);

        Packet *p, *pp;
        for (p = q->top, pp = p->prev; p != NULL; pp = p, p = p->next) {
            SCLogDebug("p %p, pp %p, p->next %p, p->prev %p", p, pp, p->next, p->prev);
            BUG_ON(pp != p->prev);
        }

    }
}

#define BUGGER_ON(cond) { \
    if ((cond)) { \
        PacketQueueValidateDebug(q); \
    } \
}

void PacketQueueValidate(PacketQueue *q) {
    if (q->len == 0) {
        BUGGER_ON(q->top != NULL);
        BUGGER_ON(q->bot != NULL);
    } else if(q->len == 1) {
        BUGGER_ON(q->top != q->bot);
        BUGGER_ON(q->top->next != NULL);
        BUGGER_ON(q->bot->next != NULL);
        BUGGER_ON(q->top->prev != NULL);
        BUGGER_ON(q->bot->prev != NULL);
    } else if (q->len == 2) {
        BUGGER_ON(q->top == NULL);
        BUGGER_ON(q->bot == NULL);

        BUGGER_ON(q->top == q->bot);

        BUGGER_ON(q->top->prev != NULL);
        BUGGER_ON(q->top->next != q->bot);

        BUGGER_ON(q->bot->prev != q->top);
        BUGGER_ON(q->bot->next != NULL);
    } else {
        BUGGER_ON(q->top == NULL);
        BUGGER_ON(q->bot == NULL);

        BUGGER_ON(q->top == q->bot);
        BUGGER_ON(q->top->prev != NULL);
        BUGGER_ON(q->bot->next != NULL);

        BUGGER_ON(q->top->next == q->bot);
        BUGGER_ON(q->bot->prev == q->top);

        Packet *p, *pp;
        for (p = q->top, pp = p->prev; p != NULL; pp = p, p = p->next) {
            BUGGER_ON(pp != p->prev);
        }

    }
}
#endif /* DEBUG */

void PacketEnqueue (PacketQueue *q, Packet *p) {
    //PacketQueueValidateDebug(q);

    if (p == NULL)
        return;

    /* more packets in queue */
    if (q->top != NULL) {
        p->prev = NULL;
        p->next = q->top;
        q->top->prev = p;
        q->top = p;
    /* only packet */
    } else {
        p->prev = NULL;
        p->next = NULL;
        q->top = p;
        q->bot = p;
    }
    q->len++;
#ifdef DBG_PERF
    if (q->len > q->dbg_maxlen)
        q->dbg_maxlen = q->len;
#endif /* DBG_PERF */
    //PacketQueueValidateDebug(q);
}

Packet *PacketDequeue (PacketQueue *q) {
    Packet *p = NULL;

    //PacketQueueValidateDebug(q);
    /* if the queue is empty there are no packets left. */
    if (q->len == 0) {
        return NULL;
    }

    q->len--;

    /* pull the bottom packet from the queue */
    p = q->bot;
    /* Weird issue: sometimes it looks that two thread arrive
     * here at the same time so the bot ptr is NULL (only on OS X?)
     */
    if (p == NULL) {
        return NULL;
    }

    /* more packets in queue */
    if (q->bot->prev != NULL) {
        q->bot = q->bot->prev;
        q->bot->next = NULL;
        /* just the one we remove, so now empty */
    } else {
        q->top = NULL;
        q->bot = NULL;
    }

    //PacketQueueValidateDebug(q);
    return p;
}

typedef struct PacketMultiQueue_ {
    SC_ATOMIC_DECLARE(uint32_t, idx);
    SC_ATOMIC_DECLARE(uint32_t, usage);
    uint32_t size;
    PacketQueue *queues;
} PacketMultiQueue;


/** \brief 2pass lookup for Packets
 *
 *  To reduce lock contention we start at a different position each
 *  time. We look up in 2 passed. The first pass uses trylock, and
 *  moves to the next queue immediately if a queue is locked. The 2nd
 *  pass does wait for a lock.
 *
 *  \retval p Packet or NULL if all queues were empty.
 */
Packet *PacketMultiQueueGet(PacketMultiQueue *pm_queue) {
    BUG_ON(pm_queue == NULL);
    uint32_t idx = SC_ATOMIC_GET(pm_queue->idx);
    idx %= pm_queue->size;
    BUG_ON(idx > pm_queue->size);
    Packet *p = NULL;
    uint32_t tried = 0;
    int pass = 0;

    /* no need to do any looping when we know we don't
     * have packets */
    if (SC_ATOMIC_GET(pm_queue->usage) == 0)
        return NULL;

    /* loop through our queues once */
    while (1) {
        /* we walk the queues in 2 passes. */
        if (tried >= pm_queue->size) {
            if (pass == 1)
                return NULL;

            tried = 0;
            pass = 1;
        }

        PacketQueue *q = &pm_queue->queues[idx];
        BUG_ON(q == NULL);

        if (pass == 1) {
            SCMutexLock(&q->mutex_q);
        } else {
            /* skip locked queues */
            if (SCMutexTrylock(&q->mutex_q) != 0) {
                tried++;
                idx++;
                if (idx >= pm_queue->size)
                    idx = 0;
                continue;
            }
        }

        /* have lock now */

        /* skip empty queues */
        if (q->len == 0) {
            SCMutexUnlock(&q->mutex_q);
            tried++;
            idx++;
            if (idx >= pm_queue->size)
                idx = 0;
            continue;

        }

        SC_ATOMIC_SUB(pm_queue->usage,1);
        p = PacketDequeue(q);
        BUG_ON(p == NULL); // can't fail as we have lock and q->len != 0
        SCMutexUnlock(&q->mutex_q);
        break;
    }
    SC_ATOMIC_ADD(pm_queue->idx, 1);
    return p;
}

void PacketQueueInit(PacketQueue *pq)
{
    SCMutexInit(&pq->mutex_q, NULL);
}

void PacketQueueDeinit(PacketQueue *pq)
{
    SCMutexDestroy(&pq->mutex_q);
}

/** \brief Put a packet in the queue
 *
 *  Consider 2 things: (1) pick a queue that isn't locked, but (2) make sure to keep things somewhat balanced.
 */
void PacketMultiQueuePut(PacketMultiQueue *pm_queue, Packet *p) {
    BUG_ON(pm_queue == NULL||p == NULL);

    uint32_t idx = SC_ATOMIC_GET(pm_queue->idx);
    idx %= pm_queue->size;
    BUG_ON(idx > pm_queue->size);

    while (1) {
        PacketQueue *q = &pm_queue->queues[idx];

        /* skip locked queues */
        if (SCMutexTrylock(&q->mutex_q) != 0) {
            idx++;
            if (idx >= pm_queue->size)
                idx = 0;
            continue;
        }

        /* queue is now locked */

        /* empty queue, put it in here */
        if (q->len == 0) {
            PacketEnqueue(q,p);
            SC_ATOMIC_ADD(pm_queue->usage,1);
            SCMutexUnlock(&q->mutex_q);
            break; /* done */

        /* non-empty. We need to check the balance:
           threshold is: total in our multi queue, devided by num queues, times 2 */
        } else {
            uint32_t usage = SC_ATOMIC_GET(pm_queue->usage);
            if (q->len > (2 * (usage / pm_queue->size))) {
                SCMutexUnlock(&q->mutex_q);
                /* too many in queue already, try the next */
                idx++;
                if (idx >= pm_queue->size)
                    idx = 0;
                continue;
            } else {
                PacketEnqueue(q,p);
                SC_ATOMIC_ADD(pm_queue->usage,1);
                SCMutexUnlock(&q->mutex_q);
                break;
            }
        }
    }
    SC_ATOMIC_ADD(pm_queue->idx, 1);
}

PacketMultiQueue *PacketMultiQueueInit(uint32_t nqueues, uint32_t npackets)
{
    PacketMultiQueue *pm = SCMalloc(sizeof(*pm));
    BUG_ON(pm == NULL);
    memset(pm, 0x00, sizeof(*pm));
    SC_ATOMIC_INIT(pm->usage);
    SC_ATOMIC_INIT(pm->idx);
    pm->queues = SCMalloc(nqueues * sizeof(PacketQueue));
    BUG_ON(pm->queues == NULL);
    memset(pm->queues, 0x00, (nqueues * sizeof(PacketQueue)));
    pm->size = nqueues;
    uint32_t u;
    for (u = 0; u < nqueues; u++) {
        PacketQueue *pq = &pm->queues[u];
        BUG_ON(pq == NULL);
        PacketQueueInit(pq);
    }

    for (u = 0; u < npackets; u++) {
        Packet *p = PacketGetFromAlloc();
        if (unlikely(p == NULL)) {
            SCLogError(SC_ERR_FATAL, "Fatal error encountered while allocating a packet. Exiting...");
            exit(EXIT_FAILURE);
        }
        p->flags &= ~PKT_ALLOC;
        PacketMultiQueuePut(pm, p);
    }

    return pm;
}

void PacketMultiQueueDestroy(PacketMultiQueue *pm) {
    BUG_ON(pm == NULL);

    uint32_t packets = SC_ATOMIC_GET(pm->usage);
    while (packets--) {
        Packet *p = PacketMultiQueueGet(pm);
        BUG_ON(p == NULL);
        PACKET_CLEANUP(p);
        PacketFree(p);
    }

    uint32_t u;
    for (u = 0; u < pm->size; u++) {
        PacketQueue *pq = &pm->queues[u];
        BUG_ON(pq == NULL);
        PacketQueueDeinit(pq);
    }

    SCFree(pm->queues);
    SC_ATOMIC_DESTROY(pm->usage);
    SC_ATOMIC_DESTROY(pm->idx);
    SCFree(pm);
}

static PacketMultiQueue *pseudo_packet_mq = NULL;

void PseudoPacketQueueInit(uint32_t nqueues, uint32_t npackets)
{
    BUG_ON(pseudo_packet_mq != NULL);
    pseudo_packet_mq = PacketMultiQueueInit(nqueues, npackets);
    BUG_ON(pseudo_packet_mq == NULL);
}

void PseudoPacketQueueDestroy(void)
{
    BUG_ON(pseudo_packet_mq == NULL);
    PacketMultiQueueDestroy(pseudo_packet_mq);
    pseudo_packet_mq = NULL;
    BUG_ON(pseudo_packet_mq != NULL);
}

void PseudoPacketPut(Packet *p)
{
    BUG_ON(pseudo_packet_mq == NULL);
    PacketMultiQueuePut(pseudo_packet_mq, p);
}

Packet *PseudoPacketGet(void)
{
    BUG_ON(pseudo_packet_mq == NULL);
    Packet *p = PacketMultiQueueGet(pseudo_packet_mq);
    if (p != NULL) {
        PACKET_RECYCLE(p);
        p->ReleasePacket = PseudoPacketPut;
        PACKET_PROFILING_START(p);
    }
    return p;
}
