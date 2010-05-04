/* Copyright (C) 2007-2010 Victor Julien <victor@inliniac.net>
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

void PacketEnqueue (PacketQueue *q, Packet *p) {
    /* more packets in queue */
    if (q->top != NULL) {
        p->next = q->top;
        q->top->prev = p;
        q->top = p;
    /* only packet */
    } else {
        q->top = p;
        q->bot = p;
    }
    q->len++;
#ifdef DBG_PERF
    if (q->len > q->dbg_maxlen)
        q->dbg_maxlen = q->len;
#endif /* DBG_PERF */
}

Packet *PacketDequeue (PacketQueue *q) {
    /* if the queue is empty there are no packets left.
     * In that case we sleep and try again. */
    if (q->len == 0) {
//        printf("PacketDequeue: queue is empty, waiting...\n");
//        TmqDebugList();
//        usleep(100000); /* sleep 100ms */
//        return PacketDequeue(q);
        return NULL;
    }

    /* If we are going to get the last packet, set len to 0
     * before doing anything else (to make the threads to follow
     * the SCondWait as soon as possible) */
    q->len--;

    /* pull the bottom packet from the queue */
    Packet *p = q->bot;

#ifdef OS_DARWIN
    /* Weird issue in OS_DARWIN
     * Sometimes it looks that two thread arrive here at the same time
     * so the bot ptr is NULL
     */
    if (p == NULL) {
        printf("No packet to dequeue!\n");
        return NULL;
    }
#endif

    /* more packets in queue */
    if (q->bot->prev != NULL) {
        q->bot = q->bot->prev;
        q->bot->next = NULL;
        /* just the one we remove, so now empty */
    } else {
        q->top = NULL;
        q->bot = NULL;
    }

    p->next = NULL;
    p->prev = NULL;
    return p;
}

