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

#ifdef DEBUG
void PacketQueueValidateDebug(PacketQueue *q)
{
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

void PacketQueueValidate(PacketQueue *q)
{
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

void PacketEnqueue (PacketQueue *q, Packet *p)
{
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

Packet *PacketDequeue (PacketQueue *q)
{
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

