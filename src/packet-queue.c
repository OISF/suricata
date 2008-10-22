/* Copyright (c) 2008 Victor Julien <victor@inliniac.net> */

#include "vips.h"
#include "decode.h"
#include "packet-queue.h"

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
        printf("PacketDequeue: queue is empty, waiting...\n");
        usleep(100000); /* sleep 100ms */
        return PacketDequeue(q);
    }

    /* pull the bottom packet from the queue */
    Packet *p = q->bot;

    /* more packets in queue */
    if (q->bot->prev != NULL) {
        q->bot = q->bot->prev;
        q->bot->next = NULL;
        /* just the one we remove, so now empty */
    } else {
        q->top = NULL;
        q->bot = NULL;
    }
    q->len--;

    p->next = NULL;
    p->prev = NULL;
    return p;
}

