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

static u_int32_t dbg_packetdequeue = 0;

Packet *PacketDequeue (PacketQueue *q) {
    Packet *p = q->bot;
    if (p == NULL) {
        /* queue empty, alloc a new packet */
        p = malloc(sizeof(Packet));
        if (p == NULL) {
            printf("ERROR: malloc failed: %s\n", strerror(errno));
            return NULL;
        }

        CLEAR_TCP_PACKET(p);
        CLEAR_PACKET(p);

        dbg_packetdequeue++;
        printf("PacketDequeue: alloced a new packet. MAX_PENDING %u, extra alloc: %u\n", MAX_PENDING, dbg_packetdequeue);
    } else {
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
    }
    p->next = NULL;
    p->prev = NULL;
    return p;
}

