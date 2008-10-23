/* Copyright (c) 2008 Victor Julien <victor@inliniac.net> */

#include "vips.h"
#include "decode.h"
#include "packet-queue.h"
#include "threads.h"

void PacketEnqueue (PacketQueue *q, Packet *p) {
    if (IS_TUNNEL_PKT(p)) {
        /* get a lock */
        pthread_mutex_t *m = p->root ? &p->root->mutex_rtv_cnt : &p->mutex_rtv_cnt;
        mutex_lock(m);

        if (IS_TUNNEL_ROOT_PKT(p)) {
            if (TUNNEL_PKT_TPR(p) == 0) {
                /* if this packet is the root and there are no
                 * more tunnel packets, enqueue it */

                /* fall through */
            } else {
                /* if this is the root and there are more tunnel
                 * packets, don't add this. It's still referenced
                 * by the tunnel packets, and we will enqueue it
                 * when we handle them */
                p->tunnel_verdicted = 1;
                mutex_unlock(m);
                return;
            }
        } else {
            if (p->root->tunnel_verdicted == 1 && TUNNEL_PKT_TPR(p) == 1) {
                /* the root is ready and we are the last tunnel packet,
                 * lets enqueue them both. */
                TUNNEL_DECR_PKT_TPR_NOLOCK(p);

                /* handle the root */
                PacketEnqueue(q,p->root);

                /* fall through */
            } else {
                TUNNEL_DECR_PKT_TPR_NOLOCK(p);
                /* fall through */
            }
        }
        mutex_unlock(m);
    }

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

