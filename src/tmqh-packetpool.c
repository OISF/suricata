
#include "vips.h"
#include "packet-queue.h"
#include "decode.h"
#include "threads.h"
#include "threadvars.h"

#include "tm-queuehandlers.h"

#include "pkt-var.h"

Packet *TmqhInputPacketpool(ThreadVars *t);
void TmqhOutputPacketpool(ThreadVars *t, Packet *p);

void TmqhPacketpoolRegister (void) {
    tmqh_table[TMQH_PACKETPOOL].name = "packetpool";
    tmqh_table[TMQH_PACKETPOOL].InHandler = TmqhInputPacketpool;
    tmqh_table[TMQH_PACKETPOOL].OutHandler = TmqhOutputPacketpool;
}

Packet *TmqhInputPacketpool(ThreadVars *t)
{
    /* XXX */
    Packet *p = SetupPkt();

/*
 * Disabled because it can enter a 'wait' state, while
 * keeping the nfq queue locked thus making it impossble
 * to free packets, the exact condition we are waiting
 * for. VJ 09-01-16
 *
    mutex_lock(&mutex_pending);
    if (pending > MAX_PENDING) {
        pthread_cond_wait(&cond_pending, &mutex_pending);
    }
    mutex_unlock(&mutex_pending);
*/
    return p;
}

void TmqhOutputPacketpool(ThreadVars *t, Packet *p)
{
    PacketQueue *q = &packet_q;
    char proot = 0;

    if (IS_TUNNEL_PKT(p)) {
        //printf("TmqhOutputPacketpool: tunnel packet: %p %s\n", p,p->root ? "upper layer":"root");

        /* get a lock */
        pthread_mutex_t *m = p->root ? &p->root->mutex_rtv_cnt : &p->mutex_rtv_cnt;
        mutex_lock(m);

        if (IS_TUNNEL_ROOT_PKT(p)) {
            //printf("TmqhOutputPacketpool: IS_TUNNEL_ROOT_PKT\n");
            if (TUNNEL_PKT_TPR(p) == 0) {
                //printf("TmqhOutputPacketpool: TUNNEL_PKT_TPR(p) == 0\n");
                /* if this packet is the root and there are no
                 * more tunnel packets, enqueue it */

                /* fall through */
            } else {
                //printf("TmqhOutputPacketpool: TUNNEL_PKT_TPR(p) > 0\n");
                /* if this is the root and there are more tunnel
                 * packets, don't add this. It's still referenced
                 * by the tunnel packets, and we will enqueue it
                 * when we handle them */
                p->tunnel_verdicted = 1;
                mutex_unlock(m);
                return;
            }
        } else {
            //printf("TmqhOutputPacketpool: NOT IS_TUNNEL_ROOT_PKT\n");
            if (p->root->tunnel_verdicted == 1 && TUNNEL_PKT_TPR(p) == 1) {
                //printf("TmqhOutputPacketpool: p->root->tunnel_verdicted == 1 && TUNNEL_PKT_TPR(p) == 1\n");
                /* the root is ready and we are the last tunnel packet,
                 * lets enqueue them both. */
                TUNNEL_DECR_PKT_TPR_NOLOCK(p);

                /* handle the root */
                //printf("TmqhOutputPacketpool: calling PacketEnqueue for root pkt\n");
                proot = 1;

                /* fall through */
            } else {
                //printf("TmqhOutputPacketpool: NOT p->root->tunnel_verdicted == 1 && TUNNEL_PKT_TPR(p) == 1 (%u)\n", TUNNEL_PKT_TPR(p));
                TUNNEL_DECR_PKT_TPR_NOLOCK(p);

                 /* fall through */
            }
        }
        mutex_unlock(m);
        //printf("TmqhOutputPacketpool: tunnel stuff done, move on\n");
    }

    if (proot) {
        CLEAR_PACKET(p->root);
    }
    CLEAR_PACKET(p);

    mutex_lock(&q->mutex_q);
    if (proot) {
        PacketEnqueue(q, p->root);
    }
    PacketEnqueue(q, p);
    mutex_unlock(&q->mutex_q);

    mutex_lock(&mutex_pending);
    if (pending) {
        pending--;
    } else {
        printf("TmqhOutputPacketpool: warning, trying to subtract from 0 pending counter.\n");
    }
    if (pending <= MAX_PENDING)
        pthread_cond_signal(&cond_pending);
    mutex_unlock(&mutex_pending);
}

