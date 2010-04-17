/* Packetpool queue handlers */

#include "suricata.h"
#include "packet-queue.h"
#include "decode.h"
#include "detect.h"
#include "detect-uricontent.h"
#include "threads.h"
#include "threadvars.h"
#include "flow.h"

#include "tm-queuehandlers.h"

#include "pkt-var.h"

#include "tmqh-packetpool.h"

extern int max_pending_packets;

void TmqhPacketpoolRegister (void) {
    tmqh_table[TMQH_PACKETPOOL].name = "packetpool";
    tmqh_table[TMQH_PACKETPOOL].InHandler = TmqhInputPacketpool;
    tmqh_table[TMQH_PACKETPOOL].OutHandler = TmqhOutputPacketpool;
}

Packet *TmqhInputPacketpool(ThreadVars *t)
{
    /* XXX */
    Packet *p = SetupPkt();

    SCMutexLock(&mutex_pending);
    pending++;
    //printf("PcapFileCallback: pending %" PRIu32 "\n", pending);
#ifdef DBG_PERF
    if (pending > dbg_maxpending)
        dbg_maxpending = pending;
#endif /* DBG_PERF */
    SCMutexUnlock(&mutex_pending);

/*
 * Disabled because it can enter a 'wait' state, while
 * keeping the nfq queue locked thus making it impossble
 * to free packets, the exact condition we are waiting
 * for. VJ 09-01-16
 *
    SCMutexLock(&mutex_pending);
    if (pending > MAX_PENDING) {
        SCondWait(&cond_pending, &mutex_pending);
    }
    SCMutexUnlock(&mutex_pending);
*/
    return p;
}

void TmqhOutputPacketpool(ThreadVars *t, Packet *p)
{
    PacketQueue *q = &packet_q;
    char proot = 0;

    if (p == NULL)
        return;

    if (IS_TUNNEL_PKT(p)) {
        //printf("TmqhOutputPacketpool: tunnel packet: %p %s\n", p,p->root ? "upper layer":"root");

        /* get a lock */
        SCMutex *m = p->root ? &p->root->mutex_rtv_cnt : &p->mutex_rtv_cnt;
        SCMutexLock(m);

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
                SCMutexUnlock(m);
                return;
            }
        } else {
            //printf("TmqhOutputPacketpool: NOT IS_TUNNEL_ROOT_PKT\n");

            /* the p->root != NULL here seems unnecessary: IS_TUNNEL_PKT checks
             * that p->tunnel_pkt == 1, IS_TUNNEL_ROOT_PKT checks that +
             * p->root == NULL. So when we are here p->root can only be
             * non-NULL, right? CLANG thinks differently. May be a FP, but
             * better safe than sorry. VJ */
            if (p->root != NULL && p->root->tunnel_verdicted == 1 &&
                    TUNNEL_PKT_TPR(p) == 1)
            {
                //printf("TmqhOutputPacketpool: p->root->tunnel_verdicted == 1 && TUNNEL_PKT_TPR(p) == 1\n");
                /* the root is ready and we are the last tunnel packet,
                 * lets enqueue them both. */
                TUNNEL_DECR_PKT_TPR_NOLOCK(p);

                /* handle the root */
                //printf("TmqhOutputPacketpool: calling PacketEnqueue for root pkt, p->root %p (%p)\n", p->root, p);
                proot = 1;

                /* fall through */
            } else {
                //printf("TmqhOutputPacketpool: NOT p->root->tunnel_verdicted == 1 && TUNNEL_PKT_TPR(p) == 1 (%" PRIu32 ")\n", TUNNEL_PKT_TPR(p));
                TUNNEL_DECR_PKT_TPR_NOLOCK(p);

                 /* fall through */
            }
        }
        SCMutexUnlock(m);
        //printf("TmqhOutputPacketpool: tunnel stuff done, move on\n");
    }

    FlowDecrUsecnt(t,p);

    if (proot && p->root != NULL) {
        CLEAR_PACKET(p->root);

        SCMutexLock(&q->mutex_q);
        PacketEnqueue(q, p->root);
        SCMutexUnlock(&q->mutex_q);
    }

    CLEAR_PACKET(p);

    SCMutexLock(&q->mutex_q);
    PacketEnqueue(q, p);
    SCMutexUnlock(&q->mutex_q);

    SCMutexLock(&mutex_pending);
    //printf("TmqhOutputPacketpool: pending %" PRIu32 "\n", pending);
    if (pending > 0) {
        pending--;
        if (proot) {
            if (pending > 0) {
                pending--;
            } else {
                printf("TmqhOutputPacketpool: warning, trying to subtract from 0 pending counter (tunnel root).\n");
            }
        }
    } else {
        printf("TmqhOutputPacketpool: warning, trying to subtract from 0 pending counter.\n");
    }
    if (pending <= max_pending_packets)
        SCCondSignal(&cond_pending);
    SCMutexUnlock(&mutex_pending);
}

/**
 * \brief Release all the packets in the queue back to the packetpool.  Mainly
 *        used by threads that have failed, and wants to return the packets back
 *        to the packetpool.
 *
 * \param pq Pointer to the packetqueue from which the packets have to be
 *           returned back to the packetpool
 */
void TmqhReleasePacketsToPacketPool(PacketQueue *pq)
{
    Packet *p = NULL;

    if (pq == NULL)
        return;

    SCMutexLock(&pq->mutex_q);

    while ( (p = PacketDequeue(pq)) != NULL)
        TmqhOutputPacketpool(NULL, p);

    SCMutexUnlock(&pq->mutex_q);

    return;
}
