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
 * Packetpool queue handlers. Packet pool is implemented as a ringbuffer.
 * We're using a multi reader / multi writer version of the ringbuffer,
 * that is relatively expensive due to the CAS function. But it is necessary
 * because every thread can return packets to the pool and multiple parts
 * of the code retrieve packets (Decode, Defrag) and these can run in their
 * own threads as well.
 */

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

#include "util-ringbuffer.h"

static RingBuffer16 *ringbuffer = NULL;

void TmqhPacketpoolRegister (void) {
    tmqh_table[TMQH_PACKETPOOL].name = "packetpool";
    tmqh_table[TMQH_PACKETPOOL].InHandler = TmqhInputPacketpool;
    tmqh_table[TMQH_PACKETPOOL].OutHandler = TmqhOutputPacketpool;

    ringbuffer = RingBufferInit();
}

int PacketPoolIsEmpty(void) {
    return RingBufferIsEmpty(ringbuffer);
}

uint16_t PacketPoolSize(void) {
    return RingBufferSize(ringbuffer);
}

void PacketPoolWait(void) {
    RingBufferWait(ringbuffer);
}

/** \brief a initialized packet
 *
 *  \warning Use *only* at init, not at packet runtime
 */
void PacketPoolStorePacket(Packet *p) {
    if (RingBufferIsFull(ringbuffer)) {
        exit(1);
    }

    RingBufferMrMwPut(ringbuffer, (void *)p);
    SCLogDebug("buffersize %u", RingBufferSize(ringbuffer));
}

/** \brief get a packet from the packet pool, but if the
 *         pool is empty, don't wait, just return NULL
 */
Packet *PacketPoolGetPacket(void) {
    if (RingBufferIsEmpty(ringbuffer))
        return NULL;

    Packet *p = RingBufferMrMwGetNoWait(ringbuffer);
    return p;
}

Packet *TmqhInputPacketpool(ThreadVars *t)
{
    Packet *p = NULL;

    while (p == NULL && ringbuffer->shutdown == FALSE) {
        p = RingBufferMrMwGet(ringbuffer);
    }

    /* packet is clean */

    return p;
}

void TmqhOutputPacketpool(ThreadVars *t, Packet *p)
{
    SCEnter();

    SCLogDebug("Packet %p, p->root %p, alloced %s", p, p->root, p->flags & PKT_ALLOC ? "true" : "false");

    char proot = 0;

    if (IS_TUNNEL_PKT(p)) {
        SCLogDebug("Packet %p is a tunnel packet: %s",
            p,p->root ? "upper layer" : "tunnel root");

        /* get a lock */
        SCMutex *m = p->root ? &p->root->mutex_rtv_cnt : &p->mutex_rtv_cnt;
        SCMutexLock(m);

        if (IS_TUNNEL_ROOT_PKT(p)) {
            SCLogDebug("IS_TUNNEL_ROOT_PKT == TRUE");
            if (TUNNEL_PKT_TPR(p) == 0) {
                SCLogDebug("TUNNEL_PKT_TPR(p) == 0, no more tunnel packet depending on this root");
                /* if this packet is the root and there are no
                 * more tunnel packets, enqueue it */

                /* fall through */
            } else {
                SCLogDebug("tunnel root Packet %p: TUNNEL_PKT_TPR(p) > 0, packets are still depending on this root, setting p->tunnel_verdicted == 1", p);
                /* if this is the root and there are more tunnel
                 * packets, don't add this. It's still referenced
                 * by the tunnel packets, and we will enqueue it
                 * when we handle them */
                p->tunnel_verdicted = 1;
                SCMutexUnlock(m);
                SCReturn;
            }
        } else {
            SCLogDebug("NOT IS_TUNNEL_ROOT_PKT, so tunnel pkt");

            /* the p->root != NULL here seems unnecessary: IS_TUNNEL_PKT checks
             * that p->tunnel_pkt == 1, IS_TUNNEL_ROOT_PKT checks that +
             * p->root == NULL. So when we are here p->root can only be
             * non-NULL, right? CLANG thinks differently. May be a FP, but
             * better safe than sorry. VJ */
            if (p->root != NULL && p->root->tunnel_verdicted == 1 &&
                    TUNNEL_PKT_TPR(p) == 1)
            {
                SCLogDebug("p->root->tunnel_verdicted == 1 && TUNNEL_PKT_TPR(p) == 1");
                /* the root is ready and we are the last tunnel packet,
                 * lets enqueue them both. */
                TUNNEL_DECR_PKT_TPR_NOLOCK(p);

                /* handle the root */
                SCLogDebug("calling PacketEnqueue for root pkt, p->root %p (tunnel packet %p)", p->root, p);
                proot = 1;

                /* fall through */
            } else {
                /* root not ready yet, so get rid of the tunnel pkt only */

                SCLogDebug("NOT p->root->tunnel_verdicted == 1 && TUNNEL_PKT_TPR(p) == 1 (%" PRIu32 ")", TUNNEL_PKT_TPR(p));
                TUNNEL_DECR_PKT_TPR_NOLOCK(p);

                 /* fall through */
            }
        }
        SCMutexUnlock(m);
        SCLogDebug("tunnel stuff done, move on (proot %d)", proot);
    }

    FlowDecrUsecnt(p->flow);

    /* we're done with the tunnel root now as well */
    if (proot == 1) {
        SCLogDebug("getting rid of root pkt... alloc'd %s", p->root->flags & PKT_ALLOC ? "true" : "false");
        if (p->root->flags & PKT_ALLOC) {
            PACKET_CLEANUP(p->root);
            SCFree(p->root);
            p->root = NULL;
        } else {
            PACKET_RECYCLE(p->root);
            RingBufferMrMwPut(ringbuffer, (void *)p->root);
        }
    }

    SCLogDebug("getting rid of tunnel pkt... alloc'd %s (root %p)", p->flags & PKT_ALLOC ? "true" : "false", p->root);
    if (p->flags & PKT_ALLOC) {
        PACKET_CLEANUP(p);
        SCFree(p);
    } else {
        PACKET_RECYCLE(p);
        RingBufferMrMwPut(ringbuffer, (void *)p);
    }

    SCReturn;
}

/**
 *  \brief Release all the packets in the queue back to the packetpool.  Mainly
 *         used by threads that have failed, and wants to return the packets back
 *         to the packetpool.
 *
 *  \param pq Pointer to the packetqueue from which the packets have to be
 *            returned back to the packetpool
 *
 *  \warning this function assumes that the pq does not use locking
 */
void TmqhReleasePacketsToPacketPool(PacketQueue *pq)
{
    Packet *p = NULL;

    if (pq == NULL)
        return;

    while ( (p = PacketDequeue(pq)) != NULL)
        TmqhOutputPacketpool(NULL, p);

    return;
}
