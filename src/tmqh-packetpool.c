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
#include "flow-util.h"
#include "host.h"

#include "stream.h"
#include "stream-tcp-reassemble.h"

#include "tm-queuehandlers.h"

#include "pkt-var.h"

#include "tmqh-packetpool.h"

#include "util-ringbuffer.h"
#include "util-debug.h"
#include "util-error.h"
#include "util-profiling.h"
#include "util-device.h"

static RingBuffer16 *ringbuffer = NULL;
/**
 * \brief TmqhPacketpoolRegister
 * \initonly
 */
void TmqhPacketpoolRegister (void) {
    tmqh_table[TMQH_PACKETPOOL].name = "packetpool";
    tmqh_table[TMQH_PACKETPOOL].InHandler = TmqhInputPacketpool;
    tmqh_table[TMQH_PACKETPOOL].OutHandler = TmqhOutputPacketpool;

    ringbuffer = RingBufferInit();
    if (ringbuffer == NULL) {
        SCLogError(SC_ERR_FATAL, "Error registering Packet pool handler (at ring buffer init)");
        exit(EXIT_FAILURE);
    }
}

void TmqhPacketpoolDestroy (void) {
    /* doing this clean up PacketPoolDestroy now,
     * where we also clean the packets */
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

    /* Clear the PKT_ALLOC flag, since that indicates to push back
     * onto the ring buffer. */
    p->flags &= ~PKT_ALLOC;
    p->ReleasePacket = PacketPoolReturnPacket;
    PacketPoolReturnPacket(p);

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

/** \brief Return packet to Packet pool
 *
 */
void PacketPoolReturnPacket(Packet *p)
{
    PACKET_RECYCLE(p);
    RingBufferMrMwPut(ringbuffer, (void *)p);
}

void PacketPoolInit(intmax_t max_pending_packets) {
    /* pre allocate packets */
    SCLogDebug("preallocating packets... packet size %" PRIuMAX "", (uintmax_t)SIZE_OF_PACKET);
    int i = 0;
    for (i = 0; i < max_pending_packets; i++) {
        Packet *p = PacketGetFromAlloc();
        if (unlikely(p == NULL)) {
            SCLogError(SC_ERR_FATAL, "Fatal error encountered while allocating a packet. Exiting...");
            exit(EXIT_FAILURE);
        }
        PacketPoolStorePacket(p);
    }
    SCLogInfo("preallocated %"PRIiMAX" packets. Total memory %"PRIuMAX"",
            max_pending_packets, (uintmax_t)(max_pending_packets*SIZE_OF_PACKET));
}

void PacketPoolDestroy(void) {
    if (ringbuffer == NULL) {
        return;
    }

    Packet *p = NULL;
    while ((p = PacketPoolGetPacket()) != NULL) {
        PACKET_CLEANUP(p);
        SCFree(p);
    }

    RingBufferDestroy(ringbuffer);
    ringbuffer = NULL;
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
    int proot = 0;

    SCEnter();
    SCLogDebug("Packet %p, p->root %p, alloced %s", p, p->root, p->flags & PKT_ALLOC ? "true" : "false");

    /** \todo make this a callback
     *  Release tcp segments. Done here after alerting can use them. */
    if (p->flow != NULL && p->proto == IPPROTO_TCP) {
        SCMutexLock(&p->flow->m);
        StreamTcpPruneSession(p->flow, p->flowflags & FLOW_PKT_TOSERVER ?
                STREAM_TOSERVER : STREAM_TOCLIENT);
        SCMutexUnlock(&p->flow->m);
    }

    if (IS_TUNNEL_PKT(p)) {
        SCLogDebug("Packet %p is a tunnel packet: %s",
            p,p->root ? "upper layer" : "tunnel root");

        /* get a lock to access root packet fields */
        SCMutex *m = p->root ? &p->root->tunnel_mutex : &p->tunnel_mutex;
        SCMutexLock(m);

        if (IS_TUNNEL_ROOT_PKT(p)) {
            SCLogDebug("IS_TUNNEL_ROOT_PKT == TRUE");
            if (TUNNEL_PKT_TPR(p) == 0) {
                SCLogDebug("TUNNEL_PKT_TPR(p) == 0, no more tunnel packet "
                        "depending on this root");
                /* if this packet is the root and there are no
                 * more tunnel packets, return it to the pool */

                /* fall through */
            } else {
                SCLogDebug("tunnel root Packet %p: TUNNEL_PKT_TPR(p) > 0, so "
                        "packets are still depending on this root, setting "
                        "p->tunnel_verdicted == 1", p);
                /* if this is the root and there are more tunnel
                 * packets, return this to the pool. It's still referenced
                 * by the tunnel packets, and we will return it
                 * when we handle them */
                SET_TUNNEL_PKT_VERDICTED(p);

                PACKET_PROFILING_END(p);
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
            if (p->root != NULL && IS_TUNNEL_PKT_VERDICTED(p->root) &&
                    TUNNEL_PKT_TPR(p) == 1)
            {
                SCLogDebug("p->root->tunnel_verdicted == 1 && TUNNEL_PKT_TPR(p) == 1");
                /* the root is ready and we are the last tunnel packet,
                 * lets enqueue them both. */
                TUNNEL_DECR_PKT_TPR_NOLOCK(p);

                /* handle the root */
                SCLogDebug("setting proot = 1 for root pkt, p->root %p "
                        "(tunnel packet %p)", p->root, p);
                proot = 1;

                /* fall through */
            } else {
                /* root not ready yet, so get rid of the tunnel pkt only */

                SCLogDebug("NOT p->root->tunnel_verdicted == 1 && "
                        "TUNNEL_PKT_TPR(p) == 1 (%" PRIu32 ")", TUNNEL_PKT_TPR(p));

                TUNNEL_DECR_PKT_TPR_NOLOCK(p);

                 /* fall through */
            }
        }
        SCMutexUnlock(m);

        SCLogDebug("tunnel stuff done, move on (proot %d)", proot);
    }

    FlowDeReference(&p->flow);

    /* we're done with the tunnel root now as well */
    if (proot == 1) {
        SCLogDebug("getting rid of root pkt... alloc'd %s", p->root->flags & PKT_ALLOC ? "true" : "false");

        FlowDeReference(&p->root->flow);
        /* if p->root uses extended data, free them */
        if (p->root->ext_pkt) {
            if (!(p->root->flags & PKT_ZERO_COPY)) {
                SCFree(p->root->ext_pkt);
            }
            p->root->ext_pkt = NULL;
        }
        p->root->ReleasePacket(p->root);
        p->root = NULL;
    }

    PACKET_PROFILING_END(p);

    p->ReleasePacket(p);

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
