/* Copyright (C) 2007-2019 Open Information Security Foundation
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
 */

#ifndef SURICATA_PACKET_QUEUE_H
#define SURICATA_PACKET_QUEUE_H

#include "threads.h"

/** \brief simple fifo queue for packets
 *
 *  \note PacketQueueNoLock and PacketQueue need to keep identical
 *        layouts except for the mutex_q and cond_q fields.
 */
typedef struct PacketQueueNoLock_ {
    struct Packet_ *top;
    struct Packet_ *bot;
    uint32_t len;
#ifdef DBG_PERF
    uint32_t dbg_maxlen;
#endif /* DBG_PERF */
} PacketQueueNoLock;

/** \brief simple fifo queue for packets with mutex and cond
 *  Calling the mutex or triggering the cond is responsibility of the caller
 *
 *  \note PacketQueueNoLock and PacketQueue need to keep identical
 *        layouts except for the mutex_q and cond_q fields.
 */
typedef struct PacketQueue_ {
    struct Packet_ *top;
    struct Packet_ *bot;
    uint32_t len;
#ifdef DBG_PERF
    uint32_t dbg_maxlen;
#endif /* DBG_PERF */
    SCMutex mutex_q;
    SCCondT cond_q;
} PacketQueue;


void PacketEnqueueNoLock(PacketQueueNoLock *qnl, struct Packet_ *p);
void PacketEnqueue (PacketQueue *, struct Packet_ *);

struct Packet_ *PacketDequeueNoLock (PacketQueueNoLock *qnl);
struct Packet_ *PacketDequeue (PacketQueue *);

PacketQueue *PacketQueueAlloc(void);
void PacketQueueFree(PacketQueue *);

#endif /* SURICATA_PACKET_QUEUE_H */
