/* Copyright (C) 2007-2014 Open Information Security Foundation
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

#ifndef __TMQH_PACKETPOOL_H__
#define __TMQH_PACKETPOOL_H__

#include "decode.h"
#include "threads.h"
#include "util-atomic.h"

    /* Return stack, onto which other threads free packets. */
typedef struct PktPoolLockedStack_{
    /* linked list of free packets. */
    SCMutex mutex;
    SCCondT cond;
    SC_ATOMIC_DECLARE(int, sync_now);
    Packet *head;
} __attribute__((aligned(CLS))) PktPoolLockedStack;

typedef struct PktPool_ {
    /* link listed of free packets local to this thread.
     * No mutex is needed.
     */
    Packet *head;
    /* Packets waiting (pending) to be returned to the given Packet
     * Pool. Accumulate packets for the same pool until a theshold is
     * reached, then return them all at once.  Keep the head and tail
     * to fast insertion of the entire list onto a return stack.
     */
    struct PktPool_ *pending_pool;
    Packet *pending_head;
    Packet *pending_tail;
    uint32_t pending_count;

#ifdef DEBUG_VALIDATION
    int initialized;
    int destroyed;
#endif /* DEBUG_VALIDATION */

    /* All members above this point are accessed locally by only one thread, so
     * these should live on their own cache line.
     */

    /* Return stack, where other threads put packets that they free that belong
     * to this thread.
     */
    PktPoolLockedStack return_stack;
} PktPool;

Packet *TmqhInputPacketpool(ThreadVars *);
void TmqhOutputPacketpool(ThreadVars *, Packet *);
void TmqhReleasePacketsToPacketPool(PacketQueue *);
void TmqhPacketpoolRegister(void);
Packet *PacketPoolGetPacket(void);
void PacketPoolWait(void);
void PacketPoolWaitForN(int n);
void PacketPoolReturnPacket(Packet *p);
void PacketPoolInit(void);
void PacketPoolInitEmpty(void);
void PacketPoolDestroy(void);
void PacketPoolPostRunmodes(void);

#endif /* __TMQH_PACKETPOOL_H__ */
