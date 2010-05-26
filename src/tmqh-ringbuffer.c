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
 * RingBuffer queue handler
 */

#include "suricata.h"
#include "packet-queue.h"
#include "decode.h"
#include "threads.h"
#include "threadvars.h"

#include "tm-queuehandlers.h"

#include "util-ringbuffer.h"

static RingBufferMrSw *ringbuffers[256];

Packet *TmqhInputRingBuffer(ThreadVars *t);
void TmqhOutputRingBuffer(ThreadVars *t, Packet *p);

void TmqhRingBufferRegister (void) {
    tmqh_table[TMQH_RINGBUFFER].name = "ringbuffer";
    tmqh_table[TMQH_RINGBUFFER].InHandler = TmqhInputRingBuffer;
    tmqh_table[TMQH_RINGBUFFER].OutHandler = TmqhOutputRingBuffer;

    int i = 0;
    for (i = 0; i < 256; i++) {
        ringbuffers[i] = RingBufferMrSwInit();
    }
}

Packet *TmqhInputRingBuffer(ThreadVars *t)
{
    RingBufferMrSw *rb = ringbuffers[t->inq->id];

    Packet *p = (Packet *)RingBufferMrSwGet(rb);
    return p;
}

void TmqhOutputRingBuffer(ThreadVars *t, Packet *p)
{
    RingBufferMrSw *rb = ringbuffers[t->outq->id];
    RingBufferMrSwPut(rb, (void *)p);
}

