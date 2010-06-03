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

static RingBufferMrMw8 *ringbuffers[256];

Packet *TmqhInputRingBuffer(ThreadVars *t);
void TmqhOutputRingBuffer(ThreadVars *t, Packet *p);
void TmqhInputRingBufferShutdownHandler(ThreadVars *);

void TmqhRingBufferRegister (void) {
    tmqh_table[TMQH_RINGBUFFER].name = "ringbuffer";
    tmqh_table[TMQH_RINGBUFFER].InHandler = TmqhInputRingBuffer;
    tmqh_table[TMQH_RINGBUFFER].InShutdownHandler = TmqhInputRingBufferShutdownHandler;
    tmqh_table[TMQH_RINGBUFFER].OutHandler = TmqhOutputRingBuffer;

    memset(ringbuffers, 0, sizeof(ringbuffers));

    int i = 0;
    for (i = 0; i < 256; i++) {
        ringbuffers[i] = RingBufferMrMw8Init();
    }
}

Packet *TmqhInputRingBuffer(ThreadVars *t)
{
    RingBufferMrMw8 *rb = ringbuffers[t->inq->id];

    Packet *p = (Packet *)RingBufferMrMw8Get(rb);

    if (t->sc_perf_pctx.perf_flag == 1)
        SCPerfUpdateCounterArray(t->sc_perf_pca, &t->sc_perf_pctx, 0);

    return p;
}

void TmqhInputRingBufferShutdownHandler(ThreadVars *tv) {
    if (tv == NULL || tv->inq == NULL) {
        return;
    }

    RingBufferMrMw8 *rb = ringbuffers[tv->inq->id];
    if (rb == NULL) {
        return;
    }

    rb->shutdown = 1;
}

void TmqhOutputRingBuffer(ThreadVars *t, Packet *p)
{
    RingBufferMrMw8 *rb = ringbuffers[t->outq->id];
    RingBufferMrMw8Put(rb, (void *)p);
}

