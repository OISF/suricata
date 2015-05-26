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

static RingBuffer8 *ringbuffers[256];

Packet *TmqhInputRingBufferMrSw(ThreadVars *t);
void TmqhOutputRingBufferMrSw(ThreadVars *t, Packet *p);
Packet *TmqhInputRingBufferSrSw(ThreadVars *t);
void TmqhOutputRingBufferSrSw(ThreadVars *t, Packet *p);
Packet *TmqhInputRingBufferSrMw(ThreadVars *t);
void TmqhOutputRingBufferSrMw(ThreadVars *t, Packet *p);
void TmqhInputRingBufferShutdownHandler(ThreadVars *);

/**
 * \brief TmqhRingBufferRegister
 * \initonly
 */
void TmqhRingBufferRegister (void)
{
    tmqh_table[TMQH_RINGBUFFER_MRSW].name = "ringbuffer_mrsw";
    tmqh_table[TMQH_RINGBUFFER_MRSW].InHandler = TmqhInputRingBufferMrSw;
    tmqh_table[TMQH_RINGBUFFER_MRSW].InShutdownHandler = TmqhInputRingBufferShutdownHandler;
    tmqh_table[TMQH_RINGBUFFER_MRSW].OutHandler = TmqhOutputRingBufferMrSw;

    tmqh_table[TMQH_RINGBUFFER_SRSW].name = "ringbuffer_srsw";
    tmqh_table[TMQH_RINGBUFFER_SRSW].InHandler = TmqhInputRingBufferSrSw;
    tmqh_table[TMQH_RINGBUFFER_SRSW].InShutdownHandler = TmqhInputRingBufferShutdownHandler;
    tmqh_table[TMQH_RINGBUFFER_SRSW].OutHandler = TmqhOutputRingBufferSrSw;

    tmqh_table[TMQH_RINGBUFFER_SRMW].name = "ringbuffer_srmw";
    tmqh_table[TMQH_RINGBUFFER_SRMW].InHandler = TmqhInputRingBufferSrMw;
    tmqh_table[TMQH_RINGBUFFER_SRMW].InShutdownHandler = TmqhInputRingBufferShutdownHandler;
    tmqh_table[TMQH_RINGBUFFER_SRMW].OutHandler = TmqhOutputRingBufferSrMw;

    memset(ringbuffers, 0, sizeof(ringbuffers));

    int i = 0;
    for (i = 0; i < 256; i++) {
        ringbuffers[i] = RingBuffer8Init();
        if (ringbuffers[i] == NULL) {
            SCLogError(SC_ERR_FATAL, "Error allocating memory to register Ringbuffers. Exiting...");
            exit(EXIT_FAILURE);
        }
    }
}

void TmqhRingBufferDestroy (void)
{
    int i = 0;
    for (i = 0; i < 256; i++) {
        RingBuffer8Destroy(ringbuffers[i]);
    }
}

void TmqhInputRingBufferShutdownHandler(ThreadVars *tv)
{
    if (tv == NULL || tv->inq == NULL) {
        return;
    }

    RingBuffer8 *rb = ringbuffers[tv->inq->id];
    if (rb == NULL) {
        return;
    }

    RingBuffer8Shutdown(rb);
}

Packet *TmqhInputRingBufferMrSw(ThreadVars *t)
{
    RingBuffer8 *rb = ringbuffers[t->inq->id];

    Packet *p = (Packet *)RingBufferMrSw8Get(rb);

    StatsSyncCountersIfSignalled(t);

    return p;
}

void TmqhOutputRingBufferMrSw(ThreadVars *t, Packet *p)
{
    RingBuffer8 *rb = ringbuffers[t->outq->id];
    RingBufferMrSw8Put(rb, (void *)p);
}

Packet *TmqhInputRingBufferSrSw(ThreadVars *t)
{
    RingBuffer8 *rb = ringbuffers[t->inq->id];

    Packet *p = (Packet *)RingBufferSrSw8Get(rb);

    StatsSyncCountersIfSignalled(t);

    return p;
}

void TmqhOutputRingBufferSrSw(ThreadVars *t, Packet *p)
{
    RingBuffer8 *rb = ringbuffers[t->outq->id];
    RingBufferSrSw8Put(rb, (void *)p);
}

Packet *TmqhInputRingBufferSrMw(ThreadVars *t)
{
    RingBuffer8 *rb = ringbuffers[t->inq->id];

    Packet *p = (Packet *)RingBufferSrMw8Get(rb);

    StatsSyncCountersIfSignalled(t);

    return p;
}

void TmqhOutputRingBufferSrMw(ThreadVars *t, Packet *p)
{
    RingBuffer8 *rb = ringbuffers[t->outq->id];
    RingBufferSrMw8Put(rb, (void *)p);
}

