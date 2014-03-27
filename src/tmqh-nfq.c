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
 * NFQ Verdict Handler
 */

#include "suricata-common.h"
#include "packet-queue.h"
#include "decode.h"
#include "threads.h"
#include "threadvars.h"

#include "tm-queuehandlers.h"

void TmqhOutputVerdictNfq(ThreadVars *t, Packet *p);

void TmqhNfqRegister (void)
{
    tmqh_table[TMQH_NFQ].name = "nfq";
    tmqh_table[TMQH_NFQ].InHandler = NULL;
    tmqh_table[TMQH_NFQ].OutHandler = TmqhOutputVerdictNfq;
}

void TmqhOutputVerdictNfq(ThreadVars *t, Packet *p)
{
/* XXX not scaling */
#if 0
    PacketQueue *q = &trans_q[p->verdict_q_id];

    SCMutexLock(&q->mutex_q);
    PacketEnqueue(q, p);
    SCCondSignal(&q->cond_q);
    SCMutexUnlock(&q->mutex_q);
#endif
}

