/* Copyright (c) 2008 Victor Julien <victor@inliniac.net> */

#include "suricata-common.h"
#include "packet-queue.h"
#include "decode.h"
#include "threads.h"
#include "threadvars.h"

#include "tm-queuehandlers.h"

void TmqhOutputVerdictNfq(ThreadVars *t, Packet *p);

void TmqhNfqRegister (void) {
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

