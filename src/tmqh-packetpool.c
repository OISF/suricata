
#include "vips.h"
#include "packet-queue.h"
#include "decode.h"
#include "threads.h"
#include "threadvars.h"

#include "tm-queuehandlers.h"

Packet *TmqhInputPacketpool(ThreadVars *t);
void TmqhOutputPacketpool(ThreadVars *t, Packet *p);

void TmqhPacketpoolRegister (void) {
    tmqh_table[TMQH_PACKETPOOL].name = "packetpool";
    tmqh_table[TMQH_PACKETPOOL].InHandler = TmqhInputPacketpool;
    tmqh_table[TMQH_PACKETPOOL].OutHandler = TmqhOutputPacketpool;
}

Packet *TmqhInputPacketpool(ThreadVars *t)
{
    /* XXX */
    Packet *p = SetupPkt();

    mutex_lock(&mutex_pending);
    if (pending > MAX_PENDING)
        pthread_cond_wait(&cond_pending, &mutex_pending);
    mutex_unlock(&mutex_pending);

    return p;
}

void TmqhOutputPacketpool(ThreadVars *t, Packet *p)
{
    PacketQueue *q = &packet_q;

    mutex_lock(&q->mutex_q);
    PacketEnqueue(q, p);
    mutex_unlock(&q->mutex_q);

    mutex_lock(&mutex_pending);
    pending--;
    if (pending <= MAX_PENDING)
        pthread_cond_signal(&cond_pending);
    mutex_unlock(&mutex_pending);
}

