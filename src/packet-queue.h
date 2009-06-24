/* Copyright (c) 2008 Victor Julien <victor@inliniac.net> */

#ifndef __PACKET_QUEUE_H__
#define __PACKET_QUEUE_H__

#include <pthread.h>
#include "decode.h"

/* XXX: moved to decode.h */
#if 0
typedef struct _PacketQueue {
    Packet *top;
    Packet *bot;
    u_int16_t len;
    pthread_mutex_t mutex_q;
    pthread_cond_t cond_q;
#ifdef DBG_PERF
    u_int16_t dbg_maxlen;
#endif /* DBG_PERF */
} PacketQueue;
#endif
void PacketEnqueue (PacketQueue *, Packet *);
Packet *PacketDequeue (PacketQueue *);

#endif /* __PACKET_QUEUE_H__ */

