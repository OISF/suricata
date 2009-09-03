/* Copyright (c) 2008 Victor Julien <victor@inliniac.net> */

#ifndef __TMQH_PACKETPOOL_H__
#define __TMQH_PACKETPOOL_H__

Packet *TmqhInputPacketpool(ThreadVars *);
void TmqhOutputPacketpool(ThreadVars *, Packet *);
void TmqhReleasePacketsToPacketPool(PacketQueue *);
void TmqhPacketpoolRegister (void);

#endif /* __TMQH_PACKETPOOL_H__ */
