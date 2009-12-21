/* Copyright (c) 2008 Victor Julien <victor@inliniac.net> */

#ifndef __PACKET_QUEUE_H__
#define __PACKET_QUEUE_H__

#include "threads.h"
#include "decode.h"

void PacketEnqueue (PacketQueue *, Packet *);
Packet *PacketDequeue (PacketQueue *);

#endif /* __PACKET_QUEUE_H__ */

