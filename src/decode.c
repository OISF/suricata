/* Copyright (c) 2008 Victor Julien <victor@inliniac.net> */

/* Decode the raw packet */

#include "eidps-common.h"
#include "decode.h"

void DecodeTunnel(ThreadVars *tv, DecodeThreadVars *dtv, Packet *p, uint8_t *pkt, uint16_t len, PacketQueue *pq)
{
    switch (p->tunnel_proto) {
        case IPPROTO_IP:
            return DecodeIPV4(tv, dtv, p, pkt, len, pq);
        case IPPROTO_IPV6:
            return DecodeIPV6(tv, dtv, p, pkt, len, pq);
        default:
            printf("FIXME: DecodeTunnel: protocol %" PRIu32 " not supported.\n", p->tunnel_proto);
            break;
    }
}

