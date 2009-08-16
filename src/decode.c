/* Copyright (c) 2008 Victor Julien <victor@inliniac.net> */

/* Decode the raw packet */

#include "eidps-common.h"
#include "decode.h"

void DecodeTunnel(ThreadVars *t, Packet *p, uint8_t *pkt, uint16_t len, PacketQueue *pq)
{
    switch (p->tunnel_proto) {
        case IPPROTO_IP:
            return DecodeIPV4(t, p, pkt, len, pq);
            break;
        case IPPROTO_IPV6:
            //printf("DecodeTunnel: IPv6 packet\n");
            return DecodeIPV6(t, p, pkt, len);
            break;
        default:
            printf("FIXME: DecodeTunnel: protocol %" PRIu32 " not supported.\n", p->tunnel_proto);
            break;
    }
}

