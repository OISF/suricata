/* Copyright (c) 2008 Victor Julien <victor@inliniac.net> */

/* Decode the raw packet */

#include "decode.h"

void DecodeTunnel(ThreadVars *t, Packet *p, u_int8_t *pkt, u_int16_t len)
{
    switch (p->tunnel_proto) {
        case IPPROTO_IP:
            return(DecodeIPV4(t, p, pkt, len));
            break;
        case IPPROTO_IPV6:
            return(DecodeIPV6(t, p, pkt, len));
            break;
        default:
            printf("FIXME: DecodeTunnel: protocol %u not supported.\n", p->tunnel_proto);
            break;
    }
}

