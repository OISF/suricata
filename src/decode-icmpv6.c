/* Copyright (c) 2008 Victor Julien <victor@inliniac.net> */

#include "decode.h"
#include "decode-icmpv6.h"

void DecodeICMPV6(ThreadVars *t, Packet *p, u_int8_t *pkt, u_int16_t len)
{
    p->icmpv6h = (ICMPV6Hdr *)pkt;

    if (len < ICMPV6_HEADER_LEN) {
        return;
    }

#ifdef DEBUG
    printf("ICMPV6 TYPE %u CODE %u\n", p->icmpv6h->type, p->icmpv6h->code);
#endif

    return;
}

