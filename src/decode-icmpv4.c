/* Copyright (c) 2008 Victor Julien <victor@inliniac.net> */

#include "decode.h"
#include "decode-icmpv4.h"

void DecodeICMPV4(ThreadVars *t, Packet *p, u_int8_t *pkt, u_int16_t len )
{
    p->icmpv4h = (ICMPV4Hdr *)pkt;

    PerfCounterIncr(COUNTER_DECODER_ICMPV4, t->pca);

    if (len < ICMPV4_HEADER_LEN) {
        return;
    }

#ifdef DEBUG
    printf("ICMPV4 TYPE %u CODE %u\n", p->icmpv4h->type, p->icmpv4h->code);
#endif

    p->proto = IPPROTO_ICMP;
    return;
}

