/* Copyright (c) 2008 Victor Julien <victor@inliniac.net> */

#include "eidps-common.h"
#include "decode.h"
#include "decode-icmpv4.h"

void DecodeICMPV4(ThreadVars *t, Packet *p, uint8_t *pkt, uint16_t len )
{
    p->icmpv4h = (ICMPV4Hdr *)pkt;

    PerfCounterIncr(COUNTER_DECODER_ICMPV4, t->pca);

    if (len < ICMPV4_HEADER_LEN) {
        return;
    }

#ifdef DEBUG
    printf("ICMPV4 TYPE %" PRIu32 " CODE %" PRIu32 "\n", p->icmpv4h->type, p->icmpv4h->code);
#endif

    p->proto = IPPROTO_ICMP;
    return;
}

