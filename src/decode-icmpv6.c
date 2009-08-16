/* Copyright (c) 2008 Victor Julien <victor@inliniac.net> */

#include "eidps-common.h"
#include "decode.h"
#include "decode-icmpv6.h"

void DecodeICMPV6(ThreadVars *t, Packet *p, uint8_t *pkt, uint16_t len)
{
    p->icmpv6h = (ICMPV6Hdr *)pkt;

    PerfCounterIncr(COUNTER_DECODER_ICMPV6, t->pca);

    if (len < ICMPV6_HEADER_LEN) {
        return;
    }

#ifdef DEBUG
    printf("ICMPV6 TYPE %" PRIu32 " CODE %" PRIu32 "\n", p->icmpv6h->type, p->icmpv6h->code);
#endif

    p->proto = IPPROTO_ICMPV6;
    return;
}

