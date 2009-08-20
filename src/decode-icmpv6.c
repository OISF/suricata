/* Copyright (c) 2008 Victor Julien <victor@inliniac.net> */

#include "eidps-common.h"
#include "decode.h"
#include "decode-icmpv6.h"

void DecodeICMPV6(ThreadVars *tv, DecodeThreadVars *dtv, Packet *p, uint8_t *pkt, uint16_t len, PacketQueue *pq)
{
    PerfCounterIncr(dtv->counter_icmpv6, tv->pca);

    if (len < ICMPV6_HEADER_LEN) {
        /** \todo decode event */
        return;
    }

    p->icmpv6h = (ICMPV6Hdr *)pkt;

#ifdef DEBUG
    printf("ICMPV6 TYPE %" PRIu32 " CODE %" PRIu32 "\n", p->icmpv6h->type, p->icmpv6h->code);
#endif

    p->proto = IPPROTO_ICMPV6;
    return;
}

