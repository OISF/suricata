/* Copyright (c) 2009 Victor Julien <victor@inliniac.net> */

#include "suricata-common.h"
#include "decode.h"
#include "decode-sll.h"
#include "decode-events.h"
#include "util-debug.h"

void DecodeSll(ThreadVars *tv, DecodeThreadVars *dtv, Packet *p, uint8_t *pkt, uint16_t len, PacketQueue *pq)
{
    SCPerfCounterIncr(dtv->counter_sll, tv->sc_perf_pca);

    if (len < SLL_HEADER_LEN) {
        DECODER_SET_EVENT(p,SLL_PKT_TOO_SMALL);
        return;
    }

    SllHdr *sllh = (SllHdr *)pkt;
    if (sllh == NULL)
        return;

    SCLogDebug("p %p pkt %p sll_protocol %04x", p, pkt, ntohs(sllh->sll_protocol));

    switch (ntohs(sllh->sll_protocol)) {
        case ETHERNET_TYPE_IP:
            DecodeIPV4(tv, dtv, p, pkt + SLL_HEADER_LEN,
                       len - SLL_HEADER_LEN, pq);
            break;
        case ETHERNET_TYPE_IPV6:
            DecodeIPV6(tv, dtv, p, pkt + SLL_HEADER_LEN,
                       len - SLL_HEADER_LEN, pq);
            break;
        case ETHERNET_TYPE_VLAN:
            DecodeVLAN(tv, dtv, p, pkt + SLL_HEADER_LEN,
                                 len - SLL_HEADER_LEN, pq);
            break;
        default:
            SCLogDebug("p %p pkt %p sll type %04x not supported", p,
                       pkt, ntohs(sllh->sll_protocol));
    }
}
