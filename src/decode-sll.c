/* Copyright (c) 2009 Victor Julien <victor@inliniac.net> */

#include "decode.h"
#include "decode-sll.h"
#include "decode-events.h"

void DecodeSll(ThreadVars *t, Packet *p, u_int8_t *pkt, u_int16_t len,
               PacketQueue *pq, void *data)
{
    DecodeThreadVars *dtv = (DecodeThreadVars *)data;

    PerfCounterIncr(dtv->counter_sll, t->pca);

    if (len < SLL_HEADER_LEN) {
        DECODER_SET_EVENT(p,SLL_PKT_TOO_SMALL);
        return;
    }

    SllHdr *sllh = (SllHdr *)pkt;
    if (sllh == NULL)
        return;

#ifdef DEBUG
    printf("DecodeSll: p %p pkt %p sll_protocol %04x\n", p, pkt, ntohs(sllh->sll_protocol));
#endif

    if (ntohs(sllh->sll_protocol) == ETHERNET_TYPE_IP) {
        //printf("DecodeSll ip4\n");
        DecodeIPV4(t, p, pkt + SLL_HEADER_LEN, len - SLL_HEADER_LEN, pq, data);
    } else if(ntohs(sllh->sll_protocol) == ETHERNET_TYPE_IPV6) {
        //printf("DecodeSll ip6\n");
        DecodeIPV6(t, p, pkt + SLL_HEADER_LEN, len - SLL_HEADER_LEN, data);
    }
}

