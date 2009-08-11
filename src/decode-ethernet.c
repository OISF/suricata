/* Copyright (c) 2009 Victor Julien <victor@inliniac.net> */

#include "decode.h"
#include "decode-ethernet.h"
#include "decode-events.h"

void DecodeEthernet(ThreadVars *t, Packet *p, u_int8_t *pkt, u_int16_t len, PacketQueue *pq)
{
    PerfCounterIncr(COUNTER_DECODER_ETH, t->pca);

    if (len < ETHERNET_HEADER_LEN) {
        DECODER_SET_EVENT(p,ETHERNET_PKT_TOO_SMALL);
        return;
    }

    EthernetHdr *ethh = (EthernetHdr *)pkt;
    if (ethh == NULL)
        return;

#ifdef DEBUG
    printf("DecodeEthernet: p %p pkt %p ether type %04x\n", p, pkt, ntohs(ethh->eth_type));
#endif

    if (ntohs(ethh->eth_type) == ETHERNET_TYPE_IP) {
        //printf("DecodeEthernet ip4\n");
        DecodeIPV4(t, p, pkt + ETHERNET_HEADER_LEN, len - ETHERNET_HEADER_LEN, pq);
    } else if(ntohs(ethh->eth_type) == ETHERNET_TYPE_IPV6) {
        //printf("DecodeEthernet ip6\n");
        DecodeIPV6(t, p, pkt + ETHERNET_HEADER_LEN, len - ETHERNET_HEADER_LEN);
    }

    return;
}

