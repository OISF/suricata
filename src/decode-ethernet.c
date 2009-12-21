/* Copyright (c) 2009 Victor Julien <victor@inliniac.net> */

#include "suricata-common.h"
#include "decode.h"
#include "decode-ethernet.h"
#include "decode-events.h"

#include "util-unittest.h"
#include "util-debug.h"

void DecodeEthernet(ThreadVars *tv, DecodeThreadVars *dtv, Packet *p, uint8_t *pkt, uint16_t len, PacketQueue *pq)
{
    SCPerfCounterIncr(dtv->counter_eth, tv->sc_perf_pca);

    if (len < ETHERNET_HEADER_LEN) {
        DECODER_SET_EVENT(p,ETHERNET_PKT_TOO_SMALL);
        return;
    }

    EthernetHdr *ethh = (EthernetHdr *)pkt;
    if (ethh == NULL)
        return;

    SCLogDebug("p %p pkt %p ether type %04x", p, pkt, ntohs(ethh->eth_type));

    if (ntohs(ethh->eth_type) == ETHERNET_TYPE_IP) {
        //printf("DecodeEthernet ip4\n");
        DecodeIPV4(tv, dtv, p, pkt + ETHERNET_HEADER_LEN, len - ETHERNET_HEADER_LEN, pq);
    } else if(ntohs(ethh->eth_type) == ETHERNET_TYPE_IPV6) {
        //printf("DecodeEthernet ip6\n");
        DecodeIPV6(tv, dtv, p, pkt + ETHERNET_HEADER_LEN, len - ETHERNET_HEADER_LEN, pq);
    } else if(ntohs(ethh->eth_type) == ETHERNET_TYPE_PPPOE_SESS) {
        //printf("DecodeEthernet PPPOE Session\n");
        DecodePPPOESession(tv, dtv, p, pkt + ETHERNET_HEADER_LEN, len - ETHERNET_HEADER_LEN, pq);
    } else if(ntohs(ethh->eth_type) == ETHERNET_TYPE_PPPOE_DISC) {
        //printf("DecodeEthernet PPPOE Discovery\n");
        DecodePPPOEDiscovery(tv, dtv, p, pkt + ETHERNET_HEADER_LEN, len - ETHERNET_HEADER_LEN, pq);
    }

    return;
}

#ifdef UNITTESTS
/** DecodeEthernettest01
 *  \brief Valid Ethernet packet
 *  \retval 0 Expected test value
 */
static int DecodeEthernetTest01 (void)   {

    /* ICMP packet wrapped in PPPOE */
    uint8_t raw_eth[] = {
        0x00, 0x10, 0x94, 0x55, 0x00, 0x01, 0x00, 0x10,
        0x94, 0x56, 0x00, 0x01, 0x88, 0x64, 0x11, 0x00,
        0x00, 0x01, 0x00, 0x68, 0x00, 0x21, 0x45, 0xc0,
        0x00, 0x64, 0x00, 0x1e, 0x00, 0x00, 0xff, 0x01,
        0xa7, 0x78, 0x0a, 0x00, 0x00, 0x02, 0x0a, 0x00,
        0x00, 0x01, 0x08, 0x00, 0x4a, 0x61, 0x00, 0x06,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0f,
        0x3b, 0xd4, 0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd,
        0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd,
        0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd,
        0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd,
        0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd,
        0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd,
        0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd,
        0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd,
        0xab, 0xcd };

    Packet p;
    ThreadVars tv;
    DecodeThreadVars dtv;

    memset(&dtv, 0, sizeof(DecodeThreadVars));
    memset(&tv,  0, sizeof(ThreadVars));
    memset(&p,   0, sizeof(Packet));

    DecodeEthernet(&tv, &dtv, &p, raw_eth, sizeof(raw_eth), NULL);

    return 0;
}
#endif /* UNITTESTS */


/**
 * \brief Registers Ethernet unit tests
 * \todo More Ethernet tests
 */
void DecodeEthernetRegisterTests(void) {
#ifdef UNITTESTS
    UtRegisterTest("DecodeEthernetTest01", DecodeEthernetTest01, 0);
#endif /* UNITTESTS */
}
