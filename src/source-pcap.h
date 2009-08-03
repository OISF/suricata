/* Copyright (c) 2009 Victor Julien <victor@inliniac.net> */

#ifndef __SOURCE_PCAP_H__
#define __SOURCE_PCAP_H__

void TmModuleReceivePcapRegister (void);
void TmModuleDecodePcapRegister (void);

/* XXX replace with user configurable options */
#define LIBPCAP_SNAPLEN     1518
#define LIBPCAP_COPYWAIT    500
#define LIBPCAP_PROMISC     1

// The counter ids.  In case you can't recollect the ids, use the counter name
#define DECODER_PKTS    1
#define DECODER_BYTES   2
#define DECODER_IPV4    3
#define DECODER_IPV6    4
#define DECODER_ETH     5
#define DECODER_SLL     6
#define DECODER_TCP     7
#define DECODER_UDP     8
#define DECODER_ICMPV4  9
#define DECODER_ICMPV6 10
#define DECODER_PPP    11

/* per packet Pcap vars */
typedef struct PcapPacketVars_
{
    int datalink; /* datalink from libpcap */
} PcapPacketVars;

#endif /* __SOURCE_PCAP_H__ */

