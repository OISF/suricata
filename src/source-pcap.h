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
#define COUNTER_DECODER_PKTS    1
#define COUNTER_DECODER_BYTES   2
#define COUNTER_DECODER_IPV4    3
#define COUNTER_DECODER_IPV6    4
#define COUNTER_DECODER_ETH     5
#define COUNTER_DECODER_SLL     6
#define COUNTER_DECODER_TCP     7
#define COUNTER_DECODER_UDP     8
#define COUNTER_DECODER_ICMPV4  9
#define COUNTER_DECODER_ICMPV6 10
#define COUNTER_DECODER_PPP    11
#define COUNTER_DECODER_AVG_PKT_SIZE 12
#define COUNTER_DECODER_MAX_PKT_SIZE 13

/* per packet Pcap vars */
typedef struct PcapPacketVars_
{
    int datalink; /* datalink from libpcap */
} PcapPacketVars;

#endif /* __SOURCE_PCAP_H__ */

