/* Copyright (c) 2009 Victor Julien <victor@inliniac.net> */

#ifndef __SOURCE_PCAP_H__
#define __SOURCE_PCAP_H__

void TmModuleReceivePcapRegister (void);
void TmModuleDecodePcapRegister (void);

/* XXX replace with user configurable options */
#define LIBPCAP_SNAPLEN     1518
#define LIBPCAP_COPYWAIT    500
#define LIBPCAP_PROMISC     1

/* per packet Pcap vars */
typedef struct PcapPacketVars_
{
} PcapPacketVars;

#endif /* __SOURCE_PCAP_H__ */

