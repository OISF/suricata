/* Copyright (c) 2008 Victor Julien <victor@inliniac.net> */
#ifndef __DECODE_ETHERNET_H__
#define __DECODE_ETHERNET_H__

/* Ethernet types -- taken from Snort and Libdnet */
#define ETHERNET_TYPE_PUP             0x0200 /* PUP protocol */
#define ETHERNET_TYPE_IP              0x0800
#define ETHERNET_TYPE_ARP             0x0806
#define ETHERNET_TYPE_REVARP          0x8035
#define ETHERNET_TYPE_EAPOL           0x888e
#define ETHERNET_TYPE_IPV6            0x86dd
#define ETHERNET_TYPE_IPX             0x8137
#define ETHERNET_TYPE_PPPoE_DISC      0x8863 /* discovery stage */
#define ETHERNET_TYPE_PPPoE_SESS      0x8864 /* session stage */
#define ETHERNET_TYPE_8021Q           0x8100
#define ETHERNET_TYPE_LOOP            0x9000

typedef struct _EthernetHdr {
    u_int8_t eth_dst[6];
    u_int8_t eth_src[6];
    u_int16_t eth_type;
} EthernetHdr;

#endif /* __DECODE_ETHERNET_H__ */

