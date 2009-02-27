/* Copyright (c) 2008 Victor Julien <victor@inliniac.net> */

#ifndef __DECODE_H__
#define __DECODE_H__

//#define IPQ
#define NFQ
//#define IPFW
//#define PCAP

//#define DEBUG
#define DBG_PERF
//#define DBG_THREADS
#define COUNTERS

#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#include "threadvars.h"

#ifdef NFQ
#include "source-nfq.h"
#endif /* NFQ */

#include "action-globals.h"

#include "decode-ethernet.h"
#include "decode-ipv4.h"
#include "decode-ipv6.h"
#include "decode-icmpv4.h"
#include "decode-icmpv6.h"
#include "decode-tcp.h"
#include "decode-udp.h"

/* Address */
typedef struct _Address
{
    char family;
    union {
        u_int32_t       address_un_data32[4]; /* type-specific field */
        u_int16_t       address_un_data16[8]; /* type-specific field */
        u_int8_t        address_un_data8[16]; /* type-specific field */
    } address;
} Address;

#define addr_data32 address.address_un_data32
#define addr_data16 address.address_un_data16
#define addr_data8  address.address_un_data8

/* Set the IPv4 addressesinto the Addrs of the Packet.
 * Make sure p->ip4h is initialized and validated.
 *
 * We set the rest of the struct to 0 so we can
 * prevent using memset. */
#define SET_IPV4_SRC_ADDR(p,a) { \
    (a)->family = AF_INET; \
    (a)->addr_data32[0] = (u_int32_t)(p)->ip4h->ip_src.s_addr; \
    (a)->addr_data32[1] = 0; \
    (a)->addr_data32[2] = 0; \
    (a)->addr_data32[3] = 0; \
}
#define SET_IPV4_DST_ADDR(p,a) { \
    (a)->family = AF_INET; \
    (a)->addr_data32[0] = (u_int32_t)(p)->ip4h->ip_dst.s_addr; \
    (a)->addr_data32[1] = 0; \
    (a)->addr_data32[2] = 0; \
    (a)->addr_data32[3] = 0; \
}
/* Set the IPv6 addressesinto the Addrs of the Packet.
 * Make sure p->ip6h is initialized and validated. */
#define SET_IPV6_SRC_ADDR(p,a) { \
    (a)->family = AF_INET6; \
    (a)->addr_data32[0] = (p)->ip6h->ip6_src[0]; \
    (a)->addr_data32[1] = (p)->ip6h->ip6_src[1]; \
    (a)->addr_data32[2] = (p)->ip6h->ip6_src[2]; \
    (a)->addr_data32[3] = (p)->ip6h->ip6_src[3]; \
}
#define SET_IPV6_DST_ADDR(p,a) { \
    (a)->family = AF_INET6; \
    (a)->addr_data32[0] = (p)->ip6h->ip6_dst[0]; \
    (a)->addr_data32[1] = (p)->ip6h->ip6_dst[1]; \
    (a)->addr_data32[2] = (p)->ip6h->ip6_dst[2]; \
    (a)->addr_data32[3] = (p)->ip6h->ip6_dst[3]; \
}
/* Set the TCP ports into the Ports of the Packet.
 * Make sure p->tcph is initialized and validated. */
#define SET_TCP_SRC_PORT(pkt,prt) { \
    SET_PORT(TCP_GET_SRC_PORT((pkt)), *prt); \
}
#define SET_TCP_DST_PORT(pkt,prt) { \
    SET_PORT(TCP_GET_DST_PORT((pkt)), *prt); \
}
/* Set the UDP ports into the Ports of the Packet.
 * Make sure p->udph is initialized and validated. */
#define SET_UDP_SRC_PORT(pkt,prt) { \
    SET_PORT(UDP_GET_SRC_PORT((pkt)), *prt); \
}
#define SET_UDP_DST_PORT(pkt,prt) { \
    SET_PORT(UDP_GET_DST_PORT((pkt)), *prt); \
}

#define GET_IPV4_SRC_ADDR_U32(p) ((p)->src.addr_data32[0])
#define GET_IPV4_DST_ADDR_U32(p) ((p)->dst.addr_data32[0])
#define GET_IPV4_SRC_ADDR_PTR(p) ((p)->src.addr_data32)
#define GET_IPV4_DST_ADDR_PTR(p) ((p)->dst.addr_data32)

#define GET_IPV6_SRC_ADDR(p) ((p)->src.addr_data32)
#define GET_IPV6_DST_ADDR(p) ((p)->dst.addr_data32)
#define GET_TCP_SRC_PORT(p)  ((p)->sp)
#define GET_TCP_DST_PORT(p)  ((p)->dp)

/* Port is just a u_int16_t */
typedef u_int16_t Port;
#define SET_PORT(v, p) ((p) = (v))

#define CMP_ADDR(a1,a2) \
    (((a1)->addr_data32[3] == (a2)->addr_data32[3] && \
      (a1)->addr_data32[2] == (a2)->addr_data32[2] && \
      (a1)->addr_data32[1] == (a2)->addr_data32[1] && \
      (a1)->addr_data32[0] == (a2)->addr_data32[0]))
#define CMP_PORT(p1,p2) \
    ((p1 == p2))

#define PKT_IS_IPV4(p) (((p)->ip4h != NULL))
#define PKT_IS_IPV6(p) (((p)->ip6h != NULL))
#define PKT_IS_TCP(p)  (((p)->tcph != NULL))
#define PKT_IS_UDP(p)  (((p)->udph != NULL))
#define PKT_IS_ICMPV4  (((p)->icmpv4 != NULL))
#define PKT_IS_ICMPV6  (((p)->icmpv6 != NULL))


/* structure to store the sids/gids/etc the detection engine
 * found in this packet */
typedef struct _PacketAlert {
    u_int8_t  gid;
    u_int32_t sid;
    u_int8_t  rev;
    u_int8_t class;
    u_int8_t prio;
    char      *msg;
} PacketAlert;

#define PACKET_ALERT_MAX 256

typedef struct _PacketAlerts {
    u_int16_t cnt;
    PacketAlert alerts[PACKET_ALERT_MAX];
} PacketAlerts;

#define HTTP_URI_MAXCNT 8
#define HTTP_URI_MAXLEN 1024

typedef struct _HttpUri {
    /* the raw uri for the packet as set by pcre */
    u_int8_t *raw[HTTP_URI_MAXCNT];
    u_int16_t raw_size[HTTP_URI_MAXCNT];

    /* normalized uri */
    u_int8_t norm[HTTP_URI_MAXCNT][HTTP_URI_MAXLEN];
    u_int16_t norm_size[HTTP_URI_MAXCNT];

    u_int8_t cnt;
} HttpUri;

typedef struct _PktVar {
    char *name;
    u_int8_t *value;
    u_int16_t value_len;
    struct _PktVar *next; /* right now just implement this as a list,
                            * in the long run we have thing of something
                            * faster. */
} PktVar;

typedef struct _Packet
{
    /* Addresses, Ports and protocol
     * these are on top so we can use
     * the Packet as a hash key */
    Address src;
    Address dst;
    Port sp;
    Port dp;
    u_int8_t proto;
    /* make sure we can't be attacked on when the tunneled packet
     * has the exact same tuple as the lower levels */
    u_int8_t recursion_level;

    struct timeval ts;

    /* ready to set verdict counter, only set in root */
    u_int8_t rtv_cnt;
    /* tunnel packet ref count */
    u_int8_t tpr_cnt;
    pthread_mutex_t mutex_rtv_cnt;
    /* tunnel stuff */
    u_int8_t tunnel_proto;
    /* tunnel XXX convert to bitfield*/
    char tunnel_pkt;
    char tunnel_verdicted;

    /* nfq stuff */
#ifdef NFQ
    NFQPacketVars nfq_v;
#endif /* NFQ */

    /* storage */
    u_int8_t pkt[65536];
    u_int16_t pktlen;

    /* flow */
    struct _Flow *flow;
    u_int8_t flowflags;

    /* pkt vars */
    PktVar *pktvar;

    /* header pointers */
    EthernetHdr *ethh;

    IPV4Hdr *ip4h;
    IPV4Vars ip4vars;
    IPV4Cache ip4c;

    IPV6Hdr *ip6h;
    IPV6Vars ip6vars;
    IPV6Cache ip6c;
    IPV6ExtHdrs ip6eh;

    ICMPV4Hdr *icmpv4h;
    ICMPV6Hdr *icmpv6h;

    TCPHdr *tcph;
    TCPVars tcpvars;

    UDPHdr *udph;
    UDPVars udpvars;

    /* ptr to the payload of the packet
     * with it's length. */
    u_int8_t *payload;
    u_int16_t payload_len;

    /* decoder events: review how many events we have */
    u_int8_t events[65535/8];

    HttpUri http_uri;

    PacketAlerts alerts;

    /* IPS action to take */
    int action;

    /* double linked list ptrs */
    struct _Packet *next;
    struct _Packet *prev;

    /* tunnel/encapsulation handling */
    struct _Packet *root; /* in case of tunnel this is a ptr
                           * to the 'real' packet, the one we
                           * need to set the verdict on --
                           * It should always point to the lowest
                           * packet in a encapsulated packet */

} Packet;

typedef struct _PacketQueue {
    Packet *top;
    Packet *bot;
    u_int16_t len;
    pthread_mutex_t mutex_q;
    pthread_cond_t cond_q;
#ifdef DBG_PERF
    u_int16_t dbg_maxlen;
#endif /* DBG_PERF */
} PacketQueue;


/* clear key vars so we don't need to call the expensive
 * memset or bzero
 */
#define CLEAR_PACKET(p) { \
    if ((p)->tcph != NULL) { \
        CLEAR_TCP_PACKET((p)); \
    } \
    (p)->ethh = NULL; \
    (p)->ip4h = NULL; \
    (p)->ip6h = NULL; \
    (p)->action = 0; \
    (p)->pktlen = 0; \
    (p)->tunnel_pkt = 0; \
    (p)->tunnel_verdicted = 0; \
    pthread_mutex_init(&(p)->mutex_rtv_cnt,NULL); \
    (p)->rtv_cnt = 0; \
    (p)->tpr_cnt = 0; \
    (p)->root = NULL; \
    (p)->proto = 0; \
    (p)->sp = 0; \
    (p)->dp = 0; \
    (p)->flow = NULL; \
    (p)->flowflags = 0; \
    (p)->alerts.cnt = 0; \
    (p)->http_uri.cnt = 0; \
    PktVarFree((p)->pktvar); \
    (p)->pktvar = NULL; \
    (p)->recursion_level = 0; \
}


/* macro's for setting the action
 * handle the case of a root packet
 * for tunnels */
#define ACCEPT_PACKET(p)       ((p)->root ? ((p)->root->action = ACTION_ACCEPT) : ((p)->action = ACTION_ACCEPT))
#define DROP_PACKET(p)         ((p)->root ? ((p)->root->action = ACTION_DROP) : ((p)->action = ACTION_DROP))
#define REJECT_PACKET(p)       ((p)->root ? ((p)->root->action = ACTION_REJECT) : ((p)->action = ACTION_REJECT))
#define REJECT_PACKET_DST(p)   ((p)->root ? ((p)->root->action = ACTION_REJECT_DST) : ((p)->action = ACTION_REJECT_DST))
#define REJECT_PACKET_BOTH(p)  ((p)->root ? ((p)->root->action = ACTION_REJECT_BOTH) : ((p)->action = ACTION_REJECT_BOTH))

#define TUNNEL_INCR_PKT_RTV(p) \
{ \
    mutex_lock((p)->root ? &(p)->root->mutex_rtv_cnt : &(p)->mutex_rtv_cnt); \
    ((p)->root ? (p)->root->rtv_cnt++ : (p)->rtv_cnt++); \
    mutex_unlock((p)->root ? &(p)->root->mutex_rtv_cnt : &(p)->mutex_rtv_cnt); \
}

#define TUNNEL_INCR_PKT_TPR(p) \
{ \
    mutex_lock((p)->root ? &(p)->root->mutex_rtv_cnt : &(p)->mutex_rtv_cnt); \
    ((p)->root ? (p)->root->tpr_cnt++ : (p)->tpr_cnt++); \
    mutex_unlock((p)->root ? &(p)->root->mutex_rtv_cnt : &(p)->mutex_rtv_cnt); \
}
#define TUNNEL_DECR_PKT_TPR(p) \
{ \
    mutex_lock((p)->root ? &(p)->root->mutex_rtv_cnt : &(p)->mutex_rtv_cnt); \
    ((p)->root ? (p)->root->tpr_cnt-- : (p)->tpr_cnt--); \
    mutex_unlock((p)->root ? &(p)->root->mutex_rtv_cnt : &(p)->mutex_rtv_cnt); \
}
#define TUNNEL_DECR_PKT_TPR_NOLOCK(p) \
{ \
    ((p)->root ? (p)->root->tpr_cnt-- : (p)->tpr_cnt--); \
}

#define TUNNEL_PKT_RTV(p)             ((p)->root ? (p)->root->rtv_cnt : (p)->rtv_cnt)
#define TUNNEL_PKT_TPR(p)             ((p)->root ? (p)->root->tpr_cnt : (p)->tpr_cnt)

#define IS_TUNNEL_ROOT_PKT(p)  (((p)->root == NULL && (p)->tunnel_pkt == 1))
#define IS_TUNNEL_PKT(p)       (((p)->tunnel_pkt == 1))
#define SET_TUNNEL_PKT(p)      ((p)->tunnel_pkt = 1)


/* decoder functions */
void DecodeTunnel(ThreadVars *, Packet *, u_int8_t *, u_int16_t, PacketQueue *);
void DecodeIPV4(ThreadVars *, Packet *, u_int8_t *, u_int16_t, PacketQueue *);
void DecodeIPV6(ThreadVars *, Packet *, u_int8_t *, u_int16_t);
void DecodeICMPV4(ThreadVars *, Packet *, u_int8_t *, u_int16_t);
void DecodeICMPV6(ThreadVars *, Packet *, u_int8_t *, u_int16_t);
void DecodeTCP(ThreadVars *, Packet *, u_int8_t *, u_int16_t);
void DecodeUDP(ThreadVars *, Packet *, u_int8_t *, u_int16_t);
void DecodeHTTP(ThreadVars *, Packet *, u_int8_t *, u_int16_t);

Packet *SetupPkt (void);
Packet *TunnelPktSetup(ThreadVars *, Packet *, u_int8_t *, u_int16_t, u_int8_t);

#define DECODER_SET_EVENT(p, e)   ((p)->events[(e/8)] |= (1<<(e%8)))
#define DECODER_ISSET_EVENT(p, e) ((p)->events[(e/8)] & (1<<(e%8)))

#endif /* __DECODE_H__ */

