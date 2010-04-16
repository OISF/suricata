/* Copyright (c) 2008 Victor Julien <victor@inliniac.net> */

#ifndef __DECODE_H__
#define __DECODE_H__

//#define IPQ
//#define NFQ
//#define IPFW
//#define PCAP

//#define DEBUG
#define DBG_PERF
//#define DBG_THREADS
#define COUNTERS

#include "threadvars.h"

#include "source-nfq.h"

#include "source-pcap.h"
#include "action-globals.h"

#include "decode-ethernet.h"
#include "decode-gre.h"
#include "decode-ppp.h"
#include "decode-pppoe.h"
#include "decode-sll.h"
#include "decode-ipv4.h"
#include "decode-ipv6.h"
#include "decode-icmpv4.h"
#include "decode-icmpv6.h"
#include "decode-tcp.h"
#include "decode-udp.h"
#include "decode-raw.h"
#include "decode-vlan.h"

#include "detect-reference.h"

/* forward declaration */
struct DetectionEngineThreadCtx_;

/* Address */
typedef struct Address_
{
    char family;
    union {
        uint32_t       address_un_data32[4]; /* type-specific field */
        uint16_t       address_un_data16[8]; /* type-specific field */
        uint8_t        address_un_data8[16]; /* type-specific field */
    } address;
} Address;

#define addr_data32 address.address_un_data32
#define addr_data16 address.address_un_data16
#define addr_data8  address.address_un_data8

#define COPY_ADDRESS(a,b) { \
    (b)->family = (a)->family; \
    (b)->addr_data32[0] = (a)->addr_data32[0]; \
    (b)->addr_data32[1] = (a)->addr_data32[1]; \
    (b)->addr_data32[2] = (a)->addr_data32[2]; \
    (b)->addr_data32[3] = (a)->addr_data32[3]; \
}

/* Set the IPv4 addressesinto the Addrs of the Packet.
 * Make sure p->ip4h is initialized and validated.
 *
 * We set the rest of the struct to 0 so we can
 * prevent using memset. */
#define SET_IPV4_SRC_ADDR(p,a) { \
    (a)->family = AF_INET; \
    (a)->addr_data32[0] = (uint32_t)(p)->ip4h->ip_src.s_addr; \
    (a)->addr_data32[1] = 0; \
    (a)->addr_data32[2] = 0; \
    (a)->addr_data32[3] = 0; \
}
#define SET_IPV4_DST_ADDR(p,a) { \
    (a)->family = AF_INET; \
    (a)->addr_data32[0] = (uint32_t)(p)->ip4h->ip_dst.s_addr; \
    (a)->addr_data32[1] = 0; \
    (a)->addr_data32[2] = 0; \
    (a)->addr_data32[3] = 0; \
}

/* clear the address structure by setting all fields to 0 */
#define CLEAR_ADDR(a) { \
    (a)->family = 0; \
    (a)->addr_data32[0] = 0; \
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

/* Port is just a uint16_t */
typedef uint16_t Port;
#define SET_PORT(v, p) ((p) = (v))
#define COPY_PORT(a,b) (b) = (a)

#define CMP_ADDR(a1,a2) \
    (((a1)->addr_data32[3] == (a2)->addr_data32[3] && \
      (a1)->addr_data32[2] == (a2)->addr_data32[2] && \
      (a1)->addr_data32[1] == (a2)->addr_data32[1] && \
      (a1)->addr_data32[0] == (a2)->addr_data32[0]))
#define CMP_PORT(p1,p2) \
    ((p1 == p2))

/*Given a packet pkt offset to the start of the ip header in a packet
 *We determine the ip version. */
#define IP_GET_RAW_VER(pkt) (((pkt[0] & 0xf0) >> 4))

#define PKT_IS_IPV4(p)      (((p)->ip4h != NULL))
#define PKT_IS_IPV6(p)      (((p)->ip6h != NULL))
#define PKT_IS_TCP(p)       (((p)->tcph != NULL))
#define PKT_IS_UDP(p)       (((p)->udph != NULL))
#define PKT_IS_ICMPV4(p)    (((p)->icmpv4h != NULL))
#define PKT_IS_ICMPV6(p)    (((p)->icmpv6h != NULL))
#define PKT_IS_TOSERVER(p)  (((p)->flowflags & FLOW_PKT_TOSERVER))
#define PKT_IS_TOCLIENT(p)  (((p)->flowflags & FLOW_PKT_TOCLIENT))

#define IPH_IS_VALID(p) (PKT_IS_IPV4((p)) || PKT_IS_IPV6((p)))

/* structure to store the sids/gids/etc the detection engine
 * found in this packet */
typedef struct PacketAlert_ {
    uint32_t  gid;
    uint32_t sid;
    uint8_t  rev;
    uint8_t class;
    uint8_t prio;
    char *msg;
    char *class_msg;
    Reference *references;
} PacketAlert;

#define PACKET_ALERT_MAX 256

typedef struct PacketAlerts_ {
    uint16_t cnt;
    PacketAlert alerts[PACKET_ALERT_MAX];
} PacketAlerts;

typedef struct PktVar_ {
    char *name;
    struct PktVar_ *next; /* right now just implement this as a list,
                           * in the long run we have thing of something
                           * faster. */
    uint8_t *value;
    uint16_t value_len;
} PktVar;

/* forward declartion since Packet struct definition requires this */
struct PacketQueue_;

typedef struct Packet_
{
    /* Addresses, Ports and protocol
     * these are on top so we can use
     * the Packet as a hash key */
    Address src;
    Address dst;
    union {
        Port sp;
        uint8_t type;
    };
    union {
        Port dp;
        uint8_t code;
    };
    uint8_t proto;
    /* make sure we can't be attacked on when the tunneled packet
     * has the exact same tuple as the lower levels */
    uint8_t recursion_level;

    struct timeval ts;

    /* ready to set verdict counter, only set in root */
    uint8_t rtv_cnt;
    /* tunnel packet ref count */
    uint8_t tpr_cnt;
    SCMutex mutex_rtv_cnt;
    /* tunnel stuff */
    uint8_t tunnel_proto;
    /* tunnel XXX convert to bitfield*/
    char tunnel_pkt;
    char tunnel_verdicted;

    /* nfq stuff */
#ifdef NFQ
    NFQPacketVars nfq_v;
#endif /* NFQ */

    /** libpcap vars: shared by Pcap Live mode and Pcap File mode */
    PcapPacketVars pcap_v;

    /** data linktype in host order */
    int datalink;

    /* storage: maximum ip packet size + link header */
    uint8_t pkt[IPV6_HEADER_LEN + 65536 + 28];
    uint32_t pktlen;

    /* flow */
    struct Flow_ *flow;
    uint8_t flowflags;

    /*Pkt Flags*/
    uint8_t flags;

    /* pkt vars */
    PktVar *pktvar;

    /* header pointers */
    EthernetHdr *ethh;
    PPPHdr *ppph;
    PPPOESessionHdr *pppoesh;
    PPPOEDiscoveryHdr *pppoedh;
    GREHdr *greh;
    VLANHdr *vlanh;

    IPV4Hdr *ip4h;
    IPV4Vars ip4vars;
    IPV4Cache ip4c;

    IPV6Hdr *ip6h;
    IPV6Vars ip6vars;
    IPV6Cache ip6c;
    IPV6ExtHdrs ip6eh;

    ICMPV4Hdr *icmpv4h;
    ICMPV4Cache icmpv4c;
    ICMPV4Vars icmpv4vars;

    ICMPV6Hdr *icmpv6h;
    ICMPV6Cache icmpv6c;
    ICMPV6Vars icmpv6vars;

    TCPHdr *tcph;
    TCPVars tcpvars;
    TCPCache tcpc;

    UDPHdr *udph;
    UDPVars udpvars;
    UDPCache udpc;

    /* ptr to the payload of the packet
     * with it's length. */
    uint8_t *payload;
    uint16_t payload_len;

    /* decoder events: review how many events we have */
    uint8_t events[65535 / 8];

    PacketAlerts alerts;

    /* IPS action to take */
    uint8_t action;

    /* double linked list ptrs */
    struct Packet_ *next;
    struct Packet_ *prev;

    /* tunnel/encapsulation handling */
    struct Packet_ *root; /* in case of tunnel this is a ptr
                           * to the 'real' packet, the one we
                           * need to set the verdict on --
                           * It should always point to the lowest
                           * packet in a encapsulated packet */

    /* required for cuda support */
#ifdef __SC_CUDA_SUPPORT__
    PatternMatcherQueue *cuda_pmq;
    MpmCtx *cuda_mpm_ctx;
    MpmThreadCtx *cuda_mtc;

    /* used to hold the match results.  We can instead use a void *result
     * instead here.  That way we can make them hold any result. *todo* */
    uint16_t cuda_matches;
    /* indicates if the dispatcher should call the search or the scan phase
     * of the pattern matcher.  We can instead use a void *cuda_data instead.
     * This way we can send any data across to the dispatcher */
    uint8_t cuda_search;
    /* the dispatcher thread would pump the packet into this queue once it has
     * processed the packet */
    struct PacketQueue_ *cuda_outq;
#endif
} Packet;

typedef struct PacketQueue_ {
    Packet *top;
    Packet *bot;
    uint16_t len;
    SCMutex mutex_q;
    SCCondT cond_q;
#ifdef DBG_PERF
    uint16_t dbg_maxlen;
#endif /* DBG_PERF */
} PacketQueue;

/** \brief Structure to hold thread specific data for all decode modules */
typedef struct DecodeThreadVars_
{
    /** stats/counters */
    uint16_t counter_pkts;
    uint16_t counter_pkts_per_sec;
    uint16_t counter_bytes;
    uint16_t counter_bytes_per_sec;
    uint16_t counter_mbit_per_sec;
    uint16_t counter_ipv4;
    uint16_t counter_ipv6;
    uint16_t counter_eth;
    uint16_t counter_sll;
    uint16_t counter_raw;
    uint16_t counter_tcp;
    uint16_t counter_udp;
    uint16_t counter_icmpv4;
    uint16_t counter_icmpv6;
    uint16_t counter_ppp;
    uint16_t counter_gre;
    uint16_t counter_vlan;
    uint16_t counter_pppoe;
    uint16_t counter_avg_pkt_size;
    uint16_t counter_max_pkt_size;

    /** frag stats - defrag runs in the context of the decoder. */
    uint16_t counter_defrag_ipv4_fragments;
    uint16_t counter_defrag_ipv4_reassembled;
    uint16_t counter_defrag_ipv4_timeouts;
    uint16_t counter_defrag_ipv6_fragments;
    uint16_t counter_defrag_ipv6_reassembled;
    uint16_t counter_defrag_ipv6_timeouts;
} DecodeThreadVars;

/* clear key vars so we don't need to call the expensive
 * memset or bzero
 */
#define CLEAR_PACKET(p) { \
    CLEAR_ADDR(&p->src); \
    CLEAR_ADDR(&p->dst); \
    if ((p)->tcph != NULL) { \
        CLEAR_TCP_PACKET((p)); \
    } \
    (p)->ethh = NULL; \
    (p)->ppph = NULL; \
    (p)->greh = NULL; \
    (p)->vlanh = NULL; \
    (p)->ip4h = NULL; \
    (p)->ip6h = NULL; \
    (p)->action = 0; \
    (p)->pktlen = 0; \
    (p)->tunnel_pkt = 0; \
    (p)->tunnel_verdicted = 0; \
    (p)->rtv_cnt = 0; \
    (p)->tpr_cnt = 0; \
    (p)->root = NULL; \
    (p)->proto = 0; \
    (p)->sp = 0; \
    (p)->dp = 0; \
    (p)->flow = NULL; \
    (p)->flowflags = 0; \
    (p)->flags = 0; \
    (p)->alerts.cnt = 0; \
    if ((p)->pktvar != NULL) { \
        PktVarFree((p)->pktvar); \
    } \
    (p)->pktvar = NULL; \
    (p)->recursion_level = 0; \
    (p)->ts.tv_sec = 0; \
    (p)->ts.tv_usec = 0; \
}

/* reset these to -1(indicates that the packet is fresh from the queue) */
#define RESET_PACKET_CSUMS(p) { \
    (p)->ip4c.comp_csum = -1; \
    (p)->tcpc.comp_csum = -1; \
    (p)->udpc.comp_csum = -1;  \
    (p)->icmpv4c.comp_csum = -1; \
    (p)->icmpv6c.comp_csum = -1; \
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
    SCMutexLock((p)->root ? &(p)->root->mutex_rtv_cnt : &(p)->mutex_rtv_cnt); \
    ((p)->root ? (p)->root->rtv_cnt++ : (p)->rtv_cnt++); \
    SCMutexUnlock((p)->root ? &(p)->root->mutex_rtv_cnt : &(p)->mutex_rtv_cnt); \
}

#define TUNNEL_INCR_PKT_TPR(p) \
{ \
    SCMutexLock((p)->root ? &(p)->root->mutex_rtv_cnt : &(p)->mutex_rtv_cnt); \
    ((p)->root ? (p)->root->tpr_cnt++ : (p)->tpr_cnt++); \
    SCMutexUnlock((p)->root ? &(p)->root->mutex_rtv_cnt : &(p)->mutex_rtv_cnt); \
}
#define TUNNEL_DECR_PKT_TPR(p) \
{ \
    SCMutexLock((p)->root ? &(p)->root->mutex_rtv_cnt : &(p)->mutex_rtv_cnt); \
    ((p)->root ? (p)->root->tpr_cnt-- : (p)->tpr_cnt--); \
    SCMutexUnlock((p)->root ? &(p)->root->mutex_rtv_cnt : &(p)->mutex_rtv_cnt); \
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


void DecodeRegisterPerfCounters(DecodeThreadVars *, ThreadVars *);

/* decoder functions */
void DecodeEthernet(ThreadVars *, DecodeThreadVars *, Packet *, uint8_t *, uint16_t, PacketQueue *);
void DecodeSll(ThreadVars *, DecodeThreadVars *, Packet *, uint8_t *, uint16_t, PacketQueue *);
void DecodePPP(ThreadVars *, DecodeThreadVars *, Packet *, uint8_t *, uint16_t, PacketQueue *);
void DecodePPPOESession(ThreadVars *, DecodeThreadVars *, Packet *, uint8_t *, uint16_t, PacketQueue *);
void DecodePPPOEDiscovery(ThreadVars *, DecodeThreadVars *, Packet *, uint8_t *, uint16_t, PacketQueue *);
void DecodeTunnel(ThreadVars *, DecodeThreadVars *, Packet *, uint8_t *, uint16_t, PacketQueue *);
void DecodeRaw(ThreadVars *, DecodeThreadVars *, Packet *, uint8_t *, uint16_t, PacketQueue *);
void DecodeIPV4(ThreadVars *, DecodeThreadVars *, Packet *, uint8_t *, uint16_t, PacketQueue *);
void DecodeIPV6(ThreadVars *, DecodeThreadVars *, Packet *, uint8_t *, uint16_t, PacketQueue *);
void DecodeICMPV4(ThreadVars *, DecodeThreadVars *, Packet *, uint8_t *, uint16_t, PacketQueue *);
void DecodeICMPV6(ThreadVars *, DecodeThreadVars *, Packet *, uint8_t *, uint16_t, PacketQueue *);
void DecodeTCP(ThreadVars *, DecodeThreadVars *, Packet *, uint8_t *, uint16_t, PacketQueue *);
void DecodeUDP(ThreadVars *, DecodeThreadVars *, Packet *, uint8_t *, uint16_t, PacketQueue *);
void DecodeGRE(ThreadVars *, DecodeThreadVars *, Packet *, uint8_t *, uint16_t, PacketQueue *);
void DecodeVLAN(ThreadVars *, DecodeThreadVars *, Packet *, uint8_t *, uint16_t, PacketQueue *);

Packet *SetupPkt (void);
Packet *TunnelPktSetup(ThreadVars *, DecodeThreadVars *, Packet *, uint8_t *, uint16_t, uint8_t);

inline void DecodeSetNoPayloadInspectionFlag(Packet *);
inline void DecodeSetNoPacketInspectionFlag(Packet *);

#define DECODER_SET_EVENT(p, e)   ((p)->events[(e/8)] |= (1<<(e%8)))
#define DECODER_ISSET_EVENT(p, e) ((p)->events[(e/8)] & (1<<(e%8)))


/* older libcs don't contain a def for IPPROTO_DCCP
 * inside of <netinet/in.h>
 * if it isn't defined let's define it here.
 */
#ifndef IPPROTO_DCCP
#define IPPROTO_DCCP 33
#endif

/* pcap provides this, but we don't want to depend on libpcap */
#ifndef DLT_EN10MB
#define DLT_EN10MB 1
#endif

/* taken from pcap's bpf.h */
#ifndef DLT_RAW
#ifdef __OpenBSD__
#define DLT_RAW     14  /* raw IP */
#else
#define DLT_RAW     12  /* raw IP */
#endif
#endif

/** libpcap shows us the way to linktype codes
 * \todo we need more & maybe put them in a separate file? */
#define LINKTYPE_ETHERNET   DLT_EN10MB
#define LINKTYPE_LINUX_SLL  113
#define LINKTYPE_PPP        9
#define LINKTYPE_RAW        DLT_RAW
#define PPP_OVER_GRE        11
#define VLAN_OVER_GRE       13

/*Packet Flags*/
#define PKT_NOPACKET_INSPECTION         0x01    /**< Flag to indicate that packet header or contents should not be inspected*/
#define PKT_NOPAYLOAD_INSPECTION        0x02    /**< Flag to indicate that packet contents should not be inspected*/

#endif /* __DECODE_H__ */

