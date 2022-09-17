/* Copyright (C) 2007-2022 Open Information Security Foundation
 *
 * You can copy, redistribute or modify this Program under the terms of
 * the GNU General Public License version 2 as published by the Free
 * Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 */

/**
 * \file
 *
 * \author Victor Julien <victor@inliniac.net>
 */

#ifndef __DECODE_H__
#define __DECODE_H__

//#define DBG_THREADS
#define COUNTERS

#include "suricata-common.h"
#include "suricata-plugin.h"
#include "threadvars.h"
#include "util-debug.h"
#include "decode-events.h"
#ifdef PROFILING
#include "flow-worker.h"
#include "app-layer-protos.h"
#endif

#ifdef HAVE_NAPATECH
#include "util-napatech.h"
#endif /* HAVE_NAPATECH */


typedef enum {
    CHECKSUM_VALIDATION_DISABLE,
    CHECKSUM_VALIDATION_ENABLE,
    CHECKSUM_VALIDATION_AUTO,
    CHECKSUM_VALIDATION_RXONLY,
    CHECKSUM_VALIDATION_KERNEL,
} ChecksumValidationMode;

enum PktSrcEnum {
    PKT_SRC_WIRE = 1,
    PKT_SRC_DECODER_GRE,
    PKT_SRC_DECODER_IPV4,
    PKT_SRC_DECODER_IPV6,
    PKT_SRC_DECODER_TEREDO,
    PKT_SRC_DEFRAG,
    PKT_SRC_FFR,
    PKT_SRC_STREAM_TCP_DETECTLOG_FLUSH,
    PKT_SRC_DECODER_VXLAN,
    PKT_SRC_DETECT_RELOAD_FLUSH,
    PKT_SRC_CAPTURE_TIMEOUT,
    PKT_SRC_DECODER_GENEVE,
};

#include "source-nflog.h"
#include "source-nfq.h"
#include "source-ipfw.h"
#include "source-pcap.h"
#include "source-af-packet.h"
#include "source-netmap.h"
#include "source-windivert.h"
#ifdef HAVE_DPDK
#include "source-dpdk.h"
#endif
#ifdef HAVE_PF_RING_FLOW_OFFLOAD
#include "source-pfring.h"
#endif

#include "action-globals.h"

#include "decode-ethernet.h"
#include "decode-gre.h"
#include "decode-ppp.h"
#include "decode-pppoe.h"
#include "decode-ipv4.h"
#include "decode-ipv6.h"
#include "decode-icmpv4.h"
#include "decode-icmpv6.h"
#include "decode-tcp.h"
#include "decode-udp.h"
#include "decode-sctp.h"
#include "decode-esp.h"
#include "decode-vlan.h"
#include "decode-mpls.h"


/* forward declarations */
struct DetectionEngineThreadCtx_;
typedef struct AppLayerThreadCtx_ AppLayerThreadCtx;

struct PktPool_;

/* declare these here as they are called from the
 * PACKET_RECYCLE and PACKET_CLEANUP macro's. */
typedef struct AppLayerDecoderEvents_ AppLayerDecoderEvents;
void AppLayerDecoderEventsResetEvents(AppLayerDecoderEvents *events);
void AppLayerDecoderEventsFreeEvents(AppLayerDecoderEvents **events);

/* Address */
typedef struct Address_ {
    char family;
    union {
        uint32_t        address_un_data32[4]; /* type-specific field */
        uint16_t        address_un_data16[8]; /* type-specific field */
        uint8_t         address_un_data8[16]; /* type-specific field */
        struct in6_addr address_un_in6;
    } address;
} Address;

#define addr_data32 address.address_un_data32
#define addr_data16 address.address_un_data16
#define addr_data8  address.address_un_data8
#define addr_in6addr    address.address_un_in6

#define COPY_ADDRESS(a, b) do {                    \
        (b)->family = (a)->family;                 \
        (b)->addr_data32[0] = (a)->addr_data32[0]; \
        (b)->addr_data32[1] = (a)->addr_data32[1]; \
        (b)->addr_data32[2] = (a)->addr_data32[2]; \
        (b)->addr_data32[3] = (a)->addr_data32[3]; \
    } while (0)

/* Set the IPv4 addresses into the Addrs of the Packet.
 * Make sure p->ip4h is initialized and validated.
 *
 * We set the rest of the struct to 0 so we can
 * prevent using memset. */
#define SET_IPV4_SRC_ADDR(p, a) do {                              \
        (a)->family = AF_INET;                                    \
        (a)->addr_data32[0] = (uint32_t)(p)->ip4h->s_ip_src.s_addr; \
        (a)->addr_data32[1] = 0;                                  \
        (a)->addr_data32[2] = 0;                                  \
        (a)->addr_data32[3] = 0;                                  \
    } while (0)

#define SET_IPV4_DST_ADDR(p, a) do {                              \
        (a)->family = AF_INET;                                    \
        (a)->addr_data32[0] = (uint32_t)(p)->ip4h->s_ip_dst.s_addr; \
        (a)->addr_data32[1] = 0;                                  \
        (a)->addr_data32[2] = 0;                                  \
        (a)->addr_data32[3] = 0;                                  \
    } while (0)

/* clear the address structure by setting all fields to 0 */
#define CLEAR_ADDR(a) do {       \
        (a)->family = 0;         \
        (a)->addr_data32[0] = 0; \
        (a)->addr_data32[1] = 0; \
        (a)->addr_data32[2] = 0; \
        (a)->addr_data32[3] = 0; \
    } while (0)

/* Set the IPv6 addresses into the Addrs of the Packet.
 * Make sure p->ip6h is initialized and validated. */
#define SET_IPV6_SRC_ADDR(p, a) do {                    \
        (a)->family = AF_INET6;                         \
        (a)->addr_data32[0] = (p)->ip6h->s_ip6_src[0];  \
        (a)->addr_data32[1] = (p)->ip6h->s_ip6_src[1];  \
        (a)->addr_data32[2] = (p)->ip6h->s_ip6_src[2];  \
        (a)->addr_data32[3] = (p)->ip6h->s_ip6_src[3];  \
    } while (0)

#define SET_IPV6_DST_ADDR(p, a) do {                    \
        (a)->family = AF_INET6;                         \
        (a)->addr_data32[0] = (p)->ip6h->s_ip6_dst[0];  \
        (a)->addr_data32[1] = (p)->ip6h->s_ip6_dst[1];  \
        (a)->addr_data32[2] = (p)->ip6h->s_ip6_dst[2];  \
        (a)->addr_data32[3] = (p)->ip6h->s_ip6_dst[3];  \
    } while (0)

/* Set the TCP ports into the Ports of the Packet.
 * Make sure p->tcph is initialized and validated. */
#define SET_TCP_SRC_PORT(pkt, prt) do {            \
        SET_PORT(TCP_GET_SRC_PORT((pkt)), *(prt)); \
    } while (0)

#define SET_TCP_DST_PORT(pkt, prt) do {            \
        SET_PORT(TCP_GET_DST_PORT((pkt)), *(prt)); \
    } while (0)

/* Set the UDP ports into the Ports of the Packet.
 * Make sure p->udph is initialized and validated. */
#define SET_UDP_SRC_PORT(pkt, prt) do {            \
        SET_PORT(UDP_GET_SRC_PORT((pkt)), *(prt)); \
    } while (0)
#define SET_UDP_DST_PORT(pkt, prt) do {            \
        SET_PORT(UDP_GET_DST_PORT((pkt)), *(prt)); \
    } while (0)

/* Set the SCTP ports into the Ports of the Packet.
 * Make sure p->sctph is initialized and validated. */
#define SET_SCTP_SRC_PORT(pkt, prt) do {            \
        SET_PORT(SCTP_GET_SRC_PORT((pkt)), *(prt)); \
    } while (0)

#define SET_SCTP_DST_PORT(pkt, prt) do {            \
        SET_PORT(SCTP_GET_DST_PORT((pkt)), *(prt)); \
    } while (0)


#define GET_IPV4_SRC_ADDR_U32(p) ((p)->src.addr_data32[0])
#define GET_IPV4_DST_ADDR_U32(p) ((p)->dst.addr_data32[0])
#define GET_IPV4_SRC_ADDR_PTR(p) ((p)->src.addr_data32)
#define GET_IPV4_DST_ADDR_PTR(p) ((p)->dst.addr_data32)

#define GET_IPV6_SRC_IN6ADDR(p) ((p)->src.addr_in6addr)
#define GET_IPV6_DST_IN6ADDR(p) ((p)->dst.addr_in6addr)
#define GET_IPV6_SRC_ADDR(p) ((p)->src.addr_data32)
#define GET_IPV6_DST_ADDR(p) ((p)->dst.addr_data32)
#define GET_TCP_SRC_PORT(p)  ((p)->sp)
#define GET_TCP_DST_PORT(p)  ((p)->dp)

#define GET_PKT_LEN(p) ((p)->pktlen)
#define GET_PKT_DATA(p) ((((p)->ext_pkt) == NULL ) ? (uint8_t *)((p) + 1) : (p)->ext_pkt)
#define GET_PKT_DIRECT_DATA(p) (uint8_t *)((p) + 1)
#define GET_PKT_DIRECT_MAX_SIZE(p) (default_packet_size)

#define SET_PKT_LEN(p, len) do { \
    (p)->pktlen = (len); \
    } while (0)


/* Port is just a uint16_t */
typedef uint16_t Port;
#define SET_PORT(v, p) ((p) = (v))
#define COPY_PORT(a,b) ((b) = (a))

#define CMP_ADDR(a1, a2) \
    (((a1)->addr_data32[3] == (a2)->addr_data32[3] && \
      (a1)->addr_data32[2] == (a2)->addr_data32[2] && \
      (a1)->addr_data32[1] == (a2)->addr_data32[1] && \
      (a1)->addr_data32[0] == (a2)->addr_data32[0]))
#define CMP_PORT(p1, p2) \
    ((p1) == (p2))

/*Given a packet pkt offset to the start of the ip header in a packet
 *We determine the ip version. */
#define IP_GET_RAW_VER(pkt) ((((pkt)[0] & 0xf0) >> 4))

#define PKT_IS_IPV4(p)      (((p)->ip4h != NULL))
#define PKT_IS_IPV6(p)      (((p)->ip6h != NULL))
#define PKT_IS_TCP(p)       (((p)->tcph != NULL))
#define PKT_IS_UDP(p)       (((p)->udph != NULL))
#define PKT_IS_ICMPV4(p)    (((p)->icmpv4h != NULL))
#define PKT_IS_ICMPV6(p)    (((p)->icmpv6h != NULL))
#define PKT_IS_TOSERVER(p)  (((p)->flowflags & FLOW_PKT_TOSERVER))
#define PKT_IS_TOCLIENT(p)  (((p)->flowflags & FLOW_PKT_TOCLIENT))

#define IPH_IS_VALID(p) (PKT_IS_IPV4((p)) || PKT_IS_IPV6((p)))

/* Retrieve proto regardless of IP version */
#define IP_GET_IPPROTO(p) \
    (p->proto ? p->proto : \
    (PKT_IS_IPV4((p))? IPV4_GET_IPPROTO((p)) : (PKT_IS_IPV6((p))? IPV6_GET_L4PROTO((p)) : 0)))

/* structure to store the sids/gids/etc the detection engine
 * found in this packet */
typedef struct PacketAlert_ {
    SigIntId num; /* Internal num, used for sorting */
    uint8_t action; /* Internal num, used for thresholding */
    uint8_t flags;
    const struct Signature_ *s;
    uint64_t tx_id; /* Used for sorting */
    int64_t frame_id;
} PacketAlert;

/* flag to indicate the rule action (drop/pass) needs to be applied to the flow */
#define PACKET_ALERT_FLAG_APPLY_ACTION_TO_FLOW 0x1
/** alert was generated based on state */
#define PACKET_ALERT_FLAG_STATE_MATCH   0x02
/** alert was generated based on stream */
#define PACKET_ALERT_FLAG_STREAM_MATCH  0x04
/** alert is in a tx, tx_id set */
#define PACKET_ALERT_FLAG_TX            0x08
/** action was changed by rate_filter */
#define PACKET_ALERT_RATE_FILTER_MODIFIED   0x10
/** alert is in a frame, frame_id set */
#define PACKET_ALERT_FLAG_FRAME 0x20

extern uint16_t packet_alert_max;
#define PACKET_ALERT_MAX 15

typedef struct PacketAlerts_ {
    uint16_t cnt;
    uint16_t discarded;
    uint16_t suppressed;
    PacketAlert *alerts;
    /* single pa used when we're dropping,
     * so we can log it out in the drop log. */
    PacketAlert drop;
} PacketAlerts;

PacketAlert *PacketAlertCreate(void);

void PacketAlertFree(PacketAlert *pa);

/** number of decoder events we support per packet. Power of 2 minus 1
 *  for memory layout */
#define PACKET_ENGINE_EVENT_MAX 15

/** data structure to store decoder, defrag and stream events */
typedef struct PacketEngineEvents_ {
    uint8_t cnt;                                /**< number of events */
    uint8_t events[PACKET_ENGINE_EVENT_MAX];   /**< array of events */
} PacketEngineEvents;

typedef struct PktVar_ {
    uint32_t id;
    struct PktVar_ *next; /* right now just implement this as a list,
                           * in the long run we have thing of something
                           * faster. */
    uint16_t key_len;
    uint16_t value_len;
    uint8_t *key;
    uint8_t *value;
} PktVar;

#ifdef PROFILING

/** \brief Per TMM stats storage */
typedef struct PktProfilingTmmData_ {
    uint64_t ticks_start;
    uint64_t ticks_end;
#ifdef PROFILE_LOCKING
    uint64_t mutex_lock_cnt;
    uint64_t mutex_lock_wait_ticks;
    uint64_t mutex_lock_contention;
    uint64_t spin_lock_cnt;
    uint64_t spin_lock_wait_ticks;
    uint64_t spin_lock_contention;
    uint64_t rww_lock_cnt;
    uint64_t rww_lock_wait_ticks;
    uint64_t rww_lock_contention;
    uint64_t rwr_lock_cnt;
    uint64_t rwr_lock_wait_ticks;
    uint64_t rwr_lock_contention;
#endif
} PktProfilingTmmData;

typedef struct PktProfilingData_ {
    uint64_t ticks_start;
    uint64_t ticks_end;
} PktProfilingData;

typedef struct PktProfilingDetectData_ {
    uint64_t ticks_start;
    uint64_t ticks_end;
    uint64_t ticks_spent;
} PktProfilingDetectData;

typedef struct PktProfilingAppData_ {
    uint64_t ticks_spent;
} PktProfilingAppData;

typedef struct PktProfilingLoggerData_ {
    uint64_t ticks_start;
    uint64_t ticks_end;
    uint64_t ticks_spent;
} PktProfilingLoggerData;

typedef struct PktProfilingPrefilterEngine_ {
    uint64_t ticks_spent;
} PktProfilingPrefilterEngine;

typedef struct PktProfilingPrefilterData_ {
    PktProfilingPrefilterEngine *engines;
    uint32_t size;          /**< array size */
} PktProfilingPrefilterData;

/** \brief Per pkt stats storage */
typedef struct PktProfiling_ {
    uint64_t ticks_start;
    uint64_t ticks_end;

    PktProfilingTmmData tmm[TMM_SIZE];
    PktProfilingData flowworker[PROFILE_FLOWWORKER_SIZE];
    PktProfilingAppData app[ALPROTO_MAX];
    PktProfilingDetectData detect[PROF_DETECT_SIZE];
    PktProfilingLoggerData logger[LOGGER_SIZE];
    uint64_t proto_detect;
} PktProfiling;

#endif /* PROFILING */

enum PacketDropReason {
    PKT_DROP_REASON_NOT_SET = 0,
    PKT_DROP_REASON_DECODE_ERROR,
    PKT_DROP_REASON_DEFRAG_ERROR,
    PKT_DROP_REASON_DEFRAG_MEMCAP,
    PKT_DROP_REASON_FLOW_MEMCAP,
    PKT_DROP_REASON_FLOW_DROP,
    PKT_DROP_REASON_APPLAYER_ERROR,
    PKT_DROP_REASON_APPLAYER_MEMCAP,
    PKT_DROP_REASON_RULES,
    PKT_DROP_REASON_RULES_THRESHOLD, /**< detection_filter in action */
    PKT_DROP_REASON_STREAM_ERROR,
    PKT_DROP_REASON_STREAM_MEMCAP,
    PKT_DROP_REASON_STREAM_MIDSTREAM,
};

/* forward declaration since Packet struct definition requires this */
struct PacketQueue_;

/* sizes of the members:
 * src: 17 bytes
 * dst: 17 bytes
 * sp/type: 1 byte
 * dp/code: 1 byte
 * proto: 1 byte
 * recurs: 1 byte
 *
 * sum of above: 38 bytes
 *
 * flow ptr: 4/8 bytes
 * flags: 1 byte
 * flowflags: 1 byte
 *
 * sum of above 44/48 bytes
 */
typedef struct Packet_
{
    /* Addresses, Ports and protocol
     * these are on top so we can use
     * the Packet as a hash key */
    Address src;
    Address dst;
    union {
        Port sp;
        // icmp type and code of this packet
        struct {
            uint8_t type;
            uint8_t code;
        } icmp_s;
    };
    union {
        Port dp;
        // icmp type and code of the expected counterpart (for flows)
        struct {
            uint8_t type;
            uint8_t code;
        } icmp_d;
    };
    uint8_t proto;
    /* make sure we can't be attacked on when the tunneled packet
     * has the exact same tuple as the lower levels */
    uint8_t recursion_level;

    uint16_t vlan_id[2];
    uint8_t vlan_idx;

    /* flow */
    uint8_t flowflags;
    /* coccinelle: Packet:flowflags:FLOW_PKT_ */

    /* Pkt Flags */
    uint32_t flags;

    struct Flow_ *flow;

    /* raw hash value for looking up the flow, will need to modulated to the
     * hash size still */
    uint32_t flow_hash;

    struct timeval ts;

    union {
        /* nfq stuff */
#ifdef HAVE_NFLOG
        NFLOGPacketVars nflog_v;
#endif /* HAVE_NFLOG */
#ifdef NFQ
        NFQPacketVars nfq_v;
#endif /* NFQ */
#ifdef IPFW
        IPFWPacketVars ipfw_v;
#endif /* IPFW */
#ifdef AF_PACKET
        AFPPacketVars afp_v;
#endif
#ifdef HAVE_NETMAP
        NetmapPacketVars netmap_v;
#endif
#ifdef HAVE_PFRING
#ifdef HAVE_PF_RING_FLOW_OFFLOAD
        PfringPacketVars pfring_v;
#endif
#endif
#ifdef WINDIVERT
        WinDivertPacketVars windivert_v;
#endif /* WINDIVERT */
#ifdef HAVE_DPDK
        DPDKPacketVars dpdk_v;
#endif

        /* A chunk of memory that a plugin can use for its packet vars. */
        uint8_t plugin_v[PLUGIN_VAR_SIZE];

        /** libpcap vars: shared by Pcap Live mode and Pcap File mode */
        PcapPacketVars pcap_v;
    };

    /** The release function for packet structure and data */
    void (*ReleasePacket)(struct Packet_ *);
    /** The function triggering bypass the flow in the capture method.
     * Return 1 for success and 0 on error */
    int (*BypassPacketsFlow)(struct Packet_ *);

    /* pkt vars */
    PktVar *pktvar;

    /* header pointers */
    EthernetHdr *ethh;

    /* Checksum for IP packets. */
    int32_t level3_comp_csum;
    /* Check sum for TCP, UDP or ICMP packets */
    int32_t level4_comp_csum;

    IPV4Hdr *ip4h;

    IPV6Hdr *ip6h;

    /* IPv4 and IPv6 are mutually exclusive */
    union {
        IPV4Vars ip4vars;
        struct {
            IPV6Vars ip6vars;
            IPV6ExtHdrs ip6eh;
        };
    };
    /* Can only be one of TCP, UDP, ICMP at any given time */
    union {
        TCPVars tcpvars;
        ICMPV4Vars icmpv4vars;
        ICMPV6Vars icmpv6vars;
    } l4vars;
#define tcpvars     l4vars.tcpvars
#define icmpv4vars  l4vars.icmpv4vars
#define icmpv6vars  l4vars.icmpv6vars

    TCPHdr *tcph;

    UDPHdr *udph;

    SCTPHdr *sctph;

    ESPHdr *esph;

    ICMPV4Hdr *icmpv4h;

    ICMPV6Hdr *icmpv6h;

    PPPHdr *ppph;
    PPPOESessionHdr *pppoesh;
    PPPOEDiscoveryHdr *pppoedh;

    GREHdr *greh;

    /* ptr to the payload of the packet
     * with it's length. */
    uint8_t *payload;
    uint16_t payload_len;

    /* IPS action to take */
    uint8_t action;

    uint8_t pkt_src;

    /* storage: set to pointer to heap and extended via allocation if necessary */
    uint32_t pktlen;
    uint8_t *ext_pkt;

    /* Incoming interface */
    struct LiveDevice_ *livedev;

    PacketAlerts alerts;

    struct Host_ *host_src;
    struct Host_ *host_dst;

    /** packet number in the pcap file, matches wireshark */
    uint64_t pcap_cnt;


    /* engine events */
    PacketEngineEvents events;

    AppLayerDecoderEvents *app_layer_events;

    /* double linked list ptrs */
    struct Packet_ *next;
    struct Packet_ *prev;

    /** data linktype in host order */
    int datalink;

    /* count decoded layers of packet : too many layers
     * cause issues with performance and stability (stack exhaustion)
     */
    uint8_t nb_decoded_layers;

    /* enum PacketDropReason::PKT_DROP_REASON_* as uint8_t for compactness */
    uint8_t drop_reason;

    /* tunnel/encapsulation handling */
    struct Packet_ *root; /* in case of tunnel this is a ptr
                           * to the 'real' packet, the one we
                           * need to set the verdict on --
                           * It should always point to the lowest
                           * packet in a encapsulated packet */

    /** mutex to protect access to:
     *  - tunnel_rtv_cnt
     *  - tunnel_tpr_cnt
     */
    SCMutex tunnel_mutex;
    /* ready to set verdict counter, only set in root */
    uint16_t tunnel_rtv_cnt;
    /* tunnel packet ref count */
    uint16_t tunnel_tpr_cnt;

    /** tenant id for this packet, if any. If 0 then no tenant was assigned. */
    uint32_t tenant_id;

    /* The Packet pool from which this packet was allocated. Used when returning
     * the packet to its owner's stack. If NULL, then allocated with malloc.
     */
    struct PktPool_ *pool;

#ifdef PROFILING
    PktProfiling *profile;
#endif
#ifdef HAVE_NAPATECH
    NapatechPacketVars ntpv;
#endif
} Packet;

/** highest mtu of the interfaces we monitor */
extern int g_default_mtu;
#define DEFAULT_MTU 1500
#define MINIMUM_MTU 68      /**< ipv4 minimum: rfc791 */

#define DEFAULT_PACKET_SIZE (DEFAULT_MTU + ETHERNET_HEADER_LEN)
/* storage: maximum ip packet size + link header */
#define MAX_PAYLOAD_SIZE (IPV6_HEADER_LEN + 65536 + 28)
extern uint32_t default_packet_size;
#define SIZE_OF_PACKET (default_packet_size + sizeof(Packet))

/** \brief Structure to hold thread specific data for all decode modules */
typedef struct DecodeThreadVars_
{
    /** Specific context for udp protocol detection (here atm) */
    AppLayerThreadCtx *app_tctx;

    /** stats/counters */
    uint16_t counter_pkts;
    uint16_t counter_bytes;
    uint16_t counter_avg_pkt_size;
    uint16_t counter_max_pkt_size;
    uint16_t counter_max_mac_addrs_src;
    uint16_t counter_max_mac_addrs_dst;

    uint16_t counter_invalid;

    uint16_t counter_eth;
    uint16_t counter_chdlc;
    uint16_t counter_ipv4;
    uint16_t counter_ipv6;
    uint16_t counter_tcp;
    uint16_t counter_udp;
    uint16_t counter_icmpv4;
    uint16_t counter_icmpv6;

    uint16_t counter_sll;
    uint16_t counter_raw;
    uint16_t counter_null;
    uint16_t counter_sctp;
    uint16_t counter_esp;
    uint16_t counter_ppp;
    uint16_t counter_geneve;
    uint16_t counter_gre;
    uint16_t counter_vlan;
    uint16_t counter_vlan_qinq;
    uint16_t counter_vxlan;
    uint16_t counter_vntag;
    uint16_t counter_ieee8021ah;
    uint16_t counter_pppoe;
    uint16_t counter_teredo;
    uint16_t counter_mpls;
    uint16_t counter_ipv4inipv6;
    uint16_t counter_ipv6inipv6;
    uint16_t counter_erspan;
    uint16_t counter_nsh;

    /** frag stats - defrag runs in the context of the decoder. */
    uint16_t counter_defrag_ipv4_fragments;
    uint16_t counter_defrag_ipv4_reassembled;
    uint16_t counter_defrag_ipv4_timeouts;
    uint16_t counter_defrag_ipv6_fragments;
    uint16_t counter_defrag_ipv6_reassembled;
    uint16_t counter_defrag_ipv6_timeouts;
    uint16_t counter_defrag_max_hit;

    uint16_t counter_flow_memcap;

    uint16_t counter_tcp_active_sessions;
    uint16_t counter_flow_total;
    uint16_t counter_flow_active;
    uint16_t counter_flow_tcp;
    uint16_t counter_flow_udp;
    uint16_t counter_flow_icmp4;
    uint16_t counter_flow_icmp6;
    uint16_t counter_flow_tcp_reuse;
    uint16_t counter_flow_get_used;
    uint16_t counter_flow_get_used_eval;
    uint16_t counter_flow_get_used_eval_reject;
    uint16_t counter_flow_get_used_eval_busy;
    uint16_t counter_flow_get_used_failed;

    uint16_t counter_flow_spare_sync;
    uint16_t counter_flow_spare_sync_empty;
    uint16_t counter_flow_spare_sync_incomplete;
    uint16_t counter_flow_spare_sync_avg;

    uint16_t counter_engine_events[DECODE_EVENT_MAX];

    /* thread data for flow logging api: only used at forced
     * flow recycle during lookups */
    void *output_flow_thread_data;

} DecodeThreadVars;

typedef struct CaptureStats_ {

    uint16_t counter_ips_accepted;
    uint16_t counter_ips_blocked;
    uint16_t counter_ips_rejected;
    uint16_t counter_ips_replaced;

} CaptureStats;

void CaptureStatsUpdate(ThreadVars *tv, CaptureStats *s, const Packet *p);
void CaptureStatsSetup(ThreadVars *tv, CaptureStats *s);

#define PACKET_CLEAR_L4VARS(p) do {                         \
        memset(&(p)->l4vars, 0x00, sizeof((p)->l4vars));    \
    } while (0)

/**
 *  \brief reset these to -1(indicates that the packet is fresh from the queue)
 */
#define PACKET_RESET_CHECKSUMS(p) do { \
        (p)->level3_comp_csum = -1;   \
        (p)->level4_comp_csum = -1;   \
    } while (0)

/* if p uses extended data, free them */
#define PACKET_FREE_EXTDATA(p) do {                 \
        if ((p)->ext_pkt) {                         \
            if (!((p)->flags & PKT_ZERO_COPY)) {    \
                SCFree((p)->ext_pkt);               \
            }                                       \
            (p)->ext_pkt = NULL;                    \
        }                                           \
    } while(0)

/* macro's for setting the action
 * handle the case of a root packet
 * for tunnels */

#define PACKET_SET_ACTION(p, a) (p)->action = (a)

static inline void PacketSetAction(Packet *p, const uint8_t a)
{
    if (likely(p->root == NULL)) {
        PACKET_SET_ACTION(p, a);
    } else {
        PACKET_SET_ACTION(p->root, a);
    }
}

#define PACKET_ALERT(p) PACKET_SET_ACTION(p, ACTION_ALERT)

#define PACKET_ACCEPT(p) PACKET_SET_ACTION(p, ACTION_ACCEPT)

#define PACKET_TEST_ACTION(p, a) (p)->action &(a)

#define PACKET_UPDATE_ACTION(p, a) (p)->action |= (a)
static inline void PacketUpdateAction(Packet *p, const uint8_t a)
{
    if (likely(p->root == NULL)) {
        PACKET_UPDATE_ACTION(p, a);
    } else {
        PACKET_UPDATE_ACTION(p->root, a);
    }
}

static inline void PacketDrop(Packet *p, const uint8_t action, enum PacketDropReason r)
{
    if (p->drop_reason == PKT_DROP_REASON_NOT_SET)
        p->drop_reason = (uint8_t)r;

    PACKET_UPDATE_ACTION(p, action);
}

static inline void PacketPass(Packet *p)
{
    PACKET_SET_ACTION(p, ACTION_PASS);
}

static inline uint8_t PacketTestAction(const Packet *p, const uint8_t a)
{
    if (likely(p->root == NULL)) {
        return PACKET_TEST_ACTION(p, a);
    } else {
        return PACKET_TEST_ACTION(p->root, a);
    }
}

#define TUNNEL_INCR_PKT_RTV_NOLOCK(p) do {                                          \
        ((p)->root ? (p)->root->tunnel_rtv_cnt++ : (p)->tunnel_rtv_cnt++);          \
    } while (0)

#define TUNNEL_INCR_PKT_TPR(p) do {                                                 \
        SCMutexLock((p)->root ? &(p)->root->tunnel_mutex : &(p)->tunnel_mutex);     \
        ((p)->root ? (p)->root->tunnel_tpr_cnt++ : (p)->tunnel_tpr_cnt++);          \
        SCMutexUnlock((p)->root ? &(p)->root->tunnel_mutex : &(p)->tunnel_mutex);   \
    } while (0)

#define TUNNEL_PKT_RTV(p) ((p)->root ? (p)->root->tunnel_rtv_cnt : (p)->tunnel_rtv_cnt)
#define TUNNEL_PKT_TPR(p) ((p)->root ? (p)->root->tunnel_tpr_cnt : (p)->tunnel_tpr_cnt)

#define IS_TUNNEL_PKT(p)            (((p)->flags & PKT_TUNNEL))
#define SET_TUNNEL_PKT(p)           ((p)->flags |= PKT_TUNNEL)
#define UNSET_TUNNEL_PKT(p)         ((p)->flags &= ~PKT_TUNNEL)
#define IS_TUNNEL_ROOT_PKT(p)       (IS_TUNNEL_PKT(p) && (p)->root == NULL)

#define IS_TUNNEL_PKT_VERDICTED(p)  (((p)->flags & PKT_TUNNEL_VERDICTED))
#define SET_TUNNEL_PKT_VERDICTED(p) ((p)->flags |= PKT_TUNNEL_VERDICTED)

enum DecodeTunnelProto {
    DECODE_TUNNEL_ETHERNET,
    DECODE_TUNNEL_ERSPANII,
    DECODE_TUNNEL_ERSPANI,
    DECODE_TUNNEL_VLAN,
    DECODE_TUNNEL_IPV4,
    DECODE_TUNNEL_IPV6,
    DECODE_TUNNEL_IPV6_TEREDO, /**< separate protocol for stricter error handling */
    DECODE_TUNNEL_PPP,
    DECODE_TUNNEL_NSH,
    DECODE_TUNNEL_UNSET
};

Packet *PacketTunnelPktSetup(ThreadVars *tv, DecodeThreadVars *dtv, Packet *parent,
                             const uint8_t *pkt, uint32_t len, enum DecodeTunnelProto proto);
Packet *PacketDefragPktSetup(Packet *parent, const uint8_t *pkt, uint32_t len, uint8_t proto);
void PacketDefragPktSetupParent(Packet *parent);
void DecodeRegisterPerfCounters(DecodeThreadVars *, ThreadVars *);
Packet *PacketGetFromQueueOrAlloc(void);
Packet *PacketGetFromAlloc(void);
void PacketDecodeFinalize(ThreadVars *tv, DecodeThreadVars *dtv, Packet *p);
void PacketUpdateEngineEventCounters(ThreadVars *tv,
        DecodeThreadVars *dtv, Packet *p);
void PacketFree(Packet *p);
void PacketFreeOrRelease(Packet *p);
int PacketCallocExtPkt(Packet *p, int datalen);
int PacketCopyData(Packet *p, const uint8_t *pktdata, uint32_t pktlen);
int PacketSetData(Packet *p, const uint8_t *pktdata, uint32_t pktlen);
int PacketCopyDataOffset(Packet *p, uint32_t offset, const uint8_t *data, uint32_t datalen);
const char *PktSrcToString(enum PktSrcEnum pkt_src);
void PacketBypassCallback(Packet *p);
void PacketSwap(Packet *p);

DecodeThreadVars *DecodeThreadVarsAlloc(ThreadVars *);
void DecodeThreadVarsFree(ThreadVars *, DecodeThreadVars *);
void DecodeUpdatePacketCounters(ThreadVars *tv,
                                const DecodeThreadVars *dtv, const Packet *p);
const char *PacketDropReasonToString(enum PacketDropReason r);

/* decoder functions */
int DecodeEthernet(ThreadVars *, DecodeThreadVars *, Packet *, const uint8_t *, uint32_t);
int DecodeSll(ThreadVars *, DecodeThreadVars *, Packet *, const uint8_t *, uint32_t);
int DecodePPP(ThreadVars *, DecodeThreadVars *, Packet *, const uint8_t *, uint32_t);
int DecodePPPOESession(ThreadVars *, DecodeThreadVars *, Packet *, const uint8_t *, uint32_t);
int DecodePPPOEDiscovery(ThreadVars *, DecodeThreadVars *, Packet *, const uint8_t *, uint32_t);
int DecodeNull(ThreadVars *, DecodeThreadVars *, Packet *, const uint8_t *, uint32_t);
int DecodeRaw(ThreadVars *, DecodeThreadVars *, Packet *, const uint8_t *, uint32_t);
int DecodeIPV4(ThreadVars *, DecodeThreadVars *, Packet *, const uint8_t *, uint16_t);
int DecodeIPV6(ThreadVars *, DecodeThreadVars *, Packet *, const uint8_t *, uint16_t);
int DecodeICMPV4(ThreadVars *, DecodeThreadVars *, Packet *, const uint8_t *, uint32_t);
int DecodeICMPV6(ThreadVars *, DecodeThreadVars *, Packet *, const uint8_t *, uint32_t);
int DecodeTCP(ThreadVars *, DecodeThreadVars *, Packet *, const uint8_t *, uint16_t);
int DecodeUDP(ThreadVars *, DecodeThreadVars *, Packet *, const uint8_t *, uint16_t);
int DecodeSCTP(ThreadVars *, DecodeThreadVars *, Packet *, const uint8_t *, uint16_t);
int DecodeESP(ThreadVars *, DecodeThreadVars *, Packet *, const uint8_t *, uint16_t);
int DecodeGRE(ThreadVars *, DecodeThreadVars *, Packet *, const uint8_t *, uint32_t);
int DecodeVLAN(ThreadVars *, DecodeThreadVars *, Packet *, const uint8_t *, uint32_t);
int DecodeVNTag(ThreadVars *, DecodeThreadVars *, Packet *, const uint8_t *, uint32_t);
int DecodeIEEE8021ah(ThreadVars *, DecodeThreadVars *, Packet *, const uint8_t *, uint32_t);
int DecodeGeneve(ThreadVars *, DecodeThreadVars *, Packet *, const uint8_t *, uint32_t);
int DecodeVXLAN(ThreadVars *, DecodeThreadVars *, Packet *, const uint8_t *, uint32_t);
int DecodeMPLS(ThreadVars *, DecodeThreadVars *, Packet *, const uint8_t *, uint32_t);
int DecodeERSPAN(ThreadVars *, DecodeThreadVars *, Packet *, const uint8_t *, uint32_t);
int DecodeERSPANTypeI(ThreadVars *, DecodeThreadVars *, Packet *, const uint8_t *, uint32_t);
int DecodeCHDLC(ThreadVars *, DecodeThreadVars *, Packet *, const uint8_t *, uint32_t);
int DecodeTEMPLATE(ThreadVars *, DecodeThreadVars *, Packet *, const uint8_t *, uint32_t);
int DecodeNSH(ThreadVars *, DecodeThreadVars *, Packet *, const uint8_t *, uint32_t);

#ifdef UNITTESTS
void DecodeIPV6FragHeader(Packet *p, const uint8_t *pkt,
                          uint16_t hdrextlen, uint16_t plen,
                          uint16_t prev_hdrextlen);
#endif

void AddressDebugPrint(Address *);

typedef int (*DecoderFunc)(ThreadVars *tv, DecodeThreadVars *dtv, Packet *p,
         const uint8_t *pkt, uint32_t len);
void DecodeGlobalConfig(void);
void PacketAlertGetMaxConfig(void);
void DecodeUnregisterCounters(void);

#define ENGINE_SET_EVENT(p, e) do { \
    SCLogDebug("p %p event %d", (p), e); \
    if ((p)->events.cnt < PACKET_ENGINE_EVENT_MAX) { \
        (p)->events.events[(p)->events.cnt] = e; \
        (p)->events.cnt++; \
    } \
} while(0)

#define ENGINE_SET_INVALID_EVENT(p, e) do { \
    p->flags |= PKT_IS_INVALID; \
    ENGINE_SET_EVENT(p, e); \
} while(0)



#define ENGINE_ISSET_EVENT(p, e) ({ \
    int r = 0; \
    uint8_t u; \
    for (u = 0; u < (p)->events.cnt; u++) { \
        if ((p)->events.events[u] == (e)) { \
            r = 1; \
            break; \
        } \
    } \
    r; \
})

#ifndef IPPROTO_IPIP
#define IPPROTO_IPIP 4
#endif

/* older libcs don't contain a def for IPPROTO_DCCP
 * inside of <netinet/in.h>
 * if it isn't defined let's define it here.
 */
#ifndef IPPROTO_DCCP
#define IPPROTO_DCCP 33
#endif

/* older libcs don't contain a def for IPPROTO_SCTP
 * inside of <netinet/in.h>
 * if it isn't defined let's define it here.
 */
#ifndef IPPROTO_SCTP
#define IPPROTO_SCTP 132
#endif

#ifndef IPPROTO_MH
#define IPPROTO_MH 135
#endif

/* Host Identity Protocol (rfc 5201) */
#ifndef IPPROTO_HIP
#define IPPROTO_HIP 139
#endif

#ifndef IPPROTO_SHIM6
#define IPPROTO_SHIM6 140
#endif

/* pcap provides this, but we don't want to depend on libpcap */
#ifndef DLT_EN10MB
#define DLT_EN10MB 1
#endif

#ifndef DLT_C_HDLC
#define DLT_C_HDLC 104
#endif

/* taken from pcap's bpf.h */
#ifndef DLT_RAW
#ifdef __OpenBSD__
#define DLT_RAW     14  /* raw IP */
#else
#define DLT_RAW     12  /* raw IP */
#endif
#endif

#ifndef DLT_NULL
#define DLT_NULL 0
#endif

/** libpcap shows us the way to linktype codes
 * \todo we need more & maybe put them in a separate file? */
#define LINKTYPE_NULL        DLT_NULL
#define LINKTYPE_ETHERNET    DLT_EN10MB
#define LINKTYPE_LINUX_SLL   113
#define LINKTYPE_PPP         9
#define LINKTYPE_RAW         DLT_RAW
/* http://www.tcpdump.org/linktypes.html defines DLT_RAW as 101, yet others don't.
 * Libpcap on at least OpenBSD returns 101 as datalink type for RAW pcaps though. */
#define LINKTYPE_RAW2        101
#define LINKTYPE_IPV4        228
#define LINKTYPE_GRE_OVER_IP 778
#define LINKTYPE_CISCO_HDLC  DLT_C_HDLC
#define PPP_OVER_GRE         11
#define VLAN_OVER_GRE        13

/* Packet Flags */

/** Flag to indicate that packet header or contents should not be inspected */
#define PKT_NOPACKET_INSPECTION BIT_U32(0)
// vacancy

/** Flag to indicate that packet contents should not be inspected */
#define PKT_NOPAYLOAD_INSPECTION BIT_U32(2)
/** Packet was alloc'd this run, needs to be freed */
#define PKT_ALLOC BIT_U32(3)
/** Packet has matched a tag */
#define PKT_HAS_TAG BIT_U32(4)
/** Packet payload was added to reassembled stream */
#define PKT_STREAM_ADD BIT_U32(5)
/** Packet is part of established stream */
#define PKT_STREAM_EST BIT_U32(6)
/** Stream is in eof state */
#define PKT_STREAM_EOF BIT_U32(7)
#define PKT_HAS_FLOW   BIT_U32(8)
/** Pseudo packet to end the stream */
#define PKT_PSEUDO_STREAM_END BIT_U32(9)
/** Packet is modified by the stream engine, we need to recalc the csum and       \
                   reinject/replace */
#define PKT_STREAM_MODIFIED BIT_U32(10)
/** Packet mark is modified */
#define PKT_MARK_MODIFIED BIT_U32(11)
/** Exclude packet from pcap logging as it's part of a stream that has reassembly \
                   depth reached. */
#define PKT_STREAM_NOPCAPLOG BIT_U32(12)

#define PKT_TUNNEL           BIT_U32(13)
#define PKT_TUNNEL_VERDICTED BIT_U32(14)

/** Packet checksum is not computed (TX packet for example) */
#define PKT_IGNORE_CHECKSUM BIT_U32(15)
/** Packet comes from zero copy (ext_pkt must not be freed) */
#define PKT_ZERO_COPY BIT_U32(16)

#define PKT_HOST_SRC_LOOKED_UP BIT_U32(17)
#define PKT_HOST_DST_LOOKED_UP BIT_U32(18)

/** Packet is a fragment */
#define PKT_IS_FRAGMENT BIT_U32(19)
#define PKT_IS_INVALID  BIT_U32(20)
#define PKT_PROFILE     BIT_U32(21)

/** indication by decoder that it feels the packet should be handled by
 *  flow engine: Packet::flow_hash will be set */
#define PKT_WANTS_FLOW BIT_U32(22)

/** protocol detection done */
#define PKT_PROTO_DETECT_TS_DONE BIT_U32(23)
#define PKT_PROTO_DETECT_TC_DONE BIT_U32(24)

#define PKT_REBUILT_FRAGMENT                                                                       \
    BIT_U32(25) /**< Packet is rebuilt from                                                        \
                 * fragments. */
#define PKT_DETECT_HAS_STREAMDATA                                                                  \
    BIT_U32(26) /**< Set by Detect() if raw stream data is available. */

#define PKT_PSEUDO_DETECTLOG_FLUSH BIT_U32(27) /**< Detect/log flush for protocol upgrade */

/** Packet is part of stream in known bad condition (loss, wrong thread),
 *  so flag it for not setting stream events */
#define PKT_STREAM_NO_EVENTS BIT_U32(28)

/** We had no alert on flow before this packet */
#define PKT_FIRST_ALERTS BIT_U32(29)
#define PKT_FIRST_TAG    BIT_U32(30)

/** Packet updated the app-layer. */
#define PKT_APPLAYER_UPDATE BIT_U32(31)

/** \brief return 1 if the packet is a pseudo packet */
#define PKT_IS_PSEUDOPKT(p) \
    ((p)->flags & (PKT_PSEUDO_STREAM_END|PKT_PSEUDO_DETECTLOG_FLUSH))

#define PKT_SET_SRC(p, src_val) ((p)->pkt_src = src_val)

#define PKT_DEFAULT_MAX_DECODED_LAYERS 16
extern uint8_t decoder_max_layers;

static inline bool PacketIncreaseCheckLayers(Packet *p)
{
    p->nb_decoded_layers++;
    if (p->nb_decoded_layers >= decoder_max_layers) {
        ENGINE_SET_INVALID_EVENT(p, GENERIC_TOO_MANY_LAYERS);
        return false;
    }
    return true;
}

/** \brief Set the No payload inspection Flag for the packet.
 *
 * \param p Packet to set the flag in
 */
static inline void DecodeSetNoPayloadInspectionFlag(Packet *p)
{
    p->flags |= PKT_NOPAYLOAD_INSPECTION;
}

/** \brief Set the No packet inspection Flag for the packet.
 *
 * \param p Packet to set the flag in
 */
static inline void DecodeSetNoPacketInspectionFlag(Packet *p)
{
    p->flags |= PKT_NOPACKET_INSPECTION;
}

/** \brief return true if *this* packet needs to trigger a verdict.
 *
 *  If we have the root packet, and we have none outstanding,
 *  we can verdict now.
 *
 *  If we have a upper layer packet, it's the only one and root
 *  is already processed, we can verdict now.
 *
 *  Otherwise, a future packet will issue the verdict.
 */
static inline bool VerdictTunnelPacket(Packet *p)
{
    bool verdict = true;
    SCMutex *m = p->root ? &p->root->tunnel_mutex : &p->tunnel_mutex;
    SCMutexLock(m);
    const uint16_t outstanding = TUNNEL_PKT_TPR(p) - TUNNEL_PKT_RTV(p);
    SCLogDebug("tunnel: outstanding %u", outstanding);

    /* if there are packets outstanding, we won't verdict this one */
    if (IS_TUNNEL_ROOT_PKT(p) && !IS_TUNNEL_PKT_VERDICTED(p) && !outstanding) {
        // verdict
        SCLogDebug("root %p: verdict", p);
    } else if (!IS_TUNNEL_ROOT_PKT(p) && outstanding == 1 && p->root && IS_TUNNEL_PKT_VERDICTED(p->root)) {
        // verdict
        SCLogDebug("tunnel %p: verdict", p);
    } else {
        verdict = false;
    }
    SCMutexUnlock(m);
    return verdict;
}

static inline void DecodeLinkLayer(ThreadVars *tv, DecodeThreadVars *dtv,
        const int datalink, Packet *p, const uint8_t *data, const uint32_t len)
{
    /* call the decoder */
    switch (datalink) {
        case LINKTYPE_ETHERNET:
            DecodeEthernet(tv, dtv, p, data, len);
            break;
        case LINKTYPE_LINUX_SLL:
            DecodeSll(tv, dtv, p, data, len);
            break;
        case LINKTYPE_PPP:
            DecodePPP(tv, dtv, p, data, len);
            break;
        case LINKTYPE_RAW:
        case LINKTYPE_GRE_OVER_IP:
            DecodeRaw(tv, dtv, p, data, len);
            break;
        case LINKTYPE_NULL:
            DecodeNull(tv, dtv, p, data, len);
            break;
       case LINKTYPE_CISCO_HDLC:
            DecodeCHDLC(tv, dtv, p, data, len);
            break;
        default:
            SCLogError(SC_ERR_DATALINK_UNIMPLEMENTED, "datalink type "
                    "%"PRId32" not yet supported", datalink);
            break;
    }
}

/** \brief decode network layer
 *  \retval bool true if successful, false if unknown */
static inline bool DecodeNetworkLayer(ThreadVars *tv, DecodeThreadVars *dtv,
        const uint16_t proto, Packet *p, const uint8_t *data, const uint32_t len)
{
    switch (proto) {
        case ETHERNET_TYPE_IP: {
            uint16_t ip_len = (len < USHRT_MAX) ? (uint16_t)len : (uint16_t)USHRT_MAX;
            DecodeIPV4(tv, dtv, p, data, ip_len);
            break;
        }
        case ETHERNET_TYPE_IPV6: {
            uint16_t ip_len = (len < USHRT_MAX) ? (uint16_t)len : (uint16_t)USHRT_MAX;
            DecodeIPV6(tv, dtv, p, data, ip_len);
            break;
        }
        case ETHERNET_TYPE_PPPOE_SESS:
            DecodePPPOESession(tv, dtv, p, data, len);
            break;
        case ETHERNET_TYPE_PPPOE_DISC:
            DecodePPPOEDiscovery(tv, dtv, p, data, len);
            break;
        case ETHERNET_TYPE_VLAN:
        case ETHERNET_TYPE_8021AD:
        case ETHERNET_TYPE_8021QINQ:
            if (p->vlan_idx >= 2) {
                ENGINE_SET_EVENT(p,VLAN_HEADER_TOO_MANY_LAYERS);
            } else {
                DecodeVLAN(tv, dtv, p, data, len);
            }
            break;
        case ETHERNET_TYPE_8021AH:
            DecodeIEEE8021ah(tv, dtv, p, data, len);
            break;
        case ETHERNET_TYPE_ARP:
            break;
        case ETHERNET_TYPE_MPLS_UNICAST:
        case ETHERNET_TYPE_MPLS_MULTICAST:
            DecodeMPLS(tv, dtv, p, data, len);
            break;
        case ETHERNET_TYPE_DCE:
            if (unlikely(len < ETHERNET_DCE_HEADER_LEN)) {
                ENGINE_SET_INVALID_EVENT(p, DCE_PKT_TOO_SMALL);
            } else {
                DecodeEthernet(tv, dtv, p, data, len);
            }
            break;
        case ETHERNET_TYPE_VNTAG:
            DecodeVNTag(tv, dtv, p, data, len);
            break;
        case ETHERNET_TYPE_NSH:
            DecodeNSH(tv, dtv, p, data, len);
            break;
        default:
            SCLogDebug("unknown ether type: %" PRIx16 "", proto);
            return false;
    }
    return true;
}

#endif /* __DECODE_H__ */
