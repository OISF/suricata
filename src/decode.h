/* Copyright (C) 2007-2024 Open Information Security Foundation
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

#ifndef SURICATA_DECODE_H
#define SURICATA_DECODE_H

//#define DBG_THREADS
#define COUNTERS

#include "suricata-common.h"
#include "suricata-plugin.h"
#include "threadvars.h"
#include "util-debug.h"
#include "decode-events.h"
#include "util-exception-policy-types.h"
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
    CHECKSUM_VALIDATION_OFFLOAD,
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
    PKT_SRC_SHUTDOWN_FLUSH,
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
#ifdef HAVE_AF_XDP
#include "source-af-xdp.h"
#endif

#include "decode-ethernet.h"
#include "decode-gre.h"
#include "decode-ppp.h"
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
#include "decode-arp.h"

#include "util-validate.h"

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
#define SET_IPV4_SRC_ADDR(ip4h, a)                                                                 \
    do {                                                                                           \
        (a)->family = AF_INET;                                                                     \
        (a)->addr_data32[0] = (uint32_t)(ip4h)->s_ip_src.s_addr;                                   \
        (a)->addr_data32[1] = 0;                                                                   \
        (a)->addr_data32[2] = 0;                                                                   \
        (a)->addr_data32[3] = 0;                                                                   \
    } while (0)

#define SET_IPV4_DST_ADDR(ip4h, a)                                                                 \
    do {                                                                                           \
        (a)->family = AF_INET;                                                                     \
        (a)->addr_data32[0] = (uint32_t)(ip4h)->s_ip_dst.s_addr;                                   \
        (a)->addr_data32[1] = 0;                                                                   \
        (a)->addr_data32[2] = 0;                                                                   \
        (a)->addr_data32[3] = 0;                                                                   \
    } while (0)

/* Set the IPv6 addresses into the Addrs of the Packet. */
#define SET_IPV6_SRC_ADDR(ip6h, a)                                                                 \
    do {                                                                                           \
        (a)->family = AF_INET6;                                                                    \
        (a)->addr_data32[0] = (ip6h)->s_ip6_src[0];                                                \
        (a)->addr_data32[1] = (ip6h)->s_ip6_src[1];                                                \
        (a)->addr_data32[2] = (ip6h)->s_ip6_src[2];                                                \
        (a)->addr_data32[3] = (ip6h)->s_ip6_src[3];                                                \
    } while (0)

#define SET_IPV6_DST_ADDR(ip6h, a)                                                                 \
    do {                                                                                           \
        (a)->family = AF_INET6;                                                                    \
        (a)->addr_data32[0] = (ip6h)->s_ip6_dst[0];                                                \
        (a)->addr_data32[1] = (ip6h)->s_ip6_dst[1];                                                \
        (a)->addr_data32[2] = (ip6h)->s_ip6_dst[2];                                                \
        (a)->addr_data32[3] = (ip6h)->s_ip6_dst[3];                                                \
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

#define GET_PKT_LEN(p)             (p)->pktlen
#define GET_PKT_DATA(p)            (((p)->ext_pkt == NULL) ? GET_PKT_DIRECT_DATA(p) : (p)->ext_pkt)
#define GET_PKT_DIRECT_DATA(p)     (p)->pkt_data
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

#define PKT_IS_TCP(p)       (((p)->tcph != NULL))
#define PKT_IS_UDP(p)       (((p)->udph != NULL))
#define PKT_IS_ICMPV4(p)    (((p)->icmpv4h != NULL))
#define PKT_IS_ICMPV6(p)    (((p)->icmpv6h != NULL))
#define PKT_IS_TOSERVER(p)  (((p)->flowflags & FLOW_PKT_TOSERVER))
#define PKT_IS_TOCLIENT(p)  (((p)->flowflags & FLOW_PKT_TOCLIENT))

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
    PKT_DROP_REASON_STREAM_REASSEMBLY,
    PKT_DROP_REASON_NFQ_ERROR,    /**< no nfq verdict, must be error */
    PKT_DROP_REASON_INNER_PACKET, /**< drop issued by inner (tunnel) packet */
    PKT_DROP_REASON_MAX,
};

enum PacketTunnelType {
    PacketTunnelNone,
    PacketTunnelRoot,
    PacketTunnelChild,
};

/* forward declaration since Packet struct definition requires this */
struct PacketQueue_;

enum PacketL2Types {
    PACKET_L2_UNKNOWN = 0,
    PACKET_L2_ETHERNET,
};

struct PacketL2 {
    enum PacketL2Types type;
    union L2Hdrs {
        EthernetHdr *ethh;
    } hdrs;
};

enum PacketL3Types {
    PACKET_L3_UNKNOWN = 0,
    PACKET_L3_IPV4,
    PACKET_L3_IPV6,
    PACKET_L3_ARP,
};

struct PacketL3 {
    enum PacketL3Types type;
    /* Checksum for IP packets. */
    bool csum_set;
    uint16_t csum;
    union Hdrs {
        IPV4Hdr *ip4h;
        IPV6Hdr *ip6h;
        ARPHdr *arph;
    } hdrs;
    /* IPv4 and IPv6 are mutually exclusive */
    union {
        IPV4Vars ip4;
        struct {
            IPV6Vars v;
            IPV6ExtHdrs eh;
        } ip6;
    } vars;
};

enum PacketL4Types {
    PACKET_L4_UNKNOWN = 0,
    PACKET_L4_TCP,
    PACKET_L4_UDP,
    PACKET_L4_ICMPV4,
    PACKET_L4_ICMPV6,
    PACKET_L4_SCTP,
    PACKET_L4_GRE,
    PACKET_L4_ESP,
};

struct PacketL4 {
    enum PacketL4Types type;
    bool csum_set;
    uint16_t csum;
    union L4Hdrs {
        TCPHdr *tcph;
        UDPHdr *udph;
        ICMPV4Hdr *icmpv4h;
        ICMPV6Hdr *icmpv6h;
        SCTPHdr *sctph;
        GREHdr *greh;
        ESPHdr *esph;
    } hdrs;
    union L4Vars {
        TCPVars tcp;
        ICMPV4Vars icmpv4;
        ICMPV6Vars icmpv6;
    } vars;
};

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

    uint16_t vlan_id[VLAN_MAX_LAYERS];
    uint8_t vlan_idx;

    /* flow */
    uint8_t flowflags;
    /* coccinelle: Packet:flowflags:FLOW_PKT_ */

    uint8_t app_update_direction; // enum StreamUpdateDir

    /* Pkt Flags */
    uint32_t flags;

    struct Flow_ *flow;

    /* raw hash value for looking up the flow, will need to modulated to the
     * hash size still */
    uint32_t flow_hash;

    /* tunnel type: none, root or child */
    enum PacketTunnelType ttype;

    SCTime_t ts;

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
#ifdef HAVE_NAPATECH
        NapatechPacketVars ntpv;
#endif
#ifdef HAVE_AF_XDP
        AFXDPPacketVars afxdp_v;
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

    struct PacketL2 l2;
    struct PacketL3 l3;
    struct PacketL4 l4;

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

    /** has verdict on this tunneled packet been issued? */
    bool tunnel_verdicted;

    /* tunnel/encapsulation handling */
    struct Packet_ *root; /* in case of tunnel this is a ptr
                           * to the 'real' packet, the one we
                           * need to set the verdict on --
                           * It should always point to the lowest
                           * packet in a encapsulated packet */

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
    /* things in the packet that live beyond a reinit */
    struct {
        /** lock to protect access to:
         *  - tunnel_rtv_cnt
         *  - tunnel_tpr_cnt
         *  - tunnel_verdicted
         *  - nfq_v.mark (if p->ttype != PacketTunnelNone)
         */
        SCSpinlock tunnel_lock;
    } persistent;

    /** flex array accessor to allocated packet data. Size of the additional
     *  data is `default_packet_size`. If this is insufficient,
     *  Packet::ext_pkt will be used instead. */
    uint8_t pkt_data[];
} Packet;

static inline bool PacketIsIPv4(const Packet *p);
static inline bool PacketIsIPv6(const Packet *p);

/** highest mtu of the interfaces we monitor */
#define DEFAULT_MTU 1500
#define MINIMUM_MTU 68      /**< ipv4 minimum: rfc791 */

#define DEFAULT_PACKET_SIZE (DEFAULT_MTU + ETHERNET_HEADER_LEN)
/* storage: maximum ip packet size + link header */
#define MAX_PAYLOAD_SIZE (IPV6_HEADER_LEN + 65536 + 28)
extern uint32_t default_packet_size;
#define SIZE_OF_PACKET (default_packet_size + sizeof(Packet))

static inline bool PacketIsIPv4(const Packet *p)
{
    return p->l3.type == PACKET_L3_IPV4;
}

static inline const IPV4Hdr *PacketGetIPv4(const Packet *p)
{
    DEBUG_VALIDATE_BUG_ON(!PacketIsIPv4(p));
    return p->l3.hdrs.ip4h;
}

static inline IPV4Hdr *PacketSetIPV4(Packet *p, const uint8_t *buf)
{
    DEBUG_VALIDATE_BUG_ON(p->l3.type != PACKET_L3_UNKNOWN);
    p->l3.type = PACKET_L3_IPV4;
    p->l3.hdrs.ip4h = (IPV4Hdr *)buf;
    return p->l3.hdrs.ip4h;
}

/* Retrieve proto regardless of IP version */
static inline uint8_t PacketGetIPProto(const Packet *p)
{
    if (p->proto != 0) {
        return p->proto;
    }
    if (PacketIsIPv4(p)) {
        const IPV4Hdr *hdr = PacketGetIPv4(p);
        return IPV4_GET_RAW_IPPROTO(hdr);
    } else if (PacketIsIPv6(p)) {
        return IPV6_GET_L4PROTO(p);
    }
    return 0;
}

static inline uint8_t PacketGetIPv4IPProto(const Packet *p)
{
    if (PacketGetIPv4(p)) {
        const IPV4Hdr *hdr = PacketGetIPv4(p);
        return IPV4_GET_RAW_IPPROTO(hdr);
    }
    return 0;
}

static inline const IPV6Hdr *PacketGetIPv6(const Packet *p)
{
    DEBUG_VALIDATE_BUG_ON(!PacketIsIPv6(p));
    return p->l3.hdrs.ip6h;
}

static inline IPV6Hdr *PacketSetIPV6(Packet *p, const uint8_t *buf)
{
    DEBUG_VALIDATE_BUG_ON(p->l3.type != PACKET_L3_UNKNOWN);
    p->l3.type = PACKET_L3_IPV6;
    p->l3.hdrs.ip6h = (IPV6Hdr *)buf;
    return p->l3.hdrs.ip6h;
}

static inline bool PacketIsIPv6(const Packet *p)
{
    return p->l3.type == PACKET_L3_IPV6;
}

static inline void PacketClearL2(Packet *p)
{
    memset(&p->l2, 0, sizeof(p->l2));
}

/* Can be called multiple times, e.g. for DCE */
static inline EthernetHdr *PacketSetEthernet(Packet *p, const uint8_t *buf)
{
    DEBUG_VALIDATE_BUG_ON(p->l2.type != PACKET_L2_UNKNOWN && p->l2.type != PACKET_L2_ETHERNET);
    p->l2.type = PACKET_L2_ETHERNET;
    p->l2.hdrs.ethh = (EthernetHdr *)buf;
    return p->l2.hdrs.ethh;
}

static inline const EthernetHdr *PacketGetEthernet(const Packet *p)
{
    DEBUG_VALIDATE_BUG_ON(p->l2.type != PACKET_L2_ETHERNET);
    return p->l2.hdrs.ethh;
}

static inline bool PacketIsEthernet(const Packet *p)
{
    return p->l2.type == PACKET_L2_ETHERNET;
}

static inline void PacketClearL3(Packet *p)
{
    memset(&p->l3, 0, sizeof(p->l3));
}

static inline void PacketClearL4(Packet *p)
{
    memset(&p->l4, 0, sizeof(p->l4));
}

static inline TCPHdr *PacketSetTCP(Packet *p, const uint8_t *buf)
{
    DEBUG_VALIDATE_BUG_ON(p->l4.type != PACKET_L4_UNKNOWN);
    p->l4.type = PACKET_L4_TCP;
    p->l4.hdrs.tcph = (TCPHdr *)buf;
    return p->l4.hdrs.tcph;
}

static inline const TCPHdr *PacketGetTCP(const Packet *p)
{
    DEBUG_VALIDATE_BUG_ON(p->l4.type != PACKET_L4_TCP);
    return p->l4.hdrs.tcph;
}

static inline bool PacketIsTCP(const Packet *p)
{
    return p->l4.type == PACKET_L4_TCP;
}

static inline UDPHdr *PacketSetUDP(Packet *p, const uint8_t *buf)
{
    DEBUG_VALIDATE_BUG_ON(p->l4.type != PACKET_L4_UNKNOWN);
    p->l4.type = PACKET_L4_UDP;
    p->l4.hdrs.udph = (UDPHdr *)buf;
    return p->l4.hdrs.udph;
}

static inline const UDPHdr *PacketGetUDP(const Packet *p)
{
    DEBUG_VALIDATE_BUG_ON(p->l4.type != PACKET_L4_UDP);
    return p->l4.hdrs.udph;
}

static inline bool PacketIsUDP(const Packet *p)
{
    return p->l4.type == PACKET_L4_UDP;
}

static inline ICMPV4Hdr *PacketSetICMPv4(Packet *p, const uint8_t *buf)
{
    DEBUG_VALIDATE_BUG_ON(p->l4.type != PACKET_L4_UNKNOWN);
    p->l4.type = PACKET_L4_ICMPV4;
    p->l4.hdrs.icmpv4h = (ICMPV4Hdr *)buf;
    return p->l4.hdrs.icmpv4h;
}

static inline const ICMPV4Hdr *PacketGetICMPv4(const Packet *p)
{
    DEBUG_VALIDATE_BUG_ON(p->l4.type != PACKET_L4_ICMPV4);
    return p->l4.hdrs.icmpv4h;
}

static inline bool PacketIsICMPv4(const Packet *p)
{
    return p->l4.type == PACKET_L4_ICMPV4;
}

static inline const IPV4Hdr *PacketGetICMPv4EmbIPv4(const Packet *p)
{
    const uint8_t *start = (const uint8_t *)PacketGetICMPv4(p);
    const uint8_t *ip = start + p->l4.vars.icmpv4.emb_ip4h_offset;
    return (const IPV4Hdr *)ip;
}

static inline ICMPV6Hdr *PacketSetICMPv6(Packet *p, const uint8_t *buf)
{
    DEBUG_VALIDATE_BUG_ON(p->l4.type != PACKET_L4_UNKNOWN);
    p->l4.type = PACKET_L4_ICMPV6;
    p->l4.hdrs.icmpv6h = (ICMPV6Hdr *)buf;
    return p->l4.hdrs.icmpv6h;
}

static inline const ICMPV6Hdr *PacketGetICMPv6(const Packet *p)
{
    DEBUG_VALIDATE_BUG_ON(p->l4.type != PACKET_L4_ICMPV6);
    return p->l4.hdrs.icmpv6h;
}

static inline bool PacketIsICMPv6(const Packet *p)
{
    return p->l4.type == PACKET_L4_ICMPV6;
}

static inline SCTPHdr *PacketSetSCTP(Packet *p, const uint8_t *buf)
{
    DEBUG_VALIDATE_BUG_ON(p->l4.type != PACKET_L4_UNKNOWN);
    p->l4.type = PACKET_L4_SCTP;
    p->l4.hdrs.sctph = (SCTPHdr *)buf;
    return p->l4.hdrs.sctph;
}

static inline const SCTPHdr *PacketGetSCTP(const Packet *p)
{
    DEBUG_VALIDATE_BUG_ON(p->l4.type != PACKET_L4_SCTP);
    return p->l4.hdrs.sctph;
}

static inline bool PacketIsSCTP(const Packet *p)
{
    return p->l4.type == PACKET_L4_SCTP;
}

static inline GREHdr *PacketSetGRE(Packet *p, const uint8_t *buf)
{
    DEBUG_VALIDATE_BUG_ON(p->l4.type != PACKET_L4_UNKNOWN);
    p->l4.type = PACKET_L4_GRE;
    p->l4.hdrs.greh = (GREHdr *)buf;
    return p->l4.hdrs.greh;
}

static inline const GREHdr *PacketGetGRE(const Packet *p)
{
    DEBUG_VALIDATE_BUG_ON(p->l4.type != PACKET_L4_GRE);
    return p->l4.hdrs.greh;
}

static inline bool PacketIsGRE(const Packet *p)
{
    return p->l4.type == PACKET_L4_GRE;
}

static inline ESPHdr *PacketSetESP(Packet *p, const uint8_t *buf)
{
    DEBUG_VALIDATE_BUG_ON(p->l4.type != PACKET_L4_UNKNOWN);
    p->l4.type = PACKET_L4_ESP;
    p->l4.hdrs.esph = (ESPHdr *)buf;
    return p->l4.hdrs.esph;
}

static inline const ESPHdr *PacketGetESP(const Packet *p)
{
    DEBUG_VALIDATE_BUG_ON(p->l4.type != PACKET_L4_ESP);
    return p->l4.hdrs.esph;
}

static inline bool PacketIsESP(const Packet *p)
{
    return p->l4.type == PACKET_L4_ESP;
}

static inline const ARPHdr *PacketGetARP(const Packet *p)
{
    DEBUG_VALIDATE_BUG_ON(p->l3.type != PACKET_L3_ARP);
    return p->l3.hdrs.arph;
}

static inline ARPHdr *PacketSetARP(Packet *p, const uint8_t *buf)
{
    DEBUG_VALIDATE_BUG_ON(p->l3.type != PACKET_L3_UNKNOWN);
    p->l3.type = PACKET_L3_ARP;
    p->l3.hdrs.arph = (ARPHdr *)buf;
    return p->l3.hdrs.arph;
}

static inline bool PacketIsARP(const Packet *p)
{
    return p->l3.type == PACKET_L3_ARP;
}

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
    uint16_t counter_tcp_syn;
    uint16_t counter_tcp_synack;
    uint16_t counter_tcp_rst;
    uint16_t counter_udp;
    uint16_t counter_icmpv4;
    uint16_t counter_icmpv6;
    uint16_t counter_arp;
    uint16_t counter_ethertype_unknown;

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
    uint16_t counter_vlan_qinqinq;
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
    uint16_t counter_defrag_ipv6_fragments;
    uint16_t counter_defrag_ipv6_reassembled;
    uint16_t counter_defrag_max_hit;
    uint16_t counter_defrag_no_frags;
    uint16_t counter_defrag_tracker_soft_reuse;
    uint16_t counter_defrag_tracker_hard_reuse;
    uint16_t counter_defrag_tracker_timeout;
    ExceptionPolicyCounters counter_defrag_memcap_eps;

    uint16_t counter_flow_memcap;
    ExceptionPolicyCounters counter_flow_memcap_eps;

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

void CaptureStatsUpdate(ThreadVars *tv, const Packet *p);
void CaptureStatsSetup(ThreadVars *tv);

#define PACKET_CLEAR_L4VARS(p) do {                         \
        memset(&(p)->l4vars, 0x00, sizeof((p)->l4vars));    \
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

#define TUNNEL_INCR_PKT_RTV_NOLOCK(p) do {                                          \
        ((p)->root ? (p)->root->tunnel_rtv_cnt++ : (p)->tunnel_rtv_cnt++);          \
    } while (0)

static inline void TUNNEL_INCR_PKT_TPR(Packet *p)
{
    Packet *rp = p->root ? p->root : p;
    SCSpinLock(&rp->persistent.tunnel_lock);
    rp->tunnel_tpr_cnt++;
    SCSpinUnlock(&rp->persistent.tunnel_lock);
}

#define TUNNEL_PKT_RTV(p) ((p)->root ? (p)->root->tunnel_rtv_cnt : (p)->tunnel_rtv_cnt)
#define TUNNEL_PKT_TPR(p) ((p)->root ? (p)->root->tunnel_tpr_cnt : (p)->tunnel_tpr_cnt)

static inline bool PacketTunnelIsVerdicted(const Packet *p)
{
    return p->tunnel_verdicted;
}
static inline void PacketTunnelSetVerdicted(Packet *p)
{
    p->tunnel_verdicted = true;
}

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
    DECODE_TUNNEL_ARP,
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
int DecodeARP(ThreadVars *, DecodeThreadVars *, Packet *, const uint8_t *, uint32_t);

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
#define LINKTYPE_IPV6        229
#define LINKTYPE_GRE_OVER_IP 778
#define LINKTYPE_CISCO_HDLC  DLT_C_HDLC
#define PPP_OVER_GRE         11
#define VLAN_OVER_GRE        13

/* Packet Flags */

/** Flag to indicate that packet header or contents should not be inspected */
#define PKT_NOPACKET_INSPECTION BIT_U32(0)
/** Packet has a PPP_VJ_UCOMP header */
#define PKT_PPP_VJ_UCOMP BIT_U32(1)

/** Flag to indicate that packet contents should not be inspected */
#define PKT_NOPAYLOAD_INSPECTION BIT_U32(2)
// vacancy

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

// vacancy

/** Exclude packet from pcap logging as it's part of a stream that has reassembly \
                   depth reached. */
#define PKT_STREAM_NOPCAPLOG BIT_U32(12)

// vacancy 2x

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

static inline bool PacketIsTunnelRoot(const Packet *p)
{
    return (p->ttype == PacketTunnelRoot);
}

static inline bool PacketIsTunnelChild(const Packet *p)
{
    return (p->ttype == PacketTunnelChild);
}

static inline bool PacketIsTunnel(const Packet *p)
{
    return (p->ttype != PacketTunnelNone);
}

static inline bool PacketIsNotTunnel(const Packet *p)
{
    return (p->ttype == PacketTunnelNone);
}

static inline bool VerdictTunnelPacketInternal(const Packet *p)
{
    const uint16_t outstanding = TUNNEL_PKT_TPR(p) - TUNNEL_PKT_RTV(p);
    SCLogDebug("tunnel: outstanding %u", outstanding);

    /* if there are packets outstanding, we won't verdict this one */
    if (PacketIsTunnelRoot(p) && !PacketTunnelIsVerdicted(p) && !outstanding) {
        SCLogDebug("root %p: verdict", p);
        return true;

    } else if (PacketIsTunnelChild(p) && outstanding == 1 && p->root &&
               PacketTunnelIsVerdicted(p->root)) {
        SCLogDebug("tunnel %p: verdict", p);
        return true;

    } else {
        return false;
    }
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
    bool verdict;
    SCSpinlock *lock = p->root ? &p->root->persistent.tunnel_lock : &p->persistent.tunnel_lock;
    SCSpinLock(lock);
    verdict = VerdictTunnelPacketInternal(p);
    SCSpinUnlock(lock);
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
            SCLogError("datalink type "
                       "%" PRId32 " not yet supported",
                    datalink);
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
            if (p->vlan_idx > VLAN_MAX_LAYER_IDX) {
                ENGINE_SET_EVENT(p,VLAN_HEADER_TOO_MANY_LAYERS);
            } else {
                DecodeVLAN(tv, dtv, p, data, len);
            }
            break;
        case ETHERNET_TYPE_8021AH:
            DecodeIEEE8021ah(tv, dtv, p, data, len);
            break;
        case ETHERNET_TYPE_ARP:
            DecodeARP(tv, dtv, p, data, len);
            break;
        case ETHERNET_TYPE_MPLS_UNICAST:
        case ETHERNET_TYPE_MPLS_MULTICAST:
            DecodeMPLS(tv, dtv, p, data, len);
            break;
        case ETHERNET_TYPE_DCE:
            if (unlikely(len < ETHERNET_DCE_HEADER_LEN)) {
                ENGINE_SET_INVALID_EVENT(p, DCE_PKT_TOO_SMALL);
            } else {
                // DCE layer is ethernet + 2 bytes, followed by another ethernet
                DecodeEthernet(tv, dtv, p, data + 2, len - 2);
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
            StatsIncr(tv, dtv->counter_ethertype_unknown);
            return false;
    }
    return true;
}

#endif /* SURICATA_DECODE_H */
