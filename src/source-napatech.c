/* Copyright (C) 2012-2020 Open Information Security Foundation
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
 - * \author nPulse Technologies, LLC.
 - * \author Matt Keeler <mk@npulsetech.com>
 *  *
 * Support for NAPATECH adapter with the 3GD Driver/API.
 * Requires libntapi from Napatech A/S.
 *
 */
#include "suricata-common.h"
#include "suricata.h"
#include "threadvars.h"
#include "util-datalink.h"
#include "util-optimize.h"
#include "tm-queuehandlers.h"
#include "tm-threads.h"
#include "tm-modules.h"
#include "util-privs.h"
#include "tmqh-packetpool.h"
#include "util-napatech.h"
#include "source-napatech.h"

#ifndef HAVE_NAPATECH

TmEcode NoNapatechSupportExit(ThreadVars*, const void*, void**);

void TmModuleNapatechStreamRegister(void)
{
    tmm_modules[TMM_RECEIVENAPATECH].name = "NapatechStream";
    tmm_modules[TMM_RECEIVENAPATECH].ThreadInit = NoNapatechSupportExit;
    tmm_modules[TMM_RECEIVENAPATECH].Func = NULL;
    tmm_modules[TMM_RECEIVENAPATECH].ThreadExitPrintStats = NULL;
    tmm_modules[TMM_RECEIVENAPATECH].ThreadDeinit = NULL;
    tmm_modules[TMM_RECEIVENAPATECH].cap_flags = SC_CAP_NET_ADMIN;
}

void TmModuleNapatechDecodeRegister(void)
{
    tmm_modules[TMM_DECODENAPATECH].name = "NapatechDecode";
    tmm_modules[TMM_DECODENAPATECH].ThreadInit = NoNapatechSupportExit;
    tmm_modules[TMM_DECODENAPATECH].Func = NULL;
    tmm_modules[TMM_DECODENAPATECH].ThreadExitPrintStats = NULL;
    tmm_modules[TMM_DECODENAPATECH].ThreadDeinit = NULL;
    tmm_modules[TMM_DECODENAPATECH].cap_flags = 0;
    tmm_modules[TMM_DECODENAPATECH].flags = TM_FLAG_DECODE_TM;
}

TmEcode NoNapatechSupportExit(ThreadVars *tv, const void *initdata, void **data)
{
    SCLogError(SC_ERR_NAPATECH_NOSUPPORT,
            "Error creating thread %s: you do not have support for Napatech adapter "
            "enabled please recompile with --enable-napatech",
            tv->name);
    exit(EXIT_FAILURE);
}

#else /* Implied we do have NAPATECH support */


#include <numa.h>
#include <nt.h>

extern int max_pending_packets;

typedef struct NapatechThreadVars_
{
    ThreadVars *tv;
    NtNetStreamRx_t rx_stream;
    uint16_t stream_id;
    int hba;
    TmSlot *slot;
} NapatechThreadVars;

#ifdef NAPATECH_ENABLE_BYPASS
static int NapatechBypassCallback(Packet *p);
#endif

TmEcode NapatechStreamThreadInit(ThreadVars *, const void *, void **);
void NapatechStreamThreadExitStats(ThreadVars *, void *);
TmEcode NapatechPacketLoop(ThreadVars *tv, void *data, void *slot);

TmEcode NapatechDecodeThreadInit(ThreadVars *, const void *, void **);
TmEcode NapatechDecodeThreadDeinit(ThreadVars *tv, void *data);
TmEcode NapatechDecode(ThreadVars *, Packet *, void *);

/* These are used as the threads are exiting to get a comprehensive count of
 * all the packets received and dropped.
 */
SC_ATOMIC_DECLARE(uint64_t, total_packets);
SC_ATOMIC_DECLARE(uint64_t, total_drops);
SC_ATOMIC_DECLARE(uint16_t, total_tallied);

/* Streams are counted as they are instantiated in order to know when all threads
 * are running*/
SC_ATOMIC_DECLARE(uint16_t, stream_count);

SC_ATOMIC_DECLARE(uint16_t, numa0_count);
SC_ATOMIC_DECLARE(uint16_t, numa1_count);
SC_ATOMIC_DECLARE(uint16_t, numa2_count);
SC_ATOMIC_DECLARE(uint16_t, numa3_count);

SC_ATOMIC_DECLARE(uint64_t, flow_callback_cnt);
SC_ATOMIC_DECLARE(uint64_t, flow_callback_handled_pkts);
SC_ATOMIC_DECLARE(uint64_t, flow_callback_udp_pkts);
SC_ATOMIC_DECLARE(uint64_t, flow_callback_tcp_pkts);
SC_ATOMIC_DECLARE(uint64_t, flow_callback_unhandled_pkts);

/**
 * \brief Register the Napatech  receiver (reader) module.
 */
void TmModuleNapatechStreamRegister(void)
{
    tmm_modules[TMM_RECEIVENAPATECH].name = "NapatechStream";
    tmm_modules[TMM_RECEIVENAPATECH].ThreadInit = NapatechStreamThreadInit;
    tmm_modules[TMM_RECEIVENAPATECH].Func = NULL;
    tmm_modules[TMM_RECEIVENAPATECH].PktAcqLoop = NapatechPacketLoop;
    tmm_modules[TMM_RECEIVENAPATECH].PktAcqBreakLoop = NULL;
    tmm_modules[TMM_RECEIVENAPATECH].ThreadExitPrintStats = NapatechStreamThreadExitStats;
    tmm_modules[TMM_RECEIVENAPATECH].ThreadDeinit = NapatechStreamThreadDeinit;
    tmm_modules[TMM_RECEIVENAPATECH].cap_flags = SC_CAP_NET_RAW;
    tmm_modules[TMM_RECEIVENAPATECH].flags = TM_FLAG_RECEIVE_TM;

    SC_ATOMIC_INIT(total_packets);
    SC_ATOMIC_INIT(total_drops);
    SC_ATOMIC_INIT(total_tallied);
    SC_ATOMIC_INIT(stream_count);

    SC_ATOMIC_INIT(numa0_count);
    SC_ATOMIC_INIT(numa1_count);
    SC_ATOMIC_INIT(numa2_count);
    SC_ATOMIC_INIT(numa3_count);

    SC_ATOMIC_INIT(flow_callback_cnt);
    SC_ATOMIC_INIT(flow_callback_handled_pkts);
    SC_ATOMIC_INIT(flow_callback_udp_pkts);
    SC_ATOMIC_INIT(flow_callback_tcp_pkts);
    SC_ATOMIC_INIT(flow_callback_unhandled_pkts);
}

/**
 * \brief Register the Napatech decoder module.
 */
void TmModuleNapatechDecodeRegister(void)
{
    tmm_modules[TMM_DECODENAPATECH].name = "NapatechDecode";
    tmm_modules[TMM_DECODENAPATECH].ThreadInit = NapatechDecodeThreadInit;
    tmm_modules[TMM_DECODENAPATECH].Func = NapatechDecode;
    tmm_modules[TMM_DECODENAPATECH].ThreadExitPrintStats = NULL;
    tmm_modules[TMM_DECODENAPATECH].ThreadDeinit = NapatechDecodeThreadDeinit;
    tmm_modules[TMM_DECODENAPATECH].cap_flags = 0;
    tmm_modules[TMM_DECODENAPATECH].flags = TM_FLAG_DECODE_TM;
}

#ifdef NAPATECH_ENABLE_BYPASS
/**
 * \brief template of IPv4 header
 */
struct ipv4_hdr
{
    uint8_t version_ihl; /**< version and header length */
    uint8_t type_of_service; /**< type of service */
    uint16_t total_length; /**< length of packet */
    uint16_t packet_id; /**< packet ID */
    uint16_t fragment_offset; /**< fragmentation offset */
    uint8_t time_to_live; /**< time to live */
    uint8_t next_proto_id; /**< protocol ID */
    uint16_t hdr_checksum; /**< header checksum */
    uint32_t src_addr; /**< source address */
    uint32_t dst_addr; /**< destination address */
} __attribute__ ((__packed__));

/**
 * \brief template of IPv6 header
 */
struct ipv6_hdr
{
    uint32_t vtc_flow; /**< IP version, traffic class & flow label. */
    uint16_t payload_len; /**< IP packet length - includes sizeof(ip_header). */
    uint8_t proto; /**< Protocol, next header. */
    uint8_t hop_limits; /**< Hop limits. */
    uint8_t src_addr[16]; /**< IP address of source host. */
    uint8_t dst_addr[16]; /**< IP address of destination host(s). */
} __attribute__ ((__packed__));

/**
 * \brief template of UDP header
 */
struct udp_hdr
{
    uint16_t src_port; /**< UDP source port. */
    uint16_t dst_port; /**< UDP destination port. */
    uint16_t dgram_len; /**< UDP datagram length */
    uint16_t dgram_cksum; /**< UDP datagram checksum */
} __attribute__ ((__packed__));

/**
 * \brief template of TCP header
 */
struct tcp_hdr
{
    uint16_t src_port; /**< TCP source port. */
    uint16_t dst_port; /**< TCP destination port. */
    uint32_t sent_seq; /**< TX data sequence number. */
    uint32_t recv_ack; /**< RX data acknowledgement sequence number. */
    uint8_t data_off; /**< Data offset. */
    uint8_t tcp_flags; /**< TCP flags */
    uint16_t rx_win; /**< RX flow control window. */
    uint16_t cksum; /**< TCP checksum. */
    uint16_t tcp_urp; /**< TCP urgent pointer, if any. */
} __attribute__ ((__packed__));


/*  The hardware will assign a "color" value indicating what filters are matched
 * by a given packet.  These constants indicate what bits are set in the color
 * field for different protocols
 *
 */
#define RTE_PTYPE_L2_ETHER                  0x10000000
#define RTE_PTYPE_L3_IPV4                   0x01000000
#define RTE_PTYPE_L3_IPV6                   0x04000000
#define RTE_PTYPE_L4_TCP                    0x00100000
#define RTE_PTYPE_L4_UDP                    0x00200000

/* These masks are used to extract layer 3 and layer 4 protocol
 * values from the color field in the packet descriptor.
 */
#define RTE_PTYPE_L3_MASK                   0x0f000000
#define RTE_PTYPE_L4_MASK                   0x00f00000

#define COLOR_IS_SPAN                       0x00001000

static int is_inline = 0;
static int inline_port_map[MAX_PORTS] = { -1 };

/**
 * \brief Binds two ports together for inline operation.
 *
 * Get the ID of an adapter on which a given port resides.
 *
 * \param port one of the ports in a pairing.
 * \param peer the other port in a pairing.
 * \return ID of the adapter.
 *
 */
int NapatechSetPortmap(int port, int peer)
{
    if ((inline_port_map[port] == -1) && (inline_port_map[peer] == -1)) {
        inline_port_map[port] = peer;
        inline_port_map[peer] = port;
    } else {
        SCLogError(SC_ERR_NAPATECH_PARSE_CONFIG,
                "Port pairing is already configured.");
        return 0;
    }
    return 1;
}

/**
 * \brief Returns the ID of the adapter
 *
 * Get the ID of an adapter on which a given port resides.
 *
 * \param port for which adapter ID is requested.
 * \return ID of the adapter.
 *
 */
int NapatechGetAdapter(uint8_t port)
{
    static int port_adapter_map[MAX_PORTS] = { -1 };
    int status;
    NtInfo_t h_info; /* Info handle */
    NtInfoStream_t h_info_stream; /* Info stream handle */

    if (unlikely(port_adapter_map[port] == -1)) {
        if ((status = NT_InfoOpen(&h_info_stream, "ExampleInfo")) != NT_SUCCESS) {
            NAPATECH_ERROR(SC_ERR_NAPATECH_OPEN_FAILED, status);
            return -1;
        }
        /* Read the system info */
        h_info.cmd = NT_INFO_CMD_READ_PORT_V9;
        h_info.u.port_v9.portNo = (uint8_t) port;
        if ((status = NT_InfoRead(h_info_stream, &h_info)) != NT_SUCCESS) {
            /* Get the status code as text */
            NAPATECH_ERROR(SC_ERR_NAPATECH_OPEN_FAILED, status);
            NT_InfoClose(h_info_stream);
            return -1;
        }
        port_adapter_map[port] = h_info.u.port_v9.data.adapterNo;
    }
    return port_adapter_map[port];
}

/**
 * \brief IPv4 4-tuple convenience structure
 */
struct IPv4Tuple4
{
    uint32_t sa; /*!< Source address */
    uint32_t da; /*!< Destination address */
    uint16_t sp; /*!< Source port */
    uint16_t dp; /*!< Destination port */
};

/**
 * \brief IPv6 4-tuple convenience structure
 */
struct IPv6Tuple4
{
    uint8_t sa[16]; /*!< Source address */
    uint8_t da[16]; /*!< Destination address */
    uint16_t sp;    /*!< Source port */
    uint16_t dp;    /*!< Destination port */
};


/**
 * \brief Compares the byte order value of two IPv6 addresses.
 *
 *
 * \param addr_a The first address to compare
 * \param addr_b The second adress to compare
 *
 * \return -1 if addr_a < addr_b
 *          1 if addr_a > addr_b
 *          0 if addr_a == addr_b
 */
static int CompareIPv6Addr(uint8_t addr_a[16], uint8_t addr_b[16]) {
    uint16_t pos;
    for (pos = 0; pos < 16; ++pos) {
        if (addr_a[pos] < addr_b[pos]) {
            return -1;
        } else if (addr_a[pos] > addr_b[pos]) {
            return 1;
        } /* else they are equal - check next position*/
    }

    /* if we get here the addresses are equal */
    return 0;
}

/**
 * \brief  Initializes the FlowStreams used to program flow data.
 *
 * Opens a FlowStream on the adapter associated with the rx port.  This
 * FlowStream is subsequently used to program the adapter with
 * flows to bypass.
 *
 * \return the flow stream handle, NULL if failure.
 */
static NtFlowStream_t InitFlowStream(int adapter, int stream_id)
{
    int status;
    NtFlowStream_t hFlowStream;

    NtFlowAttr_t attr;
    char flow_name[80];

    NT_FlowOpenAttrInit(&attr);
    NT_FlowOpenAttrSetAdapterNo(&attr, adapter);

    snprintf(flow_name, sizeof(flow_name), "Flow_stream_%d", stream_id );
    SCLogDebug("Opening flow programming stream:  %s", flow_name);
    if ((status = NT_FlowOpen_Attr(&hFlowStream, flow_name, &attr)) != NT_SUCCESS) {
        SCLogWarning(SC_WARN_COMPATIBILITY,
                "Napatech bypass functionality not supported by the FPGA version on adapter %d - disabling support.",
                adapter);
        return NULL;
    }
    return hFlowStream;
}

/**
 * \brief Callback function to process Bypass events on Napatech Adapter.
 *
 * Callback function that sets up the Flow tables on the Napatech card
 * so that subsequent packets from this flow are bypassed on the hardware.
 *
 * \param p packet containing information about the flow to be bypassed
 * \param is_inline indicates if Suricata is being run in inline mode.
 *
 * \return Error code indicating success (1) or failure (0).
 *
 */
static int ProgramFlow(Packet *p, int is_inline)
{
    NtFlow_t flow_match;
    memset(&flow_match, 0, sizeof(flow_match));

    NapatechPacketVars *ntpv = &(p->ntpv);

    /*
     * The hardware decoder will "color" the packets according to the protocols
     * in the packet and the port the packet arrived on.  packet_type gets
     * these bits and we mask out layer3, layer4, and is_span to determine
     * the protocols and if the packet is coming in from a SPAN port.
     */
    uint32_t packet_type = ((ntpv->dyn3->color_hi << 14) & 0xFFFFC000) | ntpv->dyn3->color_lo;
    uint8_t *packet = (uint8_t *) ntpv->dyn3 + ntpv->dyn3->descrLength;

    uint32_t layer3 = packet_type & RTE_PTYPE_L3_MASK;
    uint32_t layer4 = packet_type & RTE_PTYPE_L4_MASK;
    uint32_t is_span = packet_type & COLOR_IS_SPAN;

    /*
     * When we're programming the flows to arrive on a span port,
     * where upstream and downstream packets arrive on the same port,
     * the hardware is configured to swap the source and dest
     * fields if the src addr > dest addr.  We need to program the
     * flow tables to match.  We'll compare addresses and set
     * do_swap accordingly.
     */

    uint32_t do_swap = 0;

    SC_ATOMIC_ADD(flow_callback_cnt, 1);

    /* Only bypass TCP and UDP */
    if (PKT_IS_TCP(p)) {
        SC_ATOMIC_ADD(flow_callback_tcp_pkts, 1);
    } else if PKT_IS_UDP(p) {
        SC_ATOMIC_ADD(flow_callback_udp_pkts, 1);
    } else {
        SC_ATOMIC_ADD(flow_callback_unhandled_pkts, 1);
    }

    struct IPv4Tuple4 v4Tuple;
    struct IPv6Tuple4 v6Tuple;
    struct ipv4_hdr *pIPv4_hdr = NULL;
    struct ipv6_hdr *pIPv6_hdr = NULL;

    switch (layer3) {
        case RTE_PTYPE_L3_IPV4:
        {
            pIPv4_hdr = (struct ipv4_hdr *) (packet + ntpv->dyn3->offset0);
            if (!is_span) {
                v4Tuple.sa = pIPv4_hdr->src_addr;
                v4Tuple.da = pIPv4_hdr->dst_addr;
            } else {
                do_swap = (htonl(pIPv4_hdr->src_addr) > htonl(pIPv4_hdr->dst_addr));
                if (!do_swap) {
                    /* already in order */
                    v4Tuple.sa = pIPv4_hdr->src_addr;
                    v4Tuple.da = pIPv4_hdr->dst_addr;
                } else { /* swap */
                    v4Tuple.sa = pIPv4_hdr->dst_addr;
                    v4Tuple.da = pIPv4_hdr->src_addr;
                }
            }
            break;
        }
        case RTE_PTYPE_L3_IPV6:
        {
            pIPv6_hdr = (struct ipv6_hdr *) (packet + ntpv->dyn3->offset0);
            do_swap = (CompareIPv6Addr(pIPv6_hdr->src_addr, pIPv6_hdr->dst_addr) > 0);

            if (!is_span) {
                memcpy(&(v6Tuple.sa), pIPv6_hdr->src_addr, 16);
                memcpy(&(v6Tuple.da), pIPv6_hdr->dst_addr, 16);
            } else {
                /* sort src/dest address before programming */
                if (!do_swap) {
                    /* already in order */
                    memcpy(&(v6Tuple.sa), pIPv6_hdr->src_addr, 16);
                    memcpy(&(v6Tuple.da), pIPv6_hdr->dst_addr, 16);
                } else { /* swap the addresses */
                    memcpy(&(v6Tuple.sa), pIPv6_hdr->dst_addr, 16);
                    memcpy(&(v6Tuple.da), pIPv6_hdr->src_addr, 16);
                }
            }
            break;
        }
        default:
        {
            return 0;
        }
    }

    switch (layer4) {
        case RTE_PTYPE_L4_TCP:
        {
            struct tcp_hdr *tcp_hdr = (struct tcp_hdr *) (packet + ntpv->dyn3->offset1);
            if (layer3 == RTE_PTYPE_L3_IPV4) {
                if (!is_span) {
                    v4Tuple.dp = tcp_hdr->dst_port;
                    v4Tuple.sp = tcp_hdr->src_port;
                    flow_match.keyId = NAPATECH_KEYTYPE_IPV4;
                } else {
                    if (!do_swap) {
                        v4Tuple.sp = tcp_hdr->src_port;
                        v4Tuple.dp = tcp_hdr->dst_port;
                    } else {
                        v4Tuple.sp = tcp_hdr->dst_port;
                        v4Tuple.dp = tcp_hdr->src_port;
                    }
                    flow_match.keyId = NAPATECH_KEYTYPE_IPV4_SPAN;
                }
                memcpy(&(flow_match.keyData), &v4Tuple, sizeof(v4Tuple));
            } else {
                if (!is_span) {
                    v6Tuple.dp = tcp_hdr->dst_port;
                    v6Tuple.sp = tcp_hdr->src_port;
                    flow_match.keyId = NAPATECH_KEYTYPE_IPV6;
                } else {
                    if (!do_swap) {
                        v6Tuple.sp = tcp_hdr->src_port;
                        v6Tuple.dp = tcp_hdr->dst_port;
                    } else {
                        v6Tuple.dp = tcp_hdr->src_port;
                        v6Tuple.sp = tcp_hdr->dst_port;
                    }
                    flow_match.keyId = NAPATECH_KEYTYPE_IPV6_SPAN;
                }
                memcpy(&(flow_match.keyData), &v6Tuple, sizeof(v6Tuple));
            }
            flow_match.ipProtocolField = 6;
            break;
        }
        case RTE_PTYPE_L4_UDP:
        {
            struct udp_hdr *udp_hdr = (struct udp_hdr *) (packet + ntpv->dyn3->offset1);
            if (layer3 == RTE_PTYPE_L3_IPV4) {
                if (!is_span) {
                    v4Tuple.dp = udp_hdr->dst_port;
                    v4Tuple.sp = udp_hdr->src_port;
                    flow_match.keyId = NAPATECH_KEYTYPE_IPV4;
                } else {
                    if (!do_swap) {
                        v4Tuple.sp = udp_hdr->src_port;
                        v4Tuple.dp = udp_hdr->dst_port;
                    } else {
                        v4Tuple.dp = udp_hdr->src_port;
                        v4Tuple.sp = udp_hdr->dst_port;
                    }
                    flow_match.keyId = NAPATECH_KEYTYPE_IPV4_SPAN;
                }
                memcpy(&(flow_match.keyData), &v4Tuple, sizeof(v4Tuple));
            } else { /* layer3 is IPV6 */
                if (!is_span) {
                    v6Tuple.dp = udp_hdr->dst_port;
                    v6Tuple.sp = udp_hdr->src_port;
                    flow_match.keyId = NAPATECH_KEYTYPE_IPV6;
                } else {
                    if (!do_swap) {
                        v6Tuple.sp = udp_hdr->src_port;
                        v6Tuple.dp = udp_hdr->dst_port;
                    } else {
                        v6Tuple.dp = udp_hdr->src_port;
                        v6Tuple.sp = udp_hdr->dst_port;
                    }
                    flow_match.keyId = NAPATECH_KEYTYPE_IPV6_SPAN;
                }
                memcpy(&(flow_match.keyData), &v6Tuple, sizeof(v6Tuple));
            }
            flow_match.ipProtocolField = 17;
            break;
        }
        default:
        {
            return 0;
        }
    }

    flow_match.op = 1;  /* program flow */
    flow_match.gfi = 1; /* Generate FlowInfo records */
    flow_match.tau = 1; /* tcp automatic unlearn */

    if (PacketTestAction(p, ACTION_DROP)) {
        flow_match.keySetId = NAPATECH_FLOWTYPE_DROP;
    } else {
        if (is_inline) {
            flow_match.keySetId = NAPATECH_FLOWTYPE_PASS;
        } else {
            flow_match.keySetId = NAPATECH_FLOWTYPE_DROP;
        }
    }

    if (NT_FlowWrite(ntpv->flow_stream, &flow_match, -1) != NT_SUCCESS) {
        if (!(suricata_ctl_flags & SURICATA_STOP)) {
            SCLogError(SC_ERR_NAPATECH_OPEN_FAILED,"NT_FlowWrite failed!.");
            exit(EXIT_FAILURE);
        }
    }

    return 1;
}

/**
 * \brief     Callback from Suricata when a flow that should be bypassed
 *            is identified.
 */

static int NapatechBypassCallback(Packet *p)
{
    NapatechPacketVars *ntpv = &(p->ntpv);

    /*
     *  Since, at this point, we don't know what action to take,
     *  simply mark this packet as one that should be
     *  bypassed when the packet is returned by suricata with a
     *  pass/drop verdict.
     */
    ntpv->bypass = 1;

    return 1;
}

#endif

/**
 * \brief   Initialize the Napatech receiver thread, generate a single
 *          NapatechThreadVar structure for each thread, this will
 *          contain a NtNetStreamRx_t stream handle which is used when the
 *          thread executes to acquire the packets.
 *
 * \param tv        Thread variable to ThreadVars
 * \param initdata  Initial data to the adapter passed from the user,
 *                  this is processed by the user.
 *
 *                  For now, we assume that we have only a single name for the NAPATECH
 *                  adapter.
 *
 * \param data      data pointer gets populated with
 *
 */
TmEcode NapatechStreamThreadInit(ThreadVars *tv, const void *initdata, void **data)
{
    SCEnter();
    struct NapatechStreamDevConf *conf = (struct NapatechStreamDevConf *) initdata;
    uint16_t stream_id = conf->stream_id;
    *data = NULL;

    NapatechThreadVars *ntv = SCCalloc(1, sizeof (NapatechThreadVars));
    if (unlikely(ntv == NULL)) {
        FatalError(SC_ERR_FATAL,
                   "Failed to allocate memory for NAPATECH  thread vars.");
    }

    memset(ntv, 0, sizeof (NapatechThreadVars));
    ntv->stream_id = stream_id;
    ntv->tv = tv;
    ntv->hba = conf->hba;

    DatalinkSetGlobalType(LINKTYPE_ETHERNET);

    SCLogDebug("Started processing packets from NAPATECH  Stream: %lu", ntv->stream_id);

    *data = (void *) ntv;
    SCReturnInt(TM_ECODE_OK);
}

/**
 * \brief Callback to indicate that the packet buffer can be returned to the hardware.
 *
 *  Called when Suricata is done processing the packet.  Before the packet is released
 *  this also checks the action to see if the packet should be dropped and programs the
 *  flow hardware if the flow is to be bypassed and the Napatech packet buffer is released.
 *
 *
 * \param p Packet to return to the system.
 *
 */
static void NapatechReleasePacket(struct Packet_ *p)
{
    /*
     * If the packet is to be dropped we need to set the wirelength
     * before releasing the Napatech buffer back to NTService.
     */
#ifdef NAPATECH_ENABLE_BYPASS
    if (is_inline && PacketTestAction(p, ACTION_DROP)) {
        p->ntpv.dyn3->wireLength = 0;
    }

    /*
     *  If this flow is to be programmed for hardware bypass we do it now.  This is done
     *  here because the action is not available in the packet structure at the time of the
     *  bypass callback and it needs to be done before we release the packet structure.
     */
    if (p->ntpv.bypass == 1) {
        ProgramFlow(p, is_inline);
    }
#endif

    NT_NetRxRelease(p->ntpv.rx_stream, p->ntpv.nt_packet_buf);
    PacketFreeOrRelease(p);
}

/**
 * \brief Returns the NUMA node associated with the currently running thread.
 *
 * \return ID of the NUMA node.
 *
 */
static int GetNumaNode(void)
{
    int cpu = 0;
    int node = 0;

#if defined(__linux__)
    cpu = sched_getcpu();
    node = numa_node_of_cpu(cpu);
#else
    SCLogWarning(SC_ERR_NAPATECH_NOSUPPORT,
            "Auto configuration of NUMA node is not supported on this OS.");
#endif

    return node;
}

/**
 * \brief Outputs hints on the optimal host-buffer configuration to aid tuning.
 *
 * \param log_level of the currently running instance.
 *
 */
static void RecommendNUMAConfig(SCLogLevel log_level)
{
    char string0[16];
    char string1[16];
    char string2[16];
    char string3[16];
    int set_cpu_affinity = 0;

    if (ConfGetBool("threading.set-cpu-affinity", &set_cpu_affinity) != 1) {
        set_cpu_affinity = 0;
    }

    if (set_cpu_affinity) {
        SCLog(log_level, __FILE__, __FUNCTION__, __LINE__,
                "Minimum host buffers that should be defined in ntservice.ini:");

        SCLog(log_level, __FILE__, __FUNCTION__, __LINE__, "   NUMA Node 0: %d",
                (SC_ATOMIC_GET(numa0_count)));

        if (numa_max_node() >= 1)
            SCLog(log_level, __FILE__, __FUNCTION__, __LINE__,
                    "   NUMA Node 1: %d ", (SC_ATOMIC_GET(numa1_count)));

        if (numa_max_node() >= 2)
            SCLog(log_level, __FILE__, __FUNCTION__, __LINE__,
                    "   NUMA Node 2: %d ", (SC_ATOMIC_GET(numa2_count)));

        if (numa_max_node() >= 3)
            SCLog(log_level, __FILE__, __FUNCTION__, __LINE__,
                    "   NUMA Node 3: %d ", (SC_ATOMIC_GET(numa3_count)));

        snprintf(string0, 16, "[%d, 16, 0]", SC_ATOMIC_GET(numa0_count));
        snprintf(string1, 16, (numa_max_node() >= 1 ? ",[%d, 16, 1]" : ""),
                SC_ATOMIC_GET(numa1_count));
        snprintf(string2, 16, (numa_max_node() >= 2 ? ",[%d, 16, 2]" : ""),
                SC_ATOMIC_GET(numa2_count));
        snprintf(string3, 16, (numa_max_node() >= 3 ? ",[%d, 16, 3]" : ""),
                SC_ATOMIC_GET(numa3_count));

        SCLog(log_level, __FILE__, __FUNCTION__, __LINE__,
                "E.g.: HostBuffersRx=%s%s%s%s", string0, string1, string2,
                string3);
    } else if (log_level == SC_LOG_ERROR) {
        SCLogError(SC_ERR_NAPATECH_STREAMS_REGISTER_FAILED,
                "Or, try running /opt/napatech3/bin/ntpl -e \"delete=all\" to clean-up stream NUMA config.");
    }
}

/**
 * \brief   Main Napatechpacket processing loop
 *
 * \param tv     Thread variable to ThreadVars
 * \param data   Pointer to NapatechThreadVars with data specific to Napatech
 * \param slot   TMSlot where this instance is running.
 *
 */
TmEcode NapatechPacketLoop(ThreadVars *tv, void *data, void *slot)
{
    int32_t status;
    char error_buffer[100];
    uint64_t pkt_ts;
    NtNetBuf_t packet_buffer;
    NapatechThreadVars *ntv = (NapatechThreadVars *) data;
    uint64_t hba_pkt_drops = 0;
    uint64_t hba_byte_drops = 0;
    uint16_t hba_pkt = 0;
    int numa_node = -1;
    int set_cpu_affinity = 0;
    int closer = 0;
    int is_autoconfig = 0;

    /* This just keeps the startup output more orderly. */
    usleep(200000 * ntv->stream_id);

#ifdef NAPATECH_ENABLE_BYPASS
    NtFlowStream_t flow_stream[MAX_ADAPTERS] = { 0 };

    /* Get a FlowStream handle for each adapter so we can efficiently find the
     * correct handle corresponding to the port on which a packet is received.
     */
    int adapter = 0;
    for (adapter = 0; adapter < NapatechGetNumAdapters(); ++adapter) {
        flow_stream[adapter] = InitFlowStream(adapter, ntv->stream_id);
    }
#endif

    if (ConfGetBool("napatech.auto-config", &is_autoconfig) == 0) {
        is_autoconfig = 0;
    }

    if (is_autoconfig) {
        numa_node = GetNumaNode();
        switch (numa_node) {
        case 0:
            SC_ATOMIC_ADD(numa0_count, 1);
            break;
        case 1:
            SC_ATOMIC_ADD(numa1_count, 1);
            break;
        case 2:
            SC_ATOMIC_ADD(numa2_count, 1);
            break;
        case 3:
            SC_ATOMIC_ADD(numa3_count, 1);
            break;
        default:
            break;
        }

        if (ConfGetBool("threading.set-cpu-affinity", &set_cpu_affinity) != 1) {
            set_cpu_affinity = 0;
        }

        if (set_cpu_affinity) {
            NapatechSetupNuma(ntv->stream_id, numa_node);
        }

        numa_node = GetNumaNode();
        SC_ATOMIC_ADD(stream_count, 1);
        if (SC_ATOMIC_GET(stream_count) == NapatechGetNumConfiguredStreams()) {

#ifdef NAPATECH_ENABLE_BYPASS
            if (ConfGetBool("napatech.inline", &is_inline) == 0) {
                is_inline = 0;
            }

            /* Initialize the port map before we setup traffic filters */
            for (int i = 0; i < MAX_PORTS; ++i) {
                inline_port_map[i] = -1;
            }
#endif
            /* The last thread to run sets up and deletes the streams */
            status = NapatechSetupTraffic(NapatechGetNumFirstStream(),
                    NapatechGetNumLastStream());

            closer = 1;

            if (status == 0x20002061) {
                SCLogError(SC_ERR_NAPATECH_STREAMS_REGISTER_FAILED,
                        "Check host buffer configuration in ntservice.ini.");
                RecommendNUMAConfig(SC_LOG_ERROR);
                exit(EXIT_FAILURE);

            } else if (status == 0x20000008) {
                        FatalError(SC_ERR_FATAL,
                                   "Check napatech.ports in the suricata config file.");
            }
            RecommendNUMAConfig(SC_LOG_PERF);
            SCLogNotice("Napatech packet input engine started.");
        }
    } // is_autoconfig

    SCLogInfo(
            "Napatech Packet Loop Started - cpu: %3d, cpu_numa: %3d   stream: %3u ",
            sched_getcpu(), numa_node, ntv->stream_id);

    if (ntv->hba > 0) {
        char *s_hbad_pkt = SCCalloc(1, 32);
        if (unlikely(s_hbad_pkt == NULL)) {
                    FatalError(SC_ERR_FATAL,
                               "Failed to allocate memory for NAPATECH stream counter.");
        }
        snprintf(s_hbad_pkt, 32, "nt%d.hba_drop", ntv->stream_id);
        hba_pkt = StatsRegisterCounter(s_hbad_pkt, tv);
        StatsSetupPrivate(tv);
        StatsSetUI64(tv, hba_pkt, 0);
    }
    SCLogDebug("Opening NAPATECH Stream: %lu for processing", ntv->stream_id);

    if ((status = NT_NetRxOpen(&(ntv->rx_stream), "SuricataStream",
            NT_NET_INTERFACE_PACKET, ntv->stream_id, ntv->hba)) != NT_SUCCESS) {

        NAPATECH_ERROR(SC_ERR_NAPATECH_OPEN_FAILED, status);
        SCFree(ntv);
        SCReturnInt(TM_ECODE_FAILED);
    }
    TmSlot *s = (TmSlot *) slot;
    ntv->slot = s->slot_next;

    while (!(suricata_ctl_flags & SURICATA_STOP)) {
        /* make sure we have at least one packet in the packet pool, to prevent
         * us from alloc'ing packets at line rate */
        PacketPoolWait();

        /* Napatech returns packets 1 at a time */
        status = NT_NetRxGet(ntv->rx_stream, &packet_buffer, 1000);
        if (unlikely(
                status == NT_STATUS_TIMEOUT || status == NT_STATUS_TRYAGAIN)) {
            if (status == NT_STATUS_TIMEOUT) {
                TmThreadsCaptureHandleTimeout(tv, NULL);
            }
            continue;
        } else if (unlikely(status != NT_SUCCESS)) {
            NAPATECH_ERROR(SC_ERR_NAPATECH_OPEN_FAILED, status);
            SCLogInfo("Failed to read from Napatech Stream %d: %s",
                    ntv->stream_id, error_buffer);
            break;
        }

        Packet *p = PacketGetFromQueueOrAlloc();
#ifdef NAPATECH_ENABLE_BYPASS
        p->ntpv.bypass = 0;
#endif

        p->ntpv.rx_stream = ntv->rx_stream;

        if (unlikely(p == NULL)) {
            NT_NetRxRelease(ntv->rx_stream, packet_buffer);
            SCReturnInt(TM_ECODE_FAILED);
        }

        pkt_ts = NT_NET_GET_PKT_TIMESTAMP(packet_buffer);

        /*
         * Handle the different timestamp forms that the napatech cards could use
         *   - NT_TIMESTAMP_TYPE_NATIVE is not supported due to having an base
         *     of 0 as opposed to NATIVE_UNIX which has a base of 1/1/1970
         */
        switch (NT_NET_GET_PKT_TIMESTAMP_TYPE(packet_buffer)) {
            case NT_TIMESTAMP_TYPE_NATIVE_UNIX:
                p->ts.tv_sec = pkt_ts / 100000000;
                p->ts.tv_usec = ((pkt_ts % 100000000) / 100) + ((pkt_ts % 100) > 50 ? 1 : 0);
                break;
            case NT_TIMESTAMP_TYPE_PCAP:
                p->ts.tv_sec = pkt_ts >> 32;
                p->ts.tv_usec = pkt_ts & 0xFFFFFFFF;
                break;
            case NT_TIMESTAMP_TYPE_PCAP_NANOTIME:
                p->ts.tv_sec = pkt_ts >> 32;
                p->ts.tv_usec = ((pkt_ts & 0xFFFFFFFF) / 1000) + ((pkt_ts % 1000) > 500 ? 1 : 0);
                break;
            case NT_TIMESTAMP_TYPE_NATIVE_NDIS:
                /* number of seconds between 1/1/1601 and 1/1/1970 */
                p->ts.tv_sec = (pkt_ts / 100000000) - 11644473600;
                p->ts.tv_usec = ((pkt_ts % 100000000) / 100) + ((pkt_ts % 100) > 50 ? 1 : 0);
                break;
            default:
                SCLogError(SC_ERR_NAPATECH_TIMESTAMP_TYPE_NOT_SUPPORTED,
                        "Packet from Napatech Stream: %u does not have a supported timestamp format",
                        ntv->stream_id);
                NT_NetRxRelease(ntv->rx_stream, packet_buffer);
                SCReturnInt(TM_ECODE_FAILED);
        }

        if (unlikely(ntv->hba > 0)) {
            NtNetRx_t stat_cmd;
            stat_cmd.cmd = NT_NETRX_READ_CMD_STREAM_DROP;
            /* Update drop counter */
            if (unlikely((status = NT_NetRxRead(ntv->rx_stream, &stat_cmd)) != NT_SUCCESS)) {
                NAPATECH_ERROR(SC_ERR_NAPATECH_OPEN_FAILED, status);
                SCLogInfo("Couldn't retrieve drop statistics from the RX stream: %u",
                        ntv->stream_id);
            } else {
                hba_pkt_drops = stat_cmd.u.streamDrop.pktsDropped;

                StatsSetUI64(tv, hba_pkt, hba_pkt_drops);
            }
            StatsSyncCountersIfSignalled(tv);
        }

#ifdef NAPATECH_ENABLE_BYPASS
        p->ntpv.dyn3 = _NT_NET_GET_PKT_DESCR_PTR_DYN3(packet_buffer);
        p->BypassPacketsFlow = (NapatechIsBypassSupported() ? NapatechBypassCallback : NULL);
        NT_NET_SET_PKT_TXPORT(packet_buffer, inline_port_map[p->ntpv.dyn3->rxPort]);
        p->ntpv.flow_stream = flow_stream[NapatechGetAdapter(p->ntpv.dyn3->rxPort)];

#endif

        p->ReleasePacket = NapatechReleasePacket;
        p->ntpv.nt_packet_buf = packet_buffer;
        p->ntpv.stream_id = ntv->stream_id;
        p->datalink = LINKTYPE_ETHERNET;

        if (unlikely(PacketSetData(p, (uint8_t *)NT_NET_GET_PKT_L2_PTR(packet_buffer), NT_NET_GET_PKT_WIRE_LENGTH(packet_buffer)))) {
            TmqhOutputPacketpool(ntv->tv, p);
            SCReturnInt(TM_ECODE_FAILED);
        }

        if (unlikely(TmThreadsSlotProcessPkt(ntv->tv, ntv->slot, p) != TM_ECODE_OK)) {
            SCReturnInt(TM_ECODE_FAILED);
        }

        /*
         * At this point the packet and the Napatech Packet Buffer have been returned
         * to the system in the NapatechReleasePacket() Callback.
         */

        StatsSyncCountersIfSignalled(tv);
    } // while

    if (closer) {
        NapatechDeleteFilters();
    }

    if (unlikely(ntv->hba > 0)) {
        SCLogInfo("Host Buffer Allowance Drops - pkts: %ld,  bytes: %ld", hba_pkt_drops, hba_byte_drops);
    }

    SCReturnInt(TM_ECODE_OK);
}

/**
 * \brief Print some stats to the log at program exit.
 *
 * \param tv Pointer to ThreadVars.
 * \param data Pointer to data, ErfFileThreadVars.
 */
void NapatechStreamThreadExitStats(ThreadVars *tv, void *data)
{
    NapatechThreadVars *ntv = (NapatechThreadVars *) data;
    NapatechCurrentStats stat = NapatechGetCurrentStats(ntv->stream_id);

    double percent = 0;
    if (stat.current_drop_packets > 0)
        percent = (((double) stat.current_drop_packets)
                  / (stat.current_packets + stat.current_drop_packets)) * 100;

    SCLogInfo("nt%lu - pkts: %lu; drop: %lu (%5.2f%%); bytes: %lu",
                 (uint64_t) ntv->stream_id, stat.current_packets,
                  stat.current_drop_packets, percent, stat.current_bytes);

    SC_ATOMIC_ADD(total_packets, stat.current_packets);
    SC_ATOMIC_ADD(total_drops, stat.current_drop_packets);
    SC_ATOMIC_ADD(total_tallied, 1);

    if (SC_ATOMIC_GET(total_tallied) == NapatechGetNumConfiguredStreams()) {
        if (SC_ATOMIC_GET(total_drops) > 0)
            percent = (((double) SC_ATOMIC_GET(total_drops)) / (SC_ATOMIC_GET(total_packets)
                         + SC_ATOMIC_GET(total_drops))) * 100;

        SCLogInfo(" ");
        SCLogInfo("--- Total Packets: %ld  Total Dropped: %ld (%5.2f%%)",
                SC_ATOMIC_GET(total_packets), SC_ATOMIC_GET(total_drops), percent);

#ifdef NAPATECH_ENABLE_BYPASS
        SCLogInfo("--- BypassCB - Total: %ld,  UDP: %ld,  TCP: %ld,  Unhandled: %ld",
                SC_ATOMIC_GET(flow_callback_cnt),
                SC_ATOMIC_GET(flow_callback_udp_pkts),
                SC_ATOMIC_GET(flow_callback_tcp_pkts),
                SC_ATOMIC_GET(flow_callback_unhandled_pkts));
#endif
    }
}

/**
 * \brief   Deinitializes the NAPATECH card.
 * \param   tv pointer to ThreadVars
 * \param   data pointer that gets cast into PcapThreadVars for ptv
 */
TmEcode NapatechStreamThreadDeinit(ThreadVars *tv, void *data)
{
    SCEnter();
    NapatechThreadVars *ntv = (NapatechThreadVars *) data;

    SCLogDebug("Closing Napatech Stream: %d", ntv->stream_id);
    NT_NetRxClose(ntv->rx_stream);

    SCReturnInt(TM_ECODE_OK);
}

/**
 * \brief   This function passes off to link type decoders.
 *
 * NapatechDecode decodes packets from Napatech and passes
 * them off to the proper link type decoder.
 *
 * \param t pointer to ThreadVars
 * \param p pointer to the current packet
 * \param data pointer that gets cast into PcapThreadVars for ptv
 */
TmEcode NapatechDecode(ThreadVars *tv, Packet *p, void *data)
{
    SCEnter();

    DecodeThreadVars *dtv = (DecodeThreadVars *) data;

    BUG_ON(PKT_IS_PSEUDOPKT(p));

    // update counters
    DecodeUpdatePacketCounters(tv, dtv, p);

    switch (p->datalink) {
        case LINKTYPE_ETHERNET:
            DecodeEthernet(tv, dtv, p, GET_PKT_DATA(p), GET_PKT_LEN(p));
            break;
        default:
            SCLogError(SC_ERR_DATALINK_UNIMPLEMENTED,
                    "Datalink type %" PRId32 " not yet supported in module NapatechDecode",
                    p->datalink);
            break;
    }

    PacketDecodeFinalize(tv, dtv, p);
    SCReturnInt(TM_ECODE_OK);
}

/**
 * \brief   Initialization of Napatech Thread.
 *
 * \param t pointer to ThreadVars
 * \param initdata - unused.
 * \param data pointer that gets cast into DecoderThreadVars
 */
TmEcode NapatechDecodeThreadInit(ThreadVars *tv, const void *initdata, void **data)
{
    SCEnter();
    DecodeThreadVars *dtv = NULL;
    dtv = DecodeThreadVarsAlloc(tv);
    if (dtv == NULL) {
        SCReturnInt(TM_ECODE_FAILED);
    }

    DecodeRegisterPerfCounters(dtv, tv);
    *data = (void *) dtv;
    SCReturnInt(TM_ECODE_OK);
}

/**
 * \brief   Deinitialization of Napatech Thread.
 *
 * \param tv pointer to ThreadVars
 * \param data pointer that gets cast into DecoderThreadVars
 */
TmEcode NapatechDecodeThreadDeinit(ThreadVars *tv, void *data)
{
    if (data != NULL) {
        DecodeThreadVarsFree(tv, data);
    }
    SCReturnInt(TM_ECODE_OK);
}

#endif /* HAVE_NAPATECH */
