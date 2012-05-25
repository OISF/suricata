/* Copyright (C) 2007-2012 Open Information Security Foundation
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
 * \defgroup decode Packet decoding
 *
 * \brief Code in charge of protocol decoding
 *
 * The task of decoding packets is made in different files and
 * as Suricata is supporting encapsulation there is a potential
 * recursivity in the call.
 *
 * For each protocol a DecodePROTO function is provided. For
 * example we have DecodeIPV4() for IPv4 and DecodePPP() for
 * PPP.
 *
 * These functions have all a pkt and and a len argument which
 * are respectively a pointer to the protocol data and the length
 * of this protocol data.
 *
 * \attention The pkt parameter must point to the effective data because
 * it will be used later to set per protocol pointer like Packet::tcph
 *
 * @{
 */


/**
 * \file
 *
 * \author Victor Julien <victor@inliniac.net>
 *
 * Decode the raw packet
 */

#include "suricata-common.h"
#include "suricata.h"
#include "decode.h"
#include "util-debug.h"
#include "util-mem.h"
#include "app-layer-detect-proto.h"
#include "tm-threads.h"
#include "util-error.h"
#include "util-print.h"
#include "tmqh-packetpool.h"
#include "util-profiling.h"

void DecodeTunnel(ThreadVars *tv, DecodeThreadVars *dtv, Packet *p,
        uint8_t *pkt, uint16_t len, PacketQueue *pq, uint8_t proto)
{
    switch (proto) {
        case PPP_OVER_GRE:
            return DecodePPP(tv, dtv, p, pkt, len, pq);
        case IPPROTO_IP:
            return DecodeIPV4(tv, dtv, p, pkt, len, pq);
        case IPPROTO_IPV6:
            return DecodeIPV6(tv, dtv, p, pkt, len, pq);
       case VLAN_OVER_GRE:
            return DecodeVLAN(tv, dtv, p, pkt, len, pq);
        default:
            SCLogInfo("FIXME: DecodeTunnel: protocol %" PRIu32 " not supported.", proto);
            break;
    }
}

/**
 * \brief Get a malloced packet.
 *
 * \retval p packet, NULL on error
 */
Packet *PacketGetFromAlloc(void)
{
    Packet *p = SCMalloc(SIZE_OF_PACKET);
    if (p == NULL) {
        return NULL;
    }

    PACKET_INITIALIZE(p);
    p->flags |= PKT_ALLOC;

    SCLogDebug("allocated a new packet only using alloc...");

    PACKET_PROFILING_START(p);
    return p;
}

/**
 *  \brief Get a packet. We try to get a packet from the packetpool first, but
 *         if that is empty we alloc a packet that is free'd again after
 *         processing.
 *
 *  \retval p packet, NULL on error
 */
Packet *PacketGetFromQueueOrAlloc(void)
{
    Packet *p = NULL;

    /* try the pool first */
    if (PacketPoolSize() > 0) {
        p = PacketPoolGetPacket();
    }

    if (p == NULL) {
        /* non fatal, we're just not processing a packet then */
        p = PacketGetFromAlloc();
    } else {
        PACKET_PROFILING_START(p);
    }

    return p;
}

/**
 *  \brief Copy data to Packet payload at given offset
 *
 * This function copies data/payload to a Packet. It uses the
 * space allocated at Packet creation (pointed by Packet::pkt)
 * or allocate some memory (pointed by Packet::ext_pkt) if the
 * data size is to big to fit in initial space (of size
 * default_packet_size).
 *
 *  \param Pointer to the Packet to modify
 *  \param Offset of the copy relatively to payload of Packet
 *  \param Pointer to the data to copy
 *  \param Length of the data to copy
 */
inline int PacketCopyDataOffset(Packet *p, int offset, uint8_t *data, int datalen)
{
    if (offset + datalen > MAX_PAYLOAD_SIZE) {
        /* too big */
        return -1;
    }

    /* Do we have already an packet with allocated data */
    if (! p->ext_pkt) {
        if (offset + datalen <= (int)default_packet_size) {
            /* data will fit in memory allocated with packet */
            memcpy(p->pkt + offset, data, datalen);
        } else {
            /* here we need a dynamic allocation */
            p->ext_pkt = SCMalloc(MAX_PAYLOAD_SIZE);
            if (p->ext_pkt == NULL) {
                SET_PKT_LEN(p, 0);
                return -1;
            }
            /* copy initial data */
            memcpy(p->ext_pkt, GET_PKT_DIRECT_DATA(p), GET_PKT_DIRECT_MAX_SIZE(p));
            /* copy data as asked */
            memcpy(p->ext_pkt + offset, data, datalen);
        }
    } else {
        memcpy(p->ext_pkt + offset, data, datalen);
    }
    return 0;
}

/**
 *  \brief Copy data to Packet payload and set packet length
 *
 *  \param Pointer to the Packet to modify
 *  \param Pointer to the data to copy
 *  \param Length of the data to copy
 */
inline int PacketCopyData(Packet *p, uint8_t *pktdata, int pktlen)
{
    SET_PKT_LEN(p, (size_t)pktlen);
    return PacketCopyDataOffset(p, 0, pktdata, pktlen);
}



/**
 *  \brief Setup a pseudo packet (tunnel)
 *
 *  \param parent parent packet for this pseudo pkt
 *  \param pkt raw packet data
 *  \param len packet data length
 *  \param proto protocol of the tunneled packet
 *
 *  \retval p the pseudo packet or NULL if out of memory
 */
Packet *PacketPseudoPktSetup(Packet *parent, uint8_t *pkt, uint16_t len, uint8_t proto)
{
    SCEnter();

    /* get us a packet */
    Packet *p = PacketGetFromQueueOrAlloc();
    if (p == NULL) {
        SCReturnPtr(NULL, "Packet");
    }

    /* set the root ptr to the lowest layer */
    if (parent->root != NULL)
        p->root = parent->root;
    else
        p->root = parent;

    /* copy packet and set lenght, proto */
    PacketCopyData(p, pkt, len);
    p->recursion_level = parent->recursion_level + 1;
    p->ts.tv_sec = parent->ts.tv_sec;
    p->ts.tv_usec = parent->ts.tv_usec;
    p->datalink = DLT_RAW;

    /* set tunnel flags */

    /* tell new packet it's part of a tunnel */
    SET_TUNNEL_PKT(p);
    /* tell parent packet it's part of a tunnel */
    SET_TUNNEL_PKT(parent);

    /* increment tunnel packet refcnt in the root packet */
    TUNNEL_INCR_PKT_TPR(p);

    /* disable payload (not packet) inspection on the parent, as the payload
     * is the packet we will now run through the system separately. We do
     * check it against the ip/port/other header checks though */
    DecodeSetNoPayloadInspectionFlag(parent);
    SCReturnPtr(p, "Packet");
}

/**
 *  \brief Setup a pseudo packet (reassembled frags)
 *
 *  Difference with PacketPseudoPktSetup is that this func doesn't increment
 *  the recursion level. It needs to be on the same level as the frags because
 *  we run the flow engine against this and we need to get the same flow.
 *
 *  \param parent parent packet for this pseudo pkt
 *  \param pkt raw packet data
 *  \param len packet data length
 *  \param proto protocol of the tunneled packet
 *
 *  \retval p the pseudo packet or NULL if out of memory
 */
Packet *PacketDefragPktSetup(Packet *parent, uint8_t *pkt, uint16_t len, uint8_t proto) {
    SCEnter();

    /* get us a packet */
    Packet *p = PacketGetFromQueueOrAlloc();
    if (p == NULL) {
        SCReturnPtr(NULL, "Packet");
    }

    /* set the root ptr to the lowest layer */
    if (parent->root != NULL)
        p->root = parent->root;
    else
        p->root = parent;

    /* copy packet and set lenght, proto */
    PacketCopyData(p, pkt, len);
    p->recursion_level = parent->recursion_level; /* NOT incremented */
    p->ts.tv_sec = parent->ts.tv_sec;
    p->ts.tv_usec = parent->ts.tv_usec;
    p->datalink = DLT_RAW;

    /* set tunnel flags */

    /* tell new packet it's part of a tunnel */
    SET_TUNNEL_PKT(p);
    /* tell parent packet it's part of a tunnel */
    SET_TUNNEL_PKT(parent);

    /* increment tunnel packet refcnt in the root packet */
    TUNNEL_INCR_PKT_TPR(p);

    /* disable payload (not packet) inspection on the parent, as the payload
     * is the packet we will now run through the system separately. We do
     * check it against the ip/port/other header checks though */
    DecodeSetNoPayloadInspectionFlag(parent);
    SCReturnPtr(p, "Packet");
}

void DecodeRegisterPerfCounters(DecodeThreadVars *dtv, ThreadVars *tv)
{
    /* register counters */
    dtv->counter_pkts = SCPerfTVRegisterCounter("decoder.pkts", tv,
                                                SC_PERF_TYPE_UINT64, "NULL");
#if 0
    dtv->counter_pkts_per_sec = SCPerfTVRegisterIntervalCounter("decoder.pkts_per_sec",
                                                                tv, SC_PERF_TYPE_DOUBLE,
                                                                "NULL", "1s");
#endif
    dtv->counter_bytes = SCPerfTVRegisterCounter("decoder.bytes", tv,
                                                 SC_PERF_TYPE_UINT64, "NULL");
#if 0
    dtv->counter_bytes_per_sec = SCPerfTVRegisterIntervalCounter("decoder.bytes_per_sec",
                                                                tv, SC_PERF_TYPE_DOUBLE,
                                                                "NULL", "1s");
    dtv->counter_mbit_per_sec = SCPerfTVRegisterIntervalCounter("decoder.mbit_per_sec",
                                                                tv, SC_PERF_TYPE_DOUBLE,
                                                                "NULL", "1s");
#endif
    dtv->counter_ipv4 = SCPerfTVRegisterCounter("decoder.ipv4", tv,
                                                SC_PERF_TYPE_UINT64, "NULL");
    dtv->counter_ipv6 = SCPerfTVRegisterCounter("decoder.ipv6", tv,
                                                SC_PERF_TYPE_UINT64, "NULL");
    dtv->counter_eth = SCPerfTVRegisterCounter("decoder.ethernet", tv,
                                               SC_PERF_TYPE_UINT64, "NULL");
    dtv->counter_raw = SCPerfTVRegisterCounter("decoder.raw", tv,
                                               SC_PERF_TYPE_UINT64, "NULL");
    dtv->counter_sll = SCPerfTVRegisterCounter("decoder.sll", tv,
                                               SC_PERF_TYPE_UINT64, "NULL");
    dtv->counter_tcp = SCPerfTVRegisterCounter("decoder.tcp", tv,
                                               SC_PERF_TYPE_UINT64, "NULL");
    dtv->counter_udp = SCPerfTVRegisterCounter("decoder.udp", tv,
                                               SC_PERF_TYPE_UINT64, "NULL");
    dtv->counter_sctp = SCPerfTVRegisterCounter("decoder.sctp", tv,
                                               SC_PERF_TYPE_UINT64, "NULL");
    dtv->counter_icmpv4 = SCPerfTVRegisterCounter("decoder.icmpv4", tv,
                                                  SC_PERF_TYPE_UINT64, "NULL");
    dtv->counter_icmpv6 = SCPerfTVRegisterCounter("decoder.icmpv6", tv,
                                                  SC_PERF_TYPE_UINT64, "NULL");
    dtv->counter_ppp = SCPerfTVRegisterCounter("decoder.ppp", tv,
                                               SC_PERF_TYPE_UINT64, "NULL");
    dtv->counter_pppoe = SCPerfTVRegisterCounter("decoder.pppoe", tv,
                                                 SC_PERF_TYPE_UINT64, "NULL");
    dtv->counter_gre = SCPerfTVRegisterCounter("decoder.gre", tv,
                                               SC_PERF_TYPE_UINT64, "NULL");
    dtv->counter_vlan = SCPerfTVRegisterCounter("decoder.vlan", tv,
                                               SC_PERF_TYPE_UINT64, "NULL");
    dtv->counter_avg_pkt_size = SCPerfTVRegisterAvgCounter("decoder.avg_pkt_size", tv,
                                                           SC_PERF_TYPE_DOUBLE, "NULL");
    dtv->counter_max_pkt_size = SCPerfTVRegisterMaxCounter("decoder.max_pkt_size", tv,
                                                           SC_PERF_TYPE_UINT64, "NULL");

    dtv->counter_defrag_ipv4_fragments =
        SCPerfTVRegisterCounter("defrag.ipv4.fragments", tv,
            SC_PERF_TYPE_UINT64, "NULL");
    dtv->counter_defrag_ipv4_reassembled =
        SCPerfTVRegisterCounter("defrag.ipv4.reassembled", tv,
            SC_PERF_TYPE_UINT64, "NULL");
    dtv->counter_defrag_ipv4_timeouts =
        SCPerfTVRegisterCounter("defrag.ipv4.timeouts", tv,
            SC_PERF_TYPE_UINT64, "NULL");
    dtv->counter_defrag_ipv6_fragments =
        SCPerfTVRegisterCounter("defrag.ipv6.fragments", tv,
            SC_PERF_TYPE_UINT64, "NULL");
    dtv->counter_defrag_ipv6_reassembled =
        SCPerfTVRegisterCounter("defrag.ipv6.reassembled", tv,
            SC_PERF_TYPE_UINT64, "NULL");
    dtv->counter_defrag_ipv6_timeouts =
        SCPerfTVRegisterCounter("defrag.ipv6.timeouts", tv,
            SC_PERF_TYPE_UINT64, "NULL");

    tv->sc_perf_pca = SCPerfGetAllCountersArray(&tv->sc_perf_pctx);
    SCPerfAddToClubbedTMTable(tv->name, &tv->sc_perf_pctx);

    return;
}

/**
 *  \brief Debug print function for printing addresses
 *
 *  \param Address object
 *
 *  \todo IPv6
 */
void AddressDebugPrint(Address *a) {
    if (a == NULL)
        return;

    switch (a->family) {
        case AF_INET:
        {
            char s[16];
            PrintInet(AF_INET, (const void *)&a->addr_data32[0], s, sizeof(s));
            SCLogDebug("%s", s);
            break;
        }
    }
}

/** \brief Alloc and setup DecodeThreadVars */
DecodeThreadVars *DecodeThreadVarsAlloc() {

    DecodeThreadVars *dtv = NULL;

    if ( (dtv = SCMalloc(sizeof(DecodeThreadVars))) == NULL)
        return NULL;

    memset(dtv, 0, sizeof(DecodeThreadVars));

    /* initialize UDP app layer code */
    AlpProtoFinalize2Thread(&dtv->udp_dp_ctx);

    return dtv;
}


/**
 * \brief Set data for Packet and set length when zeo copy is used
 *
 *  \param Pointer to the Packet to modify
 *  \param Pointer to the data
 *  \param Length of the data
 */
inline int PacketSetData(Packet *p, uint8_t *pktdata, int pktlen)
{
    SET_PKT_LEN(p, (size_t)pktlen);
    if (!pktdata) {
        return -1;
    }
    p->ext_pkt = pktdata;
    p->flags |= PKT_ZERO_COPY;

    return 0;
}

/**
 * @}
 */
