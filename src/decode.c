/* Copyright (C) 2007-2014 Open Information Security Foundation
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
#include "conf.h"
#include "decode.h"
#include "util-debug.h"
#include "util-mem.h"
#include "app-layer-detect-proto.h"
#include "app-layer.h"
#include "tm-threads.h"
#include "util-error.h"
#include "util-print.h"
#include "tmqh-packetpool.h"
#include "util-profiling.h"
#include "pkt-var.h"
#include "util-mpm-ac.h"

#include "output.h"
#include "output-flow.h"

int DecodeTunnel(ThreadVars *tv, DecodeThreadVars *dtv, Packet *p,
        uint8_t *pkt, uint16_t len, PacketQueue *pq, enum DecodeTunnelProto proto)
{
    switch (proto) {
        case DECODE_TUNNEL_PPP:
            return DecodePPP(tv, dtv, p, pkt, len, pq);
        case DECODE_TUNNEL_IPV4:
            return DecodeIPV4(tv, dtv, p, pkt, len, pq);
        case DECODE_TUNNEL_IPV6:
            return DecodeIPV6(tv, dtv, p, pkt, len, pq);
        case DECODE_TUNNEL_VLAN:
            return DecodeVLAN(tv, dtv, p, pkt, len, pq);
        case DECODE_TUNNEL_ETHERNET:
            return DecodeEthernet(tv, dtv, p, pkt, len, pq);
        case DECODE_TUNNEL_ERSPAN:
            return DecodeERSPAN(tv, dtv, p, pkt, len, pq);
        default:
            SCLogInfo("FIXME: DecodeTunnel: protocol %" PRIu32 " not supported.", proto);
            break;
    }
    return TM_ECODE_OK;
}

/**
 * \brief Return a malloced packet.
 */
void PacketFree(Packet *p)
{
    PACKET_DESTRUCTOR(p);
    SCFree(p);
}

/**
 * \brief Finalize decoding of a packet
 *
 * This function needs to be call at the end of decode
 * functions when decoding has been succesful.
 *
 */

void PacketDecodeFinalize(ThreadVars *tv, DecodeThreadVars *dtv, Packet *p)
{

    if (p->flags & PKT_IS_INVALID)
        StatsIncr(tv, dtv->counter_invalid);

#ifdef __SC_CUDA_SUPPORT__
    if (dtv->cuda_vars.mpm_is_cuda)
        CudaBufferPacket(&dtv->cuda_vars, p);
#endif

}

/**
 * \brief Get a malloced packet.
 *
 * \retval p packet, NULL on error
 */
Packet *PacketGetFromAlloc(void)
{
    Packet *p = SCMalloc(SIZE_OF_PACKET);
    if (unlikely(p == NULL)) {
        return NULL;
    }

    memset(p, 0, SIZE_OF_PACKET);
    PACKET_INITIALIZE(p);
    p->ReleasePacket = PacketFree;
    p->flags |= PKT_ALLOC;

    SCLogDebug("allocated a new packet only using alloc...");

    PACKET_PROFILING_START(p);
    return p;
}

/**
 * \brief Return a packet to where it was allocated.
 */
void PacketFreeOrRelease(Packet *p)
{
    if (p->flags & PKT_ALLOC)
        PacketFree(p);
    else
        PacketPoolReturnPacket(p);
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
    /* try the pool first */
    Packet *p = PacketPoolGetPacket();

    if (p == NULL) {
        /* non fatal, we're just not processing a packet then */
        p = PacketGetFromAlloc();
    } else {
        PACKET_PROFILING_START(p);
    }

    return p;
}

inline int PacketCallocExtPkt(Packet *p, int datalen)
{
    if (! p->ext_pkt) {
        p->ext_pkt = SCCalloc(1, datalen);
        if (unlikely(p->ext_pkt == NULL)) {
            SET_PKT_LEN(p, 0);
            return -1;
        }
    }
    return 0;
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
    if (unlikely(offset + datalen > MAX_PAYLOAD_SIZE)) {
        /* too big */
        return -1;
    }

    /* Do we have already an packet with allocated data */
    if (! p->ext_pkt) {
        if (offset + datalen <= (int)default_packet_size) {
            /* data will fit in memory allocated with packet */
            memcpy(GET_PKT_DIRECT_DATA(p) + offset, data, datalen);
        } else {
            /* here we need a dynamic allocation */
            p->ext_pkt = SCMalloc(MAX_PAYLOAD_SIZE);
            if (unlikely(p->ext_pkt == NULL)) {
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
Packet *PacketTunnelPktSetup(ThreadVars *tv, DecodeThreadVars *dtv, Packet *parent,
                             uint8_t *pkt, uint16_t len, enum DecodeTunnelProto proto,
                             PacketQueue *pq)
{
    int ret;

    SCEnter();

    /* get us a packet */
    Packet *p = PacketGetFromQueueOrAlloc();
    if (unlikely(p == NULL)) {
        SCReturnPtr(NULL, "Packet");
    }

    /* copy packet and set lenght, proto */
    PacketCopyData(p, pkt, len);
    p->recursion_level = parent->recursion_level + 1;
    p->ts.tv_sec = parent->ts.tv_sec;
    p->ts.tv_usec = parent->ts.tv_usec;
    p->datalink = DLT_RAW;
    p->tenant_id = parent->tenant_id;

    /* set the root ptr to the lowest layer */
    if (parent->root != NULL)
        p->root = parent->root;
    else
        p->root = parent;

    /* tell new packet it's part of a tunnel */
    SET_TUNNEL_PKT(p);

    ret = DecodeTunnel(tv, dtv, p, GET_PKT_DATA(p),
                       GET_PKT_LEN(p), pq, proto);

    if (unlikely(ret != TM_ECODE_OK)) {
        /* Not a tunnel packet, just a pseudo packet */
        p->root = NULL;
        UNSET_TUNNEL_PKT(p);
        TmqhOutputPacketpool(tv, p);
        SCReturnPtr(NULL, "Packet");
    }


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
Packet *PacketDefragPktSetup(Packet *parent, uint8_t *pkt, uint16_t len, uint8_t proto)
{
    SCEnter();

    /* get us a packet */
    Packet *p = PacketGetFromQueueOrAlloc();
    if (unlikely(p == NULL)) {
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
    p->tenant_id = parent->tenant_id;
    /* tell new packet it's part of a tunnel */
    SET_TUNNEL_PKT(p);
    p->vlan_id[0] = parent->vlan_id[0];
    p->vlan_id[1] = parent->vlan_id[1];
    p->vlan_idx = parent->vlan_idx;

    SCReturnPtr(p, "Packet");
}

/**
 *  \brief inform defrag "parent" that a pseudo packet is
 *         now assosiated to it.
 */
void PacketDefragPktSetupParent(Packet *parent)
{
    /* tell parent packet it's part of a tunnel */
    SET_TUNNEL_PKT(parent);

    /* increment tunnel packet refcnt in the root packet */
    TUNNEL_INCR_PKT_TPR(parent);

    /* disable payload (not packet) inspection on the parent, as the payload
     * is the packet we will now run through the system separately. We do
     * check it against the ip/port/other header checks though */
    DecodeSetNoPayloadInspectionFlag(parent);
}

void DecodeRegisterPerfCounters(DecodeThreadVars *dtv, ThreadVars *tv)
{
    /* register counters */
    dtv->counter_pkts = StatsRegisterCounter("decoder.pkts", tv);
    dtv->counter_bytes = StatsRegisterCounter("decoder.bytes", tv);
    dtv->counter_invalid = StatsRegisterCounter("decoder.invalid", tv);
    dtv->counter_ipv4 = StatsRegisterCounter("decoder.ipv4", tv);
    dtv->counter_ipv6 = StatsRegisterCounter("decoder.ipv6", tv);
    dtv->counter_eth = StatsRegisterCounter("decoder.ethernet", tv);
    dtv->counter_raw = StatsRegisterCounter("decoder.raw", tv);
    dtv->counter_null = StatsRegisterCounter("decoder.null", tv);
    dtv->counter_sll = StatsRegisterCounter("decoder.sll", tv);
    dtv->counter_tcp = StatsRegisterCounter("decoder.tcp", tv);
    dtv->counter_udp = StatsRegisterCounter("decoder.udp", tv);
    dtv->counter_sctp = StatsRegisterCounter("decoder.sctp", tv);
    dtv->counter_icmpv4 = StatsRegisterCounter("decoder.icmpv4", tv);
    dtv->counter_icmpv6 = StatsRegisterCounter("decoder.icmpv6", tv);
    dtv->counter_ppp = StatsRegisterCounter("decoder.ppp", tv);
    dtv->counter_pppoe = StatsRegisterCounter("decoder.pppoe", tv);
    dtv->counter_gre = StatsRegisterCounter("decoder.gre", tv);
    dtv->counter_vlan = StatsRegisterCounter("decoder.vlan", tv);
    dtv->counter_vlan_qinq = StatsRegisterCounter("decoder.vlan_qinq", tv);
    dtv->counter_teredo = StatsRegisterCounter("decoder.teredo", tv);
    dtv->counter_ipv4inipv6 = StatsRegisterCounter("decoder.ipv4_in_ipv6", tv);
    dtv->counter_ipv6inipv6 = StatsRegisterCounter("decoder.ipv6_in_ipv6", tv);
    dtv->counter_mpls = StatsRegisterCounter("decoder.mpls", tv);
    dtv->counter_avg_pkt_size = StatsRegisterAvgCounter("decoder.avg_pkt_size", tv);
    dtv->counter_max_pkt_size = StatsRegisterMaxCounter("decoder.max_pkt_size", tv);
    dtv->counter_erspan = StatsRegisterMaxCounter("decoder.erspan", tv);
    dtv->counter_flow_memcap = StatsRegisterCounter("flow.memcap", tv);

    dtv->counter_defrag_ipv4_fragments =
        StatsRegisterCounter("defrag.ipv4.fragments", tv);
    dtv->counter_defrag_ipv4_reassembled =
        StatsRegisterCounter("defrag.ipv4.reassembled", tv);
    dtv->counter_defrag_ipv4_timeouts =
        StatsRegisterCounter("defrag.ipv4.timeouts", tv);
    dtv->counter_defrag_ipv6_fragments =
        StatsRegisterCounter("defrag.ipv6.fragments", tv);
    dtv->counter_defrag_ipv6_reassembled =
        StatsRegisterCounter("defrag.ipv6.reassembled", tv);
    dtv->counter_defrag_ipv6_timeouts =
        StatsRegisterCounter("defrag.ipv6.timeouts", tv);
    dtv->counter_defrag_max_hit =
        StatsRegisterCounter("defrag.max_frag_hits", tv);

    return;
}

void DecodeUpdatePacketCounters(ThreadVars *tv,
                                const DecodeThreadVars *dtv, const Packet *p)
{
    StatsIncr(tv, dtv->counter_pkts);
    //StatsIncr(tv, dtv->counter_pkts_per_sec);
    StatsAddUI64(tv, dtv->counter_bytes, GET_PKT_LEN(p));
    StatsAddUI64(tv, dtv->counter_avg_pkt_size, GET_PKT_LEN(p));
    StatsSetUI64(tv, dtv->counter_max_pkt_size, GET_PKT_LEN(p));
}

/**
 *  \brief Debug print function for printing addresses
 *
 *  \param Address object
 *
 *  \todo IPv6
 */
void AddressDebugPrint(Address *a)
{
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
DecodeThreadVars *DecodeThreadVarsAlloc(ThreadVars *tv)
{
    DecodeThreadVars *dtv = NULL;

    if ( (dtv = SCMalloc(sizeof(DecodeThreadVars))) == NULL)
        return NULL;
    memset(dtv, 0, sizeof(DecodeThreadVars));

    dtv->app_tctx = AppLayerGetCtxThread(tv);

    if (OutputFlowLogThreadInit(tv, NULL, &dtv->output_flow_thread_data) != TM_ECODE_OK) {
        SCLogError(SC_ERR_THREAD_INIT, "initializing flow log API for thread failed");
        DecodeThreadVarsFree(tv, dtv);
        return NULL;
    }

    /** set config defaults */
    int vlanbool = 0;
    if ((ConfGetBool("vlan.use-for-tracking", &vlanbool)) == 1 && vlanbool == 0) {
        dtv->vlan_disabled = 1;
    }
    SCLogDebug("vlan tracking is %s", dtv->vlan_disabled == 0 ? "enabled" : "disabled");

    return dtv;
}

void DecodeThreadVarsFree(ThreadVars *tv, DecodeThreadVars *dtv)
{
    if (dtv != NULL) {
        if (dtv->app_tctx != NULL)
            AppLayerDestroyCtxThread(dtv->app_tctx);

        if (dtv->output_flow_thread_data != NULL)
            OutputFlowLogThreadDeinit(tv, dtv->output_flow_thread_data);

        SCFree(dtv);
    }
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
    if (unlikely(!pktdata)) {
        return -1;
    }
    p->ext_pkt = pktdata;
    p->flags |= PKT_ZERO_COPY;

    return 0;
}

const char *PktSrcToString(enum PktSrcEnum pkt_src)
{
    char *pkt_src_str = "<unknown>";
    switch (pkt_src) {
        case PKT_SRC_WIRE:
            pkt_src_str = "wire/pcap";
            break;
        case PKT_SRC_DECODER_GRE:
            pkt_src_str = "gre tunnel";
            break;
        case PKT_SRC_DECODER_IPV4:
            pkt_src_str = "ipv4 tunnel";
            break;
        case PKT_SRC_DECODER_IPV6:
            pkt_src_str = "ipv6 tunnel";
            break;
        case PKT_SRC_DECODER_TEREDO:
            pkt_src_str = "teredo tunnel";
            break;
        case PKT_SRC_DEFRAG:
            pkt_src_str = "defrag";
            break;
        case PKT_SRC_STREAM_TCP_STREAM_END_PSEUDO:
            pkt_src_str = "stream";
            break;
        case PKT_SRC_FFR:
            pkt_src_str = "stream (flow timeout)";
            break;
    }
    return pkt_src_str;
}

void CaptureStatsUpdate(ThreadVars *tv, CaptureStats *s, const Packet *p)
{
    if (unlikely(PACKET_TEST_ACTION(p, (ACTION_REJECT|ACTION_REJECT_DST|ACTION_REJECT_BOTH)))) {
        StatsIncr(tv, s->counter_ips_rejected);
    } else if (unlikely(PACKET_TEST_ACTION(p, ACTION_DROP))) {
        StatsIncr(tv, s->counter_ips_blocked);
    } else if (unlikely(p->flags & PKT_STREAM_MODIFIED)) {
        StatsIncr(tv, s->counter_ips_replaced);
    } else {
        StatsIncr(tv, s->counter_ips_accepted);
    }
}

void CaptureStatsSetup(ThreadVars *tv, CaptureStats *s)
{
    s->counter_ips_accepted = StatsRegisterCounter("ips.accepted", tv);
    s->counter_ips_blocked = StatsRegisterCounter("ips.blocked", tv);
    s->counter_ips_rejected = StatsRegisterCounter("ips.rejected", tv);
    s->counter_ips_replaced = StatsRegisterCounter("ips.replaced", tv);
}

/**
 * @}
 */
