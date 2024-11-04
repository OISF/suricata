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
 * These functions have all a pkt and a len argument which
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
#include "decode.h"

#include "packet.h"
#include "flow.h"
#include "flow-storage.h"
#include "tmqh-packetpool.h"
#include "app-layer.h"
#include "output.h"

#include "decode-vxlan.h"
#include "decode-geneve.h"
#include "decode-erspan.h"
#include "decode-teredo.h"
#include "decode-arp.h"

#include "defrag-hash.h"

#include "util-hash.h"
#include "util-hash-string.h"
#include "util-print.h"
#include "util-profiling.h"
#include "util-validate.h"
#include "util-debug.h"
#include "util-exception-policy.h"
#include "action-globals.h"

uint32_t default_packet_size = 0;
extern bool stats_decoder_events;
extern const char *stats_decoder_events_prefix;
extern bool stats_stream_events;
uint8_t decoder_max_layers = PKT_DEFAULT_MAX_DECODED_LAYERS;
uint16_t packet_alert_max = PACKET_ALERT_MAX;

/* Settings order as in the enum */
// clang-format off
ExceptionPolicyStatsSetts defrag_memcap_eps_stats = {
    .valid_settings_ids = {
    /* EXCEPTION_POLICY_NOT_SET */      false,
    /* EXCEPTION_POLICY_AUTO */         false,
    /* EXCEPTION_POLICY_PASS_PACKET */  true,
    /* EXCEPTION_POLICY_PASS_FLOW */    false,
    /* EXCEPTION_POLICY_BYPASS_FLOW */  true,
    /* EXCEPTION_POLICY_DROP_PACKET */  false,
    /* EXCEPTION_POLICY_DROP_FLOW */    false,
    /* EXCEPTION_POLICY_REJECT */       true,
    },
    .valid_settings_ips = {
    /* EXCEPTION_POLICY_NOT_SET */      false,
    /* EXCEPTION_POLICY_AUTO */         false,
    /* EXCEPTION_POLICY_PASS_PACKET */  true,
    /* EXCEPTION_POLICY_PASS_FLOW */    false,
    /* EXCEPTION_POLICY_BYPASS_FLOW */  true,
    /* EXCEPTION_POLICY_DROP_PACKET */  true,
    /* EXCEPTION_POLICY_DROP_FLOW */    false,
    /* EXCEPTION_POLICY_REJECT */       true,
    },
};
// clang-format on

/* Settings order as in the enum */
// clang-format off
ExceptionPolicyStatsSetts flow_memcap_eps_stats = {
    .valid_settings_ids = {
    /* EXCEPTION_POLICY_NOT_SET */      false,
    /* EXCEPTION_POLICY_AUTO */         false,
    /* EXCEPTION_POLICY_PASS_PACKET */  true,
    /* EXCEPTION_POLICY_PASS_FLOW */    false,
    /* EXCEPTION_POLICY_BYPASS_FLOW */  true,
    /* EXCEPTION_POLICY_DROP_PACKET */  false,
    /* EXCEPTION_POLICY_DROP_FLOW */    false,
    /* EXCEPTION_POLICY_REJECT */       true,
    },
    .valid_settings_ips = {
    /* EXCEPTION_POLICY_NOT_SET */      false,
    /* EXCEPTION_POLICY_AUTO */         false,
    /* EXCEPTION_POLICY_PASS_PACKET */  true,
    /* EXCEPTION_POLICY_PASS_FLOW */    false,
    /* EXCEPTION_POLICY_BYPASS_FLOW */  true,
    /* EXCEPTION_POLICY_DROP_PACKET */  true,
    /* EXCEPTION_POLICY_DROP_FLOW */    false,
    /* EXCEPTION_POLICY_REJECT */       true,
    },
};
// clang-format on

/**
 * \brief Initialize PacketAlerts with dynamic alerts array size
 *
 */
PacketAlert *PacketAlertCreate(void)
{
    PacketAlert *pa_array = SCCalloc(packet_alert_max, sizeof(PacketAlert));
    BUG_ON(pa_array == NULL);

    return pa_array;
}

void PacketAlertFree(PacketAlert *pa)
{
    if (pa != NULL) {
        SCFree(pa);
    }
}

static int DecodeTunnel(ThreadVars *, DecodeThreadVars *, Packet *, const uint8_t *, uint32_t,
        enum DecodeTunnelProto) WARN_UNUSED;

static int DecodeTunnel(ThreadVars *tv, DecodeThreadVars *dtv, Packet *p, const uint8_t *pkt,
        uint32_t len, enum DecodeTunnelProto proto)
{
    switch (proto) {
        case DECODE_TUNNEL_PPP:
            return DecodePPP(tv, dtv, p, pkt, len);
        case DECODE_TUNNEL_IPV4:
            DEBUG_VALIDATE_BUG_ON(len > UINT16_MAX);
            return DecodeIPV4(tv, dtv, p, pkt, (uint16_t)len);
        case DECODE_TUNNEL_IPV6:
        case DECODE_TUNNEL_IPV6_TEREDO:
            DEBUG_VALIDATE_BUG_ON(len > UINT16_MAX);
            return DecodeIPV6(tv, dtv, p, pkt, (uint16_t)len);
        case DECODE_TUNNEL_VLAN:
            return DecodeVLAN(tv, dtv, p, pkt, len);
        case DECODE_TUNNEL_ETHERNET:
            return DecodeEthernet(tv, dtv, p, pkt, len);
        case DECODE_TUNNEL_ERSPANII:
            return DecodeERSPAN(tv, dtv, p, pkt, len);
        case DECODE_TUNNEL_ERSPANI:
            return DecodeERSPANTypeI(tv, dtv, p, pkt, len);
        case DECODE_TUNNEL_NSH:
            return DecodeNSH(tv, dtv, p, pkt, len);
        case DECODE_TUNNEL_ARP:
            return DecodeARP(tv, dtv, p, pkt, len);
        default:
            SCLogDebug("FIXME: DecodeTunnel: protocol %" PRIu32 " not supported.", proto);
            break;
    }
    return TM_ECODE_OK;
}

/**
 * \brief Return a malloced packet.
 */
void PacketFree(Packet *p)
{
    PacketDestructor(p);
    SCFree(p);
}

/**
 * \brief Finalize decoding of a packet
 *
 * This function needs to be call at the end of decode
 * functions when decoding has been successful.
 *
 */
void PacketDecodeFinalize(ThreadVars *tv, DecodeThreadVars *dtv, Packet *p)
{
    if (p->flags & PKT_IS_INVALID) {
        StatsIncr(tv, dtv->counter_invalid);
    }
}

void PacketUpdateEngineEventCounters(ThreadVars *tv,
        DecodeThreadVars *dtv, Packet *p)
{
    for (uint8_t i = 0; i < p->events.cnt; i++) {
        const uint8_t e = p->events.events[i];

        if (e <= DECODE_EVENT_PACKET_MAX && !stats_decoder_events)
            continue;
        else if (e > DECODE_EVENT_PACKET_MAX && !stats_stream_events)
            continue;
        StatsIncr(tv, dtv->counter_engine_events[e]);
    }
}

/**
 * \brief Get a malloced packet.
 *
 * \retval p packet, NULL on error
 */
Packet *PacketGetFromAlloc(void)
{
    Packet *p = SCCalloc(1, SIZE_OF_PACKET);
    if (unlikely(p == NULL)) {
        return NULL;
    }
    PacketInit(p);
    p->ReleasePacket = PacketFree;

    SCLogDebug("allocated a new packet only using alloc...");

    PACKET_PROFILING_START(p);
    return p;
}

/**
 * \brief Return a packet to where it was allocated.
 */
void PacketFreeOrRelease(Packet *p)
{
    if (likely(p->pool != NULL)) {
        p->ReleasePacket = PacketPoolReturnPacket;
        PacketPoolReturnPacket(p);
    } else {
        PacketFree(p);
    }
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
        DEBUG_VALIDATE_BUG_ON(p->ReleasePacket != PacketPoolReturnPacket);
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
inline int PacketCopyDataOffset(Packet *p, uint32_t offset, const uint8_t *data, uint32_t datalen)
{
    if (unlikely(offset + datalen > MAX_PAYLOAD_SIZE)) {
        /* too big */
        SET_PKT_LEN(p, 0);
        return -1;
    }

    /* Do we have already an packet with allocated data */
    if (! p->ext_pkt) {
        uint32_t newsize = offset + datalen;
        // check overflow
        if (newsize < offset)
            return -1;
        if (newsize <= default_packet_size) {
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
inline int PacketCopyData(Packet *p, const uint8_t *pktdata, uint32_t pktlen)
{
    SET_PKT_LEN(p, pktlen);
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
                             const uint8_t *pkt, uint32_t len, enum DecodeTunnelProto proto)
{
    int ret;

    SCEnter();

    if (parent->nb_decoded_layers + 1 >= decoder_max_layers) {
        ENGINE_SET_INVALID_EVENT(parent, GENERIC_TOO_MANY_LAYERS);
        SCReturnPtr(NULL, "Packet");
    }

    /* get us a packet */
    Packet *p = PacketGetFromQueueOrAlloc();
    if (unlikely(p == NULL)) {
        SCReturnPtr(NULL, "Packet");
    }

    /* copy packet and set length, proto */
    PacketCopyData(p, pkt, len);
    DEBUG_VALIDATE_BUG_ON(parent->recursion_level == 255);
    p->recursion_level = parent->recursion_level + 1;
    DEBUG_VALIDATE_BUG_ON(parent->nb_decoded_layers >= decoder_max_layers);
    p->nb_decoded_layers = parent->nb_decoded_layers + 1;
    p->ts = parent->ts;
    p->datalink = DLT_RAW;
    p->tenant_id = parent->tenant_id;
    p->livedev = parent->livedev;

    /* set the root ptr to the lowest layer */
    if (parent->root != NULL) {
        p->root = parent->root;
        BUG_ON(parent->ttype != PacketTunnelChild);
    } else {
        p->root = parent;
        parent->ttype = PacketTunnelRoot;
    }
    /* tell new packet it's part of a tunnel */
    p->ttype = PacketTunnelChild;

    ret = DecodeTunnel(tv, dtv, p, GET_PKT_DATA(p),
                       GET_PKT_LEN(p), proto);

    if (unlikely(ret != TM_ECODE_OK) ||
            (proto == DECODE_TUNNEL_IPV6_TEREDO && (p->flags & PKT_IS_INVALID)))
    {
        /* Not a (valid) tunnel packet */
        SCLogDebug("tunnel packet is invalid");
        p->root = NULL;
        TmqhOutputPacketpool(tv, p);
        SCReturnPtr(NULL, "Packet");
    }

    /* Update tunnel settings in parent */
    if (parent->root == NULL) {
        parent->ttype = PacketTunnelRoot;
    }
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
Packet *PacketDefragPktSetup(Packet *parent, const uint8_t *pkt, uint32_t len, uint8_t proto)
{
    SCEnter();

    /* get us a packet */
    Packet *p = PacketGetFromQueueOrAlloc();
    if (unlikely(p == NULL)) {
        SCReturnPtr(NULL, "Packet");
    }

    /* set the root ptr to the lowest layer */
    if (parent->root != NULL) {
        p->root = parent->root;
        BUG_ON(parent->ttype != PacketTunnelChild);
    } else {
        p->root = parent;
        // we set parent->ttype later
    }
    /* tell new packet it's part of a tunnel */
    p->ttype = PacketTunnelChild;

    /* copy packet and set length, proto */
    if (pkt && len) {
        PacketCopyData(p, pkt, len);
    }
    p->recursion_level = parent->recursion_level; /* NOT incremented */
    p->ts = parent->ts;
    p->tenant_id = parent->tenant_id;
    memcpy(&p->vlan_id[0], &parent->vlan_id[0], sizeof(p->vlan_id));
    p->vlan_idx = parent->vlan_idx;
    p->livedev = parent->livedev;

    SCReturnPtr(p, "Packet");
}

/**
 *  \brief inform defrag "parent" that a pseudo packet is
 *         now associated to it.
 */
void PacketDefragPktSetupParent(Packet *parent)
{
    /* tell parent packet it's part of a tunnel */
    if (parent->ttype == PacketTunnelNone)
        parent->ttype = PacketTunnelRoot;

    /* increment tunnel packet refcnt in the root packet */
    TUNNEL_INCR_PKT_TPR(parent);

    /* disable payload (not packet) inspection on the parent, as the payload
     * is the packet we will now run through the system separately. We do
     * check it against the ip/port/other header checks though */
    DecodeSetNoPayloadInspectionFlag(parent);
}

/**
 *  \note if p->flow is set, the flow is locked
 */
void PacketBypassCallback(Packet *p)
{
    if (PKT_IS_PSEUDOPKT(p))
        return;

#ifdef CAPTURE_OFFLOAD
    /* Don't try to bypass if flow is already out or
     * if we have failed to do it once */
    if (p->flow) {
        int state = p->flow->flow_state;
        if ((state == FLOW_STATE_LOCAL_BYPASSED) ||
                (state == FLOW_STATE_CAPTURE_BYPASSED)) {
            return;
        }

        FlowBypassInfo *fc;

        fc = FlowGetStorageById(p->flow, GetFlowBypassInfoID());
        if (fc == NULL) {
            fc = SCCalloc(sizeof(FlowBypassInfo), 1);
            if (fc) {
                FlowSetStorageById(p->flow, GetFlowBypassInfoID(), fc);
            } else {
                return;
            }
        }
    }
    if (p->BypassPacketsFlow && p->BypassPacketsFlow(p)) {
        if (p->flow) {
            FlowUpdateState(p->flow, FLOW_STATE_CAPTURE_BYPASSED);
        }
    } else {
        if (p->flow) {
            FlowUpdateState(p->flow, FLOW_STATE_LOCAL_BYPASSED);
        }
    }
#else /* CAPTURE_OFFLOAD */
    if (p->flow) {
        int state = p->flow->flow_state;
        if (state == FLOW_STATE_LOCAL_BYPASSED)
            return;
        FlowUpdateState(p->flow, FLOW_STATE_LOCAL_BYPASSED);
    }
#endif
}

/** \brief switch direction of a packet */
void PacketSwap(Packet *p)
{
    if (PKT_IS_TOSERVER(p)) {
        p->flowflags &= ~FLOW_PKT_TOSERVER;
        p->flowflags |= FLOW_PKT_TOCLIENT;

        if (p->flowflags & FLOW_PKT_TOSERVER_FIRST) {
            p->flowflags &= ~FLOW_PKT_TOSERVER_FIRST;
            p->flowflags |= FLOW_PKT_TOCLIENT_FIRST;
        }
    } else {
        p->flowflags &= ~FLOW_PKT_TOCLIENT;
        p->flowflags |= FLOW_PKT_TOSERVER;

        if (p->flowflags & FLOW_PKT_TOCLIENT_FIRST) {
            p->flowflags &= ~FLOW_PKT_TOCLIENT_FIRST;
            p->flowflags |= FLOW_PKT_TOSERVER_FIRST;
        }
    }
}

/* counter name store */
static HashTable *g_counter_table = NULL;
static SCMutex g_counter_table_mutex = SCMUTEX_INITIALIZER;

void DecodeUnregisterCounters(void)
{
    SCMutexLock(&g_counter_table_mutex);
    if (g_counter_table) {
        HashTableFree(g_counter_table);
        g_counter_table = NULL;
    }
    SCMutexUnlock(&g_counter_table_mutex);
}

static bool IsDefragMemcapExceptionPolicyStatsValid(enum ExceptionPolicy policy)
{
    if (EngineModeIsIPS()) {
        return defrag_memcap_eps_stats.valid_settings_ips[policy];
    }
    return defrag_memcap_eps_stats.valid_settings_ids[policy];
}

static bool IsFlowMemcapExceptionPolicyStatsValid(enum ExceptionPolicy policy)
{
    if (EngineModeIsIPS()) {
        return flow_memcap_eps_stats.valid_settings_ips[policy];
    }
    return flow_memcap_eps_stats.valid_settings_ids[policy];
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
    dtv->counter_arp = StatsRegisterCounter("decoder.arp", tv);
    dtv->counter_ethertype_unknown = StatsRegisterCounter("decoder.unknown_ethertype", tv);
    dtv->counter_chdlc = StatsRegisterCounter("decoder.chdlc", tv);
    dtv->counter_raw = StatsRegisterCounter("decoder.raw", tv);
    dtv->counter_null = StatsRegisterCounter("decoder.null", tv);
    dtv->counter_sll = StatsRegisterCounter("decoder.sll", tv);
    dtv->counter_tcp = StatsRegisterCounter("decoder.tcp", tv);

    dtv->counter_tcp_syn = StatsRegisterCounter("tcp.syn", tv);
    dtv->counter_tcp_synack = StatsRegisterCounter("tcp.synack", tv);
    dtv->counter_tcp_rst = StatsRegisterCounter("tcp.rst", tv);

    dtv->counter_udp = StatsRegisterCounter("decoder.udp", tv);
    dtv->counter_sctp = StatsRegisterCounter("decoder.sctp", tv);
    dtv->counter_esp = StatsRegisterCounter("decoder.esp", tv);
    dtv->counter_icmpv4 = StatsRegisterCounter("decoder.icmpv4", tv);
    dtv->counter_icmpv6 = StatsRegisterCounter("decoder.icmpv6", tv);
    dtv->counter_ppp = StatsRegisterCounter("decoder.ppp", tv);
    dtv->counter_pppoe = StatsRegisterCounter("decoder.pppoe", tv);
    dtv->counter_geneve = StatsRegisterCounter("decoder.geneve", tv);
    dtv->counter_gre = StatsRegisterCounter("decoder.gre", tv);
    dtv->counter_vlan = StatsRegisterCounter("decoder.vlan", tv);
    dtv->counter_vlan_qinq = StatsRegisterCounter("decoder.vlan_qinq", tv);
    dtv->counter_vlan_qinqinq = StatsRegisterCounter("decoder.vlan_qinqinq", tv);
    dtv->counter_vxlan = StatsRegisterCounter("decoder.vxlan", tv);
    dtv->counter_vntag = StatsRegisterCounter("decoder.vntag", tv);
    dtv->counter_ieee8021ah = StatsRegisterCounter("decoder.ieee8021ah", tv);
    dtv->counter_teredo = StatsRegisterCounter("decoder.teredo", tv);
    dtv->counter_ipv4inipv6 = StatsRegisterCounter("decoder.ipv4_in_ipv6", tv);
    dtv->counter_ipv6inipv6 = StatsRegisterCounter("decoder.ipv6_in_ipv6", tv);
    dtv->counter_mpls = StatsRegisterCounter("decoder.mpls", tv);
    dtv->counter_avg_pkt_size = StatsRegisterAvgCounter("decoder.avg_pkt_size", tv);
    dtv->counter_max_pkt_size = StatsRegisterMaxCounter("decoder.max_pkt_size", tv);
    dtv->counter_max_mac_addrs_src = StatsRegisterMaxCounter("decoder.max_mac_addrs_src", tv);
    dtv->counter_max_mac_addrs_dst = StatsRegisterMaxCounter("decoder.max_mac_addrs_dst", tv);
    dtv->counter_erspan = StatsRegisterMaxCounter("decoder.erspan", tv);
    dtv->counter_nsh = StatsRegisterMaxCounter("decoder.nsh", tv);
    dtv->counter_flow_memcap = StatsRegisterCounter("flow.memcap", tv);
    ExceptionPolicySetStatsCounters(tv, &dtv->counter_flow_memcap_eps, &flow_memcap_eps_stats,
            FlowGetMemcapExceptionPolicy(), "flow.memcap_exception_policy.",
            IsFlowMemcapExceptionPolicyStatsValid);

    dtv->counter_tcp_active_sessions = StatsRegisterCounter("tcp.active_sessions", tv);
    dtv->counter_flow_total = StatsRegisterCounter("flow.total", tv);
    dtv->counter_flow_active = StatsRegisterCounter("flow.active", tv);
    dtv->counter_flow_tcp = StatsRegisterCounter("flow.tcp", tv);
    dtv->counter_flow_udp = StatsRegisterCounter("flow.udp", tv);
    dtv->counter_flow_icmp4 = StatsRegisterCounter("flow.icmpv4", tv);
    dtv->counter_flow_icmp6 = StatsRegisterCounter("flow.icmpv6", tv);
    dtv->counter_flow_tcp_reuse = StatsRegisterCounter("flow.tcp_reuse", tv);
    dtv->counter_flow_get_used = StatsRegisterCounter("flow.get_used", tv);
    dtv->counter_flow_get_used_eval = StatsRegisterCounter("flow.get_used_eval", tv);
    dtv->counter_flow_get_used_eval_reject = StatsRegisterCounter("flow.get_used_eval_reject", tv);
    dtv->counter_flow_get_used_eval_busy = StatsRegisterCounter("flow.get_used_eval_busy", tv);
    dtv->counter_flow_get_used_failed = StatsRegisterCounter("flow.get_used_failed", tv);

    dtv->counter_flow_spare_sync_avg = StatsRegisterAvgCounter("flow.wrk.spare_sync_avg", tv);
    dtv->counter_flow_spare_sync = StatsRegisterCounter("flow.wrk.spare_sync", tv);
    dtv->counter_flow_spare_sync_incomplete = StatsRegisterCounter("flow.wrk.spare_sync_incomplete", tv);
    dtv->counter_flow_spare_sync_empty = StatsRegisterCounter("flow.wrk.spare_sync_empty", tv);

    dtv->counter_defrag_ipv4_fragments =
        StatsRegisterCounter("defrag.ipv4.fragments", tv);
    dtv->counter_defrag_ipv4_reassembled = StatsRegisterCounter("defrag.ipv4.reassembled", tv);
    dtv->counter_defrag_ipv6_fragments =
        StatsRegisterCounter("defrag.ipv6.fragments", tv);
    dtv->counter_defrag_ipv6_reassembled = StatsRegisterCounter("defrag.ipv6.reassembled", tv);
    dtv->counter_defrag_max_hit = StatsRegisterCounter("defrag.max_trackers_reached", tv);
    dtv->counter_defrag_no_frags = StatsRegisterCounter("defrag.max_frags_reached", tv);
    dtv->counter_defrag_tracker_soft_reuse = StatsRegisterCounter("defrag.tracker_soft_reuse", tv);
    dtv->counter_defrag_tracker_hard_reuse = StatsRegisterCounter("defrag.tracker_hard_reuse", tv);
    dtv->counter_defrag_tracker_timeout = StatsRegisterCounter("defrag.wrk.tracker_timeout", tv);

    ExceptionPolicySetStatsCounters(tv, &dtv->counter_defrag_memcap_eps, &defrag_memcap_eps_stats,
            DefragGetMemcapExceptionPolicy(), "defrag.memcap_exception_policy.",
            IsDefragMemcapExceptionPolicyStatsValid);

    for (int i = 0; i < DECODE_EVENT_MAX; i++) {
        BUG_ON(i != (int)DEvents[i].code);

        if (i <= DECODE_EVENT_PACKET_MAX && !stats_decoder_events)
            continue;
        else if (i > DECODE_EVENT_PACKET_MAX && !stats_stream_events)
            continue;

        if (i < DECODE_EVENT_PACKET_MAX &&
                strncmp(DEvents[i].event_name, "decoder.", 8) == 0)
        {
            SCMutexLock(&g_counter_table_mutex);
            if (g_counter_table == NULL) {
                g_counter_table = HashTableInit(256, StringHashFunc,
                        StringHashCompareFunc,
                        StringHashFreeFunc);
                if (g_counter_table == NULL) {
                    FatalError("decoder counter hash "
                               "table init failed");
                }
            }

            char name[256];
            char *dot = strchr(DEvents[i].event_name, '.');
            BUG_ON(!dot);
            snprintf(name, sizeof(name), "%s.%s",
                    stats_decoder_events_prefix, dot+1);

            const char *found = HashTableLookup(g_counter_table, name, 0);
            if (!found) {
                char *add = SCStrdup(name);
                if (add == NULL)
                    FatalError("decoder counter hash "
                               "table name init failed");
                int r = HashTableAdd(g_counter_table, add, 0);
                if (r != 0)
                    FatalError("decoder counter hash "
                               "table name add failed");
                found = add;
            }
            dtv->counter_engine_events[i] = StatsRegisterCounter(
                    found, tv);

            SCMutexUnlock(&g_counter_table_mutex);
        } else {
            dtv->counter_engine_events[i] = StatsRegisterCounter(
                    DEvents[i].event_name, tv);
        }
    }
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

    if ((dtv = SCCalloc(1, sizeof(DecodeThreadVars))) == NULL)
        return NULL;

    dtv->app_tctx = AppLayerGetCtxThread();

    if (OutputFlowLogThreadInit(tv, &dtv->output_flow_thread_data) != TM_ECODE_OK) {
        SCLogError("initializing flow log API for thread failed");
        DecodeThreadVarsFree(tv, dtv);
        return NULL;
    }

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
 * \brief Set data for Packet and set length when zero copy is used
 *
 *  \param Pointer to the Packet to modify
 *  \param Pointer to the data
 *  \param Length of the data
 */
inline int PacketSetData(Packet *p, const uint8_t *pktdata, uint32_t pktlen)
{
    SET_PKT_LEN(p, pktlen);
    if (unlikely(!pktdata)) {
        return -1;
    }
    // ext_pkt cannot be const (because we sometimes copy)
    p->ext_pkt = (uint8_t *) pktdata;
    p->flags |= PKT_ZERO_COPY;

    return 0;
}

const char *PktSrcToString(enum PktSrcEnum pkt_src)
{
    const char *pkt_src_str = NULL;
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
        case PKT_SRC_STREAM_TCP_DETECTLOG_FLUSH:
            pkt_src_str = "stream (detect/log)";
            break;
        case PKT_SRC_FFR:
            pkt_src_str = "stream (flow timeout)";
            break;
        case PKT_SRC_DECODER_GENEVE:
            pkt_src_str = "geneve encapsulation";
            break;
        case PKT_SRC_DECODER_VXLAN:
            pkt_src_str = "vxlan encapsulation";
            break;
        case PKT_SRC_DETECT_RELOAD_FLUSH:
            pkt_src_str = "detect reload flush";
            break;
        case PKT_SRC_CAPTURE_TIMEOUT:
            pkt_src_str = "capture timeout flush";
            break;
        case PKT_SRC_SHUTDOWN_FLUSH:
            pkt_src_str = "shutdown flush";
            break;
    }
    DEBUG_VALIDATE_BUG_ON(pkt_src_str == NULL);
    return pkt_src_str;
}

const char *PacketDropReasonToString(enum PacketDropReason r)
{
    switch (r) {
        case PKT_DROP_REASON_DECODE_ERROR:
            return "decode error";
        case PKT_DROP_REASON_DEFRAG_ERROR:
            return "defrag error";
        case PKT_DROP_REASON_DEFRAG_MEMCAP:
            return "defrag memcap";
        case PKT_DROP_REASON_FLOW_MEMCAP:
            return "flow memcap";
        case PKT_DROP_REASON_FLOW_DROP:
            return "flow drop";
        case PKT_DROP_REASON_STREAM_ERROR:
            return "stream error";
        case PKT_DROP_REASON_STREAM_MEMCAP:
            return "stream memcap";
        case PKT_DROP_REASON_STREAM_MIDSTREAM:
            return "stream midstream";
        case PKT_DROP_REASON_STREAM_REASSEMBLY:
            return "stream reassembly";
        case PKT_DROP_REASON_APPLAYER_ERROR:
            return "applayer error";
        case PKT_DROP_REASON_APPLAYER_MEMCAP:
            return "applayer memcap";
        case PKT_DROP_REASON_RULES:
            return "rules";
        case PKT_DROP_REASON_RULES_THRESHOLD:
            return "threshold detection_filter";
        case PKT_DROP_REASON_NFQ_ERROR:
            return "nfq error";
        case PKT_DROP_REASON_INNER_PACKET:
            return "tunnel packet drop";
        case PKT_DROP_REASON_NOT_SET:
        case PKT_DROP_REASON_MAX:
            return NULL;
    }
    return NULL;
}

static const char *PacketDropReasonToJsonString(enum PacketDropReason r)
{
    switch (r) {
        case PKT_DROP_REASON_DECODE_ERROR:
            return "ips.drop_reason.decode_error";
        case PKT_DROP_REASON_DEFRAG_ERROR:
            return "ips.drop_reason.defrag_error";
        case PKT_DROP_REASON_DEFRAG_MEMCAP:
            return "ips.drop_reason.defrag_memcap";
        case PKT_DROP_REASON_FLOW_MEMCAP:
            return "ips.drop_reason.flow_memcap";
        case PKT_DROP_REASON_FLOW_DROP:
            return "ips.drop_reason.flow_drop";
        case PKT_DROP_REASON_STREAM_ERROR:
            return "ips.drop_reason.stream_error";
        case PKT_DROP_REASON_STREAM_MEMCAP:
            return "ips.drop_reason.stream_memcap";
        case PKT_DROP_REASON_STREAM_MIDSTREAM:
            return "ips.drop_reason.stream_midstream";
        case PKT_DROP_REASON_STREAM_REASSEMBLY:
            return "ips.drop_reason.stream_reassembly";
        case PKT_DROP_REASON_APPLAYER_ERROR:
            return "ips.drop_reason.applayer_error";
        case PKT_DROP_REASON_APPLAYER_MEMCAP:
            return "ips.drop_reason.applayer_memcap";
        case PKT_DROP_REASON_RULES:
            return "ips.drop_reason.rules";
        case PKT_DROP_REASON_RULES_THRESHOLD:
            return "ips.drop_reason.threshold_detection_filter";
        case PKT_DROP_REASON_NFQ_ERROR:
            return "ips.drop_reason.nfq_error";
        case PKT_DROP_REASON_INNER_PACKET:
            return "ips.drop_reason.tunnel_packet_drop";
        case PKT_DROP_REASON_NOT_SET:
        case PKT_DROP_REASON_MAX:
            return NULL;
    }
    return NULL;
}

typedef struct CaptureStats_ {
    uint16_t counter_ips_accepted;
    uint16_t counter_ips_blocked;
    uint16_t counter_ips_rejected;
    uint16_t counter_ips_replaced;

    uint16_t counter_drop_reason[PKT_DROP_REASON_MAX];
} CaptureStats;

thread_local CaptureStats t_capture_stats;

void CaptureStatsUpdate(ThreadVars *tv, const Packet *p)
{
    if (!EngineModeIsIPS() || PKT_IS_PSEUDOPKT(p))
        return;

    CaptureStats *s = &t_capture_stats;
    if (unlikely(PacketCheckAction(p, ACTION_REJECT_ANY))) {
        StatsIncr(tv, s->counter_ips_rejected);
    } else if (unlikely(PacketCheckAction(p, ACTION_DROP))) {
        StatsIncr(tv, s->counter_ips_blocked);
    } else if (unlikely(p->flags & PKT_STREAM_MODIFIED)) {
        StatsIncr(tv, s->counter_ips_replaced);
    } else {
        StatsIncr(tv, s->counter_ips_accepted);
    }
    if (p->drop_reason != PKT_DROP_REASON_NOT_SET) {
        StatsIncr(tv, s->counter_drop_reason[p->drop_reason]);
    }
}

void CaptureStatsSetup(ThreadVars *tv)
{
    if (EngineModeIsIPS()) {
        CaptureStats *s = &t_capture_stats;
        s->counter_ips_accepted = StatsRegisterCounter("ips.accepted", tv);
        s->counter_ips_blocked = StatsRegisterCounter("ips.blocked", tv);
        s->counter_ips_rejected = StatsRegisterCounter("ips.rejected", tv);
        s->counter_ips_replaced = StatsRegisterCounter("ips.replaced", tv);
        for (int i = PKT_DROP_REASON_NOT_SET; i < PKT_DROP_REASON_MAX; i++) {
            const char *name = PacketDropReasonToJsonString(i);
            if (name != NULL)
                s->counter_drop_reason[i] = StatsRegisterCounter(name, tv);
        }
    }
}

void DecodeGlobalConfig(void)
{
    DecodeTeredoConfig();
    DecodeGeneveConfig();
    DecodeVXLANConfig();
    DecodeERSPANConfig();
    intmax_t value = 0;
    if (ConfGetInt("decoder.max-layers", &value) == 1) {
        if (value < 0 || value > UINT8_MAX) {
            SCLogWarning("Invalid value for decoder.max-layers");
        } else {
            decoder_max_layers = (uint8_t)value;
        }
    }
    PacketAlertGetMaxConfig();
}

void PacketAlertGetMaxConfig(void)
{
    intmax_t max = 0;
    if (ConfGetInt("packet-alert-max", &max) == 1) {
        if (max <= 0 || max > UINT8_MAX) {
            SCLogWarning("Invalid value for packet-alert-max, default value set instead");
        } else {
            packet_alert_max = (uint16_t)max;
        }
    }
    SCLogDebug("detect->packet_alert_max set to %d", packet_alert_max);
}

/**
 * @}
 */
