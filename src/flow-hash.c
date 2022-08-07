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
 *  \file
 *
 *  \author Victor Julien <victor@inliniac.net>
 *  \author Pablo Rincon Crespo <pablo.rincon.crespo@gmail.com>
 *
 *  Flow Hashing functions.
 */

#include "suricata-common.h"
#include "threads.h"

#include "decode.h"
#include "detect-engine-state.h"

#include "flow.h"
#include "flow-hash.h"
#include "flow-util.h"
#include "flow-private.h"
#include "flow-manager.h"
#include "flow-storage.h"
#include "flow-timeout.h"
#include "flow-spare-pool.h"
#include "app-layer-parser.h"

#include "util-time.h"
#include "util-debug.h"

#include "util-hash-lookup3.h"

#include "conf.h"
#include "output.h"
#include "output-flow.h"
#include "stream-tcp.h"
#include "util-exception-policy.h"

extern TcpStreamCnf stream_config;


FlowBucket *flow_hash;
SC_ATOMIC_EXTERN(unsigned int, flow_prune_idx);
SC_ATOMIC_EXTERN(unsigned int, flow_flags);

static Flow *FlowGetUsedFlow(ThreadVars *tv, DecodeThreadVars *dtv, const struct timeval *ts);

/** \brief compare two raw ipv6 addrs
 *
 *  \note we don't care about the real ipv6 ip's, this is just
 *        to consistently fill the FlowHashKey6 struct, without all
 *        the SCNtohl calls.
 *
 *  \warning do not use elsewhere unless you know what you're doing.
 *           detect-engine-address-ipv6.c's AddressIPv6GtU32 is likely
 *           what you are looking for.
 */
static inline int FlowHashRawAddressIPv6GtU32(const uint32_t *a, const uint32_t *b)
{
    for (int i = 0; i < 4; i++) {
        if (a[i] > b[i])
            return 1;
        if (a[i] < b[i])
            break;
    }

    return 0;
}

typedef struct FlowHashKey4_ {
    union {
        struct {
            uint32_t addrs[2];
            uint16_t ports[2];
            uint16_t proto; /**< u16 so proto and recur add up to u32 */
            uint16_t recur; /**< u16 so proto and recur add up to u32 */
            uint16_t vlan_id[VLAN_MAX_LAYERS];
            uint16_t pad[1];
        };
        const uint32_t u32[6];
    };
} FlowHashKey4;

typedef struct FlowHashKey6_ {
    union {
        struct {
            uint32_t src[4], dst[4];
            uint16_t ports[2];
            uint16_t proto; /**< u16 so proto and recur add up to u32 */
            uint16_t recur; /**< u16 so proto and recur add up to u32 */
            uint16_t vlan_id[VLAN_MAX_LAYERS];
            uint16_t pad[1];
        };
        const uint32_t u32[12];
    };
} FlowHashKey6;

/* calculate the hash key for this packet
 *
 * we're using:
 *  hash_rand -- set at init time
 *  source port
 *  destination port
 *  source address
 *  destination address
 *  recursion level -- for tunnels, make sure different tunnel layers can
 *                     never get mixed up.
 *
 *  For ICMP we only consider UNREACHABLE errors atm.
 */
static inline uint32_t FlowGetHash(const Packet *p)
{
    uint32_t hash = 0;

    if (p->ip4h != NULL) {
        if (p->tcph != NULL || p->udph != NULL) {
            FlowHashKey4 fhk = { .pad[0] = 0 };

            int ai = (p->src.addr_data32[0] > p->dst.addr_data32[0]);
            fhk.addrs[1-ai] = p->src.addr_data32[0];
            fhk.addrs[ai] = p->dst.addr_data32[0];

            const int pi = (p->sp > p->dp);
            fhk.ports[1-pi] = p->sp;
            fhk.ports[pi] = p->dp;

            fhk.proto = (uint16_t)p->proto;
            fhk.recur = (uint16_t)p->recursion_level;
            /* g_vlan_mask sets the vlan_ids to 0 if vlan.use-for-tracking
             * is disabled. */
            fhk.vlan_id[0] = p->vlan_id[0] & g_vlan_mask;
            fhk.vlan_id[1] = p->vlan_id[1] & g_vlan_mask;
            fhk.vlan_id[2] = p->vlan_id[2] & g_vlan_mask;

            hash = hashword(fhk.u32, sizeof(fhk.u32) / sizeof(uint32_t), flow_config.hash_rand);

        } else if (ICMPV4_DEST_UNREACH_IS_VALID(p)) {
            uint32_t psrc = IPV4_GET_RAW_IPSRC_U32(ICMPV4_GET_EMB_IPV4(p));
            uint32_t pdst = IPV4_GET_RAW_IPDST_U32(ICMPV4_GET_EMB_IPV4(p));
            FlowHashKey4 fhk = { .pad[0] = 0 };

            const int ai = (psrc > pdst);
            fhk.addrs[1-ai] = psrc;
            fhk.addrs[ai] = pdst;

            const int pi = (p->icmpv4vars.emb_sport > p->icmpv4vars.emb_dport);
            fhk.ports[1-pi] = p->icmpv4vars.emb_sport;
            fhk.ports[pi] = p->icmpv4vars.emb_dport;

            fhk.proto = (uint16_t)ICMPV4_GET_EMB_PROTO(p);
            fhk.recur = (uint16_t)p->recursion_level;
            fhk.vlan_id[0] = p->vlan_id[0] & g_vlan_mask;
            fhk.vlan_id[1] = p->vlan_id[1] & g_vlan_mask;
            fhk.vlan_id[2] = p->vlan_id[2] & g_vlan_mask;

            hash = hashword(fhk.u32, sizeof(fhk.u32) / sizeof(uint32_t), flow_config.hash_rand);

        } else {
            FlowHashKey4 fhk = { .pad[0] = 0 };
            const int ai = (p->src.addr_data32[0] > p->dst.addr_data32[0]);
            fhk.addrs[1-ai] = p->src.addr_data32[0];
            fhk.addrs[ai] = p->dst.addr_data32[0];
            fhk.ports[0] = 0xfeed;
            fhk.ports[1] = 0xbeef;
            fhk.proto = (uint16_t)p->proto;
            fhk.recur = (uint16_t)p->recursion_level;
            fhk.vlan_id[0] = p->vlan_id[0] & g_vlan_mask;
            fhk.vlan_id[1] = p->vlan_id[1] & g_vlan_mask;
            fhk.vlan_id[2] = p->vlan_id[2] & g_vlan_mask;

            hash = hashword(fhk.u32, sizeof(fhk.u32) / sizeof(uint32_t), flow_config.hash_rand);
        }
    } else if (p->ip6h != NULL) {
        FlowHashKey6 fhk = { .pad[0] = 0 };
        if (FlowHashRawAddressIPv6GtU32(p->src.addr_data32, p->dst.addr_data32)) {
            fhk.src[0] = p->src.addr_data32[0];
            fhk.src[1] = p->src.addr_data32[1];
            fhk.src[2] = p->src.addr_data32[2];
            fhk.src[3] = p->src.addr_data32[3];
            fhk.dst[0] = p->dst.addr_data32[0];
            fhk.dst[1] = p->dst.addr_data32[1];
            fhk.dst[2] = p->dst.addr_data32[2];
            fhk.dst[3] = p->dst.addr_data32[3];
        } else {
            fhk.src[0] = p->dst.addr_data32[0];
            fhk.src[1] = p->dst.addr_data32[1];
            fhk.src[2] = p->dst.addr_data32[2];
            fhk.src[3] = p->dst.addr_data32[3];
            fhk.dst[0] = p->src.addr_data32[0];
            fhk.dst[1] = p->src.addr_data32[1];
            fhk.dst[2] = p->src.addr_data32[2];
            fhk.dst[3] = p->src.addr_data32[3];
        }

        const int pi = (p->sp > p->dp);
        fhk.ports[1-pi] = p->sp;
        fhk.ports[pi] = p->dp;
        fhk.proto = (uint16_t)p->proto;
        fhk.recur = (uint16_t)p->recursion_level;
        fhk.vlan_id[0] = p->vlan_id[0] & g_vlan_mask;
        fhk.vlan_id[1] = p->vlan_id[1] & g_vlan_mask;
        fhk.vlan_id[2] = p->vlan_id[2] & g_vlan_mask;

        hash = hashword(fhk.u32, sizeof(fhk.u32) / sizeof(uint32_t), flow_config.hash_rand);
    }

    return hash;
}

/**
 * Basic hashing function for FlowKey
 *
 * \note Function only used for bypass and TCP or UDP flows
 *
 * \note this is only used at start to create Flow from pinned maps
 * so fairness is not an issue
 */
uint32_t FlowKeyGetHash(FlowKey *fk)
{
    uint32_t hash = 0;

    if (fk->src.family == AF_INET) {
        FlowHashKey4 fhk;
        int ai = (fk->src.address.address_un_data32[0] > fk->dst.address.address_un_data32[0]);
        fhk.addrs[1-ai] = fk->src.address.address_un_data32[0];
        fhk.addrs[ai] = fk->dst.address.address_un_data32[0];

        const int pi = (fk->sp > fk->dp);
        fhk.ports[1-pi] = fk->sp;
        fhk.ports[pi] = fk->dp;

        fhk.proto = (uint16_t)fk->proto;
        fhk.recur = (uint16_t)fk->recursion_level;
        fhk.vlan_id[0] = fk->vlan_id[0] & g_vlan_mask;
        fhk.vlan_id[1] = fk->vlan_id[1] & g_vlan_mask;
        fhk.vlan_id[2] = fk->vlan_id[2] & g_vlan_mask;

        hash = hashword(fhk.u32, sizeof(fhk.u32) / sizeof(uint32_t), flow_config.hash_rand);
    } else {
        FlowHashKey6 fhk;
        if (FlowHashRawAddressIPv6GtU32(fk->src.address.address_un_data32,
                    fk->dst.address.address_un_data32)) {
            fhk.src[0] = fk->src.address.address_un_data32[0];
            fhk.src[1] = fk->src.address.address_un_data32[1];
            fhk.src[2] = fk->src.address.address_un_data32[2];
            fhk.src[3] = fk->src.address.address_un_data32[3];
            fhk.dst[0] = fk->dst.address.address_un_data32[0];
            fhk.dst[1] = fk->dst.address.address_un_data32[1];
            fhk.dst[2] = fk->dst.address.address_un_data32[2];
            fhk.dst[3] = fk->dst.address.address_un_data32[3];
        } else {
            fhk.src[0] = fk->dst.address.address_un_data32[0];
            fhk.src[1] = fk->dst.address.address_un_data32[1];
            fhk.src[2] = fk->dst.address.address_un_data32[2];
            fhk.src[3] = fk->dst.address.address_un_data32[3];
            fhk.dst[0] = fk->src.address.address_un_data32[0];
            fhk.dst[1] = fk->src.address.address_un_data32[1];
            fhk.dst[2] = fk->src.address.address_un_data32[2];
            fhk.dst[3] = fk->src.address.address_un_data32[3];
        }

        const int pi = (fk->sp > fk->dp);
        fhk.ports[1-pi] = fk->sp;
        fhk.ports[pi] = fk->dp;
        fhk.proto = (uint16_t)fk->proto;
        fhk.recur = (uint16_t)fk->recursion_level;
        fhk.vlan_id[0] = fk->vlan_id[0] & g_vlan_mask;
        fhk.vlan_id[1] = fk->vlan_id[1] & g_vlan_mask;
        fhk.vlan_id[2] = fk->vlan_id[2] & g_vlan_mask;

        hash = hashword(fhk.u32, sizeof(fhk.u32) / sizeof(uint32_t), flow_config.hash_rand);
    }
    return hash;
}

static inline bool CmpAddrs(const uint32_t addr1[4], const uint32_t addr2[4])
{
    return addr1[0] == addr2[0] && addr1[1] == addr2[1] &&
           addr1[2] == addr2[2] && addr1[3] == addr2[3];
}

static inline bool CmpAddrsAndPorts(const uint32_t src1[4],
    const uint32_t dst1[4], Port src_port1, Port dst_port1,
    const uint32_t src2[4], const uint32_t dst2[4], Port src_port2,
    Port dst_port2)
{
    /* Compare the source and destination addresses. If they are not equal,
     * compare the first source address with the second destination address,
     * and vice versa. Likewise for ports. */
    return (CmpAddrs(src1, src2) && CmpAddrs(dst1, dst2) &&
            src_port1 == src_port2 && dst_port1 == dst_port2) ||
           (CmpAddrs(src1, dst2) && CmpAddrs(dst1, src2) &&
            src_port1 == dst_port2 && dst_port1 == src_port2);
}

static inline bool CmpVlanIds(
        const uint16_t vlan_id1[VLAN_MAX_LAYERS], const uint16_t vlan_id2[VLAN_MAX_LAYERS])
{
    return ((vlan_id1[0] ^ vlan_id2[0]) & g_vlan_mask) == 0 &&
           ((vlan_id1[1] ^ vlan_id2[1]) & g_vlan_mask) == 0 &&
           ((vlan_id1[2] ^ vlan_id2[2]) & g_vlan_mask) == 0;
}

/* Since two or more flows can have the same hash key, we need to compare
 * the flow with the current packet or flow key. */
static inline bool CmpFlowPacket(const Flow *f, const Packet *p)
{
    const uint32_t *f_src = f->src.address.address_un_data32;
    const uint32_t *f_dst = f->dst.address.address_un_data32;
    const uint32_t *p_src = p->src.address.address_un_data32;
    const uint32_t *p_dst = p->dst.address.address_un_data32;
    return CmpAddrsAndPorts(f_src, f_dst, f->sp, f->dp, p_src, p_dst, p->sp,
                            p->dp) && f->proto == p->proto &&
            f->recursion_level == p->recursion_level &&
            CmpVlanIds(f->vlan_id, p->vlan_id);
}

static inline bool CmpFlowKey(const Flow *f, const FlowKey *k)
{
    const uint32_t *f_src = f->src.address.address_un_data32;
    const uint32_t *f_dst = f->dst.address.address_un_data32;
    const uint32_t *k_src = k->src.address.address_un_data32;
    const uint32_t *k_dst = k->dst.address.address_un_data32;
    return CmpAddrsAndPorts(f_src, f_dst, f->sp, f->dp, k_src, k_dst, k->sp,
                            k->dp) && f->proto == k->proto &&
            f->recursion_level == k->recursion_level &&
            CmpVlanIds(f->vlan_id, k->vlan_id);
}

static inline bool CmpAddrsAndICMPTypes(const uint32_t src1[4],
    const uint32_t dst1[4], uint8_t icmp_s_type1, uint8_t icmp_d_type1,
    const uint32_t src2[4], const uint32_t dst2[4], uint8_t icmp_s_type2,
    uint8_t icmp_d_type2)
{
    /* Compare the source and destination addresses. If they are not equal,
     * compare the first source address with the second destination address,
     * and vice versa. Likewise for icmp types. */
    return (CmpAddrs(src1, src2) && CmpAddrs(dst1, dst2) &&
            icmp_s_type1 == icmp_s_type2 && icmp_d_type1 == icmp_d_type2) ||
           (CmpAddrs(src1, dst2) && CmpAddrs(dst1, src2) &&
            icmp_s_type1 == icmp_d_type2 && icmp_d_type1 == icmp_s_type2);
}

static inline bool CmpFlowICMPPacket(const Flow *f, const Packet *p)
{
    const uint32_t *f_src = f->src.address.address_un_data32;
    const uint32_t *f_dst = f->dst.address.address_un_data32;
    const uint32_t *p_src = p->src.address.address_un_data32;
    const uint32_t *p_dst = p->dst.address.address_un_data32;
    return CmpAddrsAndICMPTypes(f_src, f_dst, f->icmp_s.type,
                f->icmp_d.type, p_src, p_dst, p->icmp_s.type, p->icmp_d.type) &&
            f->proto == p->proto && f->recursion_level == p->recursion_level &&
            CmpVlanIds(f->vlan_id, p->vlan_id);
}

/**
 *  \brief See if a ICMP packet belongs to a flow by comparing the embedded
 *         packet in the ICMP error packet to the flow.
 *
 *  \param f flow
 *  \param p ICMP packet
 *
 *  \retval 1 match
 *  \retval 0 no match
 */
static inline int FlowCompareICMPv4(Flow *f, const Packet *p)
{
    if (ICMPV4_DEST_UNREACH_IS_VALID(p)) {
        /* first check the direction of the flow, in other words, the client ->
         * server direction as it's most likely the ICMP error will be a
         * response to the clients traffic */
        if ((f->src.addr_data32[0] == IPV4_GET_RAW_IPSRC_U32(ICMPV4_GET_EMB_IPV4(p))) &&
                (f->dst.addr_data32[0] == IPV4_GET_RAW_IPDST_U32(ICMPV4_GET_EMB_IPV4(p))) &&
                f->sp == p->icmpv4vars.emb_sport && f->dp == p->icmpv4vars.emb_dport &&
                f->proto == ICMPV4_GET_EMB_PROTO(p) && f->recursion_level == p->recursion_level &&
                CmpVlanIds(f->vlan_id, p->vlan_id)) {
            return 1;

        /* check the less likely case where the ICMP error was a response to
         * a packet from the server. */
        } else if ((f->dst.addr_data32[0] == IPV4_GET_RAW_IPSRC_U32(ICMPV4_GET_EMB_IPV4(p))) &&
                   (f->src.addr_data32[0] == IPV4_GET_RAW_IPDST_U32(ICMPV4_GET_EMB_IPV4(p))) &&
                   f->dp == p->icmpv4vars.emb_sport && f->sp == p->icmpv4vars.emb_dport &&
                   f->proto == ICMPV4_GET_EMB_PROTO(p) &&
                   f->recursion_level == p->recursion_level && CmpVlanIds(f->vlan_id, p->vlan_id)) {
            return 1;
        }

        /* no match, fall through */
    } else {
        /* just treat ICMP as a normal proto for now */
        return CmpFlowICMPPacket(f, p);
    }

    return 0;
}

/**
 *  \brief See if a IP-ESP packet belongs to a flow by comparing the SPI
 *
 *  \param f flow
 *  \param p ESP packet
 *
 *  \retval 1 match
 *  \retval 0 no match
 */
static inline int FlowCompareESP(Flow *f, const Packet *p)
{
    const uint32_t *f_src = f->src.address.address_un_data32;
    const uint32_t *f_dst = f->dst.address.address_un_data32;
    const uint32_t *p_src = p->src.address.address_un_data32;
    const uint32_t *p_dst = p->dst.address.address_un_data32;

    return CmpAddrs(f_src, p_src) && CmpAddrs(f_dst, p_dst) && f->proto == p->proto &&
           f->recursion_level == p->recursion_level && CmpVlanIds(f->vlan_id, p->vlan_id) &&
           f->esp.spi == ESP_GET_SPI(p);
}

void FlowSetupPacket(Packet *p)
{
    p->flags |= PKT_WANTS_FLOW;
    p->flow_hash = FlowGetHash(p);
}

static inline int FlowCompare(Flow *f, const Packet *p)
{
    if (p->proto == IPPROTO_ICMP) {
        return FlowCompareICMPv4(f, p);
    } else if (p->proto == IPPROTO_ESP) {
        return FlowCompareESP(f, p);
    } else {
        return CmpFlowPacket(f, p);
    }
}

/**
 *  \brief Check if we should create a flow based on a packet
 *
 *  We use this check to filter out flow creation based on:
 *  - ICMP error messages
 *  - TCP flags (emergency mode only)
 *
 *  \param p packet
 *  \retval 1 true
 *  \retval 0 false
 */
static inline int FlowCreateCheck(const Packet *p, const bool emerg)
{
    /* if we're in emergency mode, don't try to create a flow for a TCP
     * that is not a TCP SYN packet. */
    if (emerg) {
        if (PKT_IS_TCP(p)) {
            if (p->tcph->th_flags == TH_SYN || !stream_config.midstream) {
                ;
            } else {
                return 0;
            }
        }
    }

    if (PKT_IS_ICMPV4(p)) {
        if (ICMPV4_IS_ERROR_MSG(p)) {
            return 0;
        }
    }

    return 1;
}

static inline void FlowUpdateCounter(ThreadVars *tv, DecodeThreadVars *dtv,
        uint8_t proto)
{
#ifdef UNITTESTS
    if (tv && dtv) {
#endif
        StatsIncr(tv, dtv->counter_flow_total);
        StatsIncr(tv, dtv->counter_flow_active);
        switch (proto){
            case IPPROTO_UDP:
                StatsIncr(tv, dtv->counter_flow_udp);
                break;
            case IPPROTO_TCP:
                StatsIncr(tv, dtv->counter_flow_tcp);
                break;
            case IPPROTO_ICMP:
                StatsIncr(tv, dtv->counter_flow_icmp4);
                break;
            case IPPROTO_ICMPV6:
                StatsIncr(tv, dtv->counter_flow_icmp6);
                break;
        }
#ifdef UNITTESTS
    }
#endif
}

/** \internal
 *  \brief try to fetch a new set of flows from the master flow pool.
 *
 *  If in emergency mode, do this only once a second at max to avoid trying
 *  to synchronise per packet in the worse case. */
static inline Flow *FlowSpareSync(ThreadVars *tv, FlowLookupStruct *fls,
        const Packet *p, const bool emerg)
{
    Flow *f = NULL;
    bool spare_sync = false;
    if (emerg) {
        if ((uint32_t)p->ts.tv_sec > fls->emerg_spare_sync_stamp) {
            fls->spare_queue = FlowSpareGetFromPool(); /* local empty, (re)populate and try again */
            spare_sync = true;
            f = FlowQueuePrivateGetFromTop(&fls->spare_queue);
            if (f == NULL) {
                /* wait till next full sec before retrying */
                fls->emerg_spare_sync_stamp = (uint32_t)p->ts.tv_sec;
            }
        }
    } else {
        fls->spare_queue = FlowSpareGetFromPool(); /* local empty, (re)populate and try again */
        f = FlowQueuePrivateGetFromTop(&fls->spare_queue);
        spare_sync = true;
    }
#ifdef UNITTESTS
    if (tv && fls->dtv) {
#endif
        if (spare_sync) {
            if (f != NULL) {
                StatsAddUI64(tv, fls->dtv->counter_flow_spare_sync_avg, fls->spare_queue.len+1);
                if (fls->spare_queue.len < 99) {
                    StatsIncr(tv, fls->dtv->counter_flow_spare_sync_incomplete);
                }
            } else if (fls->spare_queue.len == 0) {
                StatsIncr(tv, fls->dtv->counter_flow_spare_sync_empty);
            }
            StatsIncr(tv, fls->dtv->counter_flow_spare_sync);
        }
#ifdef UNITTESTS
    }
#endif
    return f;
}

static inline void NoFlowHandleIPS(Packet *p)
{
    ExceptionPolicyApply(p, flow_config.memcap_policy, PKT_DROP_REASON_FLOW_MEMCAP);
}

/**
 *  \brief Get a new flow
 *
 *  Get a new flow. We're checking memcap first and will try to make room
 *  if the memcap is reached.
 *
 *  \param tv thread vars
 *  \param fls lookup support vars
 *
 *  \retval f *LOCKED* flow on succes, NULL on error.
 */
static Flow *FlowGetNew(ThreadVars *tv, FlowLookupStruct *fls, Packet *p)
{
    const bool emerg = ((SC_ATOMIC_GET(flow_flags) & FLOW_EMERGENCY) != 0);
#ifdef DEBUG
    if (g_eps_flow_memcap != UINT64_MAX && g_eps_flow_memcap == p->pcap_cnt) {
        return NULL;
    }
#endif
    if (FlowCreateCheck(p, emerg) == 0) {
        return NULL;
    }

    /* get a flow from the spare queue */
    Flow *f = FlowQueuePrivateGetFromTop(&fls->spare_queue);
    if (f == NULL) {
        f = FlowSpareSync(tv, fls, p, emerg);
    }
    if (f == NULL) {
        /* If we reached the max memcap, we get a used flow */
        if (!(FLOW_CHECK_MEMCAP(sizeof(Flow) + FlowStorageSize()))) {
            /* declare state of emergency */
            if (!(SC_ATOMIC_GET(flow_flags) & FLOW_EMERGENCY)) {
                SC_ATOMIC_OR(flow_flags, FLOW_EMERGENCY);
                FlowTimeoutsEmergency();
                FlowWakeupFlowManagerThread();
            }

            f = FlowGetUsedFlow(tv, fls->dtv, &p->ts);
            if (f == NULL) {
                NoFlowHandleIPS(p);
                return NULL;
            }
#ifdef UNITTESTS
            if (tv != NULL && fls->dtv != NULL) {
#endif
                StatsIncr(tv, fls->dtv->counter_flow_get_used);
#ifdef UNITTESTS
            }
#endif
            /* flow is still locked from FlowGetUsedFlow() */
            FlowUpdateCounter(tv, fls->dtv, p->proto);
            return f;
        }

        /* now see if we can alloc a new flow */
        f = FlowAlloc();
        if (f == NULL) {
#ifdef UNITTESTS
            if (tv != NULL && fls->dtv != NULL) {
#endif
                StatsIncr(tv, fls->dtv->counter_flow_memcap);
#ifdef UNITTESTS
            }
#endif
            NoFlowHandleIPS(p);
            return NULL;
        }

        /* flow is initialized but *unlocked* */
    } else {
        /* flow has been recycled before it went into the spare queue */

        /* flow is initialized (recylced) but *unlocked* */
    }

    FLOWLOCK_WRLOCK(f);
    FlowUpdateCounter(tv, fls->dtv, p->proto);
    return f;
}

static Flow *TcpReuseReplace(ThreadVars *tv, FlowLookupStruct *fls, FlowBucket *fb, Flow *old_f,
        const uint32_t hash, Packet *p)
{
#ifdef UNITTESTS
    if (tv != NULL && fls->dtv != NULL) {
#endif
        StatsIncr(tv, fls->dtv->counter_flow_tcp_reuse);
#ifdef UNITTESTS
    }
#endif
    /* tag flow as reused so future lookups won't find it */
    old_f->flags |= FLOW_TCP_REUSED;
    /* time out immediately */
    old_f->timeout_at = 0;
    /* get some settings that we move over to the new flow */
    FlowThreadId thread_id[2] = { old_f->thread_id[0], old_f->thread_id[1] };

    /* flow is unlocked by caller */

    /* Get a new flow. It will be either a locked flow or NULL */
    Flow *f = FlowGetNew(tv, fls, p);
    if (f == NULL) {
        return NULL;
    }

    /* put at the start of the list */
    f->next = fb->head;
    fb->head = f;

    /* initialize and return */
    FlowInit(f, p);
    f->flow_hash = hash;
    f->fb = fb;
    FlowUpdateState(f, FLOW_STATE_NEW);

    f->thread_id[0] = thread_id[0];
    f->thread_id[1] = thread_id[1];
    return f;
}

static inline bool FlowBelongsToUs(const ThreadVars *tv, const Flow *f)
{
#ifdef UNITTESTS
    if (RunmodeIsUnittests()) {
        return true;
    }
#endif
    return f->thread_id[0] == tv->id;
}

static inline void MoveToWorkQueue(ThreadVars *tv, FlowLookupStruct *fls,
        FlowBucket *fb, Flow *f, Flow *prev_f)
{
    f->flow_end_flags |= FLOW_END_FLAG_TIMEOUT;

    /* remove from hash... */
    if (prev_f) {
        prev_f->next = f->next;
    }
    if (f == fb->head) {
        fb->head = f->next;
    }

    if (f->proto != IPPROTO_TCP || FlowBelongsToUs(tv, f)) { // TODO thread_id[] direction
        f->fb = NULL;
        f->next = NULL;
        FlowQueuePrivateAppendFlow(&fls->work_queue, f);
    } else {
        /* implied: TCP but our thread does not own it. So set it
         * aside for the Flow Manager to pick it up. */
        f->next = fb->evicted;
        fb->evicted = f;
        if (SC_ATOMIC_GET(f->fb->next_ts) != 0) {
            SC_ATOMIC_SET(f->fb->next_ts, 0);
        }
    }
}

static inline bool FlowIsTimedOut(const Flow *f, const uint32_t sec, const bool emerg)
{
    if (unlikely(f->timeout_at < sec)) {
        return true;
    } else if (unlikely(emerg)) {
        extern FlowProtoTimeout flow_timeouts_delta[FLOW_PROTO_MAX];

        int64_t timeout_at = f->timeout_at -
            FlowGetFlowTimeoutDirect(flow_timeouts_delta, f->flow_state, f->protomap);
        if ((int64_t)sec >= timeout_at)
            return true;
    }
    return false;
}

/** \brief Get Flow for packet
 *
 * Hash retrieval function for flows. Looks up the hash bucket containing the
 * flow pointer. Then compares the packet with the found flow to see if it is
 * the flow we need. If it isn't, walk the list until the right flow is found.
 *
 * If the flow is not found or the bucket was emtpy, a new flow is taken from
 * the spare pool. The pool will alloc new flows as long as we stay within our
 * memcap limit.
 *
 * The p->flow pointer is updated to point to the flow.
 *
 *  \param tv thread vars
 *  \param dtv decode thread vars (for flow log api thread data)
 *
 *  \retval f *LOCKED* flow or NULL
 */
Flow *FlowGetFlowFromHash(ThreadVars *tv, FlowLookupStruct *fls, Packet *p, Flow **dest)
{
    Flow *f = NULL;

    /* get our hash bucket and lock it */
    const uint32_t hash = p->flow_hash;
    FlowBucket *fb = &flow_hash[hash % flow_config.hash_size];
    FBLOCK_LOCK(fb);

    SCLogDebug("fb %p fb->head %p", fb, fb->head);

    /* see if the bucket already has a flow */
    if (fb->head == NULL) {
        f = FlowGetNew(tv, fls, p);
        if (f == NULL) {
            FBLOCK_UNLOCK(fb);
            return NULL;
        }

        /* flow is locked */
        fb->head = f;

        /* got one, now lock, initialize and return */
        FlowInit(f, p);
        f->flow_hash = hash;
        f->fb = fb;
        FlowUpdateState(f, FLOW_STATE_NEW);

        FlowReference(dest, f);

        FBLOCK_UNLOCK(fb);
        return f;
    }

    const bool emerg = (SC_ATOMIC_GET(flow_flags) & FLOW_EMERGENCY) != 0;
    const uint32_t fb_nextts = !emerg ? SC_ATOMIC_GET(fb->next_ts) : 0;
    /* ok, we have a flow in the bucket. Let's find out if it is our flow */
    Flow *prev_f = NULL; /* previous flow */
    f = fb->head;
    do {
        Flow *next_f = NULL;
        const bool timedout =
            (fb_nextts < (uint32_t)p->ts.tv_sec && FlowIsTimedOut(f, (uint32_t)p->ts.tv_sec, emerg));
        if (timedout) {
            FLOWLOCK_WRLOCK(f);
            if (likely(f->use_cnt == 0)) {
                next_f = f->next;
                MoveToWorkQueue(tv, fls, fb, f, prev_f);
                FLOWLOCK_UNLOCK(f);
                goto flow_removed;
            }
            FLOWLOCK_UNLOCK(f);
        } else if (FlowCompare(f, p) != 0) {
            FLOWLOCK_WRLOCK(f);
            /* found a matching flow that is not timed out */
            if (unlikely(TcpSessionPacketSsnReuse(p, f, f->protoctx) == 1)) {
                Flow *new_f = TcpReuseReplace(tv, fls, fb, f, hash, p);
                if (likely(f->use_cnt == 0)) {
                    if (prev_f == NULL) /* if we have no prev it means new_f is now our prev */
                        prev_f = new_f;
                    MoveToWorkQueue(tv, fls, fb, f, prev_f); /* evict old flow */
                }
                FLOWLOCK_UNLOCK(f); /* unlock old replaced flow */

                if (new_f == NULL) {
                    FBLOCK_UNLOCK(fb);
                    return NULL;
                }
                f = new_f;
            }
            FlowReference(dest, f);
            FBLOCK_UNLOCK(fb);
            return f; /* return w/o releasing flow lock */
        }
        /* unless we removed 'f', prev_f needs to point to
         * current 'f' when adding a new flow below. */
        prev_f = f;
        next_f = f->next;

flow_removed:
        if (next_f == NULL) {
            f = FlowGetNew(tv, fls, p);
            if (f == NULL) {
                FBLOCK_UNLOCK(fb);
                return NULL;
            }

            /* flow is locked */

            f->next = fb->head;
            fb->head = f;

            /* initialize and return */
            FlowInit(f, p);
            f->flow_hash = hash;
            f->fb = fb;
            FlowUpdateState(f, FLOW_STATE_NEW);
            FlowReference(dest, f);
            FBLOCK_UNLOCK(fb);
            return f;
        }
        f = next_f;
    } while (f != NULL);

    /* should be unreachable */
    BUG_ON(1);
    return NULL;
}

static inline int FlowCompareKey(Flow *f, FlowKey *key)
{
    if ((f->proto != IPPROTO_TCP) && (f->proto != IPPROTO_UDP))
        return 0;
    return CmpFlowKey(f, key);
}

/** \brief Look for existing Flow using a flow id value
 *
 * Hash retrieval function for flows. Looks up the hash bucket containing the
 * flow pointer. Then compares the packet with the found flow to see if it is
 * the flow we need. If it isn't, walk the list until the right flow is found.
 *
 *
 *  \param flow_id Flow ID of the flow to look for
 *  \retval f *LOCKED* flow or NULL
 */

Flow *FlowGetExistingFlowFromFlowId(int64_t flow_id)
{
    uint32_t hash = flow_id & 0x0000FFFF;
    /* get our hash bucket and lock it */
    FlowBucket *fb = &flow_hash[hash % flow_config.hash_size];
    FBLOCK_LOCK(fb);

    SCLogDebug("fb %p fb->head %p", fb, fb->head);

    /* return if the bucket don't have a flow */
    if (fb->head == NULL) {
        FBLOCK_UNLOCK(fb);
        return NULL;
    }

    /* ok, we have a flow in the bucket. Let's find out if it is our flow */
    Flow *f = fb->head;

    /* see if this is the flow we are looking for */
    if (FlowGetId(f) != flow_id) {
        while (f) {
            f = f->next;

            if (f == NULL) {
                FBLOCK_UNLOCK(fb);
                return NULL;
            }
            if (FlowGetId(f) != flow_id) {
                /* found our flow, lock & return */
                FLOWLOCK_WRLOCK(f);

                FBLOCK_UNLOCK(fb);
                return f;
            }
        }
    }

    /* lock & return */
    FLOWLOCK_WRLOCK(f);

    FBLOCK_UNLOCK(fb);
    return f;
}

/** \brief Get or create a Flow using a FlowKey
 *
 * Hash retrieval function for flows. Looks up the hash bucket containing the
 * flow pointer. Then compares the packet with the found flow to see if it is
 * the flow we need. If it isn't, walk the list until the right flow is found.
 * Return a new Flow if ever no Flow was found.
 *
 *
 *  \param key Pointer to FlowKey build using flow to look for
 *  \param ttime time to use for flow creation
 *  \param hash Value of the flow hash
 *  \retval f *LOCKED* flow or NULL
 */

Flow *FlowGetFromFlowKey(FlowKey *key, struct timespec *ttime, const uint32_t hash)
{
    Flow *f = FlowGetExistingFlowFromHash(key, hash);

    if (f != NULL) {
        return f;
    }
    /* TODO use spare pool */
    /* now see if we can alloc a new flow */
    f = FlowAlloc();
    if (f == NULL) {
        SCLogDebug("Can't get a spare flow at start");
        return NULL;
    }
    f->proto = key->proto;
    memcpy(&f->vlan_id[0], &key->vlan_id[0], sizeof(f->vlan_id));
    ;
    f->src.addr_data32[0] = key->src.addr_data32[0];
    f->src.addr_data32[1] = key->src.addr_data32[1];
    f->src.addr_data32[2] = key->src.addr_data32[2];
    f->src.addr_data32[3] = key->src.addr_data32[3];
    f->dst.addr_data32[0] = key->dst.addr_data32[0];
    f->dst.addr_data32[1] = key->dst.addr_data32[1];
    f->dst.addr_data32[2] = key->dst.addr_data32[2];
    f->dst.addr_data32[3] = key->dst.addr_data32[3];
    f->sp = key->sp;
    f->dp = key->dp;
    f->recursion_level = 0;
    f->flow_hash = hash;
    if (key->src.family == AF_INET) {
        f->flags |= FLOW_IPV4;
    } else if (key->src.family == AF_INET6) {
        f->flags |= FLOW_IPV6;
    }

    f->protomap = FlowGetProtoMapping(f->proto);
    /* set timestamp to now */
    f->startts.tv_sec = ttime->tv_sec;
    f->startts.tv_usec = ttime->tv_nsec * 1000;
    f->lastts = f->startts;

    FlowBucket *fb = &flow_hash[hash % flow_config.hash_size];
    FBLOCK_LOCK(fb);
    f->fb = fb;
    f->next = fb->head;
    fb->head = f;
    FLOWLOCK_WRLOCK(f);
    FBLOCK_UNLOCK(fb);
    return f;
}

/** \brief Look for existing Flow using a FlowKey
 *
 * Hash retrieval function for flows. Looks up the hash bucket containing the
 * flow pointer. Then compares the packet with the found flow to see if it is
 * the flow we need. If it isn't, walk the list until the right flow is found.
 *
 *
 *  \param key Pointer to FlowKey build using flow to look for
 *  \param hash Value of the flow hash
 *  \retval f *LOCKED* flow or NULL
 */
Flow *FlowGetExistingFlowFromHash(FlowKey *key, const uint32_t hash)
{
    /* get our hash bucket and lock it */
    FlowBucket *fb = &flow_hash[hash % flow_config.hash_size];
    FBLOCK_LOCK(fb);

    SCLogDebug("fb %p fb->head %p", fb, fb->head);

    /* return if the bucket don't have a flow */
    if (fb->head == NULL) {
        FBLOCK_UNLOCK(fb);
        return NULL;
    }

    /* ok, we have a flow in the bucket. Let's find out if it is our flow */
    Flow *f = fb->head;

    /* see if this is the flow we are looking for */
    if (FlowCompareKey(f, key) == 0) {
        while (f) {
            f = f->next;

            if (f == NULL) {
                FBLOCK_UNLOCK(fb);
                return NULL;
            }

            if (FlowCompareKey(f, key) != 0) {
                /* found our flow, lock & return */
                FLOWLOCK_WRLOCK(f);

                FBLOCK_UNLOCK(fb);
                return f;
            }
        }
    }

    /* lock & return */
    FLOWLOCK_WRLOCK(f);

    FBLOCK_UNLOCK(fb);
    return f;
}

#define FLOW_GET_NEW_TRIES 5

/* inline locking wrappers to make profiling easier */

static inline int GetUsedTryLockBucket(FlowBucket *fb)
{
    int r = FBLOCK_TRYLOCK(fb);
    return r;
}
static inline int GetUsedTryLockFlow(Flow *f)
{
    int r = FLOWLOCK_TRYWRLOCK(f);
    return r;
}
static inline uint32_t GetUsedAtomicUpdate(const uint32_t val)
{
    uint32_t r =  SC_ATOMIC_ADD(flow_prune_idx, val);
    return r;
}

/** \internal
 *  \brief check if flow has just seen an update.
 */
static inline bool StillAlive(const Flow *f, const struct timeval *ts)
{
    switch (f->flow_state) {
        case FLOW_STATE_NEW:
            if (ts->tv_sec - f->lastts.tv_sec <= 1) {
                return true;
            }
            break;
        case FLOW_STATE_ESTABLISHED:
            if (ts->tv_sec - f->lastts.tv_sec <= 5) {
                return true;
            }
            break;
        case FLOW_STATE_CLOSED:
            if (ts->tv_sec - f->lastts.tv_sec <= 3) {
                return true;
            }
            break;
        default:
            if (ts->tv_sec - f->lastts.tv_sec < 30) {
                return true;
            }
            break;
    }
    return false;
}

#ifdef UNITTESTS
    #define STATSADDUI64(cnt, value) \
        if (tv && dtv) { \
            StatsAddUI64(tv, dtv->cnt, (value)); \
        }
#else
    #define STATSADDUI64(cnt, value) \
        StatsAddUI64(tv, dtv->cnt, (value));
#endif

/** \internal
 *  \brief Get a flow from the hash directly.
 *
 *  Called in conditions where the spare queue is empty and memcap is reached.
 *
 *  Walks the hash until a flow can be freed. Timeouts are disregarded, use_cnt
 *  is adhered to. "flow_prune_idx" atomic int makes sure we don't start at the
 *  top each time since that would clear the top of the hash leading to longer
 *  and longer search times under high pressure (observed).
 *
 *  \param tv thread vars
 *  \param dtv decode thread vars (for flow log api thread data)
 *
 *  \retval f flow or NULL
 */
static Flow *FlowGetUsedFlow(ThreadVars *tv, DecodeThreadVars *dtv, const struct timeval *ts)
{
    uint32_t idx = GetUsedAtomicUpdate(FLOW_GET_NEW_TRIES) % flow_config.hash_size;
    uint32_t tried = 0;

    while (1) {
        if (tried++ > FLOW_GET_NEW_TRIES) {
            STATSADDUI64(counter_flow_get_used_eval, tried);
            break;
        }
        if (++idx >= flow_config.hash_size)
            idx = 0;

        FlowBucket *fb = &flow_hash[idx];

        if (SC_ATOMIC_GET(fb->next_ts) == INT_MAX)
            continue;

        if (GetUsedTryLockBucket(fb) != 0) {
            STATSADDUI64(counter_flow_get_used_eval_busy, 1);
            continue;
        }

        Flow *f = fb->head;
        if (f == NULL) {
            FBLOCK_UNLOCK(fb);
            continue;
        }

        if (GetUsedTryLockFlow(f) != 0) {
            STATSADDUI64(counter_flow_get_used_eval_busy, 1);
            FBLOCK_UNLOCK(fb);
            continue;
        }

        /** never prune a flow that is used by a packet or stream msg
         *  we are currently processing in one of the threads */
        if (f->use_cnt > 0) {
            STATSADDUI64(counter_flow_get_used_eval_busy, 1);
            FBLOCK_UNLOCK(fb);
            FLOWLOCK_UNLOCK(f);
            continue;
        }

        if (StillAlive(f, ts)) {
            STATSADDUI64(counter_flow_get_used_eval_reject, 1);
            FBLOCK_UNLOCK(fb);
            FLOWLOCK_UNLOCK(f);
            continue;
        }

        /* remove from the hash */
        fb->head = f->next;
        f->next = NULL;
        f->fb = NULL;
        FBLOCK_UNLOCK(fb);

        /* rest of the flags is updated on-demand in output */
        f->flow_end_flags |= FLOW_END_FLAG_FORCED;
        if (SC_ATOMIC_GET(flow_flags) & FLOW_EMERGENCY)
            f->flow_end_flags |= FLOW_END_FLAG_EMERGENCY;

        /* invoke flow log api */
#ifdef UNITTESTS
        if (dtv) {
#endif
            if (dtv->output_flow_thread_data) {
                (void)OutputFlowLog(tv, dtv->output_flow_thread_data, f);
            }
#ifdef UNITTESTS
        }
#endif

        FlowClearMemory(f, f->protomap);

        /* leave locked */

        STATSADDUI64(counter_flow_get_used_eval, tried);
        return f;
    }

    STATSADDUI64(counter_flow_get_used_failed, 1);
    return NULL;
}
