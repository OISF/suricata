/* Copyright (C) 2022 Open Information Security Foundation
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
 * \author Lukas Sismis <sismis@cesnet.cz>
 */

#include "util-dpdk-bypass.h"
#include "flow-hash.h"
#include "flow-storage.h"

#ifdef HAVE_DPDK

void PFMessageAddBypassInit(struct PFMessage *msg)
{
    msg->msg_type = PF_MESSAGE_BYPASS_ADD;
    msg->next_msg = NULL;
}

void PFMessageDeleteBypassInit(struct PFMessage *msg)
{
    msg->msg_type = PF_MESSAGE_BYPASS_SOFT_DELETE;
    msg->next_msg = NULL;
}

void PFMessageEvictBypassInit(struct PFMessage *msg)
{
    msg->msg_type = PF_MESSAGE_BYPASS_EVICT;
    msg->next_msg = NULL;
}

void PFMessageErrorFlowNotFoundBypassInit(struct PFMessage *msg)
{
    msg->msg_type = PF_MESSAGE_BYPASS_FLOW_NOT_FOUND;
    msg->next_msg = NULL;
}

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

static void FlowKeySetIpv4Address(Address *addr, uint32_t new_addr)
{
    addr->family = AF_INET;
    addr->family_padding = 0;
    addr->address.address_un_data32[0] = new_addr;
    addr->address.address_un_data32[1] = 0;
    addr->address.address_un_data32[2] = 0;
    addr->address.address_un_data32[3] = 0;
}

static void FlowKeySetIpv6Address(Address *addr, const uint32_t new_addr[4])
{
    addr->family = AF_INET6;
    addr->family_padding = 0;
    addr->address.address_un_data32[0] = new_addr[0];
    addr->address.address_un_data32[1] = new_addr[1];
    addr->address.address_un_data32[2] = new_addr[2];
    addr->address.address_un_data32[3] = new_addr[3];
}

static void FlowKeySwapIpv4Addresses(Address *addr1, Address *addr2)
{
    uint32_t addr = addr1->address.address_un_data32[0];
    addr1->address.address_un_data32[0] = addr1->address.address_un_data32[0];
    addr1->address.address_un_data32[0] = addr;
}

static void FlowKeySwapIpv6Addresses(Address *addr1, Address *addr2)
{
    uint32_t tmp_addr[4];

    tmp_addr[0] = addr1->address.address_un_data32[0];
    tmp_addr[1] = addr1->address.address_un_data32[1];
    tmp_addr[2] = addr1->address.address_un_data32[2];
    tmp_addr[3] = addr1->address.address_un_data32[3];

    addr1->address.address_un_data32[0] = addr2->address.address_un_data32[0];
    addr1->address.address_un_data32[1] = addr2->address.address_un_data32[1];
    addr1->address.address_un_data32[2] = addr2->address.address_un_data32[2];
    addr1->address.address_un_data32[3] = addr2->address.address_un_data32[3];

    addr2->address.address_un_data32[0] = tmp_addr[0];
    addr2->address.address_un_data32[1] = tmp_addr[1];
    addr2->address.address_un_data32[2] = tmp_addr[2];
    addr2->address.address_un_data32[3] = tmp_addr[3];
}

int FlowKeyInitFromFlow(FlowKey *fk, Flow *f)
{
    for (uint8_t i = 0; i < sizeof(fk->spare8) / sizeof(fk->spare8[0]); i++) {
        fk->spare8[i] = 0;
    }
    if (FLOW_IS_IPV4(f)) {
        FlowKeySetIpv4Address(&fk->src, f->src.address.address_un_data32[0]);
        FlowKeySetIpv4Address(&fk->dst, f->dst.address.address_un_data32[0]);

        fk->sp = f->sp;
        fk->dp = f->dp;

        fk->vlan_id[0] = f->vlan_id[0];
        fk->vlan_id[1] = f->vlan_id[1];
        fk->proto = f->proto;
        fk->recursion_level = f->recursion_level;
        return 0;
    } else if (FLOW_IS_IPV6(f)) {
        FlowKeySetIpv6Address(&fk->src, f->src.address.address_un_data32);
        FlowKeySetIpv6Address(&fk->dst, f->dst.address.address_un_data32);

        fk->sp = f->sp;
        fk->dp = f->dp;

        fk->vlan_id[0] = f->vlan_id[0];
        fk->vlan_id[1] = f->vlan_id[1];
        fk->proto = f->proto;
        fk->recursion_level = f->recursion_level;
    } else {
        SCLogInfo("Flow conversion supported only to IPv4/6");
        return -1;
    }
    return 0;
}

// make flow key unified and extract src positions of addr and port
struct FlowKeyDirection FlowKeyUnify(FlowKey *fk)
{
    struct FlowKeyDirection fd;

    if (fk->src.family == AF_INET) {
        if (fk->src.address.address_un_data32[0] < fk->dst.address.address_un_data32[0]) {
            fd.src_addr = 0;
        } else {
            FlowKeySwapIpv4Addresses(&fk->src, &fk->dst);
            fd.src_addr = 1;
        }
    } else if (fk->src.family == AF_INET6) {
        if (FlowHashRawAddressIPv6GtU32(
                    fk->src.address.address_un_data32, fk->dst.address.address_un_data32)) {
            fd.src_addr = 0;
        } else {
            FlowKeySwapIpv6Addresses(&fk->src, &fk->dst);
            fd.src_addr = 1;
        }
    } else {
        SCLogError(EINVAL, "BUG: Family not supported!");
        exit(1);
    }

    if (fk->sp <= fk->dp) {
        fd.src_port = 0;
    } else {
        uint16_t tp = fk->sp;
        fk->sp = fk->dp;
        fk->dp = tp;
        fd.src_port = 1;
    }

    return fd;
}

void FlowKeyReconstruct(FlowKey *fk, struct FlowKeyDirection *fd)
{
    if (fd->src_addr == 1) {
        if (fk->src.family == AF_INET) {
            FlowKeySwapIpv4Addresses(&fk->src, &fk->dst);
        } else if (fk->src.family == AF_INET6) {
            FlowKeySwapIpv6Addresses(&fk->src, &fk->dst);
        } else {
            SCLogError(EINVAL, "BUG: FlowKeyReconstruct only supports IPv4/6 address families");
            exit(1);
        }
    }

    if (fd->src_port == 1) {
        uint32_t tp = fk->sp;
        fk->sp = fk->dp;
        fk->dp = tp;
    }
}

static uint16_t FlowKeyExtendedInitUnifiedVlan(
        struct rte_ether_hdr *ether_hdr, uint16_t *outer_vlan, uint16_t *inner_vlan)
{
    *outer_vlan = *inner_vlan = 0;
    uint16_t vlan_hdrs_len;
    vlan_hdrs_len = sizeof(struct rte_vlan_hdr);
    struct rte_vlan_hdr *vh = (struct rte_vlan_hdr *)(ether_hdr + 1);

    *outer_vlan = rte_be_to_cpu_16(vh->vlan_tci) & 0x0FFF; // 12 bottom bits

    if (vh->eth_proto == rte_cpu_to_be_16(RTE_ETHER_TYPE_VLAN)) {
        vh++; // move by one entire vlan header forward
        *inner_vlan = rte_be_to_cpu_16(vh->vlan_tci) & 0x0FFF; // 12 bottom bits
        vlan_hdrs_len += sizeof(struct rte_vlan_hdr);
    }

    return vlan_hdrs_len;
}

static uint16_t FlowKeyExtendedInitUnifiedIpv4(
        FlowKeyExtended *flow_key, struct rte_ipv4_hdr *ip4_hdr, uint16_t *hdr_len)
{
    if (ip4_hdr->src_addr < ip4_hdr->dst_addr) {
        flow_key->fd.src_addr = 0;
        FlowKeySetIpv4Address(&flow_key->fk.src, ip4_hdr->src_addr);
        FlowKeySetIpv4Address(&flow_key->fk.dst, ip4_hdr->dst_addr);
    } else {
        flow_key->fd.src_addr = 1;
        FlowKeySetIpv4Address(&flow_key->fk.src, ip4_hdr->dst_addr);
        FlowKeySetIpv4Address(&flow_key->fk.dst, ip4_hdr->src_addr);
    }

    *hdr_len = rte_ipv4_hdr_len(ip4_hdr);

    return ip4_hdr->next_proto_id;
}

static uint16_t FlowKeyExtendedInitUnifiedIpv6(
        FlowKeyExtended *flow_key, struct rte_ipv6_hdr *ip6_hdr, uint16_t *hdr_len)
{
    uint32_t *ip6_src = (uint32_t *)ip6_hdr->src_addr;
    uint32_t *ip6_dst = (uint32_t *)ip6_hdr->dst_addr;

    if (FlowHashRawAddressIPv6GtU32(ip6_src, ip6_dst)) {
        flow_key->fd.src_addr = 0;
        FlowKeySetIpv6Address(&flow_key->fk.src, ip6_src);
        FlowKeySetIpv6Address(&flow_key->fk.dst, ip6_dst);
    } else {
        flow_key->fd.src_addr = 1;
        FlowKeySetIpv6Address(&flow_key->fk.src, ip6_dst);
        FlowKeySetIpv6Address(&flow_key->fk.dst, ip6_src);
    }

    *hdr_len = sizeof(struct rte_ipv6_hdr);

    return ip6_hdr->proto;
}

static void FlowKeyExtendedInitUnifiedTcp(FlowKeyExtended *flow_key, struct rte_tcp_hdr *tcp_hdr)
{
    flow_key->fk.proto = IPPROTO_TCP;
    if (rte_cpu_to_be_16(tcp_hdr->src_port) < rte_cpu_to_be_16(tcp_hdr->dst_port)) {
        flow_key->fd.src_port = 0;
        flow_key->fk.sp = rte_cpu_to_be_16(tcp_hdr->src_port);
        flow_key->fk.dp = rte_cpu_to_be_16(tcp_hdr->dst_port);
    } else {
        flow_key->fd.src_port = 1;
        flow_key->fk.sp = rte_cpu_to_be_16(tcp_hdr->dst_port);
        flow_key->fk.dp = rte_cpu_to_be_16(tcp_hdr->src_port);
    }
}

static void FlowKeyExtendedInitUnifiedUdp(FlowKeyExtended *flow_key, struct rte_udp_hdr *udp_hdr)
{
    flow_key->fk.proto = IPPROTO_UDP;
    if (rte_cpu_to_be_16(udp_hdr->src_port) < rte_cpu_to_be_16(udp_hdr->dst_port)) {
        flow_key->fd.src_port = 0;
        flow_key->fk.sp = rte_cpu_to_be_16(udp_hdr->src_port);
        flow_key->fk.dp = rte_cpu_to_be_16(udp_hdr->dst_port);
    } else {
        flow_key->fd.src_port = 1;
        flow_key->fk.sp = rte_cpu_to_be_16(udp_hdr->dst_port);
        flow_key->fk.dp = rte_cpu_to_be_16(udp_hdr->src_port);
    }
}

/**
 * Populates structure FlowKeyExtended from an mbuf.
 * The resulting flow key (part of extended flow key) is unified,
 * in a sense of placing the lower IP address / L4 port as a src address/port.
 * By this, one flow key represents both "half flows".
 * VLANs remain on the same position where outer vlan is filled as the first
 * @param extended_flow_key to fill
 * @param mbuf source of information
 * @return < 0 when error occurs, 0 on success, 1 when parsing hits unsupported protocol
 */
int FlowKeyExtendedInitFromMbuf(FlowKeyExtended *flow_key, struct rte_mbuf *mbuf)
{
    uint16_t l3_hdr_len;
    uint16_t l3_next_proto;
    uint8_t vlan_hdrs_len = 0;
    struct rte_ether_hdr *ether_hdr;

    memset(flow_key->fk.spare8, 0, sizeof(flow_key->fk.spare8) / sizeof(flow_key->fk.spare8[0]));
    flow_key->fk.recursion_level = 0;

    ether_hdr = rte_pktmbuf_mtod(mbuf, struct rte_ether_hdr *);
    if (ether_hdr->ether_type == rte_cpu_to_be_16(RTE_ETHER_TYPE_VLAN)) {
        vlan_hdrs_len = FlowKeyExtendedInitUnifiedVlan(
                ether_hdr, &flow_key->fk.vlan_id[0], &flow_key->fk.vlan_id[1]);
        ether_hdr = (void *)ether_hdr + vlan_hdrs_len;
    }

    if (ether_hdr->ether_type == rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4)) {
        struct rte_ipv4_hdr *ip4_hdr = (void *)ether_hdr + sizeof(struct rte_ether_hdr);
        l3_next_proto = FlowKeyExtendedInitUnifiedIpv4(flow_key, ip4_hdr, &l3_hdr_len);

        if (l3_next_proto == IPPROTO_TCP) {
            struct rte_tcp_hdr *tcp_hdr = (void *)ip4_hdr + l3_hdr_len;
            FlowKeyExtendedInitUnifiedTcp(flow_key, tcp_hdr);
        } else if (l3_next_proto == IPPROTO_UDP) {
            struct rte_udp_hdr *udp_hdr = (void *)ip4_hdr + l3_hdr_len;
            FlowKeyExtendedInitUnifiedUdp(flow_key, udp_hdr);
        } else {
            return 1;
        }
    } else if (ether_hdr->ether_type == rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV6)) {
        struct rte_ipv6_hdr *ip6_hdr = (void *)ether_hdr + sizeof(struct rte_ether_hdr);
        l3_next_proto = FlowKeyExtendedInitUnifiedIpv6(flow_key, ip6_hdr, &l3_hdr_len);

        if (l3_next_proto == IPPROTO_TCP) {
            struct rte_tcp_hdr *tcp_hdr = (void *)ip6_hdr + l3_hdr_len;
            FlowKeyExtendedInitUnifiedTcp(flow_key, tcp_hdr);
        } else if (l3_next_proto == IPPROTO_UDP) {
            struct rte_udp_hdr *udp_hdr = (void *)ip6_hdr + sizeof(struct rte_ipv6_hdr);
            FlowKeyExtendedInitUnifiedUdp(flow_key, udp_hdr);
        } else {
            return 1;
        }
    } else {
        return 1;
    }

    return 0;
}

int DPDKBypassManagerAssistantInit(ThreadVars *th_v, struct timespec *curtime, void *data)
{
    SCLogInfo("Initing bypass manager assistant");
    return 0;
}

// expects the message is evict message
static void FlowBypassUpdate(
        Flow *f, struct PFMessage *msg, struct timespec *curtime, struct flows_stats *bypassstats)
{
    FlowBypassInfo *fc = FlowGetStorageById(f, GetFlowBypassInfoID());
    if (fc) {
        f->lastts.tv_sec = curtime->tv_sec;
        struct DPDKFlowBypassData *d = (struct DPDKFlowBypassData *)fc->bypass_data;
        if (d) {
            d->pending_msgs = 0;
        }
        fc->tosrcpktcnt += msg->bypass_evict_msg.tosrcpktcnt;
        fc->tosrcbytecnt += msg->bypass_evict_msg.tosrcbytecnt;
        fc->todstpktcnt += msg->bypass_evict_msg.todstpktcnt;
        fc->todstbytecnt += msg->bypass_evict_msg.todstbytecnt;

        bypassstats->bytes +=
                msg->bypass_evict_msg.tosrcbytecnt + msg->bypass_evict_msg.todstbytecnt;
        bypassstats->packets +=
                msg->bypass_evict_msg.tosrcpktcnt + msg->bypass_evict_msg.todstpktcnt;
        // not sure if the count is count of total bypassed flows or count of bypass update calls
        bypassstats->count++;
    }
}

// my flow delete attempt with locking f_prev
// static void FlowDeleteFromFlowTable(Flow *f)
//{
//    // f is locked
//    // current flow bucket is locked
//    FBLOCK_LOCK(f->fb);
//    Flow *f_prev = f->fb->head == f ? NULL : f->fb->head;
//
//    if (f_prev != NULL) {
//        FLOWLOCK_RDLOCK(f_prev);
//        Flow *f_prev_prev;
//        while (f_prev->next != f) {
//            f_prev_prev = f_prev;
//            f_prev = f_prev->next;
//            FLOWLOCK_UNLOCK(f_prev_prev);
//
//            if (f_prev != NULL) {
//                FLOWLOCK_RDLOCK(f_prev);
//            } else {
//                // we hit the end of the bucket
//                // can not find the original flow (the flow to delete)
//                return;
//            }
//        }
//
//        f_prev->next = f->next;
//    } else {
//        f->fb->head = f->next;
//    }
//
//    FLOWLOCK_UNLOCK(f_prev);
//
//    f->next = f->fb->evicted;
//    f->fb->evicted = f;
//
//    f->flags |= FLOW_END_FLAG_TIMEOUT;
//    FlowSetEndFlags(f);
//    FLOWLOCK_UNLOCK(f);
//    FBLOCK_UNLOCK(f->fb);
//}

static void FlowDeleteFromFlowTable(Flow *f)
{
    if (f->livedev) {
        if (FLOW_IS_IPV4(f)) {
            LiveDevSubBypassStats(f->livedev, 1, AF_INET);
        } else if (FLOW_IS_IPV6(f)) {
            LiveDevSubBypassStats(f->livedev, 1, AF_INET6);
        }
    }

    FlowBypassInfo *fc = FlowGetStorageById(f, GetFlowBypassInfoID());
    if (fc && fc->BypassFree && fc->bypass_data) {
        fc->BypassFree(fc->bypass_data);
        fc->bypass_data = NULL;
        fc->BypassFree = NULL;
    }

    FBLOCK_LOCK(f->fb);
    Flow *f_prev = f->fb->head == f ? NULL : f->fb->head;

    // todo: examine if this can't be a race condition.
    while (f_prev != NULL && f_prev->next != f) {
        f_prev = f_prev->next;
    }

    if (f_prev) {
        f_prev->next = f->next;
    } else {
        f->fb->head = f->next;
    }

    f->next = f->fb->evicted;
    f->fb->evicted = f;

    f->flags |= FLOW_END_FLAG_TIMEOUT;
    FlowSetEndFlags(f);

    FBLOCK_UNLOCK(f->fb);
}

// expects locked flow
static void FlowBypassEvict(Flow *f)
{
    if (f->livedev) {
        if (FLOW_IS_IPV4(f)) {
            LiveDevAddBypassSuccess(f->livedev, 1, AF_INET);
        } else if (FLOW_IS_IPV6(f)) {
            LiveDevAddBypassSuccess(f->livedev, 1, AF_INET6);
        }
    }

    FlowDeleteFromFlowTable(f);
    FLOWLOCK_UNLOCK(f);
}

static Flow *FlowBypassGetWorkerLockedFlow(FlowKey *flow_key)
{
    Flow *f = NULL;
    uint32_t hash = FlowKeyGetHash(flow_key);
    f = FlowGetExistingLockedFlowFromHash(flow_key, hash);
    if (f == NULL)
        SCLogDebug("Unable to get flow locked for workers");

    return f;
}

// return 0 if no new stats, non zero if otherwise, function expects zeroed bypass stats
int DPDKCheckBypassMessages(
        ThreadVars *th_v, struct flows_stats *bypassstats, struct timespec *curtime, void *data)
{
    bool new_stats = false;
    uint16_t msg_cnt;
    struct PFMessage *msg_arr[32];
    struct PFMessage *msg;
    Flow *f = NULL;
    struct DPDKBypassManagerAssistantData *dpdk_v = (struct DPDKBypassManagerAssistantData *)data;

    msg_cnt = rte_ring_dequeue_burst(dpdk_v->results_ring, (void **)msg_arr, 32, NULL);
    if (msg_cnt == 0)
        return new_stats;

    for (uint16_t i = 0; i < msg_cnt; i++) {
        msg = msg_arr[i];
        if (msg->msg_type == PF_MESSAGE_BYPASS_EVICT) {
            f = FlowBypassGetWorkerLockedFlow(&msg->fk);
            if (f == NULL)
                continue;

            if (!(f->flags & FLOW_LOCK_FOR_WORKERS))
                SCLogWarning(SC_ERR_DPDK_BYPASS, "Flow does not have lock set!");

            if (msg->bypass_evict_msg.tosrcpktcnt == 0 && msg->bypass_evict_msg.todstpktcnt == 0) {
                FlowBypassEvict(f);
                SCLogDebug("Flow deleted");
            } else {
                FlowBypassUpdate(f, msg, curtime, bypassstats);
                FLOWLOCK_UNLOCK(f);
                new_stats = true;
            }
        } else if (msg->msg_type == PF_MESSAGE_BYPASS_FLOW_NOT_FOUND) {
            f = FlowBypassGetWorkerLockedFlow(&msg->fk);
            if (f == NULL)
                continue;

            FlowBypassInfo *fc = FlowGetStorageById(f, GetFlowBypassInfoID());
            if (fc && fc->BypassFree && fc->bypass_data) {
                fc->BypassFree(fc->bypass_data);
                fc->bypass_data = NULL;
                fc->BypassFree = NULL;
            }
            FlowUpdateState(f, FLOW_STATE_LOCAL_BYPASSED);
            SCLogDebug("Flow not found in the capture bypass, moved to local bypassed state");
            FLOWLOCK_UNLOCK(f);
        } else {
            SCLogInfo("Assistant has an unknown message type");
            continue;
        }
    }

    rte_mempool_generic_put(dpdk_v->msg_mp, (void **)msg_arr, msg_cnt, dpdk_v->msg_mpc);

    return new_stats;
}

#endif /* HAVE_DPDK */