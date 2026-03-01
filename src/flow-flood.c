/* Copyright (C) 2025 Open Information Security Foundation
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
 * \author Eric Leblond <el@stamus-networks.com>
 *
 * Structure to handle packet flood.
 *
 */

#include "suricata-common.h"
#include "suricata.h"
#include "decode.h"
#include "flow-flood.h"
#include "tmqh-packetpool.h"
#include "util-device.h"

/* Declare new flood struct */

static uint32_t NewFlowHash(struct HashTable_ *ht, void *data, uint16_t size)
{
    FloodStorageRingElt *fp = (FloodStorageRingElt *)data;
    return fp->p->flow_hash % ht->array_size;
}

static inline bool CmpVlanIds(
        const uint16_t vlan_id1[VLAN_MAX_LAYERS], const uint16_t vlan_id2[VLAN_MAX_LAYERS])
{
    return ((vlan_id1[0] ^ vlan_id2[0]) & g_vlan_mask) == 0 &&
           ((vlan_id1[1] ^ vlan_id2[1]) & g_vlan_mask) == 0 &&
           ((vlan_id1[2] ^ vlan_id2[2]) & g_vlan_mask) == 0;
}

static inline bool CmpAddrs(const uint32_t addr1[4], const uint32_t addr2[4])
{
    return addr1[0] == addr2[0] && addr1[1] == addr2[1] && addr1[2] == addr2[2] &&
           addr1[3] == addr2[3];
}

static inline bool CmpAddrsAndPorts(const uint32_t src1[4], const uint32_t dst1[4], Port src_port1,
        Port dst_port1, const uint32_t src2[4], const uint32_t dst2[4], Port src_port2,
        Port dst_port2)
{
    /* Compare the source and destination addresses. If they are not equal,
     * compare the first source address with the second destination address,
     * and vice versa. Likewise for ports. */
    return (CmpAddrs(src1, src2) && CmpAddrs(dst1, dst2) && src_port1 == src_port2 &&
                   dst_port1 == dst_port2) ||
           (CmpAddrs(src1, dst2) && CmpAddrs(dst1, src2) && src_port1 == dst_port2 &&
                   dst_port1 == src_port2);
}

/* Since two or more flows can have the same hash key, we need to compare
 * the flow with the current packet or flow key. */
static inline bool CmpPackets(const Packet *p0, const Packet *p1)
{
    const uint32_t *p0_src = p0->src.address.address_un_data32;
    const uint32_t *p0_dst = p0->dst.address.address_un_data32;
    const uint32_t *p1_src = p1->src.address.address_un_data32;
    const uint32_t *p1_dst = p1->dst.address.address_un_data32;
    return CmpAddrsAndPorts(p0_src, p0_dst, p0->sp, p0->dp, p1_src, p1_dst, p1->sp, p1->dp) &&
           p0->proto == p1->proto && p0->recursion_level == p1->recursion_level &&
           CmpVlanIds(p0->vlan_id, p1->vlan_id) &&
           (p0->livedev == p1->livedev || g_livedev_mask == 0);
}

static char NewFlowCompare(void *ptr1, uint16_t size1, void *ptr2, uint16_t size2)
{
    FloodStorageRingElt *fp1 = (FloodStorageRingElt *)ptr1;
    FloodStorageRingElt *fp2 = (FloodStorageRingElt *)ptr2;
    if (fp1->p->flow_hash != fp2->p->flow_hash)
        return 0;
    if ((fp1->p->sp != fp2->p->sp) && (fp1->p->sp != fp2->p->dp))
        return 0;
    return CmpPackets(fp1->p, fp2->p);
}

static void NewFlowFree(void *p)
{
}

/* Declare new flood struct */

static uint32_t EstFlowHash(struct HashTable_ *ht, void *data, uint16_t size)
{
    uint32_t flow_hash = (uint64_t)data;
    return flow_hash & ht->array_mask;
}

static char EstFlowCompare(void *ptr1, uint16_t size1, void *ptr2, uint16_t size2)
{
    uint32_t flow_hash_1 = (uint64_t)ptr1;
    uint32_t flow_hash_2 = (uint64_t)ptr2;

    return flow_hash_1 == flow_hash_2;
}

static void EstFlowFree(void *p)
{
}

FloodStorage *FloodStorageInit(ThreadVars *tv, size_t size)
{
    FloodStorage *fst = SCCalloc(1, sizeof(FloodStorage));
    if (fst == NULL)
        return NULL;
    fst->size = size;
    fst->stored = StatsRegisterCounter("flow.flood.holding.stored", tv);
    fst->passed = StatsRegisterCounter("flow.flood.holding.passed", tv);
    fst->dropped = StatsRegisterCounter("flow.flood.holding.dropped", tv);
    fst->est_hit = StatsRegisterCounter("flow.flood.prefilter.hits", tv);
    fst->est_nohit = StatsRegisterCounter("flow.flood.prefilter.misses", tv);
    fst->one_way_pkts = StatsRegisterCounter("flow.flood.one_way.pkts", tv);
    fst->one_way_bytes = StatsRegisterCounter("flow.flood.one_way.bytes", tv);
    fst->one_way_flows = StatsRegisterCounter("flow.flood.one_way.flows", tv);
    fst->syn_pkts = StatsRegisterCounter("flow.flood.syn_only.pkts", tv);
    fst->syn_bytes = StatsRegisterCounter("flow.flood.syn_only.bytes", tv);

    fst->new_hash = HashTableInit(size, NewFlowHash, NewFlowCompare, NewFlowFree);
    if (fst->new_hash == NULL) {
        SCFree(fst);
        return NULL;
    }
    HashTablePreAlloc(fst->new_hash);

    fst->new_ring = (FloodStorageRingElt *)SCCalloc(size, sizeof(FloodStorageRingElt));
    if (fst->new_ring == NULL) {
        SCFree(fst->new_hash);
        SCFree(fst);
        return NULL;
    }

    fst->new_ins = fst->new_ring;

    uint32_t hash_size = FlowGetHashSize();
    uint32_t power_of_two = 1;

    while (power_of_two <= hash_size) {
        power_of_two *= 2;
    }
    hash_size = power_of_two;

    fst->est_hash = HashTableInit(hash_size, EstFlowHash, EstFlowCompare, EstFlowFree);
    if (fst->est_hash == NULL) {
        SCFree(fst->new_hash);
        SCFree(fst->new_ring);
        SCFree(fst);
        return NULL;
    }
    HashTablePreAlloc(fst->est_hash);

    SCLogNotice("Flood stage initialized with size %zu", size);
    return fst;
}

static inline void FloodStorageReleasePacket(ThreadVars *tv, Packet *p)
{
    p->flags &= ~PKT_FROM_FLOOD;
    TmqhOutputPacketpool(tv, p);
}

static inline void FloodStorageAcctElt(ThreadVars *tv, FloodStorage *fst, FloodStorageRingElt *elt)
{
    /* If we have more than one packet this is not a syn flood */
    if (elt->flags & FSR_OTHERS) {
        StatsAddUI64(tv, fst->one_way_pkts, elt->pkts_cnt);
        StatsAddUI64(tv, fst->one_way_bytes, elt->bytes_cnt);
        StatsAddUI64(tv, fst->one_way_flows, 1);
    } else {
        StatsAddUI64(tv, fst->syn_pkts, 1);
        StatsAddUI64(tv, fst->syn_bytes, GET_PKT_LEN(elt->p));
    }
}

static inline void FloodStorageRecycleElt(
        ThreadVars *tv, FloodStorage *fst, FloodStorageRingElt *elt)
{
    FloodStorageAcctElt(tv, fst, elt);
    elt->pkts_cnt = 0;
    elt->bytes_cnt = 0;
    FloodStorageReleasePacket(tv, elt->p);
}

void FloodStorageDeinit(ThreadVars *tv, FloodStorage *fst)
{
    uint64_t drop_count = 0;
    if (fst == NULL)
        return;
    if (fst->new_ring) {
        /* iterate on the ring to free the Packet */
        FloodStorageRingElt *end = fst->new_ring + fst->size;
        for (FloodStorageRingElt *elt = fst->new_ring; elt < end; elt++) {
            if (elt->flags & FSR_USED) {
                FloodStorageAcctElt(tv, fst, elt);
                /* Pool system is stopped so we need a direct free */
                PacketFree(elt->p);
                drop_count++;
            }
        }
        StatsAddUI64(tv, fst->dropped, drop_count);
        SCFree(fst->new_ring);
    }
    SCLogNotice("Flood Storage [%d]: stored %lu, dropped %lu, passed %lu, freed %lu [est: %lu, "
                "new: %lu]",
            tv->id, StatsGetLocalCounterValue(tv, fst->stored),
            StatsGetLocalCounterValue(tv, fst->dropped), StatsGetLocalCounterValue(tv, fst->passed),
            drop_count, StatsGetLocalCounterValue(tv, fst->est_hit),
            StatsGetLocalCounterValue(tv, fst->est_nohit));
    StatsSyncCounters(tv);
    SCLogDebug("Flood stage freed, synced counters");
    if (fst->new_hash)
        HashTableFree(fst->new_hash);
    if (fst->est_hash)
        HashTableFree(fst->est_hash);
    SCFree(fst);
}

static inline void FloodStorageSetFlagsFromPkt(FloodStorageRingElt *fpr, Packet *p)
{
    if (TCP_GET_FLAGS(p) != TH_SYN)
        fpr->flags |= FSR_OTHERS;
    else
        fpr->flags |= FSR_SYN;
}

static inline FloodStorageRingElt *FloodStorageRingAdd(ThreadVars *tv, FloodStorage *fst, Packet *p)
{
    FloodStorageRingElt *next_elt = fst->new_ins;
    if (next_elt->flags & FSR_USED) {
        SCLogDebug("You're dead and you don't know it.");
        HashTableRemove(fst->new_hash, next_elt, sizeof(FloodStorageRingElt));
        FloodStorageRecycleElt(tv, fst, next_elt);
        StatsAddUI64(tv, fst->dropped, 1);
    } else {
        SCLogDebug("used now");
        next_elt->flags = FSR_USED;
    }
    next_elt->p = p;
    next_elt->pkts_cnt = 1;
    next_elt->bytes_cnt = GET_PKT_LEN(p);
    FloodStorageSetFlagsFromPkt(next_elt, p);
    /* Mark packet to avoid release */
    p->flags |= PKT_FROM_FLOOD;
    StatsAddUI64(tv, fst->stored, 1);
    fst->new_ins++;
    if ((size_t)(fst->new_ins - fst->new_ring) >= fst->size) {
        SCLogDebug("Looping the ring: %lu (dropped %lu)",
                StatsGetLocalCounterValue(tv, fst->stored),
                StatsGetLocalCounterValue(tv, fst->dropped));
        fst->new_ins = fst->new_ring;
    }
    return next_elt;
}

static inline void FloodStorageAddEstablished(ThreadVars *tv, FloodStorage *fst, Packet *p)
{
    uint64_t next_elt = p->flow_hash;

    /* we just want the flow in the hash so let's just use the int as pointer */
    if (HashTableAdd(fst->est_hash, (void *)next_elt, sizeof(uint32_t)) != 0) {
        SCLogDebug("Can't add element to hash");
    }
}

bool FloodStorageIsEstablished(ThreadVars *tv, FloodStorage *fst, Packet *p)
{
    if (HashTableLookup(fst->est_hash, (void *)(uint64_t)p->flow_hash, sizeof(uint32_t)) != NULL) {
        StatsAddUI64(tv, fst->est_hit, 1);
        return true;
    }
    StatsAddUI64(tv, fst->est_nohit, 1);
    return false;
}

void FloodStorageRemovedEstablished(ThreadVars *tv, FloodStorage *fst, Flow *f)
{
    if (fst == NULL)
        return;
    /* We only work on TCP */
    if (f->proto == IPPROTO_TCP) {
        if (HashTableRemove(fst->est_hash, (void *)(uint64_t)(f->flow_hash), sizeof(uint32_t)) !=
                0) {
            SCLogDebug("Can't remove hash");
        }
    }
}

/* Check Packet against flood structure

If it returns a packet, this one must be injected
into the packet stream before the current packet.
If it returns NULL then the current packet must be disregarded.

*/

Packet *FloodStorageNewCheck(ThreadVars *tv, FloodStorage *fst, Packet *p)
{
    FloodStorageRingElt fp = { .p = p, .flags = FSR_USED };
    FloodStorageRingElt *fpr = HashTableLookup(fst->new_hash, &fp, sizeof(fp));
    /* It is first packet for the "flow" */
    SCLogDebug("check at %u", fst->stored);
    if (fpr == NULL) {
        SCLogDebug("Adding elet");
        FloodStorageRingElt *elt = FloodStorageRingAdd(tv, fst, p);
        if (HashTableAdd(fst->new_hash, elt, sizeof(FloodStorageRingElt)) != 0) {
            SCLogDebug("Can't add element to hash");
            FloodStorageReleasePacket(tv, p);
            elt->flags = 0;
        }
        return NULL;
    }
    /* Same direction we susbtitute packets */
    if ((fpr->p->sp == p->sp) && (fpr->p->dp == p->dp)) {
        BUG_ON(p == fpr->p);
        SCLogDebug("same direction at %u (%p %p)", fst->stored, p, fpr->p);
        FloodStorageReleasePacket(tv, fpr->p);
        p->flags |= PKT_FROM_FLOOD;
        fpr->p = p;
        fpr->pkts_cnt++;
        fpr->bytes_cnt += GET_PKT_LEN(p);
        FloodStorageSetFlagsFromPkt(fpr, p);
        StatsAddUI64(tv, fst->dropped, 1);
        return NULL;
    }
    /* Packet in the other direction so we transmit */
    fpr->pkts_cnt = 0;
    fpr->bytes_cnt = 0;
    fpr->flags = 0;
    if (HashTableRemove(fst->new_hash, fpr, sizeof(FloodStorageRingElt)) != 0) {
        SCLogError("Can't remove elt from hash");
    }
    /* Also add the new flow to established flow */
    FloodStorageAddEstablished(tv, fst, fpr->p);
    StatsAddUI64(tv, fst->passed, 2);
    return fpr->p;
}
