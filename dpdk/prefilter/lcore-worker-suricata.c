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
 * \author Lukas Sismis <lukas.sismis@cesnet.cz>
 */

#define PCRE2_CODE_UNIT_WIDTH 8
#define _POSIX_C_SOURCE       200809L
#include <string.h>
#include <netinet/in.h>
#include <dirent.h>

#include "lcore-worker-suricata.h"
#include "lcores-manager.h"
#include "lcore-worker.h"
#include "dev-conf.h"
#include "dev-conf-suricata.h"
#include "logger.h"
#include "util-prefilter.h"

#include <rte_ethdev.h>
#include <rte_malloc.h>

#include "suricata-common.h"
#include "conf.h"
#include "conf-yaml-loader.h"
#include "util-atomic.h"
#include "tm-threads-common.h"
#include "threads.h"
#include "util-device.h"
#include "util-debug.h"
#include "util-dpdk.h"
#include "runmode-dpdk.h"
#include "source-dpdk.h"

// The flag is used to set mbuf offload flags
// Prefilter receives from 2 NICs but aggregates the traffic into a single DPDK ring
// This flag notes, from which NIC it was received, so the other NIC is for transmitting the packet.
#define PKT_ORIGIN_PORT1 PKT_FIRST_FREE

struct lcore_values *ThreadSuricataInit(struct lcore_init *init_vals)
{
    int ret;
    struct ring_list_entry *re = (struct ring_list_entry *)init_vals->re;
    struct ring_list_entry_suricata *suri_entry =
            (struct ring_list_entry_suricata *)re->pre_ring_conf;

    struct lcore_values *lv = rte_calloc("struct lcore_values", 1, sizeof(struct lcore_values), 0);
    if (lv == NULL) {
        Log().error(EINVAL,
                "Error (%s): memory allocation error of lcore_values for ring %s lcoreid %u",
                rte_strerror(rte_errno), re->main_ring.name_base, rte_lcore_id());
        return NULL;
    }

    lv->port1_addr = suri_entry->nic_conf.port1_pcie;
    ret = rte_eth_dev_get_port_by_name(lv->port1_addr, &lv->port1_id);
    if (ret != 0) {
        Log().error(EINVAL, "Error (%s): Unable to obtain port qid of %s", rte_strerror(-ret),
                lv->port1_addr);
        return NULL;
    }

    lv->port2_addr = suri_entry->nic_conf.port2_pcie;
    ret = rte_eth_dev_get_port_by_name(lv->port2_addr, &lv->port2_id);
    if (ret != 0) {
        Log().error(EINVAL, "Error (%s): Unable to obtain port qid of %s", rte_strerror(-ret),
                lv->port2_addr);
        return NULL;
    }

    lv->socket_id = rte_socket_id();
    lv->qid = init_vals->lcore_id;
    lv->opmode = re->opmode;
    lv->ring_offset_start = init_vals->ring_offset_start;
    lv->rings_cnt = init_vals->rings_cnt;

    lv->rings_from_pf =
            rte_calloc("struct rte_ring *", lv->rings_cnt, sizeof(struct rte_ring *), 0);
    lv->rings_to_pf = rte_calloc("struct rte_ring *", lv->rings_cnt, sizeof(struct rte_ring *), 0);

    // find rings
    for (uint16_t i = 0; i < init_vals->rings_cnt; i++) {
        uint16_t ring_id = lv->ring_offset_start + i;
        struct rte_ring *r;
        const char *name = DevConfRingGetRxName(re->main_ring.name_base, ring_id);
        r = rte_ring_lookup(name);
        if (r == NULL) {
            Log().error(
                    EINVAL, "Error (%s): unable to find ring %s", rte_strerror(rte_errno), name);
            return NULL;
        }

        lv->rings_from_pf[i] = r;

        if (re->opmode != IDS) {
            name = DevConfRingGetTxName(re->main_ring.name_base, ring_id);
            r = rte_ring_lookup(name);
            if (r == NULL) {
                Log().error(EINVAL, "Error (%s): unable to find ring %s", rte_strerror(rte_errno),
                        name);
                return NULL;
            }

            lv->rings_to_pf[i] = r;
        }
    }

    // allocate pkt ring buffer
    lv->rb = rte_calloc("ring_buffer", sizeof(ring_buffer), init_vals->rings_cnt, 0);
    if (lv->rb == NULL) {
        Log().error(EINVAL,
                "Error (%s): Unable to allocate memory for ring queues of ring %s lcoreid %u",
                rte_strerror(-ret), re->main_ring.name_base, lv->qid);
        return NULL;
    }

    return lv;
}

static int ThreadSuricataStartPort(
        uint16_t pid, const char *pname, const struct lcore_values *const lv)
{
    int ret;
    struct rte_eth_dev_info port_info;
    ret = rte_eth_dev_info_get(pid, &port_info);
    if (ret != 0) {
        Log().error(ret, "Error (%s) when getting port info of %s", rte_strerror(-ret), pname);
        return ret;
    }

    ret = rte_eth_dev_start(pid);
    if (ret != 0) {
        Log().error(ret, "Error (%s) when starting port %s", rte_strerror(-ret), pname);
        return ret;
    }

    DevicePostStartPMDSpecificActions(pid, lv->rings_cnt, port_info.driver_name);
    return 0;
}

static int ThreadSuricataStartPorts(const struct lcore_values *const lv)
{
    int ret;
    ret = ThreadSuricataStartPort(lv->port1_id, lv->port1_addr, lv);
    if (ret != 0)
        return ret;

    if (lv->opmode != IDS) {
        ret = ThreadSuricataStartPort(lv->port2_id, lv->port2_addr, lv);
        if (ret != 0)
            return ret;
    }

    return 0;
}

static int ThreadSuricataStopPort(uint16_t pid, const char *pname)
{
    int ret;
    struct rte_eth_dev_info port_info;
    ret = rte_eth_dev_info_get(pid, &port_info);
    if (ret != 0) {
        Log().error(ret, "Error (%s) when getting port info of %s", rte_strerror(-ret), pname);
        return ret;
    }

    DevicePreStopPMDSpecificActions(pid, port_info.driver_name);
    ret = rte_eth_dev_stop(pid);
    if (ret != 0) {
        Log().error(ret, "Error (%s) when stopping port %s", rte_strerror(-ret), pname);
        return ret;
    }
    return 0;
}

static int ThreadSuricataStopPorts(const struct lcore_values *const lv)
{
    int ret;
    ret = ThreadSuricataStopPort(lv->port1_id, lv->port1_addr);
    if (ret != 0)
        return ret;

    if (lv->opmode != IDS) {
        ret = ThreadSuricataStopPort(lv->port2_id, lv->port2_addr);
        if (ret != 0)
            return ret;
    }

    return 0;
}

void ThreadSuricataRun(struct lcore_values *lv)
{
    int ret;
    uint32_t pkt_count = 0, pkt_count1 = 0, pkt_count2 = 0;
    uint16_t queue_id;
    uint64_t ring_cntrs[16] = { 0 };
    struct rte_mbuf *pkts[2 * BURST_SIZE] = { NULL };
    struct rte_mbuf *pkts_nic2[2 * BURST_SIZE] = { NULL };
    memset(&lv->stats, 0, sizeof(lv->stats)); // null the stats

    Log().notice("Lcore %u trying to rcv from %s (p%d)", lv->qid, lv->port1_addr, lv->port1_id);
    if (lv->opmode != IDS)
        Log().notice("Lcore %u trying to rcv from %s (p%d)", lv->qid, lv->port2_addr, lv->port2_id);

    if (lv->qid == 0) {
        ret = ThreadSuricataStartPorts(lv);
        if (ret != 0) {
            StopWorkers();
            return;
        }
    }

    while (!ShouldStop()) {
        pkt_count1 = rte_eth_rx_burst(lv->port1_id, lv->qid, pkts, BURST_SIZE);

        if (lv->opmode != IDS) {
            pkt_count2 = rte_eth_rx_burst(lv->port2_id, lv->qid, pkts + pkt_count1, BURST_SIZE);
        }
        lv->stats.pkts_rx += pkt_count1 + pkt_count2;

        for (uint32_t i = 0; i < pkt_count1; i++) {
            uint32_t pkt_rss_hash = pkts[i]->hash.rss >> 8;
            queue_id = pkt_rss_hash % lv->rings_cnt;
            Log().debug(
                    "port1 pkt - pkt_rss_hash orig %u pkt_rss_hash edit %u queue %d/%d lcore %d",
                    pkts[i]->hash.rss, pkt_rss_hash, queue_id, lv->rings_cnt, rte_lcore_id());
            lv->rb[queue_id].buf[lv->rb[queue_id].len] = pkts[i];
            lv->rb[queue_id].buf[lv->rb[queue_id].len]->ol_flags |= PKT_ORIGIN_PORT1;
            lv->rb[queue_id].len++;
            ring_cntrs[queue_id] += 1;
        }

        for (uint32_t i = pkt_count1; i < pkt_count1 + pkt_count2; i++) {
            // RSS distribution among NIC queues uses `mod` operation,
            // using the `mod` operation on packets received on the NIC queue
            // would result in wrong distribution. Because of that, RSS hash is shifted
            // to get a fresh value unaffected by the previous `mod` operation.
            // e.g. if 2 NIC queues should distribute packets to 4 workers (1 queue to 4 workers)
            // then NIC queue no. 1 receives packets with odd hash. Applying `mod 2` on that hash
            // would only result in odd results.
            uint32_t pkt_rss_hash = (pkts[i]->hash.rss >> 8);
            queue_id = pkt_rss_hash % lv->rings_cnt;
            Log().debug(
                    "port2 pkt - pkt_rss_hash orig %u pkt_rss_hash edit %u queue %d/%d lcore %d",
                    pkts[i]->hash.rss, pkt_rss_hash, queue_id, lv->rings_cnt, rte_lcore_id());
            lv->rb[queue_id].buf[lv->rb[queue_id].len] = pkts[i];
            lv->rb[queue_id].buf[lv->rb[queue_id].len]->ol_flags &= ~PKT_ORIGIN_PORT1;
            lv->rb[queue_id].len++;
            ring_cntrs[queue_id]++;
        }

        for (uint16_t i = 0; i < lv->rings_cnt; i++) {
            pkt_count = rte_ring_enqueue_burst(
                    lv->rings_from_pf[i], (void **)lv->rb[i].buf, lv->rb[i].len, NULL);
            lv->stats.pkts_enq += pkt_count;
            if (pkt_count > 0) {
                Log().debug("ENQ %d packet/s to rxring %s", pkt_count, lv->rings_from_pf[i]->name);
            }

            // TODO: optimization - aggregate non-enqueued pkts from all rings and free all at once
            if (pkt_count < lv->rb[i].len) {
                rte_pktmbuf_free_bulk(&lv->rb[i].buf[pkt_count], lv->rb[i].len - pkt_count);
            }

            lv->rb[i].len = 0;
        }

        if (lv->opmode != IDS) {
            // deq
            for (uint16_t ring_id = 0; ring_id < lv->rings_cnt; ring_id++) {
                lv->rb[ring_id].len = rte_ring_dequeue_burst(lv->rings_to_pf[ring_id],
                        (void **)lv->rb[ring_id].buf, BURST_SIZE * 2, NULL);
                lv->stats.pkts_deq += lv->rb[ring_id].len;
                if (lv->rb[ring_id].len > 0) {
                    Log().debug("DEQ %d packet/s from txring %s\n", lv->rb[ring_id].len,
                            lv->rings_to_pf[ring_id]->name);
                }

                pkt_count1 = 0;
                pkt_count2 = 0;
                for (uint16_t i = 0; i < lv->rb[ring_id].len; i++) {
                    if (lv->rb[ring_id].buf[i]->ol_flags & PKT_ORIGIN_PORT1) {
                        Log().debug("Pkt direction %s -> %s", lv->port1_addr, lv->port2_addr);
                        pkts[pkt_count1++] = lv->rb[ring_id].buf[i];
                    } else {
                        Log().debug("Pkt direction %s -> %s", lv->port2_addr, lv->port1_addr);
                        pkts_nic2[pkt_count2++] = lv->rb[ring_id].buf[i];
                    }
                }

                // tx to ports
                pkt_count = rte_eth_tx_burst(lv->port1_id, lv->qid, pkts, pkt_count1);
                lv->stats.pkts_tx += pkt_count;
                if (pkt_count < pkt_count1) {
                    rte_pktmbuf_free_bulk(pkts + pkt_count, pkt_count1 - pkt_count);
                }

                pkt_count = rte_eth_tx_burst(lv->port2_id, lv->qid, pkts_nic2, pkt_count2);
                lv->stats.pkts_tx += pkt_count;
                if (pkt_count < pkt_count2) {
                    rte_pktmbuf_free_bulk(pkts_nic2 + pkt_count, pkt_count2 - pkt_count);
                }

                lv->rb[ring_id].len = 0;
            }
        }
    }

    if (lv->qid == 0) {
        ThreadSuricataStopPorts(lv);
    }
}

void ThreadSuricataExitStats(struct lcore_values *lv)
{
    Log().notice("STATS lcore id %d: rx pkts: %lu enq pkts: %lu deq pkts: %lu tx pkts: %lu",
            rte_lcore_id(), lv->stats.pkts_rx, lv->stats.pkts_enq, lv->stats.pkts_deq,
            lv->stats.pkts_tx);
}

void ThreadSuricataDeinit(struct lcore_init *vals, struct lcore_values *lv)
{
    if (vals != NULL)
        rte_free(vals);
    if (lv != NULL) {
        rte_free(lv);
    }
}