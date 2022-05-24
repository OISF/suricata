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

#ifndef STATS_H
#define STATS_H

#include <rte_atomic.h>

#define PCRE2_CODE_UNIT_WIDTH 8
#define _POSIX_C_SOURCE       200809L
#include <string.h>
#include <netinet/in.h>
#include <dirent.h>
#include "suricata-common.h"
#include "conf.h"
#include "conf-yaml-loader.h"
#include "util-atomic.h"
#include "tm-threads-common.h"
#include "threads.h"
#include "util-device.h"
#include "util-debug.h"
#include "util-dpdk.h"
#include "util-dpdk-bypass.h"
#include "runmode-dpdk.h"
#include "source-dpdk.h"

#define MAX_WORKERS_TO_PREFILTER_LCORE 16

struct pf_stats {
    rte_atomic64_t p1_rx;
    rte_atomic64_t p2_rx;
    rte_atomic64_t p1_tx_all;
    rte_atomic64_t p2_tx_all;
    rte_atomic64_t p1_tx;
    rte_atomic64_t p2_tx;
    rte_atomic64_t pkts_enqueue_tries;
    rte_atomic64_t pkts_enqueues;
    rte_atomic64_t pkts_dequeues;
    rte_atomic64_t pkts_inspects;
    rte_atomic64_t pkts_bypasses;
    rte_atomic64_t msgs_rx;
    rte_atomic64_t msgs_tx;
    rte_atomic64_t msgs_tx_fail;
    rte_atomic64_t msgs_mp_puts;
    rte_atomic64_t flow_bypasses;
    rte_atomic64_t flow_bypass_dels;
    rte_atomic64_t flow_bypass_updates;
};

struct lcore_stats {
    uint64_t pkts_p1_rx;
    uint64_t pkts_p2_rx;
    int64_t pkts_inspected;
    int64_t pkts_bypassed;
    uint64_t pkts_to_ring_enq_total[MAX_WORKERS_TO_PREFILTER_LCORE];
    uint64_t pkts_to_ring_enq_success[MAX_WORKERS_TO_PREFILTER_LCORE];
    uint64_t pkts_from_ring_deq_success[MAX_WORKERS_TO_PREFILTER_LCORE];
    uint64_t pkts_p1_tx_total;
    uint64_t pkts_p1_tx_success;
    uint64_t pkts_p2_tx_total;
    uint64_t pkts_p2_tx_success;

    uint64_t msgs_deq;
    uint64_t msgs_type_rx[PF_MESSAGE_CNT];
    uint64_t msgs_type_tx[PF_MESSAGE_CNT];
    uint64_t msgs_enq_fail;
    uint64_t msgs_mempool_put;
    uint64_t flow_bypass_success;
    uint64_t flow_bypass_exists;
    uint64_t flow_bypass_del_success;
    uint64_t flow_bypass_del_fail;
    uint64_t flow_bypass_update;
};

int PFStatsInit(struct pf_stats **s);
void PFStatsExitLog(struct pf_stats *s);
void PFStatsDeinit(struct pf_stats *s);

#endif // STATS_H
