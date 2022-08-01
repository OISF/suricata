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

#ifndef LCORE_WORKER_H
#define LCORE_WORKER_H

#include <stdint-gcc.h>
#include "dev-conf.h"
#include "stats.h"

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

#include "flow.h"

#define BURST_SIZE 32

typedef struct {
    struct rte_mbuf *buf[2 * BURST_SIZE];
    uint16_t len;
} ring_buffer;

struct lcore_values {
    uint16_t qid; // lcore qid based on the order of lcore spawns
    enum PFOpMode opmode;
    const char *port1_addr;
    uint16_t port1_id;
    const char *port2_addr;
    uint16_t port2_id;
    uint16_t ring_offset_start;
    uint16_t rings_cnt;
    uint32_t socket_id;              // filled in thread init
    struct rte_ring **rings_from_pf; // rings in direction to the secondary app
    struct rte_ring **rings_to_pf;   // rings in direction from the secondary app to the prefilter
    struct rte_ring *tasks_ring;
    struct rte_ring *results_ring;
    struct rte_mempool *message_mp;
    struct rte_table_hash *bt; // bypass table
    ring_buffer *tmp_ring_bufs;
    FlowKeyExtended fke_arr;
    FlowKey **fk_arr; // points flowkeys of fke_arr
    rte_atomic16_t *state;
    struct lcore_stats stats;
    //    struct rte_table_hash *bypass_table;
    //    struct rte_mempool *mp;
    struct rte_mbuf *pkts[2 * BURST_SIZE];
    struct rte_mbuf *pkts_to_inspect[2 * BURST_SIZE];
    struct rte_mbuf *pkts_to_bypass[2 * BURST_SIZE];
    struct BypassHashTableData *bypass_data[2 * BURST_SIZE];
};

int ThreadMain(void *init_values);

#endif // LCORE_WORKER_H
