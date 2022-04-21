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
    struct rte_mbuf *(*ring_buffers)[2 * BURST_SIZE];
    ring_buffer *rb;
    struct lcore_stats stats;
    //    struct rte_table_hash *bypass_table;
    //    struct rte_mempool *mp;
};

int ThreadMain(void *ring_list_entry);

#endif // LCORE_WORKER_H
