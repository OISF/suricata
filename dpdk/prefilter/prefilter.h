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
 * \author Lukas Sismis <sismis@cesnet.com>
 *
 */

#ifndef SURICATA_PREFILTER_H
#define SURICATA_PREFILTER_H

#define _POSIX_C_SOUCRE 200809L

#include <rte_eal.h>
#include <rte_atomic.h>
#include <rte_ring.h>
#include <rte_mempool.h>
#include <rte_hash.h>

#include "dev-conf.h"
#include "hash-table-bypass.h"

#define PREFILTER_CONF_MEMZONE_NAME "prefilter_conf"

extern struct ctx_global_resource ctx;

struct ctx_mempools_resource {
    uint16_t mempool_arr_len;
    struct rte_mempool **mempool_arr;
};

struct ctx_rings_resource {
    uint16_t ring_arr_len;
    struct rte_ring **ring_arr;
};

struct ctx_htable_resource {
    uint16_t htable_arr_len;
    struct rte_table_hash **htable_arr;
};

struct ctx_lcore_resources {
    rte_atomic16_t *state;
    struct rte_table_hash *bypass_table;
};

struct ctx_lcore_state_resource {
    struct ctx_lcore_resources *lcores_arr;
    uint16_t lcores_arr_len;
    uint16_t lcores_arr_capa;
};

struct ctx_ring_conf_list_entry_resource {
    struct ctx_rings_resource rings_from_pf;
    struct ctx_rings_resource rings_to_pf;
    struct ctx_rings_resource rings_tasks;
    struct ctx_rings_resource rings_result;
    struct ctx_mempools_resource mempools_messages;
    struct ctx_htable_resource htable_bypass; // bypass hash tables
};

struct action_control {
    bool attached;
    bool app_ready;
};

struct app_control {
    struct action_control actions;
};

struct ctx_global_resource {
    struct ctx_ring_conf_list_entry_resource *ring_conf_entries;
    uint16_t ring_conf_entries_cnt;
    struct ctx_lcore_state_resource lcores_state;
    struct pf_stats *app_stats;
    struct app_control status;
    const struct rte_memzone *shared_conf;
};

#endif // SURICATA_PREFILTER_H
