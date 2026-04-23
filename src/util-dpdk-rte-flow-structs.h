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
 *  \defgroup dpdk DPDK rte_flow rules util functions
 *
 *  @{
 */

/**
 * \file
 *
 * \author Adam Kiripolsky <adam.kiripolsky@cesnet.cz>
 *
 * DPDK rte_flow rules util structures
 *
 */

#ifndef SURICATA_RTE_FLOW_STRUCTS_H
#define SURICATA_RTE_FLOW_STRUCTS_H

#ifdef HAVE_DPDK
#include "suricata-common.h"
#include "util-dpdk-common.h"

typedef struct RteFlowRuleStorage_ {
    uint32_t rule_cnt;
    uint32_t rule_size;
    char **rules;
    struct rte_flow **rule_handlers;
} RteFlowRuleStorage;

typedef struct RteFlowBypassData_ {
    struct rte_mempool *bypass_info_mp;
    struct rte_mempool *bypass_mp;
    struct rte_ring *bypass_ring;
    uint32_t rte_bypass_rule_capacity;
    SC_ATOMIC_DECLARE(uint32_t, rte_bypass_rules_error);
    SC_ATOMIC_DECLARE(uint32_t, rte_bypass_rules_created);
    SC_ATOMIC_DECLARE(uint32_t, rte_bypass_rules_active);
    SC_ATOMIC_DECLARE(uint32_t, rte_bypass_mempool_get_error);
    SC_ATOMIC_DECLARE(uint32_t, rte_bypass_info_mempool_get_error);
    SC_ATOMIC_DECLARE(uint32_t, rte_bypass_flow_error);
    SC_ATOMIC_DECLARE(uint32_t, rte_bypass_query_error);
    SC_ATOMIC_DECLARE(uint32_t, rte_bypass_enqueue_error);

} RteFlowBypassData;

#endif /* HAVE_DPDK */
#endif /* SURICATA_RTE_FLOW_STRUCTS_H */
/**
 * @}
 */
