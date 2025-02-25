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
 * DPDK rte_flow rules util functions
 *
 */

#ifndef SURICATA_RTE_FLOW_RULES_H
#define SURICATA_RTE_FLOW_RULES_H

#ifdef HAVE_DPDK

#include "conf.h"
#include "util-dpdk.h"

typedef struct RteFlowRuleStorage_ {
    uint32_t rule_cnt;
    uint32_t rule_size;
    char **rules;
    struct rte_flow **rule_handlers;
} RteFlowRuleStorage;

void RteFlowRuleStorageFree(RteFlowRuleStorage *rule_storage);
int ConfigLoadRteFlowRules(
        SCConfNode *if_root, const char *drop_filter_str, RteFlowRuleStorage *rule_storage);
int RteFlowRulesCreate(
        uint16_t port_id, RteFlowRuleStorage *rule_storage, const char *driver_name);

#endif /* HAVE_DPDK */
#endif /* SURICATA_RTE_FLOW_RULES_H */
/**
 * @}
 */
