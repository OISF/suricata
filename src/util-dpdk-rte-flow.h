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
#include "flow-bypass.h"
#include "flow-hash.h"

typedef struct RteFlowHandlerToFlow_ {
    Flow *flow;
    struct rte_flow *src_handler;
    struct rte_flow *dst_handler;
    DPDKDeviceResources *dpdk_vars;
} RteFlowHandlerToFlow;

typedef struct RteFlowHandlerTable_ {
    // timespec to periodically check the table for changes
    struct timespec *ts;
    RteFlowHandlerToFlow *handler_to_flow;
    uint16_t size;
    uint16_t cnt;
    uint16_t ref_count;
} RteFlowHandlerTable;

typedef struct RteFlowBypassPacketData_ {
    FlowKey *flow_key;
    uint16_t port_id;
} RteFlowBypassPacketData;

void RteFlowRuleStorageFree(RteFlowRuleStorage *rte_flow_rule_storage);
int ConfigLoadRteFlowRules(
        SCConfNode *if_root, const char *filter_type, RteFlowRuleStorage *rte_flow_rule_storage);
int RteFlowRulesCreate(char *port_name, int port_id, RteFlowRuleStorage *rte_flow_rule_storage,
        const char *driver_name);
uint64_t RteFlowFilteredPacketsQuery(struct rte_flow **rte_flow_rules, uint16_t rule_count,
        char *device_name, int port_id, uint64_t *filtered_packets);
int RteBypassInit(DPDKDeviceResources *dpdk_resources, uint32_t bypass_ring_size,
        const char *port_name, int port_id);
void RteBypassMempoolFree(void *data);
int RteFlowBypassCallback(Packet *);
int RteFlowBypassCheckFlowInit(ThreadVars *th_v, struct timespec *curtime, void *data);
int RteFlowBypassRuleLoad(
        ThreadVars *th_v, struct flows_stats *bypassstats, struct timespec *curtime, void *data);
bool RteBypassUpdate(Flow *flow, void *data, time_t tsec);
void RteBypassFree(void *data);

#endif /* HAVE_DPDK */
#endif /* SURICATA_RTE_FLOW_RULES_H */
/**
 * @}
 */
