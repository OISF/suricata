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
 *  \defgroup dpdk DPDK rte_flow RSS  helpers functions
 *
 *  @{
 */

/**
 * \file
 *
 * \author Adam Kiripolsky <adam.kiripolsky@cesnet.cz>
 *
 * DPDK rte_flow RSS helper functions
 *
 */

#include "util-dpdk-rss.h"
#include "util-dpdk.h"
#include "util-debug.h"

#ifdef HAVE_DPDK

uint8_t RSS_HKEY[] = {
    0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A,
    0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A,
    0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A,                         // 40
    0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, // 52
};

/**
 * \brief Initialize RSS action configuration for
 *        RTE_FLOW RSS rule based on input arguments
 *
 * \param rss_conf RSS configuration
 * \param nb_rx_queues number of rx queues
 * \param queues array of queue indexes
 * \param func RSS hash function
 * \param set_key flag to set RSS hash key and its length
 * \return struct rte_flow_action_rss RSS action configuration
 *         to be used in a rule
 */
struct rte_flow_action_rss DPDKInitRSSAction(struct rte_eth_rss_conf rss_conf, int nb_rx_queues,
        uint16_t *queues, enum rte_eth_hash_function func, bool set_key)
{
    struct rte_flow_action_rss rss_action_conf = { 0 };
    rss_action_conf.func = func;
    rss_action_conf.level = 0;

    if (set_key) {
        rss_action_conf.key = rss_conf.rss_key;
        rss_action_conf.key_len = rss_conf.rss_key_len;
    } else {
        rss_action_conf.key = NULL;
        rss_action_conf.key_len = 0;
    }

    if (nb_rx_queues != 0) {
        for (int i = 0; i < nb_rx_queues; ++i)
            queues[i] = i;

        rss_action_conf.queue = queues;
    } else {
        rss_action_conf.queue = NULL;
    }
    rss_action_conf.queue_num = nb_rx_queues;

    return rss_action_conf;
}

/**
 * \brief Creates RTE_FLOW RSS rule used by NIC drivers
 *        to redistribute packets to different queues based
 *        on IP adresses.
 *
 * \param port_id The port identifier of the Ethernet device
 * \param port_name The port name of the Ethernet device
 * \param rss_conf RSS configuration
 * \return int 0 on success, a negative errno value otherwise
 */
int DPDKCreateRSSFlowGeneric(
        int port_id, const char *port_name, struct rte_flow_action_rss rss_conf)
{
    struct rte_flow_attr attr = { 0 };
    struct rte_flow_action action[] = { { 0 }, { 0 } };
    struct rte_flow_error flow_error = { 0 };
    struct rte_flow_item pattern[] = { { 0 }, { 0 } };

    rss_conf.types = RTE_ETH_RSS_IPV4 | RTE_ETH_RSS_IPV6;

    attr.ingress = 1;
    action[0].type = RTE_FLOW_ACTION_TYPE_RSS;
    action[0].conf = &rss_conf;
    action[1].type = RTE_FLOW_ACTION_TYPE_END;

    pattern[0].type = RTE_FLOW_ITEM_TYPE_ETH;
    pattern[1].type = RTE_FLOW_ITEM_TYPE_END;

    struct rte_flow *flow = rte_flow_create(port_id, &attr, pattern, action, &flow_error);
    if (flow == NULL) {
        SCLogError("%s: rte_flow rule creation error: %s", port_name, flow_error.message);
        int ret = rte_flow_validate(port_id, &attr, pattern, action, &flow_error);
        SCLogError("%s: rte_flow rule validation error: %s, errmsg: %s", port_name,
                rte_strerror(-ret), flow_error.message);
        return ret;
    } else {
        SCLogDebug("%s: rte_flow rule created", port_name);
    }

    return 0;
}

/**
 * \brief Create RTE_FLOW RSS rule configured with pattern and rss_type
 *        but with no rx_queues configured. This is specific way of setting RTE_FLOW RSS rule
 *        for some drivers (mostly Intel NICs). This function's call must be preceded by
 *        call to function DeviceSetRSSFlowQueues().
 *
 * \param port_id The port identifier of the Ethernet device
 * \param port_name The port name of the Ethernet device
 * \param rss_conf RSS configuration
 * \param rss_type RSS hash type - only this type is used when creating hash with RSS hash function
 * \param pattern pattern to match incoming traffic
 * \return int 0 on success, a negative errno value otherwise
 */
int DPDKCreateRSSFlow(int port_id, const char *port_name, struct rte_flow_action_rss rss_conf,
        uint64_t rss_type, struct rte_flow_item *pattern)
{
    struct rte_flow_attr attr = { 0 };
    struct rte_flow_action action[] = { { 0 }, { 0 } };
    struct rte_flow_error flow_error = { 0 };

    rss_conf.types = rss_type;

    attr.ingress = 1;
    action[0].type = RTE_FLOW_ACTION_TYPE_RSS;
    action[0].conf = &rss_conf;
    action[1].type = RTE_FLOW_ACTION_TYPE_END;

    struct rte_flow *flow = rte_flow_create(port_id, &attr, pattern, action, &flow_error);
    if (flow == NULL) {
        SCLogError("%s: rte_flow rule creation error: %s", port_name, flow_error.message);
        int ret = rte_flow_validate(port_id, &attr, pattern, action, &flow_error);
        SCLogError("%s: rte_flow rule validation error: %s, errmsg: %s", port_name,
                rte_strerror(-ret), flow_error.message);
        return ret;
    } else {
        SCLogDebug("%s: rte_flow rule created", port_name);
    }

    return 0;
}

/**
 * \brief Some drivers (mostly Intel NICs) require specific way of setting RTE_FLOW RSS rules
 *        with one rule that sets up only queues and other rules that specify patterns to match with
 *        queues configured (created with function DeviceCreateRSSFlow() that should follow after
 *        this function's call).
 *
 * \param port_id The port identifier of the Ethernet device
 * \param port_name The port name of the Ethernet device
 * \param rss_conf RSS configuration
 * \return int 0 on success, a negative errno value otherwise
 */
int DPDKSetRSSFlowQueues(int port_id, const char *port_name, struct rte_flow_action_rss rss_conf)
{
    struct rte_flow_attr attr = { 0 };
    struct rte_flow_item pattern[] = { { 0 } };
    struct rte_flow_action action[] = { { 0 }, { 0 } };
    struct rte_flow_error flow_error = { 0 };

    rss_conf.types = 0; // queues region can not be configured with types

    attr.ingress = 1;
    pattern[0].type = RTE_FLOW_ITEM_TYPE_END;
    action[0].type = RTE_FLOW_ACTION_TYPE_RSS;
    action[0].conf = &rss_conf;
    action[1].type = RTE_FLOW_ACTION_TYPE_END;

    struct rte_flow *flow = rte_flow_create(port_id, &attr, pattern, action, &flow_error);
    if (flow == NULL) {
        SCLogError("%s: rte_flow rule creation error: %s", port_name, flow_error.message);
        int ret = rte_flow_validate(port_id, &attr, pattern, action, &flow_error);
        SCLogError("%s: rte_flow rule validation error: %s, errmsg: %s", port_name,
                rte_strerror(-ret), flow_error.message);
        return ret;
    } else {
        SCLogDebug("%s: rte_flow rule created", port_name);
    }
    return 0;
}

#endif /* HAVE_DPDK */
/**
 * @}
 */
