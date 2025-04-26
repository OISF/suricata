/* Copyright (C) 2021-2025 Open Information Security Foundation
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
 *  \defgroup dpdk DPDK Intel ICE driver helpers functions
 *
 *  @{
 */

/**
 * \file
 *
 * \author Lukas Sismis <lukas.sismis@gmail.com>
 *
 * DPDK driver's helper functions
 *
 */

#include "util-dpdk-ice.h"
#include "util-dpdk.h"
#include "util-dpdk-rss.h"
#include "util-debug.h"
#include "util-dpdk-bonding.h"

#ifdef HAVE_DPDK

static void iceDeviceSetRSSHashFunction(uint64_t *rss_hf)
{
#if RTE_VERSION < RTE_VERSION_NUM(20, 0, 0, 0)
    *rss_hf = RTE_ETH_RSS_FRAG_IPV4 | RTE_ETH_RSS_NONFRAG_IPV4_OTHER | RTE_ETH_RSS_FRAG_IPV6 |
              RTE_ETH_RSS_NONFRAG_IPV6_OTHER;
#else
    *rss_hf = RTE_ETH_RSS_IPV4 | RTE_ETH_RSS_FRAG_IPV4 | RTE_ETH_RSS_NONFRAG_IPV4_OTHER |
              RTE_ETH_RSS_IPV6 | RTE_ETH_RSS_FRAG_IPV6 | RTE_ETH_RSS_NONFRAG_IPV6_OTHER;
#endif
}

/**
 * \brief Creates RTE_FLOW pattern to match ipv4 traffic
 *
 * \param port_id The port identifier of the Ethernet device
 * \param port_name The port name of the Ethernet device
 * \param rss_conf RSS configuration
 * \return int 0 on success, a negative errno value otherwise
 */
static int iceDeviceSetRSSFlowIPv4(
        int port_id, const char *port_name, struct rte_flow_action_rss rss_conf)
{
    struct rte_flow_item pattern[] = { { 0 }, { 0 }, { 0 } };

    pattern[0].type = RTE_FLOW_ITEM_TYPE_ETH;
    pattern[1].type = RTE_FLOW_ITEM_TYPE_IPV4;
    pattern[2].type = RTE_FLOW_ITEM_TYPE_END;

    return DPDKCreateRSSFlow(port_id, port_name, rss_conf, RTE_ETH_RSS_IPV4, pattern);
}

/**
 * \brief Creates RTE_FLOW pattern to match ipv6 traffic
 *
 * \param port_id The port identifier of the Ethernet device
 * \param port_name The port name of the Ethernet device
 * \param rss_conf RSS configuration
 * \return int 0 on success, a negative errno value otherwise
 */

static int iceDeviceSetRSSFlowIPv6(
        int port_id, const char *port_name, struct rte_flow_action_rss rss_conf)
{
    struct rte_flow_item pattern[] = { { 0 }, { 0 }, { 0 } };

    pattern[0].type = RTE_FLOW_ITEM_TYPE_ETH;
    pattern[1].type = RTE_FLOW_ITEM_TYPE_IPV6;
    pattern[2].type = RTE_FLOW_ITEM_TYPE_END;

    return DPDKCreateRSSFlow(port_id, port_name, rss_conf, RTE_ETH_RSS_IPV6, pattern);
}

int iceDeviceSetRSS(int port_id, uint16_t nb_rx_queues, char *port_name)
{
    uint16_t queues[RTE_MAX_QUEUES_PER_PORT];
    struct rte_flow_error flush_error = { 0 };
    struct rte_eth_rss_conf rss_conf = { 0 };

    if (nb_rx_queues < 1) {
        FatalError("The number of queues for RSS configuration must be "
                   "configured with a positive number");
    }

    struct rte_flow_action_rss rss_action_conf =
            DPDKInitRSSAction(rss_conf, 0, queues, RTE_ETH_HASH_FUNCTION_TOEPLITZ, false);

    int retval = iceDeviceSetRSSFlowIPv4(port_id, port_name, rss_action_conf);
    retval |= iceDeviceSetRSSFlowIPv6(port_id, port_name, rss_action_conf);
    if (retval != 0) {
        retval = rte_flow_flush(port_id, &flush_error);
        if (retval != 0) {
            SCLogError("%s: unable to flush rte_flow rules: %s Flush error msg: %s", port_name,
                    rte_strerror(-retval), flush_error.message);
        }
        return retval;
    }

    return 0;
}

void iceDeviceSetRSSConf(struct rte_eth_rss_conf *rss_conf)
{
    iceDeviceSetRSSHashFunction(&rss_conf->rss_hf);
    rss_conf->rss_key_len = 52;
}

#endif /* HAVE_DPDK */
/**
 * @}
 */
