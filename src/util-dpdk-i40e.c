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
 *  \defgroup dpdk DPDK Intel I40E driver helpers functions
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

#include "util-dpdk-i40e.h"
#include "util-dpdk.h"
#include "util-debug.h"
#include "util-dpdk-rss.h"

#ifdef HAVE_DPDK

#define I40E_RSS_HKEY_LEN      52
#define I40E_RSS_HASH_FUNCTION RTE_ETH_HASH_FUNCTION_TOEPLITZ

static int i40eDeviceSetRSSFlowIPv4(
        int port_id, const char *port_name, struct rte_flow_action_rss rss_conf)
{
    int ret = 0;
    struct rte_flow_item pattern[] = { { 0 }, { 0 }, { 0 }, { 0 } };

    pattern[0].type = RTE_FLOW_ITEM_TYPE_ETH;
    pattern[1].type = RTE_FLOW_ITEM_TYPE_IPV4;
    pattern[2].type = RTE_FLOW_ITEM_TYPE_END;
    ret |= DPDKCreateRSSFlow(port_id, port_name, rss_conf,
            RTE_ETH_RSS_NONFRAG_IPV4_OTHER | RTE_ETH_RSS_L3_SRC_ONLY | RTE_ETH_RSS_L3_DST_ONLY,
            pattern);
    memset(pattern, 0, sizeof(pattern));

    pattern[0].type = RTE_FLOW_ITEM_TYPE_ETH;
    pattern[1].type = RTE_FLOW_ITEM_TYPE_IPV4;
    pattern[2].type = RTE_FLOW_ITEM_TYPE_UDP;
    pattern[3].type = RTE_FLOW_ITEM_TYPE_END;
    ret |= DPDKCreateRSSFlow(port_id, port_name, rss_conf,
            RTE_ETH_RSS_NONFRAG_IPV4_UDP | RTE_ETH_RSS_L3_SRC_ONLY | RTE_ETH_RSS_L3_DST_ONLY,
            pattern);
    memset(pattern, 0, sizeof(pattern));

    pattern[0].type = RTE_FLOW_ITEM_TYPE_ETH;
    pattern[1].type = RTE_FLOW_ITEM_TYPE_IPV4;
    pattern[2].type = RTE_FLOW_ITEM_TYPE_TCP;
    pattern[3].type = RTE_FLOW_ITEM_TYPE_END;
    ret |= DPDKCreateRSSFlow(port_id, port_name, rss_conf,
            RTE_ETH_RSS_NONFRAG_IPV4_TCP | RTE_ETH_RSS_L3_SRC_ONLY | RTE_ETH_RSS_L3_DST_ONLY,
            pattern);
    memset(pattern, 0, sizeof(pattern));

    pattern[0].type = RTE_FLOW_ITEM_TYPE_ETH;
    pattern[1].type = RTE_FLOW_ITEM_TYPE_IPV4;
    pattern[2].type = RTE_FLOW_ITEM_TYPE_SCTP;
    pattern[3].type = RTE_FLOW_ITEM_TYPE_END;
    ret |= DPDKCreateRSSFlow(port_id, port_name, rss_conf,
            RTE_ETH_RSS_NONFRAG_IPV4_SCTP | RTE_ETH_RSS_L3_SRC_ONLY | RTE_ETH_RSS_L3_DST_ONLY,
            pattern);
    memset(pattern, 0, sizeof(pattern));

    return ret;
}

static int i40eDeviceSetRSSFlowIPv6(
        int port_id, const char *port_name, struct rte_flow_action_rss rss_conf)
{
    int ret = 0;
    struct rte_flow_item pattern[] = { { 0 }, { 0 }, { 0 }, { 0 } };

    pattern[0].type = RTE_FLOW_ITEM_TYPE_ETH;
    pattern[1].type = RTE_FLOW_ITEM_TYPE_IPV6;
    pattern[2].type = RTE_FLOW_ITEM_TYPE_END;
    ret |= DPDKCreateRSSFlow(port_id, port_name, rss_conf,
            RTE_ETH_RSS_NONFRAG_IPV6_OTHER | RTE_ETH_RSS_L3_SRC_ONLY | RTE_ETH_RSS_L3_DST_ONLY,
            pattern);
    memset(pattern, 0, sizeof(pattern));

    pattern[0].type = RTE_FLOW_ITEM_TYPE_ETH;
    pattern[1].type = RTE_FLOW_ITEM_TYPE_IPV6;
    pattern[2].type = RTE_FLOW_ITEM_TYPE_UDP;
    pattern[3].type = RTE_FLOW_ITEM_TYPE_END;
    ret |= DPDKCreateRSSFlow(port_id, port_name, rss_conf,
            RTE_ETH_RSS_NONFRAG_IPV6_UDP | RTE_ETH_RSS_L3_SRC_ONLY | RTE_ETH_RSS_L3_DST_ONLY,
            pattern);
    memset(pattern, 0, sizeof(pattern));

    pattern[0].type = RTE_FLOW_ITEM_TYPE_ETH;
    pattern[1].type = RTE_FLOW_ITEM_TYPE_IPV6;
    pattern[2].type = RTE_FLOW_ITEM_TYPE_TCP;
    pattern[3].type = RTE_FLOW_ITEM_TYPE_END;
    ret |= DPDKCreateRSSFlow(port_id, port_name, rss_conf,
            RTE_ETH_RSS_NONFRAG_IPV6_TCP | RTE_ETH_RSS_L3_SRC_ONLY | RTE_ETH_RSS_L3_DST_ONLY,
            pattern);
    memset(pattern, 0, sizeof(pattern));

    pattern[0].type = RTE_FLOW_ITEM_TYPE_ETH;
    pattern[1].type = RTE_FLOW_ITEM_TYPE_IPV6;
    pattern[2].type = RTE_FLOW_ITEM_TYPE_SCTP;
    pattern[3].type = RTE_FLOW_ITEM_TYPE_END;
    ret |= DPDKCreateRSSFlow(port_id, port_name, rss_conf,
            RTE_ETH_RSS_NONFRAG_IPV6_SCTP | RTE_ETH_RSS_L3_SRC_ONLY | RTE_ETH_RSS_L3_DST_ONLY,
            pattern);
    memset(pattern, 0, sizeof(pattern));

    return ret;
}

static int i40eDeviceSetRSSWithFlows(int port_id, const char *port_name, int nb_rx_queues)
{
    uint16_t queues[RTE_MAX_QUEUES_PER_PORT];
    struct rte_flow_error flush_error = { 0 };
    struct rte_eth_rss_conf rss_conf = {
        .rss_key = RSS_HKEY,
        .rss_key_len = I40E_RSS_HKEY_LEN,
    };

    if (nb_rx_queues < 1) {
        FatalError("The number of queues for RSS configuration must be "
                   "configured with a positive number");
    }

    struct rte_flow_action_rss rss_action_conf =
            DPDKInitRSSAction(rss_conf, nb_rx_queues, queues, RTE_ETH_HASH_FUNCTION_DEFAULT, false);

    int retval = DPDKSetRSSFlowQueues(port_id, port_name, rss_action_conf);

    memset(&rss_action_conf, 0, sizeof(struct rte_flow_action_rss));
    rss_action_conf = DPDKInitRSSAction(rss_conf, 0, queues, I40E_RSS_HASH_FUNCTION, true);

    retval |= i40eDeviceSetRSSFlowIPv4(port_id, port_name, rss_action_conf);
    retval |= i40eDeviceSetRSSFlowIPv6(port_id, port_name, rss_action_conf);
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

int i40eDeviceSetRSS(int port_id, uint16_t nb_rx_queues, char *port_name)
{
    i40eDeviceSetRSSWithFlows(port_id, port_name, nb_rx_queues);
    return 0;
}

void i40eDeviceSetRSSConf(struct rte_eth_rss_conf *rss_conf)
{
    rss_conf->rss_hf = RTE_ETH_RSS_FRAG_IPV4 | RTE_ETH_RSS_NONFRAG_IPV4_OTHER |
                       RTE_ETH_RSS_FRAG_IPV6 | RTE_ETH_RSS_NONFRAG_IPV6_OTHER;
    rss_conf->rss_key = NULL;
    rss_conf->rss_key_len = 0;
}

#endif /* HAVE_DPDK */
/**
 * @}
 */
