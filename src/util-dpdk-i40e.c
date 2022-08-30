/* Copyright (C) 2021-2022 Open Information Security Foundation
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

#ifdef HAVE_DPDK

#define I40E_RSS_HKEY_LEN 52

#if RTE_VER_YEAR <= 19
static int i40eDeviceEnableSymHash(
        int port_id, const char *port_name, uint32_t ftype, enum rte_eth_hash_function function)
{
    struct rte_eth_hash_filter_info info;
    int retval;
    uint32_t idx, offset;

    memset(&info, 0, sizeof(info));

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
    retval = rte_eth_dev_filter_supported(port_id, RTE_ETH_FILTER_HASH);
#pragma GCC diagnostic pop
    if (retval < 0) {
        SCLogError(SC_ERR_DPDK_CONF, "RTE_ETH_FILTER_HASH not supported on port: %s", port_name);
        return retval;
    }

    info.info_type = RTE_ETH_HASH_FILTER_GLOBAL_CONFIG;
    info.info.global_conf.hash_func = function;

    idx = ftype / UINT64_BIT;
    offset = ftype % UINT64_BIT;
    info.info.global_conf.valid_bit_mask[idx] |= (1ULL << offset);
    info.info.global_conf.sym_hash_enable_mask[idx] |= (1ULL << offset);

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
    retval = rte_eth_dev_filter_ctrl(port_id, RTE_ETH_FILTER_HASH, RTE_ETH_FILTER_SET, &info);
#pragma GCC diagnostic pop

    if (retval < 0) {
        SCLogError(SC_ERR_DPDK_CONF, "Cannot set global hash configurations on port %s", port_name);
        return retval;
    }

    return 0;
}

static int i40eDeviceSetSymHash(int port_id, const char *port_name, int enable)
{
    int ret;
    struct rte_eth_hash_filter_info info;

    memset(&info, 0, sizeof(info));

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
    ret = rte_eth_dev_filter_supported(port_id, RTE_ETH_FILTER_HASH);
#pragma GCC diagnostic pop

    if (ret < 0) {
        SCLogError(SC_ERR_DPDK_CONF, "RTE_ETH_FILTER_HASH not supported on port: %s", port_name);
        return ret;
    }

    info.info_type = RTE_ETH_HASH_FILTER_SYM_HASH_ENA_PER_PORT;
    info.info.enable = enable;
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
    ret = rte_eth_dev_filter_ctrl(port_id, RTE_ETH_FILTER_HASH, RTE_ETH_FILTER_SET, &info);
#pragma GCC diagnostic pop

    if (ret < 0) {
        SCLogError(SC_ERR_DPDK_CONF, "Cannot set symmetric hash enable per port on port %s",
                port_name);
        return ret;
    }

    return 0;
}

static int i40eDeviceSetRSSWithFilter(int port_id, const char *port_name)
{
    int retval = 0;

    // Behavior of RTE_FLOW in DPDK version 19.xx and less is different than on versions
    // above. For that reason RSS on i40e driver is set differently.
    retval |= i40eDeviceEnableSymHash(
            port_id, port_name, RTE_ETH_FLOW_FRAG_IPV4, RTE_ETH_HASH_FUNCTION_TOEPLITZ);
    retval |= i40eDeviceEnableSymHash(
            port_id, port_name, RTE_ETH_FLOW_NONFRAG_IPV4_TCP, RTE_ETH_HASH_FUNCTION_TOEPLITZ);
    retval |= i40eDeviceEnableSymHash(
            port_id, port_name, RTE_ETH_FLOW_NONFRAG_IPV4_UDP, RTE_ETH_HASH_FUNCTION_TOEPLITZ);
    retval |= i40eDeviceEnableSymHash(
            port_id, port_name, RTE_ETH_FLOW_NONFRAG_IPV4_SCTP, RTE_ETH_HASH_FUNCTION_TOEPLITZ);
    retval |= i40eDeviceEnableSymHash(
            port_id, port_name, RTE_ETH_FLOW_NONFRAG_IPV4_OTHER, RTE_ETH_HASH_FUNCTION_TOEPLITZ);

    retval |= i40eDeviceEnableSymHash(
            port_id, port_name, RTE_ETH_FLOW_FRAG_IPV6, RTE_ETH_HASH_FUNCTION_TOEPLITZ);
    retval |= i40eDeviceEnableSymHash(
            port_id, port_name, RTE_ETH_FLOW_NONFRAG_IPV6_TCP, RTE_ETH_HASH_FUNCTION_TOEPLITZ);
    retval |= i40eDeviceEnableSymHash(
            port_id, port_name, RTE_ETH_FLOW_NONFRAG_IPV6_UDP, RTE_ETH_HASH_FUNCTION_TOEPLITZ);
    retval |= i40eDeviceEnableSymHash(
            port_id, port_name, RTE_ETH_FLOW_NONFRAG_IPV6_SCTP, RTE_ETH_HASH_FUNCTION_TOEPLITZ);
    retval |= i40eDeviceEnableSymHash(
            port_id, port_name, RTE_ETH_FLOW_NONFRAG_IPV6_OTHER, RTE_ETH_HASH_FUNCTION_TOEPLITZ);

    retval |= i40eDeviceSetSymHash(port_id, port_name, 1);
    return retval;
}

#else

static int i40eDeviceSetRSSFlowQueues(
        int port_id, const char *port_name, struct rte_eth_rss_conf rss_conf, int nb_rx_queues)
{
    struct rte_flow_action_rss rss_action_conf = { 0 };
    struct rte_flow_attr attr = { 0 };
    struct rte_flow_item pattern[] = { { 0 }, { 0 }, { 0 }, { 0 } };
    struct rte_flow_action action[] = { { 0 }, { 0 } };
    struct rte_flow *flow;
    struct rte_flow_error flow_error = { 0 };
    uint16_t queues[RTE_MAX_QUEUES_PER_PORT];

    for (int i = 0; i < nb_rx_queues; ++i)
        queues[i] = i;

    rss_action_conf.func = RTE_ETH_HASH_FUNCTION_DEFAULT;
    rss_action_conf.level = 0;
    rss_action_conf.types = 0; // queues region can not be configured with types
    rss_action_conf.key = rss_conf.rss_key;
    rss_action_conf.key_len = rss_conf.rss_key_len;
    rss_action_conf.queue_num = nb_rx_queues;
    rss_action_conf.queue = queues;

    attr.ingress = 1;
    pattern[0].type = RTE_FLOW_ITEM_TYPE_END;
    action[0].type = RTE_FLOW_ACTION_TYPE_RSS;
    action[0].conf = &rss_action_conf;
    action[1].type = RTE_FLOW_ACTION_TYPE_END;

    flow = rte_flow_create(port_id, &attr, pattern, action, &flow_error);
    if (flow == NULL) {
        SCLogError(SC_ERR_DPDK_CONF, "Error when creating rte_flow rule on %s: %s", port_name,
                flow_error.message);
        int ret = rte_flow_validate(port_id, &attr, pattern, action, &flow_error);
        SCLogError(SC_ERR_DPDK_CONF, "Error on rte_flow validation for port %s: %s errmsg: %s",
                port_name, rte_strerror(-ret), flow_error.message);
        return ret;
    } else {
        SCLogInfo("RTE_FLOW queue region created for port %s", port_name);
    }
    return 0;
}

static int i40eDeviceCreateRSSFlow(int port_id, const char *port_name,
        struct rte_eth_rss_conf rss_conf, uint64_t rss_type, struct rte_flow_item *pattern)
{
    struct rte_flow_action_rss rss_action_conf = { 0 };
    struct rte_flow_attr attr = { 0 };
    struct rte_flow_action action[] = { { 0 }, { 0 } };
    struct rte_flow *flow;
    struct rte_flow_error flow_error = { 0 };

    rss_action_conf.func = RTE_ETH_HASH_FUNCTION_SYMMETRIC_TOEPLITZ;
    rss_action_conf.level = 0;
    rss_action_conf.types = rss_type;
    rss_action_conf.key_len = rss_conf.rss_key_len;
    rss_action_conf.key = rss_conf.rss_key;
    rss_action_conf.queue_num = 0;
    rss_action_conf.queue = NULL;

    attr.ingress = 1;
    action[0].type = RTE_FLOW_ACTION_TYPE_RSS;
    action[0].conf = &rss_action_conf;
    action[1].type = RTE_FLOW_ACTION_TYPE_END;

    flow = rte_flow_create(port_id, &attr, pattern, action, &flow_error);
    if (flow == NULL) {
        SCLogError(SC_ERR_DPDK_CONF, "Error when creating rte_flow rule on %s: %s", port_name,
                flow_error.message);
        int ret = rte_flow_validate(port_id, &attr, pattern, action, &flow_error);
        SCLogError(SC_ERR_DPDK_CONF, "Error on rte_flow validation for port %s: %s errmsg: %s",
                port_name, rte_strerror(-ret), flow_error.message);
        return ret;
    } else {
        SCLogInfo("RTE_FLOW flow rule created for port %s", port_name);
    }

    return 0;
}

static int i40eDeviceSetRSSFlowIPv4(
        int port_id, const char *port_name, struct rte_eth_rss_conf rss_conf)
{
    int ret = 0;
    struct rte_flow_item pattern[] = { { 0 }, { 0 }, { 0 }, { 0 } };

    pattern[0].type = RTE_FLOW_ITEM_TYPE_ETH;
    pattern[1].type = RTE_FLOW_ITEM_TYPE_IPV4;
    pattern[2].type = RTE_FLOW_ITEM_TYPE_END;
    ret |= i40eDeviceCreateRSSFlow(
            port_id, port_name, rss_conf, ETH_RSS_NONFRAG_IPV4_OTHER, pattern);
    memset(pattern, 0, sizeof(pattern));

    pattern[0].type = RTE_FLOW_ITEM_TYPE_ETH;
    pattern[1].type = RTE_FLOW_ITEM_TYPE_IPV4;
    pattern[2].type = RTE_FLOW_ITEM_TYPE_UDP;
    pattern[3].type = RTE_FLOW_ITEM_TYPE_END;
    ret |= i40eDeviceCreateRSSFlow(port_id, port_name, rss_conf, ETH_RSS_NONFRAG_IPV4_UDP, pattern);
    memset(pattern, 0, sizeof(pattern));

    pattern[0].type = RTE_FLOW_ITEM_TYPE_ETH;
    pattern[1].type = RTE_FLOW_ITEM_TYPE_IPV4;
    pattern[2].type = RTE_FLOW_ITEM_TYPE_TCP;
    pattern[3].type = RTE_FLOW_ITEM_TYPE_END;
    ret |= i40eDeviceCreateRSSFlow(port_id, port_name, rss_conf, ETH_RSS_NONFRAG_IPV4_TCP, pattern);
    memset(pattern, 0, sizeof(pattern));

    pattern[0].type = RTE_FLOW_ITEM_TYPE_ETH;
    pattern[1].type = RTE_FLOW_ITEM_TYPE_IPV4;
    pattern[2].type = RTE_FLOW_ITEM_TYPE_SCTP;
    pattern[3].type = RTE_FLOW_ITEM_TYPE_END;
    ret |= i40eDeviceCreateRSSFlow(
            port_id, port_name, rss_conf, ETH_RSS_NONFRAG_IPV4_SCTP, pattern);
    memset(pattern, 0, sizeof(pattern));

    pattern[0].type = RTE_FLOW_ITEM_TYPE_ETH;
    pattern[1].type = RTE_FLOW_ITEM_TYPE_IPV4;
    pattern[2].type = RTE_FLOW_ITEM_TYPE_END;
    ret |= i40eDeviceCreateRSSFlow(port_id, port_name, rss_conf, ETH_RSS_FRAG_IPV4, pattern);

    return ret;
}

static int i40eDeviceSetRSSFlowIPv6(
        int port_id, const char *port_name, struct rte_eth_rss_conf rss_conf)
{
    int ret = 0;
    struct rte_flow_item pattern[] = { { 0 }, { 0 }, { 0 }, { 0 } };

    pattern[0].type = RTE_FLOW_ITEM_TYPE_ETH;
    pattern[1].type = RTE_FLOW_ITEM_TYPE_IPV6;
    pattern[2].type = RTE_FLOW_ITEM_TYPE_END;
    ret |= i40eDeviceCreateRSSFlow(
            port_id, port_name, rss_conf, ETH_RSS_NONFRAG_IPV6_OTHER, pattern);
    memset(pattern, 0, sizeof(pattern));

    pattern[0].type = RTE_FLOW_ITEM_TYPE_ETH;
    pattern[1].type = RTE_FLOW_ITEM_TYPE_IPV6;
    pattern[2].type = RTE_FLOW_ITEM_TYPE_UDP;
    pattern[3].type = RTE_FLOW_ITEM_TYPE_END;
    ret |= i40eDeviceCreateRSSFlow(port_id, port_name, rss_conf, ETH_RSS_NONFRAG_IPV6_UDP, pattern);
    memset(pattern, 0, sizeof(pattern));

    pattern[0].type = RTE_FLOW_ITEM_TYPE_ETH;
    pattern[1].type = RTE_FLOW_ITEM_TYPE_IPV6;
    pattern[2].type = RTE_FLOW_ITEM_TYPE_TCP;
    pattern[3].type = RTE_FLOW_ITEM_TYPE_END;
    ret |= i40eDeviceCreateRSSFlow(port_id, port_name, rss_conf, ETH_RSS_NONFRAG_IPV6_TCP, pattern);
    memset(pattern, 0, sizeof(pattern));

    pattern[0].type = RTE_FLOW_ITEM_TYPE_ETH;
    pattern[1].type = RTE_FLOW_ITEM_TYPE_IPV6;
    pattern[2].type = RTE_FLOW_ITEM_TYPE_SCTP;
    pattern[3].type = RTE_FLOW_ITEM_TYPE_END;
    ret |= i40eDeviceCreateRSSFlow(
            port_id, port_name, rss_conf, ETH_RSS_NONFRAG_IPV6_SCTP, pattern);
    memset(pattern, 0, sizeof(pattern));

    pattern[0].type = RTE_FLOW_ITEM_TYPE_ETH;
    pattern[1].type = RTE_FLOW_ITEM_TYPE_IPV6;
    pattern[2].type = RTE_FLOW_ITEM_TYPE_END;
    ret |= i40eDeviceCreateRSSFlow(port_id, port_name, rss_conf, ETH_RSS_FRAG_IPV6, pattern);

    return ret;
}

static int i40eDeviceSetRSSWithFlows(int port_id, const char *port_name, int nb_rx_queues)
{
    int retval;
    uint8_t rss_key[I40E_RSS_HKEY_LEN];
    struct rte_flow_error flush_error = { 0 };
    struct rte_eth_rss_conf rss_conf = {
        .rss_key = rss_key,
        .rss_key_len = I40E_RSS_HKEY_LEN,
    };

    retval = rte_eth_dev_rss_hash_conf_get(port_id, &rss_conf);
    if (retval != 0) {
        SCLogError(SC_ERR_DPDK_CONF, "Unable to get RSS hash configuration of port %s", port_name);
        return retval;
    }

    retval = 0;
    retval |= i40eDeviceSetRSSFlowQueues(port_id, port_name, rss_conf, nb_rx_queues);
    retval |= i40eDeviceSetRSSFlowIPv4(port_id, port_name, rss_conf);
    retval |= i40eDeviceSetRSSFlowIPv6(port_id, port_name, rss_conf);
    if (retval != 0) {
        retval = rte_flow_flush(port_id, &flush_error);
        if (retval != 0) {
            SCLogError(SC_ERR_DPDK_CONF,
                    "Unable to flush rte_flow rules of %s: %s Flush error msg: %s", port_name,
                    rte_strerror(-retval), flush_error.message);
        }
        return retval;
    }

    return 0;
}

#endif /* RTE_VER_YEAR < 19 */

int i40eDeviceSetRSS(int port_id, int nb_rx_queues)
{
    int retval;
    (void)nb_rx_queues; // avoid unused variable warnings
    char port_name[RTE_ETH_NAME_MAX_LEN];

    retval = rte_eth_dev_get_name_by_port(port_id, port_name);
    if (unlikely(retval != 0)) {
        SCLogError(SC_ERR_STAT, "Failed to convert port id %d to the interface name: %s", port_id,
                strerror(-retval));
        return retval;
    }

#if RTE_VER_YEAR <= 19
    i40eDeviceSetRSSWithFilter(port_id, port_name);
#else
    i40eDeviceSetRSSWithFlows(port_id, port_name, nb_rx_queues);
#endif
    return 0;
}

void i40eDeviceSetRSSHashFunction(uint64_t *rss_hf)
{
    if (RTE_VER_YEAR <= 19)
        *rss_hf = ETH_RSS_FRAG_IPV4 | ETH_RSS_NONFRAG_IPV4_TCP | ETH_RSS_NONFRAG_IPV4_UDP |
                  ETH_RSS_NONFRAG_IPV4_SCTP | ETH_RSS_NONFRAG_IPV4_OTHER | ETH_RSS_FRAG_IPV6 |
                  ETH_RSS_NONFRAG_IPV6_TCP | ETH_RSS_NONFRAG_IPV6_UDP | ETH_RSS_NONFRAG_IPV6_SCTP |
                  ETH_RSS_NONFRAG_IPV6_OTHER | ETH_RSS_SCTP;
    else
        *rss_hf = ETH_RSS_FRAG_IPV4 | ETH_RSS_NONFRAG_IPV4_OTHER | ETH_RSS_FRAG_IPV6 |
                  ETH_RSS_NONFRAG_IPV6_OTHER;
}

#endif /* HAVE_DPDK */
/**
 * @}
 */
