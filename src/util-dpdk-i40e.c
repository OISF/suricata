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
#include "util-dpdk-bonding.h"
#include "util-dpdk-rss.h"

#ifdef HAVE_DPDK

#if RTE_VERSION < RTE_VERSION_NUM(21, 0, 0, 0)
#define I40E_RSS_HKEY_LEN      40
#define I40E_RSS_HASH_FUNCTION RTE_ETH_HASH_FUNCTION_SYMMETRIC_TOEPLITZ
#else
#define I40E_RSS_HKEY_LEN      52
#define I40E_RSS_HASH_FUNCTION RTE_ETH_HASH_FUNCTION_TOEPLITZ
#endif // RTE_VERSION < RTE_VERSION_NUM(21, 0, 0, 0)

#if RTE_VERSION < RTE_VERSION_NUM(20, 0, 0, 0)
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
        SCLogError("%s: RTE_ETH_FILTER_HASH not supported", port_name);
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
        SCLogError("%s: cannot set global hash configurations", port_name);
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
        SCLogError("%s: RTE_ETH_FILTER_HASH not supported", port_name);
        return ret;
    }

    info.info_type = RTE_ETH_HASH_FILTER_SYM_HASH_ENA_PER_PORT;
    info.info.enable = enable;
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
    ret = rte_eth_dev_filter_ctrl(port_id, RTE_ETH_FILTER_HASH, RTE_ETH_FILTER_SET, &info);
#pragma GCC diagnostic pop

    if (ret < 0) {
        SCLogError("%s: cannot set symmetric hash enable per port", port_name);
        return ret;
    }

    return 0;
}

static int i40eDeviceApplyRSSFilter(int port_id, const char *port_name)
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

static int32_t i40eDeviceSetRSSWithFilter(int port_id, const char *port_name)
{
    int32_t ret = BondingIsBond(port_id);
    if (ret < 0)
        return -ret;

    if (ret == 1) { // regular device
        i40eDeviceApplyRSSFilter(port_id, port_name);
    } else if (ret == 0) { // the device is Bond PMD
        uint16_t bonded_devs[RTE_MAX_ETHPORTS];
        ret = BondingMemberDevicesGet(port_id, bonded_devs, RTE_MAX_ETHPORTS);
        for (int i = 0; i < ret; i++) {
            i40eDeviceApplyRSSFilter(bonded_devs[i], port_name);
        }
    } else {
        FatalError("Unknown return value from BondingIsBond()");
    }

    return 0;
}

#else

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

#endif /* RTE_VERSION < RTE_VERSION_NUM(20,0,0,0) */

int i40eDeviceSetRSS(int port_id, uint16_t nb_rx_queues, char *port_name)
{
    (void)nb_rx_queues; // avoid unused variable warnings

#if RTE_VERSION >= RTE_VERSION_NUM(20, 0, 0, 0)
    i40eDeviceSetRSSWithFlows(port_id, port_name, nb_rx_queues);
#else
    i40eDeviceSetRSSWithFilter(port_id, port_name);
#endif
    return 0;
}

void i40eDeviceSetRSSConf(struct rte_eth_rss_conf *rss_conf)
{
#if RTE_VERSION >= RTE_VERSION_NUM(20, 0, 0, 0)
    rss_conf->rss_hf = RTE_ETH_RSS_FRAG_IPV4 | RTE_ETH_RSS_NONFRAG_IPV4_OTHER |
                       RTE_ETH_RSS_FRAG_IPV6 | RTE_ETH_RSS_NONFRAG_IPV6_OTHER;
    rss_conf->rss_key = NULL;
    rss_conf->rss_key_len = 0;
#else
    rss_conf->rss_hf =
            RTE_ETH_RSS_FRAG_IPV4 | RTE_ETH_RSS_NONFRAG_IPV4_TCP | RTE_ETH_RSS_NONFRAG_IPV4_UDP |
            RTE_ETH_RSS_NONFRAG_IPV4_SCTP | RTE_ETH_RSS_NONFRAG_IPV4_OTHER | RTE_ETH_RSS_FRAG_IPV6 |
            RTE_ETH_RSS_NONFRAG_IPV6_TCP | RTE_ETH_RSS_NONFRAG_IPV6_UDP |
            RTE_ETH_RSS_NONFRAG_IPV6_SCTP | RTE_ETH_RSS_NONFRAG_IPV6_OTHER | RTE_ETH_RSS_SCTP;
#endif
}

#endif /* HAVE_DPDK */
/**
 * @}
 */
