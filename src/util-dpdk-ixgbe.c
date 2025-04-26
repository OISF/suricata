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
 *  \defgroup dpdk DPDK Intel IXGBE driver helpers functions
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

#include "util-dpdk-ixgbe.h"
#include "util-dpdk.h"
#include "util-debug.h"
#include "util-dpdk-bonding.h"
#include "util-dpdk-rss.h"

#ifdef HAVE_DPDK

#define IXGBE_RSS_HKEY_LEN 40

void ixgbeDeviceSetRSSHashFunction(uint64_t *rss_hf)
{
    *rss_hf = RTE_ETH_RSS_IPV4 | RTE_ETH_RSS_IPV6 | RTE_ETH_RSS_IPV6_EX;
}

int ixgbeDeviceSetRSS(int port_id, uint16_t nb_rx_queues, char *port_name)
{
    uint16_t queues[RTE_MAX_QUEUES_PER_PORT];
    struct rte_flow_error flush_error = { 0 };
    struct rte_eth_rss_conf rss_conf = {
        .rss_key = RSS_HKEY,
        .rss_key_len = IXGBE_RSS_HKEY_LEN,
    };

    if (nb_rx_queues < 1) {
        FatalError("The number of queues for RSS configuration must be "
                   "configured with a positive number");
    }

    struct rte_flow_action_rss rss_action_conf =
            DPDKInitRSSAction(rss_conf, nb_rx_queues, queues, RTE_ETH_HASH_FUNCTION_DEFAULT, true);

    int retval = DPDKCreateRSSFlowGeneric(port_id, port_name, rss_action_conf);
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

#endif /* HAVE_DPDK */
/**
 * @}
 */
