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
 *  \defgroup dpdk DPDK NVIDIA mlx5 driver helpers functions
 *
 *  @{
 */

/**
 * \file
 *
 * \author Adam Kiripolsky <adam.kiripolsky@cesnet.cz>
 *
 * DPDK driver's helper functions
 *
 */

#include "decode.h"
#include "util-debug.h"
#include "util-dpdk.h"
#include "source-dpdk.h"
#include "util-dpdk-bonding.h"
#include "util-dpdk-mlx5.h"
#include "util-dpdk-rss.h"
#include "util-dpdk-rte-flow.h"

#ifdef HAVE_DPDK

#define MLX5_RSS_HKEY_LEN 40

static int mlx5DeviceSetRSS(int, uint16_t, char *, uint16_t);

/**
 * \brief Post-start device actions specific to the mlx5 driver: create the
 *        rte_flow jump rule for capture bypass (if enabled) and install the
 *        RSS steering rule into the appropriate flow group.
 *
 * \param port_id port id of the device
 * \param nb_rx_queues number of RX queues of the device
 * \param port_name name of the device's port
 * \param dpdk_vars DPDK device resources of the device
 * \param dpdk_config configuration of the device
 * \return int 0 on success, negative value on error
 */
int mlx5DevicePostStartActions(int port_id, uint16_t nb_rx_queues, char *port_name,
        DPDKDeviceResources *dpdk_vars, DPDKIfaceConfig *dpdk_config)
{
    int retval = 0;
    uint16_t group = RTE_GROUP_DEFAULT;

    if (dpdk_config->capture_bypass_enabled) {
        retval = RteFlowCreateJumpRule(port_id, port_name);
        if (retval != 0) {
            SCLogError("%s: rte_flow jump rule creation failed, capture-bypass not supported on "
                       "this interface",
                    port_name);
            SCReturnInt(-ENOTSUP);
        } else {
            group = RTE_GROUP_JUMP;
        }
    }
    retval = mlx5DeviceSetRSS(port_id, nb_rx_queues, port_name, group);
    return retval;
}

static int mlx5DeviceSetRSS(int port_id, uint16_t nb_rx_queues, char *port_name, uint16_t group)
{
    uint16_t queues[RTE_MAX_QUEUES_PER_PORT];
    struct rte_flow_error flush_error = { 0 };
    struct rte_eth_rss_conf rss_conf = {
        .rss_key = RSS_HKEY,
        .rss_key_len = MLX5_RSS_HKEY_LEN,
    };

    if (nb_rx_queues < 1) {
        FatalError("The number of queues for RSS configuration must be "
                   "configured with a positive number");
    }

    struct rte_flow_action_rss rss_action_conf =
            DPDKInitRSSAction(rss_conf, nb_rx_queues, queues, RTE_ETH_HASH_FUNCTION_TOEPLITZ, true);

    int retval = DPDKCreateRSSFlowGeneric(
            port_id, port_name, rss_action_conf, group, RTE_PRIORITY_LOW_1);
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
