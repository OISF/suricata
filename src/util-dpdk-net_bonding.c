/* Copyright (C) 2023 Open Information Security Foundation
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
 * \file
 *
 * \author Lukas Sismis <lukas.sismis@gmail.com>
 */

#ifndef UTIL_DPDK_NET_BONDING_C
#define UTIL_DPDK_NET_BONDING_C

#include "util-dpdk-net_bonding.h"
#include "suricata-common.h"

#ifdef HAVE_DPDK

#include "util-dpdk.h"
#include "util-debug.h"

/**
 * Determines if the port is Bond or not by evaluating device driver name
 * @param pid port ID
 * @return 0 - the device si Bond PMD, 1 - regular device, <0 error
 */
int32_t net_bonding_is_port_bond(uint16_t pid)
{
    int32_t ret;
    struct rte_eth_dev_info di;
    ret = rte_eth_dev_info_get(pid, &di);
    if (ret < 0) {
        char dev_name[RTE_ETH_NAME_MAX_LEN];
        int32_t subret = rte_eth_dev_get_name_by_port(pid, dev_name);
        if (ret < 0) {
            SCLogError("Port %d: unable to get port name (err: %s)", pid, rte_strerror(-ret));
            return subret;
        }
        SCLogError("%s: unable to get device info (err: %s)", dev_name, rte_strerror(-ret));
        return ret;
    }

    return strcmp(di.driver_name, "net_bonding") == 0 ? 0 : 1;
}

uint16_t net_bonding_get_bonded_devices(
        uint16_t bond_pid, uint16_t bonded_devs[], uint16_t bonded_devs_length)
{
    int32_t len;
    len = rte_eth_bond_slaves_get(bond_pid, bonded_devs, bonded_devs_length);

    if (len == 0) {
        char dev_name[RTE_ETH_NAME_MAX_LEN];
        int32_t ret = rte_eth_dev_get_name_by_port(bond_pid, dev_name);
        if (ret < 0) {
            FatalError("Error (%s): Failed to obtain port name from port ID %d", rte_strerror(-ret),
                    bond_pid);
        }
        FatalError("Error: unable to get any bonded devices from interface %s", dev_name);
    } else if (len < 0) {
        char dev_name[RTE_ETH_NAME_MAX_LEN];
        int32_t ret = rte_eth_dev_get_name_by_port(bond_pid, dev_name);
        if (ret < 0) {
            FatalError("Error (%s): Failed to obtain port name from port ID %d", rte_strerror(-ret),
                    bond_pid);
        }
        FatalError("Error (%s): unable to retrieve bonded devices from interface %s",
                rte_strerror(-len), dev_name);
    }

    return len;
}

int32_t net_bonding_devices_use_same_driver(uint16_t bond_pid)
{
    uint16_t len;
    uint16_t bonded_devs[RTE_MAX_ETHPORTS] = { 0 };
    len = net_bonding_get_bonded_devices(bond_pid, bonded_devs, RTE_MAX_ETHPORTS);

    const char *driver_name = NULL, *first_driver_name = NULL;
    int32_t ret;
    struct rte_eth_dev_info di = { 0 };

    for (uint16_t i = 0; i < len; i++) {
        ret = rte_eth_dev_info_get(bonded_devs[i], &di);
        if (ret < 0) {
            char dev_name[RTE_ETH_NAME_MAX_LEN];
            int32_t subret = rte_eth_dev_get_name_by_port(bonded_devs[i], dev_name);
            if (subret < 0) {
                FatalError("Error (%s): Failed to obtain port name from port ID %d",
                        rte_strerror(-subret), bonded_devs[0]);
            }
            FatalError(
                    "Error (%s): Failed to obtain device info of %s", rte_strerror(-ret), dev_name);
        }

        if (i == 0) {
            first_driver_name = di.driver_name;
        } else {
            driver_name = di.driver_name;
            if (strncmp(first_driver_name, driver_name,
                        MIN(strlen(first_driver_name), strlen(driver_name))) != 0) {
                return -EINVAL; // inconsistent drivers
            }
        }
    }

    return 0;
}

/**
 * Translates to the driver that is actually used by the bonded ports
 * \param bond_pid
 * \return driver name, FatalError otherwise
 */
const char *net_bonding_device_driver_get(uint16_t bond_pid)
{
    uint16_t bonded_devs[RTE_MAX_ETHPORTS] = { 0 };
    net_bonding_get_bonded_devices(bond_pid, bonded_devs, RTE_MAX_ETHPORTS);

    int32_t ret;
    struct rte_eth_dev_info di = { 0 };
    ret = rte_eth_dev_info_get(bonded_devs[0], &di);
    if (ret < 0) {
        char dev_name[RTE_ETH_NAME_MAX_LEN];
        int32_t subret = rte_eth_dev_get_name_by_port(bonded_devs[0], dev_name);
        if (subret < 0) {
            FatalError("Error (%s): Failed to obtain port name from port ID %d",
                    rte_strerror(-subret), bonded_devs[0]);
        }
        FatalError("Error (%s): Failed to obtain device info of %s", rte_strerror(-ret), dev_name);
    }
    return di.driver_name;
}

#endif /* HAVE_DPDK */

#endif /* UTIL_DPDK_NET_BONDING_C */
