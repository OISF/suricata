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

#ifndef UTIL_DPDK_BONDING_C
#define UTIL_DPDK_BONDING_C

#include "suricata-common.h"
#include "util-dpdk-bonding.h"

#ifdef HAVE_DPDK

#include "util-dpdk.h"
#include "util-debug.h"

/**
 * Determines if the port is Bond or not by evaluating device driver name
 * @param pid port ID
 * @return 0 - the device si Bond PMD, 1 - regular device, <0 error
 */
int32_t BondingIsBond(uint16_t pid)
{
    struct rte_eth_dev_info di;
    int32_t ret = rte_eth_dev_info_get(pid, &di);
    if (ret < 0) {
        SCLogError("%s: unable to get device info (err: %s)", DPDKGetPortNameByPortID(pid),
                rte_strerror(-ret));
        return ret;
    }

    return strcmp(di.driver_name, "net_bonding") == 0 ? 0 : 1;
}

uint16_t BondingMemberDevicesGet(
        uint16_t bond_pid, uint16_t bonded_devs[], uint16_t bonded_devs_length)
{
#ifdef HAVE_DPDK_BOND
#if RTE_VERSION >= RTE_VERSION_NUM(23, 11, 0, 0)

#if RTE_VERSION < RTE_VERSION_NUM(24, 11, 0, 0) // DPDK 23.11 - 24.07
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
#endif /* RTE_VERSION < RTE_VERSION_NUM(24, 11, 0, 0) */

    int32_t len = rte_eth_bond_members_get(bond_pid, bonded_devs, bonded_devs_length);

#if RTE_VERSION < RTE_VERSION_NUM(24, 11, 0, 0)
#pragma GCC diagnostic pop
#endif /* RTE_VERSION < RTE_VERSION_NUM(24, 11, 0, 0) */

#else
    int32_t len = rte_eth_bond_slaves_get(bond_pid, bonded_devs, bonded_devs_length);
#endif /* RTE_VERSION >= RTE_VERSION_NUM(23, 11, 0, 0) */

    if (len == 0)
        FatalError("%s: no bonded devices found", DPDKGetPortNameByPortID(bond_pid));
    else if (len < 0)
        FatalError("%s: unable to get bonded devices (err: %s)", DPDKGetPortNameByPortID(bond_pid),
                rte_strerror(-len));

    return len;
#else
    FatalError(
            "%s: bond port not supported in DPDK installation", DPDKGetPortNameByPortID(bond_pid));
#endif
}

int32_t BondingAllDevicesSameDriver(uint16_t bond_pid)
{
    uint16_t bonded_devs[RTE_MAX_ETHPORTS] = { 0 };
    uint16_t len = BondingMemberDevicesGet(bond_pid, bonded_devs, RTE_MAX_ETHPORTS);

    const char *driver_name = NULL, *first_driver_name = NULL;
    struct rte_eth_dev_info di = { 0 };

    for (uint16_t i = 0; i < len; i++) {
        int32_t ret = rte_eth_dev_info_get(bonded_devs[i], &di);
        if (ret < 0)
            FatalError("%s: unable to get device info (err: %s)",
                    DPDKGetPortNameByPortID(bonded_devs[i]), rte_strerror(-ret));

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
const char *BondingDeviceDriverGet(uint16_t bond_pid)
{
    uint16_t bonded_devs[RTE_MAX_ETHPORTS] = { 0 };
    BondingMemberDevicesGet(bond_pid, bonded_devs, RTE_MAX_ETHPORTS);

    struct rte_eth_dev_info di = { 0 };
    int32_t ret = rte_eth_dev_info_get(bonded_devs[0], &di);
    if (ret < 0)
        FatalError("%s: unable to get device info (err: %s)",
                DPDKGetPortNameByPortID(bonded_devs[0]), rte_strerror(-ret));

    return di.driver_name;
}

#endif /* HAVE_DPDK */

#endif /* UTIL_DPDK_BONDING_C */
