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

/**
 * \brief Callback for rte_kvargs_process that increments a counter.
 */
static int BondingMemberCountCb(
        const char *key __rte_unused, const char *value __rte_unused, void *opaque)
{
    uint16_t *cnt = opaque;
    (*cnt)++;
    return 0;
}

/**
 * \brief Count bonding member devices from the device's devargs.
 *
 * Bonding members are only attached when rte_eth_dev_configure() is called
 * (inside bond_ethdev_configure), so rte_eth_bond_members_get() returns 0
 * during early config. Instead, parse the devargs stored during device probe
 * to count member/slave entries.
 *
 * \param dev_info device info (must be non-NULL)
 * \return number of member devices found, 0 on any failure
 */
static uint16_t BondingMemberDevCountFromDevargs(const struct rte_eth_dev_info *dev_info)
{
    if (dev_info->device == NULL) {
        return 0;
    }

#if RTE_VERSION >= RTE_VERSION_NUM(22, 11, 0, 0)
    const struct rte_devargs *devargs = rte_dev_devargs(dev_info->device);
#else
    const struct rte_devargs *devargs = dev_info->device->devargs;
#endif
    if (devargs == NULL || devargs->args == NULL) {
        return 0;
    }

    struct rte_kvargs *kvargs = rte_kvargs_parse(devargs->args, NULL);
    if (kvargs == NULL) {
        return 0;
    }

    uint16_t count = 0;
#if RTE_VERSION >= RTE_VERSION_NUM(23, 11, 0, 0)
    rte_kvargs_process(kvargs, "member", BondingMemberCountCb, &count);
#else
    rte_kvargs_process(kvargs, "slave", BondingMemberCountCb, &count);
#endif

    rte_kvargs_free(kvargs);
    return count;
}

uint32_t BondingMempoolSizeCalculate(
        uint16_t bond_pid, const struct rte_eth_dev_info *dev_info, uint32_t curr_mempool_size)
{
    if (curr_mempool_size == 0) {
        return 0;
    }

    uint16_t cnt = BondingMemberDevCountFromDevargs(dev_info);
    if (cnt == 0) {
        // don't adjust if unable to determine the number of bonded devices
        return curr_mempool_size;
    } else if (curr_mempool_size > UINT32_MAX / cnt) {
        FatalError("%s: mempool size too large to adjust for %u bonded devices",
                DPDKGetPortNameByPortID(bond_pid), cnt);
    }

    return curr_mempool_size * cnt;
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
