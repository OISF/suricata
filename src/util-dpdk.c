/* Copyright (C) 2021 Open Information Security Foundation
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
#include "suricata.h"
#include "util-dpdk.h"
#include "util-debug.h"
#include "util-device-private.h"

void DPDKCleanupEAL(void)
{
#ifdef HAVE_DPDK
    if (SCRunmodeGet() == RUNMODE_DPDK) {
        int retval = rte_eal_cleanup();
        if (retval != 0)
            SCLogError("EAL cleanup failed: %s", strerror(-retval));
    }
#endif
}

void DPDKCloseDevice(LiveDevice *ldev)
{
    (void)ldev; // avoid warnings of unused variable
#ifdef HAVE_DPDK
    if (SCRunmodeGet() == RUNMODE_DPDK) {
        uint16_t port_id;
        int retval = rte_eth_dev_get_port_by_name(ldev->dev, &port_id);
        if (retval < 0) {
            SCLogError("%s: failed get port id, error: %s", ldev->dev, rte_strerror(-retval));
            return;
        }

        SCLogPerf("%s: closing device", ldev->dev);
        rte_eth_dev_close(port_id);
    }
#endif
}

void DPDKFreeDevice(LiveDevice *ldev)
{
    (void)ldev; // avoid warnings of unused variable
#ifdef HAVE_DPDK
    if (SCRunmodeGet() == RUNMODE_DPDK) {
        SCLogDebug("%s: releasing packet mempools", ldev->dev);
        DPDKDeviceResourcesDeinit(&ldev->dpdk_vars);
    }
#endif
}

/**
 * \param port_id - queried port
 * \param socket_id - socket ID of the queried port
 * \return non-negative number on success, negative on failure (errno)
 */
int32_t DPDKDeviceSetSocketID(uint16_t port_id, int32_t *socket_id)
{
#ifdef HAVE_DPDK
    rte_errno = 0;
    int retval = rte_eth_dev_socket_id(port_id);
    *socket_id = retval;

#if RTE_VERSION >= RTE_VERSION_NUM(22, 11, 0, 0) // DPDK API changed since 22.11
    retval = -rte_errno;
#else
    if (retval == SOCKET_ID_ANY)
        retval = 0; // DPDK couldn't determine socket ID of a port
#endif

    return retval;
#endif /* HAVE_DPDK */
    return -ENOTSUP;
}

/**
 * \param iface_name - name of the queried interface
 * \param socket_id - socket ID of the queried port
 * \return non-negative number on success, negative on failure (errno)
 */
int32_t DPDKDeviceNameSetSocketID(char *iface_name, int32_t *socket_id)
{
#ifdef HAVE_DPDK
    uint16_t port_id = 0;
    int r = rte_eth_dev_get_port_by_name(iface_name, &port_id);
    if (r < 0) {
        SCLogError("%s: interface not found: %s", iface_name, rte_strerror(-r));
        SCReturnInt(r);
    }
    return DPDKDeviceSetSocketID(port_id, socket_id);
#endif /* HAVE_DPDK */
    return -ENOTSUP;
}

#ifdef HAVE_DPDK
/**
 * Retrieves name of the port from port id
 * Not thread-safe
 * @param pid
 * @return static dev_name on success
 */
const char *DPDKGetPortNameByPortID(uint16_t pid)
{
    static char dev_name[RTE_ETH_NAME_MAX_LEN];
    int32_t ret = rte_eth_dev_get_name_by_port(pid, dev_name);
    if (ret < 0) {
        FatalError("Port %d: Failed to obtain port name (err: %s)", pid, rte_strerror(-ret));
    }
    return dev_name;
}

#endif /* HAVE_DPDK */
