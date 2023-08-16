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

#include "suricata.h"
#include "util-dpdk.h"
#include "util-debug.h"
#include <math.h>

void DPDKCleanupEAL(void)
{
#ifdef HAVE_DPDK
    if (run_mode == RUNMODE_DPDK) {
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
    if (run_mode == RUNMODE_DPDK) {
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
    if (run_mode == RUNMODE_DPDK) {
        SCLogDebug("%s: releasing packet mempool", ldev->dev);
        rte_mempool_free(ldev->dpdk_vars.pkt_mp);
    }
#endif
}

static uint32_t MemInfoParseValue(FILE *fp, const char *keyword)
{
    char path[256], value_str[64];
    uint32_t value = UINT32_MAX;

    while (fscanf(fp, "%255s", path) != EOF) {
        if (strcmp(path, keyword) == 0) {
            if (fscanf(fp, "%63s", value_str) == EOF) {
                SCLogDebug("%s: not followed by any number", keyword);
                break;
            }

            errno = 0;
            char *endptr;
            value = (uint32_t)strtoul(value_str, &endptr, 10);
            if (errno != 0 || *endptr != '\0') {
                SCLogDebug("Failed to convert %s from /proc/meminfo", keyword);
                value = UINT32_MAX;
            }
            break;
        }
    }
    return value;
}

static void MemInfoEvaluateHugepages(uint32_t free_hugepages, uint32_t total_hugepages)
{
    if (free_hugepages == UINT32_MAX || total_hugepages == UINT32_MAX) {
        SCLogDebug("Hugepages information not found in /proc/meminfo");
        return;
    }

    if (total_hugepages == 0) {
        SCLogDebug("HugePages_Total: 0 hugepages");
        return;
    }

    float free_hugepages_ratio = (float)free_hugepages / (float)total_hugepages;
    if (free_hugepages_ratio > 0.5) {
        SCLogInfo("%" PRIu32 " of %" PRIu32
                  " of hugepages are free - number of hugepages can be lowered to e.g. %.0lf",
                free_hugepages, total_hugepages, ceil((total_hugepages - free_hugepages) * 1.15));
    }
}

void DPDKEvaluateHugepages(void)
{
    if (run_mode != RUNMODE_DPDK)
        return;

#ifdef HAVE_DPDK
    if (rte_eal_has_hugepages() == 0) { // hugepages disabled
        SCLogPerf("Hugepages not enabled - enabling hugepages can improve performance");
        return;
    }
#endif

    FILE *fp = fopen("/proc/meminfo", "r");
    if (fp == NULL) {
        SCLogInfo("Can't analyze hugepage usage: failed to open /proc/meminfo");
        return;
    }

    uint32_t free_hugepages = MemInfoParseValue(fp, "HugePages_Free:");
    rewind(fp);
    uint32_t total_hugepages = MemInfoParseValue(fp, "HugePages_Total:");

    fclose(fp);

    MemInfoEvaluateHugepages(free_hugepages, total_hugepages);
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
