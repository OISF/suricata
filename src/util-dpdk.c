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
 * \author Lukas Sismis <sismis@cesnet.cz>
 */

#ifndef UTIL_DPDK_C
#define UTIL_DPDK_C

#include "suricata.h"
#include "util-dpdk.h"

uint32_t ArrayMaxValue(const uint32_t *arr, uint16_t arr_len)
{
    uint32_t max = 0;
    for (uint16_t i = 0; i < arr_len; i++) {
        max = MAX(arr[i], max);
    }
    return max;
}

// Used to determine size for memory allocation of a string
uint8_t CountDigits(uint32_t n)
{
    uint8_t digits_cnt = 0;
    if (n == 0)
        return 1;

    while (n != 0) {
        n = n / 10;
        digits_cnt++;
    }
    return digits_cnt;
}

void DPDKCleanupEAL(void)
{
#ifdef HAVE_DPDK
    if (run_mode == RUNMODE_DPDK && rte_eal_process_type() == RTE_PROC_PRIMARY) {
        int retval = rte_eal_cleanup();
        if (retval != 0)
            SCLogError(SC_ERR_DPDK_EAL_DEINIT, "EAL cleanup failed: %s", strerror(-retval));
    }
#endif
}

void DPDKCloseDevice(LiveDevice *ldev)
{
    (void)ldev; // avoid warnings of unused variable
#ifdef HAVE_DPDK
    uint16_t port_id;
    int retval;
    if (run_mode == RUNMODE_DPDK && rte_eal_process_type() == RTE_PROC_PRIMARY) {
        retval = rte_eth_dev_get_port_by_name(ldev->dev, &port_id);
        if (retval < 0) {
            SCLogError(SC_ERR_DPDK_EAL_DEINIT, "Unable to get port id of \"%s\", error: %s",
                    ldev->dev, rte_strerror(-retval));
            return;
        }

        SCLogInfo("Closing device %s", ldev->dev);
        rte_eth_dev_close(port_id);
    }
#endif
}

#endif /* UTIL_DPDK_C */