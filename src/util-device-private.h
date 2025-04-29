/* Copyright (C) 2011-2025 Open Information Security Foundation
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

/* Suricata private header, should only be included by Suricata source
 * files. */

#ifndef SURICATA_UTIL_DEVICE_PRIVATE_H
#define SURICATA_UTIL_DEVICE_PRIVATE_H

#include "util-device.h"
#include "queue.h"
#include "util-storage.h"
#include "util-dpdk-common.h"

#define MAX_DEVNAME 10

/** storage for live device names */
typedef struct LiveDevice_ {
    char *dev; /**< the device (e.g. "eth0") */
    char dev_short[MAX_DEVNAME + 1];
    int mtu; /* MTU of the device */
    bool tenant_id_set;

    uint16_t id;

    SC_ATOMIC_DECLARE(uint64_t, pkts);
    SC_ATOMIC_DECLARE(uint64_t, drop);
    SC_ATOMIC_DECLARE(uint64_t, bypassed);
    SC_ATOMIC_DECLARE(uint64_t, invalid_checksums);
    TAILQ_ENTRY(LiveDevice_) next;

    uint32_t tenant_id;    /**< tenant id in multi-tenancy */
    uint32_t offload_orig; /**< original offload settings to restore @exit */
#ifdef HAVE_DPDK
    // DPDK resources that needs to be cleaned after workers are stopped and devices closed
    DPDKDeviceResources *dpdk_vars;
#endif
    /** storage handle as a flex array member */
    Storage storage[];
} LiveDevice;

#endif /* SURICATA_UTIL_DEVICE_PRIVATE_H */
