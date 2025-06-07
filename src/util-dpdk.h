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

#ifndef UTIL_DPDK_H
#define UTIL_DPDK_H

#include "util-dpdk-common.h"
#include "util-device.h"

void DPDKCleanupEAL(void);

void DPDKCloseDevice(LiveDevice *ldev);
void DPDKFreeDevice(LiveDevice *ldev);
int32_t DPDKDeviceSetSocketID(uint16_t port_id, int32_t *socket_id);
int32_t DPDKDeviceNameSetSocketID(char *iface_name, int32_t *socket_id);

#ifdef HAVE_DPDK
const char *DPDKGetPortNameByPortID(uint16_t pid);
#endif /* HAVE_DPDK */

#endif /* UTIL_DPDK_H */
