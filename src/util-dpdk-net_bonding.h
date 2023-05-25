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

#ifndef UTIL_DPDK_NET_BONDING_H
#define UTIL_DPDK_NET_BONDING_H

#include "suricata-common.h"

#ifdef HAVE_DPDK

int32_t net_bonding_is_port_bond(uint16_t pid);
uint16_t net_bonding_get_bonded_devices(
        uint16_t bond_pid, uint16_t bonded_devs[], uint16_t bonded_devs_length);
int32_t net_bonding_devices_use_same_driver(uint16_t bond_pid);
const char *net_bonding_device_driver_get(uint16_t bond_pid);

#endif /* HAVE_DPDK */

#endif /* UTIL_DPDK_NET_BONDING_H */
