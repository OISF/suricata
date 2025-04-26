/* Copyright (C) 2021-2025 Open Information Security Foundation
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

#ifndef UTIL_DPDK_ICE_H
#define UTIL_DPDK_ICE_H

#include "suricata-common.h"

#ifdef HAVE_DPDK

#include "util-dpdk.h"

int iceDeviceSetRSS(int port_id, uint16_t nb_rx_queues, char *port_name);
void iceDeviceSetRSSConf(struct rte_eth_rss_conf *rss_conf);

#endif /* HAVE_DPDK */

#endif /* UTIL_DPDK_ICE_H */
