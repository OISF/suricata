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

#ifndef SURICATA_UTIL_DPDK_I40E_H
#define SURICATA_UTIL_DPDK_I40E_H

#include "suricata-common.h"
#include "util-dpdk.h"

#ifdef HAVE_DPDK

int i40eDeviceSetRSS(int port_id, int nb_rx_queues);

int i40eDeviceSetRSSWithFlows(int port_id, int nb_rx_queues);
int i40eDeviceCreateRSSFlow(int port_id, struct rte_eth_rss_conf rss_conf, uint64_t rss_type,
        struct rte_flow_item *pattern);
int i40eDeviceSetRSSFlowQueues(struct rte_eth_rss_conf rss_conf, int port_id, int nb_rx_queues);
int i40eDeviceSetRSSFlowIPv4(struct rte_eth_rss_conf rss_conf, int port_id);
int i40eDeviceSetRSSFlowIPv6(struct rte_eth_rss_conf rss_conf, int port_id);

int i40eDeviceSetRSSWithFilter(int port_id);
int i40eDeviceEnableSymHash(int port_id, uint32_t ftype, enum rte_eth_hash_function function);
int i40eDeviceSetSymHash(int port_id, int enable);

#endif /* HAVE_DPDK */

#endif /* SURICATA_UTIL_DPDK_I40E_H */
