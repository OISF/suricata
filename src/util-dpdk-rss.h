/* Copyright (C) 2025 Open Information Security Foundation
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
 * \author Adam Kiripolsky <adam.kiripolsky@cesnet.cz>
 */

#ifndef UTIL_DPDK_RSS
#define UTIL_DPDK_RSS

#include "suricata-common.h"

#ifdef HAVE_DPDK

#include "util-dpdk.h"

#define RSS_HKEY_LEN 40

extern uint8_t RSS_HKEY[];

struct rte_flow_action_rss DPDKInitRSSAction(struct rte_eth_rss_conf rss_conf, int nb_rx_queues,
        uint16_t *queues, enum rte_eth_hash_function func, bool set_key);
int DPDKCreateRSSFlowGeneric(
        int port_id, const char *port_name, struct rte_flow_action_rss rss_conf);
int DPDKSetRSSFlowQueues(int port_id, const char *port_name, struct rte_flow_action_rss rss_conf);
int DPDKCreateRSSFlow(int port_id, const char *port_name, struct rte_flow_action_rss rss_conf,
        uint64_t rss_type, struct rte_flow_item *pattern);

#endif /* HAVE_DPDK */

#endif /* UTIL_DPDK_RSS */
