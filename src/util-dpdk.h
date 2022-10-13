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

#ifdef HAVE_DPDK

#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_launch.h>
#include <rte_lcore.h>
#include <rte_log.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>
#include <rte_flow.h>

#if RTE_VER_YEAR < 22
#define RTE_ETH_MQ_RX_RSS ETH_MQ_RX_RSS

#endif

#if RTE_VER_YEAR < 21 || RTE_VER_YEAR == 21 && RTE_VER_MONTH < 11
#define RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE DEV_TX_OFFLOAD_MBUF_FAST_FREE

#define RTE_ETH_RX_OFFLOAD_CHECKSUM DEV_RX_OFFLOAD_CHECKSUM
#define RTE_ETH_RX_OFFLOAD_RSS_HASH DEV_RX_OFFLOAD_RSS_HASH

#define RTE_ETH_MQ_TX_NONE ETH_MQ_TX_NONE

#define RTE_ETH_MQ_RX_NONE ETH_MQ_RX_NONE

#define RTE_ETH_RSS_IP     ETH_RSS_IP
#define RTE_ETH_RSS_UDP    ETH_RSS_UDP
#define RTE_ETH_RSS_TCP    ETH_RSS_TCP
#define RTE_ETH_RSS_SCTP   ETH_RSS_SCTP
#define RTE_ETH_RSS_TUNNEL ETH_RSS_TUNNEL

#define RTE_ETH_RSS_L3_SRC_ONLY ETH_RSS_L3_SRC_ONLY
#define RTE_ETH_RSS_L3_DST_ONLY ETH_RSS_L3_DST_ONLY
#define RTE_ETH_RSS_L4_SRC_ONLY ETH_RSS_L4_SRC_ONLY
#define RTE_ETH_RSS_L4_DST_ONLY ETH_RSS_L4_DST_ONLY

#define RTE_ETH_RSS_IPV4               ETH_RSS_IPV4
#define RTE_ETH_RSS_FRAG_IPV4          ETH_RSS_FRAG_IPV4
#define RTE_ETH_RSS_NONFRAG_IPV4_TCP   ETH_RSS_NONFRAG_IPV4_TCP
#define RTE_ETH_RSS_NONFRAG_IPV4_UDP   ETH_RSS_NONFRAG_IPV4_UDP
#define RTE_ETH_RSS_NONFRAG_IPV4_SCTP  ETH_RSS_NONFRAG_IPV4_SCTP
#define RTE_ETH_RSS_NONFRAG_IPV4_OTHER ETH_RSS_NONFRAG_IPV4_OTHER
#define RTE_ETH_RSS_IPV6               ETH_RSS_IPV6
#define RTE_ETH_RSS_FRAG_IPV6          ETH_RSS_FRAG_IPV6
#define RTE_ETH_RSS_NONFRAG_IPV6_TCP   ETH_RSS_NONFRAG_IPV6_TCP
#define RTE_ETH_RSS_NONFRAG_IPV6_UDP   ETH_RSS_NONFRAG_IPV6_UDP
#define RTE_ETH_RSS_NONFRAG_IPV6_SCTP  ETH_RSS_NONFRAG_IPV6_SCTP
#define RTE_ETH_RSS_NONFRAG_IPV6_OTHER ETH_RSS_NONFRAG_IPV6_OTHER
#define RTE_ETH_RSS_L2_PAYLOAD         ETH_RSS_L2_PAYLOAD
#define RTE_ETH_RSS_IPV6_EX            ETH_RSS_IPV6_EX
#define RTE_ETH_RSS_IPV6_TCP_EX        ETH_RSS_IPV6_TCP_EX
#define RTE_ETH_RSS_IPV6_UDP_EX        ETH_RSS_IPV6_UDP_EX
#define RTE_ETH_RSS_PORT               ETH_RSS_PORT
#define RTE_ETH_RSS_VXLAN              ETH_RSS_VXLAN
#define RTE_ETH_RSS_GENEVE             ETH_RSS_GENEVE
#define RTE_ETH_RSS_NVGRE              ETH_RSS_NVGRE
#define RTE_ETH_RSS_GTPU               ETH_RSS_GTPU

#define RTE_MBUF_F_RX_IP_CKSUM_MASK PKT_RX_IP_CKSUM_MASK
#define RTE_MBUF_F_RX_IP_CKSUM_NONE PKT_RX_IP_CKSUM_NONE
#define RTE_MBUF_F_RX_IP_CKSUM_GOOD PKT_RX_IP_CKSUM_GOOD
#define RTE_MBUF_F_RX_IP_CKSUM_BAD  PKT_RX_IP_CKSUM_BAD

#define RTE_MBUF_F_RX_L4_CKSUM_MASK PKT_RX_L4_CKSUM_MASK
#define RTE_MBUF_F_RX_L4_CKSUM_GOOD PKT_RX_L4_CKSUM_GOOD
#define RTE_MBUF_F_RX_L4_CKSUM_BAD  PKT_RX_L4_CKSUM_BAD
#endif

#endif /* HAVE_DPDK */

#include "util-device.h"

void DPDKCleanupEAL(void);

void DPDKCloseDevice(LiveDevice *ldev);

#endif /* UTIL_DPDK_H */
