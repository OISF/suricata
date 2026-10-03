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
 * \author Lukas Sismis <lsismis@oisf.net>
 */

#ifndef UTIL_DPDK_COMMON_H
#define UTIL_DPDK_COMMON_H

#ifdef HAVE_DPDK

#include <rte_eal.h>
#include <rte_ethdev.h>
#ifdef HAVE_DPDK_BOND
#include <rte_eth_bond.h>
#endif
#include <rte_launch.h>
#include <rte_lcore.h>
#include <rte_log.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>
#include <rte_flow.h>
#include <rte_kvargs.h>
#include <rte_version.h>

#if RTE_VERSION < RTE_VERSION_NUM(22, 0, 0, 0)
#define RTE_ETH_MQ_RX_RSS ETH_MQ_RX_RSS
#endif

typedef struct {
    struct rte_mempool **pkt_mp;
    uint16_t pkt_mp_cnt;
    uint16_t pkt_mp_capa;
} DPDKDeviceResources;

int DPDKDeviceResourcesInit(DPDKDeviceResources **dpdk_vars, uint16_t mp_cnt);
void DPDKDeviceResourcesDeinit(DPDKDeviceResources **dpdk_vars);

#endif /* HAVE_DPDK */

#endif /* UTIL_DPDK_COMMON_H */
