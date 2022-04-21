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

#ifndef __SOURCE_DPDK_H__
#define __SOURCE_DPDK_H__

#include "queue.h"
#include "util-dpdk.h"

#define DPDK_BURST_TX_WAIT_US 1

/**
 * \brief per packet DPDK vars
 *
 * This structure is used by the release data system and for IPS
 */
typedef struct DPDKPacketVars_ {
    struct rte_mbuf *mbuf;
    uint16_t out_port_id;
    uint16_t out_queue_id;
    uint8_t copy_mode;
    struct rte_ring *tx_ring; // pkt is sent to this ring (same as out_port_*)
} DPDKPacketVars;

void DevicePostStartPMDSpecificActions(int port_id, int nb_rx_queues, const char *driver_name);
void DevicePreStopPMDSpecificActions(int port_id, const char *driver_name);

void TmModuleReceiveDPDKRegister(void);
void TmModuleDecodeDPDKRegister(void);

#endif /* __SOURCE_DPDK_H__ */
