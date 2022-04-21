/* Copyright (C) 2022 Open Information Security Foundation
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
 * \author Lukas Sismis <lukas.sismis@cesnet.cz>
 */

#ifndef DEV_CONF_SURICATA_H
#define DEV_CONF_SURICATA_H

#include <stdint-gcc.h>
#include <sys/types.h>

#include <rte_ring.h>
#include <rte_mempool.h>

struct nic_conf {
    const char *port1_pcie;
    const char *port2_pcie;
    uint16_t port1_id;
    uint16_t port2_id;
    uint16_t socket_id;
    /* Ring mode settings */
    struct rte_ring **rx_rings;
    struct rte_ring **tx_rings;
    /* End of ring mode settings */
    /* DPDK flags */
    uint32_t flags;
    /* set maximum transmission unit of the device in bytes */
    uint16_t mtu;
    uint16_t nb_rx_desc;
    uint16_t nb_tx_desc;
    uint32_t mempool_size;
    uint32_t mempool_cache_size;
    struct rte_mempool *pkt_mempool;
};

struct ring_list_entry_suricata {
    struct nic_conf nic_conf;
};

extern struct DeviceConfigurer dev_conf_suricata_ops;

#endif // DEV_CONF_SURICATA_H
