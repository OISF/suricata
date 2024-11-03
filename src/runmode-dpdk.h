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

/** \file
 *
 *  \author Lukas Sismis <lukas.sismis@gmail.com>
 */

#ifndef SURICATA_RUNMODE_DPDK_H
#define SURICATA_RUNMODE_DPDK_H

typedef struct DPDKIfaceConfigAttributes_ {
    const char *threads;
    const char *irq_mode;
    const char *promisc;
    const char *multicast;
    const char *checksum_checks;
    const char *checksum_checks_offload;
    const char *mtu;
    const char *vlan_strip_offload;
    const char *rss_hf;
    const char *mempool_size;
    const char *mempool_cache_size;
    const char *rx_descriptors;
    const char *tx_descriptors;
    const char *copy_mode;
    const char *copy_iface;
} DPDKIfaceConfigAttributes;

int RunModeIdsDpdkWorkers(void);
void RunModeDpdkRegister(void);
const char *RunModeDpdkGetDefaultMode(void);

void DPDKRunmodeRegisterTests(void);

#endif /* SURICATA_RUNMODE_DPDK_H */
