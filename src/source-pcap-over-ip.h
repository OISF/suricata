/* Copyright (C) 2007-2024 Open Information Security Foundation
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
 * \author Mahmoud Maatuq <mahmoudmatook.mm@gmail.com>
 *
 * Pcap over ip packet acquisition support
 */

#ifndef SURICATA_SOURCE_PCAP_OVER_IP_H
#define SURICATA_SOURCE_PCAP_OVER_IP_H

#include "suricata-common.h"
#include "util-checksum.h"

void TmModuleReceivePcapOverIPRegister(void);
void TmModuleDecodePcapOverIPRegister(void);

#define PCAPOVERIP_SOCKET_ADDR_LENGTH 256

typedef struct PcapOverIPIfaceConfig_ {
    char socket_addr[PCAPOVERIP_SOCKET_ADDR_LENGTH];
    int threads;
    int buffer_size;
    int snaplen;
    int promisc;
    const char *bpf_filter;
    ChecksumValidationMode checksum_mode;
    SC_ATOMIC_DECLARE(unsigned int, ref);
    void (*DerefFunc)(void *);
} PcapOverIPIfaceConfig;

#endif /* SURICATA_SOURCE_PCAP_OVER_IP_H */
