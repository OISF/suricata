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
 *
 */

#ifndef SURICATA_SOURCE_PCAP_PACKET_H
#define SURICATA_SOURCE_PCAP_PACKET_H

#include "suricata-common.h"
#include "decode.h"

uint64_t PcapPacketCntGet(const Packet *p);
void PcapPacketCntSet(Packet *p, uint64_t pcap_cnt);
void PcapPacketCntReset(Packet *p);

#endif /* SURICATA_SOURCE_PCAP_PACKET_H */
