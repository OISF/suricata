/* Copyright (C) 2024 Open Information Security Foundation
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
 *
 * \author Giuseppe Longo <giuseppe@glongo.it>
 */

#ifndef SURICATA_DECODE_ARP_H
#define SURICATA_DECODE_ARP_H

#define ARP_HEADER_MIN_LEN   2
#define ARP_HEADER_LEN       28
#define ARP_HW_TYPE_ETHERNET 0x01
#define ARP_PROTO_TYPE_IP    0x0800
#define ARP_HW_SIZE          6
#define ARP_PROTO_SIZE       4

typedef struct ARPHdr_ {
    uint16_t hw_type;
    uint16_t proto_type;
    uint8_t hw_size;
    uint8_t proto_size;
    uint16_t opcode;
    uint8_t source_mac[6];
    uint8_t source_ip[4];
    uint8_t dest_mac[6];
    uint8_t dest_ip[4];
} __attribute__((__packed__)) ARPHdr;

#endif /* SURICATA_DECODE_ARP_H */
