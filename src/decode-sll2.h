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
 * \author Jeff Lucovsky (jeff.lucovsky@corelight.com)
 */

#ifndef SURICATA_DECODE_SLL2_H
#define SURICATA_DECODE_SLL2_H

#define SLL2_HEADER_LEN 20

typedef struct Sll2Hdr_ {
    uint16_t sll_protocol;     /* protocol */
    uint16_t sll2_reservd;     /* reserved */
    uint32_t sll_ifindex;      /* interface index*/
    uint16_t sll2_arphdtotype; /* ARPHRD_ type*/
    uint8_t sll2_pkttype;      /* packet type */
    uint8_t sll2_addrlen;      /* link-layer addr len*/
    uint8_t sll2_addr[8];      /* link-layer address */
} __attribute__((__packed__)) Sll2Hdr;

#endif /* SURICATA_DECODE_SLL2_H */
