/* Copyright (C) 2007-2022 Open Information Security Foundation
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
 * \author Breno Silva <breno.silva@gmail.com>
 */

#ifndef SURICATA_DECODE_VLAN_H
#define SURICATA_DECODE_VLAN_H

/* return vlan id in host byte order */
uint16_t DecodeVLANGetId(const struct Packet_ *, uint8_t layer);

/** Vlan type */
#define ETHERNET_TYPE_VLAN          0x8100

/** Vlan macros to access Vlan priority, Vlan CFI and VID */
#define GET_VLAN_PRIORITY(vlanh)    ((SCNtohs((vlanh)->vlan_cfi) & 0xe000) >> 13)
#define GET_VLAN_CFI(vlanh)         ((SCNtohs((vlanh)->vlan_cfi) & 0x0100) >> 12)
#define GET_VLAN_ID(vlanh)          ((uint16_t)(SCNtohs((vlanh)->vlan_cfi) & 0x0FFF))
#define GET_VLAN_PROTO(vlanh)       ((SCNtohs((vlanh)->protocol)))

/** Vlan header struct */
typedef struct VLANHdr_ {
    uint16_t vlan_cfi;
    uint16_t protocol;  /**< protocol field */
} __attribute__((__packed__)) VLANHdr;

/** VLAN header length */
#define VLAN_HEADER_LEN 4

void DecodeVLANRegisterTests(void);

/** VLAN max encapsulation layer count/index */
#define VLAN_MAX_LAYERS    3
#define VLAN_MAX_LAYER_IDX (VLAN_MAX_LAYERS - 1)

#endif /* SURICATA_DECODE_VLAN_H */
