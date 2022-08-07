/* Copyright (C) 2007-2010 Open Information Security Foundation
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

#ifndef __DECODE_VLAN_H__
#define __DECODE_VLAN_H__

/* return vlan id in host byte order */
uint16_t DecodeVLANGetId(const struct Packet_ *, uint8_t layer);

/** Vlan type */
#define ETHERNET_TYPE_VLAN          0x8100

/** Vlan macros to access Vlan priority, Vlan CFI and VID */
#define GET_VLAN_PRIORITY(vlanh)    ((SCNtohs((vlanh)->vlan_cfi) & 0xe000) >> 13)
#define GET_VLAN_CFI(vlanh)         ((SCNtohs((vlanh)->vlan_cfi) & 0x0100) >> 12)
#define GET_VLAN_ID(vlanh)          ((uint16_t)(SCNtohs((vlanh)->vlan_cfi) & 0x0FFF))
#define GET_VLAN_PROTO(vlanh)       ((SCNtohs((vlanh)->protocol)))

/* return vlan id in host byte order */
#define VLAN_GET_ID1(p)             DecodeVLANGetId((p), 0)
#define VLAN_GET_ID2(p)             DecodeVLANGetId((p), 1)
#define VLAN_GET_ID3(p)             DecodeVLANGetId((p), 2)

/** Vlan header struct */
typedef struct VLANHdr_ {
    uint16_t vlan_cfi;
    uint16_t protocol;  /**< protocol field */
} __attribute__((__packed__)) VLANHdr;

/** VLAN header length */
#define VLAN_HEADER_LEN 4

void DecodeVLANRegisterTests(void);

#endif /* __DECODE_VLAN_H__ */

