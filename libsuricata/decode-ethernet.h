/* Copyright (C) 2007-2021 Open Information Security Foundation
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
 * \author Victor Julien <victor@inliniac.net>
 */

#ifndef __DECODE_ETHERNET_H__
#define __DECODE_ETHERNET_H__

#define ETHERNET_HEADER_LEN           14

/* Cisco Fabric Path / DCE header length. */
#define ETHERNET_DCE_HEADER_LEN       (ETHERNET_HEADER_LEN + 2)

/* Ethernet types -- taken from Snort and Libdnet */
#define ETHERNET_TYPE_PUP             0x0200 /* PUP protocol */
#define ETHERNET_TYPE_IP              0x0800
#define ETHERNET_TYPE_ARP             0x0806
#define ETHERNET_TYPE_BRIDGE          0x6558 /* transparent ethernet bridge (GRE) */
#define ETHERNET_TYPE_REVARP          0x8035
#define ETHERNET_TYPE_EAPOL           0x888e
#define ETHERNET_TYPE_IPV6            0x86dd
#define ETHERNET_TYPE_IPX             0x8137
#define ETHERNET_TYPE_PPPOE_DISC      0x8863 /* discovery stage */
#define ETHERNET_TYPE_PPPOE_SESS      0x8864 /* session stage */
#define ETHERNET_TYPE_8021AD          0x88a8
#define ETHERNET_TYPE_8021AH          0x88e7
#define ETHERNET_TYPE_8021Q           0x8100
#define ETHERNET_TYPE_LOOP            0x9000
#define ETHERNET_TYPE_8021QINQ        0x9100
#define ETHERNET_TYPE_ERSPAN          0x88BE
#define ETHERNET_TYPE_DCE             0x8903 /* Data center ethernet,
                                              * Cisco Fabric Path */
#define ETHERNET_TYPE_NSH 0x894F
#define ETHERNET_TYPE_VNTAG 0x8926 /* 802.1Qbh */

typedef struct EthernetHdr_ {
    uint8_t eth_dst[6];
    uint8_t eth_src[6];
    uint16_t eth_type;
} __attribute__((__packed__)) EthernetHdr;

void DecodeEthernetRegisterTests(void);

#endif /* __DECODE_ETHERNET_H__ */

