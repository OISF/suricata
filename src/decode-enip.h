/* Copyright (C) 2012 Open Information Security Foundation
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
 * \author Kevin Wong <kwong@solananetworks.com>
 */

#ifndef _DETECT_ENIP_H
#define	_DETECT_ENIP_H

#include "detect-cipservice.h"
#include "decode-cip.h"

#define MAX_ENIP_CMD	65535

// EtherNet/IP commands
#define NOP                0x0000
#define LIST_SERVICES      0x0004
#define LIST_IDENTITY      0x0063
#define LIST_INTERFACES    0x0064
#define REGISTER_SESSION   0x0065
#define UNREGISTER_SESSION 0x0066
#define SEND_RR_DATA       0x006F
#define SEND_UNIT_DATA     0x0070
#define INDICATE_STATUS    0x0072
#define CANCEL             0x0073

//Common Packet Format Types
#define NULL_ADDR              	0x0000
#define CONNECTION_BASED		0x00a1
#define CONNECTED_DATA_ITEM 	0x00b1
#define UNCONNECTED_DATA_ITEM 	0x00b2
#define SEQUENCE_ADDR_ITEM      0xB002

//status codes
#define SUCCESS               0x0000
#define INVALID_CMD           0x0001
#define NO_RESOURCES          0x0002
#define INCORRECT_DATA        0x0003
#define INVALID_SESSION       0x0064
#define INVALID_LENGTH        0x0065
#define UNSUPPORTED_PROT_REV  0x0069

/**
 * Entry point for decoding ENIP Packet
 */
int DecodeENIP(Packet *p, ENIPData *enip_data);

/**
 * Decodes Common Packet Format
 */
int DecodeCommonPacketFormat(Packet *p, ENIPData *enip_data, uint16_t offset);

#endif	/* _DETECT_ENIP_H */

