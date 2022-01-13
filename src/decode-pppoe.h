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
 * \author James Riden <jamesr@europe.com>
 */

#ifndef __DECODE_PPPOE_H__
#define __DECODE_PPPOE_H__

#include "decode.h"
#include "threadvars.h"

// Session header length minus the protocol field
#define PPPOE_SESSION_HEADER_MIN_LEN     7
#define PPPOE_DISCOVERY_HEADER_MIN_LEN 6
#define PPPOE_SESSION_GET_VERSION(hdr) ((hdr)->pppoe_version_type & 0xF0) >> 4
#define PPPOE_SESSION_GET_TYPE(hdr) ((hdr)->pppoe_version_type & 0x0F)
#define PPPOE_DISCOVERY_GET_VERSION(hdr) ((hdr)->pppoe_version_type & 0xF0) >> 4
#define PPPOE_DISCOVERY_GET_TYPE(hdr) ((hdr)->pppoe_version_type & 0x0F)

typedef struct PPPOESessionHdr_
{
    uint8_t pppoe_version_type;
    uint8_t pppoe_code;
    uint16_t session_id;
    uint16_t pppoe_length;
    uint16_t protocol;
} PPPOESessionHdr;

typedef struct PPPOEDiscoveryTag_
{
    uint16_t pppoe_tag_type;
    uint16_t pppoe_tag_length;
} __attribute__((__packed__)) PPPOEDiscoveryTag;

typedef struct PPPOEDiscoveryHdr_
{
    uint8_t pppoe_version_type;
    uint8_t pppoe_code;
    uint16_t discovery_id;
    uint16_t pppoe_length;
} __attribute__((__packed__)) PPPOEDiscoveryHdr;

/* see RFC 2516 - discovery codes */
#define PPPOE_CODE_PADI 0x09
#define PPPOE_CODE_PADO 0x07
#define PPPOE_CODE_PADR 0x19
#define PPPOE_CODE_PADS 0x65
#define PPPOE_CODE_PADT 0xa7

/* see RFC 2516 Appendix A */
#define PPPOE_TAG_END_OF_LIST         0x0000 /* End-Of-List */
#define PPPOE_TAG_SERVICE_NAME        0x0101 /* Service-Name */
#define PPPOE_TAG_AC_NAME             0x0102 /* AC-Name */
#define PPPOE_TAG_HOST_UNIQ           0x0103 /* Host-Uniq */
#define PPPOE_TAG_AC_COOKIE           0x0104 /* AC-Cookie */
#define PPPOE_TAG_VENDOR_SPECIFIC     0x0105 /* Vendor-Specific */
#define PPPOE_TAG_RELAY_SESSION_ID    0x0110 /* Relay-Session-Id */
#define PPPOE_TAG_SERVICE_NAME_ERROR  0x0201 /* Service-Name-Error */
#define PPPOE_TAG_AC_SYS_ERROR        0x0202 /* AC-System Error */
#define PPPOE_TAG_GEN_ERROR           0x0203 /* Generic-Error */

void DecodePPPOERegisterTests(void);

#endif /* __DECODE_PPPOE_H__ */

