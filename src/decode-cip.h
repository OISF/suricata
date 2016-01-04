/* Copyright (C) 2015 Open Information Security Foundation
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

#ifndef _DETECT_CIP_H
#define	_DETECT_CIP_H

#include "detect-cipservice.h"

#define MAX_CIP_SERVICE		127
#define MAX_CIP_CLASS		65535
#define MAX_CIP_ATTRIBUTE	65535

// CIP service codes
#define CIP_RESERVED	    0x00
#define CIP_GET_ATTR_ALL    0x01
#define CIP_GET_ATTR_LIST   0x03
#define CIP_SET_ATTR_LIST   0x04
#define CIP_RESET           0x05
#define CIP_START           0x06
#define CIP_STOP            0x07
#define CIP_CREATE          0x08
#define CIP_DELETE          0x09
#define CIP_MSP             0x0a
#define CIP_APPLY_ATTR      0x0d
#define CIP_GET_ATTR_SINGLE 0x0e
#define CIP_SET_ATTR_SINGLE 0x10
#define CIP_KICK_TIMER      0x4b
#define CIP_OPEN_CONNECTION 0x4c
#define CIP_CHANGE_START    0x4f
#define CIP_GET_STATUS      0x50

//PATH sizing codes
#define PATH_CLASS_8BIT      	0x20
#define PATH_CLASS_16BIT      	0x21
#define PATH_INSTANCE_8BIT      0x24
#define PATH_INSTANCE_16BIT     0x25
#define PATH_ATTR_8BIT      	0x30
#define PATH_ATTR_16BIT      	0x31 //possible value

/**
 * CIP Request Header
 */
typedef struct CIPReqHdr_
{
    u_int8_t service;
    u_int8_t path_size;
} CIPReqHdr;

/**
 * CIP Response Header
 */
typedef struct CIPRespHdr_
{
    u_int8_t service;
    u_int8_t pad;
    u_int8_t status;
    u_int8_t status_size;
} CIPRespHdr;

/**
 * Decode CIP
 */
int DecodeCIP(Packet *p, ENIPData *enip_data, uint16_t offset);

/**
 * Decode CIP Response
 */
int DecodeCIPResponse(Packet *p, ENIPData *enip_data, uint16_t offset);

/**
 * Decode CIP Request
 */
int DecodeCIPRequest(Packet *p, ENIPData *enip_data, uint16_t offset);

/**
 * Decode CIP Request Path
 */
int DecodeCIPRequestPath(Packet *p, CIPServiceData *node, uint16_t offset,
        DetectCipServiceData *cipserviced);

/**
 * Decode CIP Request MultiService Packet
 */
int DecodeCIPRequestMSP(Packet *p, ENIPData *enip_data, uint16_t offset);

/**
 * Decode CIP Response MultiService Packet
 */
int DecodeCIPResponseMSP(Packet *p, ENIPData *enip_data, uint16_t offset);

#endif	/* _DETECT_CIP_H */

