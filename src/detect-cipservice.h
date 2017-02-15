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

#ifndef _DETECT_CIPSERVICE_H
#define	_DETECT_CIPSERVICE_H

#include "app-layer-protos.h"
#include "app-layer-parser.h"
#include "flow.h"
#include "queue.h"
#include "app-layer-enip-common.h"

#define ENIP_PORT 44818 //standard EtherNet/IP port

/**
 * CIP Service rule data structure
 */
typedef struct DetectCipServiceData_
{
    uint8_t cipservice;     /* cip service type */
    uint16_t cipclass;
    uint16_t cipattribute;
    uint8_t matchattribute; /* whether to match on attribute*/
    uint8_t tokens;         /* number of parameters*/
} DetectCipServiceData;

/**
 * ENIP Command rule data structure
 */
typedef struct DetectEnipCommandData_
{
    uint16_t enipcommand; /* enip command */
} DetectEnipCommandData;

void DetectCipServiceRegister(void);
void DetectEnipCommandRegister(void);

/**
 * link list node for storing CIP service data
 */
typedef struct CIPServiceData_
{
    uint8_t service; //cip service
    union
    {
        struct
        {
            uint8_t path_size; //cip path size
            uint16_t path_offset; //offset to cip path
        } request;
        struct
        {
            uint8_t status;
        } response;
    };
    struct CIPServiceData* next;
} CIPServiceData;

/**
 * ENIP data structure
 */
typedef struct ENIPData_
{
    int direction;
    ENIPEncapHdr header; //encapsulation header
    ENIPEncapDataHdr encap_data_header; //encapsulation data header
    ENIPEncapAddresItem encap_addr_item; //encapsulated address item
    ENIPEncapDataItem encap_data_item; //encapsulated data item

    CIPServiceData* service_head; //head of cip service data list
    CIPServiceData* service_tail; //tail of cip service data list

} ENIPData;

#endif	/* _DETECT_CIPSERVICE_H */
