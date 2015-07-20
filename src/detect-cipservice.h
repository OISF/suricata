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

#ifndef _DETECT_CIPSERVICE_H
#define	_DETECT_CIPSERVICE_H

/**
 * Byte extraction utilities
 */
void ENIPExtractUint8(uint8_t *res, uint8_t *input, uint16_t *offset);
void ENIPExtractUint16(uint16_t *res, uint8_t *input, uint16_t *offset);
void ENIPExtractUint32(uint32_t *res, uint8_t *input, uint16_t *offset);
void ENIPExtractUint64(uint64_t *res, uint8_t *input, uint16_t *offset);

#define ENIP_PORT 44818 //standard EtherNet/IP port

/**
 * CIP Service rule data structure
 */
typedef struct DetectCipServiceData_
{
    uint8_t cipservice; /* cip service type */
    uint16_t cipclass; /* cip service type */
    uint16_t cipattribute; /* cip service type */
    uint8_t tokens; /* number of parameters*/
} DetectCipServiceData;

/**
 * ENIP Command rule data structure
 */
typedef struct DetectEnipCommandData_
{
    u_int16_t enipcommand; /* enip command */
} DetectEnipCommandData;

void DetectCipServiceRegister(void);
void DetectEnipCommandRegister(void);

/**
 * ENIP encapsulation header
 */
typedef struct ENIPEncapHdr_
{
    u_int64_t context;
    u_int32_t session;
    u_int32_t status;
    u_int32_t option;
    u_int16_t command;
    u_int16_t length;
} ENIPEncapHdr;

/**
 * ENIP encapsulation data header
 */
typedef struct ENIPEncapDataHdr_
{
    u_int32_t interface_handle;
    u_int16_t timeout;
    u_int16_t item_count;
} ENIPEncapDataHdr;

/**
 * ENIP encapsulation address item
 */
typedef struct ENIPEncapAddresItem_
{
    u_int16_t type;
    u_int16_t length;
    u_int16_t conn_id;
    u_int16_t sequence_num;
} ENIPEncapAddresItem;

/**
 * ENIP encapsulation data item
 */
typedef struct ENIPEncapDataItem_
{
    u_int16_t type;
    u_int16_t length;
    u_int16_t sequence_count;
} ENIPEncapDataItem;

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
            u_int8_t status;
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

/**
 * Ccompare cip service data to cip servicerule
 */
int CIPServiceMatch(Packet *p, ENIPData *enip_data,
        DetectCipServiceData *cipserviced);

/**
 * Add new CIPServiceData node to link list
 */
CIPServiceData *CreateCIPServiceData(ENIPData *enip_data);

#endif	/* _DETECT_CIPSERVICE_H */

