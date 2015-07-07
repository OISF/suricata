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
void ENIPExtractUint8(uint8_t *res, uint8_t  *input, uint16_t *offset);
void ENIPExtractUint16(uint16_t *res,  uint8_t *input, uint16_t *offset) ;
void ENIPExtractUint32(uint32_t *res, uint8_t *input, uint16_t *offset);
void ENIPExtractUint64(uint64_t *res, uint8_t *input, uint16_t *offset) ;

#define ENIP_PORT 44818 //standard EtherNet/IP port

/**
 * CIP Service rule data structure
 */
typedef struct DetectCipServiceData_ {
    uint8_t cipservice;   /* cip service type */
    uint16_t cipclass;   /* cip service type */
    uint16_t cipattribute;   /* cip service type */
    uint8_t tokens;		/* number of parameters*/
} DetectCipServiceData;

/**
 * ENIP Command rule data structure
 */
typedef struct DetectEnipCommandData_ {
	u_int16_t enipcommand;   /**< enip command */
} DetectEnipCommandData;


void DetectCipServiceRegister(void);
void DetectEnipCommandRegister(void);

/**
 * ENIP encapsulation header
 */
typedef struct _ENIP_ENCAP_HEADER
{
    u_int16_t command;
    u_int16_t length;
    u_int32_t session;
    u_int32_t status;
    u_int64_t context;
    u_int32_t option;
} ENIP_ENCAP_HEADER;


/**
 * ENIP encapsulation data header
 */
typedef struct _ENIP_ENCAP_DATA_HEADER
{
	u_int32_t interface_handle;
	u_int16_t timeout;
	u_int16_t item_count;
} ENIP_ENCAP_DATA_HEADER;


/**
 * ENIP encapsulation address header
 */
typedef struct _ENIP_ENCAP_ADDRESS_ITEM
{
	u_int16_t type;
	u_int16_t length;
	u_int16_t conn_id;
	u_int16_t sequence_num;
} ENIP_ENCAP_ADDRESS_ITEM;


/**
 * ENIP encapsulation data item
 */
typedef struct _ENIP_ENCAP_DATA_ITEM
{
	u_int16_t type;
	u_int16_t length;
    u_int16_t sequence_count;
} ENIP_ENCAP_DATA_ITEM;


/**
 * link list node for storing CIP service data
 */
typedef struct _CIP_SERVICE_DATA
{
	uint8_t service; 	//cip service
	union {
	        struct {
	            uint8_t path_size; 		//cip path size
	        	uint16_t path_offset;	//offset to cip path
	        } request;
	        struct {
	            u_int8_t status;
	        } response;
	    };
	struct _CIP_SERVICE_DATA* next;
} CIP_SERVICE_DATA;


/**
 * ENIP data structure
 */
typedef struct _ENIP_DATA
{
	int direction;
	ENIP_ENCAP_HEADER header;	//encapsulation header
	ENIP_ENCAP_DATA_HEADER encap_data_header; //encapsulation data header
	ENIP_ENCAP_ADDRESS_ITEM encap_addr_item; //encapsulated address item
	ENIP_ENCAP_DATA_ITEM encap_data_item; //encapsulated data item

	CIP_SERVICE_DATA* service_head; //head of cip service data list
	CIP_SERVICE_DATA* service_tail; //tail of cip service data list

} ENIP_DATA;



/**
 * Ccompare cip service data to cip servicerule
 */
int CIPServiceMatch(Packet *p, ENIP_DATA *enip_data, DetectCipServiceData *cipserviced );


/**
 * Create cip service structures
 */
CIP_SERVICE_DATA *CreateCIPServiceData(ENIP_DATA *enip_data);


#endif	/* _DETECT_CIPSERVICE_H */

