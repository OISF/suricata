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

#ifndef __APP_LAYER_ENIP_COMMON_H__
#define __APP_LAYER_ENIP_COMMON_H__

#include "rust.h"

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
#define NULL_ADDR               0x0000
#define CONNECTION_BASED        0x00a1
#define CONNECTED_DATA_ITEM     0x00b1
#define UNCONNECTED_DATA_ITEM   0x00b2
#define SEQUENCE_ADDR_ITEM      0xB002

//status codes
#define SUCCESS               0x0000
#define INVALID_CMD           0x0001
#define NO_RESOURCES          0x0002
#define INCORRECT_DATA        0x0003
#define INVALID_SESSION       0x0064
#define INVALID_LENGTH        0x0065
#define UNSUPPORTED_PROT_REV  0x0069
//Found in wireshark
#define ENCAP_HEADER_ERROR    0x006A

#define MAX_CIP_SERVICE     127
#define MAX_CIP_CLASS       65535
#define MAX_CIP_ATTRIBUTE   65535

// CIP service codes
#define CIP_RESERVED        0x00
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
#define PATH_CLASS_8BIT         0x20
#define PATH_CLASS_16BIT        0x21
#define PATH_INSTANCE_8BIT      0x24
#define PATH_INSTANCE_16BIT     0x25
#define PATH_ATTR_8BIT          0x30
#define PATH_ATTR_16BIT         0x31 //possible value

/**
 * ENIP encapsulation header
 */
typedef struct ENIPEncapHdr_
{
    uint64_t context;
    uint32_t session;
    uint32_t status;
    uint32_t option;
    uint16_t command;
    uint16_t length;
} ENIPEncapHdr;

/**
 * ENIP encapsulation data header
 */
typedef struct ENIPEncapDataHdr_
{
    uint32_t interface_handle;
    uint16_t timeout;
    uint16_t item_count;
} ENIPEncapDataHdr;

/**
 * ENIP encapsulation address item
 */
typedef struct ENIPEncapAddresItem_
{
    uint16_t type;
    uint16_t length;
    uint32_t conn_id;
    uint32_t sequence_num;
} ENIPEncapAddresItem;

/**
 * ENIP encapsulation data item
 */
typedef struct ENIPEncapDataItem_
{
    uint16_t type;
    uint16_t length;
    uint16_t sequence_count;
} ENIPEncapDataItem;

/**
 * CIP Request Header
 */
typedef struct CIPReqHdr_
{
    uint8_t service;
    uint8_t path_size;
} CIPReqHdr;

/**
 * CIP Response Header
 */
typedef struct CIPRespHdr_
{
    uint8_t service;
    uint8_t pad;
    uint8_t status;
    uint8_t status_size;
} CIPRespHdr;

typedef struct SegmentEntry_
{
    uint16_t segment;   /**< segment type */
    uint16_t value;     /**< segment value (class or attribute) */

    TAILQ_ENTRY(SegmentEntry_) next;
} SegmentEntry;

typedef struct AttributeEntry_
{
    uint16_t attribute; /**< segment class */

    TAILQ_ENTRY(AttributeEntry_) next;
} AttributeEntry;

typedef struct CIPServiceEntry_
{
    uint8_t service;                            /**< cip service */
    uint8_t direction;
    union
    {
        struct
        {
            uint8_t path_size;                  /**< cip path size */
            uint16_t path_offset;               /**< offset to cip path */
        } request;
        struct
        {
            uint16_t status;
        } response;
    };

    TAILQ_HEAD(, SegmentEntry_) segment_list;   /**< list for CIP segment */
    TAILQ_HEAD(, AttributeEntry_) attrib_list;  /**< list for CIP segment */

    TAILQ_ENTRY(CIPServiceEntry_) next;
} CIPServiceEntry;

typedef struct ENIPTransaction_
{
    struct ENIPState_ *enip;
    uint64_t tx_num;                            /**< internal: id */
    uint16_t tx_id;                             /**< transaction id */
    uint16_t service_count;

    ENIPEncapHdr header;                        /**< encapsulation header */
    ENIPEncapDataHdr encap_data_header;         /**< encapsulation data header */
    ENIPEncapAddresItem encap_addr_item;        /**< encapsulated address item */
    ENIPEncapDataItem encap_data_item;          /**< encapsulated data item */

    TAILQ_HEAD(, CIPServiceEntry_) service_list; /**< list for CIP  */

    TAILQ_ENTRY(ENIPTransaction_) next;
    AppLayerTxData tx_data;
} ENIPTransaction;

/** \brief Per flow ENIP state container */
typedef struct ENIPState_
{
    AppLayerStateData state_data;
    TAILQ_HEAD(, ENIPTransaction_) tx_list; /**< transaction list */
    ENIPTransaction *curr;                  /**< ptr to current tx */
    ENIPTransaction *iter;
    uint64_t transaction_max;
    uint64_t tx_with_detect_state_cnt;

    uint16_t events;
    uint16_t givenup;

    /* used by TCP only */
    uint16_t offset;
    uint16_t record_len;
    uint8_t *buffer;
} ENIPState;

int DecodeENIPPDU(const uint8_t *input, uint32_t input_len,
        ENIPTransaction *enip_data);
int DecodeCommonPacketFormatPDU(const uint8_t *input, uint32_t input_len,
        ENIPTransaction *enip_data, uint16_t offset);
int DecodeCIPPDU(const uint8_t *input, uint32_t input_len,
        ENIPTransaction *enip_data, uint16_t offset);
int DecodeCIPRequestPDU(const uint8_t *input, uint32_t input_len,
        ENIPTransaction *enip_data, uint16_t offset);
int DecodeCIPResponsePDU(const uint8_t *input, uint32_t input_len,
        ENIPTransaction *enip_data, uint16_t offset);
int DecodeCIPRequestPathPDU(const uint8_t *input, uint32_t input_len,
        CIPServiceEntry *node, uint16_t offset);
int DecodeCIPRequestMSPPDU(const uint8_t *input, uint32_t input_len,
        ENIPTransaction *enip_data, uint16_t offset);
int DecodeCIPResponseMSPPDU(const uint8_t *input, uint32_t input_len,
        ENIPTransaction *enip_data, uint16_t offset);

#endif /* __APP_LAYER_ENIP_COMMON_H__ */
