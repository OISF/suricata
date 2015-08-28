/*
 * Copyright (C) 2014 ANSSI
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL
 * THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
 * OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 * ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/**
 * \file
 *
 * \author Kevin Wong <kwong@solananetworks.com>
 */

#ifndef __APP_LAYER_ENIP_COMMON_H__
#define __APP_LAYER_ENIP_COMMON_H__

#include "app-layer-protos.h"
#include "app-layer-parser.h"
#include "flow.h"
#include "queue.h"

#define MAX_ENIP_CMD    65535

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

typedef struct SegmentEntry_
{
    uint16_t segment; //segment type
    uint16_t value; //segment value (class or attribute)

TAILQ_ENTRY(SegmentEntry_) next;
} SegmentEntry;

typedef struct AttributeEntry_
{
    uint16_t attribute; //segment class

TAILQ_ENTRY(AttributeEntry_) next;
} AttributeEntry;

typedef struct CIPServiceEntry_
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

TAILQ_HEAD(, SegmentEntry_) segment_list; /**< list for CIP segment */
TAILQ_HEAD(, AttributeEntry_) attrib_list; /**< list for CIP segment */

TAILQ_ENTRY(CIPServiceEntry_) next;
} CIPServiceEntry;

typedef struct ENIPTransaction_
{
    uint16_t tx_num; /**< internal: id */
    uint16_t tx_id; /**< transaction id */

    ENIPEncapHdr header; //encapsulation header
    ENIPEncapDataHdr encap_data_header; //encapsulation data header
    ENIPEncapAddresItem encap_addr_item; //encapsulated address item
    ENIPEncapDataItem encap_data_item; //encapsulated data item

    TAILQ_HEAD(, CIPServiceEntry_) service_list; /**< list for CIP  */

    AppLayerDecoderEvents *decoder_events; /**< per tx events */

    TAILQ_ENTRY(ENIPTransaction_) next;
    DetectEngineState *de_state;
} ENIPTransaction;

/** \brief Per flow ENIP state container */
typedef struct ENIPState_
{
    TAILQ_HEAD(, ENIPTransaction_) tx_list; /**< transaction list */
    ENIPTransaction *curr; /**< ptr to current tx */
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

int DecodeENIPPDU(uint8_t *input, uint32_t input_len,
        ENIPTransaction *enip_data);
int DecodeCommonPacketFormatPDU(uint8_t *input, uint32_t input_len,
        ENIPTransaction *enip_data, uint16_t offset);
int DecodeCIPPDU(uint8_t *input, uint32_t input_len,
        ENIPTransaction *enip_data, uint16_t offset);
int DecodeCIPRequestPDU(uint8_t *input, uint32_t input_len,
        ENIPTransaction *enip_data, uint16_t offset);
int DecodeCIPResponsePDU(uint8_t *input, uint32_t input_len,
        ENIPTransaction *enip_data, uint16_t offset);
int DecodeCIPRequestPathPDU(uint8_t *input, uint32_t input_len,
        CIPServiceEntry *node, uint16_t offset);
int DecodeCIPRequestMSPPDU(uint8_t *input, uint32_t input_len,
        ENIPTransaction *enip_data, uint16_t offset);
int DecodeCIPResponseMSPPDU(uint8_t *input, uint32_t input_len,
        ENIPTransaction *enip_data, uint16_t offset);

#endif /* __APP_LAYER_ENIP_COMMON_H__ */
