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

#include "app-layer-protos.h"
#include "app-layer-parser.h"
#include "flow.h"
#include "queue.h"

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
    uint8_t matchattribute;         /* whether to match on attribute*/
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


enum {
    ENIP_DECODER_EVENT_UNSOLLICITED_RESPONSE,
    ENIP_DECODER_EVENT_MALFORMED_DATA,
    ENIP_DECODER_EVENT_NOT_A_REQUEST,
    ENIP_DECODER_EVENT_NOT_A_RESPONSE,
    ENIP_DECODER_EVENT_Z_FLAG_SET,
    ENIP_DECODER_EVENT_FLOODED,
    ENIP_DECODER_EVENT_STATE_MEMCAP_REACHED,
};

typedef struct ENIPTransaction_ {
    uint16_t tx_num;                                /**< internal: id */
    uint16_t tx_id;                                 /**< transaction id */
    uint8_t replied;                                /**< bool indicating request is
                                                         replied to. */
    uint8_t reply_lost;
    uint8_t rcode;                                  /**< response code (e.g. "no error" / "no such name") */
    uint8_t recursion_desired;                      /**< server said "recursion desired" */

  //  TAILQ_HEAD(, ENIPQueryEntry_) query_list;        /**< list for query/queries */
  //  TAILQ_HEAD(, ENIPAnswerEntry_) answer_list;      /**< list for answers */
  //  TAILQ_HEAD(, ENIPAnswerEntry_) authority_list;   /**< list for authority records */

    AppLayerDecoderEvents *decoder_events;          /**< per tx events */

    TAILQ_ENTRY(ENIPTransaction_) next;
    DetectEngineState *de_state;
} ENIPTransaction;

/** \brief Per flow ENIP state container */
typedef struct ENIPState_ {
    TAILQ_HEAD(, ENIPTransaction_) tx_list;  /**< transaction list */
    ENIPTransaction *curr;                   /**< ptr to current tx */
    ENIPTransaction *iter;
    uint64_t transaction_max;
    uint32_t unreplied_cnt;                 /**< number of unreplied requests in a row */
    uint32_t memuse;                        /**< state memuse, for comparing with
                                                 state-memcap settings */
    uint64_t tx_with_detect_state_cnt;

    uint16_t events;
    uint16_t givenup;

    /* used by TCP only */
    uint16_t offset;
    uint16_t record_len;
    uint8_t *buffer;
} ENIPState;









#endif	/* _DETECT_CIPSERVICE_H */

