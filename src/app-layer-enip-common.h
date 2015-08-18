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

// clean later
#include "detect-cipservice.h"
#include "decode-enip.h"


enum {
    ENIP_DECODER_EVENT_UNSOLLICITED_RESPONSE,
    ENIP_DECODER_EVENT_MALFORMED_DATA,
    ENIP_DECODER_EVENT_NOT_A_REQUEST,
    ENIP_DECODER_EVENT_NOT_A_RESPONSE,
    ENIP_DECODER_EVENT_Z_FLAG_SET,
    ENIP_DECODER_EVENT_FLOODED,
    ENIP_DECODER_EVENT_STATE_MEMCAP_REACHED,
};




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

    TAILQ_HEAD(, SegmentEntry_) segment_list;        /**< list for CIP segment */
    TAILQ_HEAD(, AttributeEntry_) attrib_list;        /**< list for CIP segment */

    TAILQ_ENTRY(CIPServiceEntry_) next;
} CIPServiceEntry;


typedef struct ENIPTransaction_ {
    uint16_t tx_num;                                /**< internal: id */
    uint16_t tx_id;                                 /**< transaction id */
    uint8_t replied;                                /**< bool indicating request is
                                                         replied to. */
    uint8_t reply_lost;
    uint8_t rcode;                                  /**< response code (e.g. "no error" / "no such name") */
    uint8_t recursion_desired;                      /**< server said "recursion desired" */

    ENIPEncapHdr header; //encapsulation header
    ENIPEncapDataHdr encap_data_header; //encapsulation data header
    ENIPEncapAddresItem encap_addr_item; //encapsulated address item
    ENIPEncapDataItem encap_data_item; //encapsulated data item

    TAILQ_HEAD(, CIPServiceEntry_) service_list;        /**< list for CIP  */

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

    uint16_t test;

    /* used by TCP only */
    uint16_t offset;
    uint16_t record_len;
    uint8_t *buffer;
} ENIPState;


int DecodeENIPPDU(uint8_t *input, uint32_t input_len, ENIPTransaction *enip_data);
int DecodeCommonPacketFormatPDU(uint8_t *input, uint32_t input_len, ENIPTransaction *enip_data, uint16_t offset);
int DecodeCIPPDU(uint8_t *input, uint32_t input_len, ENIPTransaction *enip_data, uint16_t offset);
int DecodeCIPRequestPDU(uint8_t *input, uint32_t input_len, ENIPTransaction *enip_data, uint16_t offset);
int DecodeCIPResponsePDU(uint8_t *input, uint32_t input_len, ENIPTransaction *enip_data, uint16_t offset);
int DecodeCIPRequestPathPDU(uint8_t *input, uint32_t input_len, CIPServiceEntry *node, uint16_t offset);
int DecodeCIPRequestMSPPDU(uint8_t *input, uint32_t input_len, ENIPTransaction *enip_data, uint16_t offset);
int DecodeCIPResponseMSPPDU(uint8_t *input, uint32_t input_len, ENIPTransaction *enip_data, uint16_t offset);



#endif /* __APP_LAYER_MODBUS_H__ */
