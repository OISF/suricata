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
 * \author David DIALLO <diallo@et.esiea.fr>
 */

#ifndef __APP_LAYER_MODBUS_H__
#define __APP_LAYER_MODBUS_H__

#include "decode.h"
#include "detect-engine-state.h"
#include "queue.h"

/* Modbus Application Data Unit (ADU)
 * and Protocol Data Unit (PDU) messages */
enum {
    MODBUS_DECODER_EVENT_INVALID_PROTOCOL_ID,
    MODBUS_DECODER_EVENT_UNSOLICITED_RESPONSE,
    MODBUS_DECODER_EVENT_INVALID_LENGTH,
    MODBUS_DECODER_EVENT_INVALID_UNIT_IDENTIFIER,
    MODBUS_DECODER_EVENT_INVALID_FUNCTION_CODE,
    MODBUS_DECODER_EVENT_INVALID_VALUE,
    MODBUS_DECODER_EVENT_INVALID_EXCEPTION_CODE,
    MODBUS_DECODER_EVENT_VALUE_MISMATCH,
    MODBUS_DECODER_EVENT_FLOODED,
};

/* Modbus Function Code Categories. */
#define MODBUS_CAT_NONE                 0x0
#define MODBUS_CAT_PUBLIC_ASSIGNED      (1<<0)
#define MODBUS_CAT_PUBLIC_UNASSIGNED    (1<<1)
#define MODBUS_CAT_USER_DEFINED         (1<<2)
#define MODBUS_CAT_RESERVED             (1<<3)
#define MODBUS_CAT_ALL                  0xFF

/* Modbus Read/Write function and Access Types. */
#define MODBUS_TYP_NONE                 0x0
#define MODBUS_TYP_ACCESS_MASK          0x03
#define MODBUS_TYP_READ                 (1<<0)
#define MODBUS_TYP_WRITE                (1<<1)
#define MODBUS_TYP_ACCESS_FUNCTION_MASK 0x3C
#define MODBUS_TYP_BIT_ACCESS_MASK      0x0C
#define MODBUS_TYP_DISCRETES            (1<<2)
#define MODBUS_TYP_COILS                (1<<3)
#define MODBUS_TYP_WORD_ACCESS_MASK     0x30
#define MODBUS_TYP_INPUT                (1<<4)
#define MODBUS_TYP_HOLDING              (1<<5)
#define MODBUS_TYP_SINGLE               (1<<6)
#define MODBUS_TYP_MULTIPLE             (1<<7)
#define MODBUS_TYP_WRITE_SINGLE         (MODBUS_TYP_WRITE | MODBUS_TYP_SINGLE)
#define MODBUS_TYP_WRITE_MULTIPLE       (MODBUS_TYP_WRITE | MODBUS_TYP_MULTIPLE)
#define MODBUS_TYP_READ_WRITE_MULTIPLE  (MODBUS_TYP_READ | MODBUS_TYP_WRITE | MODBUS_TYP_MULTIPLE)

/* Modbus Transaction Structure, request/response. */
typedef struct ModbusTransaction_ {
    struct ModbusState_ *modbus;

    uint64_t    tx_num;         /**< internal: id */
    uint16_t    transactionId;
    uint16_t    length;
    uint8_t     function;
    uint8_t     category;
    uint8_t     type;
    uint8_t     replied;                    /**< bool indicating request is replied to. */

    union {
        uint16_t    subFunction;
        uint8_t     mei;
        struct {
            struct {
                uint16_t    address;
                uint16_t    quantity;
            } read;
            struct {
                uint16_t    address;
                uint16_t    quantity;
                uint8_t     count;
            } write;
        };
    };
    uint16_t    *data;  /**< to store data to write, bit is converted in 16bits. */

    AppLayerDecoderEvents *decoder_events;  /**< per tx events */
    DetectEngineState *de_state;

    TAILQ_ENTRY(ModbusTransaction_) next;
} ModbusTransaction;

/* Modbus State Structure. */
typedef struct ModbusState_ {
    TAILQ_HEAD(, ModbusTransaction_)    tx_list;    /**< transaction list */
    ModbusTransaction                   *curr;      /**< ptr to current tx */
    uint64_t                            transaction_max;
    uint32_t                            unreplied_cnt;  /**< number of unreplied requests */
    uint16_t                            events;
    uint8_t                             givenup;    /**< bool indicating flood. */
} ModbusState;

void RegisterModbusParsers(void);
void ModbusParserRegisterTests(void);

/* Modbus Application Data Unit (ADU) length range. */
#define MODBUS_MIN_ADU_LEN  2
#define MODBUS_MAX_ADU_LEN  254

/* Modbus Protocol version. */
#define MODBUS_PROTOCOL_VER 0

/* Modbus Unit Identifier range. */
#define MODBUS_MIN_INVALID_UNIT_ID  247
#define MODBUS_MAX_INVALID_UNIT_ID  255

/* Modbus Quantity range. */
#define MODBUS_MIN_QUANTITY                 0
#define MODBUS_MAX_QUANTITY_IN_BIT_ACCESS   2000
#define MODBUS_MAX_QUANTITY_IN_WORD_ACCESS  125

/* Modbus Count range. */
#define MODBUS_MIN_COUNT    1
#define MODBUS_MAX_COUNT    250

/* Modbus Function Code. */
#define MODBUS_FUNC_NONE                0x00
#define MODBUS_FUNC_READCOILS           0x01
#define MODBUS_FUNC_READDISCINPUTS      0x02
#define MODBUS_FUNC_READHOLDREGS        0x03
#define MODBUS_FUNC_READINPUTREGS       0x04
#define MODBUS_FUNC_WRITESINGLECOIL     0x05
#define MODBUS_FUNC_WRITESINGLEREG      0x06
#define MODBUS_FUNC_READEXCSTATUS       0x07
#define MODBUS_FUNC_DIAGNOSTIC          0x08
#define MODBUS_FUNC_GETCOMEVTCOUNTER    0x0b
#define MODBUS_FUNC_GETCOMEVTLOG        0x0c
#define MODBUS_FUNC_WRITEMULTCOILS      0x0f
#define MODBUS_FUNC_WRITEMULTREGS       0x10
#define MODBUS_FUNC_REPORTSERVERID      0x11
#define MODBUS_FUNC_READFILERECORD      0x14
#define MODBUS_FUNC_WRITEFILERECORD     0x15
#define MODBUS_FUNC_MASKWRITEREG        0x16
#define MODBUS_FUNC_READWRITEMULTREGS   0x17
#define MODBUS_FUNC_READFIFOQUEUE       0x18
#define MODBUS_FUNC_ENCAPINTTRANS       0x2b
#define MODBUS_FUNC_MASK                0x7f
#define MODBUS_FUNC_ERRORMASK           0x80

/* Modbus Diagnostic functions: Subfunction Code. */
#define MODBUS_SUBFUNC_QUERY_DATA           0x00
#define MODBUS_SUBFUNC_RESTART_COM          0x01
#define MODBUS_SUBFUNC_DIAG_REGS            0x02
#define MODBUS_SUBFUNC_CHANGE_DELIMITER     0x03
#define MODBUS_SUBFUNC_LISTEN_MODE          0x04
#define MODBUS_SUBFUNC_CLEAR_REGS           0x0a
#define MODBUS_SUBFUNC_BUS_MSG_COUNT        0x0b
#define MODBUS_SUBFUNC_COM_ERR_COUNT        0x0c
#define MODBUS_SUBFUNC_EXCEPT_ERR_COUNT     0x0d
#define MODBUS_SUBFUNC_SERVER_MSG_COUNT     0x0e
#define MODBUS_SUBFUNC_SERVER_NO_RSP_COUNT  0x0f
#define MODBUS_SUBFUNC_SERVER_NAK_COUNT     0x10
#define MODBUS_SUBFUNC_SERVER_BUSY_COUNT    0x11
#define MODBUS_SUBFUNC_SERVER_CHAR_COUNT    0x12
#define MODBUS_SUBFUNC_CLEAR_COUNT          0x14

/* Modbus Encapsulated Interface Transport function: MEI type. */
#define MODBUS_MEI_ENCAPINTTRANS_CAN   0x0d
#define MODBUS_MEI_ENCAPINTTRANS_READ  0x0e

/* Modbus Exception Codes. */
#define MODBUS_ERROR_CODE_ILLEGAL_FUNCTION      0x01
#define MODBUS_ERROR_CODE_ILLEGAL_DATA_ADDRESS  0x02
#define MODBUS_ERROR_CODE_ILLEGAL_DATA_VALUE    0x03
#define MODBUS_ERROR_CODE_SERVER_DEVICE_FAILURE 0x04
#define MODBUS_ERROR_CODE_MEMORY_PARITY_ERROR   0x08



#endif /* __APP_LAYER_MODBUS_H__ */
