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
 *
 * App-layer parser for Modbus protocol
 *
 */

#include "suricata-common.h"

#include "util-debug.h"
#include "util-byte.h"
#include "util-enum.h"
#include "util-mem.h"
#include "util-misc.h"

#include "stream.h"
#include "stream-tcp.h"

#include "app-layer-protos.h"
#include "app-layer-parser.h"
#include "app-layer-modbus.h"

#include "app-layer-detect-proto.h"

#include "conf.h"
#include "conf-yaml-loader.h"
#include "decode.h"

SCEnumCharMap modbus_decoder_event_table[ ] = {
    /* Modbus Application Data Unit messages - ADU Modbus */
    { "INVALID_PROTOCOL_ID",        MODBUS_DECODER_EVENT_INVALID_PROTOCOL_ID    },
    { "UNSOLICITED_RESPONSE",       MODBUS_DECODER_EVENT_UNSOLICITED_RESPONSE   },
    { "INVALID_LENGTH",             MODBUS_DECODER_EVENT_INVALID_LENGTH         },
    { "INVALID_UNIT_IDENTIFIER",    MODBUS_DECODER_EVENT_INVALID_UNIT_IDENTIFIER},

    /* Modbus Protocol Data Unit messages - PDU Modbus */
    { "INVALID_FUNCTION_CODE",      MODBUS_DECODER_EVENT_INVALID_FUNCTION_CODE  },
    { "INVALID_VALUE",              MODBUS_DECODER_EVENT_INVALID_VALUE          },
    { "INVALID_EXCEPTION_CODE",     MODBUS_DECODER_EVENT_INVALID_EXCEPTION_CODE },
    { "VALUE_MISMATCH",             MODBUS_DECODER_EVENT_VALUE_MISMATCH         },

    /* Modbus Decoder event */
    { "FLOODED",                    MODBUS_DECODER_EVENT_FLOODED},
    { NULL,                         -1 },
};

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

/* Modbus Application Protocol (MBAP) header. */
struct ModbusHeader_ {
    uint16_t     transactionId;
    uint16_t     protocolId;
    uint16_t     length;
    uint8_t      unitId;
}  __attribute__((__packed__));
typedef struct ModbusHeader_ ModbusHeader;

/* Modbus Read/Write function and Access Types. */
#define MODBUS_TYP_WRITE_SINGLE         (MODBUS_TYP_WRITE | MODBUS_TYP_SINGLE)
#define MODBUS_TYP_WRITE_MULTIPLE       (MODBUS_TYP_WRITE | MODBUS_TYP_MULTIPLE)
#define MODBUS_TYP_READ_WRITE_MULTIPLE  (MODBUS_TYP_READ | MODBUS_TYP_WRITE | MODBUS_TYP_MULTIPLE)

/* Macro to convert quantity value (in bit) into count value (in word): count = Ceil(quantity/8) */
#define CEIL(quantity) (((quantity) + 7)>>3)

/* Modbus Default unreplied Modbus requests are considered a flood */
#define MODBUS_CONFIG_DEFAULT_REQUEST_FLOOD 500

/* Modbus default stream reassembly depth */
#define MODBUS_CONFIG_DEFAULT_STREAM_DEPTH 0

static uint32_t request_flood = MODBUS_CONFIG_DEFAULT_REQUEST_FLOOD;
static uint32_t stream_depth = MODBUS_CONFIG_DEFAULT_STREAM_DEPTH;

static int ModbusStateGetEventInfo(const char *event_name, int *event_id, AppLayerEventType *event_type)
{
    *event_id = SCMapEnumNameToValue(event_name, modbus_decoder_event_table);

    if (*event_id == -1) {
        SCLogError(SC_ERR_INVALID_ENUM_MAP, "event \"%s\" not present in "
                   "modbus's enum map table.",  event_name);
        /* yes this is fatal */
        return -1;
    }

    *event_type = APP_LAYER_EVENT_TYPE_TRANSACTION;

    return 0;
}

static int ModbusStateGetEventInfoById(int event_id, const char **event_name,
                                       AppLayerEventType *event_type)
{
    *event_name = SCMapEnumValueToName(event_id, modbus_decoder_event_table);

    if (*event_name == NULL) {
        SCLogError(SC_ERR_INVALID_ENUM_MAP, "event \"%d\" not present in "
                   "modbus's enum map table.",  event_id);
        /* yes this is fatal */
        return -1;
    }

    *event_type = APP_LAYER_EVENT_TYPE_TRANSACTION;

    return 0;
}

static void ModbusSetEvent(ModbusState *modbus, uint8_t e)
{
    if (modbus && modbus->curr) {
        SCLogDebug("modbus->curr->decoder_events %p", modbus->curr->decoder_events);
        AppLayerDecoderEventsSetEventRaw(&modbus->curr->decoder_events, e);
        SCLogDebug("modbus->curr->decoder_events %p", modbus->curr->decoder_events);
        modbus->events++;
    } else
        SCLogDebug("couldn't set event %u", e);
}

static AppLayerDecoderEvents *ModbusGetEvents(void *tx)
{
    return ((ModbusTransaction *)tx)->decoder_events;
}

static int ModbusGetAlstateProgress(void *modbus_tx, uint8_t direction)
{
    ModbusTransaction   *tx     = (ModbusTransaction *) modbus_tx;
    ModbusState         *modbus = tx->modbus;

    if (tx->replied == 1)
        return 1;

    /* Check flood limit */
    if ((modbus->givenup == 1)  &&
        ((modbus->transaction_max - tx->tx_num) > request_flood))
        return 1;

    return 0;
}

/** \brief Get value for 'complete' status in Modbus
 */
static int ModbusGetAlstateProgressCompletionStatus(uint8_t direction)
{
    return 1;
}

static void *ModbusGetTx(void *alstate, uint64_t tx_id)
{
    ModbusState         *modbus = (ModbusState *) alstate;
    ModbusTransaction   *tx = NULL;

    if (modbus->curr && modbus->curr->tx_num == tx_id + 1)
        return modbus->curr;

    TAILQ_FOREACH(tx, &modbus->tx_list, next) {
        SCLogDebug("tx->tx_num %"PRIu64", tx_id %"PRIu64, tx->tx_num, (tx_id+1));
        if (tx->tx_num != (tx_id+1))
            continue;

        SCLogDebug("returning tx %p", tx);
        return tx;
    }

    return NULL;
}

static void ModbusSetTxLogged(void *alstate, void *vtx, LoggerId logged)
{
    ModbusTransaction *tx = (ModbusTransaction *)vtx;
    tx->logged = logged;
}

static LoggerId ModbusGetTxLogged(void *alstate, void *vtx)
{
    ModbusTransaction *tx = (ModbusTransaction *)vtx;
    return tx->logged;
}

static uint64_t ModbusGetTxCnt(void *alstate)
{
    return ((uint64_t) ((ModbusState *) alstate)->transaction_max);
}

/** \internal
 *  \brief Find the Modbus Transaction in the state based on Transaction ID.
 *
 *  \param  modbus          Pointer to Modbus state structure
 *  \param  transactionId   Transaction ID of the transaction
 *
 *  \retval tx or NULL      if not found
 */
static ModbusTransaction *ModbusTxFindByTransaction(const ModbusState   *modbus,
                                                    const uint16_t      transactionId)
{
    ModbusTransaction *tx = NULL;

    if (modbus->curr == NULL)
        return NULL;

    /* fast path */
    if ((modbus->curr->transactionId == transactionId)  &&
        !(modbus->curr->replied)) {
        return modbus->curr;
    /* slow path, iterate list */
    } else {
        TAILQ_FOREACH(tx, &modbus->tx_list, next) {
            if ((tx->transactionId == transactionId)    &&
                !(modbus->curr->replied))
                return tx;
        }
    }
    /* not found */
    return NULL;
}

/** \internal
 *  \brief Allocate a Modbus Transaction and
 *          add it into Transaction list of Modbus State
 *
 *  \param  modbus Pointer to Modbus state structure
 *
 *  \retval Pointer to Transaction or NULL pointer
 */
static ModbusTransaction *ModbusTxAlloc(ModbusState *modbus) {
    ModbusTransaction *tx;

    tx = (ModbusTransaction *) SCCalloc(1, sizeof(ModbusTransaction));
    if (unlikely(tx == NULL))
        return NULL;

    modbus->transaction_max++;
    modbus->unreplied_cnt++;

    /* Check flood limit */
    if ((request_flood != 0) && (modbus->unreplied_cnt > request_flood)) {
        ModbusSetEvent(modbus, MODBUS_DECODER_EVENT_FLOODED);
        modbus->givenup = 1;
    }

    modbus->curr = tx;

    SCLogDebug("modbus->transaction_max updated to %"PRIu64, modbus->transaction_max);

    TAILQ_INSERT_TAIL(&modbus->tx_list, tx, next);

    tx->modbus  = modbus;
    tx->tx_num  = modbus->transaction_max;

    return tx;
}

/** \internal
 *  \brief Free a Modbus Transaction
 *
 *  \retval Pointer to Transaction or NULL pointer
 */
static void ModbusTxFree(ModbusTransaction *tx) {
    SCEnter();
    if (tx->data != NULL)
        SCFree(tx->data);

    AppLayerDecoderEventsFreeEvents(&tx->decoder_events);

    if (tx->de_state != NULL)
        DetectEngineStateFree(tx->de_state);

    SCFree(tx);
    SCReturn;
}

/**
 *  \brief Modbus transaction cleanup callback
 */
static void ModbusStateTxFree(void *state, uint64_t tx_id)
{
    SCEnter();
    ModbusState         *modbus = (ModbusState *) state;
    ModbusTransaction   *tx = NULL, *ttx;

    SCLogDebug("state %p, id %"PRIu64, modbus, tx_id);

    TAILQ_FOREACH_SAFE(tx, &modbus->tx_list, next, ttx) {
        SCLogDebug("tx %p tx->tx_num %"PRIu64", tx_id %"PRIu64, tx, tx->tx_num, (tx_id+1));

        if (tx->tx_num != (tx_id+1))
            continue;

        if (tx == modbus->curr)
            modbus->curr = NULL;

        if (tx->decoder_events != NULL) {
            if (tx->decoder_events->cnt <= modbus->events)
                modbus->events -= tx->decoder_events->cnt;
            else
                modbus->events = 0;
        }

        modbus->unreplied_cnt--;

        /* Check flood limit */
        if ((modbus->givenup == 1)                  &&
            (request_flood != 0)                    &&
            (modbus->unreplied_cnt < request_flood) )
            modbus->givenup = 0;

        TAILQ_REMOVE(&modbus->tx_list, tx, next);
        ModbusTxFree(tx);
        break;
    }
    SCReturn;
}

/** \internal
 *  \brief Extract 8bits data from pointer the received input data
 *
 *  \param  res		    Pointer to the result
 *  \param  input       Pointer the received input data
 *  \param  input_len   Length of the received input data
 *  \param  offset      Offset of the received input data pointer
 */
static int ModbusExtractUint8(ModbusState   *modbus,
                              uint8_t       *res,
                              uint8_t       *input,
                              uint32_t      input_len,
                              uint16_t      *offset) {
    SCEnter();
    if (input_len < (uint32_t) (*offset + sizeof(uint8_t))) {
        ModbusSetEvent(modbus, MODBUS_DECODER_EVENT_INVALID_LENGTH);
        SCReturnInt(-1);
    }

    *res     = *(input + *offset);
    *offset += sizeof(uint8_t);
    SCReturnInt(0);
}

/** \internal
 *  \brief Extract 16bits data from pointer the received input data
 *
 *  \param  res		    Pointer to the result
 *  \param  input       Pointer the received input data
 *  \param  input_len   Length of the received input data
 *  \param  offset      Offset of the received input data pointer
 */
static int ModbusExtractUint16(ModbusState  *modbus,
                               uint16_t     *res,
                               uint8_t      *input,
                               uint32_t     input_len,
                               uint16_t     *offset) {
    SCEnter();
    if (input_len < (uint32_t) (*offset + sizeof(uint16_t))) {
        ModbusSetEvent(modbus, MODBUS_DECODER_EVENT_INVALID_LENGTH);
        SCReturnInt(-1);
    }

    ByteExtractUint16(res, BYTE_BIG_ENDIAN, sizeof(uint16_t), (const uint8_t *) (input + *offset));
    *offset += sizeof(uint16_t);
    SCReturnInt(0);
}

/** \internal
 *  \brief Check length field in Modbus header according to code function
 *
 *  \param  modbus  Pointer to Modbus state structure
 *  \param  length  Length field in Modbus Header
 *  \param  len		Length according to code functio
 */
static int ModbusCheckHeaderLength(ModbusState *modbus,
                                   uint16_t    length,
                                   uint16_t    len) {
    SCEnter();
    if (length != len) {
        ModbusSetEvent(modbus, MODBUS_DECODER_EVENT_INVALID_LENGTH);
        SCReturnInt(-1);
    }
    SCReturnInt(0);
}

/** \internal
 *  \brief Check Modbus header
 *
 *  \param  tx      Pointer to Modbus Transaction structure
 *  \param  modbus  Pointer to Modbus state structure
 *  \param  header  Pointer to Modbus header state in which the value to be stored
 */
static void ModbusCheckHeader(ModbusState       *modbus,
                              ModbusHeader      *header)
{
    SCEnter();
    /* MODBUS protocol is identified by the value 0. */
    if (header->protocolId != MODBUS_PROTOCOL_VER)
        ModbusSetEvent(modbus, MODBUS_DECODER_EVENT_INVALID_PROTOCOL_ID);

    /* Check Length field that is a byte count of the following fields */
    if ((header->length < MODBUS_MIN_ADU_LEN)   ||
        (header->length > MODBUS_MAX_ADU_LEN)   )
        ModbusSetEvent(modbus, MODBUS_DECODER_EVENT_INVALID_LENGTH);

    /* Check Unit Identifier field that is not in invalid range */
    if ((header->unitId > MODBUS_MIN_INVALID_UNIT_ID)   &&
        (header->unitId < MODBUS_MAX_INVALID_UNIT_ID)   )
        ModbusSetEvent(modbus, MODBUS_DECODER_EVENT_INVALID_UNIT_IDENTIFIER);

    SCReturn;
}

/** \internal
 *  \brief Parse Exception Response and verify protocol compliance.
 *
 *  \param  tx          Pointer to Modbus Transaction structure
 *  \param  modbus      Pointer to Modbus state structure
 *  \param  input       Pointer the received input data
 *  \param  input_len   Length of the received input data
 *  \param  offset      Offset of the received input data pointer
 */
static void ModbusExceptionResponse(ModbusTransaction   *tx,
                                    ModbusState         *modbus,
                                    uint8_t             *input,
                                    uint32_t            input_len,
                                    uint16_t            *offset)
{
    SCEnter();
    uint8_t exception = 0;

    /* Exception code (1 byte) */
    if (ModbusExtractUint8(modbus, &exception, input, input_len, offset))
        SCReturn;

    switch (exception) {
        case MODBUS_ERROR_CODE_ILLEGAL_FUNCTION:
        case MODBUS_ERROR_CODE_SERVER_DEVICE_FAILURE:
            break;
        case MODBUS_ERROR_CODE_ILLEGAL_DATA_VALUE:
            if (tx->function == MODBUS_FUNC_DIAGNOSTIC) {
                break;
            }
            /* Fallthrough */
        case MODBUS_ERROR_CODE_ILLEGAL_DATA_ADDRESS:
            if (    (tx->type & MODBUS_TYP_ACCESS_FUNCTION_MASK)    ||
                    (tx->function == MODBUS_FUNC_READFIFOQUEUE)     ||
                    (tx->function == MODBUS_FUNC_ENCAPINTTRANS)) {
                break;
            }
            /* Fallthrough */
        case MODBUS_ERROR_CODE_MEMORY_PARITY_ERROR:
            if (    (tx->function == MODBUS_FUNC_READFILERECORD)     ||
                    (tx->function == MODBUS_FUNC_WRITEFILERECORD)    ) {
                break;
            }
            /* Fallthrough */
        default:
            ModbusSetEvent(modbus, MODBUS_DECODER_EVENT_INVALID_EXCEPTION_CODE);
            break;
    }

    SCReturn;
}

/** \internal
 *  \brief Parse Read data Request, complete Transaction structure
 *          and verify protocol compliance.
 *
 *  \param  tx          Pointer to Modbus Transaction structure
 *  \param  modbus      Pointer to Modbus state structure
 *  \param  input       Pointer the received input data
 *  \param  input_len   Length of the received input data
 *  \param  offset      Offset of the received input data pointer
 */
static void ModbusParseReadRequest(ModbusTransaction   *tx,
                                   ModbusState         *modbus,
                                   uint8_t             *input,
                                   uint32_t            input_len,
                                   uint16_t            *offset)
{
    SCEnter();
    uint16_t    quantity;
    uint8_t     type = tx->type;

    /* Starting Address (2 bytes) */
    if (ModbusExtractUint16(modbus, &(tx->read.address), input, input_len, offset))
        goto end;

    /* Quantity (2 bytes) */
    if (ModbusExtractUint16(modbus, &(tx->read.quantity), input, input_len, offset))
        goto end;
    quantity = tx->read.quantity;

    /* Check Quantity range */
    if (type & MODBUS_TYP_BIT_ACCESS_MASK) {
        if ((quantity == MODBUS_MIN_QUANTITY) ||
            (quantity > MODBUS_MAX_QUANTITY_IN_BIT_ACCESS))
            goto error;
    } else {
        if ((quantity == MODBUS_MIN_QUANTITY) ||
            (quantity > MODBUS_MAX_QUANTITY_IN_WORD_ACCESS))
            goto error;
    }

    if (~type & MODBUS_TYP_WRITE)
        /* Except from Read/Write Multiple Registers function (code 23)     */
        /* The length of all Read Data function requests is 6 bytes         */
        /* Modbus Application Protocol Specification V1.1b3 from 6.1 to 6.4 */
        ModbusCheckHeaderLength(modbus, tx->length, 6);

    goto end;

error:
    ModbusSetEvent(modbus, MODBUS_DECODER_EVENT_INVALID_VALUE);
end:
    SCReturn;
}

/** \internal
 *  \brief Parse Read data Response and verify protocol compliance
 *
 *  \param  tx          Pointer to Modbus Transaction structure
 *  \param  modbus      Pointer to Modbus state structure
 *  \param  input       Pointer the received input data
 *  \param  input_len   Length of the received input data
 *  \param  offset      Offset of the received input data pointer
 */
static void ModbusParseReadResponse(ModbusTransaction   *tx,
                                    ModbusState         *modbus,
                                    uint8_t             *input,
                                    uint32_t            input_len,
                                    uint16_t            *offset)
{
    SCEnter();
    uint8_t count = 0;

    /* Count (1 bytes) */
    if (ModbusExtractUint8(modbus, &count, input, input_len, offset))
        goto end;

    /* Check Count range and value according to the request */
    if ((tx->type) & MODBUS_TYP_BIT_ACCESS_MASK) {
        if (    (count < MODBUS_MIN_COUNT)          ||
                (count > MODBUS_MAX_COUNT)          ||
                (count != CEIL(tx->read.quantity)))
            goto error;
    } else {
        if (    (count == MODBUS_MIN_COUNT)         ||
                (count > MODBUS_MAX_COUNT)          ||
                (count != (2 * (tx->read.quantity))))
            goto error;
    }

    /* Except from Read/Write Multiple Registers function (code 23)         */
    /* The length of all Read Data function responses is (3 bytes + count)  */
    /* Modbus Application Protocol Specification V1.1b3 from 6.1 to 6.4     */
    ModbusCheckHeaderLength(modbus, tx->length, 3 + count);
    goto end;

error:
    ModbusSetEvent(modbus, MODBUS_DECODER_EVENT_VALUE_MISMATCH);
end:
    SCReturn;
}

/** \internal
 *  \brief Parse Write data Request, complete Transaction structure
 *          and verify protocol compliance.
 *
 *  \param  tx          Pointer to Modbus Transaction structure
 *  \param  modbus      Pointer to Modbus state structure
 *  \param  input       Pointer the received input data
 *  \param  input_len   Length of the received input data
 *  \param  offset      Offset of the received input data pointer
 *
 *  \retval On success returns 0 or on failure returns -1.
 */
static int ModbusParseWriteRequest(ModbusTransaction   *tx,
                                   ModbusState         *modbus,
                                   uint8_t             *input,
                                   uint32_t            input_len,
                                   uint16_t            *offset)
{
    SCEnter();
    uint16_t    quantity = 1, word = 0;
    uint8_t     byte = 0, count = 1, type = tx->type;

    int i = 0;

    /* Starting/Output/Register Address (2 bytes) */
    if (ModbusExtractUint16(modbus, &(tx->write.address), input, input_len, offset))
        goto end;

    if (type & MODBUS_TYP_SINGLE) {
        /* The length of Write Single Coil (code 5) and                 */
        /* Write Single Register (code 6) requests is 6 bytes           */
        /* Modbus Application Protocol Specification V1.1b3 6.5 and 6.6 */
        if (ModbusCheckHeaderLength(modbus, tx->length, 6))
            goto end;
    } else if (type & MODBUS_TYP_MULTIPLE) {
        /* Quantity (2 bytes) */
        if (ModbusExtractUint16(modbus, &quantity, input, input_len, offset))
            goto end;
        tx->write.quantity = quantity;

        /* Count (1 bytes) */
        if (ModbusExtractUint8(modbus, &count, input, input_len, offset))
            goto end;
        tx->write.count = count;

        if (type & MODBUS_TYP_BIT_ACCESS_MASK) {
            /* Check Quantity range and conversion in byte (count) */
            if ((quantity == MODBUS_MIN_QUANTITY)               ||
                (quantity > MODBUS_MAX_QUANTITY_IN_BIT_ACCESS)  ||
                (quantity != CEIL(count)))
                goto error;

            /* The length of Write Multiple Coils (code 15) request is (7 + count)  */
            /* Modbus Application Protocol Specification V1.1b3 6.11                */
            if (ModbusCheckHeaderLength(modbus, tx->length, 7 + count))
                goto end;
        } else {
            /* Check Quantity range and conversion in byte (count) */
            if ((quantity == MODBUS_MIN_QUANTITY)               ||
                (quantity > MODBUS_MAX_QUANTITY_IN_WORD_ACCESS) ||
                (count != (2 * quantity)))
                goto error;

            if (type & MODBUS_TYP_READ) {
                /* The length of Read/Write Multiple Registers function (code 23)   */
                /* request is (11 bytes + count)                                    */
                /* Modbus Application Protocol Specification V1.1b3 6.17            */
                if (ModbusCheckHeaderLength(modbus, tx->length, 11 + count))
                    goto end;
            } else {
                /* The length of Write Multiple Coils (code 15) and                             */
                /* Write Multiple Registers (code 16) functions requests is (7 bytes + count)   */
                /* Modbus Application Protocol Specification V1.1b3 from 6.11 and 6.12          */
                if (ModbusCheckHeaderLength(modbus, tx->length, 7 + count))
                    goto end;
            }
        }
    } else {
        /* Mask Write Register function (And_Mask and Or_Mask) */
        quantity = 2;

        /* The length of Mask Write Register (code 22) function request is 8    */
        /* Modbus Application Protocol Specification V1.1b3 6.16                */
        if (ModbusCheckHeaderLength(modbus, tx->length, 8))
            goto end;
    }

    if (type & MODBUS_TYP_COILS) {
        /* Output value (data block) unit is count */
        tx->data = (uint16_t *) SCCalloc(1, count * sizeof(uint16_t));
        if (unlikely(tx->data == NULL))
            SCReturnInt(-1);

        if (type & MODBUS_TYP_SINGLE) {
            /* Outputs value (2 bytes) */
            if (ModbusExtractUint16(modbus, &word, input, input_len, offset))
                goto end;
            tx->data[i] = word;

            if ((word != 0x00) && (word != 0xFF00))
                goto error;
        } else {
            for (i = 0; i < count; i++) {
                /* Outputs value (1 byte) */
                if (ModbusExtractUint8(modbus, &byte, input, input_len, offset))
                    goto end;
                tx->data[i] = (uint16_t) byte;
            }
        }
    } else {
        /* Registers value (data block) unit is quantity */
        tx->data = (uint16_t *) SCCalloc(1, quantity * sizeof(uint16_t));
        if (unlikely(tx->data == NULL))
            SCReturnInt(-1);

        for (i = 0; i < quantity; i++) {
            /* Outputs/Registers value (2 bytes) */
            if (ModbusExtractUint16(modbus, &word, input, input_len, offset))
                goto end;
            tx->data[i] = word;
        }
    }
    goto end;

error:
    ModbusSetEvent(modbus, MODBUS_DECODER_EVENT_INVALID_VALUE);
end:
    SCReturnInt(0);
}

/** \internal
 *  \brief Parse Write data Response and verify protocol compliance
 *
 *  \param  tx          Pointer to Modbus Transaction structure
 *  \param  modbus      Pointer to Modbus state structure
 *  \param  input       Pointer the received input data
 *  \param  input_len   Length of the received input data
 *  \param  offset      Offset of the received input data pointer
 */
static void ModbusParseWriteResponse(ModbusTransaction   *tx,
                                     ModbusState         *modbus,
                                     uint8_t             *input,
                                     uint32_t            input_len,
                                     uint16_t            *offset)
{
    SCEnter();
    uint16_t    address = 0, quantity = 0, word = 0;
    uint8_t     type = tx->type;

    /* Starting Address (2 bytes) */
    if (ModbusExtractUint16(modbus, &address, input, input_len, offset))
        goto end;

    if (address != tx->write.address)
        goto error;

    if (type & MODBUS_TYP_SINGLE) {
        /* Check if Outputs/Registers value has been stored */
        if (tx->data != NULL)
        {
            /* Outputs/Registers value (2 bytes) */
            if (ModbusExtractUint16(modbus, &word, input, input_len, offset))
                goto end;

            /* Check with Outputs/Registers from request */
            if (word != tx->data[0])
                goto error;
        }
    } else if (type & MODBUS_TYP_MULTIPLE) {
        /* Quantity (2 bytes) */
        if (ModbusExtractUint16(modbus, &quantity, input, input_len, offset))
            goto end;

        /* Check Quantity range */
        if (type & MODBUS_TYP_BIT_ACCESS_MASK) {
            if ((quantity == MODBUS_MIN_QUANTITY) ||
                (quantity > MODBUS_MAX_QUANTITY_IN_WORD_ACCESS))
                goto error;
        } else {
            if ((quantity == MODBUS_MIN_QUANTITY) ||
                (quantity > MODBUS_MAX_QUANTITY_IN_BIT_ACCESS))
                goto error;
        }

        /* Check Quantity value according to the request */
        if (quantity != tx->write.quantity)
            goto error;
    } else {
        /* Check if And_Mask and Or_Mask values have been stored */
        if (tx->data != NULL)
        {
            /* And_Mask value (2 bytes) */
            if (ModbusExtractUint16(modbus, &word, input, input_len, offset))
                goto end;

            /* Check And_Mask value according to the request */
            if (word != tx->data[0])
                goto error;

            /* And_Or_Mask value (2 bytes) */
            if (ModbusExtractUint16(modbus, &word, input, input_len, offset))
                goto end;

            /* Check Or_Mask value according to the request */
            if (word != tx->data[1])
                goto error;
        }

        /* The length of Mask Write Register (code 22) function response is 8   */
        /* Modbus Application Protocol Specification V1.1b3 6.16                */
        ModbusCheckHeaderLength(modbus, tx->length, 8);
        goto end;
    }

    /* Except from Mask Write Register (code 22)                                        */
    /* The length of all Write Data function responses is 6                             */
    /* Modbus Application Protocol Specification V1.1b3 6.5, 6.6, 6.11, 6.12 and 6.17   */
    ModbusCheckHeaderLength(modbus, tx->length, 6);
    goto end;

error:
    ModbusSetEvent(modbus, MODBUS_DECODER_EVENT_VALUE_MISMATCH);
end:
    SCReturn;
}

/** \internal
 *  \brief Parse Diagnostic Request, complete Transaction
 *          structure (Category) and verify protocol compliance.
 *
 *  \param  tx          Pointer to Modbus Transaction structure
 *  \param  modbus      Pointer to Modbus state structure
 *  \param  input       Pointer the received input data
 *  \param  input_len   Length of the received input data
 *  \param  offset      Offset of the received input data pointer
 *
 *  \retval Reserved category function returns 1 otherwise returns 0.
 */
static int ModbusParseDiagnosticRequest(ModbusTransaction   *tx,
                                        ModbusState         *modbus,
                                        uint8_t             *input,
                                        uint32_t            input_len,
                                        uint16_t            *offset)
{
    SCEnter();
    uint16_t data = 0;

    /* Sub-function (2 bytes) */
    if (ModbusExtractUint16(modbus, &(tx->subFunction), input, input_len, offset))
        goto end;

    /* Data (2 bytes) */
    if (ModbusExtractUint16(modbus, &data, input, input_len, offset))
        goto end;

    if (tx->subFunction != MODBUS_SUBFUNC_QUERY_DATA) {
        switch (tx->subFunction) {
            case MODBUS_SUBFUNC_RESTART_COM:
                if ((data != 0x00) && (data != 0xFF00))
                    goto error;
                break;

            case MODBUS_SUBFUNC_CHANGE_DELIMITER:
                if ((data & 0xFF) != 0x00)
                    goto error;
                break;

            case MODBUS_SUBFUNC_LISTEN_MODE:
                /* No answer is expected then mark tx as completed. */
                tx->replied = 1;
                /* Fallthrough */
            case MODBUS_SUBFUNC_DIAG_REGS:
            case MODBUS_SUBFUNC_CLEAR_REGS:
            case MODBUS_SUBFUNC_BUS_MSG_COUNT:
            case MODBUS_SUBFUNC_COM_ERR_COUNT:
            case MODBUS_SUBFUNC_EXCEPT_ERR_COUNT:
            case MODBUS_SUBFUNC_SERVER_MSG_COUNT:
            case MODBUS_SUBFUNC_SERVER_NO_RSP_COUNT:
            case MODBUS_SUBFUNC_SERVER_NAK_COUNT:
            case MODBUS_SUBFUNC_SERVER_BUSY_COUNT:
            case MODBUS_SUBFUNC_SERVER_CHAR_COUNT:
            case MODBUS_SUBFUNC_CLEAR_COUNT:
                if (data != 0x00)
                    goto error;
                break;

            default:
                /* Set function code category */
                tx->category = MODBUS_CAT_RESERVED;
                SCReturnInt(1);
        }

        /* The length of all Diagnostic Requests is 6           */
        /* Modbus Application Protocol Specification V1.1b3 6.8 */
        ModbusCheckHeaderLength(modbus, tx->length, 6);
    }

    goto end;

error:
    ModbusSetEvent(modbus, MODBUS_DECODER_EVENT_INVALID_VALUE);
end:
    SCReturnInt(0);
}

/* Modbus Function Code Categories structure. */
typedef struct ModbusFunctionCodeRange_ {
    uint8_t        function;
    uint8_t        category;
} ModbusFunctionCodeRange;

/* Modbus Function Code Categories table. */
static ModbusFunctionCodeRange modbusFunctionCodeRanges[] = {
        { 0,    MODBUS_CAT_PUBLIC_UNASSIGNED},
        { 9,    MODBUS_CAT_RESERVED         },
        { 15,   MODBUS_CAT_PUBLIC_UNASSIGNED},
        { 41,   MODBUS_CAT_RESERVED         },
        { 43,   MODBUS_CAT_PUBLIC_UNASSIGNED},
        { 65,   MODBUS_CAT_USER_DEFINED     },
        { 73,   MODBUS_CAT_PUBLIC_UNASSIGNED},
        { 90,   MODBUS_CAT_RESERVED         },
        { 92,   MODBUS_CAT_PUBLIC_UNASSIGNED},
        { 100,  MODBUS_CAT_USER_DEFINED     },
        { 111,  MODBUS_CAT_PUBLIC_UNASSIGNED},
        { 125,  MODBUS_CAT_RESERVED         },
        { 128,  MODBUS_CAT_NONE             }
};

/** \internal
 *  \brief Parse the Modbus Protocol Data Unit (PDU) Request
 *
 *  \param  tx          Pointer to Modbus Transaction structure
 *  \param  ModbusPdu   Pointer the Modbus PDU state in which the value to be stored
 *  \param  input       Pointer the received input data
 *  \param  input_len   Length of the received input data
 */
static void ModbusParseRequestPDU(ModbusTransaction *tx,
                                  ModbusState       *modbus,
                                  uint8_t           *input,
                                  uint32_t          input_len)
{
    SCEnter();
    uint16_t    offset = (uint16_t) sizeof(ModbusHeader);
    uint8_t     count = 0;

    int i = 0;

    /* Standard function codes used on MODBUS application layer protocol (1 byte) */
    if (ModbusExtractUint8(modbus, &(tx->function), input, input_len, &offset))
        goto end;

    /* Set default function code category */
    tx->category = MODBUS_CAT_NONE;

    /* Set default function primary table */
    tx->type = MODBUS_TYP_NONE;

    switch (tx->function) {
        case MODBUS_FUNC_NONE:
            ModbusSetEvent(modbus, MODBUS_DECODER_EVENT_INVALID_FUNCTION_CODE);
            break;

        case MODBUS_FUNC_READCOILS:
            /* Set function type */
            tx->type = (MODBUS_TYP_COILS | MODBUS_TYP_READ);
            break;

        case MODBUS_FUNC_READDISCINPUTS:
            /* Set function type */
            tx->type = (MODBUS_TYP_DISCRETES | MODBUS_TYP_READ);
            break;

        case MODBUS_FUNC_READHOLDREGS:
            /* Set function type */
            tx->type = (MODBUS_TYP_HOLDING | MODBUS_TYP_READ);
            break;

        case MODBUS_FUNC_READINPUTREGS:
            /* Set function type */
            tx->type = (MODBUS_TYP_INPUT | MODBUS_TYP_READ);
            break;

        case MODBUS_FUNC_WRITESINGLECOIL:
            /* Set function type */
            tx->type = (MODBUS_TYP_COILS | MODBUS_TYP_WRITE_SINGLE);
            break;

        case MODBUS_FUNC_WRITESINGLEREG:
            /* Set function type */
            tx->type = (MODBUS_TYP_HOLDING | MODBUS_TYP_WRITE_SINGLE);
            break;

        case MODBUS_FUNC_WRITEMULTCOILS:
            /* Set function type */
            tx->type = (MODBUS_TYP_COILS | MODBUS_TYP_WRITE_MULTIPLE);
            break;

        case MODBUS_FUNC_WRITEMULTREGS:
            /* Set function type */
            tx->type = (MODBUS_TYP_HOLDING | MODBUS_TYP_WRITE_MULTIPLE);
            break;

        case MODBUS_FUNC_MASKWRITEREG:
            /* Set function type */
            tx->type = (MODBUS_TYP_HOLDING | MODBUS_TYP_WRITE);
            break;

        case MODBUS_FUNC_READWRITEMULTREGS:
            /* Set function type */
            tx->type = (MODBUS_TYP_HOLDING | MODBUS_TYP_READ_WRITE_MULTIPLE);
            break;

        case MODBUS_FUNC_READFILERECORD:
        case MODBUS_FUNC_WRITEFILERECORD:
            /* Count/length (1 bytes) */
            if (ModbusExtractUint8(modbus, &count, input, input_len, &offset))
                goto end;

            /* Modbus Application Protocol Specification V1.1b3 6.14 and 6.15   */
            ModbusCheckHeaderLength(modbus, tx->length, 2 + count);
            break;

        case MODBUS_FUNC_DIAGNOSTIC:
            if(ModbusParseDiagnosticRequest(tx, modbus, input, input_len, &offset))
                goto end;
            break;

        case MODBUS_FUNC_READEXCSTATUS:
        case MODBUS_FUNC_GETCOMEVTCOUNTER:
        case MODBUS_FUNC_GETCOMEVTLOG:
        case MODBUS_FUNC_REPORTSERVERID:
            /* Modbus Application Protocol Specification V1.1b3 6.7, 6.9, 6.10 and 6.13 */
            ModbusCheckHeaderLength(modbus, tx->length, 2);
            break;

        case MODBUS_FUNC_READFIFOQUEUE:
            /* Modbus Application Protocol Specification V1.1b3 6.18 */
            ModbusCheckHeaderLength(modbus, tx->length, 4);
            break;

        case MODBUS_FUNC_ENCAPINTTRANS:
            /* MEI type (1 byte) */
           if (ModbusExtractUint8(modbus, &(tx->mei), input, input_len, &offset))
               goto end;

            if (tx->mei == MODBUS_MEI_ENCAPINTTRANS_READ) {
                /* Modbus Application Protocol Specification V1.1b3 6.21 */
                ModbusCheckHeaderLength(modbus, tx->length, 5);
            } else if (tx->mei != MODBUS_MEI_ENCAPINTTRANS_CAN) {
                /* Set function code category */
                tx->category = MODBUS_CAT_RESERVED;
                goto end;
            }
            break;

        default:
            /* Check if request is error. */
            if (tx->function & MODBUS_FUNC_ERRORMASK) {
                ModbusSetEvent(modbus, MODBUS_DECODER_EVENT_INVALID_FUNCTION_CODE);
                goto end;
            }

            /* Get and store function code category */
            for (i = 0; modbusFunctionCodeRanges[i].category != MODBUS_CAT_NONE; i++) {
                if (tx->function <= modbusFunctionCodeRanges[i].function)
                    break;
                tx->category = modbusFunctionCodeRanges[i].category;
            }
            goto end;
    }

    /* Set function code category */
    tx->category = MODBUS_CAT_PUBLIC_ASSIGNED;

    if (tx->type & MODBUS_TYP_READ)
        ModbusParseReadRequest(tx, modbus, input, input_len, &offset);

    if (tx->type & MODBUS_TYP_WRITE)
        ModbusParseWriteRequest(tx, modbus, input, input_len, &offset);

end:
    SCReturn;
}

/** \internal
 *  \brief Parse the Modbus Protocol Data Unit (PDU) Response
 *
 *  \param  tx          Pointer to Modbus Transaction structure
 *  \param  modbus      Pointer the Modbus PDU state in which the value to be stored
 *  \param  input       Pointer the received input data
 *  \param  input_len   Length of the received input data
 *  \param  offset      Offset of the received input data pointer
 */
static void ModbusParseResponsePDU(ModbusTransaction    *tx,
                                   ModbusState          *modbus,
                                   uint8_t              *input,
                                   uint32_t             input_len)
{
    SCEnter();
    uint16_t    offset = (uint16_t) sizeof(ModbusHeader);
    uint8_t     count = 0, error = FALSE, function = 0, mei = 0;

    /* Standard function codes used on MODBUS application layer protocol (1 byte) */
    if (ModbusExtractUint8(modbus, &function, input, input_len, &offset))
        goto end;

    /* Check if response is error */
    if(function & MODBUS_FUNC_ERRORMASK) {
        function &= MODBUS_FUNC_MASK;
        error = TRUE;
    }

    if (tx->category == MODBUS_CAT_PUBLIC_ASSIGNED) {
        /* Check if response is error. */
        if (error) {
            ModbusExceptionResponse(tx, modbus, input, input_len, &offset);
        } else {
            switch(function) {
                case MODBUS_FUNC_READEXCSTATUS:
                    /* Modbus Application Protocol Specification V1.1b3 6.7 */
                    ModbusCheckHeaderLength(modbus, tx->length, 3);
                    goto end;

                case MODBUS_FUNC_GETCOMEVTCOUNTER:
                    /* Modbus Application Protocol Specification V1.1b3 6.9 */
                    ModbusCheckHeaderLength(modbus, tx->length, 6);
                    goto end;

                case MODBUS_FUNC_READFILERECORD:
                case MODBUS_FUNC_WRITEFILERECORD:
                    /* Count/length (1 bytes) */
                    if (ModbusExtractUint8(modbus, &count, input, input_len, &offset))
                        goto end;

                    /* Modbus Application Protocol Specification V1.1b3 6.14 and 6.15 */
                    ModbusCheckHeaderLength(modbus, tx->length, 2 + count);
                    goto end;

                case MODBUS_FUNC_ENCAPINTTRANS:
                    /* MEI type (1 byte) */
                    if (ModbusExtractUint8(modbus, &mei, input, input_len, &offset))
                        goto end;

                    if (mei != tx->mei)
                        ModbusSetEvent(modbus, MODBUS_DECODER_EVENT_VALUE_MISMATCH);
                    goto end;
            }

            if (tx->type & MODBUS_TYP_READ)
                ModbusParseReadResponse(tx, modbus, input, input_len, &offset);
            /* Read/Write response contents none write response part */
            else if (tx->type & MODBUS_TYP_WRITE)
                ModbusParseWriteResponse(tx, modbus, input, input_len, &offset);
        }
    }

end:
    SCReturn;
}

/** \internal
 *  \brief Parse the Modbus Application Protocol (MBAP) header
 *
 *  \param  header  Pointer the Modbus header state in which the value to be stored
 *  \param  input   Pointer the received input data
 */
static int ModbusParseHeader(ModbusState   *modbus,
                             ModbusHeader  *header,
                             uint8_t       *input,
                             uint32_t      input_len)
{
    SCEnter();
    uint16_t offset = 0;

    int r = 0;

    /* can't pass the header fields directly due to alignment (Bug 2088) */
    uint16_t transaction_id = 0;
    uint16_t protocol_id = 0;
    uint16_t length = 0;
    uint8_t unit_id = 0;

    /* Transaction Identifier (2 bytes) */
    r = ModbusExtractUint16(modbus, &transaction_id, input, input_len, &offset);
    /* Protocol Identifier (2 bytes) */
    r |= ModbusExtractUint16(modbus, &protocol_id, input, input_len, &offset);
    /* Length (2 bytes) */
    r |= ModbusExtractUint16(modbus, &length, input, input_len, &offset);
    /* Unit Identifier (1 byte) */
    r |= ModbusExtractUint8(modbus, &unit_id, input, input_len, &offset);

    if (r != 0) {
        SCReturnInt(-1);
    }
    header->transactionId = transaction_id;
    header->protocolId = protocol_id;
    header->length = length;
    header->unitId = unit_id;

    SCReturnInt(0);
}

/** \internal
 *
 * \brief This function is called to retrieve a Modbus Request
 *
 * \param state     Modbus state structure for the parser
 * \param input     Input line of the command
 * \param input_len Length of the request
 *
 * \retval 1 when the command is parsed, 0 otherwise
 */
static int ModbusParseRequest(Flow                  *f,
                              void                  *state,
                              AppLayerParserState   *pstate,
                              uint8_t               *input,
                              uint32_t              input_len,
                              void                  *local_data,
                              const uint8_t         flags)
{
    SCEnter();
    ModbusState         *modbus = (ModbusState *) state;
    ModbusTransaction   *tx;
    ModbusHeader        header;

    if (input == NULL && AppLayerParserStateIssetFlag(pstate, APP_LAYER_PARSER_EOF)) {
        SCReturnInt(1);
    } else if (input == NULL || input_len == 0) {
        SCReturnInt(-1);
    }

    while (input_len > 0) {
        uint32_t    adu_len = input_len;
        uint8_t     *adu = input;

        /* Extract MODBUS Header */
        if (ModbusParseHeader(modbus, &header, adu, adu_len))
            SCReturnInt(0);

        /* Update ADU length with length in Modbus header. */
        adu_len = (uint32_t) sizeof(ModbusHeader) + (uint32_t) header.length - 1;
        if (adu_len > input_len)
            SCReturnInt(0);

        /* Allocate a Transaction Context and add it to Transaction list */
        tx = ModbusTxAlloc(modbus);
        if (tx == NULL)
            SCReturnInt(0);

        /* Check MODBUS Header */
        ModbusCheckHeader(modbus, &header);

        /* Store Unit ID, Transaction ID & PDU length */
        tx->unit_id         = header.unitId;
        tx->transactionId   = header.transactionId;
        tx->length          = header.length;

        /* Extract MODBUS PDU and fill Transaction Context */
        ModbusParseRequestPDU(tx, modbus, adu, adu_len);

        /* Update input line and remaining input length of the command */
        input       += adu_len;
        input_len   -= adu_len;
    }

    SCReturnInt(1);
}

/** \internal
 * \brief This function is called to retrieve a Modbus response
 *
 * \param state     Pointer to Modbus state structure for the parser
 * \param input     Input line of the command
 * \param input_len Length of the request
 *
 * \retval 1 when the command is parsed, 0 otherwise
 */
static int ModbusParseResponse(Flow                 *f,
                               void                 *state,
                               AppLayerParserState  *pstate,
                               uint8_t              *input,
                               uint32_t             input_len,
                               void                 *local_data,
                               const uint8_t        flags)
{
    SCEnter();
    ModbusHeader        header;
    ModbusState         *modbus = (ModbusState *) state;
    ModbusTransaction   *tx;

    if (input == NULL && AppLayerParserStateIssetFlag(pstate, APP_LAYER_PARSER_EOF)) {
        SCReturnInt(1);
    } else if (input == NULL || input_len == 0) {
        SCReturnInt(-1);
    }

    while (input_len > 0) {
        uint32_t    adu_len = input_len;
        uint8_t     *adu = input;

        /* Extract MODBUS Header */
        if (ModbusParseHeader(modbus, &header, adu, adu_len))
            SCReturnInt(0);

        /* Update ADU length with length in Modbus header. */
        adu_len = (uint32_t) sizeof(ModbusHeader) + (uint32_t) header.length - 1;
        if (adu_len > input_len)
            SCReturnInt(0);

        /* Find the transaction context thanks to transaction ID (and function code) */
        tx = ModbusTxFindByTransaction(modbus, header.transactionId);
        if (tx == NULL) {
            /* Allocate a Transaction Context if not previous request */
            /* and add it to Transaction list */
            tx = ModbusTxAlloc(modbus);
            if (tx == NULL)
                SCReturnInt(0);

            SCLogDebug("MODBUS_DECODER_EVENT_UNSOLICITED_RESPONSE");
            ModbusSetEvent(modbus, MODBUS_DECODER_EVENT_UNSOLICITED_RESPONSE);
        } else {
            /* Store PDU length */
            tx->length = header.length;

            /* Extract MODBUS PDU and fill Transaction Context */
            ModbusParseResponsePDU(tx, modbus, adu, adu_len);
        }

        /* Check and store MODBUS Header */
        ModbusCheckHeader(modbus, &header);

        /* Mark as completed */
        tx->replied = 1;

        /* Update input line and remaining input length of the command */
        input       += adu_len;
        input_len   -= adu_len;
    }

    SCReturnInt(1);
}

/** \internal
 *     \brief Function to allocate the Modbus state memory
 */
static void *ModbusStateAlloc(void)
{
    ModbusState *modbus;

    modbus = (ModbusState *) SCCalloc(1, sizeof(ModbusState));
    if (unlikely(modbus == NULL))
        return NULL;

    TAILQ_INIT(&modbus->tx_list);

    return (void *) modbus;
}

/** \internal
 *  \brief Function to free the Modbus state memory
 */
static void ModbusStateFree(void *state)
{
    SCEnter();
    ModbusState         *modbus = (ModbusState *) state;
    ModbusTransaction   *tx = NULL, *ttx;

    if (state) {
        TAILQ_FOREACH_SAFE(tx, &modbus->tx_list, next, ttx) {
            ModbusTxFree(tx);
        }

        SCFree(state);
    }
    SCReturn;
}

static uint16_t ModbusProbingParser(Flow *f,
                                    uint8_t direction,
                                    uint8_t     *input,
                                    uint32_t    input_len,
                                    uint8_t *rdir)
{
    ModbusHeader *header = (ModbusHeader *) input;

    /* Modbus header is 7 bytes long */
    if (input_len < sizeof(ModbusHeader))
        return ALPROTO_UNKNOWN;

    /* MODBUS protocol is identified by the value 0. */
    if (header->protocolId != 0)
        return ALPROTO_FAILED;

    return ALPROTO_MODBUS;
}

static DetectEngineState *ModbusGetTxDetectState(void *vtx)
{
    ModbusTransaction *tx = (ModbusTransaction *)vtx;
    return tx->de_state;
}

static int ModbusSetTxDetectState(void *vtx, DetectEngineState *s)
{
    ModbusTransaction *tx = (ModbusTransaction *)vtx;
    tx->de_state = s;
    return 0;
}

/**
 * \brief Function to register the Modbus protocol parsers and other functions
 */
void RegisterModbusParsers(void)
{
    SCEnter();
    const char *proto_name = "modbus";

    /* Modbus application protocol V1.1b3 */
    if (AppLayerProtoDetectConfProtoDetectionEnabled("tcp", proto_name)) {
        AppLayerProtoDetectRegisterProtocol(ALPROTO_MODBUS, proto_name);

        if (RunmodeIsUnittests()) {
            AppLayerProtoDetectPPRegister(IPPROTO_TCP,
                                          "502",
                                          ALPROTO_MODBUS,
                                          0, sizeof(ModbusHeader),
                                          STREAM_TOSERVER,
                                          ModbusProbingParser, NULL);
        } else {
            /* If there is no app-layer section for Modbus, silently
             * leave it disabled. */
            if (!AppLayerProtoDetectPPParseConfPorts("tcp", IPPROTO_TCP,
                                                proto_name, ALPROTO_MODBUS,
                                                0, sizeof(ModbusHeader),
                                                ModbusProbingParser, NULL)) {
#ifndef AFLFUZZ_APPLAYER
                return;
#endif
            }
        }

        ConfNode *p = NULL;
        p = ConfGetNode("app-layer.protocols.modbus.request-flood");
        if (p != NULL) {
            uint32_t value;
            if (ParseSizeStringU32(p->val, &value) < 0) {
                SCLogError(SC_ERR_MODBUS_CONFIG, "invalid value for request-flood %s", p->val);
            } else {
                request_flood = value;
            }
        }
        SCLogConfig("Modbus request flood protection level: %u", request_flood);

        p = ConfGetNode("app-layer.protocols.modbus.stream-depth");
        if (p != NULL) {
            uint32_t value;
            if (ParseSizeStringU32(p->val, &value) < 0) {
                SCLogError(SC_ERR_MODBUS_CONFIG, "invalid value for stream-depth %s", p->val);
            } else {
                stream_depth = value;
            }
        }
        SCLogConfig("Modbus stream depth: %u", stream_depth);
    } else {
#ifndef AFLFUZZ_APPLAYER
        SCLogConfig("Protocol detection and parser disabled for %s protocol.", proto_name);
        return;
#endif
    }
    if (AppLayerParserConfParserEnabled("tcp", proto_name)) {
        AppLayerParserRegisterParser(IPPROTO_TCP, ALPROTO_MODBUS, STREAM_TOSERVER, ModbusParseRequest);
        AppLayerParserRegisterParser(IPPROTO_TCP, ALPROTO_MODBUS, STREAM_TOCLIENT, ModbusParseResponse);
        AppLayerParserRegisterStateFuncs(IPPROTO_TCP, ALPROTO_MODBUS, ModbusStateAlloc, ModbusStateFree);

        AppLayerParserRegisterGetEventsFunc(IPPROTO_TCP, ALPROTO_MODBUS, ModbusGetEvents);
        AppLayerParserRegisterDetectStateFuncs(IPPROTO_TCP, ALPROTO_MODBUS,
                                               ModbusGetTxDetectState, ModbusSetTxDetectState);

        AppLayerParserRegisterGetTx(IPPROTO_TCP, ALPROTO_MODBUS, ModbusGetTx);
        AppLayerParserRegisterGetTxCnt(IPPROTO_TCP, ALPROTO_MODBUS, ModbusGetTxCnt);
        AppLayerParserRegisterLoggerFuncs(IPPROTO_TCP, ALPROTO_MODBUS, ModbusGetTxLogged,
                                          ModbusSetTxLogged);
        AppLayerParserRegisterTxFreeFunc(IPPROTO_TCP, ALPROTO_MODBUS, ModbusStateTxFree);

        AppLayerParserRegisterGetStateProgressFunc(IPPROTO_TCP, ALPROTO_MODBUS, ModbusGetAlstateProgress);
        AppLayerParserRegisterGetStateProgressCompletionStatus(ALPROTO_MODBUS,
                                                                ModbusGetAlstateProgressCompletionStatus);

        AppLayerParserRegisterGetEventInfo(IPPROTO_TCP, ALPROTO_MODBUS, ModbusStateGetEventInfo);
        AppLayerParserRegisterGetEventInfoById(IPPROTO_TCP, ALPROTO_MODBUS, ModbusStateGetEventInfoById);

        AppLayerParserRegisterParserAcceptableDataDirection(IPPROTO_TCP, ALPROTO_MODBUS, STREAM_TOSERVER);

        AppLayerParserSetStreamDepth(IPPROTO_TCP, ALPROTO_MODBUS, stream_depth);
    } else {
        SCLogConfig("Parsed disabled for %s protocol. Protocol detection" "still on.", proto_name);
    }
#ifdef UNITTESTS
    AppLayerParserRegisterProtocolUnittests(IPPROTO_TCP, ALPROTO_MODBUS, ModbusParserRegisterTests);
#endif

    SCReturn;
}

/* UNITTESTS */
#ifdef UNITTESTS
#include "detect.h"
#include "detect-engine.h"
#include "detect-parse.h"

#include "flow-util.h"

#include "util-unittest.h"
#include "util-unittest-helper.h"

#include "stream-tcp.h"
#include "stream-tcp-private.h"

/* Modbus Application Protocol Specification V1.1b3 6.1: Read Coils */
static uint8_t invalidFunctionCode[] = {/* Transaction ID */    0x00, 0x00,
                                         /* Protocol ID */       0x00, 0x01,
                                         /* Length */            0x00, 0x02,
                                         /* Unit ID */           0x00,
                                         /* Function code */     0x00};

/* Modbus Application Protocol Specification V1.1b3 6.1: Read Coils */
/* Example of a request to read discrete outputs 20-38 */
static uint8_t readCoilsReq[] = {/* Transaction ID */    0x00, 0x00,
                                 /* Protocol ID */       0x00, 0x00,
                                 /* Length */            0x00, 0x06,
                                 /* Unit ID */           0x00,
                                 /* Function code */     0x01,
                                 /* Starting Address */  0x78, 0x90,
                                 /* Quantity of coils */ 0x00, 0x13 };

static uint8_t readCoilsRsp[] = {/* Transaction ID */    0x00, 0x00,
                                 /* Protocol ID */       0x00, 0x00,
                                 /* Length */            0x00, 0x06,
                                 /* Unit ID */           0x00,
                                 /* Function code */     0x01,
                                 /* Byte count */        0x03,
                                 /* Coil Status */       0xCD, 0x6B, 0x05 };

static uint8_t readCoilsErrorRsp[] = {/* Transaction ID */    0x00, 0x00,
                                      /* Protocol ID */       0x00, 0x00,
                                      /* Length */            0x00, 0x03,
                                      /* Unit ID */           0x00,
                                      /* Function code */     0x81,
                                      /* Exception code */    0x05};

/* Modbus Application Protocol Specification V1.1b3 6.6: Write Single register */
/* Example of a request to write register 2 to 00 03 hex */
static uint8_t writeSingleRegisterReq[] = {/* Transaction ID */     0x00, 0x0A,
                                           /* Protocol ID */        0x00, 0x00,
                                           /* Length */             0x00, 0x06,
                                           /* Unit ID */            0x00,
                                           /* Function code */      0x06,
                                           /* Register Address */   0x00, 0x01,
                                           /* Register Value */     0x00, 0x03};

static uint8_t invalidWriteSingleRegisterReq[] = {/* Transaction ID */      0x00, 0x0A,
                                                  /* Protocol ID */         0x00, 0x00,
                                                  /* Length */              0x00, 0x04,
                                                  /* Unit ID */             0x00,
                                                  /* Function code */       0x06,
                                                  /* Register Address */    0x00, 0x01};

static uint8_t writeSingleRegisterRsp[] = {/* Transaction ID */         0x00, 0x0A,
                                           /* Protocol ID */            0x00, 0x00,
                                           /* Length */                 0x00, 0x06,
                                           /* Unit ID */                0x00,
                                           /* Function code */          0x06,
                                           /* Register Address */       0x00, 0x01,
                                           /* Register Value */         0x00, 0x03};

/* Modbus Application Protocol Specification V1.1b3 6.12: Write Multiple registers */
/* Example of a request to write two registers starting at 2 to 00 0A and 01 02 hex */
static uint8_t writeMultipleRegistersReq[] = {/* Transaction ID */          0x00, 0x0A,
                                              /* Protocol ID */             0x00, 0x00,
                                              /* Length */                  0x00, 0x0B,
                                              /* Unit ID */                 0x00,
                                              /* Function code */           0x10,
                                              /* Starting Address */        0x00, 0x01,
                                              /* Quantity of Registers */   0x00, 0x02,
                                              /* Byte count */              0x04,
                                              /* Registers Value */         0x00, 0x0A,
                                                                            0x01, 0x02};

static uint8_t writeMultipleRegistersRsp[] = {/* Transaction ID */          0x00, 0x0A,
                                              /* Protocol ID */             0x00, 0x00,
                                              /* Length */                  0x00, 0x06,
                                              /* Unit ID */                 0x00,
                                              /* Function code */           0x10,
                                              /* Starting Address */        0x00, 0x01,
                                              /* Quantity of Registers */   0x00, 0x02};

/* Modbus Application Protocol Specification V1.1b3 6.16: Mask Write Register */
/* Example of a request to mask write to register 5 */
static uint8_t maskWriteRegisterReq[] = {/* Transaction ID */       0x00, 0x0A,
                                         /* Protocol ID */          0x00, 0x00,
                                         /* Length */               0x00, 0x08,
                                         /* Unit ID */              0x00,
                                         /* Function code */        0x16,
                                         /* Reference Address */    0x00, 0x04,
                                         /* And_Mask */             0x00, 0xF2,
                                         /* Or_Mask */              0x00, 0x25};

static uint8_t invalidMaskWriteRegisterReq[] = {/* Transaction ID */    0x00, 0x0A,
                                                /* Protocol ID */       0x00, 0x00,
                                                /* Length */            0x00, 0x06,
                                                /* Unit ID */           0x00,
                                                /* Function code */     0x16,
                                                /* Reference Address */ 0x00, 0x04,
                                                /* And_Mask */          0x00, 0xF2};

static uint8_t maskWriteRegisterRsp[] = {/* Transaction ID */       0x00, 0x0A,
                                         /* Protocol ID */          0x00, 0x00,
                                         /* Length */               0x00, 0x08,
                                         /* Unit ID */              0x00,
                                         /* Function code */        0x16,
                                         /* Reference Address */    0x00, 0x04,
                                         /* And_Mask */             0x00, 0xF2,
                                         /* Or_Mask */              0x00, 0x25};

/* Modbus Application Protocol Specification V1.1b3 6.17: Read/Write Multiple registers */
/* Example of a request to read six registers starting at register 4, */
/* and to write three registers starting at register 15 */
static uint8_t readWriteMultipleRegistersReq[] = {/* Transaction ID */          0x12, 0x34,
                                                  /* Protocol ID */             0x00, 0x00,
                                                  /* Length */                  0x00, 0x11,
                                                  /* Unit ID */                 0x00,
                                                  /* Function code */           0x17,
                                                  /* Read Starting Address */   0x00, 0x03,
                                                  /* Quantity to Read */        0x00, 0x06,
                                                  /* Write Starting Address */  0x00, 0x0E,
                                                  /* Quantity to Write */       0x00, 0x03,
                                                  /* Write Byte count */        0x06,
                                                  /* Write Registers Value */   0x12, 0x34,
                                                                                0x56, 0x78,
                                                                                0x9A, 0xBC};

/* Mismatch value in Byte count 0x0B instead of 0x0C */
static uint8_t readWriteMultipleRegistersRsp[] = {/* Transaction ID */          0x12, 0x34,
                                                  /* Protocol ID */             0x00, 0x00,
                                                  /* Length */                  0x00, 0x0E,
                                                  /* Unit ID */                 0x00,
                                                  /* Function code */           0x17,
                                                  /* Byte count */              0x0B,
                                                  /* Read Registers Value */    0x00, 0xFE,
                                                                                0x0A, 0xCD,
                                                                                0x00, 0x01,
                                                                                0x00, 0x03,
                                                                                0x00, 0x0D,
                                                                                0x00};

/* Modbus Application Protocol Specification V1.1b3 6.8.1: 04 Force Listen Only Mode */
/* Example of a request to to remote device to its Listen Only MOde for Modbus Communications. */
static uint8_t forceListenOnlyMode[] = {/* Transaction ID */     0x0A, 0x00,
                                        /* Protocol ID */        0x00, 0x00,
                                        /* Length */             0x00, 0x06,
                                        /* Unit ID */            0x00,
                                        /* Function code */      0x08,
                                        /* Sub-function code */  0x00, 0x04,
                                        /* Data */               0x00, 0x00};

static uint8_t invalidProtocolIdReq[] = {/* Transaction ID */    0x00, 0x00,
                                         /* Protocol ID */       0x00, 0x01,
                                         /* Length */            0x00, 0x06,
                                         /* Unit ID */           0x00,
                                         /* Function code */     0x01,
                                         /* Starting Address */  0x78, 0x90,
                                         /* Quantity of coils */ 0x00, 0x13 };

static uint8_t invalidLengthWriteMultipleRegistersReq[] = {
                                              /* Transaction ID */          0x00, 0x0A,
                                              /* Protocol ID */             0x00, 0x00,
                                              /* Length */                  0x00, 0x09,
                                              /* Unit ID */                 0x00,
                                              /* Function code */           0x10,
                                              /* Starting Address */        0x00, 0x01,
                                              /* Quantity of Registers */   0x00, 0x02,
                                              /* Byte count */              0x04,
                                              /* Registers Value */         0x00, 0x0A,
                                                                            0x01, 0x02};

static uint8_t exceededLengthWriteMultipleRegistersReq[] = {
                                              /* Transaction ID */          0x00, 0x0A,
                                              /* Protocol ID */             0x00, 0x00,
                                              /* Length */                  0xff, 0xfa,
                                              /* Unit ID */                 0x00,
                                              /* Function code */           0x10,
                                              /* Starting Address */        0x00, 0x01,
                                              /* Quantity of Registers */   0x7f, 0xf9,
                                              /* Byte count */              0xff};

static uint8_t invalidLengthPDUWriteMultipleRegistersReq[] = {
                                              /* Transaction ID */          0x00, 0x0A,
                                              /* Protocol ID */             0x00, 0x00,
                                              /* Length */                  0x00, 0x02,
                                              /* Unit ID */                 0x00,
                                              /* Function code */           0x10};

/** \test Send Modbus Read Coils request/response. */
static int ModbusParserTest01(void) {
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();
    Flow f;
    TcpSession ssn;

    FAIL_IF_NULL(alp_tctx);

    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    FLOW_INITIALIZE(&f);
    f.protoctx  = (void *)&ssn;
    f.proto     = IPPROTO_TCP;
    f.alproto   = ALPROTO_MODBUS;

    StreamTcpInitConfig(TRUE);

    FLOWLOCK_WRLOCK(&f);
    int r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_MODBUS,
                                STREAM_TOSERVER, readCoilsReq,
                                sizeof(readCoilsReq));
    FAIL_IF_NOT(r == 0);
    FLOWLOCK_UNLOCK(&f);

    ModbusState    *modbus_state = f.alstate;
    FAIL_IF_NULL(modbus_state);

    ModbusTransaction *tx = ModbusGetTx(modbus_state, 0);
    FAIL_IF_NOT(tx->function == 1);
    FAIL_IF_NOT(tx->read.address == 0x7890);
    FAIL_IF_NOT(tx->read.quantity == 19);

    FLOWLOCK_WRLOCK(&f);
    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_MODBUS,
                            STREAM_TOCLIENT, readCoilsRsp,
                            sizeof(readCoilsRsp));
    FAIL_IF_NOT(r == 0);
    FLOWLOCK_UNLOCK(&f);

    FAIL_IF_NOT(modbus_state->transaction_max == 1);

    AppLayerParserThreadCtxFree(alp_tctx);
    StreamTcpFreeConfig(TRUE);
    FLOW_DESTROY(&f);
    PASS;
}

/** \test Send Modbus Write Multiple registers request/response. */
static int ModbusParserTest02(void) {
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();
    Flow f;
    TcpSession ssn;

    FAIL_IF_NULL(alp_tctx);

    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    FLOW_INITIALIZE(&f);
    f.protoctx  = (void *)&ssn;
    f.proto     = IPPROTO_TCP;
    f.alproto   = ALPROTO_MODBUS;

    StreamTcpInitConfig(TRUE);

    FLOWLOCK_WRLOCK(&f);
    int r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_MODBUS,
                                STREAM_TOSERVER, writeMultipleRegistersReq,
                                sizeof(writeMultipleRegistersReq));
    FAIL_IF_NOT(r == 0);
    FLOWLOCK_UNLOCK(&f);

    ModbusState    *modbus_state = f.alstate;
    FAIL_IF_NULL(modbus_state);

    ModbusTransaction *tx = ModbusGetTx(modbus_state, 0);

    FAIL_IF_NOT(tx->function == 16);
    FAIL_IF_NOT(tx->write.address == 0x01);
    FAIL_IF_NOT(tx->write.quantity == 2);
    FAIL_IF_NOT(tx->write.count == 4);
    FAIL_IF_NOT(tx->data[0] == 0x000A);
    FAIL_IF_NOT(tx->data[1] == 0x0102);

    FLOWLOCK_WRLOCK(&f);
    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_MODBUS,
                            STREAM_TOCLIENT, writeMultipleRegistersRsp,
                            sizeof(writeMultipleRegistersRsp));
    FAIL_IF_NOT(r == 0);
    FLOWLOCK_UNLOCK(&f);

    FAIL_IF_NOT(modbus_state->transaction_max == 1);

    AppLayerParserThreadCtxFree(alp_tctx);
    StreamTcpFreeConfig(TRUE);
    FLOW_DESTROY(&f);
    PASS;
}

/** \test Send Modbus Read/Write Multiple registers request/response with mismatch value. */
static int ModbusParserTest03(void) {
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();
    DetectEngineThreadCtx *det_ctx = NULL;
    Flow f;
    Packet *p = NULL;
    Signature *s = NULL;
    TcpSession ssn;
    ThreadVars tv;

    FAIL_IF_NULL(alp_tctx);

    memset(&tv, 0, sizeof(ThreadVars));
    memset(&f, 0, sizeof(Flow));
    memset(&ssn, 0, sizeof(TcpSession));

    p = UTHBuildPacket(NULL, 0, IPPROTO_TCP);

    FLOW_INITIALIZE(&f);
    f.alproto   = ALPROTO_MODBUS;
    f.protoctx  = (void *)&ssn;
    f.proto     = IPPROTO_TCP;
    f.alproto   = ALPROTO_MODBUS;
    f.flags     |= FLOW_IPV4;

    p->flow         = &f;
    p->flags        |= PKT_HAS_FLOW | PKT_STREAM_EST;
    p->flowflags    |= FLOW_PKT_TOSERVER | FLOW_PKT_ESTABLISHED;

    StreamTcpInitConfig(TRUE);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);

    de_ctx->flags |= DE_QUIET;
    s = DetectEngineAppendSig(de_ctx, "alert modbus any any -> any any "
                                      "(msg:\"Modbus Data mismatch\"; "
                                      "app-layer-event: "
                                      "modbus.value_mismatch; "
                                      "sid:1;)");
    FAIL_IF_NULL(s);

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&tv, (void *)de_ctx, (void *)&det_ctx);

    FLOWLOCK_WRLOCK(&f);
    int r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_MODBUS,
                                STREAM_TOSERVER,
                                readWriteMultipleRegistersReq,
                                sizeof(readWriteMultipleRegistersReq));
    FAIL_IF_NOT(r == 0);
    FLOWLOCK_UNLOCK(&f);

    ModbusState    *modbus_state = f.alstate;
    FAIL_IF_NULL(modbus_state);

    ModbusTransaction *tx = ModbusGetTx(modbus_state, 0);

    FAIL_IF_NOT(tx->function == 23);
    FAIL_IF_NOT(tx->read.address == 0x03);
    FAIL_IF_NOT(tx->read.quantity == 6);
    FAIL_IF_NOT(tx->write.address == 0x0E);
    FAIL_IF_NOT(tx->write.quantity == 3);
    FAIL_IF_NOT(tx->write.count == 6);
    FAIL_IF_NOT(tx->data[0] == 0x1234);
    FAIL_IF_NOT(tx->data[1] == 0x5678);
    FAIL_IF_NOT(tx->data[2] == 0x9ABC);

    FLOWLOCK_WRLOCK(&f);
    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_MODBUS,
                            STREAM_TOCLIENT, readWriteMultipleRegistersRsp,
                            sizeof(readWriteMultipleRegistersRsp));
    FAIL_IF_NOT(r == 0);
    FLOWLOCK_UNLOCK(&f);

    FAIL_IF_NOT(modbus_state->transaction_max == 1);

    /* do detect */
    SigMatchSignatures(&tv, de_ctx, det_ctx, p);

    FAIL_IF_NOT(PacketAlertCheck(p, 1));

    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);

    DetectEngineThreadCtxDeinit(&tv, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);

    AppLayerParserThreadCtxFree(alp_tctx);
    StreamTcpFreeConfig(TRUE);
    FLOW_DESTROY(&f);
    UTHFreePackets(&p, 1);
    PASS;
}

/** \test Send Modbus Force Listen Only Mode request. */
static int ModbusParserTest04(void) {
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();
    Flow f;
    TcpSession ssn;

    FAIL_IF_NULL(alp_tctx);

    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    FLOW_INITIALIZE(&f);
    f.protoctx  = (void *)&ssn;
    f.proto     = IPPROTO_TCP;
    f.alproto   = ALPROTO_MODBUS;

    StreamTcpInitConfig(TRUE);

    FLOWLOCK_WRLOCK(&f);
    int r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_MODBUS,
                                STREAM_TOSERVER, forceListenOnlyMode,
                                sizeof(forceListenOnlyMode));
    FAIL_IF_NOT(r == 0);
    FLOWLOCK_UNLOCK(&f);

    ModbusState    *modbus_state = f.alstate;
    FAIL_IF_NULL(modbus_state);

    ModbusTransaction *tx = ModbusGetTx(modbus_state, 0);

    FAIL_IF_NOT(tx->function == 8);
    FAIL_IF_NOT(tx->subFunction == 4);

    AppLayerParserThreadCtxFree(alp_tctx);
    StreamTcpFreeConfig(TRUE);
    FLOW_DESTROY(&f);
    PASS;
}

/** \test Send Modbus invalid Protocol version in request. */
static int ModbusParserTest05(void) {
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();
    DetectEngineThreadCtx *det_ctx = NULL;
    Flow f;
    Packet *p = NULL;
    Signature *s = NULL;
    TcpSession ssn;
    ThreadVars tv;

    FAIL_IF_NULL(alp_tctx);

    memset(&tv, 0, sizeof(ThreadVars));
    memset(&f, 0, sizeof(Flow));
    memset(&ssn, 0, sizeof(TcpSession));

    p = UTHBuildPacket(NULL, 0, IPPROTO_TCP);

    FLOW_INITIALIZE(&f);
    f.alproto   = ALPROTO_MODBUS;
    f.protoctx  = (void *)&ssn;
    f.proto     = IPPROTO_TCP;
    f.alproto   = ALPROTO_MODBUS;
    f.flags     |= FLOW_IPV4;

    p->flow         = &f;
    p->flags        |= PKT_HAS_FLOW | PKT_STREAM_EST;
    p->flowflags    |= FLOW_PKT_TOSERVER | FLOW_PKT_ESTABLISHED;

    StreamTcpInitConfig(TRUE);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);

    de_ctx->flags |= DE_QUIET;
    s = DetectEngineAppendSig(de_ctx, "alert modbus any any -> any any "
                                      "(msg:\"Modbus invalid Protocol version\"; "
                                      "app-layer-event: "
                                      "modbus.invalid_protocol_id; "
                                      "sid:1;)");
    FAIL_IF_NULL(s);

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&tv, (void *)de_ctx, (void *)&det_ctx);

    FLOWLOCK_WRLOCK(&f);
    int r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_MODBUS,
                                STREAM_TOSERVER, invalidProtocolIdReq,
                                sizeof(invalidProtocolIdReq));
    FAIL_IF_NOT(r == 0);
    FLOWLOCK_UNLOCK(&f);

    ModbusState    *modbus_state = f.alstate;
    FAIL_IF_NULL(modbus_state);

    /* do detect */
    SigMatchSignatures(&tv, de_ctx, det_ctx, p);

    FAIL_IF_NOT(PacketAlertCheck(p, 1));

    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);

    DetectEngineThreadCtxDeinit(&tv, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);

    AppLayerParserThreadCtxFree(alp_tctx);
    StreamTcpFreeConfig(TRUE);
    FLOW_DESTROY(&f);
    UTHFreePackets(&p, 1);
    PASS;
}

/** \test Send Modbus unsolicited response. */
static int ModbusParserTest06(void) {
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();
    DetectEngineThreadCtx *det_ctx = NULL;
    Flow f;
    Packet *p = NULL;
    Signature *s = NULL;
    TcpSession ssn;
    ThreadVars tv;

    FAIL_IF_NULL(alp_tctx);

    memset(&tv, 0, sizeof(ThreadVars));
    memset(&f, 0, sizeof(Flow));
    memset(&ssn, 0, sizeof(TcpSession));

    p = UTHBuildPacket(NULL, 0, IPPROTO_TCP);

    FLOW_INITIALIZE(&f);
    f.alproto   = ALPROTO_MODBUS;
    f.protoctx  = (void *)&ssn;
    f.proto     = IPPROTO_TCP;
    f.alproto   = ALPROTO_MODBUS;
    f.flags     |= FLOW_IPV4;

    p->flow         = &f;
    p->flags        |= PKT_HAS_FLOW | PKT_STREAM_EST;
    p->flowflags    |= FLOW_PKT_TOSERVER | FLOW_PKT_ESTABLISHED;

    StreamTcpInitConfig(TRUE);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);

    de_ctx->flags |= DE_QUIET;
    s = DetectEngineAppendSig(de_ctx, "alert modbus any any -> any any "
                                      "(msg:\"Modbus unsolicited response\"; "
                                      "app-layer-event: "
                                      "modbus.unsolicited_response; "
                                      "sid:1;)");
    FAIL_IF_NULL(s);

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&tv, (void *)de_ctx, (void *)&det_ctx);

    FLOWLOCK_WRLOCK(&f);
    int r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_MODBUS,
                                STREAM_TOCLIENT, readCoilsRsp,
                                sizeof(readCoilsRsp));
    FAIL_IF_NOT(r == 0);
    FLOWLOCK_UNLOCK(&f);

    ModbusState    *modbus_state = f.alstate;
    FAIL_IF_NULL(modbus_state);

    /* do detect */
    SigMatchSignatures(&tv, de_ctx, det_ctx, p);

    FAIL_IF_NOT(PacketAlertCheck(p, 1));

    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);

    DetectEngineThreadCtxDeinit(&tv, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);

    AppLayerParserThreadCtxFree(alp_tctx);
    StreamTcpFreeConfig(TRUE);
    FLOW_DESTROY(&f);
    UTHFreePackets(&p, 1);
    PASS;
}

/** \test Send Modbus invalid Length request. */
static int ModbusParserTest07(void) {
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();
    DetectEngineThreadCtx *det_ctx = NULL;
    Flow f;
    Packet *p = NULL;
    Signature *s = NULL;
    TcpSession ssn;
    ThreadVars tv;

    FAIL_IF_NULL(alp_tctx);

    memset(&tv, 0, sizeof(ThreadVars));
    memset(&f, 0, sizeof(Flow));
    memset(&ssn, 0, sizeof(TcpSession));

    p = UTHBuildPacket(NULL, 0, IPPROTO_TCP);

    FLOW_INITIALIZE(&f);
    f.alproto   = ALPROTO_MODBUS;
    f.protoctx  = (void *)&ssn;
    f.proto     = IPPROTO_TCP;
    f.alproto   = ALPROTO_MODBUS;
    f.flags     |= FLOW_IPV4;

    p->flow         = &f;
    p->flags        |= PKT_HAS_FLOW | PKT_STREAM_EST;
    p->flowflags    |= FLOW_PKT_TOSERVER | FLOW_PKT_ESTABLISHED;

    StreamTcpInitConfig(TRUE);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);

    de_ctx->flags |= DE_QUIET;
    s = DetectEngineAppendSig(de_ctx, "alert modbus any any -> any any "
                                      "(msg:\"Modbus invalid Length\"; "
                                      "app-layer-event: "
                                      "modbus.invalid_length; "
                                      "sid:1;)");
    FAIL_IF_NULL(s);

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&tv, (void *)de_ctx, (void *)&det_ctx);

    FLOWLOCK_WRLOCK(&f);
    int r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_MODBUS,
                                STREAM_TOSERVER,
                                invalidLengthWriteMultipleRegistersReq,
                                sizeof(invalidLengthWriteMultipleRegistersReq));
    FAIL_IF_NOT(r == 0);
    FLOWLOCK_UNLOCK(&f);

    ModbusState    *modbus_state = f.alstate;
    FAIL_IF_NULL(modbus_state);

    /* do detect */
    SigMatchSignatures(&tv, de_ctx, det_ctx, p);

    FAIL_IF_NOT(PacketAlertCheck(p, 1));

    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);

    DetectEngineThreadCtxDeinit(&tv, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);

    AppLayerParserThreadCtxFree(alp_tctx);
    StreamTcpFreeConfig(TRUE);
    FLOW_DESTROY(&f);
    UTHFreePackets(&p, 1);
    PASS;
}

/** \test Send Modbus Read Coils request and error response with Exception code invalid. */
static int ModbusParserTest08(void) {
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();
    DetectEngineThreadCtx *det_ctx = NULL;
    Flow f;
    Packet *p = NULL;
    Signature *s = NULL;
    TcpSession ssn;
    ThreadVars tv;

    FAIL_IF_NULL(alp_tctx);

    memset(&tv, 0, sizeof(ThreadVars));
    memset(&f, 0, sizeof(Flow));
    memset(&ssn, 0, sizeof(TcpSession));

    p = UTHBuildPacket(NULL, 0, IPPROTO_TCP);

    FLOW_INITIALIZE(&f);
    f.alproto   = ALPROTO_MODBUS;
    f.protoctx  = (void *)&ssn;
    f.proto     = IPPROTO_TCP;
    f.alproto   = ALPROTO_MODBUS;
    f.flags     |= FLOW_IPV4;

    p->flow         = &f;
    p->flags        |= PKT_HAS_FLOW | PKT_STREAM_EST;
    p->flowflags    |= FLOW_PKT_TOSERVER | FLOW_PKT_ESTABLISHED;

    StreamTcpInitConfig(TRUE);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);

    de_ctx->flags |= DE_QUIET;
    s = DetectEngineAppendSig(de_ctx, "alert modbus any any -> any any "
                                      "(msg:\"Modbus Exception code invalid\"; "
                                      "app-layer-event: "
                                      "modbus.invalid_exception_code; "
                                      "sid:1;)");
    FAIL_IF_NULL(s);

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&tv, (void *)de_ctx, (void *)&det_ctx);

    FLOWLOCK_WRLOCK(&f);
    int r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_MODBUS,
                                STREAM_TOSERVER, readCoilsReq,
                                sizeof(readCoilsReq));
    FAIL_IF_NOT(r == 0);
    FLOWLOCK_UNLOCK(&f);

    ModbusState    *modbus_state = f.alstate;
    FAIL_IF_NULL(modbus_state);

    ModbusTransaction *tx = ModbusGetTx(modbus_state, 0);

    FAIL_IF_NOT(tx->function == 1);
    FAIL_IF_NOT(tx->read.address == 0x7890);
    FAIL_IF_NOT(tx->read.quantity == 19);

    FLOWLOCK_WRLOCK(&f);
    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_MODBUS,
                            STREAM_TOCLIENT, readCoilsErrorRsp,
                            sizeof(readCoilsErrorRsp));
    FAIL_IF_NOT(r == 0);
    FLOWLOCK_UNLOCK(&f);

    FAIL_IF_NOT(modbus_state->transaction_max == 1);

    /* do detect */
    SigMatchSignatures(&tv, de_ctx, det_ctx, p);

    FAIL_IF_NOT(PacketAlertCheck(p, 1));

    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);

    DetectEngineThreadCtxDeinit(&tv, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);

    AppLayerParserThreadCtxFree(alp_tctx);
    StreamTcpFreeConfig(TRUE);
    FLOW_DESTROY(&f);
    UTHFreePackets(&p, 1);
    PASS;
}

/** \test Modbus fragmentation - 1 ADU over 2 TCP packets. */
static int ModbusParserTest09(void) {
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();
    Flow f;
    TcpSession ssn;

    uint32_t    input_len = sizeof(readCoilsReq), part2_len = 3;
    uint8_t     *input = readCoilsReq;

    FAIL_IF_NULL(alp_tctx);

    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    FLOW_INITIALIZE(&f);
    f.protoctx  = (void *)&ssn;
    f.proto     = IPPROTO_TCP;
    f.alproto   = ALPROTO_MODBUS;

    StreamTcpInitConfig(TRUE);

    FLOWLOCK_WRLOCK(&f);
    int r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_MODBUS,
                                STREAM_TOSERVER, input, input_len - part2_len);
    FAIL_IF_NOT(r == 0);

    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_MODBUS,
                            STREAM_TOSERVER, input, input_len);
    FAIL_IF_NOT(r == 0);
    FLOWLOCK_UNLOCK(&f);

    ModbusState    *modbus_state = f.alstate;
    FAIL_IF_NULL(modbus_state);

    ModbusTransaction *tx = ModbusGetTx(modbus_state, 0);

    FAIL_IF_NOT(tx->function == 1);
    FAIL_IF_NOT(tx->read.address == 0x7890);
    FAIL_IF_NOT(tx->read.quantity == 19);

    input_len = sizeof(readCoilsRsp);
    part2_len = 10;
    input = readCoilsRsp;

    FLOWLOCK_WRLOCK(&f);
    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_MODBUS,
                            STREAM_TOCLIENT, input, input_len - part2_len);
    FAIL_IF_NOT(r == 0);

    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_MODBUS,
                            STREAM_TOCLIENT, input, input_len);
    FAIL_IF_NOT(r == 0);
    FLOWLOCK_UNLOCK(&f);

    FAIL_IF_NOT(modbus_state->transaction_max ==1);

    AppLayerParserThreadCtxFree(alp_tctx);
    StreamTcpFreeConfig(TRUE);
    FLOW_DESTROY(&f);
    PASS;
}

/** \test Modbus fragmentation - 2 ADU in 1 TCP packet. */
static int ModbusParserTest10(void) {
    uint32_t    input_len = sizeof(readCoilsReq) + sizeof(writeMultipleRegistersReq);
    uint8_t     *input, *ptr;

    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();
    Flow f;
    TcpSession ssn;

    FAIL_IF_NULL(alp_tctx);

    input  = (uint8_t *) SCMalloc (input_len * sizeof(uint8_t));
    FAIL_IF_NULL(input);

    memcpy(input, readCoilsReq, sizeof(readCoilsReq));
    memcpy(input + sizeof(readCoilsReq), writeMultipleRegistersReq, sizeof(writeMultipleRegistersReq));

    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    FLOW_INITIALIZE(&f);
    f.protoctx  = (void *)&ssn;
    f.proto     = IPPROTO_TCP;
    f.alproto   = ALPROTO_MODBUS;

    StreamTcpInitConfig(TRUE);

    FLOWLOCK_WRLOCK(&f);
    int r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_MODBUS,
                                STREAM_TOSERVER, input, input_len);
    FAIL_IF_NOT(r == 0);
    FLOWLOCK_UNLOCK(&f);

    ModbusState    *modbus_state = f.alstate;
    FAIL_IF_NULL(modbus_state);

    FAIL_IF_NOT(modbus_state->transaction_max == 2);

    ModbusTransaction *tx = ModbusGetTx(modbus_state, 1);

    FAIL_IF_NOT(tx->function == 16);
    FAIL_IF_NOT(tx->write.address == 0x01);
    FAIL_IF_NOT(tx->write.quantity == 2);
    FAIL_IF_NOT(tx->write.count == 4);
    FAIL_IF_NOT(tx->data[0] == 0x000A);
    FAIL_IF_NOT(tx->data[1] == 0x0102);

    input_len = sizeof(readCoilsRsp) + sizeof(writeMultipleRegistersRsp);

    ptr = (uint8_t *) SCRealloc (input, input_len * sizeof(uint8_t));
    FAIL_IF_NULL(ptr);
    input = ptr;

    memcpy(input, readCoilsRsp, sizeof(readCoilsRsp));
    memcpy(input + sizeof(readCoilsRsp), writeMultipleRegistersRsp, sizeof(writeMultipleRegistersRsp));

    FLOWLOCK_WRLOCK(&f);
    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_MODBUS,
                            STREAM_TOCLIENT, input, sizeof(input_len));
    FAIL_IF_NOT(r == 0);
    FLOWLOCK_UNLOCK(&f);

    SCFree(input);
    AppLayerParserThreadCtxFree(alp_tctx);
    StreamTcpFreeConfig(TRUE);
    FLOW_DESTROY(&f);
    PASS;
}

/** \test Send Modbus exceed Length request. */
static int ModbusParserTest11(void) {
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();
    DetectEngineThreadCtx *det_ctx = NULL;
    Flow f;
    Packet *p = NULL;
    Signature *s = NULL;
    TcpSession ssn;
    ThreadVars tv;

    FAIL_IF(alp_tctx == NULL);

    memset(&tv, 0, sizeof(ThreadVars));
    memset(&f, 0, sizeof(Flow));
    memset(&ssn, 0, sizeof(TcpSession));

    p = UTHBuildPacket(NULL, 0, IPPROTO_TCP);

    FLOW_INITIALIZE(&f);
    f.alproto   = ALPROTO_MODBUS;
    f.protoctx  = (void *)&ssn;
    f.proto     = IPPROTO_TCP;
    f.alproto   = ALPROTO_MODBUS;
    f.flags     |= FLOW_IPV4;

    p->flow         = &f;
    p->flags        |= PKT_HAS_FLOW | PKT_STREAM_EST;
    p->flowflags    |= FLOW_PKT_TOSERVER | FLOW_PKT_ESTABLISHED;

    StreamTcpInitConfig(TRUE);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);

    de_ctx->flags |= DE_QUIET;
    s = DetectEngineAppendSig(de_ctx, "alert modbus any any -> any any "
                                      "(msg:\"Modbus invalid Length\"; "
                                      "app-layer-event: "
                                      "modbus.invalid_length; "
                                      "sid:1;)");
    FAIL_IF_NULL(s);

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&tv, (void *)de_ctx, (void *)&det_ctx);

    FLOWLOCK_WRLOCK(&f);
    int r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_MODBUS,
                                STREAM_TOSERVER,
                                exceededLengthWriteMultipleRegistersReq,
                                sizeof(exceededLengthWriteMultipleRegistersReq) + 65523 * sizeof(uint8_t));
    FAIL_IF_NOT(r == 0);
    FLOWLOCK_UNLOCK(&f);

    ModbusState    *modbus_state = f.alstate;
    FAIL_IF_NULL(modbus_state);

    /* do detect */
    SigMatchSignatures(&tv, de_ctx, det_ctx, p);

    FAIL_IF_NOT(PacketAlertCheck(p, 1));

    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);

    DetectEngineThreadCtxDeinit(&tv, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);

    AppLayerParserThreadCtxFree(alp_tctx);
    StreamTcpFreeConfig(TRUE);
    FLOW_DESTROY(&f);
    UTHFreePackets(&p, 1);
    PASS;
}

/** \test Send Modbus invalid PDU Length. */
static int ModbusParserTest12(void) {
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();
    DetectEngineThreadCtx *det_ctx = NULL;
    Flow f;
    Packet *p = NULL;
    Signature *s = NULL;
    TcpSession ssn;
    ThreadVars tv;

    FAIL_IF_NULL(alp_tctx);

    memset(&tv, 0, sizeof(ThreadVars));
    memset(&f, 0, sizeof(Flow));
    memset(&ssn, 0, sizeof(TcpSession));

    p = UTHBuildPacket(NULL, 0, IPPROTO_TCP);

    FLOW_INITIALIZE(&f);
    f.alproto   = ALPROTO_MODBUS;
    f.protoctx  = (void *)&ssn;
    f.proto     = IPPROTO_TCP;
    f.alproto   = ALPROTO_MODBUS;
    f.flags     |= FLOW_IPV4;

    p->flow         = &f;
    p->flags        |= PKT_HAS_FLOW | PKT_STREAM_EST;
    p->flowflags    |= FLOW_PKT_TOSERVER | FLOW_PKT_ESTABLISHED;

    StreamTcpInitConfig(TRUE);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);

    de_ctx->flags |= DE_QUIET;
    s = DetectEngineAppendSig(de_ctx, "alert modbus any any -> any any "
                                      "(msg:\"Modbus invalid Length\"; "
                                      "app-layer-event: "
                                      "modbus.invalid_length; "
                                      "sid:1;)");
    FAIL_IF_NULL(s);

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&tv, (void *)de_ctx, (void *)&det_ctx);

    FLOWLOCK_WRLOCK(&f);
    int r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_MODBUS,
                                STREAM_TOSERVER,
                                invalidLengthPDUWriteMultipleRegistersReq,
                                sizeof(invalidLengthPDUWriteMultipleRegistersReq));
    FAIL_IF_NOT(r == 0);
    FLOWLOCK_UNLOCK(&f);

    ModbusState    *modbus_state = f.alstate;
    FAIL_IF_NULL(modbus_state);

    /* do detect */
    SigMatchSignatures(&tv, de_ctx, det_ctx, p);

    FAIL_IF_NOT(PacketAlertCheck(p, 1));

    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);

    DetectEngineThreadCtxDeinit(&tv, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);

    AppLayerParserThreadCtxFree(alp_tctx);
    StreamTcpFreeConfig(TRUE);
    FLOW_DESTROY(&f);
    UTHFreePackets(&p, 1);
    PASS;
}

/** \test Send Modbus Mask Write register request/response. */
static int ModbusParserTest13(void) {
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();
    Flow f;
    TcpSession ssn;

    FAIL_IF_NULL(alp_tctx);

    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    FLOW_INITIALIZE(&f);
    f.protoctx  = (void *)&ssn;
    f.proto     = IPPROTO_TCP;
    f.alproto   = ALPROTO_MODBUS;

    StreamTcpInitConfig(TRUE);

    FLOWLOCK_WRLOCK(&f);
    int r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_MODBUS,
                                STREAM_TOSERVER, maskWriteRegisterReq,
                                sizeof(maskWriteRegisterReq));
    FAIL_IF_NOT(r == 0);
    FLOWLOCK_UNLOCK(&f);

    ModbusState    *modbus_state = f.alstate;
    FAIL_IF_NULL(modbus_state);

    ModbusTransaction *tx = ModbusGetTx(modbus_state, 0);

    FAIL_IF_NOT(tx->function == 22);
    FAIL_IF_NOT(tx->data[0] == 0x00F2);
    FAIL_IF_NOT(tx->data[1] == 0x0025);

    FLOWLOCK_WRLOCK(&f);
    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_MODBUS,
                            STREAM_TOCLIENT, maskWriteRegisterRsp,
                            sizeof(maskWriteRegisterRsp));
    FAIL_IF_NOT(r == 0);
    FLOWLOCK_UNLOCK(&f);

    FAIL_IF_NOT(modbus_state->transaction_max == 1);

    AppLayerParserThreadCtxFree(alp_tctx);
    StreamTcpFreeConfig(TRUE);
    FLOW_DESTROY(&f);
    PASS;
}

/** \test Send Modbus Write single register request/response. */
static int ModbusParserTest14(void) {
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();
    Flow f;
    TcpSession ssn;

    FAIL_IF_NULL(alp_tctx);

    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    FLOW_INITIALIZE(&f);
    f.protoctx  = (void *)&ssn;
    f.proto     = IPPROTO_TCP;
    f.alproto   = ALPROTO_MODBUS;

    StreamTcpInitConfig(TRUE);

    FLOWLOCK_WRLOCK(&f);
    int r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_MODBUS,
                                STREAM_TOSERVER, writeSingleRegisterReq,
                                sizeof(writeSingleRegisterReq));
    FAIL_IF_NOT(r == 0);
    FLOWLOCK_UNLOCK(&f);

    ModbusState    *modbus_state = f.alstate;
    FAIL_IF_NULL(modbus_state);

    ModbusTransaction *tx = ModbusGetTx(modbus_state, 0);

    FAIL_IF_NOT(tx->function == 6);
    FAIL_IF_NOT(tx->write.address == 0x0001);
    FAIL_IF_NOT(tx->data[0] == 0x0003);

    FLOWLOCK_WRLOCK(&f);
    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_MODBUS,
                            STREAM_TOCLIENT, writeSingleRegisterRsp,
                            sizeof(writeSingleRegisterRsp));
    FAIL_IF_NOT(r == 0);
    FLOWLOCK_UNLOCK(&f);

    FAIL_IF_NOT(modbus_state->transaction_max == 1);

    AppLayerParserThreadCtxFree(alp_tctx);
    StreamTcpFreeConfig(TRUE);
    FLOW_DESTROY(&f);
    PASS;
}

/** \test Send invalid Modbus Mask Write register request. */
static int ModbusParserTest15(void) {
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();
    DetectEngineThreadCtx *det_ctx = NULL;
    Flow f;
    Packet *p = NULL;
    Signature *s = NULL;
    TcpSession ssn;
    ThreadVars tv;

    FAIL_IF_NULL(alp_tctx);

    memset(&tv, 0, sizeof(ThreadVars));
    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    p = UTHBuildPacket(NULL, 0, IPPROTO_TCP);

    FLOW_INITIALIZE(&f);
    f.alproto   = ALPROTO_MODBUS;
    f.protoctx  = (void *)&ssn;
    f.proto     = IPPROTO_TCP;
    f.alproto   = ALPROTO_MODBUS;
    f.flags     |= FLOW_IPV4;

    p->flow         = &f;
    p->flags        |= PKT_HAS_FLOW | PKT_STREAM_EST;
    p->flowflags    |= FLOW_PKT_TOSERVER | FLOW_PKT_ESTABLISHED;

    StreamTcpInitConfig(TRUE);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);

    de_ctx->flags |= DE_QUIET;
    s = DetectEngineAppendSig(de_ctx, "alert modbus any any -> any any "
                                      "(msg:\"Modbus invalid Length\"; "
                                      "app-layer-event: "
                                      "modbus.invalid_length; "
                                      "sid:1;)");
    FAIL_IF_NULL(s);

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&tv, (void *)de_ctx, (void *)&det_ctx);

    FLOWLOCK_WRLOCK(&f);
    int r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_MODBUS,
                                STREAM_TOSERVER, invalidMaskWriteRegisterReq,
                                sizeof(invalidMaskWriteRegisterReq));
    FAIL_IF_NOT(r == 0);
    FLOWLOCK_UNLOCK(&f);

    ModbusState    *modbus_state = f.alstate;
    FAIL_IF_NULL(modbus_state);

    ModbusTransaction *tx = ModbusGetTx(modbus_state, 0);

    FAIL_IF_NOT(tx->function == 22);

    /* do detect */
    SigMatchSignatures(&tv, de_ctx, det_ctx, p);

    FAIL_IF_NOT(PacketAlertCheck(p, 1));

    FLOWLOCK_WRLOCK(&f);
    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_MODBUS,
                            STREAM_TOCLIENT, maskWriteRegisterRsp,
                            sizeof(maskWriteRegisterRsp));
    FAIL_IF_NOT(r == 0);
    FLOWLOCK_UNLOCK(&f);

    FAIL_IF_NOT(modbus_state->transaction_max == 1);

    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);

    DetectEngineThreadCtxDeinit(&tv, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);

    AppLayerParserThreadCtxFree(alp_tctx);
    StreamTcpFreeConfig(TRUE);
    FLOW_DESTROY(&f);
    UTHFreePackets(&p, 1);
    PASS;
}

/** \test Send invalid Modbus Mask Write register request. */
static int ModbusParserTest16(void) {
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();
    DetectEngineThreadCtx *det_ctx = NULL;
    Flow f;
    Packet *p = NULL;
    Signature *s = NULL;
    TcpSession ssn;
    ThreadVars tv;

    FAIL_IF_NULL(alp_tctx);

    memset(&tv, 0, sizeof(ThreadVars));
    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    p = UTHBuildPacket(NULL, 0, IPPROTO_TCP);

    FLOW_INITIALIZE(&f);
    f.alproto   = ALPROTO_MODBUS;
    f.protoctx  = (void *)&ssn;
    f.proto     = IPPROTO_TCP;
    f.alproto   = ALPROTO_MODBUS;
    f.flags     |= FLOW_IPV4;

    p->flow         = &f;
    p->flags        |= PKT_HAS_FLOW | PKT_STREAM_EST;
    p->flowflags    |= FLOW_PKT_TOSERVER | FLOW_PKT_ESTABLISHED;

    StreamTcpInitConfig(TRUE);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);

    de_ctx->flags |= DE_QUIET;
    s = DetectEngineAppendSig(de_ctx, "alert modbus any any -> any any "
                                      "(msg:\"Modbus invalid Length\"; "
                                      "app-layer-event: "
                                      "modbus.invalid_length; "
                                      "sid:1;)");
    FAIL_IF_NULL(s);

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&tv, (void *)de_ctx, (void *)&det_ctx);

    FLOWLOCK_WRLOCK(&f);
    int r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_MODBUS,
                                STREAM_TOSERVER,
                                invalidWriteSingleRegisterReq,
                                sizeof(invalidWriteSingleRegisterReq));
    FAIL_IF_NOT(r == 0);
    FLOWLOCK_UNLOCK(&f);

    ModbusState    *modbus_state = f.alstate;
    FAIL_IF_NULL(modbus_state);

    ModbusTransaction *tx = ModbusGetTx(modbus_state, 0);

    FAIL_IF_NOT(tx->function == 6);
    FAIL_IF_NOT(tx->write.address == 0x0001);

    /* do detect */
    SigMatchSignatures(&tv, de_ctx, det_ctx, p);

    FAIL_IF_NOT(PacketAlertCheck(p, 1));

    FLOWLOCK_WRLOCK(&f);
    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_MODBUS,
                            STREAM_TOCLIENT, writeSingleRegisterRsp,
                            sizeof(writeSingleRegisterRsp));
    FAIL_IF_NOT(r == 0);
    FLOWLOCK_UNLOCK(&f);

    FAIL_IF_NOT(modbus_state->transaction_max == 1);

    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);

    DetectEngineThreadCtxDeinit(&tv, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);

    AppLayerParserThreadCtxFree(alp_tctx);
    StreamTcpFreeConfig(TRUE);
    FLOW_DESTROY(&f);
    UTHFreePackets(&p, 1);
    PASS;}

/** \test Checks if stream_depth is correct */
static int ModbusParserTest17(void) {
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();
    Flow f;
    TcpSession ssn;

    FAIL_IF_NULL(alp_tctx);

    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    FLOW_INITIALIZE(&f);
    f.protoctx  = (void *)&ssn;
    f.proto     = IPPROTO_TCP;
    f.alproto   = ALPROTO_MODBUS;

    StreamTcpInitConfig(TRUE);

    FLOWLOCK_WRLOCK(&f);
    int r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_MODBUS, STREAM_TOSERVER,
                                readCoilsReq, sizeof(readCoilsReq));
    FAIL_IF(r != 0);
    FLOWLOCK_UNLOCK(&f);

    FAIL_IF(f.alstate == NULL);

    FAIL_IF(((TcpSession *)(f.protoctx))->reassembly_depth != MODBUS_CONFIG_DEFAULT_STREAM_DEPTH);

    FLOWLOCK_WRLOCK(&f);
    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_MODBUS, STREAM_TOCLIENT,
                            readCoilsRsp, sizeof(readCoilsRsp));
    FAIL_IF(r != 0);
    FLOWLOCK_UNLOCK(&f);

    FAIL_IF(((TcpSession *)(f.protoctx))->reassembly_depth != MODBUS_CONFIG_DEFAULT_STREAM_DEPTH);

    AppLayerParserThreadCtxFree(alp_tctx);
    StreamTcpFreeConfig(TRUE);
    FLOW_DESTROY(&f);
    PASS;
}

/*/ \test Checks if stream depth is correct over 2 TCP packets */
static int ModbusParserTest18(void) {
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();
    Flow f;
    TcpSession ssn;

    uint32_t    input_len = sizeof(readCoilsReq), part2_len = 3;
    uint8_t     *input = readCoilsReq;

    FAIL_IF_NULL(alp_tctx);

    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    FLOW_INITIALIZE(&f);
    f.protoctx  = (void *)&ssn;
    f.proto     = IPPROTO_TCP;
    f.alproto   = ALPROTO_MODBUS;

    StreamTcpInitConfig(TRUE);

    FLOWLOCK_WRLOCK(&f);
    int r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_MODBUS, STREAM_TOSERVER,
                                input, input_len - part2_len);
    FAIL_IF(r != 0);
    FLOWLOCK_UNLOCK(&f);

    FAIL_IF(((TcpSession *)(f.protoctx))->reassembly_depth != MODBUS_CONFIG_DEFAULT_STREAM_DEPTH);

    FLOWLOCK_WRLOCK(&f);
    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_MODBUS, STREAM_TOSERVER,
                            input, input_len);
    FAIL_IF(r != 0);
    FLOWLOCK_UNLOCK(&f);

    FAIL_IF(((TcpSession *)(f.protoctx))->reassembly_depth != MODBUS_CONFIG_DEFAULT_STREAM_DEPTH);

    FAIL_IF(f.alstate == NULL);

    input_len = sizeof(readCoilsRsp);
    part2_len = 10;
    input = readCoilsRsp;

    FLOWLOCK_WRLOCK(&f);
    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_MODBUS, STREAM_TOCLIENT,
                            input, input_len - part2_len);
    FAIL_IF(r != 0);
    FLOWLOCK_UNLOCK(&f);

    FAIL_IF(((TcpSession *)(f.protoctx))->reassembly_depth != MODBUS_CONFIG_DEFAULT_STREAM_DEPTH);

    FLOWLOCK_WRLOCK(&f);
    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_MODBUS, STREAM_TOCLIENT,
                            input, input_len);
    FAIL_IF(r != 0);
    FLOWLOCK_UNLOCK(&f);

    FAIL_IF(((TcpSession *)(f.protoctx))->reassembly_depth != MODBUS_CONFIG_DEFAULT_STREAM_DEPTH);

    AppLayerParserThreadCtxFree(alp_tctx);
    StreamTcpFreeConfig(TRUE);
    FLOW_DESTROY(&f);
    PASS;
}

/** \test Send Modbus invalid function. */
static int ModbusParserTest19(void) {
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();
    DetectEngineThreadCtx *det_ctx = NULL;
    Flow f;
    Packet *p = NULL;
    Signature *s = NULL;
    TcpSession ssn;
    ThreadVars tv;

    FAIL_IF_NULL(alp_tctx);

    memset(&tv, 0, sizeof(ThreadVars));
    memset(&f, 0, sizeof(Flow));
    memset(&ssn, 0, sizeof(TcpSession));

    p = UTHBuildPacket(NULL, 0, IPPROTO_TCP);

    FLOW_INITIALIZE(&f);
    f.alproto   = ALPROTO_MODBUS;
    f.protoctx  = (void *)&ssn;
    f.proto     = IPPROTO_TCP;
    f.alproto   = ALPROTO_MODBUS;
    f.flags     |= FLOW_IPV4;

    p->flow         = &f;
    p->flags        |= PKT_HAS_FLOW | PKT_STREAM_EST;
    p->flowflags    |= FLOW_PKT_TOSERVER | FLOW_PKT_ESTABLISHED;

    StreamTcpInitConfig(TRUE);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);

    de_ctx->flags |= DE_QUIET;
    s = DetectEngineAppendSig(de_ctx, "alert modbus any any -> any any "
                                      "(msg:\"Modbus invalid Function code\"; "
                                      "app-layer-event: "
                                      "modbus.invalid_function_code; "
                                      "sid:1;)");
    FAIL_IF_NULL(s);

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&tv, (void *)de_ctx, (void *)&det_ctx);

    FLOWLOCK_WRLOCK(&f);
    int r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_MODBUS,
                                STREAM_TOSERVER,
                                invalidFunctionCode,
                                sizeof(invalidFunctionCode));
    FAIL_IF_NOT(r == 0);
    FLOWLOCK_UNLOCK(&f);

    ModbusState    *modbus_state = f.alstate;
    FAIL_IF_NULL(modbus_state);

    /* do detect */
    SigMatchSignatures(&tv, de_ctx, det_ctx, p);

    FAIL_IF_NOT(PacketAlertCheck(p, 1));

    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);

    DetectEngineThreadCtxDeinit(&tv, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);

    AppLayerParserThreadCtxFree(alp_tctx);
    StreamTcpFreeConfig(TRUE);
    FLOW_DESTROY(&f);
    UTHFreePackets(&p, 1);
    PASS;
}
#endif /* UNITTESTS */

void ModbusParserRegisterTests(void) {
#ifdef UNITTESTS
    UtRegisterTest("ModbusParserTest01 - Modbus Read Coils request",
                   ModbusParserTest01);
    UtRegisterTest("ModbusParserTest02 - Modbus Write Multiple registers request",
                   ModbusParserTest02);
    UtRegisterTest("ModbusParserTest03 - Modbus Read/Write Multiple registers request",
                   ModbusParserTest03);
    UtRegisterTest("ModbusParserTest04 - Modbus Force Listen Only Mode request",
                   ModbusParserTest04);
    UtRegisterTest("ModbusParserTest05 - Modbus invalid Protocol version",
                   ModbusParserTest05);
    UtRegisterTest("ModbusParserTest06 - Modbus unsolicited response",
                   ModbusParserTest06);
    UtRegisterTest("ModbusParserTest07 - Modbus invalid Length request",
                   ModbusParserTest07);
    UtRegisterTest("ModbusParserTest08 - Modbus Exception code invalid",
                   ModbusParserTest08);
    UtRegisterTest("ModbusParserTest09 - Modbus fragmentation - 1 ADU in 2 TCP packets",
                   ModbusParserTest09);
    UtRegisterTest("ModbusParserTest10 - Modbus fragmentation - 2 ADU in 1 TCP packet",
                   ModbusParserTest10);
    UtRegisterTest("ModbusParserTest11 - Modbus exceeded Length request",
                   ModbusParserTest11);
    UtRegisterTest("ModbusParserTest12 - Modbus invalid PDU Length",
                   ModbusParserTest12);
    UtRegisterTest("ModbusParserTest13 - Modbus Mask Write register request",
                   ModbusParserTest13);
    UtRegisterTest("ModbusParserTest14 - Modbus Write single register request",
                   ModbusParserTest14);
    UtRegisterTest("ModbusParserTest15 - Modbus invalid Mask Write register request",
                   ModbusParserTest15);
    UtRegisterTest("ModbusParserTest16 - Modbus invalid Write single register request",
                   ModbusParserTest16);
    UtRegisterTest("ModbusParserTest17 - Modbus stream depth",
                   ModbusParserTest17);
    UtRegisterTest("ModbusParserTest18 - Modbus stream depth in 2 TCP packets",
                   ModbusParserTest18);
    UtRegisterTest("ModbusParserTest19 - Modbus invalid Function code",
                   ModbusParserTest19);
#endif /* UNITTESTS */
}
