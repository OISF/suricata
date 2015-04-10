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

#ifndef __APP_LAYER_DNP3_H__
#define __APP_LAYER_DNP3_H__

#include "detect-engine-state.h"
#include "util-hashlist.h"

/**
 * The maximum size of a DNP3 link PDU.
 */
#define DNP3_MAX_LINK_PDU_LEN 292

/* DNP3 application request function codes. */
#define DNP3_APP_FC_CONFIRM                0x00
#define DNP3_APP_FC_READ                   0x01
#define DNP3_APP_FC_WRITE                  0x02
#define DNP3_APP_FC_SELECT                 0x03
#define DNP3_APP_FC_OPERATE                0x04
#define DNP3_APP_FC_DIR_OPERATE            0x05
#define DNP3_APP_FC_DIR_OPERATE_NR         0x06
#define DNP3_APP_FC_FREEZE                 0x07
#define DNP3_APP_FC_FREEZE_NR              0x08
#define DNP3_APP_FC_FREEZE_CLEAR           0x09
#define DNP3_APP_FC_FREEZE_CLEAR_NR        0x0a
#define DNP3_APP_FC_FREEZE_AT_TIME         0x0b
#define DNP3_APP_FC_FREEZE_AT_TIME_NR      0x0c
#define DNP3_APP_FC_COLD_RESTART           0x0d
#define DNP3_APP_FC_WARM_RESTART           0x0e
#define DNP3_APP_FC_INITIALIZE_DATA        0x0f
#define DNP3_APP_FC_INITIALIZE_APPLICATION 0x10
#define DNP3_APP_FC_START_APPLICATION      0x11
#define DNP3_APP_FC_STOP_APPLICATION       0x12
#define DNP3_APP_FC_SAVE_CONFIGURATION     0x13
#define DNP3_APP_FC_ENABLE_UNSOLICITED     0x14
#define DNP3_APP_FC_DISABLE_UNSOLICTED     0x15
#define DNP3_APP_FC_ASSIGN_CLASS           0x16
#define DNP3_APP_FC_DELAY_MEASUREMENT      0x17
#define DNP3_APP_FC_RECORD_CURRENT_TIME    0x18
#define DNP3_APP_FC_OPEN_TIME              0x19
#define DNP3_APP_FC_CLOSE_FILE             0x1a
#define DNP3_APP_FC_DELETE_FILE            0x1b
#define DNP3_APP_FC_GET_FILE_INFO          0x1c
#define DNP3_APP_FC_AUTHENTICATE_FILE      0x1d
#define DNP3_APP_FC_ABORT_FILE             0x1e
#define DNP3_APP_FC_ACTIVATE_CONFIG        0x1f
#define DNP3_APP_FC_AUTH_REQ               0x20
#define DNP3_APP_FC_AUTH_REQ_NR            0x21

/* DNP3 application response function codes. */
#define DNP3_APP_FC_RESPONSE               0x81
#define DNP3_APP_FC_UNSOLICITED_RESP       0x82
#define DNP3_APP_FC_AUTH_RESP              0x83

/* Extract fields from the link control octet. */
#define DNP3_LINK_DIR(control) (control & 0x80)
#define DNP3_LINK_PRI(control) (control & 0x40)
#define DNP3_LINK_FCB(control) (control & 0x20)
#define DNP3_LINK_FCV(control) (control & 0x10)
#define DNP3_LINK_FC(control)  (control & 0x0f)

/* Extract fields from transport layer header octet. */
#define DNP3_TH_FIN(x) (x & 0x80)
#define DNP3_TH_FIR(x) (x & 0x40)
#define DNP3_TH_SEQ(x) (x & 0x3f)

/* Extract fields from the application control octet. */
#define DNP3_APP_FIR(x) (x & 0x80)
#define DNP3_APP_FIN(x) (x & 0x40)
#define DNP3_APP_CON(x) (x & 0x20)
#define DNP3_APP_UNS(x) (x & 0x10)
#define DNP3_APP_SEQ(x) (x & 0x0f)

/* DNP3 values are stored in little endian on the wire, so swapping will be
 * needed on big endian architectures. */
#if __BYTE_ORDER == __BIG_ENDIAN
#define DNP3_SWAP16(x) SCByteSwap16(x)
#define DNP3_SWAP32(x) SCByteSwap32(x)
#elif __BYTE_ORDER == __LITTLE_ENDIAN
#define DNP3_SWAP16(x) x
#define DNP3_SWAP32(x) x
#endif

/* DNP3 decoder events. */
enum {
    DNP3_DECODER_EVENT_FLOODED = 1,
    DNP3_DECODER_EVENT_LEN_TOO_SMALL,
    DNP3_DECODER_EVENT_BAD_LINK_CRC,
    DNP3_DECODER_EVENT_BAD_TRANSPORT_CRC,
    DNP3_DECODER_EVENT_MALFORMED,
    DNP3_DECODER_EVENT_UNKNOWN_OBJECT,
};

typedef struct DNP3LinkHeader_ {
    uint8_t  start_byte0;
    uint8_t  start_byte1;
    uint8_t  len;
    uint8_t  control;
    uint16_t dst;
    uint16_t src;
    uint16_t crc;
} __attribute__((__packed__)) DNP3LinkHeader;

typedef uint8_t DNP3TransportHeader;

typedef struct DNP3ApplicationHeader_ {
    uint8_t control;
    uint8_t function_code;
} __attribute__((__packed__)) DNP3ApplicationHeader;

typedef struct DNP3InternalInd_ {
    uint8_t iin1;
    uint8_t iin2;
} __attribute__((__packed__)) DNP3InternalInd;

/**
 * A struct used for buffering incoming data prior to reassembly.
 */
typedef struct DNP3Buffer_ {
    uint8_t *buffer;
    size_t   size;
    int      len;
    int      offset;
} DNP3Buffer;

/**
 * DNP3 application object header.
 */
typedef struct DNP3ObjHeader_ {
    uint8_t group;
    uint8_t variation;
    uint8_t qualifier;
} __attribute__((packed)) DNP3ObjHeader;

typedef struct DNP3ObjectItem_ {
    uint32_t prefix;
    uint32_t index;
    uint32_t size;
    void *item;
    TAILQ_ENTRY(DNP3ObjectItem_) next;
} DNP3ObjectItem;

typedef TAILQ_HEAD(DNP3ObjectItemList_, DNP3ObjectItem_) DNP3ObjectItemList;

/**
 * Struct to hold the list of decoded objects.
 */
typedef struct DNP3Object_ {
    uint8_t   group;
    uint8_t   variation;
    uint8_t   qualifier;
    uint8_t   prefix_code;
    uint8_t   range_code;
    uint32_t  start;
    uint32_t  stop;
    uint32_t  count;
    DNP3ObjectItemList *items;
    TAILQ_ENTRY(DNP3Object_) next;
} DNP3Object;

typedef TAILQ_HEAD(DNP3ObjectList_, DNP3Object_) DNP3ObjectList;

/**
 * DNP3 transaction.
 */
typedef struct DNP3Transaction_ {
    uint64_t tx_num; /**< Internal transaction ID. */

    struct DNP3State_ *dnp3;

    uint8_t                has_request;
    uint8_t                request_done;
    DNP3LinkHeader         request_lh;
    DNP3TransportHeader    request_th;
    DNP3ApplicationHeader  request_ah;
    uint8_t               *request_buffer; /**< Reassembled request
                                            * buffer. */
    uint32_t               request_buffer_len;
    uint8_t                request_complete; /**< Was the decode
                                        * complete.  It will not be
                                        * complete if we hit objects
                                        * we do not know. */
    DNP3ObjectList         request_objects;

    uint8_t                has_response;
    uint8_t                response_done;
    DNP3LinkHeader         response_lh;
    DNP3TransportHeader    response_th;
    DNP3ApplicationHeader  response_ah;
    DNP3InternalInd        response_iin;
    uint8_t               *response_buffer; /**< Reassembed response
                                             * buffer. */
    uint32_t               response_buffer_len;
    uint8_t                response_complete; /**< Was the decode
                                         * complete.  It will not be
                                         * complete if we hit objects
                                         * we do not know. */
    DNP3ObjectList         response_objects;

    AppLayerDecoderEvents *decoder_events; /**< Per transcation
                                            * decoder events. */
    DetectEngineState *de_state;

    TAILQ_ENTRY(DNP3Transaction_) next;
} DNP3Transaction;

TAILQ_HEAD(TxListHead, DNP3Transaction_);

/**
 * \brief Per flow DNP3 state.
 */
typedef struct DNP3State_ {
    TAILQ_HEAD(, DNP3Transaction_) tx_list;
    DNP3Transaction *curr;     /**< Current transaction. */
    uint64_t transaction_max;
    uint16_t events;
    uint32_t unreplied;        /**< Number of unreplied requests. */
    uint8_t flooded;           /**< Flag indicating flood. */

    DNP3Buffer request_buffer;
    DNP3Buffer response_buffer;

} DNP3State;

void RegisterDNP3Parsers(void);
void DNP3ParserRegisterTests(void);

#endif /* __APP_LAYER_DNP3_H__ */
