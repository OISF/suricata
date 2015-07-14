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

/* Extract fields from the link control octet. */
#define DNP3_LINK_DIR(control) (control & 0x80)
#define DNP3_LINK_PRI(control) (control & 0x40)
#define DNP3_LINK_FCB(control) (control & 0x20)
#define DNP3_LINK_FCV(control) (control & 0x10)
#define DNP3_LINK_FC(control)  (control & 0x0f)

/* Extract fields from transport layer header octet. */
#define DNP3_TRANSPORT_FIN(x) (x & 0x80)
#define DNP3_TRANSPORT_FIR(x) (x & 0x40)
#define DNP3_TRANSPORT_SEQ(x) (x & 0x3f)

/* Extract fields from the application control octet. */
#define DNP3_APP_FIR(x) (x & 0x80)
#define DNP3_APP_FIN(x) (x & 0x40)
#define DNP3_APP_CON(x) (x & 0x20)
#define DNP3_APP_UNS(x) (x & 0x10)
#define DNP3_APP_SEQ(x) (x & 0x0f)

/* DNP3 decoder events. */
enum {
    DNP3_DECODER_EVENT_FLOODED,
    DNP3_DECODER_EVENT_LEN_TOO_SMALL,
    DNP3_DECODER_EVENT_BAD_LINK_CRC,
    DNP3_DECODER_EVENT_BAD_TRANSPORT_CRC,
};

typedef uint8_t DNP3TransportHeader;

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
 * Struct to hold the list of decoded objects.
 */
typedef struct DNP3Object_ {
    uint8_t   group;
    uint8_t   variation;
    uint8_t   prefix;
    uint8_t   range;
    uint8_t  *data;
    uint32_t  len;
    TAILQ_ENTRY(DNP3Object_) next;
} DNP3Object;

typedef TAILQ_HEAD(DNP3ObjectList_, DNP3Object_) DNP3ObjectList;

/**
 * Struct to track DNP3 sessions within a TCP session.
 */
typedef struct DNP3Session_ {
    uint16_t master; /**< Master address (client). */
    uint16_t slave;  /**< Slave/outstation address (server). */

    uint8_t outstation_tran_seqno; /**< Last transport seqno from outstation. */

    struct DNP3Transaction_ *last_tx;
} DNP3Session;

/**
 * DNP3 transaction.
 */
typedef struct DNP3Transaction_ {
    uint64_t tx_num; /**< Internal transaction ID. */

    struct DNP3State_ *dnp3;
    DNP3Session *session;

    uint8_t transport_seqno;
    uint8_t app_seqno;

    uint8_t app_function_code; /**< Application function code. In the
                                * context of a transaction, this is
                                * the initiation function code.  So
                                * that most likely means the function
                                * code in the request.  The exception
                                * being an unsolicited response, this
                                * will be the function code of the
                                * unsolicited response. */

    uint8_t iin1; /**< Internal indicators, byte 1. */
    uint8_t iin2; /**< Internal indicators, byte 2. */

    uint8_t   request_ll_control; /**< Link layer control byte. */
    uint8_t   request_th;         /**< Request transport header. */
    uint8_t   request_al_control; /**< Request app. layer control. */
    uint8_t   request_al_fc;    /**< Request app. layer function code. */
    uint8_t  *request_buffer;   /**< Reassembled request buffer. */
    uint32_t  request_buffer_len;
    uint8_t   request_done;
    uint8_t   request_decode_complete; /**< Was the decode complete.
                                        * It will not be complete if
                                        * we hit objects we do not
                                        * know. */
    DNP3ObjectList request_objects;

    uint8_t   response_ll_control; /**< Link layer control byte. */
    uint8_t   response_th;         /**< Response transport header. */
    uint8_t   response_al_control; /**< Response app. layer control. */
    uint8_t   response_al_fc;    /**< Response app. layer function code. */
    uint8_t  *response_buffer;  /**< Reassembed response buffer. */
    uint32_t  response_buffer_len;
    uint8_t   response_done;
    uint8_t   response_decode_complete; /**< Was the decode complete.
                                         * It will not be complete if
                                         * we hit objects we do not
                                         * know. */
    DNP3ObjectList response_objects;

    AppLayerDecoderEvents *decoder_events; /**< Per transcation
                                            * decoder events. */
    DetectEngineState *de_state;

    TAILQ_ENTRY(DNP3Transaction_) next;
} DNP3Transaction;

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
    HashListTable *sessions;   /**< DNP3 sessions in this flow. */

    DNP3Buffer request_buffer;
    DNP3Buffer response_buffer;

} DNP3State;

void RegisterDNP3Parsers(void);
void DNP3ParserRegisterTests(void);

#endif /* __APP_LAYER_DNP3_H__ */
