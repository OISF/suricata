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

#ifndef __APP_LAYER_DNSP3_H__
#define __APP_LAYER_DNSP3_H__

#include "detect-engine-state.h"
#include "util-hashlist.h"

/**
 * The maximum size of a DNP3 link PDU.
 */
#define DNP3_MAX_LINK_PDU_LEN 292

/* DNP3 decoder events. */
enum {
    DNP3_DECODER_EVENT_FLOODED,
    DNP3_DECODER_EVENT_LEN_TOO_SMALL,
    DNP3_DECODER_EVENT_BAD_LINK_CRC,
    DNP3_DECODER_EVENT_BAD_TRANSPORT_CRC,
    DNP3_DECODER_EVENT_BAD_TRANSPORT_SEQNO,
    DNP3_DECODER_EVENT_BAD_APPLICATION_SEQNO,
};

typedef struct DNP3Buffer_ {
    uint8_t buffer[0xffff];
    int len;
    int offset;
} DNP3Buffer;

typedef struct DNP3Session_ {
    uint16_t master; /**< Master address (client). */
    uint16_t slave;  /**< Slave/outstation address (server). */

    uint32_t master_count;     /**< Count of frames from master. */
    uint32_t outstation_count; /**< Count of frames from outstation. */

    uint32_t outstation_unsol_resp_count; /**< Count of unsolicited
                                           * responses from an
                                           * outstation. Used for
                                           * application sequence
                                           * number validation. */

    uint8_t master_tran_seqno; /**< Last transport seqno from master. */
    uint8_t master_app_seqno;  /**< Last app. seqno from master. */

    uint8_t outstation_tran_seqno; /**< Last transport seqno from outstation. */
    uint8_t outstation_app_seqno;  /**< Last app. seqno from outstation. */

} DNP3Session;

typedef struct DNP3Transaction_ {
    uint64_t tx_num; /**< Internal transaction ID. */

    struct DNP3State_ *dnp3;
    DNP3Session *session;

    uint8_t transport_seqno;
    uint8_t app_seqno;

    uint8_t replied;

    uint8_t app_function_code; /**< Application function code. */

    uint8_t iin1; /**< Internal indicators, byte 1. */
    uint8_t iin2; /**< Internal indicators, byte 2. */

    uint8_t  *request_buffer;   /**< Reassembled request buffer. */
    uint32_t  request_buffer_len;

    uint8_t  *response_buffer;  /**< Reassembed response buffer. */
    uint32_t  response_buffer_len;

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

#endif /* __APP_LAYER_DNSP3_H__ */
