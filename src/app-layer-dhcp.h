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
 * \author Tom DeCanio <decanio.tom@gmail.com>
 */

#ifndef __APP_LAYER_DHCP_H__
#define __APP_LAYER_DHCP_H__

#include "detect-engine-state.h"

#include "queue.h"

void RegisterdhcpParsers(void);
void dhcpParserRegisterTests(void);

#define BOOTP_REQUEST 1
#define BOOTP_REPLY 2
#define BOOTP_ETHERNET 1
#define BOOTP_DHCP_MAGIC_COOKIE 0x63825363

typedef struct BOOTPHdr_ {
    uint8_t op;
    uint8_t htype;
    uint8_t hlen;
    uint8_t hops;
    uint32_t xid;
    uint16_t secs;
    uint16_t flags;
    uint32_t ciaddr;
    uint32_t yiaddr;
    uint32_t siaddr;
    uint32_t giaddr;
    uint32_t chaddr[4];
    uint8_t  zeros[192];
    uint32_t magic;
} BOOTPHdr;


#define DHCP_DHCP_MSG_TYPE 53

#define DHCP_DISCOVER 1
#define DHCP_OFFER 2
#define DHCP_REQUEST 3
#define DHCP_ACK 5
#define DHCP_NACK 6
#define DHCP_INFORM 8

typedef struct DHCPOpt_ {
    uint8_t code;
    uint8_t len;
    uint8_t args[];
} DHCPOpt;

typedef struct dhcpTransaction_ {

    uint64_t tx_id;             /*<< Internal transaction ID. */

    AppLayerDecoderEvents *decoder_events; /*<< Application layer
                                            * events that occurred
                                            * while parsing this
                                            * transaction. */

    uint32_t xid;
    uint32_t logged;

    uint8_t *request_buffer;
    uint32_t request_buffer_len;

    uint8_t *response_buffer;
    uint32_t response_buffer_len;

    uint8_t response_done; /*<< Flag to be set when the response is
                            * seen. */

    DetectEngineState *de_state;

    TAILQ_ENTRY(dhcpTransaction_) next;

} dhcpTransaction;

typedef struct dhcpState_ {

    SCMutex lock;    /** Mutex for access to tx_list */


    SC_ATOMIC_DECLARE(uint32_t, initialized);

    TAILQ_HEAD(, dhcpTransaction_) tx_list; /**< List of dhcp transactions
                                       * associated with this
                                       * state. */

    uint64_t transaction_max; /**< A count of the number of
                               * transactions created.  The
                               * transaction ID for each transaction
                               * is allocted by incrementing this
                               * value. */

    /* Indicates the current transaction being logged. 
     */
    uint64_t log_id;

    uint16_t events; /**< Number of application layer events created
                      * for this state. */


} dhcpState;

#endif /* __APP_LAYER_DHCP_H__ */
