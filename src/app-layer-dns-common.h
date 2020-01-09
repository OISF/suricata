/* Copyright (C) 2013 Open Information Security Foundation
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
 * \author Victor Julien <victor@inliniac.net>
 */

#ifndef __APP_LAYER_DNS_COMMON_H__
#define __APP_LAYER_DNS_COMMON_H__

#include "app-layer-protos.h"
#include "app-layer-parser.h"

enum {
    DNS_DECODER_EVENT_UNSOLLICITED_RESPONSE,
    DNS_DECODER_EVENT_MALFORMED_DATA,
    DNS_DECODER_EVENT_NOT_A_REQUEST,
    DNS_DECODER_EVENT_NOT_A_RESPONSE,
    DNS_DECODER_EVENT_Z_FLAG_SET,
    DNS_DECODER_EVENT_FLOODED,
    DNS_DECODER_EVENT_STATE_MEMCAP_REACHED,
};

/** Opaque Rust types. */

/** \brief DNS packet header */
typedef struct DNSHeader_ {
    uint16_t tx_id;
    uint16_t flags;
    uint16_t questions;
    uint16_t answer_rr;
    uint16_t authority_rr;
    uint16_t additional_rr;
} __attribute__((__packed__)) DNSHeader;

int DNSStateGetEventInfo(const char *event_name,
                         int *event_id, AppLayerEventType *event_type);
int DNSStateGetEventInfoById(int event_id, const char **event_name,
                             AppLayerEventType *event_type);
void DNSAppLayerRegisterGetEventInfo(uint8_t ipproto, AppProto alproto);
void DNSAppLayerRegisterGetEventInfoById(uint8_t ipproto, AppProto alproto);

#endif /* __APP_LAYER_DNS_COMMON_H__ */
