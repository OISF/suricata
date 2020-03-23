/* Copyright (C) 2021 Open Information Security Foundation
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

#ifndef __APP_LAYER_RECORDS_H__
#define __APP_LAYER_RECORDS_H__

#include "app-layer-events.h"
#include "detect-engine-state.h"
#include "util-file.h"
#include "stream-tcp-private.h"
#include "rust.h"

extern thread_local uint64_t app_record_base_offset;
extern thread_local uint8_t *app_record_base_ptr;
extern thread_local uint32_t app_record_base_len;

StreamPDU *AppLayerRecordNew(
        Flow *f, const uint8_t *rec_start, const uint32_t len, int dir, uint8_t rec_type);
StreamPDU *AppLayerRecordNew2(
        Flow *f, const uint32_t rec_start_rel, const uint32_t len, int dir, uint8_t rec_type);
void AppLayerRecordSetType(StreamPDU *pdu, uint8_t type);
void AppLayerRecordAddEvent(StreamPDU *pdu, uint8_t event);
void AppLayerRecordDump(Flow *f);
StreamPDU *StreamPDUGetByIndex(StreamPDUs *pdus, const uint32_t idx);

#endif
