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
#include "app-layer-parser.h"

/* TODO can we get rid of this somehow? */
extern thread_local uint64_t app_record_base_offset;
extern thread_local uint8_t *app_record_base_ptr;
extern thread_local uint32_t app_record_base_len;

typedef int64_t RecordId;

enum {
    RECORD_FLAGE_ENDS_AT_EOF,
#define RECORD_FLAG_ENDS_AT_EOF BIT_U8(RECORD_FLAGE_ENDS_AT_EOF)
};

typedef struct Record {
    uint8_t type;  /**< protocol specific field type. E.g. NBSS.HDR or SMB.DATA */
    uint8_t flags; /**< rec flags. */
    uint8_t event_cnt;
// TODO one event per record enough?
    uint8_t events[4];  /**< per record store for events */
    int32_t rel_offset; /**< relative offset in the stream on top of Stream::stream_offset (if
                           negative the start if before the stream data) */
    int32_t len;
    int64_t id;
    uint64_t tx_id;     /**< tx_id to match this rec. UINT64T_MAX if not used. */
} Record;
// size 32

#define RECORDS_STATIC_CNT 3

typedef struct Records {
    uint16_t cnt;
    uint16_t dyn_size;                      /**< size in elements of `drecs` */
    uint32_t progress_rel;                  /**< processing depth relative to STREAM_BASE_OFFSET */
    uint64_t base_id;
    Record srecs[RECORDS_STATIC_CNT];       /**< static records */
    Record *drecs;
} Records;
// size ?

typedef struct RecordsContainer {
    Records toserver;
    Records toclient;
} RecordsContainer;

void RecordsFree(Records *recs);
int RecordSlide(Records *recs, uint32_t slide);

Record *AppLayerRecordNew(
        Flow *f, const uint8_t *rec_start, const uint32_t len, int dir, uint8_t rec_type);
Record *AppLayerRecordNew2(
        Flow *f, const uint32_t rec_start_rel, const uint32_t len, int dir, uint8_t rec_type);
void AppLayerRecordDump(Flow *f);

Record *RecordGetByIndex(Records *recs, const uint32_t idx);
Record *RecordGetById(Records *recs, const int64_t id);

void AppLayerRecordAddEvent(Record *rec, uint8_t e);
RecordId AppLayerRecordGetId(Record *r);

void AppLayerRecordsUpdateProgress(Flow *f, TcpStream *stream, const uint64_t progress,
        const uint8_t direction);
void AppLayerRecordsSlide(Flow *f, const uint32_t slide, const uint8_t direction);


RecordsContainer *AppLayerRecordsGetContainer(Flow *f);
RecordsContainer *AppLayerRecordsSetupContainer(Flow *f);

#endif
