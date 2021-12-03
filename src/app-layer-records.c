/* Copyright (C) 2007-2021 Open Information Security Foundation
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
 *
 */

#include "suricata-common.h"
#include "debug.h"
#include "util-print.h"

#include "app-layer-records.h"

thread_local uint64_t app_record_base_offset;
thread_local uint8_t *app_record_base_ptr;
thread_local uint32_t app_record_base_len;

static void RecordDebug(const char *prefix, const Records *recs, const Record *rec)
{
    SCLogDebug(
            "[%s] %p: record: %p type %u flags %02x rel_offset:%u, len:%u, events:%u %u/%u/%u/%u",
            prefix, recs, rec, rec->type, rec->flags, rec->rel_offset, rec->len, rec->event_cnt,
            rec->events[0], rec->events[1], rec->events[2], rec->events[3]);
}

Record *RecordGetById(Records *recs, const int64_t id)
{
    for (uint16_t i = 0; i < recs->cnt; i++) {
        if (i < RECORDS_STATIC_CNT) {
            Record *rec = &recs->srecs[i];
            if (rec->id == id)
                return rec;
        } else {
            const uint16_t o = i - RECORDS_STATIC_CNT;
            Record *rec = &recs->drecs[o];
            if (rec->id == id)
                return rec;
        }
    }
    return NULL;
}

Record *RecordGetByIndex(Records *recs, const uint32_t idx)
{
    if (idx >= recs->cnt)
        return NULL;

    if (idx < RECORDS_STATIC_CNT) {
        Record *rec = &recs->srecs[idx];
        RecordDebug("get_by_idx(s)", recs, rec);
        return rec;
    } else {
        const uint16_t o = idx - RECORDS_STATIC_CNT;
        Record *rec = &recs->drecs[o];
        RecordDebug("get_by_idx(d)", recs, rec);
        return rec;
    }
}

static Record *RecordNew(Records *recs, uint32_t rel_offset, int32_t len)
{
    BUG_ON(recs == NULL);

    if (recs->cnt < RECORDS_STATIC_CNT) {
        Record *rec = &recs->srecs[recs->cnt];
        recs->srecs[recs->cnt].rel_offset = rel_offset;
        recs->srecs[recs->cnt].len = len;
        recs->srecs[recs->cnt].id = recs->base_id++;
        recs->cnt++;
        return rec;
    } else if (recs->drecs == NULL) {
        BUG_ON(recs->dyn_size != 0);
        BUG_ON(recs->cnt != RECORDS_STATIC_CNT);

        recs->drecs = SCCalloc(8, sizeof(Record));
        if (recs->drecs == NULL) {
            return NULL;
        }
        recs->cnt++;
        BUG_ON(recs->cnt != RECORDS_STATIC_CNT + 1);

        recs->dyn_size = 8;
        recs->drecs[0].rel_offset = rel_offset;
        recs->drecs[0].len = len;
        recs->drecs[0].id = recs->base_id++;
        return &recs->drecs[0];
    } else {
        BUG_ON(recs->cnt < RECORDS_STATIC_CNT);

        /* need to handle dynamic storage of records now */
        const uint16_t dyn_cnt = recs->cnt - RECORDS_STATIC_CNT;
        if (dyn_cnt < recs->dyn_size) {
            BUG_ON(recs->drecs == NULL);

            // fall through
        } else {
            if (recs->dyn_size == 256) {
                SCLogNotice("limit reached! 256 dynamic records already");
                // limit reached
                return NULL;
            }

            /* realloc time */
            uint16_t new_dyn_size = recs->dyn_size * 2;
            uint32_t new_alloc_size = new_dyn_size * sizeof(Record);

            void *ptr = SCRealloc(recs->drecs, new_alloc_size);
            if (ptr == NULL) {
                return NULL;
            }

            memset((uint8_t *)ptr + (recs->dyn_size * sizeof(Record)), 0x00,
                    (recs->dyn_size * sizeof(Record)));
            recs->drecs = ptr;
            recs->dyn_size = new_dyn_size;
        }

        recs->cnt++;
        recs->drecs[dyn_cnt].rel_offset = rel_offset;
        recs->drecs[dyn_cnt].len = len;
        recs->drecs[dyn_cnt].id = recs->base_id++;
        return &recs->drecs[dyn_cnt];
    }
}

static Record *AddRecordWithAbsOffset(Records *recs, uint64_t abs_offset, int32_t len)
{
    BUG_ON(abs_offset < app_record_base_offset);
    BUG_ON(abs_offset - app_record_base_offset >= (uint64_t)UINT_MAX);

    uint32_t rel_offset = abs_offset - app_record_base_offset;
    return RecordNew(recs, rel_offset, len);
}

static Record *AddRecordFromPointers(
        TcpStream *stream, Records *recs, const uint8_t *base, const uint8_t *rec, uint32_t len)
{
    BUG_ON(app_record_base_offset < STREAM_BASE_OFFSET(stream));
    uint32_t app_ahead_of_base = app_record_base_offset - STREAM_BASE_OFFSET(stream);
    BUG_ON(rec < app_record_base_ptr);
    uint32_t rel_offset = rec - app_record_base_ptr + app_ahead_of_base;
    SCLogDebug("new record: rel_offset %u len %u (base:%" PRIu64 ",app:%" PRIu64
               ",app_ahead_of_base:%u)",
            rel_offset, len, STREAM_BASE_OFFSET(stream), app_record_base_offset, app_ahead_of_base);
    return RecordNew(recs, rel_offset, len);
}

static void RecordClean(Record *rec)
{
    memset(rec, 0, sizeof(*rec));
}

static void StreamDPUCopy(Record *dst, Record *src)
{
    memcpy(dst, src, sizeof(*dst));
}

static void AppLayerRecordDumpForRecords(const char *prefix, const Records *recs)
{
    // uint32_t last_re = 0;
    for (uint16_t i = 0; i < recs->cnt; i++) {
        if (i < RECORDS_STATIC_CNT) {
            const Record *rec = &recs->srecs[i];
            RecordDebug(prefix, recs, rec);
            // BUG_ON(last_re != 0 && last_re > rec->rel_offset);
            // last_re = rec->rel_offset + rec->len;
        } else {
            const uint16_t o = i - RECORDS_STATIC_CNT;
            const Record *rec = &recs->drecs[o];
            RecordDebug(prefix, recs, rec);
            // BUG_ON(last_re != 0 && last_re > rec->rel_offset);
            // last_re = rec->rel_offset + rec->len;
        }
    }
}

/** Stream buffer slides forward, we need to update and age out
 *  record offsets/records. Aging out means we move existing records
 *  into the slots we'd free up.
 *
 *  Start:
 *
 *  [ stream ]
 *    [ rec   ...........]
 *      rel_offset: 2
 *      len: 19
 *
 *  Slide:
 *         [ stream ]
 *    [ rec ....          .]
 *      rel_offset: -10
 *       len: 19
 *
 *  Slide:
 *                [ stream ]
 *    [ rec ...........    ]
 *      rel_offset: -16
 *      len: 19
 */
int RecordSlide(Records *recs, uint32_t slide)
{
    BUG_ON(recs == NULL);
    SCLogDebug("recs %p: sliding %u bytes", recs, slide);

    if (slide >= recs->progress_rel)
        recs->progress_rel = 0;
    else
        recs->progress_rel -= slide;

    uint16_t x = 0;
    for (uint16_t i = 0; i < recs->cnt; i++) {
        if (i < RECORDS_STATIC_CNT) {
            Record *rec = &recs->srecs[i];
            RecordDebug("slide(s)", recs, rec);
            if (rec->rel_offset + rec->len <= (int32_t)slide) {
                // remove by not incrementing 'x'
                SCLogDebug("removing %p", rec);
                RecordClean(rec);
            } else {
                Record *nrec = &recs->srecs[x];
                StreamDPUCopy(nrec, rec);
                nrec->rel_offset -= slide; /* turns negative if start if before window */
                if (rec != nrec) {
                    RecordClean(rec);
                }
                x++;
            }
        } else {
            const uint16_t o = i - RECORDS_STATIC_CNT;
            Record *rec = &recs->drecs[o];
            RecordDebug("slide(d)", recs, rec);
            if (rec->rel_offset + rec->len <= (int32_t)slide) {
                // remove by not incrementing 'x'
                SCLogDebug("removing %p", rec);
                RecordClean(rec);
            } else {
                Record *nrec;
                if (x >= RECORDS_STATIC_CNT) {
                    nrec = &recs->drecs[x - RECORDS_STATIC_CNT];
                } else {
                    nrec = &recs->srecs[x];
                }
                StreamDPUCopy(nrec, rec);
                nrec->rel_offset -= slide; /* turns negative if start if before window */
                if (rec != nrec) {
                    RecordClean(rec);
                }
                x++;
            }
        }
    }
    recs->cnt = x;
    AppLayerRecordDumpForRecords("post_slide", recs);
    return 0;
}

void AppLayerRecordsUpdateProgress(
        Flow *f, TcpStream *stream, const uint64_t progress, const uint8_t direction)
{
    RecordsContainer *records_container = AppLayerRecordsGetContainer(f);
    if (records_container == NULL)
        return;

    Records *recs;
    if (direction == STREAM_TOSERVER) {
        recs = &records_container->toserver;
    } else {
        recs = &records_container->toclient;
    }

    const uint32_t slide = progress - STREAM_APP_PROGRESS(stream);
    recs->progress_rel += slide;
}

void AppLayerRecordsSlide(Flow *f, const uint32_t slide, const uint8_t direction)
{
    RecordsContainer *records_container = AppLayerRecordsGetContainer(f);
    if (records_container == NULL)
        return;
    Records *recs;
    if (direction == STREAM_TOSERVER) {
        recs = &records_container->toserver;
    } else {
        recs = &records_container->toclient;
    }
    RecordSlide(recs, slide);
}

static void RecordFreeSingleRecord(Records *recs, Record *r)
{
    RecordDebug("free", recs, r);
    RecordClean(r);
}

void RecordsFree(Records *recs)
{
    BUG_ON(recs == NULL);

    for (uint16_t i = 0; i < recs->cnt; i++) {
        if (i < RECORDS_STATIC_CNT) {
            Record *r = &recs->srecs[i];
            RecordFreeSingleRecord(recs, r);
        } else {
            const uint16_t o = i - RECORDS_STATIC_CNT;
            Record *r = &recs->drecs[o];
            RecordFreeSingleRecord(recs, r);
        }
    }
    SCFree(recs->drecs);
    recs->drecs = NULL;
}

Record *AppLayerRecordNew(
        Flow *f, const uint8_t *rec_start, const uint32_t len, int dir, uint8_t rec_type)
{
    SCLogDebug("app_record_base_offset %" PRIu64, app_record_base_offset);
    SCLogDebug("rec_start %p app_record_base_ptr %p", rec_start, app_record_base_ptr);

    /* workarounds for many (unit|fuzz)tests not handling TCP data properly */
#if defined(UNITTESTS) || defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION)
    if (f->protoctx == NULL)
        return NULL;
    if (rec_start < app_record_base_ptr || rec_start >= app_record_base_ptr + app_record_base_len)
        return NULL;
#endif
    BUG_ON(rec_start < app_record_base_ptr);
    BUG_ON(app_record_base_ptr == NULL);
    BUG_ON(f->proto != IPPROTO_TCP);
    BUG_ON(f->protoctx == NULL);

#ifdef DEBUG
    ptrdiff_t ptr_offset = rec_start - app_record_base_ptr;
    uint64_t offset = ptr_offset + app_record_base_offset;
    SCLogDebug("flow %p direction %s record %p starting at %" PRIu64 " len %u (offset %" PRIu64 ")",
            f, dir == 0 ? "toserver" : "toclient", rec_start, offset, len, app_record_base_offset);
#endif
    BUG_ON(f->alparser == NULL);

    RecordsContainer *records_container = AppLayerRecordsSetupContainer(f);
    if (records_container == NULL)
        return NULL;

    Records *recs;
    TcpSession *ssn = f->protoctx;
    TcpStream *stream;
    if (dir == 0) {
        stream = &ssn->client;
        recs = &records_container->toserver;
    } else {
        stream = &ssn->server;
        recs = &records_container->toclient;
    }

    Record *r = AddRecordFromPointers(stream, recs, app_record_base_ptr, rec_start, len);
    if (r != NULL) {
        r->type = rec_type;
    }
    return r;
}

Record *AppLayerRecordNew2(
        Flow *f, const uint32_t rec_start_rel, const uint32_t len, int dir, uint8_t rec_type)
{
    /* workarounds for many (unit|fuzz)tests not handling TCP data properly */
#if defined(UNITTESTS) || defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION)
    if (f->protoctx == NULL)
        return NULL;
    if (app_record_base_ptr == NULL)
        return NULL;
#endif
    BUG_ON(app_record_base_ptr == NULL);
    BUG_ON(f->proto != IPPROTO_TCP);
    BUG_ON(f->protoctx == NULL);
    BUG_ON(f->alparser == NULL);

    const uint64_t offset = (uint64_t)rec_start_rel + app_record_base_offset;
    SCLogDebug("flow %p direction %s record offset %u (abs %" PRIu64 ") starting at %" PRIu64
               " len %u (offset %" PRIu64 ")",
            f, dir == 0 ? "toserver" : "toclient", rec_start_rel, offset, offset, len,
            app_record_base_offset);

    RecordsContainer *records_container = AppLayerRecordsSetupContainer(f);
    if (records_container == NULL)
        return NULL;

    Records *recs;
    if (dir == 0) {
        recs = &records_container->toserver;
    } else {
        recs = &records_container->toclient;
    }

    Record *r = AddRecordWithAbsOffset(recs, offset, len);
    if (r != NULL) {
        r->type = rec_type;
    }
    return r;
}

void AppLayerRecordDump(Flow *f)
{
    if (f->proto == IPPROTO_TCP && f->protoctx && f->alparser) {
        RecordsContainer *records_container = AppLayerRecordsGetContainer(f);
        if (records_container != NULL) {
            AppLayerRecordDumpForRecords("toserver::dump", &records_container->toserver);
            AppLayerRecordDumpForRecords("toclient::dump", &records_container->toclient);
        }
    }
}

void AppLayerRecordAddEvent(Record *r, uint8_t e)
{
    if (r != NULL) {
        if (r->event_cnt < 4) { // TODO
            r->events[r->event_cnt++] = e;
        }
        RecordDebug("add_event", NULL, r);
    }
}

RecordId AppLayerRecordGetId(Record *r)
{
    if (r != NULL) {
        return r->id;
    } else {
        return -1;
    }
}
