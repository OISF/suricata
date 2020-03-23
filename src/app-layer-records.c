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

static void StreamPDUDebug(const char *prefix, const StreamPDUs *pdus, const StreamPDU *pdu)
{
    SCLogDebug("[%s] %p: pdu: %p type %u flags %02x rel_offset:%u, len:%u, events:%u %u/%u/%u/%u",
            prefix, pdus, pdu, pdu->type, pdu->flags, pdu->rel_offset, pdu->len, pdu->event_cnt,
            pdu->events[0], pdu->events[1], pdu->events[2], pdu->events[3]);
}

StreamPDU *StreamPDUGetByIndex(StreamPDUs *pdus, const uint32_t idx)
{
    if (idx >= pdus->cnt)
        return NULL;

    if (idx < STREAM_PDU_STATIC_CNT) {
        StreamPDU *pdu = &pdus->spdus[idx];
        StreamPDUDebug("get_by_idx(s)", pdus, pdu);
        return pdu;
    } else {
        const uint16_t o = idx - STREAM_PDU_STATIC_CNT;
        StreamPDU *pdu = &pdus->dpdus[o];
        StreamPDUDebug("get_by_idx(d)", pdus, pdu);
        return pdu;
    }
}

static StreamPDU *StreamPDUNew(StreamPDUs *pdus, uint32_t rel_offset, int32_t len)
{
    assert(pdus);

    if (pdus->cnt < STREAM_PDU_STATIC_CNT) {
        StreamPDU *pdu = &pdus->spdus[pdus->cnt];
        pdus->spdus[pdus->cnt].rel_offset = rel_offset;
        pdus->spdus[pdus->cnt].len = len;
        pdus->cnt++;
        return pdu;
    } else if (pdus->dpdus == NULL) {
        assert(pdus->dyn_size == 0);
        assert(pdus->cnt == STREAM_PDU_STATIC_CNT);

        pdus->dpdus = SCCalloc(8, sizeof(StreamPDU));
        if (pdus->dpdus == NULL) {
            return NULL;
        }
        pdus->cnt++;
        assert(pdus->cnt == STREAM_PDU_STATIC_CNT + 1);

        pdus->dyn_size = 8;
        pdus->dpdus[0].rel_offset = rel_offset;
        pdus->dpdus[0].len = len;
        return &pdus->dpdus[0];
    } else {
        assert(pdus->cnt >= STREAM_PDU_STATIC_CNT);

        /* need to handle dynamic storage of records now */
        const uint16_t dyn_cnt = pdus->cnt - STREAM_PDU_STATIC_CNT;
        if (dyn_cnt < pdus->dyn_size) {
            assert(pdus->dpdus);

            // fall through
        } else {
            if (pdus->dyn_size == 256) {
                SCLogNotice("limit reached! 256 dynamic records already");
                // limit reached
                return NULL;
            }

            /* realloc time */
            uint16_t new_dyn_size = pdus->dyn_size * 2;
            uint32_t new_alloc_size = new_dyn_size * sizeof(StreamPDU);

            void *ptr = SCRealloc(pdus->dpdus, new_alloc_size);
            if (ptr == NULL) {
                return NULL;
            }

            memset((uint8_t *)ptr + (pdus->dyn_size * sizeof(StreamPDU)), 0x00,
                    (pdus->dyn_size * sizeof(StreamPDU)));
            pdus->dpdus = ptr;
            pdus->dyn_size = new_dyn_size;
        }

        pdus->cnt++;
        pdus->dpdus[dyn_cnt].rel_offset = rel_offset;
        pdus->dpdus[dyn_cnt].len = len;
        return &pdus->dpdus[dyn_cnt];
    }
}

#if 0
static StreamPDU *StreamTcpAddPDUWithRelativeOffset(TcpStream *stream, uint32_t rel_offset, int32_t len)
{
    return StreamPDUNew(&stream->pdus, rel_offset, len);
}
#endif

static StreamPDU *StreamTcpAddPDUWithAbsOffset(TcpStream *stream, uint64_t abs_offset, int32_t len)
{
    assert(abs_offset >= app_record_base_offset);
    assert(abs_offset - app_record_base_offset < (uint64_t)UINT_MAX);

    uint32_t rel_offset = abs_offset - app_record_base_offset;
    return StreamPDUNew(&stream->pdus, rel_offset, len);
}

static StreamPDU *StreamTcpAddPDUToStreamFromPointers(
        TcpStream *stream, const uint8_t *base, const uint8_t *rec, uint32_t len)
{
    assert(app_record_base_offset >= STREAM_BASE_OFFSET(stream));
    uint32_t app_ahead_of_base = app_record_base_offset - STREAM_BASE_OFFSET(stream);
    assert(rec >= app_record_base_ptr);
    uint32_t rel_offset = rec - app_record_base_ptr + app_ahead_of_base;
    SCLogDebug("new record: rel_offset %u len %u (base:%" PRIu64 ",app:%" PRIu64
               ",app_ahead_of_base:%u)",
            rel_offset, len, STREAM_BASE_OFFSET(stream), app_record_base_offset, app_ahead_of_base);
    return StreamPDUNew(&stream->pdus, rel_offset, len);
}

static void StreamPDUClean(StreamPDU *pdu)
{
    memset(pdu, 0, sizeof(*pdu));
}

static void StreamDPUCopy(StreamPDU *dst, StreamPDU *src)
{
    memcpy(dst, src, sizeof(*dst));
}

static void AppLayerRecordDumpForStreamPDUs(const char *prefix, const StreamPDUs *pdus)
{
    uint32_t last_re = 0;
    for (uint16_t i = 0; i < pdus->cnt; i++) {
        if (i < STREAM_PDU_STATIC_CNT) {
            const StreamPDU *pdu = &pdus->spdus[i];
            StreamPDUDebug(prefix, pdus, pdu);
            // BUG_ON(last_re != 0 && last_re > pdu->rel_offset);
            last_re = pdu->rel_offset + pdu->len;
        } else {
            const uint16_t o = i - STREAM_PDU_STATIC_CNT;
            const StreamPDU *pdu = &pdus->dpdus[o];
            StreamPDUDebug(prefix, pdus, pdu);
            // BUG_ON(last_re != 0 && last_re > pdu->rel_offset);
            last_re = pdu->rel_offset + pdu->len;
        }
    }
}

/** Stream buffer slides forward, we need to update and age out
 *  PDU offsets/records. Aging out means we move existing records
 *  into the slots we'd free up.


Start:

[ stream ]
  [ pdu   ...........]
   rel_offset: 2
   len: 19

Slide:
          [ stream ]
[ pdu ....          .]
 rel_offset: -10
 len: 19

Slide:
                 [ stream ]
[ pdu ...........    ]
 rel_offset: -16
 len: 19


 */
int StreamPDUSlide(StreamPDUs *pdus, uint32_t slide)
{
    assert(pdus);
    SCLogDebug("pdus %p: sliding %u bytes", pdus, slide);

    uint16_t x = 0;
    for (uint16_t i = 0; i < pdus->cnt; i++) {
        if (i < STREAM_PDU_STATIC_CNT) {
            StreamPDU *pdu = &pdus->spdus[i];
            StreamPDUDebug("slide(s)", pdus, pdu);
            if (pdu->rel_offset + pdu->len <= (int32_t)slide) {
                // remove by not incrementing 'x'
                SCLogDebug("removing %p", pdu);
                StreamPDUClean(pdu);
            } else {
                StreamPDU *npdu = &pdus->spdus[x];
                StreamDPUCopy(npdu, pdu);
                npdu->rel_offset -= slide; /* turns negative if start if before window */
                if (pdu != npdu) {
                    StreamPDUClean(pdu);
                }
                x++;
            }
        } else {
            const uint16_t o = i - STREAM_PDU_STATIC_CNT;
            StreamPDU *pdu = &pdus->dpdus[o];
            StreamPDUDebug("slide(d)", pdus, pdu);
            if (pdu->rel_offset + pdu->len <= (int32_t)slide) {
                // remove by not incrementing 'x'
                SCLogDebug("removing %p", pdu);
                StreamPDUClean(pdu);
            } else {
                StreamPDU *npdu;
                if (x >= STREAM_PDU_STATIC_CNT) {
                    npdu = &pdus->dpdus[x - STREAM_PDU_STATIC_CNT];
                } else {
                    npdu = &pdus->spdus[x];
                }
                StreamDPUCopy(npdu, pdu);
                npdu->rel_offset -= slide; /* turns negative if start if before window */
                if (pdu != npdu) {
                    StreamPDUClean(pdu);
                }
                x++;
            }
        }
    }
    pdus->cnt = x;
    AppLayerRecordDumpForStreamPDUs("post_slide", pdus);
    return 0;
}

static void StreamPDUFreeSinglePDU(StreamPDUs *pdus, StreamPDU *pdu)
{
    StreamPDUDebug("free", pdus, pdu);
    StreamPDUClean(pdu);
}

void StreamPDUsFree(StreamPDUs *pdus)
{
    assert(pdus);

    for (uint16_t i = 0; i < pdus->cnt; i++) {
        if (i < STREAM_PDU_STATIC_CNT) {
            StreamPDU *pdu = &pdus->spdus[i];
            StreamPDUFreeSinglePDU(pdus, pdu);
        } else {
            const uint16_t o = i - STREAM_PDU_STATIC_CNT;
            StreamPDU *pdu = &pdus->dpdus[o];
            StreamPDUFreeSinglePDU(pdus, pdu);
        }
    }
    SCFree(pdus->dpdus);
    pdus->dpdus = NULL;
}

StreamPDU *AppLayerRecordNew(
        Flow *f, const uint8_t *rec_start, const uint32_t len, int dir, uint8_t rec_type)
{
    assert(rec_start >= app_record_base_ptr);
    assert(app_record_base_ptr);
    assert(f->proto == IPPROTO_TCP);
    assert(f->protoctx);

    ptrdiff_t ptr_offset = rec_start - app_record_base_ptr;
    uint64_t offset = ptr_offset + app_record_base_offset;
    SCLogDebug("flow %p direction %s record %p starting at %" PRIu64 " len %u (offset %" PRIu64 ")",
            f, dir == 0 ? "toserver" : "toclient", rec_start, offset, len, app_record_base_offset);

    TcpSession *ssn = f->protoctx;
    TcpStream *stream;
    if (dir == 0) {
        stream = &ssn->client;
    } else {
        stream = &ssn->server;
    }

    StreamPDU *pdu =
            StreamTcpAddPDUToStreamFromPointers(stream, app_record_base_ptr, rec_start, len);
    if (pdu != NULL) {
        pdu->type = rec_type;
    }
    return pdu;
}

StreamPDU *AppLayerRecordNew2(
        Flow *f, const uint32_t rec_start_rel, const uint32_t len, int dir, uint8_t rec_type)
{
    assert(app_record_base_ptr);
    assert(f->proto == IPPROTO_TCP);
    assert(f->protoctx);

    uint64_t offset = (uint64_t)rec_start_rel + app_record_base_offset;
    SCLogDebug("flow %p direction %s record offset %u (abs %" PRIu64 ") starting at %" PRIu64
               " len %u (offset %" PRIu64 ")",
            f, dir == 0 ? "toserver" : "toclient", rec_start_rel, offset, offset, len,
            app_record_base_offset);

    // BUG_ON(offset + len > app_record_base_offset + app_record_base_len);

    TcpSession *ssn = f->protoctx;
    TcpStream *stream;
    if (dir == 0) {
        stream = &ssn->client;
    } else {
        stream = &ssn->server;
    }

    StreamPDU *pdu = StreamTcpAddPDUWithAbsOffset(stream, offset, len);
    if (pdu != NULL) {
        pdu->type = rec_type;
    }
    return pdu;
}

static void AppLayerRecordDumpForStream(const char *prefix, TcpStream *stream)
{
    StreamPDUs *pdus = &stream->pdus;
    AppLayerRecordDumpForStreamPDUs(prefix, pdus);
}

void AppLayerRecordDump(Flow *f)
{
    assert(f->proto == IPPROTO_TCP);
    assert(f->protoctx);

    TcpSession *ssn = f->protoctx;
    AppLayerRecordDumpForStream("toserver::dump", &ssn->client);
    AppLayerRecordDumpForStream("toclient::dump", &ssn->server);
}

void AppLayerRecordAddEvent(StreamPDU *pdu, uint8_t e)
{
    assert(pdu);
    if (pdu->event_cnt < 4) { // TODO
        pdu->events[pdu->event_cnt++] = e;
    }
    StreamPDUDebug("add_event", NULL, pdu);
}

void AppLayerRecordSetType(StreamPDU *pdu, uint8_t type)
{
    SCLogNotice("pdu %p type %u", pdu, type);
    assert(pdu);
    assert(pdu->type == 0);
    pdu->type = type;
    StreamPDUDebug("set_type", NULL, pdu);
}
