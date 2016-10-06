/* Copyright (C) 2015-2016 Open Information Security Foundation
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

#include "suricata-common.h"
#include "util-streaming-buffer.h"
#include "util-unittest.h"
#include "util-print.h"

/**
 * \file
 *
 * \author Victor Julien <victor@inliniac.net>
 *
 *  \brief Streaming Buffer API
 */

/* memory handling wrappers. If config doesn't define it's own set of
 * functions, use the defaults */
#define MALLOC(cfg, s) \
    (cfg)->Malloc ? (cfg)->Malloc((s)) : SCMalloc((s))
#define CALLOC(cfg, n, s) \
    (cfg)->Calloc ? (cfg)->Calloc((n), (s)) : SCCalloc((n), (s))
#define REALLOC(cfg, ptr, orig_s, s) \
    (cfg)->Realloc ? (cfg)->Realloc((ptr), (orig_s), (s)) : SCRealloc((ptr), (s))
#define FREE(cfg, ptr, s) \
    (cfg)->Free ? (cfg)->Free((ptr), (s)) : SCFree((ptr))

static inline int InitBuffer(StreamingBuffer *sb)
{
    sb->buf = CALLOC(sb->cfg, 1, sb->cfg->buf_size);
    if (sb->buf == NULL) {
        return -1;
    }
    sb->buf_size = sb->cfg->buf_size;
    return 0;
}

StreamingBuffer *StreamingBufferInit(const StreamingBufferConfig *cfg)
{
    StreamingBuffer *sb = CALLOC(cfg, 1, sizeof(StreamingBuffer));
    if (sb != NULL) {
        sb->buf_size = cfg->buf_size;
        sb->cfg = cfg;

        if (cfg->buf_size > 0) {
            if (InitBuffer(sb) == 0) {
                return sb;
            }
            FREE(cfg, sb, sizeof(StreamingBuffer));
        /* implied buf_size == 0 */
        } else {
            return sb;
        }
    }
    return NULL;
}

void StreamingBufferClear(StreamingBuffer *sb)
{
    if (sb != NULL) {
        SCLogDebug("sb->buf_size %u max %u", sb->buf_size, sb->buf_size_max);

        if (sb->buf != NULL) {
            FREE(sb->cfg, sb->buf, sb->buf_size);
            sb->buf = NULL;
        }
    }
}

void StreamingBufferFree(StreamingBuffer *sb)
{
    if (sb != NULL) {
        StreamingBufferClear(sb);
        FREE(sb->cfg, sb, sizeof(StreamingBuffer));
    }
}

/**
 * \internal
 * \brief move buffer forward by 'slide'
 */
static void AutoSlide(StreamingBuffer *sb)
{
    uint32_t size = sb->cfg->buf_slide;
    uint32_t slide = sb->buf_offset - size;
    SCLogDebug("sliding %u forward, size of original buffer left after slide %u", slide, size);
    memmove(sb->buf, sb->buf+slide, size);
    sb->stream_offset += slide;
    sb->buf_offset = size;
}

static void GrowToSize(StreamingBuffer *sb, uint32_t size)
{
    /* try to grow in multiples of sb->cfg->buf_size */
    uint32_t x = sb->cfg->buf_size ? size % sb->cfg->buf_size : 0;
    uint32_t base = size - x;
    uint32_t grow = base + sb->cfg->buf_size;

    void *ptr = REALLOC(sb->cfg, sb->buf, sb->buf_size, grow);
    if (ptr != NULL) {
        /* for safe printing and general caution, lets memset the
         * new data to 0 */
        size_t diff = grow - sb->buf_size;
        void *new_mem = ((char *)ptr) + sb->buf_size;
        memset(new_mem, 0, diff);

        sb->buf = ptr;
        sb->buf_size = grow;
        SCLogDebug("grown buffer to %u", grow);
#ifdef DEBUG
        if (sb->buf_size > sb->buf_size_max) {
            sb->buf_size_max = sb->buf_size;
        }
#endif
    }
}

/** \internal
 *  \brief try to double the buffer size
 *  \retval 0 ok
 *  \retval -1 failed, buffer unchanged
 */
//static int Grow(StreamingBuffer *sb) __attribute__((warn_unused_result));
static int __attribute__((warn_unused_result)) Grow(StreamingBuffer *sb)
{
    uint32_t grow = sb->buf_size * 2;
    void *ptr = REALLOC(sb->cfg, sb->buf, sb->buf_size, grow);
    if (ptr == NULL)
        return -1;

    /* for safe printing and general caution, lets memset the
     * new data to 0 */
    size_t diff = grow - sb->buf_size;
    void *new_mem = ((char *)ptr) + sb->buf_size;
    memset(new_mem, 0, diff);

    sb->buf = ptr;
    sb->buf_size = grow;
    SCLogDebug("grown buffer to %u", grow);
#ifdef DEBUG
    if (sb->buf_size > sb->buf_size_max) {
        sb->buf_size_max = sb->buf_size;
    }
#endif
    return 0;
}

/**
 *  \brief slide to absolute offset
 *  \todo if sliding beyond window, we could perhaps reset?
 */
void StreamingBufferSlideToOffset(StreamingBuffer *sb, uint64_t offset)
{
    if (offset > sb->stream_offset &&
        offset <= sb->stream_offset + sb->buf_offset)
    {
        uint32_t slide = offset - sb->stream_offset;
        uint32_t size = sb->buf_offset - slide;
        SCLogDebug("sliding %u forward, size of original buffer left after slide %u", slide, size);
        memmove(sb->buf, sb->buf+slide, size);
        sb->stream_offset += slide;
        sb->buf_offset = size;
    }
}

void StreamingBufferSlide(StreamingBuffer *sb, uint32_t slide)
{
    uint32_t size = sb->buf_offset - slide;
    SCLogDebug("sliding %u forward, size of original buffer left after slide %u", slide, size);
    memmove(sb->buf, sb->buf+slide, size);
    sb->stream_offset += slide;
    sb->buf_offset = size;
}

#define DATA_FITS(sb, len) \
    ((sb)->buf_offset + (len) <= (sb)->buf_size)

StreamingBufferSegment *StreamingBufferAppendRaw(StreamingBuffer *sb, const uint8_t *data, uint32_t data_len)
{
    if (sb->buf == NULL) {
        if (InitBuffer(sb) == -1)
            return NULL;
    }

    if (!DATA_FITS(sb, data_len)) {
        if (sb->cfg->flags & STREAMING_BUFFER_AUTOSLIDE)
            AutoSlide(sb);
        if (sb->buf_size == 0) {
            GrowToSize(sb, data_len);
        } else {
            while (!DATA_FITS(sb, data_len)) {
                if (Grow(sb) != 0) {
                    return NULL;
                }
            }
        }
    }
    if (!DATA_FITS(sb, data_len)) {
        return NULL;
    }

    StreamingBufferSegment *seg = CALLOC(sb->cfg, 1, sizeof(StreamingBufferSegment));
    if (seg != NULL) {
        memcpy(sb->buf + sb->buf_offset, data, data_len);
        seg->stream_offset = sb->stream_offset + sb->buf_offset;
        seg->segment_len = data_len;
        sb->buf_offset += data_len;
        return seg;
    }
    return NULL;
}

int StreamingBufferAppend(StreamingBuffer *sb, StreamingBufferSegment *seg,
                          const uint8_t *data, uint32_t data_len)
{
    BUG_ON(seg == NULL);

    if (sb->buf == NULL) {
        if (InitBuffer(sb) == -1)
            return -1;
    }

    if (!DATA_FITS(sb, data_len)) {
        if (sb->cfg->flags & STREAMING_BUFFER_AUTOSLIDE)
            AutoSlide(sb);
        if (sb->buf_size == 0) {
            GrowToSize(sb, data_len);
        } else {
            while (!DATA_FITS(sb, data_len)) {
                if (Grow(sb) != 0) {
                    return -1;
                }
            }
        }
    }
    if (!DATA_FITS(sb, data_len)) {
        return -1;
    }

    memcpy(sb->buf + sb->buf_offset, data, data_len);
    seg->stream_offset = sb->stream_offset + sb->buf_offset;
    seg->segment_len = data_len;
    sb->buf_offset += data_len;
    return 0;
}

/**
 *  \brief add data w/o tracking a segment
 */
int StreamingBufferAppendNoTrack(StreamingBuffer *sb,
                                 const uint8_t *data, uint32_t data_len)
{
    if (sb->buf == NULL) {
        if (InitBuffer(sb) == -1)
            return -1;
    }

    if (!DATA_FITS(sb, data_len)) {
        if (sb->cfg->flags & STREAMING_BUFFER_AUTOSLIDE)
            AutoSlide(sb);
        if (sb->buf_size == 0) {
            GrowToSize(sb, data_len);
        } else {
            while (!DATA_FITS(sb, data_len)) {
                if (Grow(sb) != 0) {
                    return -1;
                }
            }
        }
    }
    if (!DATA_FITS(sb, data_len)) {
        return -1;
    }

    memcpy(sb->buf + sb->buf_offset, data, data_len);
    sb->buf_offset += data_len;
    return 0;
}

#define DATA_FITS_AT_OFFSET(sb, len, offset) \
    ((offset) + (len) <= (sb)->buf_size)

/**
 *  \param offset offset relative to StreamingBuffer::stream_offset
 */
int StreamingBufferInsertAt(StreamingBuffer *sb, StreamingBufferSegment *seg,
                            const uint8_t *data, uint32_t data_len,
                            uint64_t offset)
{
    BUG_ON(seg == NULL);

    if (offset < sb->stream_offset)
        return -1;

    if (sb->buf == NULL) {
        if (InitBuffer(sb) == -1)
            return -1;
    }

    uint32_t rel_offset = offset - sb->stream_offset;
    if (!DATA_FITS_AT_OFFSET(sb, data_len, rel_offset)) {
        if (sb->cfg->flags & STREAMING_BUFFER_AUTOSLIDE) {
            AutoSlide(sb);
            rel_offset = offset - sb->stream_offset;
        }
        if (!DATA_FITS_AT_OFFSET(sb, data_len, rel_offset)) {
            GrowToSize(sb, (rel_offset + data_len));
        }
    }
    BUG_ON(!DATA_FITS_AT_OFFSET(sb, data_len, rel_offset));

    memcpy(sb->buf + rel_offset, data, data_len);
    seg->stream_offset = offset;
    seg->segment_len = data_len;
    if (rel_offset + data_len > sb->buf_offset)
        sb->buf_offset = rel_offset + data_len;
    return 0;
}

int StreamingBufferSegmentIsBeforeWindow(const StreamingBuffer *sb,
                                         const StreamingBufferSegment *seg)
{
    if (seg->stream_offset < sb->stream_offset) {
        if (seg->stream_offset + seg->segment_len <= sb->stream_offset) {
            return 1;
        }
    }
    return 0;
}

void StreamingBufferSegmentGetData(const StreamingBuffer *sb,
                                   const StreamingBufferSegment *seg,
                                   const uint8_t **data, uint32_t *data_len)
{
    if (seg->stream_offset >= sb->stream_offset) {
        uint64_t offset = seg->stream_offset - sb->stream_offset;
        *data = sb->buf + offset;
        if (offset + seg->segment_len > sb->buf_size)
            *data_len = sb->buf_size - offset;
        else
            *data_len = seg->segment_len;
        return;
    } else {
        uint64_t offset = sb->stream_offset - seg->stream_offset;
        if (offset < seg->segment_len) {
            *data = sb->buf;
            *data_len = seg->segment_len - offset;
            return;
        }
    }
    *data = NULL;
    *data_len = 0;
    return;
}

/**
 *  \retval 1 data is the same
 *  \retval 0 data is different
 */
int StreamingBufferSegmentCompareRawData(const StreamingBuffer *sb,
                                         const StreamingBufferSegment *seg,
                                         const uint8_t *rawdata, uint32_t rawdata_len)
{
    const uint8_t *segdata = NULL;
    uint32_t segdata_len = 0;
    StreamingBufferSegmentGetData(sb, seg, &segdata, &segdata_len);
    if (segdata && segdata_len &&
        segdata_len == rawdata_len &&
        memcmp(segdata, rawdata, segdata_len) == 0)
    {
        return 1;
    }
    return 0;
}

int StreamingBufferGetData(const StreamingBuffer *sb,
        const uint8_t **data, uint32_t *data_len,
        uint64_t *stream_offset)
{
    if (sb != NULL && sb->buf != NULL) {
        *data = sb->buf;
        *data_len = sb->buf_offset;
        *stream_offset = sb->stream_offset;
        return 1;
    } else {
        *data = NULL;
        *data_len = 0;
        *stream_offset = 0;
        return 0;
    }
}

int StreamingBufferGetDataAtOffset (const StreamingBuffer *sb,
        const uint8_t **data, uint32_t *data_len,
        uint64_t offset)
{
    if (sb != NULL && sb->buf != NULL &&
            offset >= sb->stream_offset &&
            offset < (sb->stream_offset + sb->buf_offset))
    {
        uint32_t skip = offset - sb->stream_offset;
        *data = sb->buf + skip;
        *data_len = sb->buf_offset - skip;
        return 1;
    } else {
        *data = NULL;
        *data_len = 0;
        return 0;
    }
}

/**
 *  \retval 1 data is the same
 *  \retval 0 data is different
 */
int StreamingBufferCompareRawData(const StreamingBuffer *sb,
                                  const uint8_t *rawdata, uint32_t rawdata_len)
{
    const uint8_t *sbdata = NULL;
    uint32_t sbdata_len = 0;
    uint64_t offset = 0;
    StreamingBufferGetData(sb, &sbdata, &sbdata_len, &offset);
    if (offset == 0 &&
        sbdata && sbdata_len &&
        sbdata_len == rawdata_len &&
        memcmp(sbdata, rawdata, sbdata_len) == 0)
    {
        return 1;
    }
    SCLogInfo("sbdata_len %u, offset %u", sbdata_len, (uint)offset);
    PrintRawDataFp(stdout, sbdata,sbdata_len);
    return 0;
}

void Dump(StreamingBuffer *sb)
{
    PrintRawDataFp(stdout, sb->buf, sb->buf_offset);
}

void DumpSegment(StreamingBuffer *sb, StreamingBufferSegment *seg)
{
    const uint8_t *data = NULL;
    uint32_t data_len = 0;
    StreamingBufferSegmentGetData(sb, seg, &data, &data_len);
    if (data && data_len) {
        PrintRawDataFp(stdout, data, data_len);
    }
}

#ifdef UNITTESTS
static int StreamingBufferTest01(void)
{
    StreamingBufferConfig cfg = { STREAMING_BUFFER_AUTOSLIDE, 8, 16, NULL, NULL, NULL, NULL };
    StreamingBuffer *sb = StreamingBufferInit(&cfg);
    FAIL_IF(sb == NULL);

    StreamingBufferSegment *seg1 = StreamingBufferAppendRaw(sb, (const uint8_t *)"ABCDEFGH", 8);
    StreamingBufferSegment *seg2 = StreamingBufferAppendRaw(sb, (const uint8_t *)"01234567", 8);
    FAIL_IF(sb->stream_offset != 0);
    FAIL_IF(sb->buf_offset != 16);
    FAIL_IF(seg1->stream_offset != 0);
    FAIL_IF(seg2->stream_offset != 8);
    FAIL_IF(StreamingBufferSegmentIsBeforeWindow(sb,seg1));
    FAIL_IF(StreamingBufferSegmentIsBeforeWindow(sb,seg2));
    FAIL_IF(!StreamingBufferSegmentCompareRawData(sb,seg1,(const uint8_t *)"ABCDEFGH", 8));
    FAIL_IF(!StreamingBufferSegmentCompareRawData(sb,seg2,(const uint8_t *)"01234567", 8));
    Dump(sb);

    StreamingBufferSegment *seg3 = StreamingBufferAppendRaw(sb, (const uint8_t *)"QWERTY", 6);
    FAIL_IF(sb->stream_offset != 8);
    FAIL_IF(sb->buf_offset != 14);
    FAIL_IF(seg3->stream_offset != 16);
    FAIL_IF(!StreamingBufferSegmentIsBeforeWindow(sb,seg1));
    FAIL_IF(StreamingBufferSegmentIsBeforeWindow(sb,seg2));
    FAIL_IF(StreamingBufferSegmentIsBeforeWindow(sb,seg3));
    FAIL_IF(!StreamingBufferSegmentCompareRawData(sb,seg3,(const uint8_t *)"QWERTY", 6));
    Dump(sb);

    StreamingBufferSegment *seg4 = StreamingBufferAppendRaw(sb, (const uint8_t *)"KLM", 3);
    FAIL_IF(sb->stream_offset != 14);
    FAIL_IF(sb->buf_offset != 11);
    FAIL_IF(seg4->stream_offset != 22);
    FAIL_IF(!StreamingBufferSegmentIsBeforeWindow(sb,seg1));
    FAIL_IF(StreamingBufferSegmentIsBeforeWindow(sb,seg2));
    FAIL_IF(StreamingBufferSegmentIsBeforeWindow(sb,seg3));
    FAIL_IF(StreamingBufferSegmentIsBeforeWindow(sb,seg4));
    FAIL_IF(!StreamingBufferSegmentCompareRawData(sb,seg4,(const uint8_t *)"KLM", 3));
    Dump(sb);

    StreamingBufferSegment *seg5 = StreamingBufferAppendRaw(sb, (const uint8_t *)"!@#$%^&*()_+<>?/,.;:'[]{}-=", 27);
    FAIL_IF(sb->stream_offset != 17);
    FAIL_IF(sb->buf_offset != 35);
    FAIL_IF(seg5->stream_offset != 25);
    FAIL_IF(!StreamingBufferSegmentIsBeforeWindow(sb,seg1));
    FAIL_IF(!StreamingBufferSegmentIsBeforeWindow(sb,seg2));
    FAIL_IF(StreamingBufferSegmentIsBeforeWindow(sb,seg3));
    FAIL_IF(StreamingBufferSegmentIsBeforeWindow(sb,seg4));
    FAIL_IF(StreamingBufferSegmentIsBeforeWindow(sb,seg5));
    FAIL_IF(!StreamingBufferSegmentCompareRawData(sb,seg5,(const uint8_t *)"!@#$%^&*()_+<>?/,.;:'[]{}-=", 27));
    Dump(sb);

    StreamingBufferSegment *seg6 = StreamingBufferAppendRaw(sb, (const uint8_t *)"UVWXYZ", 6);
    FAIL_IF(sb->stream_offset != 17);
    FAIL_IF(sb->buf_offset != 41);
    FAIL_IF(seg6->stream_offset != 52);
    FAIL_IF(!StreamingBufferSegmentIsBeforeWindow(sb,seg1));
    FAIL_IF(!StreamingBufferSegmentIsBeforeWindow(sb,seg2));
    FAIL_IF(StreamingBufferSegmentIsBeforeWindow(sb,seg3));
    FAIL_IF(StreamingBufferSegmentIsBeforeWindow(sb,seg4));
    FAIL_IF(StreamingBufferSegmentIsBeforeWindow(sb,seg5));
    FAIL_IF(StreamingBufferSegmentIsBeforeWindow(sb,seg6));
    FAIL_IF(!StreamingBufferSegmentCompareRawData(sb,seg6,(const uint8_t *)"UVWXYZ", 6));
    Dump(sb);

    SCFree(seg1);
    SCFree(seg2);
    SCFree(seg3);
    SCFree(seg4);
    SCFree(seg5);
    SCFree(seg6);
    StreamingBufferFree(sb);
    PASS;
}

static int StreamingBufferTest02(void)
{
    StreamingBufferConfig cfg = { 0, 8, 24, NULL, NULL, NULL, NULL };
    StreamingBuffer *sb = StreamingBufferInit(&cfg);
    FAIL_IF(sb == NULL);

    StreamingBufferSegment seg1;
    FAIL_IF(StreamingBufferAppend(sb, &seg1, (const uint8_t *)"ABCDEFGH", 8) != 0);
    StreamingBufferSegment seg2;
    FAIL_IF(StreamingBufferAppend(sb, &seg2, (const uint8_t *)"01234567", 8) != 0);
    FAIL_IF(sb->stream_offset != 0);
    FAIL_IF(sb->buf_offset != 16);
    FAIL_IF(seg1.stream_offset != 0);
    FAIL_IF(seg2.stream_offset != 8);
    FAIL_IF(StreamingBufferSegmentIsBeforeWindow(sb,&seg1));
    FAIL_IF(StreamingBufferSegmentIsBeforeWindow(sb,&seg2));
    Dump(sb);
    DumpSegment(sb, &seg1);
    DumpSegment(sb, &seg2);

    StreamingBufferSlide(sb, 6);

    StreamingBufferSegment seg3;
    FAIL_IF(StreamingBufferAppend(sb, &seg3, (const uint8_t *)"QWERTY", 6) != 0);
    FAIL_IF(sb->stream_offset != 6);
    FAIL_IF(sb->buf_offset != 16);
    FAIL_IF(seg3.stream_offset != 16);
    FAIL_IF(StreamingBufferSegmentIsBeforeWindow(sb,&seg1));
    FAIL_IF(StreamingBufferSegmentIsBeforeWindow(sb,&seg2));
    FAIL_IF(StreamingBufferSegmentIsBeforeWindow(sb,&seg3));
    Dump(sb);
    DumpSegment(sb, &seg1);
    DumpSegment(sb, &seg2);
    DumpSegment(sb, &seg3);

    StreamingBufferSlide(sb, 6);
    FAIL_IF(!StreamingBufferSegmentIsBeforeWindow(sb,&seg1));
    FAIL_IF(StreamingBufferSegmentIsBeforeWindow(sb,&seg2));
    FAIL_IF(StreamingBufferSegmentIsBeforeWindow(sb,&seg3));
    Dump(sb);
    DumpSegment(sb, &seg1);
    DumpSegment(sb, &seg2);
    DumpSegment(sb, &seg3);

    StreamingBufferFree(sb);
    PASS;
}

static int StreamingBufferTest03(void)
{
    StreamingBufferConfig cfg = { 0, 8, 24, NULL, NULL, NULL, NULL };
    StreamingBuffer *sb = StreamingBufferInit(&cfg);
    FAIL_IF(sb == NULL);

    StreamingBufferSegment seg1;
    FAIL_IF(StreamingBufferAppend(sb, &seg1, (const uint8_t *)"ABCDEFGH", 8) != 0);
    StreamingBufferSegment seg2;
    FAIL_IF(StreamingBufferInsertAt(sb, &seg2, (const uint8_t *)"01234567", 8, 14) != 0);
    FAIL_IF(sb->stream_offset != 0);
    FAIL_IF(sb->buf_offset != 22);
    FAIL_IF(seg1.stream_offset != 0);
    FAIL_IF(seg2.stream_offset != 14);
    FAIL_IF(StreamingBufferSegmentIsBeforeWindow(sb,&seg1));
    FAIL_IF(StreamingBufferSegmentIsBeforeWindow(sb,&seg2));
    Dump(sb);
    DumpSegment(sb, &seg1);
    DumpSegment(sb, &seg2);

    StreamingBufferSegment seg3;
    FAIL_IF(StreamingBufferInsertAt(sb, &seg3, (const uint8_t *)"QWERTY", 6, 8) != 0);
    FAIL_IF(sb->stream_offset != 0);
    FAIL_IF(sb->buf_offset != 22);
    FAIL_IF(seg3.stream_offset != 8);
    FAIL_IF(StreamingBufferSegmentIsBeforeWindow(sb,&seg1));
    FAIL_IF(StreamingBufferSegmentIsBeforeWindow(sb,&seg2));
    FAIL_IF(StreamingBufferSegmentIsBeforeWindow(sb,&seg3));
    Dump(sb);
    DumpSegment(sb, &seg1);
    DumpSegment(sb, &seg2);
    DumpSegment(sb, &seg3);

    StreamingBufferSlide(sb, 10);
    FAIL_IF(!StreamingBufferSegmentIsBeforeWindow(sb,&seg1));
    FAIL_IF(StreamingBufferSegmentIsBeforeWindow(sb,&seg2));
    FAIL_IF(StreamingBufferSegmentIsBeforeWindow(sb,&seg3));
    Dump(sb);
    DumpSegment(sb, &seg1);
    DumpSegment(sb, &seg2);
    DumpSegment(sb, &seg3);

    StreamingBufferFree(sb);
    PASS;
}

static int StreamingBufferTest04(void)
{
    StreamingBufferConfig cfg = { 0, 8, 16, NULL, NULL, NULL, NULL };
    StreamingBuffer *sb = StreamingBufferInit(&cfg);
    FAIL_IF(sb == NULL);

    StreamingBufferSegment seg1;
    FAIL_IF(StreamingBufferAppend(sb, &seg1, (const uint8_t *)"ABCDEFGH", 8) != 0);
    StreamingBufferSegment seg2;
    FAIL_IF(StreamingBufferInsertAt(sb, &seg2, (const uint8_t *)"01234567", 8, 14) != 0);
    FAIL_IF(sb->stream_offset != 0);
    FAIL_IF(sb->buf_offset != 22);
    FAIL_IF(seg1.stream_offset != 0);
    FAIL_IF(seg2.stream_offset != 14);
    FAIL_IF(StreamingBufferSegmentIsBeforeWindow(sb,&seg1));
    FAIL_IF(StreamingBufferSegmentIsBeforeWindow(sb,&seg2));
    Dump(sb);
    DumpSegment(sb, &seg1);
    DumpSegment(sb, &seg2);

    StreamingBufferSegment seg3;
    FAIL_IF(StreamingBufferInsertAt(sb, &seg3, (const uint8_t *)"QWERTY", 6, 8) != 0);
    FAIL_IF(sb->stream_offset != 0);
    FAIL_IF(sb->buf_offset != 22);
    FAIL_IF(seg3.stream_offset != 8);
    FAIL_IF(StreamingBufferSegmentIsBeforeWindow(sb,&seg1));
    FAIL_IF(StreamingBufferSegmentIsBeforeWindow(sb,&seg2));
    FAIL_IF(StreamingBufferSegmentIsBeforeWindow(sb,&seg3));
    Dump(sb);
    DumpSegment(sb, &seg1);
    DumpSegment(sb, &seg2);
    DumpSegment(sb, &seg3);

    /* far ahead of curve: */
    StreamingBufferSegment seg4;
    FAIL_IF(StreamingBufferInsertAt(sb, &seg4, (const uint8_t *)"XYZ", 3, 124) != 0);
    FAIL_IF(sb->stream_offset != 0);
    FAIL_IF(sb->buf_offset != 127);
    FAIL_IF(sb->buf_size != 128);
    FAIL_IF(seg4.stream_offset != 124);
    FAIL_IF(StreamingBufferSegmentIsBeforeWindow(sb,&seg1));
    FAIL_IF(StreamingBufferSegmentIsBeforeWindow(sb,&seg2));
    FAIL_IF(StreamingBufferSegmentIsBeforeWindow(sb,&seg3));
    FAIL_IF(StreamingBufferSegmentIsBeforeWindow(sb,&seg4));
    Dump(sb);
    DumpSegment(sb, &seg1);
    DumpSegment(sb, &seg2);
    DumpSegment(sb, &seg3);
    DumpSegment(sb, &seg4);

    FAIL_IF(!StreamingBufferSegmentCompareRawData(sb,&seg1,(const uint8_t *)"ABCDEFGH", 8));
    FAIL_IF(!StreamingBufferSegmentCompareRawData(sb,&seg2,(const uint8_t *)"01234567", 8));
    FAIL_IF(!StreamingBufferSegmentCompareRawData(sb,&seg3,(const uint8_t *)"QWERTY", 6));
    FAIL_IF(!StreamingBufferSegmentCompareRawData(sb,&seg4,(const uint8_t *)"XYZ", 3));

    StreamingBufferFree(sb);
    PASS;
}

static int StreamingBufferTest05(void)
{
    StreamingBufferConfig cfg = { STREAMING_BUFFER_AUTOSLIDE, 8, 32, NULL, NULL, NULL, NULL };
    StreamingBuffer sb = STREAMING_BUFFER_INITIALIZER(&cfg);

    StreamingBufferSegment *seg1 = StreamingBufferAppendRaw(&sb, (const uint8_t *)"AAAAAAAA", 8);
    StreamingBufferSegment *seg2 = StreamingBufferAppendRaw(&sb, (const uint8_t *)"BBBBBBBB", 8);
    StreamingBufferSegment *seg3 = StreamingBufferAppendRaw(&sb, (const uint8_t *)"CCCCCCCC", 8);
    StreamingBufferSegment *seg4 = StreamingBufferAppendRaw(&sb, (const uint8_t *)"DDDDDDDD", 8);
    FAIL_IF(sb.stream_offset != 0);
    FAIL_IF(sb.buf_offset != 32);
    FAIL_IF(seg1->stream_offset != 0);
    FAIL_IF(seg2->stream_offset != 8);
    FAIL_IF(seg3->stream_offset != 16);
    FAIL_IF(seg4->stream_offset != 24);
    FAIL_IF(StreamingBufferSegmentIsBeforeWindow(&sb,seg1));
    FAIL_IF(StreamingBufferSegmentIsBeforeWindow(&sb,seg2));
    FAIL_IF(StreamingBufferSegmentIsBeforeWindow(&sb,seg3));
    FAIL_IF(StreamingBufferSegmentIsBeforeWindow(&sb,seg4));
    FAIL_IF(!StreamingBufferSegmentCompareRawData(&sb,seg1,(const uint8_t *)"AAAAAAAA", 8));
    FAIL_IF(!StreamingBufferSegmentCompareRawData(&sb,seg2,(const uint8_t *)"BBBBBBBB", 8));
    FAIL_IF(!StreamingBufferSegmentCompareRawData(&sb,seg3,(const uint8_t *)"CCCCCCCC", 8));
    FAIL_IF(!StreamingBufferSegmentCompareRawData(&sb,seg4,(const uint8_t *)"DDDDDDDD", 8));
    Dump(&sb);
    StreamingBufferSegment *seg5 = StreamingBufferAppendRaw(&sb, (const uint8_t *)"EEEEEEEE", 8);
    FAIL_IF(!StreamingBufferSegmentCompareRawData(&sb,seg5,(const uint8_t *)"EEEEEEEE", 8));
    Dump(&sb);

    SCFree(seg1);
    SCFree(seg2);
    SCFree(seg3);
    SCFree(seg4);
    SCFree(seg5);
    StreamingBufferClear(&sb);
    PASS;
}
#endif

void StreamingBufferRegisterTests(void)
{
#ifdef UNITTESTS
    UtRegisterTest("StreamingBufferTest01", StreamingBufferTest01);
    UtRegisterTest("StreamingBufferTest02", StreamingBufferTest02);
    UtRegisterTest("StreamingBufferTest03", StreamingBufferTest03);
    UtRegisterTest("StreamingBufferTest04", StreamingBufferTest04);
    UtRegisterTest("StreamingBufferTest05", StreamingBufferTest05);
#endif
}
