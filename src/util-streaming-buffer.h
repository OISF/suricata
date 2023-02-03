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

/*
 * This API is meant to be used with streaming data. A single memory
 * block is used to store the data. StreamingBufferSegment points to
 * chunk of data in the single StreamingBuffer. It points by offset
 * and length, so no pointers. The buffer is resized on demand and
 * slides forward, either automatically or manually.
 *
 * When a segment needs it's data it uses StreamingBufferSegmentGetData
 * which takes care of checking if the segment still has a valid offset
 * and length.
 *
 * The StreamingBuffer::stream_offset is an absolute offset since the
 * start of the data streaming.
 *
 * Similarly, StreamingBufferSegment::stream_offset is also an absolute
 * offset.
 *
 * Using the segments is optional.
 *
 *
 * stream_offset            buf_offset          stream_offset + buf_size
 * ^                        ^                   ^
 * |                        |                   |
 * |                        |                   |
 * +--------------------------------------------+
 * |         data           |     empty         |
 * |      xxxxxxxxxx        |                   |
 * +------^--------^--------+-------------------+
 *        |        |
 *        |        |
 *        |        |
 *        |        |
 *        |        |
 * +------+--------+-------+
 * | StreamingBufferSegment|
 * +-----------+-----------+
 * | offset    | len       |
 * +-----------+-----------+
 */


#ifndef __UTIL_STREAMING_BUFFER_H__
#define __UTIL_STREAMING_BUFFER_H__

#include "tree.h"

#define STREAMING_BUFFER_REGION_GAP_DEFAULT 262144

typedef struct StreamingBufferConfig_ {
    uint32_t buf_size;
    uint16_t max_regions; /**< max concurrent memory regions. 0 means no limit. */
    uint32_t region_gap;  /**< max gap size before a new region will be created. */
    void *(*Calloc)(size_t n, size_t size);
    void *(*Realloc)(void *ptr, size_t orig_size, size_t size);
    void (*Free)(void *ptr, size_t size);
} StreamingBufferConfig;

#define STREAMING_BUFFER_CONFIG_INITIALIZER                                                        \
    {                                                                                              \
        2048, 8, STREAMING_BUFFER_REGION_GAP_DEFAULT, NULL, NULL, NULL,                            \
    }

#define STREAMING_BUFFER_REGION_INIT                                                               \
    {                                                                                              \
        NULL, 0, 0, 0ULL, NULL,                                                                    \
    }

typedef struct StreamingBufferRegion_ {
    uint8_t *buf;           /**< memory block for reassembly */
    uint32_t buf_size;      /**< size of memory block */
    uint32_t buf_offset;    /**< how far we are in buf_size */
    uint64_t stream_offset; /**< stream offset of this region */
    struct StreamingBufferRegion_ *next;
} StreamingBufferRegion;

/**
 *  \brief block of continues data
 */
typedef struct StreamingBufferBlock {
    uint64_t offset;
    RB_ENTRY(StreamingBufferBlock) rb;
    uint32_t len;
} __attribute__((__packed__)) StreamingBufferBlock;

int SBBCompare(struct StreamingBufferBlock *a, struct StreamingBufferBlock *b);

/* red-black tree prototype for SACK records */
RB_HEAD(SBB, StreamingBufferBlock);
RB_PROTOTYPE(SBB, StreamingBufferBlock, rb, SBBCompare);
StreamingBufferBlock *SBB_RB_FIND_INCLUSIVE(struct SBB *head, StreamingBufferBlock *elm);

typedef struct StreamingBuffer_ {
    StreamingBufferRegion region;
    struct SBB sbb_tree;    /**< red black tree of Stream Buffer Blocks */
    StreamingBufferBlock *head; /**< head, should always be the same as RB_MIN */
    uint32_t sbb_size;          /**< data size covered by sbbs */
    uint16_t regions;
    uint16_t max_regions;
#ifdef DEBUG
    uint32_t buf_size_max;
#endif
} StreamingBuffer;

static inline bool StreamingBufferHasData(const StreamingBuffer *sb)
{
    return (sb->region.stream_offset || sb->region.buf_offset || sb->region.next != NULL ||
            !RB_EMPTY(&sb->sbb_tree));
}

static inline uint64_t StreamingBufferGetConsecutiveDataRightEdge(const StreamingBuffer *sb)
{
    return sb->region.stream_offset + sb->region.buf_offset;
}

static inline uint64_t StreamingBufferGetOffset(const StreamingBuffer *sb)
{
    return sb->region.stream_offset;
}

#ifndef DEBUG
#define STREAMING_BUFFER_INITIALIZER                                                               \
    {                                                                                              \
        STREAMING_BUFFER_REGION_INIT,                                                              \
        { NULL },                                                                                  \
        NULL,                                                                                      \
        0,                                                                                         \
        1,                                                                                         \
        1,                                                                                         \
    };
#else
#define STREAMING_BUFFER_INITIALIZER { STREAMING_BUFFER_REGION_INIT, { NULL }, NULL, 0, 1, 1, 0 };
#endif

typedef struct StreamingBufferSegment_ {
    uint32_t segment_len;
    uint64_t stream_offset;
} __attribute__((__packed__)) StreamingBufferSegment;

StreamingBuffer *StreamingBufferInit(const StreamingBufferConfig *cfg);
void StreamingBufferClear(StreamingBuffer *sb, const StreamingBufferConfig *cfg);
void StreamingBufferFree(StreamingBuffer *sb, const StreamingBufferConfig *cfg);

void StreamingBufferSlideToOffset(
        StreamingBuffer *sb, const StreamingBufferConfig *cfg, uint64_t offset);

int StreamingBufferAppend(StreamingBuffer *sb, const StreamingBufferConfig *cfg,
        StreamingBufferSegment *seg, const uint8_t *data, uint32_t data_len) WARN_UNUSED;
int StreamingBufferAppendNoTrack(StreamingBuffer *sb, const StreamingBufferConfig *cfg,
        const uint8_t *data, uint32_t data_len) WARN_UNUSED;
int StreamingBufferInsertAt(StreamingBuffer *sb, const StreamingBufferConfig *cfg,
        StreamingBufferSegment *seg, const uint8_t *data, uint32_t data_len,
        uint64_t offset) WARN_UNUSED;

void StreamingBufferSegmentGetData(const StreamingBuffer *sb,
                                   const StreamingBufferSegment *seg,
                                   const uint8_t **data, uint32_t *data_len);

void StreamingBufferSBBGetData(const StreamingBuffer *sb,
                               const StreamingBufferBlock *sbb,
                               const uint8_t **data, uint32_t *data_len);

void StreamingBufferSBBGetDataAtOffset(const StreamingBuffer *sb,
                                       const StreamingBufferBlock *sbb,
                                       const uint8_t **data, uint32_t *data_len,
                                       uint64_t offset);

int StreamingBufferSegmentCompareRawData(const StreamingBuffer *sb,
                                         const StreamingBufferSegment *seg,
                                         const uint8_t *rawdata, uint32_t rawdata_len);
int StreamingBufferCompareRawData(const StreamingBuffer *sb,
                                  const uint8_t *rawdata, uint32_t rawdata_len);

int StreamingBufferGetData(const StreamingBuffer *sb,
        const uint8_t **data, uint32_t *data_len,
        uint64_t *stream_offset);

int StreamingBufferGetDataAtOffset (const StreamingBuffer *sb,
        const uint8_t **data, uint32_t *data_len,
        uint64_t offset);

int StreamingBufferSegmentIsBeforeWindow(const StreamingBuffer *sb,
                                         const StreamingBufferSegment *seg);

void StreamingBufferRegisterTests(void);

#endif /* __UTIL_STREAMING_BUFFER_H__ */
