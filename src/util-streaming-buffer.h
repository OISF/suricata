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

#define STREAMING_BUFFER_NOFLAGS     0
#define STREAMING_BUFFER_AUTOSLIDE  (1<<0)

typedef struct StreamingBufferConfig_ {
    uint32_t flags;
    uint32_t buf_slide;
    uint32_t buf_size;
    void *(*Malloc)(size_t size);
    void *(*Calloc)(size_t n, size_t size);
    void *(*Realloc)(void *ptr, size_t orig_size, size_t size);
    void (*Free)(void *ptr, size_t size);
} StreamingBufferConfig;

#define STREAMING_BUFFER_CONFIG_INITIALIZER { 0, 0, 0, NULL, NULL, NULL, NULL, }

/**
 *  \brief block of continues data
 */
typedef struct StreamingBufferBlock_ {
    uint64_t offset;
    uint32_t len;
    struct StreamingBufferBlock_ *next;
} StreamingBufferBlock;

typedef struct StreamingBuffer_ {
    const StreamingBufferConfig *cfg;
    uint64_t stream_offset; /**< offset of the start of the memory block */

    uint8_t *buf;           /**< memory block for reassembly */
    uint32_t buf_size;      /**< size of memory block */
    uint32_t buf_offset;    /**< how far we are in buf_size */

    StreamingBufferBlock *block_list;
    StreamingBufferBlock *block_list_tail;
#ifdef DEBUG
    uint32_t buf_size_max;
#endif
} StreamingBuffer;

#ifndef DEBUG
#define STREAMING_BUFFER_INITIALIZER(cfg) { (cfg), 0, NULL, 0, 0, NULL, NULL};
#else
#define STREAMING_BUFFER_INITIALIZER(cfg) { (cfg), 0, NULL, 0, 0, NULL, NULL, 0 };
#endif

typedef struct StreamingBufferSegment_ {
    uint64_t stream_offset;
    uint32_t segment_len;
} __attribute__((__packed__)) StreamingBufferSegment;

StreamingBuffer *StreamingBufferInit(const StreamingBufferConfig *cfg);
void StreamingBufferClear(StreamingBuffer *sb);
void StreamingBufferFree(StreamingBuffer *sb);

void StreamingBufferSlide(StreamingBuffer *sb, uint32_t slide);
void StreamingBufferSlideToOffset(StreamingBuffer *sb, uint64_t offset);

StreamingBufferSegment *StreamingBufferAppendRaw(StreamingBuffer *sb,
        const uint8_t *data, uint32_t data_len) __attribute__((warn_unused_result));
int StreamingBufferAppend(StreamingBuffer *sb, StreamingBufferSegment *seg,
        const uint8_t *data, uint32_t data_len) __attribute__((warn_unused_result));
int StreamingBufferAppendNoTrack(StreamingBuffer *sb,
        const uint8_t *data, uint32_t data_len) __attribute__((warn_unused_result));
int StreamingBufferInsertAt(StreamingBuffer *sb, StreamingBufferSegment *seg,
                             const uint8_t *data, uint32_t data_len,
                             uint64_t offset) __attribute__((warn_unused_result));

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
