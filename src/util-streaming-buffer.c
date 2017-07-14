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

static void SBBFree(StreamingBuffer *sb);

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

        SBBFree(sb);
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

#ifdef DEBUG
static void SBBPrintList(const StreamingBuffer *sb)
{
    const StreamingBufferBlock *sbb = sb->block_list;
    while (sbb) {
        SCLogDebug("sbb: offset %"PRIu64", len %u", sbb->offset, sbb->len);
        if (sbb->next) {
            if ((sbb->offset + sbb->len) != sbb->next->offset) {
                SCLogDebug("gap: offset %"PRIu64", len %"PRIu64, (sbb->offset + sbb->len),
                        sbb->next->offset - (sbb->offset + sbb->len));
            }
        }

        sbb = sbb->next;
    }
}
#endif

/* setup with gap between 2 blocks
 *
 * [block][gap][block]
 **/
static void SBBInit(StreamingBuffer *sb,
                    uint32_t rel_offset, uint32_t data_len)
{
    BUG_ON(sb->block_list != NULL);
    BUG_ON(sb->buf_offset > sb->stream_offset + rel_offset);

    /* need to set up 2: existing data block and new data block */
    StreamingBufferBlock *sbb = CALLOC(sb->cfg, 1, sizeof(*sbb));
    if (sbb == NULL) {
        return;
    }
    sbb->offset = sb->stream_offset;
    sbb->len = sb->buf_offset;

    StreamingBufferBlock *sbb2 = CALLOC(sb->cfg, 1, sizeof(*sbb2));
    if (sbb2 == NULL) {
        FREE(sb->cfg, sbb, sizeof(*sbb));
        return;
    }
    sbb2->offset = sb->stream_offset + rel_offset;
    sbb2->len = data_len;

    sb->block_list = sbb;
    sbb->next = sbb2;
    sb->block_list_tail = sbb2;

    SCLogDebug("sbb1 %"PRIu64", len %u, sbb2 %"PRIu64", len %u",
            sbb->offset, sbb->len, sbb2->offset, sbb2->len);
#ifdef DEBUG
    SBBPrintList(sb);
#endif
    BUG_ON(sbb2->offset < sbb->len);
}

/* setup with leading gap
 *
 * [gap][block]
 **/
static void SBBInitLeadingGap(StreamingBuffer *sb,
                              uint64_t offset, uint32_t data_len)
{
    BUG_ON(sb->block_list != NULL);

    StreamingBufferBlock *sbb = CALLOC(sb->cfg, 1, sizeof(*sbb));
    if (sbb == NULL)
        return;
    sbb->offset = offset;
    sbb->len = data_len;

    sb->block_list = sbb;
    sb->block_list_tail = sbb;

    SCLogDebug("sbb %"PRIu64", len %u",
            sbb->offset, sbb->len);
#ifdef DEBUG
    SBBPrintList(sb);
#endif
}

static int IsBefore(StreamingBufferBlock *me, StreamingBufferBlock *you)
{
    if ((me->offset + me->len) < you->offset) {
        return 1;
    }
    return 0;
}

static int StartsBefore(StreamingBufferBlock *me, StreamingBufferBlock *you)
{
    if (me->offset < you->offset)
        return 1;
    return 0;
}

static int IsAfter(StreamingBufferBlock *me, StreamingBufferBlock *you)
{
    if (you->offset + you->len < me->offset)
        return 1;
    return 0;
}

static int IsOverlappedBy(StreamingBufferBlock *me, StreamingBufferBlock *you)
{
    if (you->offset <= me->offset && (you->offset + you->len) >= (me->offset + me->len))
        return 1;
    return 0;
}

static int EndsAfter(StreamingBufferBlock *me, StreamingBufferBlock *you)
{
    if ((me->offset + me->len) > (you->offset + you->len))
        return 1;
    return 0;
}

static StreamingBufferBlock *GetNew(StreamingBuffer *sb,
                                    uint64_t offset, uint32_t len,
                                    StreamingBufferBlock *next)
{
    StreamingBufferBlock *new_sbb = CALLOC(sb->cfg, 1, sizeof(*new_sbb));
    if (new_sbb == NULL)
        return NULL;
    new_sbb->offset = offset;
    new_sbb->len = len;
    new_sbb->next = next;
    return new_sbb;
}

/* expand our sbb forward if possible */
static int SBBUpdateLookForward(StreamingBuffer *sb,
                                StreamingBufferBlock *sbb,
                                StreamingBufferBlock *my_block)
{
    SCLogDebug("EndsAfter: consider next");

    while (sbb->offset + sbb->len == sbb->next->offset)
    {
        SCLogDebug("EndsAfter: gobble up next: %"PRIu64"/%u", sbb->next->offset, sbb->next->len);
        uint64_t right_edge = sbb->next->offset + sbb->next->len;
        uint32_t expand_by = right_edge - (sbb->offset + sbb->len);
        sbb->len += expand_by;
        SCLogDebug("EndsAfter: expand_by %u (part 2)", expand_by);
        SCLogDebug("EndsAfter: (loop) sbb now %"PRIu64"/%u", sbb->offset, sbb->len);

        /* we can gobble up next */
        StreamingBufferBlock *to_free = sbb->next;
        sbb->next = sbb->next->next;
        FREE(sb->cfg, to_free, sizeof(StreamingBufferBlock));
        if (sbb->next == NULL)
            sb->block_list_tail = sbb;

        /* update my block */
        if (expand_by >= my_block->len) {
            return 1;
        }

        my_block->len -= expand_by;
        my_block->offset += expand_by;

        if (sbb->next == NULL) {
            /* if we have nothing left in the list we're almost done,
             * except we need to check if we have some of our block
             * left */
            sbb->len += my_block->len;
            my_block->offset += my_block->len;
            my_block->len = 0;
            return 1;
        } else {
            /* if next is not directly connected and we have some
             * block len left, expand sbb further */
            uint32_t gap = sbb->next->offset - (sbb->offset + sbb->len);
            SCLogDebug("EndsAfter: we now have a gap of %u and a block of %"PRIu64"/%u", gap, my_block->offset, my_block->len);

            if (my_block->len < gap) {
                sbb->len += my_block->len;
                my_block->offset += my_block->len;
                my_block->len = 0;
                return 1;
            } else {
                sbb->len += gap;
                my_block->offset += gap;
                my_block->len -= gap;
                SCLogDebug("EndsAfter: (loop) block at %"PRIu64"/%u, sbb %"PRIu64"/%u", my_block->offset, my_block->len, sbb->offset, sbb->len);
                SCLogDebug("EndsAfter: (loop) sbb->next %"PRIu64"/%u", sbb->next->offset, sbb->next->len);
            }
        }
    }
    return 0;
}

static void SBBUpdate(StreamingBuffer *sb,
                      uint32_t rel_offset, uint32_t data_len)
{
    StreamingBufferBlock my_block = { .offset = sb->stream_offset + rel_offset,
                                      .len = data_len,
                                      .next = NULL  };
    const uint64_t my_block_right_edge = my_block.offset + my_block.len;

    StreamingBufferBlock *tail = sb->block_list_tail;

    /* fast path 1: expands tail */
    if (tail && ((tail->offset + tail->len) == my_block.offset))
    {
        tail->len = my_block_right_edge - tail->offset;
        goto done;
    }
    /* fast path 2: new isolated block after tail */
    else if (tail && IsAfter(&my_block, tail)) {
        StreamingBufferBlock *new_sbb = GetNew(sb, my_block.offset, my_block.len, NULL);
        sb->block_list_tail = tail->next = new_sbb;
        SCLogDebug("tail: new block at %"PRIu64"/%u", my_block.offset, my_block.len);
        goto done;
    }

    BUG_ON(sb->block_list == NULL);
#ifdef DEBUG
    SBBPrintList(sb);
#endif
    SCLogDebug("PreInsert: block at %"PRIu64"/%u", my_block.offset, my_block.len);
    StreamingBufferBlock *sbb = sb->block_list, *prev = NULL;
    while (sbb) {
        SCLogDebug("sbb %"PRIu64"/%u data %"PRIu64"/%u. Next %s", sbb->offset, sbb->len,
                my_block.offset, my_block.len, sbb->next ? "true" : "false");

        if (IsBefore(&my_block, sbb)) {
            StreamingBufferBlock *new_sbb = GetNew(sb, my_block.offset, my_block.len, sbb);

            /* place before, maybe replace list head */
            if (sbb == sb->block_list) {
                sb->block_list = new_sbb;
            } else {
                prev->next = new_sbb;
            }
            SCLogDebug("IsBefore: new block at %"PRIu64"/%u", my_block.offset, my_block.len);
            break;

        } else if (IsOverlappedBy(&my_block, sbb)) {
            /* nothing to do */
            SCLogDebug("IsOverlappedBy: overlapped block at %"PRIu64"/%u", my_block.offset, my_block.len);
            break;

        } else if (IsAfter(&my_block, sbb)) {

            /* if no next, place after, otherwise, iterate */
            if (sbb->next == NULL) {
                StreamingBufferBlock *new_sbb = GetNew(sb, my_block.offset, my_block.len, NULL);
                sbb->next = new_sbb;
                sb->block_list_tail = new_sbb;
                SCLogDebug("new block at %"PRIu64"/%u", my_block.offset, my_block.len);
                break;
            }
            SCLogDebug("IsAfter: block at %"PRIu64"/%u, is after sbb", my_block.offset, my_block.len);

        } else {

            /* those were the simple cases */

            if (StartsBefore(&my_block, sbb)) {
                /* expand sbb */
                uint32_t expand_by = sbb->offset - my_block.offset;
                SCLogDebug("StartsBefore: expand_by %u", expand_by);
                sbb->offset = my_block.offset;
                sbb->len += expand_by;

                /* if my_block ends before sbb right edge, we are done */
                if (my_block_right_edge <= (sbb->offset + sbb->len))
                    break;

                my_block.offset = sbb->offset + sbb->len;
                my_block.len = my_block_right_edge - my_block.offset;
                SCLogDebug("StartsBefore: block now %"PRIu64"/%u", my_block.offset, my_block.len);

                if (sbb->next == NULL) {
                    sbb->len += my_block.len;
                    break;
                }
                /* expand, but consider next */
                uint64_t right_edge = my_block_right_edge;
                if (right_edge > sbb->next->offset) {
                    right_edge = sbb->next->offset;
                }

                expand_by = right_edge - (sbb->offset + sbb->len);
                SCLogDebug("EndsAfter: expand_by %u", expand_by);
                sbb->len += expand_by;
                SCLogDebug("EndsAfter: sbb now %"PRIu64"/%u", sbb->offset, sbb->len);

                my_block.offset = sbb->offset + sbb->len;
                my_block.len = my_block_right_edge - my_block.offset;
                SCLogDebug("StartsBefore: sbb now %"PRIu64"/%u", sbb->offset, sbb->len);

            } else if (EndsAfter(&my_block, sbb)) {
                /* expand sbb, but we need to mind "next" */

                if (sbb->next == NULL) {
                    /* last, so just expand sbb */
                    sbb->len = my_block_right_edge - sbb->offset;
                    break;
                }

                /* expand, but consider next */
                uint64_t right_edge = my_block_right_edge;
                if (right_edge > sbb->next->offset) {
                    right_edge = sbb->next->offset;
                }

                uint32_t expand_by = right_edge - (sbb->offset + sbb->len);
                SCLogDebug("EndsAfter: expand_by %u", expand_by);
                sbb->len += expand_by;
                SCLogDebug("EndsAfter: sbb now %"PRIu64"/%u", sbb->offset, sbb->len);

                my_block.offset = sbb->offset + sbb->len;
                my_block.len = my_block_right_edge - my_block.offset;
            }

            if (sbb->next != NULL) {
                SCLogDebug("EndsAfter: consider next");

                if (SBBUpdateLookForward(sb, sbb, &my_block) == 1)
                    goto done;
            }

            SCLogDebug("EndsAfter: block at %"PRIu64"/%u, is after sbb", my_block.offset, my_block.len);

            if (my_block.len == 0)
                break;
        }
        prev = sbb;
        sbb = sbb->next;
    }
done:
    SCLogDebug("PostInsert: block at %"PRIu64"/%u", my_block.offset, my_block.len);
    SCLogDebug("PostInsert");
#ifdef DEBUG
    SBBPrintList(sb);
#endif
}

static void SBBFree(StreamingBuffer *sb)
{
    StreamingBufferBlock *sbb = sb->block_list;
    while (sbb) {
        StreamingBufferBlock *next = sbb->next;
        FREE(sb->cfg, sbb, sizeof(StreamingBufferBlock));
        sbb = next;
    }
    sb->block_list = NULL;
}

static void SBBPrune(StreamingBuffer *sb)
{
    StreamingBufferBlock *sbb = sb->block_list;
    while (sbb) {
        /* completely beyond window, we're done */
        if (sbb->offset > sb->stream_offset)
            break;

        /* partly before, partly beyond. Adjust */
        if (sbb->offset < sb->stream_offset &&
            sbb->offset + sbb->len > sb->stream_offset) {
            uint32_t shrink_by = sb->stream_offset - sbb->offset;
            BUG_ON(shrink_by > sbb->len);
            sbb->len -=  shrink_by;
            sbb->offset += shrink_by;
            BUG_ON(sbb->offset != sb->stream_offset);
            break;
        }

        StreamingBufferBlock *next = sbb->next;
        FREE(sb->cfg, sbb, sizeof(StreamingBufferBlock));

        sbb = next;
        sb->block_list = next;
        if (sbb && sbb->next == NULL)
            sb->block_list_tail = NULL;
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
    SBBPrune(sb);
}

static int __attribute__((warn_unused_result))
GrowToSize(StreamingBuffer *sb, uint32_t size)
{
    /* try to grow in multiples of sb->cfg->buf_size */
    uint32_t x = sb->cfg->buf_size ? size % sb->cfg->buf_size : 0;
    uint32_t base = size - x;
    uint32_t grow = base + sb->cfg->buf_size;

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

/** \internal
 *  \brief try to double the buffer size
 *  \retval 0 ok
 *  \retval -1 failed, buffer unchanged
 */
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
        SBBPrune(sb);
    }
}

void StreamingBufferSlide(StreamingBuffer *sb, uint32_t slide)
{
    uint32_t size = sb->buf_offset - slide;
    SCLogDebug("sliding %u forward, size of original buffer left after slide %u", slide, size);
    memmove(sb->buf, sb->buf+slide, size);
    sb->stream_offset += slide;
    sb->buf_offset = size;
    SBBPrune(sb);
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
            if (GrowToSize(sb, data_len) != 0)
                return NULL;
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
        uint32_t rel_offset = sb->buf_offset;
        sb->buf_offset += data_len;

        if (sb->block_list) {
            SBBUpdate(sb, rel_offset, data_len);
        }
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
            if (GrowToSize(sb, data_len) != 0)
                return -1;
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
    uint32_t rel_offset = sb->buf_offset;
    sb->buf_offset += data_len;

    if (sb->block_list) {
        SBBUpdate(sb, rel_offset, data_len);
    }
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
            if (GrowToSize(sb, data_len) != 0)
                return -1;
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
    uint32_t rel_offset = sb->buf_offset;
    sb->buf_offset += data_len;

    if (sb->block_list) {
        SBBUpdate(sb, rel_offset, data_len);
    }
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
            if (GrowToSize(sb, (rel_offset + data_len)) != 0)
                return -1;
        }
    }
    if (!DATA_FITS_AT_OFFSET(sb, data_len, rel_offset)) {
        return -1;
    }

    memcpy(sb->buf + rel_offset, data, data_len);
    seg->stream_offset = offset;
    seg->segment_len = data_len;

    SCLogDebug("rel_offset %u sb->stream_offset %"PRIu64", buf_offset %u",
            rel_offset, sb->stream_offset, sb->buf_offset);

    if (sb->block_list == NULL) {
        SCLogDebug("empty sbb list");

        if (sb->stream_offset == offset) {
            SCLogDebug("empty sbb list: block exactly what was expected, fall through");
            /* empty list, data is exactly what is expected (append),
             * so do nothing */
        } else if ((rel_offset + data_len) <= sb->buf_offset) {
            SCLogDebug("empty sbb list: block is within existing region");
        } else {
            if (sb->buf_offset && rel_offset == sb->buf_offset) {
                // nothing to do
            } else if (rel_offset < sb->buf_offset) {
                // nothing to do
            } else if (sb->buf_offset) {
                /* existing data, but there is a gap between us */
                SBBInit(sb, rel_offset, data_len);
            } else {
                /* gap before data in empty list */
                SCLogDebug("empty sbb list: invoking SBBInitLeadingGap");
                SBBInitLeadingGap(sb, offset, data_len);
            }
        }
    } else {
        /* already have blocks, so append new block based on new data */
        SBBUpdate(sb, rel_offset, data_len);
    }

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

/** \brief get the data for one SBB */
void StreamingBufferSBBGetData(const StreamingBuffer *sb,
                               const StreamingBufferBlock *sbb,
                               const uint8_t **data, uint32_t *data_len)
{
    if (sbb->offset >= sb->stream_offset) {
        uint64_t offset = sbb->offset - sb->stream_offset;
        *data = sb->buf + offset;
        if (offset + sbb->len > sb->buf_size)
            *data_len = sb->buf_size - offset;
        else
            *data_len = sbb->len;
        return;
    } else {
        uint64_t offset = sb->stream_offset - sbb->offset;
        if (offset < sbb->len) {
            *data = sb->buf;
            *data_len = sbb->len - offset;
            return;
        }
    }
    *data = NULL;
    *data_len = 0;
    return;
}

/** \brief get the data for one SBB */
void StreamingBufferSBBGetDataAtOffset(const StreamingBuffer *sb,
                                       const StreamingBufferBlock *sbb,
                                       const uint8_t **data, uint32_t *data_len,
                                       uint64_t offset)
{
    if (offset >= sbb->offset && offset < (sbb->offset + sbb->len)) {
        uint32_t sbblen = sbb->len - (offset - sbb->offset);

        if (offset >= sb->stream_offset) {
            uint64_t data_offset = offset - sb->stream_offset;
            *data = sb->buf + data_offset;
            if (data_offset + sbblen > sb->buf_size)
                *data_len = sb->buf_size - data_offset;
            else
                *data_len = sbblen;
            BUG_ON(*data_len > sbblen);
            return;
        } else {
            uint64_t data_offset = sb->stream_offset - sbb->offset;
            if (data_offset < sbblen) {
                *data = sb->buf;
                *data_len = sbblen - data_offset;
                BUG_ON(*data_len > sbblen);
                return;
            }
        }
    }

    *data = NULL;
    *data_len = 0;
    return;
}

void StreamingBufferSegmentGetData(const StreamingBuffer *sb,
                                   const StreamingBufferSegment *seg,
                                   const uint8_t **data, uint32_t *data_len)
{
    if (likely(sb->buf)) {
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
    SCLogDebug("sbdata_len %u, offset %"PRIu64, sbdata_len, offset);
    printf("got:\n");
    PrintRawDataFp(stdout, sbdata,sbdata_len);
    printf("wanted:\n");
    PrintRawDataFp(stdout, rawdata,rawdata_len);
    return 0;
}

#ifdef UNITTESTS
static void Dump(StreamingBuffer *sb)
{
    PrintRawDataFp(stdout, sb->buf, sb->buf_offset);
}

static void DumpSegment(StreamingBuffer *sb, StreamingBufferSegment *seg)
{
    const uint8_t *data = NULL;
    uint32_t data_len = 0;
    StreamingBufferSegmentGetData(sb, seg, &data, &data_len);
    if (data && data_len) {
        PrintRawDataFp(stdout, data, data_len);
    }
}

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
    FAIL_IF(sb->block_list != NULL);
    StreamingBufferSegment seg2;
    FAIL_IF(StreamingBufferInsertAt(sb, &seg2, (const uint8_t *)"01234567", 8, 14) != 0);
    FAIL_IF(sb->stream_offset != 0);
    FAIL_IF(sb->buf_offset != 22);
    FAIL_IF(seg1.stream_offset != 0);
    FAIL_IF(seg2.stream_offset != 14);
    FAIL_IF(StreamingBufferSegmentIsBeforeWindow(sb,&seg1));
    FAIL_IF(StreamingBufferSegmentIsBeforeWindow(sb,&seg2));
    FAIL_IF(sb->block_list == NULL);
    FAIL_IF(sb->block_list->offset != 0);
    FAIL_IF(sb->block_list->len != 8);
    FAIL_IF(sb->block_list->next == NULL);
    FAIL_IF(sb->block_list->next->offset != 14);
    FAIL_IF(sb->block_list->next->len != 8);
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
    FAIL_IF(sb->block_list == NULL);
    FAIL_IF(sb->block_list->offset != 0);
    FAIL_IF(sb->block_list->len != 22);
    FAIL_IF(sb->block_list->next != NULL);
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
    FAIL_IF(sb->block_list == NULL);
    FAIL_IF(sb->block_list->offset != 0);
    FAIL_IF(sb->block_list->len != 22);
    FAIL_IF(sb->block_list->next == NULL);
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

/** \test lots of gaps in block list */
static int StreamingBufferTest06(void)
{
    StreamingBufferConfig cfg = { 0, 8, 16, NULL, NULL, NULL, NULL };
    StreamingBuffer *sb = StreamingBufferInit(&cfg);
    FAIL_IF(sb == NULL);

    StreamingBufferSegment seg1;
    FAIL_IF(StreamingBufferAppend(sb, &seg1, (const uint8_t *)"A", 1) != 0);
    StreamingBufferSegment seg2;
    FAIL_IF(StreamingBufferInsertAt(sb, &seg2, (const uint8_t *)"C", 1, 2) != 0);
    Dump(sb);

    StreamingBufferSegment seg3;
    FAIL_IF(StreamingBufferInsertAt(sb, &seg3, (const uint8_t *)"F", 1, 5) != 0);
    Dump(sb);

    StreamingBufferSegment seg4;
    FAIL_IF(StreamingBufferInsertAt(sb, &seg4, (const uint8_t *)"H", 1, 7) != 0);
    Dump(sb);

    StreamingBufferSegment seg5;
    FAIL_IF(StreamingBufferInsertAt(sb, &seg5, (const uint8_t *)"ABCDEFGHIJ", 10, 0) != 0);
    Dump(sb);
    FAIL_IF(sb->block_list == NULL);
    FAIL_IF(sb->block_list->offset != 0);
    FAIL_IF(sb->block_list->len != 10);
    FAIL_IF(sb->block_list->next != NULL);

    StreamingBufferSegment seg6;
    FAIL_IF(StreamingBufferInsertAt(sb, &seg6, (const uint8_t *)"abcdefghij", 10, 0) != 0);
    Dump(sb);
    FAIL_IF(sb->block_list == NULL);
    FAIL_IF(sb->block_list->offset != 0);
    FAIL_IF(sb->block_list->len != 10);
    FAIL_IF(sb->block_list->next != NULL);

    StreamingBufferFree(sb);
    PASS;
}

/** \test lots of gaps in block list */
static int StreamingBufferTest07(void)
{
    StreamingBufferConfig cfg = { 0, 8, 16, NULL, NULL, NULL, NULL };
    StreamingBuffer *sb = StreamingBufferInit(&cfg);
    FAIL_IF(sb == NULL);

    StreamingBufferSegment seg1;
    FAIL_IF(StreamingBufferInsertAt(sb, &seg1, (const uint8_t *)"B", 1, 1) != 0);
    StreamingBufferSegment seg2;
    FAIL_IF(StreamingBufferInsertAt(sb, &seg2, (const uint8_t *)"D", 1, 3) != 0);
    Dump(sb);

    StreamingBufferSegment seg3;
    FAIL_IF(StreamingBufferInsertAt(sb, &seg3, (const uint8_t *)"F", 1, 5) != 0);
    Dump(sb);

    StreamingBufferSegment seg4;
    FAIL_IF(StreamingBufferInsertAt(sb, &seg4, (const uint8_t *)"H", 1, 7) != 0);
    Dump(sb);

    StreamingBufferSegment seg5;
    FAIL_IF(StreamingBufferInsertAt(sb, &seg5, (const uint8_t *)"ABCDEFGHIJ", 10, 0) != 0);
    Dump(sb);
    FAIL_IF(sb->block_list == NULL);
    FAIL_IF(sb->block_list->offset != 0);
    FAIL_IF(sb->block_list->len != 10);
    FAIL_IF(sb->block_list->next != NULL);

    StreamingBufferSegment seg6;
    FAIL_IF(StreamingBufferInsertAt(sb, &seg6, (const uint8_t *)"abcdefghij", 10, 0) != 0);
    Dump(sb);
    FAIL_IF(sb->block_list == NULL);
    FAIL_IF(sb->block_list->offset != 0);
    FAIL_IF(sb->block_list->len != 10);
    FAIL_IF(sb->block_list->next != NULL);

    StreamingBufferFree(sb);
    PASS;
}

/** \test lots of gaps in block list */
static int StreamingBufferTest08(void)
{
    StreamingBufferConfig cfg = { 0, 8, 16, NULL, NULL, NULL, NULL };
    StreamingBuffer *sb = StreamingBufferInit(&cfg);
    FAIL_IF(sb == NULL);

    StreamingBufferSegment seg1;
    FAIL_IF(StreamingBufferInsertAt(sb, &seg1, (const uint8_t *)"B", 1, 1) != 0);
    StreamingBufferSegment seg2;
    FAIL_IF(StreamingBufferInsertAt(sb, &seg2, (const uint8_t *)"D", 1, 3) != 0);
    Dump(sb);

    StreamingBufferSegment seg3;
    FAIL_IF(StreamingBufferInsertAt(sb, &seg3, (const uint8_t *)"F", 1, 5) != 0);
    Dump(sb);

    StreamingBufferSegment seg4;
    FAIL_IF(StreamingBufferInsertAt(sb, &seg4, (const uint8_t *)"H", 1, 7) != 0);
    Dump(sb);

    StreamingBufferSegment seg5;
    FAIL_IF(StreamingBufferInsertAt(sb, &seg5, (const uint8_t *)"ABCDEFGHIJ", 10, 0) != 0);
    Dump(sb);
    FAIL_IF(sb->block_list == NULL);
    FAIL_IF(sb->block_list->offset != 0);
    FAIL_IF(sb->block_list->len != 10);
    FAIL_IF(sb->block_list->next != NULL);

    StreamingBufferSegment seg6;
    FAIL_IF(StreamingBufferAppend(sb, &seg6, (const uint8_t *)"abcdefghij", 10) != 0);
    Dump(sb);
    FAIL_IF(sb->block_list == NULL);
    FAIL_IF(sb->block_list->offset != 0);
    FAIL_IF(sb->block_list->len != 20);
    FAIL_IF(sb->block_list->next != NULL);

    StreamingBufferFree(sb);
    PASS;
}

/** \test lots of gaps in block list */
static int StreamingBufferTest09(void)
{
    StreamingBufferConfig cfg = { 0, 8, 16, NULL, NULL, NULL, NULL };
    StreamingBuffer *sb = StreamingBufferInit(&cfg);
    FAIL_IF(sb == NULL);

    StreamingBufferSegment seg1;
    FAIL_IF(StreamingBufferInsertAt(sb, &seg1, (const uint8_t *)"B", 1, 1) != 0);
    StreamingBufferSegment seg2;
    FAIL_IF(StreamingBufferInsertAt(sb, &seg2, (const uint8_t *)"D", 1, 3) != 0);
    Dump(sb);

    StreamingBufferSegment seg3;
    FAIL_IF(StreamingBufferInsertAt(sb, &seg3, (const uint8_t *)"H", 1, 7) != 0);
    Dump(sb);

    StreamingBufferSegment seg4;
    FAIL_IF(StreamingBufferInsertAt(sb, &seg4, (const uint8_t *)"F", 1, 5) != 0);
    Dump(sb);

    StreamingBufferSegment seg5;
    FAIL_IF(StreamingBufferInsertAt(sb, &seg5, (const uint8_t *)"ABCDEFGHIJ", 10, 0) != 0);
    Dump(sb);
    FAIL_IF(sb->block_list == NULL);
    FAIL_IF(sb->block_list->offset != 0);
    FAIL_IF(sb->block_list->len != 10);
    FAIL_IF(sb->block_list->next != NULL);

    StreamingBufferSegment seg6;
    FAIL_IF(StreamingBufferInsertAt(sb, &seg6, (const uint8_t *)"abcdefghij", 10, 0) != 0);
    Dump(sb);
    FAIL_IF(sb->block_list == NULL);
    FAIL_IF(sb->block_list->offset != 0);
    FAIL_IF(sb->block_list->len != 10);
    FAIL_IF(sb->block_list->next != NULL);

    StreamingBufferFree(sb);
    PASS;
}

/** \test lots of gaps in block list */
static int StreamingBufferTest10(void)
{
    StreamingBufferConfig cfg = { 0, 8, 16, NULL, NULL, NULL, NULL };
    StreamingBuffer *sb = StreamingBufferInit(&cfg);
    FAIL_IF(sb == NULL);

    StreamingBufferSegment seg1;
    FAIL_IF(StreamingBufferInsertAt(sb, &seg1, (const uint8_t *)"A", 1, 0) != 0);
    StreamingBufferSegment seg2;
    FAIL_IF(StreamingBufferInsertAt(sb, &seg2, (const uint8_t *)"D", 1, 3) != 0);
    Dump(sb);

    StreamingBufferSegment seg3;
    FAIL_IF(StreamingBufferInsertAt(sb, &seg3, (const uint8_t *)"H", 1, 7) != 0);
    Dump(sb);

    StreamingBufferSegment seg4;
    FAIL_IF(StreamingBufferInsertAt(sb, &seg4, (const uint8_t *)"B", 1, 1) != 0);
    Dump(sb);
    StreamingBufferSegment seg5;
    FAIL_IF(StreamingBufferInsertAt(sb, &seg5, (const uint8_t *)"C", 1, 2) != 0);
    Dump(sb);
    StreamingBufferSegment seg6;
    FAIL_IF(StreamingBufferInsertAt(sb, &seg6, (const uint8_t *)"G", 1, 6) != 0);
    Dump(sb);

    StreamingBufferSegment seg7;
    FAIL_IF(StreamingBufferInsertAt(sb, &seg7, (const uint8_t *)"ABCDEFGHIJ", 10, 0) != 0);
    Dump(sb);
    FAIL_IF(sb->block_list == NULL);
    FAIL_IF(sb->block_list->offset != 0);
    FAIL_IF(sb->block_list->len != 10);
    FAIL_IF(sb->block_list->next != NULL);

    StreamingBufferSegment seg8;
    FAIL_IF(StreamingBufferInsertAt(sb, &seg8, (const uint8_t *)"abcdefghij", 10, 0) != 0);
    Dump(sb);
    FAIL_IF(sb->block_list == NULL);
    FAIL_IF(sb->block_list->offset != 0);
    FAIL_IF(sb->block_list->len != 10);
    FAIL_IF(sb->block_list->next != NULL);

    StreamingBufferFree(sb);
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
    UtRegisterTest("StreamingBufferTest06", StreamingBufferTest06);
    UtRegisterTest("StreamingBufferTest07", StreamingBufferTest07);
    UtRegisterTest("StreamingBufferTest08", StreamingBufferTest08);
    UtRegisterTest("StreamingBufferTest09", StreamingBufferTest09);
    UtRegisterTest("StreamingBufferTest10", StreamingBufferTest10);
#endif
}
