/* Copyright (C) 2007-2022 Open Information Security Foundation
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
#include "util-print.h"

#include "flow.h"
#include "stream-tcp.h"
#include "app-layer-frames.h"
#include "app-layer-parser.h"

struct FrameConfig {
    SC_ATOMIC_DECLARE(uint64_t, types);
};
static struct FrameConfig frame_config[ALPROTO_MAX];

void FrameConfigInit(void)
{
    for (AppProto p = 0; p < ALPROTO_MAX; p++) {
        SC_ATOMIC_INIT(frame_config[p].types);
    }
}

void FrameConfigEnableAll(void)
{
    const uint64_t bits = UINT64_MAX;
    for (AppProto p = 0; p < ALPROTO_MAX; p++) {
        struct FrameConfig *fc = &frame_config[p];
        SC_ATOMIC_OR(fc->types, bits);
    }
}

void FrameConfigEnable(const AppProto p, const uint8_t type)
{
    const uint64_t bits = BIT_U64(type);
    struct FrameConfig *fc = &frame_config[p];
    SC_ATOMIC_OR(fc->types, bits);
}

static inline bool FrameConfigTypeIsEnabled(const AppProto p, const uint8_t type)
{
    struct FrameConfig *fc = &frame_config[p];
    const uint64_t bits = BIT_U64(type);
    const bool enabled = (SC_ATOMIC_GET(fc->types) & bits) != 0;
    return enabled;
}

static void FrameDebug(const char *prefix, const Frames *frames, const Frame *frame)
{
#ifdef DEBUG
    const char *type_name = "unknown";
    if (frame->type == FRAME_STREAM_TYPE) {
        type_name = "stream";
    } else if (frames != NULL) {
        type_name = AppLayerParserGetFrameNameById(frames->ipproto, frames->alproto, frame->type);
    }
    SCLogDebug("[%s] %p: frame:%p type:%u/%s id:%" PRIi64 " flags:%02x offset:%" PRIu64
               ", len:%" PRIi64 ", inspect_progress:%" PRIu64 ", events:%u %u/%u/%u/%u",
            prefix, frames, frame, frame->type, type_name, frame->id, frame->flags, frame->offset,
            frame->len, frame->inspect_progress, frame->event_cnt, frame->events[0],
            frame->events[1], frame->events[2], frame->events[3]);
#endif
}

Frame *FrameGetById(Frames *frames, const int64_t id)
{
    SCLogDebug("frames %p cnt %u, looking for %" PRIi64, frames, frames->cnt, id);
    for (uint16_t i = 0; i < frames->cnt; i++) {
        if (i < FRAMES_STATIC_CNT) {
            Frame *frame = &frames->sframes[i];
            FrameDebug("get_by_id(static)", frames, frame);
            if (frame->id == id)
                return frame;
        } else {
            const uint16_t o = i - FRAMES_STATIC_CNT;
            Frame *frame = &frames->dframes[o];
            FrameDebug("get_by_id(dynamic)", frames, frame);
            if (frame->id == id)
                return frame;
        }
    }
    return NULL;
}

Frame *FrameGetByIndex(Frames *frames, const uint32_t idx)
{
    if (idx >= frames->cnt)
        return NULL;

    if (idx < FRAMES_STATIC_CNT) {
        Frame *frame = &frames->sframes[idx];
        FrameDebug("get_by_idx(s)", frames, frame);
        return frame;
    } else {
        const uint32_t o = idx - FRAMES_STATIC_CNT;
        Frame *frame = &frames->dframes[o];
        FrameDebug("get_by_idx(d)", frames, frame);
        return frame;
    }
}

static Frame *FrameNew(Frames *frames, uint64_t offset, int64_t len)
{
    BUG_ON(frames == NULL);

    if (frames->cnt < FRAMES_STATIC_CNT) {
        Frame *frame = &frames->sframes[frames->cnt];
        frames->sframes[frames->cnt].offset = offset;
        frames->sframes[frames->cnt].len = len;
        frames->sframes[frames->cnt].id = ++frames->base_id;
        frames->cnt++;
        return frame;
    } else if (frames->dframes == NULL) {
        BUG_ON(frames->dyn_size != 0);
        BUG_ON(frames->cnt != FRAMES_STATIC_CNT);

        frames->dframes = SCCalloc(8, sizeof(Frame));
        if (frames->dframes == NULL) {
            return NULL;
        }
        frames->cnt++;
        BUG_ON(frames->cnt != FRAMES_STATIC_CNT + 1);

        frames->dyn_size = 8;
        frames->dframes[0].offset = offset;
        frames->dframes[0].len = len;
        frames->dframes[0].id = ++frames->base_id;
        return &frames->dframes[0];
    } else {
        BUG_ON(frames->cnt < FRAMES_STATIC_CNT);

        /* need to handle dynamic storage of frames now */
        const uint16_t dyn_cnt = frames->cnt - FRAMES_STATIC_CNT;
        if (dyn_cnt < frames->dyn_size) {
            BUG_ON(frames->dframes == NULL);

            // fall through
        } else {
            if (frames->dyn_size == 256) {
                SCLogDebug("limit reached! 256 dynamic frames already");
                // limit reached
                // TODO figure out if this should lead to an event of sorts
                return NULL;
            }

            /* realloc time */
            uint16_t new_dyn_size = frames->dyn_size * 2;
            uint32_t new_alloc_size = new_dyn_size * sizeof(Frame);

            void *ptr = SCRealloc(frames->dframes, new_alloc_size);
            if (ptr == NULL) {
                return NULL;
            }

            memset((uint8_t *)ptr + (frames->dyn_size * sizeof(Frame)), 0x00,
                    (frames->dyn_size * sizeof(Frame)));
            frames->dframes = ptr;
            frames->dyn_size = new_dyn_size;
        }

        frames->cnt++;
        frames->dframes[dyn_cnt].offset = offset;
        frames->dframes[dyn_cnt].len = len;
        frames->dframes[dyn_cnt].id = ++frames->base_id;
        return &frames->dframes[dyn_cnt];
    }
}

static void FrameClean(Frame *frame)
{
    memset(frame, 0, sizeof(*frame));
}

static void FrameCopy(Frame *dst, Frame *src)
{
    memcpy(dst, src, sizeof(*dst));
}

static void AppLayerFrameDumpForFrames(const char *prefix, const Frames *frames)
{
    SCLogDebug("prefix: %s", prefix);
    for (uint16_t i = 0; i < frames->cnt; i++) {
        if (i < FRAMES_STATIC_CNT) {
            const Frame *frame = &frames->sframes[i];
            FrameDebug(prefix, frames, frame);
        } else {
            const uint16_t o = i - FRAMES_STATIC_CNT;
            const Frame *frame = &frames->dframes[o];
            FrameDebug(prefix, frames, frame);
        }
    }
    SCLogDebug("prefix: %s", prefix);
}

static inline uint64_t FrameLeftEdge(const TcpStream *stream, const Frame *frame)
{
    const int64_t app_progress = STREAM_APP_PROGRESS(stream);

    const int64_t frame_offset = frame->offset;
    const int64_t frame_data = app_progress - frame_offset;

    SCLogDebug("frame_offset %" PRIi64 ", frame_data %" PRIi64 ", frame->len %" PRIi64,
            frame_offset, frame_data, frame->len);
    BUG_ON(frame_offset > app_progress);

    /* length unknown, make sure to have at least 2500 */
    if (frame->len < 0) {
        if (frame_data <= 2500) {
            SCLogDebug("got <= 2500 bytes (%" PRIu64 "), returning offset %" PRIu64, frame_data,
                    frame_offset);
            return frame_offset;
        } else {
            SCLogDebug("got > 2500 bytes (%" PRIu64 "), returning offset %" PRIu64, frame_data,
                    (frame_offset + (frame_data - 2500)));
            return frame_offset + (frame_data - 2500);
        }

        /* length specified */
    } else {
        /* have all data for the frame, we can skip it */
        if (frame->len <= frame_data) {
            uint64_t x = frame_offset + frame_data;
            SCLogDebug("x %" PRIu64, x);
            return x;
            /*

                [ stream      <frame_data> ]
                             [ frame        .......]

             */
        } else if (frame_data < 2500) {
            uint64_t x = frame_offset;
            SCLogDebug("x %" PRIu64, x);
            return x;
        } else {
            uint64_t x = frame_offset + (frame_data - 2500);
            SCLogDebug("x %" PRIu64, x);
            return x;
        }
    }
}

/** Stream buffer slides forward, we need to update and age out
 *  frame offsets/frames. Aging out means we move existing frames
 *  into the slots we'd free up.
 *
 *  Start:
 *
 *  [ stream ]
 *    [ frame   ...........]
 *      offset: 2
 *      len: 19
 *
 *  Slide:
 *         [ stream ]
 *    [ frame ....          .]
 *      offset: 2
 *       len: 19
 *
 *  Slide:
 *                [ stream ]
 *    [ frame ...........    ]
 *      offset: 2
 *      len: 19
 */
static int FrameSlide(const char *ds, Frames *frames, const TcpStream *stream, const uint32_t slide)
{
    SCLogDebug("start: left edge %" PRIu64 ", left_edge_rel %u, stream base %" PRIu64
               ", next %" PRIu64,
            (uint64_t)frames->left_edge_rel + STREAM_BASE_OFFSET(stream), frames->left_edge_rel,
            STREAM_BASE_OFFSET(stream), STREAM_BASE_OFFSET(stream) + slide);
    BUG_ON(frames == NULL);
    SCLogDebug("%s frames %p: sliding %u bytes", ds, frames, slide);
    uint64_t le = STREAM_APP_PROGRESS(stream);
    const uint64_t next_base = STREAM_BASE_OFFSET(stream) + slide;
    const uint16_t start = frames->cnt;
    uint16_t removed = 0;
    uint16_t x = 0;
    for (uint16_t i = 0; i < frames->cnt; i++) {
        if (i < FRAMES_STATIC_CNT) {
            Frame *frame = &frames->sframes[i];
            FrameDebug("slide(s)", frames, frame);
            if (frame->len >= 0 && frame->offset + frame->len <= next_base) {
                // remove by not incrementing 'x'
                SCLogDebug("removing %p id %" PRIi64, frame, frame->id);
                FrameClean(frame);
                removed++;
            } else {
                Frame *nframe = &frames->sframes[x];
                FrameCopy(nframe, frame);
                if (frame != nframe) {
                    FrameClean(frame);
                }
                le = MIN(le, FrameLeftEdge(stream, nframe));
                x++;
            }
        } else {
            const uint16_t o = i - FRAMES_STATIC_CNT;
            Frame *frame = &frames->dframes[o];
            FrameDebug("slide(d)", frames, frame);
            if (frame->len >= 0 && frame->offset + frame->len <= next_base) {
                // remove by not incrementing 'x'
                SCLogDebug("removing %p id %" PRIi64, frame, frame->id);
                FrameClean(frame);
                removed++;
            } else {
                Frame *nframe;
                if (x >= FRAMES_STATIC_CNT) {
                    nframe = &frames->dframes[x - FRAMES_STATIC_CNT];
                } else {
                    nframe = &frames->sframes[x];
                }
                FrameCopy(nframe, frame);
                if (frame != nframe) {
                    FrameClean(frame);
                }
                le = MIN(le, FrameLeftEdge(stream, nframe));
                x++;
            }
        }
    }
    frames->cnt = x;
    uint64_t o = STREAM_BASE_OFFSET(stream) + slide;
    frames->left_edge_rel = le - (STREAM_BASE_OFFSET(stream) + slide);

#ifdef DEBUG
    SCLogDebug("end: left edge %" PRIu64 ", left_edge_rel %u, stream base %" PRIu64
               " (+slide), cnt %u, removed %u, start %u",
            (uint64_t)frames->left_edge_rel + STREAM_BASE_OFFSET(stream) + slide,
            frames->left_edge_rel, STREAM_BASE_OFFSET(stream) + slide, frames->cnt, removed, start);
    char pf[32] = "";
    snprintf(pf, sizeof(pf), "%s:post_slide", ds);
    AppLayerFrameDumpForFrames(pf, frames);
#endif
    BUG_ON(o > le);
    BUG_ON(x != start - removed);
    return 0;
}

void AppLayerFramesSlide(Flow *f, const uint32_t slide, const uint8_t direction)
{
    FramesContainer *frames_container = AppLayerFramesGetContainer(f);
    if (frames_container == NULL)
        return;
    Frames *frames;
    TcpSession *ssn = f->protoctx;
    TcpStream *stream;
    if (direction == STREAM_TOSERVER) {
        stream = &ssn->client;
        frames = &frames_container->toserver;
        FrameSlide("toserver", frames, stream, slide);
    } else {
        stream = &ssn->server;
        frames = &frames_container->toclient;
        FrameSlide("toclient", frames, stream, slide);
    }
}

static void FrameFreeSingleFrame(Frames *frames, Frame *r)
{
    FrameDebug("free", frames, r);
    FrameClean(r);
}

static void FramesClear(Frames *frames)
{
    BUG_ON(frames == NULL);

    SCLogDebug("frames %u", frames->cnt);
    for (uint16_t i = 0; i < frames->cnt; i++) {
        if (i < FRAMES_STATIC_CNT) {
            Frame *r = &frames->sframes[i];
            SCLogDebug("removing frame %p", r);
            FrameFreeSingleFrame(frames, r);
        } else {
            const uint16_t o = i - FRAMES_STATIC_CNT;
            Frame *r = &frames->dframes[o];
            SCLogDebug("removing frame %p", r);
            FrameFreeSingleFrame(frames, r);
        }
    }
    frames->cnt = 0;
}

void FramesFree(Frames *frames)
{
    BUG_ON(frames == NULL);
    FramesClear(frames);
    SCFree(frames->dframes);
    frames->dframes = NULL;
}

/** \brief create new frame using a pointer to start of the frame
 */
Frame *AppLayerFrameNewByPointer(Flow *f, const StreamSlice *stream_slice,
        const uint8_t *frame_start, const int64_t len, int dir, uint8_t frame_type)
{
    SCLogDebug("frame_start:%p stream_slice->input:%p stream_slice->offset:%" PRIu64, frame_start,
            stream_slice->input, stream_slice->offset);

    if (!(FrameConfigTypeIsEnabled(f->alproto, frame_type)))
        return NULL;

        /* workarounds for many (unit|fuzz)tests not handling TCP data properly */
#if defined(UNITTESTS) || defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION)
    if (f->proto == IPPROTO_TCP && f->protoctx == NULL)
        return NULL;
    if (frame_start < stream_slice->input ||
            frame_start >= stream_slice->input + stream_slice->input_len)
        return NULL;
#endif
    BUG_ON(frame_start < stream_slice->input);
    BUG_ON(stream_slice->input == NULL);
    BUG_ON(f->proto == IPPROTO_TCP && f->protoctx == NULL);

    ptrdiff_t ptr_offset = frame_start - stream_slice->input;
#ifdef DEBUG
    uint64_t offset = ptr_offset + stream_slice->offset;
    SCLogDebug("flow %p direction %s frame %p starting at %" PRIu64 " len %" PRIi64
               " (offset %" PRIu64 ")",
            f, dir == 0 ? "toserver" : "toclient", frame_start, offset, len, stream_slice->offset);
#endif
    BUG_ON(f->alparser == NULL);

    FramesContainer *frames_container = AppLayerFramesSetupContainer(f);
    if (frames_container == NULL)
        return NULL;

    Frames *frames;
    if (dir == 0) {
        frames = &frames_container->toserver;
    } else {
        frames = &frames_container->toclient;
    }

    uint64_t abs_frame_offset = stream_slice->offset + ptr_offset;

    Frame *r = FrameNew(frames, abs_frame_offset, len);
    if (r != NULL) {
        r->type = frame_type;
        FrameDebug("new_by_ptr", frames, r);
    }
    return r;
}

static Frame *AppLayerFrameUdp(Flow *f, const StreamSlice *stream_slice,
        const uint32_t frame_start_rel, const int64_t len, int dir, uint8_t frame_type)
{
    BUG_ON(f->proto != IPPROTO_UDP);

    if (!(FrameConfigTypeIsEnabled(f->alproto, frame_type)))
        return NULL;

    FramesContainer *frames_container = AppLayerFramesSetupContainer(f);
    if (frames_container == NULL)
        return NULL;

    Frames *frames;
    if (dir == 0) {
        frames = &frames_container->toserver;
    } else {
        frames = &frames_container->toclient;
    }

    Frame *r = FrameNew(frames, frame_start_rel, len);
    if (r != NULL) {
        r->type = frame_type;
    }
    return r;
}

/** \brief create new frame using a relative offset from the start of the stream slice
 */
Frame *AppLayerFrameNewByRelativeOffset(Flow *f, const StreamSlice *stream_slice,
        const uint32_t frame_start_rel, const int64_t len, int dir, uint8_t frame_type)
{
    if (!(FrameConfigTypeIsEnabled(f->alproto, frame_type)))
        return NULL;

        /* workarounds for many (unit|fuzz)tests not handling TCP data properly */
#if defined(UNITTESTS) || defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION)
    if (f->proto == IPPROTO_TCP && f->protoctx == NULL)
        return NULL;
    if (stream_slice->input == NULL)
        return NULL;
#else
    BUG_ON(stream_slice->input == NULL);
#endif
    BUG_ON(f->proto == IPPROTO_TCP && f->protoctx == NULL);
    BUG_ON(f->alparser == NULL);

    if (f->proto == IPPROTO_UDP) {
        return AppLayerFrameUdp(f, stream_slice, frame_start_rel, len, dir, frame_type);
    }

    FramesContainer *frames_container = AppLayerFramesSetupContainer(f);
    if (frames_container == NULL)
        return NULL;

    Frames *frames;
    if (dir == 0) {
        frames = &frames_container->toserver;
    } else {
        frames = &frames_container->toclient;
    }

    const uint64_t frame_abs_offset = (uint64_t)frame_start_rel + stream_slice->offset;
#ifdef DEBUG_VALIDATION
    const TcpSession *ssn = f->protoctx;
    const TcpStream *stream = dir == 0 ? &ssn->client : &ssn->server;
    BUG_ON(stream_slice->offset != STREAM_APP_PROGRESS(stream));
    BUG_ON(frame_abs_offset > STREAM_APP_PROGRESS(stream) + stream_slice->input_len);
#endif
    Frame *r = FrameNew(frames, frame_abs_offset, len);
    if (r != NULL) {
        r->type = frame_type;
    }
    return r;
}

void AppLayerFrameDump(Flow *f)
{
    if (f->proto == IPPROTO_TCP && f->protoctx && f->alparser) {
        FramesContainer *frames_container = AppLayerFramesGetContainer(f);
        if (frames_container != NULL) {
            AppLayerFrameDumpForFrames("toserver::dump", &frames_container->toserver);
            AppLayerFrameDumpForFrames("toclient::dump", &frames_container->toclient);
        }
    }
}

/** \brief create new frame using the absolute offset from the start of the stream
 */
Frame *AppLayerFrameNewByAbsoluteOffset(Flow *f, const StreamSlice *stream_slice,
        const uint64_t frame_start, const int64_t len, int dir, uint8_t frame_type)
{
    if (!(FrameConfigTypeIsEnabled(f->alproto, frame_type)))
        return NULL;

        /* workarounds for many (unit|fuzz)tests not handling TCP data properly */
#if defined(UNITTESTS) || defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION)
    if (f->proto == IPPROTO_TCP && f->protoctx == NULL)
        return NULL;
    if (stream_slice->input == NULL)
        return NULL;
#else
    BUG_ON(stream_slice->input == NULL);
#endif
    BUG_ON(f->proto == IPPROTO_TCP && f->protoctx == NULL);
    BUG_ON(f->alparser == NULL);
    BUG_ON(frame_start < stream_slice->offset);
    BUG_ON(frame_start - stream_slice->offset >= (uint64_t)INT_MAX);

    FramesContainer *frames_container = AppLayerFramesSetupContainer(f);
    if (frames_container == NULL)
        return NULL;

    Frames *frames;
    if (dir == 0) {
        frames = &frames_container->toserver;
    } else {
        frames = &frames_container->toclient;
    }

    SCLogDebug("flow %p direction %s frame type %u offset %" PRIu64 " len %" PRIi64
               " (slice offset %" PRIu64 ")",
            f, dir == 0 ? "toserver" : "toclient", frame_type, frame_start, len,
            stream_slice->offset);
    Frame *r = FrameNew(frames, frame_start, len);
    if (r != NULL) {
        r->type = frame_type;
    }
    return r;
}

void AppLayerFrameAddEvent(Frame *r, uint8_t e)
{
    if (r != NULL) {
        if (r->event_cnt < 4) { // TODO
            r->events[r->event_cnt++] = e;
        }
        FrameDebug("add_event", NULL, r);
    }
}

void AppLayerFrameAddEventById(Flow *f, const int dir, const FrameId id, uint8_t e)
{
    Frame *frame = AppLayerFrameGetById(f, dir, id);
    AppLayerFrameAddEvent(frame, e);
}

FrameId AppLayerFrameGetId(Frame *r)
{
    if (r != NULL) {
        return r->id;
    } else {
        return -1;
    }
}

void AppLayerFrameSetLength(Frame *frame, int64_t len)
{
    if (frame != NULL) {
        frame->len = len;
        FrameDebug("set_length", NULL, frame);
    }
}

void AppLayerFrameSetLengthById(Flow *f, const int dir, const FrameId id, int64_t len)
{
    Frame *frame = AppLayerFrameGetById(f, dir, id);
    AppLayerFrameSetLength(frame, len);
}

void AppLayerFrameSetTxId(Frame *r, uint64_t tx_id)
{
    if (r != NULL) {
        r->flags |= FRAME_FLAG_TX_ID_SET;
        r->tx_id = tx_id;
        FrameDebug("set_txid", NULL, r);
    }
}

void AppLayerFrameSetTxIdById(Flow *f, const int dir, const FrameId id, uint64_t tx_id)
{
    Frame *frame = AppLayerFrameGetById(f, dir, id);
    AppLayerFrameSetTxId(frame, tx_id);
}

Frame *AppLayerFrameGetById(Flow *f, const int dir, const FrameId frame_id)
{
    FramesContainer *frames_container = AppLayerFramesGetContainer(f);
    SCLogDebug("get frame_id %" PRIi64 " direction %u/%s frames_container %p", frame_id, dir,
            dir == 0 ? "toserver" : "toclient", frames_container);
    if (frames_container == NULL)
        return NULL;

    Frames *frames;
    if (dir == 0) {
        frames = &frames_container->toserver;
    } else {
        frames = &frames_container->toclient;
    }
    SCLogDebug("frames %p", frames);
    return FrameGetById(frames, frame_id);
}

static inline bool FrameIsDone(
        const Frame *frame, const uint64_t abs_offset, const uint64_t abs_right_edge)
{
    /* frame with negative length means we don't know the size yet. */
    if (frame->len < 0)
        return false;

    const int64_t frame_abs_offset = frame->offset;
    const int64_t frame_right_edge = frame_abs_offset + frame->len;
    if ((uint64_t)frame_right_edge <= abs_right_edge) {
        SCLogDebug("frame %p id %" PRIi64 " is done", frame, frame->id);
        return true;
    }
    return false;
}

static void FramePrune(Frames *frames, const TcpStream *stream, const bool eof)
{
    const uint64_t frames_le_start = (uint64_t)frames->left_edge_rel + STREAM_BASE_OFFSET(stream);
    SCLogDebug("start: left edge %" PRIu64 ", left_edge_rel %u, stream base %" PRIu64,
            (uint64_t)frames->left_edge_rel + STREAM_BASE_OFFSET(stream), frames->left_edge_rel,
            STREAM_BASE_OFFSET(stream));
    const uint64_t abs_offset = STREAM_BASE_OFFSET(stream);
    const uint64_t acked = StreamTcpGetUsable(stream, eof);
    uint64_t le = STREAM_APP_PROGRESS(stream);

    const uint16_t start = frames->cnt;
    uint16_t removed = 0;
    uint16_t x = 0;
    for (uint16_t i = 0; i < frames->cnt; i++) {
        if (i < FRAMES_STATIC_CNT) {
            Frame *frame = &frames->sframes[i];
            FrameDebug("prune(s)", frames, frame);
            if (eof || FrameIsDone(frame, abs_offset, acked)) {
                // remove by not incrementing 'x'
                SCLogDebug("removing %p id %" PRIi64, frame, frame->id);
                FrameDebug("remove(s)", frames, frame);
                FrameClean(frame);
                removed++;
            } else {
                const uint64_t fle = FrameLeftEdge(stream, frame);
                le = MIN(le, fle);
                SCLogDebug("le %" PRIu64 ", frame fle %" PRIu64, le, fle);
                Frame *nframe = &frames->sframes[x];
                FrameCopy(nframe, frame);
                if (frame != nframe) {
                    FrameClean(frame);
                }
                x++;
            }
        } else {
            const uint16_t o = i - FRAMES_STATIC_CNT;
            Frame *frame = &frames->dframes[o];
            FrameDebug("prune(d)", frames, frame);
            if (eof || FrameIsDone(frame, abs_offset, acked)) {
                // remove by not incrementing 'x'
                SCLogDebug("removing %p id %" PRIi64, frame, frame->id);
                FrameDebug("remove(d)", frames, frame);
                FrameClean(frame);
                removed++;
            } else {
                const uint64_t fle = FrameLeftEdge(stream, frame);
                le = MIN(le, fle);
                SCLogDebug("le %" PRIu64 ", frame fle %" PRIu64, le, fle);
                Frame *nframe;
                if (x >= FRAMES_STATIC_CNT) {
                    nframe = &frames->dframes[x - FRAMES_STATIC_CNT];
                } else {
                    nframe = &frames->sframes[x];
                }
                FrameCopy(nframe, frame);
                if (frame != nframe) {
                    FrameClean(frame);
                }
                x++;
            }
        }
    }
    frames->cnt = x;
    frames->left_edge_rel = le - STREAM_BASE_OFFSET(stream);
#ifdef DEBUG
    SCLogDebug("end: left edge %" PRIu64 ", left_edge_rel %u, stream base %" PRIu64
               ", cnt %u, removed %u, start %u",
            (uint64_t)frames->left_edge_rel + STREAM_BASE_OFFSET(stream), frames->left_edge_rel,
            STREAM_BASE_OFFSET(stream), frames->cnt, removed, start);
    AppLayerFrameDumpForFrames("post_slide", frames);
#endif
    BUG_ON(le < STREAM_BASE_OFFSET(stream));
    if (frames->cnt > 0) { // if we removed all this can fail
        BUG_ON(frames_le_start > le);
    }
    BUG_ON(x != start - removed);
}

void FramesPrune(Flow *f, Packet *p)
{
    if (f->proto == IPPROTO_TCP && f->protoctx == NULL)
        return;
    FramesContainer *frames_container = AppLayerFramesGetContainer(f);
    if (frames_container == NULL)
        return;

    Frames *frames;

    if (p->proto == IPPROTO_UDP) {
        SCLogDebug("clearing all UDP frames");
        if (PKT_IS_TOSERVER(p)) {
            frames = &frames_container->toserver;
        } else {
            frames = &frames_container->toclient;
        }
        FramesClear(frames);
        return;
    }

    TcpSession *ssn = f->protoctx;

    if (ssn->flags & STREAMTCP_FLAG_APP_LAYER_DISABLED) {
        AppLayerFramesFreeContainer(f);
        return;
    }

    TcpStream *stream;
    if (PKT_IS_TOSERVER(p)) {
        stream = &ssn->client;
        frames = &frames_container->toserver;
    } else {
        stream = &ssn->server;
        frames = &frames_container->toclient;
    }

    const bool eof = ssn->state == TCP_CLOSED || PKT_IS_PSEUDOPKT(p);
    SCLogDebug("eof %s", eof ? "TRUE" : "false");
    FramePrune(frames, stream, eof);
}
