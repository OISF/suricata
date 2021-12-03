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
 * You should have frameeived a copy of the GNU General Public License
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

#include "app-layer-frames.h"

static void FrameDebug(const char *prefix, const Frames *frames, const Frame *frame)
{
    SCLogDebug("[%s] %p: frame: %p type %u flags %02x rel_offset:%u, len:%u, events:%u %u/%u/%u/%u",
            prefix, frames, frame, frame->type, frame->flags, frame->rel_offset, frame->len,
            frame->event_cnt, frame->events[0], frame->events[1], frame->events[2],
            frame->events[3]);
}

Frame *FrameGetById(Frames *frames, const int64_t id)
{
    for (uint16_t i = 0; i < frames->cnt; i++) {
        if (i < FRAMES_STATIC_CNT) {
            Frame *frame = &frames->sframes[i];
            if (frame->id == id)
                return frame;
        } else {
            const uint16_t o = i - FRAMES_STATIC_CNT;
            Frame *frame = &frames->dframes[o];
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
        const uint16_t o = idx - FRAMES_STATIC_CNT;
        Frame *frame = &frames->dframes[o];
        FrameDebug("get_by_idx(d)", frames, frame);
        return frame;
    }
}

static Frame *FrameNew(Frames *frames, uint32_t rel_offset, int32_t len)
{
    BUG_ON(frames == NULL);

    if (frames->cnt < FRAMES_STATIC_CNT) {
        Frame *frame = &frames->sframes[frames->cnt];
        frames->sframes[frames->cnt].rel_offset = rel_offset;
        frames->sframes[frames->cnt].len = len;
        frames->sframes[frames->cnt].id = frames->base_id++;
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
        frames->dframes[0].rel_offset = rel_offset;
        frames->dframes[0].len = len;
        frames->dframes[0].id = frames->base_id++;
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
                SCLogNotice("limit reached! 256 dynamic frames already");
                // limit reached
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
        frames->dframes[dyn_cnt].rel_offset = rel_offset;
        frames->dframes[dyn_cnt].len = len;
        frames->dframes[dyn_cnt].id = frames->base_id++;
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
    // uint32_t last_re = 0;
    for (uint16_t i = 0; i < frames->cnt; i++) {
        if (i < FRAMES_STATIC_CNT) {
            const Frame *frame = &frames->sframes[i];
            FrameDebug(prefix, frames, frame);
            // BUG_ON(last_re != 0 && last_re > frame->rel_offset);
            // last_re = frame->rel_offset + frame->len;
        } else {
            const uint16_t o = i - FRAMES_STATIC_CNT;
            const Frame *frame = &frames->dframes[o];
            FrameDebug(prefix, frames, frame);
            // BUG_ON(last_re != 0 && last_re > frame->rel_offset);
            // last_re = frame->rel_offset + frame->len;
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
 *      rel_offset: 2
 *      len: 19
 *
 *  Slide:
 *         [ stream ]
 *    [ frame ....          .]
 *      rel_offset: -10
 *       len: 19
 *
 *  Slide:
 *                [ stream ]
 *    [ frame ...........    ]
 *      rel_offset: -16
 *      len: 19
 */
int FrameSlide(Frames *frames, uint32_t slide)
{
    BUG_ON(frames == NULL);
    SCLogDebug("frames %p: sliding %u bytes", frames, slide);

    if (slide >= frames->progress_rel)
        frames->progress_rel = 0;
    else
        frames->progress_rel -= slide;

    uint16_t x = 0;
    for (uint16_t i = 0; i < frames->cnt; i++) {
        if (i < FRAMES_STATIC_CNT) {
            Frame *frame = &frames->sframes[i];
            FrameDebug("slide(s)", frames, frame);
            if (frame->rel_offset + frame->len <= (int32_t)slide) {
                // remove by not incrementing 'x'
                SCLogDebug("removing %p", frame);
                FrameClean(frame);
            } else {
                Frame *nframe = &frames->sframes[x];
                FrameCopy(nframe, frame);
                nframe->rel_offset -= slide; /* turns negative if start if before window */
                if (frame != nframe) {
                    FrameClean(frame);
                }
                x++;
            }
        } else {
            const uint16_t o = i - FRAMES_STATIC_CNT;
            Frame *frame = &frames->dframes[o];
            FrameDebug("slide(d)", frames, frame);
            if (frame->rel_offset + frame->len <= (int32_t)slide) {
                // remove by not incrementing 'x'
                SCLogDebug("removing %p", frame);
                FrameClean(frame);
            } else {
                Frame *nframe;
                if (x >= FRAMES_STATIC_CNT) {
                    nframe = &frames->dframes[x - FRAMES_STATIC_CNT];
                } else {
                    nframe = &frames->sframes[x];
                }
                FrameCopy(nframe, frame);
                nframe->rel_offset -= slide; /* turns negative if start if before window */
                if (frame != nframe) {
                    FrameClean(frame);
                }
                x++;
            }
        }
    }
    frames->cnt = x;
    AppLayerFrameDumpForFrames("post_slide", frames);
    return 0;
}

void AppLayerFramesUpdateProgress(
        Flow *f, TcpStream *stream, const uint64_t progress, const uint8_t direction)
{
    FramesContainer *frames_container = AppLayerFramesGetContainer(f);
    if (frames_container == NULL)
        return;

    Frames *frames;
    if (direction == STREAM_TOSERVER) {
        frames = &frames_container->toserver;
    } else {
        frames = &frames_container->toclient;
    }

    const uint32_t slide = progress - STREAM_APP_PROGRESS(stream);
    frames->progress_rel += slide;
}

void AppLayerFramesSlide(Flow *f, const uint32_t slide, const uint8_t direction)
{
    FramesContainer *frames_container = AppLayerFramesGetContainer(f);
    if (frames_container == NULL)
        return;
    Frames *frames;
    if (direction == STREAM_TOSERVER) {
        frames = &frames_container->toserver;
    } else {
        frames = &frames_container->toclient;
    }
    FrameSlide(frames, slide);
}

static void FrameFreeSingleFrame(Frames *frames, Frame *r)
{
    FrameDebug("free", frames, r);
    FrameClean(r);
}

void FramesFree(Frames *frames)
{
    BUG_ON(frames == NULL);

    for (uint16_t i = 0; i < frames->cnt; i++) {
        if (i < FRAMES_STATIC_CNT) {
            Frame *r = &frames->sframes[i];
            FrameFreeSingleFrame(frames, r);
        } else {
            const uint16_t o = i - FRAMES_STATIC_CNT;
            Frame *r = &frames->dframes[o];
            FrameFreeSingleFrame(frames, r);
        }
    }
    SCFree(frames->dframes);
    frames->dframes = NULL;
}

/** \brief create new frame using a pointer to start of the frame
 */
Frame *AppLayerFrameNewByPointer(Flow *f, const StreamSlice *stream_slice,
        const uint8_t *frame_start, const uint32_t len, int dir, uint8_t frame_type)
{
    SCLogDebug("stream_slice offset %" PRIu64, stream_slice->offset);
    SCLogDebug("frame_start %p stream_slice->input %p", frame_start, stream_slice->input);

    /* workarounds for many (unit|fuzz)tests not handling TCP data properly */
#if defined(UNITTESTS) || defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION)
    if (f->protoctx == NULL)
        return NULL;
    if (frame_start < stream_slice->input ||
            frame_start >= stream_slice->input + stream_slice->input_len)
        return NULL;
#endif
    BUG_ON(frame_start < stream_slice->input);
    BUG_ON(stream_slice->input == NULL);
    BUG_ON(f->proto != IPPROTO_TCP);
    BUG_ON(f->protoctx == NULL);

    ptrdiff_t ptr_offset = frame_start - stream_slice->input;
#ifdef DEBUG
    uint64_t offset = ptr_offset + stream_slice->offset;
    SCLogDebug("flow %p direction %s frame %p starting at %" PRIu64 " len %u (offset %" PRIu64 ")",
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

    Frame *r = FrameNew(frames, (uint32_t)ptr_offset, len);
    if (r != NULL) {
        r->type = frame_type;
    }
    return r;
}

/** \brief create new frame using a relative offset from the start of the stream slice
 */
Frame *AppLayerFrameNewByRelativeOffset(Flow *f, const StreamSlice *stream_slice,
        const uint32_t frame_start_rel, const uint32_t len, int dir, uint8_t frame_type)
{
    /* workarounds for many (unit|fuzz)tests not handling TCP data properly */
#if defined(UNITTESTS) || defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION)
    if (f->protoctx == NULL)
        return NULL;
    if (stream_slice->input == NULL)
        return NULL;
#endif
    BUG_ON(stream_slice->input == NULL);
    BUG_ON(f->proto != IPPROTO_TCP);
    BUG_ON(f->protoctx == NULL);
    BUG_ON(f->alparser == NULL);
#ifdef DEBUG
    const uint64_t offset = (uint64_t)frame_start_rel + stream_slice->offset;
    SCLogDebug("flow %p direction %s frame offset %u (abs %" PRIu64 ") starting at %" PRIu64
               " len %u (offset %" PRIu64 ")",
            f, dir == 0 ? "toserver" : "toclient", frame_start_rel, offset, offset, len,
            stream_slice->offset);
#endif
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

void AppLayerFrameAddEvent(Frame *r, uint8_t e)
{
    if (r != NULL) {
        if (r->event_cnt < 4) { // TODO
            r->events[r->event_cnt++] = e;
        }
        FrameDebug("add_event", NULL, r);
    }
}

FrameId AppLayerFrameGetId(Frame *r)
{
    if (r != NULL) {
        return r->id;
    } else {
        return -1;
    }
}

void AppLayerFrameSetTxId(Frame *r, uint64_t tx_id)
{
    if (r != NULL) {
        r->flags |= FRAME_FLAG_TX_ID_SET;
        r->tx_id = tx_id;
        FrameDebug("set_txid", NULL, r);
    }
}
