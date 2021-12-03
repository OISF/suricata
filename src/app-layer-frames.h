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
 * You should have frameeived a copy of the GNU General Public License
 * version 2 along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 */

/**
 * \file
 *
 * \author Victor Julien <victor@inliniac.net>
 */

#ifndef __APP_LAYER_FRAMES_H__
#define __APP_LAYER_FRAMES_H__

#include "app-layer-events.h"
#include "detect-engine-state.h"
#include "util-file.h"
#include "stream-tcp-private.h"
#include "rust.h"
#include "app-layer-parser.h"

typedef int64_t FrameId;

enum {
    FRAME_FLAGE_TX_ID_SET,
#define FRAME_FLAG_TX_ID_SET BIT_U8(FRAME_FLAGE_TX_ID_SET)
    FRAME_FLAGE_ENDS_AT_EOF,
#define FRAME_FLAG_ENDS_AT_EOF BIT_U8(FRAME_FLAGE_ENDS_AT_EOF)
};

typedef struct Frame {
    uint8_t type;  /**< protocol specific field type. E.g. NBSS.HDR or SMB.DATA */
    uint8_t flags; /**< frame flags: FRAME_FLAG_* */
    uint8_t event_cnt;
    // TODO one event per frame enough?
    uint8_t events[4];  /**< per frame store for events */
    int32_t rel_offset; /**< relative offset in the stream on top of Stream::stream_offset (if
                           negative the start if before the stream data) */
    int32_t len;
    int64_t id;
    uint64_t tx_id; /**< tx_id to match this frame. UINT64T_MAX if not used. */
} Frame;
// size 32

#define FRAMES_STATIC_CNT 3

typedef struct Frames {
    uint16_t cnt;
    uint16_t dyn_size;     /**< size in elements of `dframes` */
    uint32_t progress_rel; /**< processing depth relative to STREAM_BASE_OFFSET */
    uint64_t base_id;
    Frame sframes[FRAMES_STATIC_CNT]; /**< static frames */
    Frame *dframes;                   /**< dynamically allocated space for more frames */
} Frames;
// size 120

typedef struct FramesContainer {
    Frames toserver;
    Frames toclient;
} FramesContainer;
// size 240

void FramesFree(Frames *frames);
int FrameSlide(Frames *frames, uint32_t slide);

Frame *AppLayerFrameNewByPointer(Flow *f, const StreamSlice *stream_slice,
        const uint8_t *frame_start, const uint32_t len, int dir, uint8_t frame_type);
Frame *AppLayerFrameNewByRelativeOffset(Flow *f, const StreamSlice *stream_slice,
        const uint32_t frame_start_rel, const uint32_t len, int dir, uint8_t frame_type);
void AppLayerFrameDump(Flow *f);

Frame *FrameGetByIndex(Frames *frames, const uint32_t idx);
Frame *FrameGetById(Frames *frames, const int64_t id);

void AppLayerFrameAddEvent(Frame *frame, uint8_t e);
FrameId AppLayerFrameGetId(Frame *r);
void AppLayerFrameSetTxId(Frame *r, uint64_t tx_id);

void AppLayerFramesUpdateProgress(
        Flow *f, TcpStream *stream, const uint64_t progress, const uint8_t direction);
void AppLayerFramesSlide(Flow *f, const uint32_t slide, const uint8_t direction);

FramesContainer *AppLayerFramesGetContainer(Flow *f);
FramesContainer *AppLayerFramesSetupContainer(Flow *f);

#endif
