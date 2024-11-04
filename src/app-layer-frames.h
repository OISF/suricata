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

#ifndef SURICATA_APP_LAYER_FRAMES_H
#define SURICATA_APP_LAYER_FRAMES_H

#include "rust.h"

/** max 63 to fit the 64 bit per protocol space */
#define FRAME_STREAM_TYPE 63

typedef int64_t FrameId;

enum {
    FRAME_FLAGE_TX_ID_SET,
#define FRAME_FLAG_TX_ID_SET BIT_U8(FRAME_FLAGE_TX_ID_SET)
    FRAME_FLAGE_ENDS_AT_EOF,
#define FRAME_FLAG_ENDS_AT_EOF BIT_U8(FRAME_FLAGE_ENDS_AT_EOF)
    FRAME_FLAGE_LOGGED,
#define FRAME_FLAG_LOGGED BIT_U8(FRAME_FLAGE_LOGGED)
};

typedef struct Frame {
    uint8_t type;  /**< protocol specific field type. E.g. NBSS.HDR or SMB.DATA */
    uint8_t flags; /**< frame flags: FRAME_FLAG_* */
    uint8_t event_cnt;
    // TODO one event per frame enough?
    uint8_t events[4];  /**< per frame store for events */
    uint64_t offset;    /**< offset from the start of the stream */
    int64_t len;
    int64_t id;
    uint64_t tx_id; /**< tx_id to match this frame. UINT64T_MAX if not used. */
    uint64_t inspect_progress; /**< inspection tracker relative to the start of the frame */
} Frame;

#define FRAMES_STATIC_CNT 3

typedef struct Frames {
    uint16_t cnt;
    uint16_t dyn_size;     /**< size in elements of `dframes` */
    uint32_t left_edge_rel;
    uint64_t base_id;
    Frame sframes[FRAMES_STATIC_CNT]; /**< static frames */
    Frame *dframes;                   /**< dynamically allocated space for more frames */
#ifdef DEBUG
    uint8_t ipproto;
    AppProto alproto;
#endif
} Frames;

typedef struct FramesContainer {
    Frames toserver;
    Frames toclient;
} FramesContainer;

void FramesFree(Frames *frames);
void FramesPrune(Flow *f, Packet *p);

Frame *AppLayerFrameNewByPointer(Flow *f, const StreamSlice *stream_slice,
        const uint8_t *frame_start, const int64_t len, int dir, uint8_t frame_type);
Frame *AppLayerFrameNewByRelativeOffset(Flow *f, const StreamSlice *stream_slice,
        const uint32_t frame_start_rel, const int64_t len, int dir, uint8_t frame_type);
Frame *AppLayerFrameNewByAbsoluteOffset(Flow *f, const StreamSlice *stream_slice,
        const uint64_t frame_start, const int64_t len, int dir, uint8_t frame_type);
void AppLayerFrameDump(Flow *f);

Frame *FrameGetByIndex(Frames *frames, const uint32_t idx);
Frame *FrameGetById(Frames *frames, const int64_t id);
Frame *FrameGetLastOpenByType(Frames *frames, const uint8_t frame_type);

Frame *AppLayerFrameGetById(Flow *f, const int direction, const FrameId frame_id);
Frame *AppLayerFrameGetLastOpenByType(Flow *f, const int direction, const uint8_t frame_type);

FrameId AppLayerFrameGetId(Frame *r);

void AppLayerFrameAddEvent(Frame *frame, uint8_t e);
void AppLayerFrameAddEventById(Flow *f, const int dir, const FrameId id, uint8_t e);
void AppLayerFrameSetLength(Frame *frame, int64_t len);
void AppLayerFrameSetLengthById(Flow *f, const int dir, const FrameId id, int64_t len);
void AppLayerFrameSetTxId(Frame *r, uint64_t tx_id);
void AppLayerFrameSetTxIdById(Flow *f, const int dir, const FrameId id, uint64_t tx_id);

void AppLayerFramesSlide(Flow *f, const uint32_t slide, const uint8_t direction);

FramesContainer *AppLayerFramesGetContainer(Flow *f);
FramesContainer *AppLayerFramesSetupContainer(Flow *f);

void FrameConfigInit(void);
void FrameConfigEnableAll(void);
void FrameConfigEnable(const AppProto p, const uint8_t type);

#endif
