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
 *
 */

#include "suricata-common.h"
#include "suricata.h"

#include "app-layer-parser.h"
#include "app-layer-frames.h"

#include "detect-engine.h"
#include "detect-engine-prefilter.h"
#include "detect-engine-content-inspection.h"
#include "detect-engine-mpm.h"
#include "detect-engine-frame.h"

#include "util-profiling.h"
#include "util-validate.h"
#include "util-print.h"

void PrefilterFrames(DetectEngineThreadCtx *det_ctx, const SigGroupHead *sgh, Packet *p,
        const uint8_t flags, const AppProto alproto)
{
    BUG_ON(p->flow == NULL);
    BUG_ON(p->flow->protoctx == NULL);

    const TcpSession *ssn = p->flow->protoctx;
    if (ssn->flags & STREAMTCP_FLAG_APP_LAYER_DISABLED) {
        return;
    }

    FramesContainer *frames_container = AppLayerFramesGetContainer(p->flow);
    if (frames_container == NULL) {
        return;
    }

    Frames *frames;
    // TcpStream *stream;
    if (PKT_IS_TOSERVER(p)) {
        // stream = &ssn->client;
        frames = &frames_container->toserver;
    } else {
        // stream = &ssn->server;
        frames = &frames_container->toclient;
    }

    for (uint32_t idx = 0; idx < frames->cnt; idx++) {
        SCLogDebug("frame %u", idx);
        const Frame *frame = FrameGetByIndex(frames, idx);
        SCLogDebug("frame %p", frame);
        if (frame != NULL) {
            PrefilterEngine *engine = sgh->frame_engines;
            do {
                SCLogDebug("frame %p engine %p", frame, engine);
                BUG_ON(engine->alproto == ALPROTO_UNKNOWN);
                if (engine->alproto == alproto && engine->ctx.frame_type == frame->type) {
                    PREFILTER_PROFILING_START;
                    engine->cb.PrefilterFrame(det_ctx, engine->pectx, p, frames, frame, idx);
                    PREFILTER_PROFILING_END(det_ctx, engine->gid);
                }
                if (engine->is_last)
                    break;
                engine++;
            } while (1);
        }
    }
}

/* generic mpm for frame engines */

// TODO same as Generic?
typedef struct PrefilterMpmFrameCtx {
    int list_id;
    const MpmCtx *mpm_ctx;
    const DetectEngineTransforms *transforms;
} PrefilterMpmFrameCtx;

/** \brief Generic Mpm prefilter callback
 *
 *  \param det_ctx detection engine thread ctx
 *  \param frames container for the frames
 *  \param frame frame to inspect
 *  \param pectx inspection context
 */
static void PrefilterMpmFrame(DetectEngineThreadCtx *det_ctx, const void *pectx, Packet *p,
        const Frames *frames, const Frame *frame, const uint32_t idx)
{
    SCEnter();

    const PrefilterMpmFrameCtx *ctx = (const PrefilterMpmFrameCtx *)pectx;
    const MpmCtx *mpm_ctx = ctx->mpm_ctx;
    SCLogDebug("running on list %d -> frame field type %u", ctx->list_id, frame->type);
    // BUG_ON(frame->type != ctx->type);

    InspectionBuffer *buffer = DetectFrame2InspectBuffer(
            det_ctx, ctx->transforms, p, frames, frame, ctx->list_id, idx, true);
    if (buffer == NULL)
        return;

    const uint32_t data_len = buffer->inspect_len;
    const uint8_t *data = buffer->inspect;

    SCLogDebug("mpm'ing buffer:");
    // SCLogNotice("frame: %p", frame);
    // PrintRawDataFp(stdout, data, MIN(64, data_len));

    if (data != NULL && data_len >= mpm_ctx->minlen) {
        (void)mpm_table[mpm_ctx->mpm_type].Search(
                mpm_ctx, &det_ctx->mtcu, &det_ctx->pmq, data, data_len);
        SCLogDebug("det_ctx->pmq.rule_id_array_cnt %u", det_ctx->pmq.rule_id_array_cnt);
    }
}

static void PrefilterMpmFrameFree(void *ptr)
{
    SCFree(ptr);
}

int PrefilterGenericMpmFrameRegister(DetectEngineCtx *de_ctx, SigGroupHead *sgh, MpmCtx *mpm_ctx,
        const DetectBufferMpmRegistery *mpm_reg, int list_id)
{
    SCEnter();
    PrefilterMpmFrameCtx *pectx = SCCalloc(1, sizeof(*pectx));
    if (pectx == NULL)
        return -1;
    pectx->list_id = list_id;
    BUG_ON(mpm_reg->frame_v1.alproto == ALPROTO_UNKNOWN);
    pectx->mpm_ctx = mpm_ctx;
    pectx->transforms = &mpm_reg->transforms;

    int r = PrefilterAppendFrameEngine(de_ctx, sgh, PrefilterMpmFrame, mpm_reg->frame_v1.alproto,
            mpm_reg->frame_v1.type, pectx, PrefilterMpmFrameFree, mpm_reg->pname);
    if (r != 0) {
        SCFree(pectx);
    }
    return r;
}

bool DetectEngineFrameInspectionRun(ThreadVars *tv, DetectEngineThreadCtx *det_ctx,
        const Signature *s, Flow *f, Packet *p, uint8_t *alert_flags)
{
    SCEnter();

    if (s->frame_inspect == NULL)
        return true;

    FramesContainer *frames_container = AppLayerFramesGetContainer(p->flow);
    if (frames_container == NULL) {
        return false;
    }

    Frames *frames;
    if (PKT_IS_TOSERVER(p)) {
        frames = &frames_container->toserver;
    } else {
        frames = &frames_container->toclient;
    }

    for (uint32_t idx = 0; idx < frames->cnt; idx++) {
        SCLogDebug("frame %u", idx);
        const Frame *frame = FrameGetByIndex(frames, idx);
        if (frame != NULL) {
            for (DetectEngineFrameInspectionEngine *e = s->frame_inspect; e != NULL; e = e->next) {
                if (frame->type == e->type) {
                    // TODO check alproto, type, direction?

                    // TODO there should be only one inspect engine for this frame, ever?

                    if (e->v1.Callback(det_ctx, e, s, p, frames, frame, idx) == true) {
                        SCLogDebug("sid %u: e %p Callback returned true", s->id, e);

                        *alert_flags |= PACKET_ALERT_FLAG_FRAME;
                        det_ctx->flags |= DETECT_ENGINE_THREAD_CTX_FRAME_ID_SET;
                        det_ctx->frame_id = frame->id;
                        return true;
                    }
                    SCLogDebug("sid %u: e %p Callback returned false", s->id, e);
                } else {
                    SCLogDebug("sid %u: e %p not for frame type %u (want %u)", s->id, e,
                            frame->type, e->type);
                }
            }
        }
    }

    SCLogDebug("sid %u: returning true", s->id);
    return false;
}

InspectionBuffer *DetectFrame2InspectBuffer(DetectEngineThreadCtx *det_ctx,
        const DetectEngineTransforms *transforms, Packet *p, const Frames *frames,
        const Frame *frame, const int list_id, const uint32_t idx, const bool first)
{
    InspectionBuffer *buffer = InspectionBufferMultipleForListGet(det_ctx, list_id, idx);
    if (buffer == NULL)
        return NULL;
    if (!first && buffer->inspect != NULL)
        return buffer;

    BUG_ON(p->flow == NULL);
    BUG_ON(p->flow->protoctx == NULL);
    TcpSession *ssn = p->flow->protoctx;
    TcpStream *stream;
    if (PKT_IS_TOSERVER(p)) {
        stream = &ssn->client;
    } else {
        stream = &ssn->server;
    }

    /*
        stream:   [s                                           ]
        frame:          [r               ]
        progress:        |>p
            rel_offset: 10, len 100
            progress: 20
            avail: 90 (complete)

        stream:   [s            ]
        frame:          [r               ]
        progress:        |>p
            stream: 0, len 59
            rel_offset: 10, len 100
            progress: 20
            avail: 30 (incomplete)

        stream:          [s                                           ]
        frame:        [r               ]
        progress:              |>p
            stream: 0, len 200
            rel_offset: -30, len 100
            progress: 20
            avail: 50 (complete)
     */

    uint32_t data_len = 0;
    const uint8_t *data = NULL;

    uint32_t frame_offset = 0;
    uint64_t offset = STREAM_BASE_OFFSET(stream);
    if (frame->rel_offset > 0 || frames->progress_rel) {
        if (frame->rel_offset >= 0) {
            frame_offset = MAX((uint32_t)frame->rel_offset, frames->progress_rel);
        } else {
            frame_offset = frames->progress_rel;
        }
        offset += (uint64_t)frame_offset;
    }

    if (StreamingBufferGetDataAtOffset(&stream->sb, &data, &data_len, offset) == 0) {
        return NULL;
    }
    if (data == NULL || data_len == 0) {
        return NULL;
    }

    /* if the frame uses explicit length, adjust the data to it while taking offsets
     * into account. */
    if (frame->len >= 0) {
        if (frame->rel_offset >= 0 && frame_offset > (uint32_t)frame->rel_offset) {
            data_len = MIN(data_len, ((uint32_t)frame->len - (frame->rel_offset - frame_offset)));
        } else if (frame->rel_offset < 0) {
            data_len =
                    MIN(data_len, ((uint32_t)frame->len - (frame->rel_offset * -1 + frame_offset)));
        } else {
            data_len = MIN(data_len, (uint32_t)frame->len);
        }
        BUG_ON(data_len > (uint32_t)frame->len);
    }

    const bool have_start = (frame->rel_offset >= 0 && frame_offset <= (uint32_t)frame->rel_offset);
    //    uint64_t frame_process_start = STREAM_BASE_OFFSET(stream) + frames->progress_rel;
    //    uint64_t frame_le = STREAM_BASE_OFFSET(stream) + frame->rel_offset;
    uint64_t frame_re = STREAM_BASE_OFFSET(stream) + frame->rel_offset + frame->len;
    uint64_t data_re = offset + data_len;
    uint8_t ci_flags = have_start ? DETECT_CI_FLAGS_START : 0;
    if (frame_re <= data_re) {
        ci_flags |= DETECT_CI_FLAGS_END;
    }

    SCLogDebug("frame %p rel_offset %d type %u len %u ci_flags %02x (start:%s, end:%s)", frame,
            frame->rel_offset, frame->type, frame->len, ci_flags,
            (ci_flags & DETECT_CI_FLAGS_START) ? "true" : "false",
            (ci_flags & DETECT_CI_FLAGS_END) ? "true" : "false");
    // PrintRawDataFp(stdout, data, MIN(64, data_len));

    InspectionBufferSetupMulti(buffer, transforms, data, data_len);
    buffer->inspect_offset = frame->rel_offset < 0 ? -1 * frame->rel_offset : 0;
    buffer->flags = ci_flags;
    return buffer;
}

/**
 * \brief Do the content inspection & validation for a signature
 *
 * \param de_ctx Detection engine context
 * \param det_ctx Detection engine thread context
 * \param s Signature to inspect
 * \param p Packet
 * \param frame stream frame to inspect
 *
 * \retval 0 no match.
 * \retval 1 match.
 */
int DetectEngineInspectFrameBufferGeneric(DetectEngineThreadCtx *det_ctx,
        const DetectEngineFrameInspectionEngine *engine, const Signature *s, Packet *p,
        const Frames *frames, const Frame *frame, const uint32_t idx)
{
    const int list_id = engine->sm_list;
    SCLogDebug("running inspect on %d", list_id);

    SCLogDebug("list %d transforms %p", engine->sm_list, engine->v1.transforms);

    /* if prefilter didn't already run, we need to consider transformations */
    const DetectEngineTransforms *transforms = NULL;
    if (!engine->mpm) {
        transforms = engine->v1.transforms;
    }

    const InspectionBuffer *buffer =
            DetectFrame2InspectBuffer(det_ctx, transforms, p, frames, frame, list_id, idx, false);
    if (unlikely(buffer == NULL)) {
        return DETECT_ENGINE_INSPECT_SIG_NO_MATCH;
    }

    const uint32_t data_len = buffer->inspect_len;
    const uint8_t *data = buffer->inspect;
    const uint64_t offset = buffer->inspect_offset;

    det_ctx->discontinue_matching = 0;
    det_ctx->buffer_offset = 0;
    det_ctx->inspection_recursion_counter = 0;
#ifdef DEBUG
    const uint8_t ci_flags = buffer->flags;
    SCLogDebug("frame %p rel_offset %d type %u len %u ci_flags %02x (start:%s, end:%s)", frame,
            frame->rel_offset, frame->type, frame->len, ci_flags,
            (ci_flags & DETECT_CI_FLAGS_START) ? "true" : "false",
            (ci_flags & DETECT_CI_FLAGS_END) ? "true" : "false");
    SCLogDebug("buffer %p offset %" PRIu64 " len %u ci_flags %02x (start:%s, end:%s)", buffer,
            buffer->inspect_offset, buffer->inspect_len, ci_flags,
            (ci_flags & DETECT_CI_FLAGS_START) ? "true" : "false",
            (ci_flags & DETECT_CI_FLAGS_END) ? "true" : "false");
    // PrintRawDataFp(stdout, data, data_len);
    // PrintRawDataFp(stdout, data, MIN(64, data_len));
#endif
    BUG_ON((int32_t)data_len > frame->len);

    int r = DetectEngineContentInspection(det_ctx->de_ctx, det_ctx, s, engine->smd, p, p->flow,
            (uint8_t *)data, data_len, offset, buffer->flags,
            DETECT_ENGINE_CONTENT_INSPECTION_MODE_RECORD);
    if (r == 1) {
        return DETECT_ENGINE_INSPECT_SIG_MATCH;
    } else {
        return DETECT_ENGINE_INSPECT_SIG_NO_MATCH;
    }
}
