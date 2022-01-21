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

#include "stream-tcp.h"

#include "util-profiling.h"
#include "util-validate.h"
#include "util-print.h"

void DetectRunPrefilterFrame(DetectEngineThreadCtx *det_ctx, const SigGroupHead *sgh, Packet *p,
        const Frames *frames, const Frame *frame, const AppProto alproto, const uint32_t idx)
{
    SCLogDebug("pcap_cnt %" PRIu64, p->pcap_cnt);
    PrefilterEngine *engine = sgh->frame_engines;
    do {
        BUG_ON(engine->alproto == ALPROTO_UNKNOWN);
        if (engine->alproto == alproto && engine->ctx.frame_type == frame->type) {
            SCLogDebug("frame %p engine %p", frame, engine);
            PREFILTER_PROFILING_START;
            engine->cb.PrefilterFrame(det_ctx, engine->pectx, p, frames, frame, idx);
            PREFILTER_PROFILING_END(det_ctx, engine->gid);
        }
        if (engine->is_last)
            break;
        engine++;
    } while (1);
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
    // SCLogDebug("frame: %p", frame);
    // PrintRawDataFp(stdout, data, MIN(32, data_len));

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

int DetectRunFrameInspectRule(ThreadVars *tv, DetectEngineThreadCtx *det_ctx, const Signature *s,
        Flow *f, Packet *p, const Frames *frames, const Frame *frame, const uint32_t idx)
{
    BUG_ON(s->frame_inspect == NULL);

    SCLogDebug("inspecting rule %u against frame %p/%" PRIi64 "/%s", s->id, frame, frame->id,
            AppLayerParserGetFrameNameById(f->proto, f->alproto, frame->type));

    for (DetectEngineFrameInspectionEngine *e = s->frame_inspect; e != NULL; e = e->next) {
        if (frame->type == e->type) {
            // TODO check alproto, direction?

            // TODO there should be only one inspect engine for this frame, ever?

            if (e->v1.Callback(det_ctx, e, s, p, frames, frame, idx) == true) {
                SCLogDebug("sid %u: e %p Callback returned true", s->id, e);
                return true;
            }
            SCLogDebug("sid %u: e %p Callback returned false", s->id, e);
        } else {
            SCLogDebug(
                    "sid %u: e %p not for frame type %u (want %u)", s->id, e, frame->type, e->type);
        }
    }
    return false;
}

/** \internal
 *  \brief setup buffer based on frame in UDP payload
 */
static InspectionBuffer *DetectFrame2InspectBufferUdp(DetectEngineThreadCtx *det_ctx,
        const DetectEngineTransforms *transforms, Packet *p, InspectionBuffer *buffer,
        const Frames *frames, const Frame *frame, const int list_id, const uint32_t idx,
        const bool first)
{
    DEBUG_VALIDATE_BUG_ON(frame->rel_offset >= p->payload_len);
    if (frame->rel_offset >= p->payload_len)
        return NULL;

    int frame_len = frame->len != -1 ? frame->len : p->payload_len - frame->rel_offset;
    uint8_t ci_flags = DETECT_CI_FLAGS_START;

    if (frame->rel_offset + frame_len > p->payload_len) {
        frame_len = p->payload_len - frame->rel_offset;
    } else {
        ci_flags |= DETECT_CI_FLAGS_END;
    }
    const uint8_t *data = p->payload + frame->rel_offset;
    const uint32_t data_len = frame_len;

    SCLogDebug("packet %" PRIu64 " -> frame %p/%" PRIi64 "/%s rel_offset %" PRIi64
               " type %u len %" PRIi64,
            p->pcap_cnt, frame, frame->id,
            AppLayerParserGetFrameNameById(p->flow->proto, p->flow->alproto, frame->type),
            frame->rel_offset, frame->type, frame->len);
    // PrintRawDataFp(stdout, data, MIN(64,data_len));

    InspectionBufferSetupMulti(buffer, transforms, data, data_len);
    buffer->inspect_offset = 0;
    buffer->flags = ci_flags;
    return buffer;
}

InspectionBuffer *DetectFrame2InspectBuffer(DetectEngineThreadCtx *det_ctx,
        const DetectEngineTransforms *transforms, Packet *p, const Frames *frames,
        const Frame *frame, const int list_id, const uint32_t idx, const bool first)
{
    // TODO do we really need multiple buffer support here?
    InspectionBuffer *buffer = InspectionBufferMultipleForListGet(det_ctx, list_id, idx);
    if (buffer == NULL)
        return NULL;
    if (!first && buffer->inspect != NULL)
        return buffer;

    BUG_ON(p->flow == NULL);

    if (p->proto == IPPROTO_UDP) {
        return DetectFrame2InspectBufferUdp(
                det_ctx, transforms, p, buffer, frames, frame, list_id, idx, first);
    }

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

    SCLogDebug("frame %" PRIi64 ", len %" PRIi64, frame->id, frame->len);

    uint32_t data_len = 0;
    const uint8_t *data = NULL;

    uint64_t offset = STREAM_BASE_OFFSET(stream);
    if (frame->rel_offset > 0 || frames->progress_rel) {
        uint64_t frame_offset = 0;
        if (frame->rel_offset >= 0) {
            frame_offset = MAX((uint64_t)frame->rel_offset, (uint64_t)frames->progress_rel);
        } else {
            frame_offset = (uint64_t)frames->progress_rel;
        }
        offset += frame_offset;
    }

    const bool eof = ssn->state == TCP_CLOSED || PKT_IS_PSEUDOPKT(p);

    const uint64_t usable = StreamTcpGetUsable(stream, eof);
    if (usable <= offset)
        return NULL;

    // TODO GAP handling
    if (StreamingBufferGetDataAtOffset(&stream->sb, &data, &data_len, offset) == 0) {
        return NULL;
    }

    const uint64_t data_right_edge = offset + data_len;
    if (data_right_edge > usable)
        data_len = usable - offset;

    const int64_t frame_start_abs_offset = frame->rel_offset + (int64_t)STREAM_BASE_OFFSET(stream);
    const uint64_t usable_right_edge = MIN(data_right_edge, usable);

    bool have_end = false;

    if (frame->len > 0) {
        const int64_t frame_avail_data_abs = (int64_t)usable_right_edge;
        const int64_t frame_end_abs_offset = frame_start_abs_offset + frame->len;
        have_end = (int64_t)usable_right_edge >= frame_end_abs_offset;

        SCLogDebug("frame_end_abs_offset %" PRIi64 ", usable_right_edge %" PRIu64,
                frame_end_abs_offset, usable_right_edge);

        const int64_t avail_from_frame = MIN(frame_end_abs_offset, frame_avail_data_abs) - offset;
        if (avail_from_frame < (int64_t)data_len) {
            SCLogDebug("adjusted data len from %u to %" PRIi64, data_len, avail_from_frame);
            data_len = (uint32_t)avail_from_frame;
        }
    }
    const bool have_start = frame_start_abs_offset == (int64_t)offset;

    if (data == NULL || data_len == 0) {
        return NULL;
    }

    // TODO use eof too?
    SCLogDebug("stream->min_inspect_depth %u", stream->min_inspect_depth);
    if (data_len < frame->len && data_len < stream->min_inspect_depth) {
        if (ssn->flags & STREAMTCP_FLAG_APP_LAYER_DISABLED || ssn->state == TCP_CLOSED ||
                stream->flags & STREAMTCP_STREAM_FLAG_DEPTH_REACHED) {
            SCLogDebug("EOF use available data: %u bytes", data_len);
        } else {
            SCLogDebug("not enough data to inspect now: have %u, want %u", data_len,
                    stream->min_inspect_depth);
            return NULL;
        }
    }

    const uint8_t ci_flags =
            (have_start ? DETECT_CI_FLAGS_START : 0) | (have_end ? DETECT_CI_FLAGS_END : 0);
    SCLogDebug("packet %" PRIu64 " -> frame %p/%" PRIi64 "/%s rel_offset %" PRIi64
               " type %u len %" PRIi64 " ci_flags %02x (start:%s, end:%s)",
            p->pcap_cnt, frame, frame->id,
            AppLayerParserGetFrameNameById(p->flow->proto, p->flow->alproto, frame->type),
            frame->rel_offset, frame->type, frame->len, ci_flags,
            (ci_flags & DETECT_CI_FLAGS_START) ? "true" : "false",
            (ci_flags & DETECT_CI_FLAGS_END) ? "true" : "false");
    // PrintRawDataFp(stdout, data, MIN(32,data_len));

    InspectionBufferSetupMulti(buffer, transforms, data, data_len);
    buffer->inspect_offset = frame->rel_offset < 0 ? -1 * frame->rel_offset : 0; // TODO review/test
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
    SCLogDebug("frame %p rel_offset %" PRIi64 " type %u len %" PRIi64
               " ci_flags %02x (start:%s, end:%s)",
            frame, frame->rel_offset, frame->type, frame->len, ci_flags,
            (ci_flags & DETECT_CI_FLAGS_START) ? "true" : "false",
            (ci_flags & DETECT_CI_FLAGS_END) ? "true" : "false");
    SCLogDebug("buffer %p offset %" PRIu64 " len %u ci_flags %02x (start:%s, end:%s)", buffer,
            buffer->inspect_offset, buffer->inspect_len, ci_flags,
            (ci_flags & DETECT_CI_FLAGS_START) ? "true" : "false",
            (ci_flags & DETECT_CI_FLAGS_END) ? "true" : "false");
    // PrintRawDataFp(stdout, data, data_len);
    // PrintRawDataFp(stdout, data, MIN(64, data_len));
#endif
    BUG_ON((int64_t)data_len > frame->len);

    // TODO don't call if matching needs frame end and DETECT_CI_FLAGS_END not set
    // TODO same for start
    int r = DetectEngineContentInspection(det_ctx->de_ctx, det_ctx, s, engine->smd, p, p->flow,
            (uint8_t *)data, data_len, offset, buffer->flags,
            DETECT_ENGINE_CONTENT_INSPECTION_MODE_FRAME);
    if (r == 1) {
        return DETECT_ENGINE_INSPECT_SIG_MATCH;
    } else {
        return DETECT_ENGINE_INSPECT_SIG_NO_MATCH;
    }
}
