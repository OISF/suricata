/* Copyright (C) 2021-2023 Open Information Security Foundation
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

struct FrameStreamData {
    // shared between prefilter and inspect
    DetectEngineThreadCtx *det_ctx;
    const DetectEngineTransforms *transforms;
    const Frame *frame;
    int list_id;
    uint32_t idx; /**< multi buffer idx, incremented for each stream chunk */

    // inspection only
    const DetectEngineFrameInspectionEngine *inspect_engine;
    const Signature *s;
    int inspect_result; // DETECT_ENGINE_INSPECT_SIG_MATCH / DETECT_ENGINE_INSPECT_SIG_NO_MATCH
    Packet *p;

    // prefilter only
    const MpmCtx *mpm_ctx;

    uint64_t requested_stream_offset;
};

static bool SetupStreamCallbackData(struct FrameStreamData *dst, const TcpSession *ssn,
        const TcpStream *stream, DetectEngineThreadCtx *det_ctx,
        const DetectEngineTransforms *transforms, const Frames *_frames, const Frame *frame,
        const int list_id, const bool eof);

static bool BufferSetup(struct FrameStreamData *fsd, InspectionBuffer *buffer, const uint8_t *input,
        const uint32_t input_len, const uint64_t input_offset);
static void BufferSetupUdp(InspectionBuffer *buffer, const Frame *frame, const Packet *p,
        const DetectEngineTransforms *transforms);

void DetectRunPrefilterFrame(DetectEngineThreadCtx *det_ctx, const SigGroupHead *sgh, Packet *p,
        const Frames *frames, const Frame *frame, const AppProto alproto)
{
    SCLogDebug("pcap_cnt %" PRIu64, p->pcap_cnt);
    PrefilterEngine *engine = sgh->frame_engines;
    do {
        BUG_ON(engine->alproto == ALPROTO_UNKNOWN);
        if (engine->alproto == alproto && engine->ctx.frame_type == frame->type) {
            SCLogDebug("frame %p engine %p", frame, engine);
            PREFILTER_PROFILING_START(det_ctx);
            engine->cb.PrefilterFrame(det_ctx, engine->pectx, p, frames, frame);
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

static int FrameStreamDataPrefilterFunc(
        void *cb_data, const uint8_t *input, const uint32_t input_len, const uint64_t input_offset)
{
    struct FrameStreamData *fsd = cb_data;
    SCLogDebug("prefilter: fsd %p { det_ctx:%p, transforms:%p, frame:%p, list_id:%d, idx:%u, "
               "data_offset:%" PRIu64 "}, input: %p, input_len:%u, input_offset:%" PRIu64,
            fsd, fsd->det_ctx, fsd->transforms, fsd->frame, fsd->list_id, fsd->idx,
            fsd->requested_stream_offset, input, input_len, input_offset);
    // PrintRawDataFp(stdout, input, input_len);

    InspectionBuffer *buffer =
            InspectionBufferMultipleForListGet(fsd->det_ctx, fsd->list_id, fsd->idx++);
    if (buffer == NULL) {
        return 0;
    }
    SCLogDebug("buffer %p idx %u", buffer, fsd->idx);

    const int more_chunks = BufferSetup(fsd, buffer, input, input_len, input_offset);

    const uint32_t data_len = buffer->inspect_len;
    const uint8_t *data = buffer->inspect;
    DetectEngineThreadCtx *det_ctx = fsd->det_ctx;
    const MpmCtx *mpm_ctx = fsd->mpm_ctx;

    if (data != NULL && data_len >= mpm_ctx->minlen) {
        // PrintRawDataFp(stdout, data, data_len);

        (void)mpm_table[mpm_ctx->mpm_type].Search(
                mpm_ctx, &det_ctx->mtc, &det_ctx->pmq, data, data_len);
        SCLogDebug("det_ctx->pmq.rule_id_array_cnt %u", det_ctx->pmq.rule_id_array_cnt);
        PREFILTER_PROFILING_ADD_BYTES(det_ctx, data_len);
    }
    return more_chunks;
}

/** \brief Generic Mpm prefilter callback
 *
 *  \param det_ctx detection engine thread ctx
 *  \param frames container for the frames
 *  \param frame frame to inspect
 *  \param pectx inspection context
 */
static void PrefilterMpmFrame(DetectEngineThreadCtx *det_ctx, const void *pectx, Packet *p,
        const Frames *frames, const Frame *frame)
{
    SCEnter();

    const PrefilterMpmFrameCtx *ctx = (const PrefilterMpmFrameCtx *)pectx;
    const MpmCtx *mpm_ctx = ctx->mpm_ctx;

    SCLogDebug("packet:%" PRIu64 ", prefilter running on list %d -> frame field type %u",
            p->pcap_cnt, ctx->list_id, frame->type);
    if (p->proto == IPPROTO_UDP) {
        // TODO can we use single here? Could it conflict with TCP?
        InspectionBuffer *buffer = InspectionBufferMultipleForListGet(det_ctx, ctx->list_id, 0);
        if (buffer == NULL)
            return;
        DEBUG_VALIDATE_BUG_ON(frame->offset >= p->payload_len);
        if (frame->offset >= p->payload_len)
            return;

        BufferSetupUdp(buffer, frame, p, ctx->transforms);
        const uint32_t data_len = buffer->inspect_len;
        const uint8_t *data = buffer->inspect;

        // PrintRawDataFp(stdout, data, data_len);

        if (data != NULL && data_len >= mpm_ctx->minlen) {
            (void)mpm_table[mpm_ctx->mpm_type].Search(
                    mpm_ctx, &det_ctx->mtc, &det_ctx->pmq, data, data_len);
            SCLogDebug("det_ctx->pmq.rule_id_array_cnt %u", det_ctx->pmq.rule_id_array_cnt);
            PREFILTER_PROFILING_ADD_BYTES(det_ctx, data_len);
        }
    } else if (p->proto == IPPROTO_TCP) {
        BUG_ON(p->flow->protoctx == NULL);
        TcpSession *ssn = p->flow->protoctx;
        TcpStream *stream;
        if (PKT_IS_TOSERVER(p)) {
            stream = &ssn->client;
        } else {
            stream = &ssn->server;
        }
        const bool eof = ssn->state == TCP_CLOSED || PKT_IS_PSEUDOPKT(p);

        struct FrameStreamData fsd;
        memset(&fsd, 0, sizeof(fsd));
        fsd.mpm_ctx = mpm_ctx;

        if (SetupStreamCallbackData(&fsd, ssn, stream, det_ctx, ctx->transforms, frames, frame,
                    ctx->list_id, eof) == true) {
            StreamReassembleForFrame(ssn, stream, FrameStreamDataPrefilterFunc, &fsd,
                    fsd.requested_stream_offset, eof);
        }
    } else {
        DEBUG_VALIDATE_BUG_ON(1);
    }
    SCLogDebug("packet:%" PRIu64
               ", prefilter done running on list %d -> frame field type %u; have %u matches",
            p->pcap_cnt, ctx->list_id, frame->type, det_ctx->pmq.rule_id_array_cnt);
}

static void PrefilterMpmFrameFree(void *ptr)
{
    SCFree(ptr);
}

int PrefilterGenericMpmFrameRegister(DetectEngineCtx *de_ctx, SigGroupHead *sgh, MpmCtx *mpm_ctx,
        const DetectBufferMpmRegistry *mpm_reg, int list_id)
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

bool DetectRunFrameInspectRule(ThreadVars *tv, DetectEngineThreadCtx *det_ctx, const Signature *s,
        Flow *f, Packet *p, const Frames *frames, const Frame *frame)
{
    BUG_ON(s->frame_inspect == NULL);

    SCLogDebug("inspecting rule %u against frame %p/%" PRIi64 "/%s", s->id, frame, frame->id,
            AppLayerParserGetFrameNameById(f->proto, f->alproto, frame->type));

    for (DetectEngineFrameInspectionEngine *e = s->frame_inspect; e != NULL; e = e->next) {
        if (frame->type == e->type) {
            // TODO check alproto, direction?

            // TODO there should be only one inspect engine for this frame, ever?

            if (e->v1.Callback(det_ctx, e, s, p, frames, frame) == true) {
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

static void BufferSetupUdp(InspectionBuffer *buffer, const Frame *frame, const Packet *p,
        const DetectEngineTransforms *transforms)
{
    uint8_t ci_flags = DETECT_CI_FLAGS_START;
    uint32_t frame_len;
    if (frame->len == -1) {
        frame_len = p->payload_len - frame->offset;
    } else {
        frame_len = (uint32_t)frame->len;
    }
    if (frame->offset + frame_len > p->payload_len) {
        frame_len = p->payload_len - frame->offset;
    } else {
        ci_flags |= DETECT_CI_FLAGS_END;
    }
    const uint8_t *data = p->payload + frame->offset;
    const uint32_t data_len = frame_len;

    SCLogDebug("packet %" PRIu64 " -> frame %p/%" PRIi64 "/%s offset %" PRIu64
               " type %u len %" PRIi64,
            p->pcap_cnt, frame, frame->id,
            AppLayerParserGetFrameNameById(p->flow->proto, p->flow->alproto, frame->type),
            frame->offset, frame->type, frame->len);

    InspectionBufferSetupMulti(buffer, transforms, data, data_len);
    buffer->inspect_offset = 0;
    buffer->flags = ci_flags;
}

/** \internal
 *  \brief setup buffer based on frame in UDP payload
 */
static int DetectFrameInspectUdp(DetectEngineThreadCtx *det_ctx,
        const DetectEngineFrameInspectionEngine *engine, const Signature *s,
        const DetectEngineTransforms *transforms, Packet *p, const Frames *_frames,
        const Frame *frame, const int list_id)
{
    SCLogDebug("packet:%" PRIu64 ", inspect: s:%p s->id:%u, transforms:%p", p->pcap_cnt, s, s->id,
            transforms);

    // TODO can we use single here? Could it conflict with TCP?
    InspectionBuffer *buffer = InspectionBufferMultipleForListGet(det_ctx, list_id, 0);
    if (buffer == NULL) {
        if (engine->match_on_null) {
            return DETECT_ENGINE_INSPECT_SIG_MATCH;
        }
        return DETECT_ENGINE_INSPECT_SIG_NO_MATCH;
    }

    DEBUG_VALIDATE_BUG_ON(frame->offset >= p->payload_len);
    if (frame->offset >= p->payload_len)
        return DETECT_ENGINE_INSPECT_SIG_NO_MATCH;

    if (!buffer->initialized)
        BufferSetupUdp(buffer, frame, p, transforms);
    DEBUG_VALIDATE_BUG_ON(!buffer->initialized);
    if (buffer->inspect == NULL)
        return DETECT_ENGINE_INSPECT_SIG_NO_MATCH;

    const bool match = DetectEngineContentInspection(det_ctx->de_ctx, det_ctx, s, engine->smd, p,
            p->flow, buffer->inspect, buffer->inspect_len, 0, buffer->flags,
            DETECT_ENGINE_CONTENT_INSPECTION_MODE_FRAME);
    if (match) {
        SCLogDebug("match!");
        return DETECT_ENGINE_INSPECT_SIG_MATCH;
    } else {
        return DETECT_ENGINE_INSPECT_SIG_NO_MATCH;
    }
}

/**
 *  \retval bool true if callback should run again */
static bool BufferSetup(struct FrameStreamData *fsd, InspectionBuffer *buffer, const uint8_t *input,
        const uint32_t input_len, const uint64_t input_offset)
{
    const Frame *frame = fsd->frame;
    /* so: relative to start of stream */
    const uint64_t so_input_re = input_offset + input_len;
    const uint64_t so_frame_re =
            frame->offset + (uint64_t)frame->len; // TODO if eof, set to available data?
    SCLogDebug("frame offset:%" PRIu64, frame->offset);
    const uint8_t *data = input;
    uint8_t ci_flags = 0;
    uint32_t data_len;

    /* fo: frame offset; offset relative to start of the frame */
    uint64_t fo_inspect_offset = 0;

    if (frame->offset == 0 && input_offset == 0) {
        ci_flags |= DETECT_CI_FLAGS_START;
        SCLogDebug("have frame data start");

        if (frame->len >= 0) {
            data_len = MIN(input_len, frame->len);
            if (data_len == frame->len) {
                ci_flags |= DETECT_CI_FLAGS_END;
                SCLogDebug("have frame data end");
            }
        } else {
            data_len = input_len;
        }
    } else {
        const uint64_t so_frame_inspect_offset = frame->inspect_progress + frame->offset;
        const uint64_t so_inspect_offset = MAX(input_offset, so_frame_inspect_offset);
        fo_inspect_offset = so_inspect_offset - frame->offset;

        if (frame->offset >= input_offset) {
            ci_flags |= DETECT_CI_FLAGS_START;
            SCLogDebug("have frame data start");
        }
        if (frame->len >= 0) {
            if (fo_inspect_offset >= (uint64_t)frame->len) {
                SCLogDebug("data entirely past frame (%" PRIu64 " > %" PRIi64 ")",
                        fo_inspect_offset, frame->len);
                InspectionBufferSetupMultiEmpty(buffer);
                return false;
            }

            /* in: relative to start of input data */
            BUG_ON(so_inspect_offset < input_offset);
            const uint32_t in_data_offset = so_inspect_offset - input_offset;
            data += in_data_offset;

            uint32_t in_data_excess = 0;
            if (so_input_re >= so_frame_re) {
                ci_flags |= DETECT_CI_FLAGS_END;
                SCLogDebug("have frame data end");
                in_data_excess = so_input_re - so_frame_re;
            }
            data_len = input_len - in_data_offset - in_data_excess;
        } else {
            /* in: relative to start of input data */
            BUG_ON(so_inspect_offset < input_offset);
            const uint32_t in_data_offset = so_inspect_offset - input_offset;
            data += in_data_offset;
            data_len = input_len - in_data_offset;
        }
    }
    // PrintRawDataFp(stdout, data, data_len);
    SCLogDebug("fsd->transforms %p", fsd->transforms);
    InspectionBufferSetupMulti(buffer, fsd->transforms, data, data_len);
    SCLogDebug("inspect_offset %" PRIu64, fo_inspect_offset);
    buffer->inspect_offset = fo_inspect_offset;
    buffer->flags = ci_flags;

    if (frame->len >= 0 && so_input_re >= so_frame_re) {
        SCLogDebug("have the full frame, we can set progress accordingly (%" PRIu64 " > %" PRIu64
                   ")",
                so_input_re, so_frame_re);
        fsd->det_ctx->frame_inspect_progress =
                MAX(fo_inspect_offset + data_len, fsd->det_ctx->frame_inspect_progress);
    } else {
        fsd->det_ctx->frame_inspect_progress =
                MAX(fo_inspect_offset + data_len, fsd->det_ctx->frame_inspect_progress);
        /* in IPS mode keep a sliding window */
        const bool ips = StreamTcpInlineMode();
        if (ips) {
            if (fsd->det_ctx->frame_inspect_progress < 2500)
                fsd->det_ctx->frame_inspect_progress = 0;
            else
                fsd->det_ctx->frame_inspect_progress -= 2500;
        }
        SCLogDebug("ips %s inspect_progress %" PRIu64, BOOL2STR(ips),
                fsd->det_ctx->frame_inspect_progress);
    }

    /* keep going as long as there is possibly still data for this frame */
    const bool ret = (frame->len >= 0 && so_input_re >= so_frame_re);
    SCLogDebug("buffer set up, more to do: %s", BOOL2STR(ret));
    return ret;
}

static int FrameStreamDataInspectFunc(
        void *cb_data, const uint8_t *input, const uint32_t input_len, const uint64_t input_offset)
{
    struct FrameStreamData *fsd = cb_data;
    SCLogDebug("inspect: fsd %p { det_ctx:%p, transforms:%p, s:%p, s->id:%u, frame:%p, list_id:%d, "
               "idx:%u, "
               "requested_stream_offset:%" PRIu64
               "}, input: %p, input_len:%u, input_offset:%" PRIu64,
            fsd, fsd->det_ctx, fsd->transforms, fsd->s, fsd->s->id, fsd->frame, fsd->list_id,
            fsd->idx, fsd->requested_stream_offset, input, input_len, input_offset);
    // PrintRawDataFp(stdout, input, input_len);

    InspectionBuffer *buffer =
            InspectionBufferMultipleForListGet(fsd->det_ctx, fsd->list_id, fsd->idx++);
    if (buffer == NULL) {
        if (fsd->inspect_engine->match_on_null && fsd->idx == 0) {
            fsd->inspect_result = DETECT_ENGINE_INSPECT_SIG_MATCH;
        }
        return 0;
    }
    SCLogDebug("buffer %p idx %u", buffer, fsd->idx);

    /* if we've not done so already, set up the buffer */
    int more_chunks = 1;
    if (!buffer->initialized) {
        more_chunks = BufferSetup(fsd, buffer, input, input_len, input_offset);
    }
    DEBUG_VALIDATE_BUG_ON(!buffer->initialized);
    if (buffer->inspect == NULL) {
        return more_chunks;
    }

    const uint32_t data_len = buffer->inspect_len;
    const uint8_t *data = buffer->inspect;
    const uint64_t data_offset = buffer->inspect_offset;
    DetectEngineThreadCtx *det_ctx = fsd->det_ctx;

    const DetectEngineFrameInspectionEngine *engine = fsd->inspect_engine;
    const Signature *s = fsd->s;
    Packet *p = fsd->p;

#ifdef DEBUG
    const uint8_t ci_flags = buffer->flags;
    SCLogDebug("frame %p offset %" PRIu64 " type %u len %" PRIi64
               " ci_flags %02x (start:%s, end:%s)",
            fsd->frame, fsd->frame->offset, fsd->frame->type, fsd->frame->len, ci_flags,
            (ci_flags & DETECT_CI_FLAGS_START) ? "true" : "false",
            (ci_flags & DETECT_CI_FLAGS_END) ? "true" : "false");
    SCLogDebug("buffer %p offset %" PRIu64 " len %u ci_flags %02x (start:%s, end:%s)", buffer,
            buffer->inspect_offset, buffer->inspect_len, ci_flags,
            (ci_flags & DETECT_CI_FLAGS_START) ? "true" : "false",
            (ci_flags & DETECT_CI_FLAGS_END) ? "true" : "false");
    // PrintRawDataFp(stdout, data, data_len);
    // PrintRawDataFp(stdout, data, MIN(64, data_len));
#endif
    BUG_ON(fsd->frame->len > 0 && (int64_t)data_len > fsd->frame->len);

    const bool match = DetectEngineContentInspection(det_ctx->de_ctx, det_ctx, s, engine->smd, p,
            p->flow, data, data_len, data_offset, buffer->flags,
            DETECT_ENGINE_CONTENT_INSPECTION_MODE_FRAME);
    if (match) {
        SCLogDebug("DETECT_ENGINE_INSPECT_SIG_MATCH");
        fsd->inspect_result = DETECT_ENGINE_INSPECT_SIG_MATCH;
    } else {
        SCLogDebug("DETECT_ENGINE_INSPECT_SIG_NO_MATCH");
    }
    return more_chunks;
}

static bool SetupStreamCallbackData(struct FrameStreamData *dst, const TcpSession *ssn,
        const TcpStream *stream, DetectEngineThreadCtx *det_ctx,
        const DetectEngineTransforms *transforms, const Frames *_frames, const Frame *frame,
        const int list_id, const bool eof)
{
    SCLogDebug("frame %" PRIi64 ", len %" PRIi64 ", offset %" PRIu64 ", inspect_progress %" PRIu64,
            frame->id, frame->len, frame->offset, frame->inspect_progress);

    const uint64_t frame_offset = frame->offset;
    const uint64_t usable = StreamDataRightEdge(stream, eof);
    if (usable <= frame_offset)
        return false;

    uint64_t want = frame->inspect_progress;
    if (frame->len == -1) {
        if (eof) {
            want = usable;
        } else {
            want += 2500;
        }
    } else {
        /* don't have the full frame yet */
        if (frame->offset + frame->len > usable) {
            want += 2500;
        } else {
            want = frame->offset + frame->len;
        }
    }

    const bool ips = StreamTcpInlineMode();

    const uint64_t have = usable;
    if (!ips && have < want) {
        SCLogDebug("wanted %" PRIu64 " bytes, got %" PRIu64, want, have);
        return false;
    }

    const uint64_t available_data = usable - STREAM_BASE_OFFSET(stream);
    SCLogDebug("check inspection for having 2500 bytes: %" PRIu64, available_data);
    if (!ips && !eof && available_data < 2500 &&
            (frame->len < 0 || frame->len > (int64_t)available_data)) {
        SCLogDebug("skip inspection until we have 2500 bytes (have %" PRIu64 ")", available_data);
        return false;
    }

    const uint64_t offset =
            MAX(STREAM_BASE_OFFSET(stream), frame->offset + frame->inspect_progress);

    dst->det_ctx = det_ctx;
    dst->transforms = transforms;
    dst->frame = frame;
    dst->list_id = list_id;
    dst->requested_stream_offset = offset;
    return true;
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
        const Frames *frames, const Frame *frame)
{
    /* if prefilter didn't already run, we need to consider transformations */
    const DetectEngineTransforms *transforms = NULL;
    if (!engine->mpm) {
        transforms = engine->v1.transforms;
    }
    const int list_id = engine->sm_list;
    SCLogDebug("running inspect on %d", list_id);

    if (p->proto == IPPROTO_UDP) {
        return DetectFrameInspectUdp(det_ctx, engine, s, transforms, p, frames, frame, list_id);
    }
    DEBUG_VALIDATE_BUG_ON(p->proto != IPPROTO_TCP);

    SCLogDebug("packet:%" PRIu64 ", frame->id:%" PRIu64
               ", list:%d, transforms:%p, s:%p, s->id:%u, engine:%p",
            p->pcap_cnt, frame->id, engine->sm_list, engine->v1.transforms, s, s->id, engine);

    BUG_ON(p->flow->protoctx == NULL);
    TcpSession *ssn = p->flow->protoctx;
    TcpStream *stream;
    if (PKT_IS_TOSERVER(p)) {
        stream = &ssn->client;
    } else {
        stream = &ssn->server;
    }
    const bool eof = ssn->state == TCP_CLOSED || PKT_IS_PSEUDOPKT(p);

    struct FrameStreamData fsd;
    memset(&fsd, 0, sizeof(fsd));
    fsd.inspect_engine = engine;
    fsd.s = s;
    fsd.inspect_result = DETECT_ENGINE_INSPECT_SIG_NO_MATCH;
    fsd.p = p;

    if (SetupStreamCallbackData(
                &fsd, ssn, stream, det_ctx, transforms, frames, frame, list_id, eof) == false) {
        return DETECT_ENGINE_INSPECT_SIG_NO_MATCH;
    }
    StreamReassembleForFrame(
            ssn, stream, FrameStreamDataInspectFunc, &fsd, fsd.requested_stream_offset, eof);

    return fsd.inspect_result;
}
