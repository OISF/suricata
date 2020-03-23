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
#include "app-layer-records.h"

#include "detect-engine.h"
#include "detect-engine-prefilter.h"
#include "detect-engine-content-inspection.h"
#include "detect-engine-mpm.h"
#include "detect-engine-record.h"

#include "util-profiling.h"
#include "util-validate.h"
#include "util-print.h"

void PrefilterRecords(DetectEngineThreadCtx *det_ctx, const SigGroupHead *sgh, Packet *p,
        const uint8_t flags, const AppProto alproto)
{
    assert(p->flow);
    assert(p->flow->protoctx);

    const TcpSession *ssn = p->flow->protoctx;
    if (ssn->flags & STREAMTCP_FLAG_APP_LAYER_DISABLED) {
        return;
    }

    RecordsContainer *records_container = AppLayerRecordsGetContainer(p->flow);
    if (records_container == NULL) {
        return;
    }

    Records *recs;
    //TcpStream *stream;
    if (PKT_IS_TOSERVER(p)) {
        //stream = &ssn->client;
        recs = &records_container->toserver;
    } else {
        //stream = &ssn->server;
        recs = &records_container->toclient;
    }

    for (uint32_t idx = 0; idx < recs->cnt; idx++) {
        SCLogDebug("rec %u", idx);
        const Record *rec = RecordGetByIndex(recs, idx);
        SCLogDebug("rec %p", rec);
        if (rec != NULL) {
            PrefilterEngine *engine = sgh->rec_engines;
            do {
                SCLogDebug("rec %p engine %p", rec, engine);
                assert(engine->alproto != ALPROTO_UNKNOWN);
                if (engine->alproto == alproto && engine->ctx.rec_type == rec->type) {
                    PREFILTER_PROFILING_START;
                    engine->cb.PrefilterRecord(det_ctx, engine->pectx, p, recs, rec, idx);
                    PREFILTER_PROFILING_END(det_ctx, engine->gid);
                }
                if (engine->is_last)
                    break;
                engine++;
            } while (1);
        }
    }
}

/* generic mpm for rec engines */

// TODO same as Generic?
typedef struct PrefilterMpmRecordCtx {
    int list_id;
    const MpmCtx *mpm_ctx;
    const DetectEngineTransforms *transforms;
} PrefilterMpmRecordCtx;

/** \brief Generic Mpm prefilter callback
 *
 *  \param det_ctx detection engine thread ctx
 *  \param recs container for the recs
 *  \param rec rec to inspect
 *  \param pectx inspection context
 */
static void PrefilterMpmRecord(DetectEngineThreadCtx *det_ctx, const void *pectx, Packet *p,
        const Records *recs, const Record *rec, const uint32_t idx)
{
    SCEnter();

    const PrefilterMpmRecordCtx *ctx = (const PrefilterMpmRecordCtx *)pectx;
    const MpmCtx *mpm_ctx = ctx->mpm_ctx;
    SCLogDebug("running on list %d -> rec field type %u", ctx->list_id, rec->type);
    // BUG_ON(rec->type != ctx->type);

    InspectionBuffer *buffer = DetectRecord2InspectBuffer(
            det_ctx, ctx->transforms, p, recs, rec, ctx->list_id, idx, true);
    if (buffer == NULL)
        return;

    const uint32_t data_len = buffer->inspect_len;
    const uint8_t *data = buffer->inspect;

    SCLogDebug("mpm'ing buffer:");
    // SCLogNotice("rec: %p", rec);
    // PrintRawDataFp(stdout, data, MIN(64, data_len));

    if (data != NULL && data_len >= mpm_ctx->minlen) {
        (void)mpm_table[mpm_ctx->mpm_type].Search(
                mpm_ctx, &det_ctx->mtcu, &det_ctx->pmq, data, data_len);
        SCLogDebug("det_ctx->pmq.rule_id_array_cnt %u", det_ctx->pmq.rule_id_array_cnt);
    }
}

static void PrefilterMpmRecordFree(void *ptr)
{
    SCFree(ptr);
}

int PrefilterGenericMpmRecordRegister(DetectEngineCtx *de_ctx, SigGroupHead *sgh, MpmCtx *mpm_ctx,
        const DetectBufferMpmRegistery *mpm_reg, int list_id)
{
    SCEnter();
    PrefilterMpmRecordCtx *pectx = SCCalloc(1, sizeof(*pectx));
    if (pectx == NULL)
        return -1;
    pectx->list_id = list_id;
    BUG_ON(mpm_reg->record_v1.alproto == ALPROTO_UNKNOWN);
    pectx->mpm_ctx = mpm_ctx;
    pectx->transforms = &mpm_reg->transforms;

    int r = PrefilterAppendRecordEngine(de_ctx, sgh, PrefilterMpmRecord, mpm_reg->record_v1.alproto,
            mpm_reg->record_v1.type, pectx, PrefilterMpmRecordFree, mpm_reg->pname);
    if (r != 0) {
        SCFree(pectx);
    }
    return r;
}

bool DetectEngineRecordInspectionRun(ThreadVars *tv, DetectEngineThreadCtx *det_ctx,
        const Signature *s, Flow *f, Packet *p, uint8_t *alert_flags)
{
    SCEnter();

    if (s->rec_inspect == NULL)
        return true;

    RecordsContainer *records_container = AppLayerRecordsGetContainer(p->flow);
    if (records_container == NULL) {
        return false;
    }

    Records *recs;
    if (PKT_IS_TOSERVER(p)) {
        recs = &records_container->toserver;
    } else {
        recs = &records_container->toclient;
    }

    for (uint32_t idx = 0; idx < recs->cnt; idx++) {
        SCLogDebug("rec %u", idx);
        const Record *rec = RecordGetByIndex(recs, idx);
        if (rec != NULL) {
            for (DetectEngineRecordInspectionEngine *e = s->rec_inspect; e != NULL; e = e->next) {
                if (rec->type == e->type) {
                    // TODO check alproto, type, direction?

                    // TODO there should be only one inspect engine for this rec, ever?

                    if (e->v1.Callback(det_ctx, e, s, p, recs, rec, idx) == true) {
                        SCLogDebug("sid %u: e %p Callback returned true", s->id, e);

                        *alert_flags |= PACKET_ALERT_FLAG_RECORD;
                        det_ctx->flags |= DETECT_ENGINE_THREAD_CTX_RECORD_ID_SET;
                        det_ctx->record_id = rec->id;
                        return true;
                    }
                    SCLogDebug("sid %u: e %p Callback returned false", s->id, e);
                } else {
                    SCLogDebug("sid %u: e %p not for rec type %u (want %u)", s->id, e, rec->type,
                            e->type);
                }
            }
        }
    }

    SCLogDebug("sid %u: returning true", s->id);
    return false;
}

InspectionBuffer *DetectRecord2InspectBuffer(DetectEngineThreadCtx *det_ctx,
        const DetectEngineTransforms *transforms, Packet *p, const Records *recs, const Record *rec, const int list_id,
        const uint32_t idx, const bool first)
{
    InspectionBuffer *buffer = InspectionBufferMultipleForListGet(det_ctx, list_id, idx);
    if (buffer == NULL)
        return NULL;
    if (!first && buffer->inspect != NULL)
        return buffer;

    assert(p->flow);
    assert(p->flow->protoctx);
    TcpSession *ssn = p->flow->protoctx;
    TcpStream *stream;
    if (PKT_IS_TOSERVER(p)) {
        stream = &ssn->client;
    } else {
        stream = &ssn->server;
    }


    /*
        stream:   [s                                           ]
        rec:          [r               ]
        progress:        |>p
            rel_offset: 10, len 100
            progress: 20
            avail: 90 (complete)

        stream:   [s            ]
        rec:          [r               ]
        progress:        |>p
            stream: 0, len 59
            rel_offset: 10, len 100
            progress: 20
            avail: 30 (incomplete)

        stream:          [s                                           ]
        rec:        [r               ]
        progress:              |>p
            stream: 0, len 200
            rel_offset: -30, len 100
            progress: 20
            avail: 50 (complete)
     */

    uint32_t data_len = 0;
    const uint8_t *data = NULL;

    uint32_t rec_offset = 0;
    uint64_t offset = STREAM_BASE_OFFSET(stream);
    if (rec->rel_offset > 0 || recs->progress_rel) {
        if (rec->rel_offset >= 0) {
            rec_offset = MAX((uint32_t)rec->rel_offset, recs->progress_rel);
        } else {
            rec_offset = recs->progress_rel;
        }
        offset += (uint64_t)rec_offset;
    }

    if (StreamingBufferGetDataAtOffset(&stream->sb, &data, &data_len, offset) == 0) {
        return NULL;
    }
    if (data == NULL || data_len == 0) {
        return NULL;
    }

    /* if the record uses explicit length, adjust the data to it while taking offsets
     * into account. */
    if (rec->len >= 0) {
        if (rec->rel_offset >= 0 && rec_offset > (uint32_t)rec->rel_offset) {
            data_len = MIN(data_len, ((uint32_t)rec->len - (rec->rel_offset - rec_offset)));
        } else if (rec->rel_offset < 0) {
            data_len = MIN(data_len, ((uint32_t)rec->len - (rec->rel_offset * -1 + rec_offset)));
        } else {
            data_len = MIN(data_len, (uint32_t)rec->len);
        }
        BUG_ON(data_len > (uint32_t)rec->len);
    }

    const bool have_start = (rec->rel_offset >= 0 && rec_offset <= (uint32_t)rec->rel_offset);
//    uint64_t rec_process_start = STREAM_BASE_OFFSET(stream) + recs->progress_rel;
//    uint64_t rec_le = STREAM_BASE_OFFSET(stream) + rec->rel_offset;
    uint64_t rec_re = STREAM_BASE_OFFSET(stream) + rec->rel_offset + rec->len;
    uint64_t data_re = offset + data_len;
    uint8_t ci_flags = have_start ? DETECT_CI_FLAGS_START : 0;
    if (rec_re <= data_re) {
        ci_flags |= DETECT_CI_FLAGS_END;
    }

    SCLogDebug("rec %p rel_offset %d type %u len %u ci_flags %02x (start:%s, end:%s)", rec,
            rec->rel_offset, rec->type, rec->len, ci_flags,
            (ci_flags & DETECT_CI_FLAGS_START) ? "true" : "false",
            (ci_flags & DETECT_CI_FLAGS_END) ? "true" : "false");
    // PrintRawDataFp(stdout, data, MIN(64, data_len));

    InspectionBufferSetupMulti(buffer, transforms, data, data_len);
    buffer->inspect_offset = rec->rel_offset < 0 ? -1 * rec->rel_offset : 0;
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
 * \param rec stream rec to inspect
 *
 * \retval 0 no match.
 * \retval 1 match.
 */
int DetectEngineInspectRecordBufferGeneric(DetectEngineThreadCtx *det_ctx,
        const DetectEngineRecordInspectionEngine *engine, const Signature *s, Packet *p,
        const Records *recs, const Record *rec, const uint32_t idx)
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
            DetectRecord2InspectBuffer(det_ctx, transforms, p, recs, rec, list_id, idx, false);
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
    SCLogDebug("rec %p rel_offset %d type %u len %u ci_flags %02x (start:%s, end:%s)", rec,
            rec->rel_offset, rec->type, rec->len, ci_flags,
            (ci_flags & DETECT_CI_FLAGS_START) ? "true" : "false",
            (ci_flags & DETECT_CI_FLAGS_END) ? "true" : "false");
    SCLogDebug("buffer %p offset %" PRIu64 " len %u ci_flags %02x (start:%s, end:%s)", buffer,
            buffer->inspect_offset, buffer->inspect_len, ci_flags,
            (ci_flags & DETECT_CI_FLAGS_START) ? "true" : "false",
            (ci_flags & DETECT_CI_FLAGS_END) ? "true" : "false");
    // PrintRawDataFp(stdout, data, data_len);
    // PrintRawDataFp(stdout, data, MIN(64, data_len));
#endif
    BUG_ON((int32_t)data_len > rec->len);

    int r = DetectEngineContentInspection(det_ctx->de_ctx, det_ctx, s, engine->smd, p, p->flow,
            (uint8_t *)data, data_len, offset, buffer->flags,
            DETECT_ENGINE_CONTENT_INSPECTION_MODE_RECORD);
    if (r == 1) {
        return DETECT_ENGINE_INSPECT_SIG_MATCH;
    } else {
        return DETECT_ENGINE_INSPECT_SIG_NO_MATCH;
    }
}
