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


/** \file
 *
 * \author Giuseppe Longo <giuseppelng@gmail.com>
 * \author Victor Julien <victor@inliniac.net>
 *
 */

#include "suricata-common.h"
#include "suricata.h"

#include "detect.h"
#include "detect-engine.h"
#include "detect-engine-mpm.h"
#include "detect-engine-content-inspection.h"
#include "detect-engine-prefilter.h"
#include "detect-engine-filedata.h"
#include "detect-engine-hsbd.h"

#include "app-layer-parser.h"

static InspectionBuffer *GetBuffer(InspectionBufferMultipleForList *fb, uint32_t id)
{
    if (id >= fb->size) {
        uint32_t old_size = fb->size;
        uint32_t new_size = id + 1;
        uint32_t grow_by = new_size - old_size;
        SCLogDebug("size is %u, need %u, so growing by %u", old_size, new_size, grow_by);

        void *ptr = SCRealloc(fb->inspection_buffers, (id + 1) * sizeof(InspectionBuffer));
        if (ptr == NULL)
            return NULL;

        InspectionBuffer *to_zero = (InspectionBuffer *)ptr + old_size;
        SCLogDebug("fb->inspection_buffers %p ptr %p to_zero %p", fb->inspection_buffers, ptr, to_zero);
        memset((uint8_t *)to_zero, 0, (grow_by * sizeof(InspectionBuffer)));
        fb->inspection_buffers = ptr;
        fb->size = new_size;
    }

    InspectionBuffer *buffer = &fb->inspection_buffers[id];
    SCLogDebug("using file_data buffer %p", buffer);
    return buffer;
}

static InspectionBuffer *FiledataGetDataCallback(DetectEngineThreadCtx *det_ctx,
        const DetectEngineTransforms *transforms,
        Flow *f, uint8_t flow_flags, File *cur_file,
        int list_id, int local_file_id, bool first)
{
    SCEnter();

    InspectionBufferMultipleForList *fb = &det_ctx->multi_inspect_buffers[list_id];
    InspectionBuffer *buffer = GetBuffer(fb, local_file_id);
    if (buffer == NULL)
        return NULL;
    if (!first && buffer->inspect != NULL)
        return buffer;

    const uint64_t file_size = FileDataSize(cur_file);
    const DetectEngineCtx *de_ctx = det_ctx->de_ctx;
    const uint32_t content_limit = de_ctx->filedata_config[f->alproto].content_limit;
    const uint32_t content_inspect_min_size = de_ctx->filedata_config[f->alproto].content_inspect_min_size;
    // TODO this is unused, is that right?
    //const uint32_t content_inspect_window = de_ctx->filedata_config[f->alproto].content_inspect_window;

    SCLogDebug("content_limit %u, content_inspect_min_size %u",
                content_limit, content_inspect_min_size);

    SCLogDebug("file %p size %"PRIu64", state %d", cur_file, file_size, cur_file->state);

    /* no new data */
    if (cur_file->content_inspected == file_size) {
        SCLogDebug("no new data");
        return NULL;
    }

    if (file_size == 0) {
        SCLogDebug("no data to inspect for this transaction");
        return NULL;
    }

    if ((content_limit == 0 || file_size < content_limit) &&
        file_size < content_inspect_min_size &&
        !(flow_flags & STREAM_EOF) && !(cur_file->state > FILE_STATE_OPENED)) {
        SCLogDebug("we still haven't seen the entire content. "
                   "Let's defer content inspection till we see the "
                   "entire content.");
        return NULL;
    }

    const uint8_t *data;
    uint32_t data_len;

    StreamingBufferGetDataAtOffset(cur_file->sb,
            &data, &data_len,
            cur_file->content_inspected);
    InspectionBufferSetup(buffer, data, data_len);
    buffer->inspect_offset = cur_file->content_inspected;
    InspectionBufferApplyTransforms(buffer, transforms);

    /* update inspected tracker */
    cur_file->content_inspected = file_size;
    SCLogDebug("content_inspected %"PRIu64, cur_file->content_inspected);

    SCLogDebug("file_data buffer %p, data %p len %u offset %"PRIu64,
        buffer, buffer->inspect, buffer->inspect_len, buffer->inspect_offset);

    SCReturnPtr(buffer, "InspectionBuffer");
}

int DetectEngineInspectFiledata(
        DetectEngineCtx *de_ctx, DetectEngineThreadCtx *det_ctx,
        const DetectEngineAppInspectionEngine *engine,
        const Signature *s,
        Flow *f, uint8_t flags, void *alstate, void *txv, uint64_t tx_id)
{
    int r = 0;
    int match = 0;

    // TODO remove
    if (f->alproto == ALPROTO_HTTP) {
        abort();
    }

    const DetectEngineTransforms *transforms = NULL;
    if (!engine->mpm) {
        transforms = engine->v2.transforms;
    }

    FileContainer *ffc = AppLayerParserGetFiles(f->proto, f->alproto,
                                                f->alstate, flags);
    if (ffc == NULL) {
        return DETECT_ENGINE_INSPECT_SIG_NO_MATCH;
    }

    int local_file_id = 0;
    File *file = ffc->head;
    for (; file != NULL; file = file->next) {
        if (file->txid != tx_id)
            continue;

        InspectionBuffer *buffer = FiledataGetDataCallback(det_ctx,
            transforms, f, flags, file, engine->sm_list, local_file_id, false);
        if (buffer == NULL)
            continue;

        det_ctx->buffer_offset = 0;
        det_ctx->discontinue_matching = 0;
        det_ctx->inspection_recursion_counter = 0;
        match = DetectEngineContentInspection(de_ctx, det_ctx, s, engine->smd,
                                              f,
                                              (uint8_t *)buffer->inspect,
                                              buffer->inspect_len,
                                              buffer->inspect_offset,
                                              DETECT_ENGINE_CONTENT_INSPECTION_MODE_STATE, NULL);
        if (match == 1) {
            r = 1;
            break;
        }
        local_file_id++;
    }

    if (r == 1)
        return DETECT_ENGINE_INSPECT_SIG_MATCH;
    else
        return DETECT_ENGINE_INSPECT_SIG_NO_MATCH;
}

typedef struct PrefilterMpmFiledata {
    int list_id;
    const MpmCtx *mpm_ctx;
    const DetectEngineTransforms *transforms;
} PrefilterMpmFiledata;

/** \brief Filedata Filedata Mpm prefilter callback
 *
 *  \param det_ctx detection engine thread ctx
 *  \param p packet to inspect
 *  \param f flow to inspect
 *  \param txv tx to inspect
 *  \param pectx inspection context
 */
static void PrefilterTxFiledata(DetectEngineThreadCtx *det_ctx,
        const void *pectx,
        Packet *p, Flow *f, void *txv,
        const uint64_t idx, const uint8_t flags)
{
    SCEnter();

    const PrefilterMpmFiledata *ctx = (const PrefilterMpmFiledata *)pectx;
    const MpmCtx *mpm_ctx = ctx->mpm_ctx;
    const int list_id = ctx->list_id;

    FileContainer *ffc = AppLayerParserGetFiles(f->proto, f->alproto,
                                                f->alstate, flags);
    int local_file_id = 0;
    if (ffc != NULL) {
        File *file = ffc->head;
        for (; file != NULL; file = file->next) {
            if (file->txid != idx)
                continue;

            InspectionBuffer *buffer = FiledataGetDataCallback(det_ctx,
                    ctx->transforms, f, flags, file, list_id, local_file_id, true);
            if (buffer == NULL)
                continue;

            if (buffer->inspect_len >= mpm_ctx->minlen) {
                (void)mpm_table[mpm_ctx->mpm_type].Search(mpm_ctx,
                        &det_ctx->mtcu, &det_ctx->pmq,
                        buffer->inspect, buffer->inspect_len);
            }
        }
    }
}

static void PrefilterMpmFiledataFree(void *ptr)
{
    SCFree(ptr);
}

int PrefilterMpmFiledataRegister(DetectEngineCtx *de_ctx,
        SigGroupHead *sgh, MpmCtx *mpm_ctx,
        const DetectMpmAppLayerRegistery *mpm_reg, int list_id)
{
    PrefilterMpmFiledata *pectx = SCCalloc(1, sizeof(*pectx));
    if (pectx == NULL)
        return -1;
    pectx->list_id = list_id;
    pectx->mpm_ctx = mpm_ctx;
    pectx->transforms = &mpm_reg->v2.transforms;

    return PrefilterAppendTxEngine(de_ctx, sgh, PrefilterTxFiledata,
            mpm_reg->v2.alproto, mpm_reg->v2.tx_min_progress,
            pectx, PrefilterMpmFiledataFree, mpm_reg->pname);
}

#ifdef UNITTESTS
#include "tests/detect-engine-filedata.c"
#endif /* UNITTESTS */

