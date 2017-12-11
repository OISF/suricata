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

#define BUFFER_STEP 50

static inline int FiledataCreateSpace(DetectEngineThreadCtx *det_ctx, uint16_t size)
{
    if (size > det_ctx->file_data_buffers_size) {
        uint16_t grow_by = size - det_ctx->file_data_buffers_size;
        grow_by = MAX(grow_by, BUFFER_STEP);

        void *ptmp = SCRealloc(det_ctx->file_data,
                         (det_ctx->file_data_buffers_size + grow_by) * sizeof(FiledataReassembledBody));
        if (ptmp == NULL) {
            SCFree(det_ctx->file_data);
            det_ctx->file_data = NULL;
            det_ctx->file_data_buffers_size = 0;
            det_ctx->file_data_buffers_list_len = 0;
            return -1;
        }
        det_ctx->file_data = ptmp;

        memset(det_ctx->file_data + det_ctx->file_data_buffers_size, 0, grow_by * sizeof(FiledataReassembledBody));
        det_ctx->file_data_buffers_size += grow_by;
    }
    uint16_t i;
    for (i = det_ctx->file_data_buffers_list_len;
            i < det_ctx->file_data_buffers_size; i++)
    {
        det_ctx->file_data[i].buffer_len = 0;
        det_ctx->file_data[i].offset = 0;
    }

    return 0;
}

static const uint8_t *DetectEngineFiledataGetBufferForTX(uint64_t tx_id,
                                               DetectEngineCtx *de_ctx,
                                               DetectEngineThreadCtx *det_ctx,
                                               Flow *f, File *curr_file,
                                               uint8_t flags,
                                               uint32_t *buffer_len,
                                               uint32_t *stream_start_offset)
{
    SCEnter();
    int index = 0;
    const uint8_t *buffer = NULL;
    *buffer_len = 0;
    *stream_start_offset = 0;
    uint64_t file_size = FileDataSize(curr_file);

    const uint32_t content_limit = de_ctx->filedata_config[f->alproto].content_limit;
    const uint32_t content_inspect_min_size = de_ctx->filedata_config[f->alproto].content_inspect_min_size;
    // TODO this is unused, is that right?
    //const uint32_t content_inspect_window = de_ctx->filedata_config[f->alproto].content_inspect_window;

    if (det_ctx->file_data_buffers_list_len == 0) {
        if (FiledataCreateSpace(det_ctx, 1) < 0)
            goto end;
        index = 0;

        if (det_ctx->file_data_buffers_list_len == 0) {
            det_ctx->file_data_start_tx_id = tx_id;
        }
        det_ctx->file_data_buffers_list_len++;
    } else {
        if ((tx_id - det_ctx->file_data_start_tx_id) < det_ctx->file_data_buffers_list_len) {
            if (det_ctx->file_data[(tx_id - det_ctx->file_data_start_tx_id)].buffer_len != 0) {
                *buffer_len = det_ctx->file_data[(tx_id - det_ctx->file_data_start_tx_id)].buffer_len;
                *stream_start_offset = det_ctx->file_data[(tx_id - det_ctx->file_data_start_tx_id)].offset;
                buffer = det_ctx->file_data[(tx_id - det_ctx->file_data_start_tx_id)].buffer;

                SCReturnPtr(buffer, "uint8_t");
            }
        } else {
            if (FiledataCreateSpace(det_ctx, (tx_id - det_ctx->file_data_start_tx_id) + 1) < 0)
                goto end;

            if (det_ctx->file_data_buffers_list_len == 0) {
                det_ctx->file_data_start_tx_id = tx_id;
            }
            det_ctx->file_data_buffers_list_len++;
        }
        index = (tx_id - det_ctx->file_data_start_tx_id);
    }

    SCLogDebug("content_limit %u, content_inspect_min_size %u",
                content_limit, content_inspect_min_size);

    SCLogDebug("file %p size %"PRIu64", state %d", curr_file, file_size, curr_file->state);

    /* no new data */
    if (curr_file->content_inspected == file_size) {
        SCLogDebug("no new data");
        goto end;
    }

    if (file_size == 0) {
        SCLogDebug("no data to inspect for this transaction");
        goto end;
    }

    if ((content_limit == 0 || file_size < content_limit) &&
        file_size < content_inspect_min_size &&
        !(flags & STREAM_EOF) && !(curr_file->state > FILE_STATE_OPENED)) {
        SCLogDebug("we still haven't seen the entire content. "
                   "Let's defer content inspection till we see the "
                   "entire content.");
        goto end;
    }

    StreamingBufferGetDataAtOffset(curr_file->sb,
            &det_ctx->file_data[index].buffer, &det_ctx->file_data[index].buffer_len,
            curr_file->content_inspected);

    det_ctx->file_data[index].offset = curr_file->content_inspected;

    /* update inspected tracker */
    curr_file->content_inspected = FileDataSize(curr_file);

    SCLogDebug("content_inspected %"PRIu64", offset %"PRIu64,
            curr_file->content_inspected, det_ctx->file_data[index].offset);

    buffer = det_ctx->file_data[index].buffer;
    *buffer_len = det_ctx->file_data[index].buffer_len;
    *stream_start_offset = det_ctx->file_data[index].offset;

end:
    SCLogDebug("buffer %p, len %u", buffer, *buffer_len);
    SCReturnPtr(buffer, "uint8_t");
}

int DetectEngineInspectFiledata(ThreadVars *tv,
        DetectEngineCtx *de_ctx, DetectEngineThreadCtx *det_ctx,
        const Signature *s, const SigMatchData *smd,
        Flow *f, uint8_t flags, void *alstate, void *tx, uint64_t tx_id)
{
    int r = 0;
    int match = 0;
    uint32_t buffer_len = 0;
    uint32_t stream_start_offset = 0;
    const uint8_t *buffer = 0;

    if (f->alproto == ALPROTO_HTTP) {
        return DetectEngineInspectHttpServerBody(tv, de_ctx, det_ctx, s,
                smd, f, flags, alstate, tx, tx_id);
    }

    FileContainer *ffc = AppLayerParserGetFiles(f->proto, f->alproto,
                                                f->alstate, flags);
    if (ffc == NULL) {
        return DETECT_ENGINE_INSPECT_SIG_NO_MATCH;
    }

    File *file = ffc->head;
    for (; file != NULL; file = file->next) {
        if (file->txid != tx_id)
            continue;

        buffer = DetectEngineFiledataGetBufferForTX(tx_id,
                de_ctx, det_ctx,
                f, file,
                flags,
                &buffer_len,
                &stream_start_offset);
        if (buffer_len == 0)
            continue;

        det_ctx->buffer_offset = 0;
        det_ctx->discontinue_matching = 0;
        det_ctx->inspection_recursion_counter = 0;
        match = DetectEngineContentInspection(de_ctx, det_ctx, s, smd,
                                              f,
                                              (uint8_t *)buffer,
                                              buffer_len,
                                              stream_start_offset,
                                              DETECT_ENGINE_CONTENT_INSPECTION_MODE_STATE, NULL);
        if (match == 1) {
            r = 1;
            break;
        }
    }

    if (r == 1)
        return DETECT_ENGINE_INSPECT_SIG_MATCH;
    else
        return DETECT_ENGINE_INSPECT_SIG_NO_MATCH;
}

void DetectEngineCleanFiledataBuffers(DetectEngineThreadCtx *det_ctx)
{
    if (det_ctx->file_data_buffers_list_len > 0) {
        for (int i = 0; i < det_ctx->file_data_buffers_list_len; i++) {
            det_ctx->file_data[i].buffer_len = 0;
            det_ctx->file_data[i].offset = 0;
        }
    }
    det_ctx->file_data_buffers_list_len = 0;
    det_ctx->file_data_start_tx_id = 0;

    return;
}

/** \brief Filedata Filedata Mpm prefilter callback
 *
 *  \param det_ctx detection engine thread ctx
 *  \param p packet to inspect
 *  \param f flow to inspect
 *  \param txv tx to inspect
 *  \param pectx inspection context
 */
void PrefilterTxFiledata(DetectEngineThreadCtx *det_ctx,
        const void *pectx,
        Packet *p, Flow *f, void *txv,
        const uint64_t idx, const uint8_t flags)
{
    SCEnter();

    const MpmCtx *mpm_ctx = (MpmCtx *)pectx;
    FileContainer *ffc = AppLayerParserGetFiles(f->proto, f->alproto,
                                                f->alstate, flags);
    if (ffc != NULL) {
        File *file = ffc->head;
        for (; file != NULL; file = file->next) {
            if (file->txid != idx)
                continue;

            uint32_t buffer_len = 0;
            uint32_t stream_start_offset = 0;

            const uint8_t *buffer = DetectEngineFiledataGetBufferForTX(idx,
                                                    det_ctx->de_ctx, det_ctx,
                                                    f, file,
                                                    flags,
                                                    &buffer_len,
                                                    &stream_start_offset);
            if (buffer != NULL && buffer_len >= mpm_ctx->minlen) {
                (void)mpm_table[mpm_ctx->mpm_type].Search(mpm_ctx,
                        &det_ctx->mtcu, &det_ctx->pmq, buffer, buffer_len);
            }
        }
    }
}

#ifdef UNITTESTS
#include "tests/detect-engine-filedata.c"
#endif /* UNITTESTS */

