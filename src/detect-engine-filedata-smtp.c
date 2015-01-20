/* Copyright (C) 2015 Open Information Security Foundation
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
 *
 */

#include "suricata-common.h"
#include "suricata.h"
#include "decode.h"

#include "detect.h"
#include "detect-engine.h"
#include "detect-engine-mpm.h"
#include "detect-parse.h"
#include "detect-engine-state.h"
#include "detect-engine-content-inspection.h"

#include "flow-util.h"
#include "util-debug.h"
#include "util-print.h"
#include "flow.h"

#include "stream-tcp.h"

#include "app-layer-parser.h"

#include "util-unittest.h"
#include "util-unittest-helper.h"
#include "app-layer.h"
#include "app-layer-smtp.h"
#include "app-layer-protos.h"

#include "conf.h"
#include "conf-yaml-loader.h"

#define BUFFER_STEP 50

static inline int SMTPCreateSpace(DetectEngineThreadCtx *det_ctx, uint16_t size)
{
    void *ptmp;
    if (size > det_ctx->smtp_buffers_size) {
        ptmp = SCRealloc(det_ctx->smtp,
                         (det_ctx->smtp_buffers_size + BUFFER_STEP) * sizeof(FiledataReassembledBody));
        if (ptmp == NULL) {
            SCFree(det_ctx->hsbd);
            det_ctx->smtp = NULL;
            det_ctx->smtp_buffers_size = 0;
            det_ctx->smtp_buffers_list_len = 0;
            return -1;
        }
        det_ctx->smtp = ptmp;

        memset(det_ctx->smtp + det_ctx->smtp_buffers_size, 0, BUFFER_STEP * sizeof(FiledataReassembledBody));
        det_ctx->smtp_buffers_size += BUFFER_STEP;
    }
    for (int i = det_ctx->smtp_buffers_list_len; i < (size); i++) {
        det_ctx->smtp[i].buffer_len = 0;
        det_ctx->smtp[i].offset = 0;
    }

    return 0;
}

static uint8_t *DetectEngineSMTPGetBufferForTX(uint64_t tx_id,
                                               DetectEngineCtx *de_ctx,
                                               DetectEngineThreadCtx *det_ctx,
                                               Flow *f, File *curr_file,
                                               uint8_t flags,
                                               uint32_t *buffer_len,
                                               uint32_t *stream_start_offset)
{
    int index = 0;
    uint8_t *buffer = NULL;
    *buffer_len = 0;
    *stream_start_offset = 0;
    FileData *curr_chunk = NULL;

    if (det_ctx->smtp_buffers_list_len == 0) {
        if (SMTPCreateSpace(det_ctx, 1) < 0)
            goto end;
        index = 0;

        if (det_ctx->smtp_buffers_list_len == 0) {
            det_ctx->smtp_start_tx_id = tx_id;
        }
        det_ctx->smtp_buffers_list_len++;
    } else {
        if ((tx_id - det_ctx->smtp_start_tx_id) < det_ctx->smtp_buffers_list_len) {
            if (det_ctx->smtp[(tx_id - det_ctx->smtp_start_tx_id)].buffer_len != 0) {
                *buffer_len = det_ctx->smtp[(tx_id - det_ctx->smtp_start_tx_id)].buffer_len;
                *stream_start_offset = det_ctx->smtp[(tx_id - det_ctx->smtp_start_tx_id)].offset;
                return det_ctx->smtp[(tx_id - det_ctx->smtp_start_tx_id)].buffer;
            }
        } else {
            if (SMTPCreateSpace(det_ctx, (tx_id - det_ctx->smtp_start_tx_id) + 1) < 0)
                goto end;

            if (det_ctx->smtp_buffers_list_len == 0) {
                det_ctx->smtp_start_tx_id = tx_id;
            }
            det_ctx->smtp_buffers_list_len++;
        }
        index = (tx_id - det_ctx->smtp_start_tx_id);
    }

    if (curr_file != NULL) {
        curr_chunk = curr_file->chunks_head;
        while (curr_chunk != NULL) {
            /* see if we can filter out chunks */

            /* see if we need to grow the buffer */
            if (det_ctx->smtp[index].buffer == NULL || (det_ctx->smtp[index].buffer_len + curr_chunk->len) > det_ctx->smtp[index].buffer_size) {
                void *ptmp;
                det_ctx->smtp[index].buffer_size += curr_chunk->len * 2;

                if ((ptmp = SCRealloc(det_ctx->smtp[index].buffer, det_ctx->smtp[index].buffer_size)) == NULL) {
                    SCFree(det_ctx->smtp[index].buffer);
                    det_ctx->smtp[index].buffer = NULL;
                    det_ctx->smtp[index].buffer_size = 0;
                    det_ctx->smtp[index].buffer_len = 0;
                    goto end;
                }
                det_ctx->smtp[index].buffer = ptmp;
            }
            memcpy(det_ctx->smtp[index].buffer + det_ctx->smtp[index].buffer_len, curr_chunk->data, curr_chunk->len);
            det_ctx->smtp[index].buffer_len += curr_chunk->len;

            curr_chunk = curr_chunk->next;
        }
    }

    buffer = det_ctx->smtp[index].buffer;
    *buffer_len = det_ctx->smtp[index].buffer_len;
    *stream_start_offset = det_ctx->smtp[index].offset;
end:
    return buffer;
}

int DetectEngineInspectSMTPFiledata(ThreadVars *tv,
                                    DetectEngineCtx *de_ctx,                                                     
                                    DetectEngineThreadCtx *det_ctx,                                              
                                    Signature *s, Flow *f, uint8_t flags,                                        
                                    void *alstate,
                                    void *tx, uint64_t tx_id)
{
    SMTPState *smtp_state = (SMTPState *)alstate;
    FileContainer *ffc = smtp_state->files_ts;
    int r = 0;
    int match = 0;
    uint32_t buffer_len = 0;
    uint32_t stream_start_offset = 0;
    uint8_t *buffer = 0;

    if (ffc != NULL) {
        File *file = ffc->head;
        for (; file != NULL; file = file->next) {
            buffer = DetectEngineSMTPGetBufferForTX(tx_id,
                                                    de_ctx, det_ctx,
                                                    f, file,
                                                    flags,
                                                    &buffer_len,
                                                    &stream_start_offset);
        if (buffer_len == 0)
            goto end;

        det_ctx->buffer_offset = 0;
        det_ctx->discontinue_matching = 0;
        det_ctx->inspection_recursion_counter = 0;
        match = DetectEngineContentInspection(de_ctx, det_ctx, s, s->sm_lists[DETECT_SM_LIST_FILEDATA],
                                              f,
                                              buffer,
                                              buffer_len,
                                              stream_start_offset,
                                              DETECT_ENGINE_CONTENT_INSPECTION_MODE_FD_SMTP, NULL);
        if (match == 1)
            r = 1;
        }
    }

end:
    if (r == 1)
        return DETECT_ENGINE_INSPECT_SIG_MATCH;
    else
        return DETECT_ENGINE_INSPECT_SIG_NO_MATCH;
}

void DetectEngineCleanSMTPBuffers(DetectEngineThreadCtx *det_ctx)
{
    if (det_ctx->smtp_buffers_list_len > 0) {
        for (int i = 0; i < det_ctx->smtp_buffers_list_len; i++) {
            det_ctx->smtp[i].buffer_len = 0;
            det_ctx->smtp[i].offset = 0;
        }
    }
    det_ctx->smtp_buffers_list_len = 0;
    det_ctx->smtp_start_tx_id = 0;

    return;
}
