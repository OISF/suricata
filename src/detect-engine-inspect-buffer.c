/* Copyright (C) 2025 Open Information Security Foundation
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

#include "suricata-common.h"
#include "detect-engine-inspect-buffer.h"
#include "detect.h"

#include "util-validate.h"

void InspectionBufferClean(DetectEngineThreadCtx *det_ctx)
{
    /* single buffers */
    for (uint32_t i = 0; i < det_ctx->inspect.to_clear_idx; i++) {
        const uint32_t idx = det_ctx->inspect.to_clear_queue[i];
        InspectionBuffer *buffer = &det_ctx->inspect.buffers[idx];
        buffer->inspect = NULL;
        buffer->initialized = false;
    }
    det_ctx->inspect.to_clear_idx = 0;

    /* multi buffers */
    for (uint32_t i = 0; i < det_ctx->multi_inspect.to_clear_idx; i++) {
        const uint32_t idx = det_ctx->multi_inspect.to_clear_queue[i];
        InspectionBufferMultipleForList *mbuffer = &det_ctx->multi_inspect.buffers[idx];
        for (uint32_t x = 0; x <= mbuffer->max; x++) {
            InspectionBuffer *buffer = &mbuffer->inspection_buffers[x];
            buffer->inspect = NULL;
            buffer->initialized = false;
        }
        mbuffer->init = 0;
        mbuffer->max = 0;
    }
    det_ctx->multi_inspect.to_clear_idx = 0;
}

InspectionBuffer *InspectionBufferGet(DetectEngineThreadCtx *det_ctx, const int list_id)
{
    return &det_ctx->inspect.buffers[list_id];
}

static InspectionBufferMultipleForList *InspectionBufferGetMulti(
        DetectEngineThreadCtx *det_ctx, const int list_id)
{
    InspectionBufferMultipleForList *buffer = &det_ctx->multi_inspect.buffers[list_id];
    if (!buffer->init) {
        det_ctx->multi_inspect.to_clear_queue[det_ctx->multi_inspect.to_clear_idx++] = list_id;
        buffer->init = 1;
    }
    return buffer;
}

/** \brief for a InspectionBufferMultipleForList get a InspectionBuffer
 *  \param fb the multiple buffer array
 *  \param local_id the index to get a buffer
 *  \param buffer the inspect buffer or NULL in case of error */
InspectionBuffer *InspectionBufferMultipleForListGet(
        DetectEngineThreadCtx *det_ctx, const int list_id, const uint32_t local_id)
{
    if (unlikely(local_id >= 1024)) {
        DetectEngineSetEvent(det_ctx, DETECT_EVENT_TOO_MANY_BUFFERS);
        return NULL;
    }

    InspectionBufferMultipleForList *fb = InspectionBufferGetMulti(det_ctx, list_id);

    if (local_id >= fb->size) {
        uint32_t old_size = fb->size;
        uint32_t new_size = local_id + 1;
        uint32_t grow_by = new_size - old_size;
        SCLogDebug("size is %u, need %u, so growing by %u", old_size, new_size, grow_by);

        SCLogDebug("fb->inspection_buffers %p", fb->inspection_buffers);
        void *ptr = SCRealloc(fb->inspection_buffers, (local_id + 1) * sizeof(InspectionBuffer));
        if (ptr == NULL)
            return NULL;

        InspectionBuffer *to_zero = (InspectionBuffer *)ptr + old_size;
        SCLogDebug("ptr %p to_zero %p", ptr, to_zero);
        memset((uint8_t *)to_zero, 0, (grow_by * sizeof(InspectionBuffer)));
        fb->inspection_buffers = ptr;
        fb->size = new_size;
    }

    fb->max = MAX(fb->max, local_id);
    InspectionBuffer *buffer = &fb->inspection_buffers[local_id];
    SCLogDebug("using buffer %p", buffer);
#ifdef DEBUG_VALIDATION
    buffer->multi = true;
#endif
    return buffer;
}

static inline void InspectionBufferApplyTransformsInternal(DetectEngineThreadCtx *det_ctx,
        InspectionBuffer *buffer, const DetectEngineTransforms *transforms)
{
    if (transforms) {
        for (int i = 0; i < DETECT_TRANSFORMS_MAX; i++) {
            const int id = transforms->transforms[i].transform;
            if (id == 0)
                break;
            DEBUG_VALIDATE_BUG_ON(sigmatch_table[id].Transform == NULL);
            sigmatch_table[id].Transform(det_ctx, buffer, transforms->transforms[i].options);
            SCLogDebug("applied transform %s", sigmatch_table[id].name);
        }
    }
}

void InspectionBufferApplyTransforms(DetectEngineThreadCtx *det_ctx, InspectionBuffer *buffer,
        const DetectEngineTransforms *transforms)
{
    InspectionBufferApplyTransformsInternal(det_ctx, buffer, transforms);
}

void InspectionBufferInit(InspectionBuffer *buffer, uint32_t initial_size)
{
    memset(buffer, 0, sizeof(*buffer));
    buffer->buf = SCCalloc(initial_size, sizeof(uint8_t));
    if (buffer->buf != NULL) {
        buffer->size = initial_size;
    }
}

/** \brief setup the buffer empty */
void InspectionBufferSetupMultiEmpty(InspectionBuffer *buffer)
{
#ifdef DEBUG_VALIDATION
    DEBUG_VALIDATE_BUG_ON(buffer->initialized);
    DEBUG_VALIDATE_BUG_ON(!buffer->multi);
#endif
    buffer->inspect = NULL;
    buffer->inspect_len = 0;
    buffer->len = 0;
    buffer->initialized = true;
}

/** \brief setup the buffer with our initial data */
void InspectionBufferSetupMulti(DetectEngineThreadCtx *det_ctx, InspectionBuffer *buffer,
        const DetectEngineTransforms *transforms, const uint8_t *data, const uint32_t data_len)
{
#ifdef DEBUG_VALIDATION
    DEBUG_VALIDATE_BUG_ON(!buffer->multi);
#endif
    buffer->inspect = buffer->orig = data;
    buffer->inspect_len = buffer->orig_len = data_len;
    buffer->len = 0;
    buffer->initialized = true;

    InspectionBufferApplyTransformsInternal(det_ctx, buffer, transforms);
}

static inline void InspectionBufferSetupInternal(DetectEngineThreadCtx *det_ctx, const int list_id,
        InspectionBuffer *buffer, const uint8_t *data, const uint32_t data_len)
{
#ifdef DEBUG_VALIDATION
    DEBUG_VALIDATE_BUG_ON(buffer->multi);
    DEBUG_VALIDATE_BUG_ON(buffer != InspectionBufferGet(det_ctx, list_id));
#endif
    if (buffer->inspect == NULL) {
#ifdef UNITTESTS
        if (det_ctx && list_id != -1)
#endif
            det_ctx->inspect.to_clear_queue[det_ctx->inspect.to_clear_idx++] = list_id;
    }
    buffer->inspect = buffer->orig = data;
    buffer->inspect_len = buffer->orig_len = data_len;
    buffer->len = 0;
    buffer->initialized = true;
}
/** \brief setup the buffer with our initial data */
void InspectionBufferSetup(DetectEngineThreadCtx *det_ctx, const int list_id,
        InspectionBuffer *buffer, const uint8_t *data, const uint32_t data_len)
{
    InspectionBufferSetupInternal(det_ctx, list_id, buffer, data, data_len);
}

/** \brief setup the buffer with our initial data */
void InspectionBufferSetupAndApplyTransforms(DetectEngineThreadCtx *det_ctx, const int list_id,
        InspectionBuffer *buffer, const uint8_t *data, const uint32_t data_len,
        const DetectEngineTransforms *transforms)
{
    InspectionBufferSetupInternal(det_ctx, list_id, buffer, data, data_len);
    InspectionBufferApplyTransformsInternal(det_ctx, buffer, transforms);
}

void InspectionBufferFree(InspectionBuffer *buffer)
{
    if (buffer->buf != NULL) {
        SCFree(buffer->buf);
    }
    memset(buffer, 0, sizeof(*buffer));
}

/**
 * \brief make sure that the buffer has at least 'min_size' bytes
 * Expand the buffer if necessary
 */
uint8_t *SCInspectionBufferCheckAndExpand(InspectionBuffer *buffer, uint32_t min_size)
{
    if (likely(buffer->size >= min_size))
        return buffer->buf;

    uint32_t new_size = (buffer->size == 0) ? 4096 : buffer->size;
    while (new_size < min_size) {
        new_size *= 2;
    }

    void *ptr = SCRealloc(buffer->buf, new_size);
    if (ptr != NULL) {
        buffer->buf = ptr;
        buffer->size = new_size;
    } else {
        return NULL;
    }
    return buffer->buf;
}

void SCInspectionBufferTruncate(InspectionBuffer *buffer, uint32_t buf_len)
{
    DEBUG_VALIDATE_BUG_ON(buffer->buf == NULL);
    DEBUG_VALIDATE_BUG_ON(buf_len > buffer->size);
    buffer->inspect = buffer->buf;
    buffer->inspect_len = buf_len;
    buffer->initialized = true;
}

void InspectionBufferCopy(InspectionBuffer *buffer, uint8_t *buf, uint32_t buf_len)
{
    SCInspectionBufferCheckAndExpand(buffer, buf_len);

    if (buffer->size) {
        uint32_t copy_size = MIN(buf_len, buffer->size);
        memcpy(buffer->buf, buf, copy_size);
        buffer->inspect = buffer->buf;
        buffer->inspect_len = copy_size;
        buffer->initialized = true;
    }
}
