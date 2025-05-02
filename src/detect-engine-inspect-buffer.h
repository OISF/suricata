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

#ifndef SURICATA_DETECT_ENGINE_INSPECT_BUFFER_H
#define SURICATA_DETECT_ENGINE_INSPECT_BUFFER_H

/* inspection buffer is a simple structure that is passed between prefilter,
 * transformation functions and inspection functions.
 * Initially setup with 'orig' ptr and len, transformations can then take
 * then and fill the 'buf'. Multiple transformations can update the buffer,
 * both growing and shrinking it.
 * Prefilter and inspection will only deal with 'inspect'. */

typedef struct InspectionBuffer {
    const uint8_t *inspect; /**< active pointer, points either to ::buf or ::orig */
    uint64_t inspect_offset;
    uint32_t inspect_len; /**< size of active data. See to ::len or ::orig_len */
    bool initialized; /**< is initialized. ::inspect might be NULL if transform lead to 0 size */
    uint8_t flags;    /**< DETECT_CI_FLAGS_* for use with DetectEngineContentInspection */
#ifdef DEBUG_VALIDATION
    bool multi;
#endif
    uint32_t len; /**< how much is in use */
    uint8_t *buf;
    uint32_t size; /**< size of the memory allocation */

    uint32_t orig_len;
    const uint8_t *orig;
} InspectionBuffer;

// Forward declarations for types from detect.h
typedef struct DetectEngineThreadCtx_ DetectEngineThreadCtx;
typedef struct DetectEngineTransforms DetectEngineTransforms;
typedef struct SigMatch_ SigMatch;

void InspectionBufferInit(InspectionBuffer *buffer, uint32_t initial_size);
void InspectionBufferSetup(DetectEngineThreadCtx *det_ctx, const int list_id,
        InspectionBuffer *buffer, const uint8_t *data, const uint32_t data_len);
void InspectionBufferSetupAndApplyTransforms(DetectEngineThreadCtx *det_ctx, const int list_id,
        InspectionBuffer *buffer, const uint8_t *data, const uint32_t data_len,
        const DetectEngineTransforms *transforms);
void InspectionBufferFree(InspectionBuffer *buffer);
uint8_t *SCInspectionBufferCheckAndExpand(InspectionBuffer *buffer, uint32_t min_size);
void SCInspectionBufferTruncate(InspectionBuffer *buffer, uint32_t buf_len);
void InspectionBufferCopy(InspectionBuffer *buffer, uint8_t *buf, uint32_t buf_len);
void InspectionBufferApplyTransforms(DetectEngineThreadCtx *det_ctx, InspectionBuffer *buffer,
        const DetectEngineTransforms *transforms);
void InspectionBufferClean(DetectEngineThreadCtx *det_ctx);
InspectionBuffer *InspectionBufferGet(DetectEngineThreadCtx *det_ctx, const int list_id);
void InspectionBufferSetupMultiEmpty(InspectionBuffer *buffer);
void InspectionBufferSetupMulti(DetectEngineThreadCtx *det_ctx, InspectionBuffer *buffer,
        const DetectEngineTransforms *transforms, const uint8_t *data, const uint32_t data_len);
InspectionBuffer *InspectionBufferMultipleForListGet(
        DetectEngineThreadCtx *det_ctx, const int list_id, uint32_t local_id);

#endif /* SURICATA_DETECT_ENGINE_INSPECT_BUFFER_H */
