/* Copyright (C) 2017 Open Information Security Foundation
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
 * \author Giuseppe Longo <giuseppe@glongo.it>
 *
 */


#include "suricata.h"
#include "suricata-common.h"

#include "app-layer-htp.h"

#include "util-file-decompression.h"
#include "util-file-swf-decompression.h"
#include "util-misc.h"
#include "util-print.h"
#include "util-validate.h"

#include "rust.h"

#include <zlib.h>

uint8_t FileGetSwfVersion(const uint8_t *buffer, const uint32_t buffer_len)
{
    if (buffer_len > 3)
        return buffer[3];

    return 0;
}

static bool FileSwfDecompressionBufferGrow(DetectEngineThreadCtx *det_ctx,
        InspectionBuffer *out_buffer, uint32_t decompressed_data_limit)
{
    const uint32_t maximum_buffer_len = decompressed_data_limit + SWF_HEADER_LEN;
    uint32_t requested_len = out_buffer->size;

    if (requested_len >= maximum_buffer_len)
        return true;

    if (requested_len == 0) {
        requested_len = MIN(SWF_DECOMPRESS_INITIAL_BUFFER_LEN, maximum_buffer_len);
    } else if (requested_len > maximum_buffer_len / 2) {
        requested_len = maximum_buffer_len;
    } else {
        requested_len *= 2;
    }

    if (SCInspectionBufferCheckAndExpand(out_buffer, requested_len) == NULL) {
        DetectEngineSetEvent(det_ctx, FILE_DECODER_EVENT_NO_MEM);
        return false;
    }
    return true;
}

static uint32_t FileSwfDecompressionOutputCapacity(
        const InspectionBuffer *out_buffer, uint32_t decompressed_data_limit)
{
    if (out_buffer->size <= SWF_HEADER_LEN)
        return 0;
    return MIN(out_buffer->size - SWF_HEADER_LEN, decompressed_data_limit);
}

/* CWS format */
/*
 * | 4 bytes         | 4 bytes    | n bytes         |
 * | 'CWS' + version | script len | compressed data |
 */
int FileSwfZlibDecompression(DetectEngineThreadCtx *det_ctx, const uint8_t *compressed_data,
        uint32_t compressed_data_len, InspectionBuffer *out_buffer,
        uint32_t decompressed_data_limit, uint32_t *decompressed_data_produced)
{
    int ret = 1;
    *decompressed_data_produced = 0;
    z_stream infstream;
    memset(&infstream, 0, sizeof(infstream));
    infstream.zalloc = Z_NULL;
    infstream.zfree = Z_NULL;
    infstream.opaque = Z_NULL;

    infstream.avail_in = (uInt)compressed_data_len;
    infstream.next_in = (Bytef *)compressed_data;

    int result = inflateInit(&infstream);
    if (result != Z_OK) {
        DetectEngineSetEvent(det_ctx, FILE_DECODER_EVENT_Z_UNKNOWN_ERROR);
        return 0;
    }

    while (true) {
        uint32_t output_capacity =
                FileSwfDecompressionOutputCapacity(out_buffer, decompressed_data_limit);
        DEBUG_VALIDATE_BUG_ON(infstream.total_out > output_capacity);
        infstream.avail_out = (uInt)(output_capacity - infstream.total_out);
        infstream.next_out = out_buffer->buf + SWF_HEADER_LEN + infstream.total_out;

        result = inflate(&infstream, Z_NO_FLUSH);
        *decompressed_data_produced = (uint32_t)infstream.total_out;

        if (result == Z_STREAM_END || *decompressed_data_produced == decompressed_data_limit)
            break;

        /* More output can be pending even after all input has been consumed. */
        if (result == Z_OK && infstream.avail_out == 0) {
            if (!FileSwfDecompressionBufferGrow(det_ctx, out_buffer, decompressed_data_limit)) {
                ret = 0;
                break;
            }
            continue;
        }

        /* A retry with no input returns Z_BUF_ERROR when no output was pending. */
        if ((result == Z_OK || result == Z_BUF_ERROR) && infstream.avail_in == 0)
            break;

        if (result == Z_DATA_ERROR) {
            DetectEngineSetEvent(det_ctx, FILE_DECODER_EVENT_Z_DATA_ERROR);
        } else if (result == Z_STREAM_ERROR) {
            DetectEngineSetEvent(det_ctx, FILE_DECODER_EVENT_Z_STREAM_ERROR);
        } else if (result == Z_BUF_ERROR) {
            DetectEngineSetEvent(det_ctx, FILE_DECODER_EVENT_Z_BUF_ERROR);
        } else {
            DetectEngineSetEvent(det_ctx, FILE_DECODER_EVENT_Z_UNKNOWN_ERROR);
        }
        ret = 0;
        break;
    }
    inflateEnd(&infstream);

    return ret;
}

/* ZWS format */
/*
 * | 4 bytes         | 4 bytes    | 4 bytes        | 5 bytes    | n bytes   | 6 bytes         |
 * | 'ZWS' + version | script len | compressed len | LZMA props | LZMA data | LZMA end marker |
 */
static uint8_t *FileSwfLzmaOutputGrow(void *output, uint32_t min_size)
{
    return SCInspectionBufferCheckAndExpand(output, min_size);
}

int FileSwfLzmaDecompression(DetectEngineThreadCtx *det_ctx, const uint8_t *compressed_data,
        uint32_t compressed_data_len, InspectionBuffer *out_buffer,
        uint32_t decompressed_data_limit, uint32_t *decompressed_data_produced)
{
    *decompressed_data_produced = 0;

    size_t inprocessed = compressed_data_len;
    size_t outprocessed = 0;
    int ret = lzma_decompress(compressed_data, &inprocessed, out_buffer, SWF_HEADER_LEN,
            decompressed_data_limit, &outprocessed, FileSwfLzmaOutputGrow,
            MAX_SWF_DECOMPRESSED_LEN);
    *decompressed_data_produced = (uint32_t)outprocessed;

    if (ret == LzmaOk || ret == LzmaOutputFull) {
        DEBUG_VALIDATE_BUG_ON(
                ret == LzmaOutputFull && *decompressed_data_produced != decompressed_data_limit);
        return 1;
    }

    if (ret == LzmaOutputAllocError) {
        DetectEngineSetEvent(det_ctx, FILE_DECODER_EVENT_NO_MEM);
    } else if (ret == LzmaIoError) {
        DetectEngineSetEvent(det_ctx, FILE_DECODER_EVENT_LZMA_IO_ERROR);
    } else if (ret == LzmaHeaderTooShortError) {
        DetectEngineSetEvent(det_ctx, FILE_DECODER_EVENT_LZMA_HEADER_TOO_SHORT_ERROR);
    } else if (ret == LzmaError) {
        DetectEngineSetEvent(det_ctx, FILE_DECODER_EVENT_LZMA_DECODER_ERROR);
    } else if (ret == LzmaMemoryError) {
        DetectEngineSetEvent(det_ctx, FILE_DECODER_EVENT_LZMA_MEMLIMIT_ERROR);
    } else if (ret == LzmaXzError) {
        /* We should not see XZ compressed SWF files */
        DetectEngineSetEvent(det_ctx, FILE_DECODER_EVENT_LZMA_XZ_ERROR);
    } else {
        DetectEngineSetEvent(det_ctx, FILE_DECODER_EVENT_LZMA_UNKNOWN_ERROR);
    }
    return 0;
}
