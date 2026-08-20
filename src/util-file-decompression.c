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
 * \brief Decompress files transferred via HTTP corresponding to file_data
 * keyword.
 *
 */

#include "suricata-common.h"
#include "suricata.h"

#include "detect-engine.h"
#include "app-layer-htp.h"

#include "util-file-decompression.h"
#include "util-file-swf-decompression.h"
#include "util-misc.h"
#include "util-print.h"
#include "util-validate.h"

#define SWF_ZLIB_MIN_VERSION    0x06
#define SWF_LZMA_MIN_VERSION    0x0D

int FileIsSwfFile(const uint8_t *buffer, uint32_t buffer_len)
{
    if (buffer_len >= 3 && buffer[1] == 'W' && buffer[2] == 'S') {
        if (buffer[0] == 'F')
            return FILE_SWF_NO_COMPRESSION;
        else if (buffer[0] == 'C')
            return FILE_SWF_ZLIB_COMPRESSION;
        else if (buffer[0] == 'Z')
            return FILE_SWF_LZMA_COMPRESSION;
        else
            return FILE_IS_NOT_SWF;
    }

    return FILE_IS_NOT_SWF;
}

/**
 * \brief This function decompresses a buffer with zlib/lzma algorithm
 *
 * \param buffer compressed buffer
 * \param buffer_len compressed buffer length
 * \param out_buffer inspection buffer that stores decompressed data
 * \param swf_type decompression algorithm to use
 * \param decompress_depth how much decompressed data we want to store
 * \param compress_depth how much compressed data we want to decompress
 *
 * \retval 1 if decompression works
 * \retval 0 an error occurred, and event set
 */
int FileSwfDecompression(const uint8_t *buffer, uint32_t buffer_len,
                         DetectEngineThreadCtx *det_ctx,
                         InspectionBuffer *out_buffer,
                         int swf_type,
                         uint32_t decompress_depth,
                         uint32_t compress_depth)
{
    int r = 0;

    if (decompress_depth > MAX_SWF_DECOMPRESS_DEPTH || compress_depth > MAX_SWF_COMPRESS_DEPTH) {
        return 0;
    }

    int compression_type = FileIsSwfFile(buffer, buffer_len);
    if (compression_type == FILE_SWF_NO_COMPRESSION) {
        return 0;
    }

    uint32_t offset = 0;
    if (compression_type == FILE_SWF_ZLIB_COMPRESSION) {
        /* compressed data start from the 4th bytes */
        offset = 8;
    } else if (compression_type == FILE_SWF_LZMA_COMPRESSION) {
        /* compressed data start from the 17th bytes */
        offset = 17;
    }

    if (buffer_len <= offset) {
        DetectEngineSetEvent(det_ctx, FILE_DECODER_EVENT_INVALID_SWF_LENGTH);
        return 0;
    }

    uint32_t compressed_data_len = 0;
    if (compress_depth > 0 && compress_depth <= buffer_len - offset) {
        compressed_data_len = compress_depth;
    } else {
        compressed_data_len = buffer_len - offset;
    }

    /* get swf version */
    uint8_t swf_version = FileGetSwfVersion(buffer, buffer_len);
    if (compression_type == FILE_SWF_ZLIB_COMPRESSION &&
        swf_version < SWF_ZLIB_MIN_VERSION)
    {
        DetectEngineSetEvent(det_ctx, FILE_DECODER_EVENT_INVALID_SWF_VERSION);
        return 0;
    }
    if (compression_type == FILE_SWF_LZMA_COMPRESSION &&
        swf_version < SWF_LZMA_MIN_VERSION)
    {
        DetectEngineSetEvent(det_ctx, FILE_DECODER_EVENT_INVALID_SWF_VERSION);
        return 0;
    }

    uint32_t decompressed_data_limit =
            (decompress_depth == 0) ? MAX_SWF_DECOMPRESSED_LEN : decompress_depth;

    uint32_t initial_buffer_len =
            MIN(SWF_DECOMPRESS_INITIAL_BUFFER_LEN, decompressed_data_limit + SWF_HEADER_LEN);
    if (SCInspectionBufferCheckAndExpand(out_buffer, initial_buffer_len) == NULL) {
        DetectEngineSetEvent(det_ctx, FILE_DECODER_EVENT_NO_MEM);
        return 0;
    }

    /*
     * FWS format
     * | 4 bytes         | 4 bytes    | n bytes |
     * | 'FWS' + version | script len | data    |
     */
    out_buffer->buf[0] = 'F';
    out_buffer->buf[1] = 'W';
    out_buffer->buf[2] = 'S';
    out_buffer->buf[3] = swf_version;
    memcpy(out_buffer->buf + 4, buffer + 4, 4);

    uint32_t decompressed_data_produced = 0;

    if ((swf_type == HTTP_SWF_COMPRESSION_ZLIB || swf_type == HTTP_SWF_COMPRESSION_BOTH) &&
            compression_type == FILE_SWF_ZLIB_COMPRESSION)
    {
        /* the first 8 bytes represents the fws header, see 'FWS format' above.
         * data will start from 8th bytes
         */
        r = FileSwfZlibDecompression(det_ctx, buffer + offset, compressed_data_len, out_buffer,
                decompressed_data_limit, &decompressed_data_produced);
        if (r == 0)
            goto error;

    } else if ((swf_type == HTTP_SWF_COMPRESSION_LZMA || swf_type == HTTP_SWF_COMPRESSION_BOTH) &&
               compression_type == FILE_SWF_LZMA_COMPRESSION)
    {
        /* we need to setup the lzma header */
        /*
         * | 5 bytes         | 8 bytes             | n bytes         |
         * | LZMA properties | Uncompressed length | Compressed data |
         */
        compressed_data_len += SWF_LZMA_HEADER_LEN;
        uint8_t *compressed_data = SCCalloc(1, compressed_data_len);
        if (compressed_data == NULL) {
            DetectEngineSetEvent(det_ctx, FILE_DECODER_EVENT_NO_MEM);
            goto error;
        }
        /* put lzma properties */
        memcpy(compressed_data, buffer + 12, 5);
        /* put lzma end marker */
        memset(compressed_data + 5, 0xFF, 8);
        /* put compressed data */
        memcpy(compressed_data + SWF_LZMA_HEADER_LEN, buffer + offset,
                compressed_data_len - SWF_LZMA_HEADER_LEN);

        /* the first 8 bytes represents the fws header, see 'FWS format' above.
         * data will start from 8th bytes
         */
        r = FileSwfLzmaDecompression(det_ctx, compressed_data, compressed_data_len, out_buffer,
                decompressed_data_limit, &decompressed_data_produced);
        SCFree(compressed_data);
        if (r == 0)
            goto error;
    } else {
        goto error;
    }

    DEBUG_VALIDATE_BUG_ON(decompressed_data_produced > decompressed_data_limit);
    out_buffer->len = SWF_HEADER_LEN + decompressed_data_produced;

    /* all went well so switch the buffer's inspect pointer/size
     * to use the new data. */
    out_buffer->inspect = out_buffer->buf;
    out_buffer->inspect_len = out_buffer->len;

    return 1;

error:
    return 0;
}
