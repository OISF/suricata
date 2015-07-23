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
 * \author Giuseppe Longo <giuseppe@glongo.it>
 *
 * \brief Decompress files transfered via HTTP corresponding to file_data
 * keyword.
 *
 */

#include "suricata-common.h"
#include "suricata.h"

#include "app-layer-htp.h"

#include "util-file-decompression.h"
#include "util-file-flash-decompression.h"
#include "util-misc.h"
#include "util-print.h"

#define FLASH_ZLIB_MIN_VERSION    0x06
#define FLASH_LZMA_MIN_VERSION    0x0D

SCEnumCharMap file_decoder_event_table[ ] = {
    { "NO MEMORY",                  FILE_DECODER_EVENT_NO_MEM },
    { "NO FLASH SUPPORT",           FILE_DECODER_EVENT_NO_FLASH_SUPPORT },
    { "INVALID FLASH VERSION",      FILE_DECODER_EVENT_INVALID_FLASH_VERSION },
    { "Z_STREAM_END",               FILE_DECODER_EVENT_Z_STREAM_END },
    { "Z_OK",                       FILE_DECODER_EVENT_Z_OK },
    { "Z_DATA_ERROR",               FILE_DECODER_EVENT_Z_DATA_ERROR },
    { "Z_STREAM_ERROR",             FILE_DECODER_EVENT_Z_STREAM_ERROR },
    { "Z_BUF_ERROR",                FILE_DECODER_EVENT_Z_BUF_ERROR },
    { "Z_UNKNOWN_ERROR",            FILE_DECODER_EVENT_Z_UNKNOWN_ERROR },
    { "LZMA_DECODER_ERROR",         FILE_DECODER_EVENT_LZMA_DECODER_ERROR },
    { "LZMA_STREAM_END",            FILE_DECODER_EVENT_LZMA_STREAM_END },
    { "LZMA_OK",                    FILE_DECODER_EVENT_LZMA_OK },
    { "LZMA_MEMLIMIT_ERROR",        FILE_DECODER_EVENT_LZMA_MEMLIMIT_ERROR },
    { "LZMA_OPTIONS_ERROR",         FILE_DECODER_EVENT_LZMA_OPTIONS_ERROR },
    { "LZMA_FORMAT_ERROR",          FILE_DECODER_EVENT_LZMA_FORMAT_ERROR },
    { "LZMA_DATA_ERROR",            FILE_DECODER_EVENT_LZMA_DATA_ERROR },
    { "LZMA_BUF_ERROR",             FILE_DECODER_EVENT_LZMA_BUF_ERROR },
    { "LZMA_UNKNOWN_ERROR",         FILE_DECODER_EVENT_LZMA_UNKNOWN_ERROR },
    { NULL,                         -1 },
};

int FileIsFlashFile(const uint8_t *buffer, uint32_t buffer_len)
{
    if (buffer_len >= 3 && buffer[1] == 'W' && buffer[2] == 'S') {
        if (buffer[0] == 'F')
            return FILE_FLASH_NO_COMPRESSION;
        else if (buffer[0] == 'C')
            return FILE_FLASH_ZLIB_COMPRESSION;
        else if (buffer[0] == 'Z')
            return FILE_FLASH_LZMA_COMPRESSION;
        else
            return FILE_IS_NOT_FLASH;
    }

    return FILE_IS_NOT_FLASH;
}

int FileDecompressFlashFile(const uint8_t *buffer, uint32_t *buffer_len,
                            uint8_t **decompressed_buffer,
                            DetectEngineThreadCtx *det_ctx,
                            int swf_type,
                            uint32_t decompress_depth,
                            uint32_t compress_depth)
{
    int r = 0;
    uint32_t buf_len = *buffer_len;
    uint8_t *compressed_data = NULL;
    uint8_t *decompressed_data = *decompressed_buffer;

    int compression_type = FileIsFlashFile(buffer, buf_len);
    if (compression_type == FILE_FLASH_NO_COMPRESSION) {
        return 0;
    }

    int offset = 0;
    if (compression_type == FILE_FLASH_ZLIB_COMPRESSION) {
        /* compressed data start from the 4th bytes */
        offset = 8;
    } else if (compression_type == FILE_FLASH_LZMA_COMPRESSION) {
        /* compressed data start from the 17th bytes */
        offset = 17;
    }

    /* if compress_depth is 0, keep the buffer length */
    uint32_t compressed_data_len = (compress_depth == 0) ? (buf_len - offset) : compress_depth;

    /* get flash decompressed file length */
    uint32_t decompressed_swf_len = FileGetFlashDecompressedLen(buffer);
    if (decompressed_swf_len == 0) {
        decompressed_swf_len = MIN_SWF_LEN;
    }

    /* if decompress_depth is 0, keep the flash file length */
    uint32_t decompressed_data_len = (decompress_depth == 0) ? decompressed_swf_len : decompress_depth;
    decompressed_data = SCMalloc(decompressed_data_len + 8);
    if (decompressed_data == NULL) {
        FileDecompressionSetEvent(det_ctx, FILE_DECODER_EVENT_NO_MEM);
        return 0;
    }

    /* get file flash version */
    uint8_t flash_version = FileGetFlashVersion(buffer, buf_len);

    /*
     * FWS format
     * | 4 bytes         | 4 bytes    | n bytes |
     * | 'FWS' + version | script len | data    |
     */
    memcpy(decompressed_data, "FWS", 3);
    memcpy(decompressed_data + 3, &flash_version, 1);
    memcpy(decompressed_data + 4, &decompressed_swf_len, 4);

    if ((swf_type == HTTP_DECOMP_FLASH_ZLIB || swf_type == HTTP_DECOMP_FLASH_BOTH) &&
        compression_type == FILE_FLASH_ZLIB_COMPRESSION)
    {
        if (flash_version < FLASH_ZLIB_MIN_VERSION) {
            FileDecompressionSetEvent(det_ctx,
                                      FILE_DECODER_EVENT_INVALID_FLASH_VERSION);
            return 0;
        }

        compressed_data = SCMalloc(compressed_data_len);
        if (compressed_data == NULL) {
            FileDecompressionSetEvent(det_ctx, FILE_DECODER_EVENT_NO_MEM);
            return 0;
        }

        /* put compressed data */
        memcpy(compressed_data, buffer + offset, compressed_data_len);

        r = FileDecompressFlashZlibData(det_ctx,
                                        compressed_data, compressed_data_len,
                                        decompressed_data + 8, decompressed_data_len);
        SCFree(compressed_data);
        if (r == 0)
            return 0;

    } else if ((swf_type == HTTP_DECOMP_FLASH_LZMA || swf_type == HTTP_DECOMP_FLASH_BOTH) &&
               compression_type == FILE_FLASH_LZMA_COMPRESSION)
    {
        if (flash_version < FLASH_LZMA_MIN_VERSION) {
            FileDecompressionSetEvent(det_ctx,
                                      FILE_DECODER_EVENT_INVALID_FLASH_VERSION);
            return 0;
        }
        /* we need to setup the lzma header */
        /*
         * | 5 bytes         | 8 bytes             | n bytes         |
         * | LZMA properties | Uncompressed length | Compressed data |
         */
        compressed_data_len += 13;
        compressed_data = SCMalloc(compressed_data_len);
        if (compressed_data == NULL) {
            FileDecompressionSetEvent(det_ctx, FILE_DECODER_EVENT_NO_MEM);
            return 0;
        }
        /* put lzma properties */
        memcpy(compressed_data, buffer + 12, 5);
        /* put lzma end marker */
        memset(compressed_data + 5, 0xFF, 8);
        /* put compressed data */
        memcpy(compressed_data + 13, buffer + offset, compressed_data_len - 13);

        r = FileDecompressFlashLzmaData(det_ctx,
                                        compressed_data, compressed_data_len,
                                        decompressed_data + 8, decompressed_data_len);
        SCFree(compressed_data);
        if (r == 0)
            return 0;
    } else {
        return 0;
    }

    *buffer_len = decompressed_data_len;
    *decompressed_buffer = decompressed_data;

    return 1;
}

int FileDecompressionGetEventInfo(const char *event_name, int *event_id,
                                  AppLayerEventType *event_type)
{
    *event_id = SCMapEnumNameToValue(event_name, file_decoder_event_table);
    if (*event_id == -1) {
        SCLogError(SC_ERR_INVALID_ENUM_MAP, "event \"%s\" not present in "
                   "file's enum map table.",  event_name);
        /* this should be treated as fatal */
        return -1;
    }

    *event_type = APP_LAYER_EVENT_TYPE_TRANSACTION;

    return 0;
    
}

int FileDecompressionHasEvents(DetectEngineThreadCtx *det_ctx)
{
    return (det_ctx->events > 0);
}

AppLayerDecoderEvents *FileDecompressionGetEvent(DetectEngineThreadCtx *det_ctx)
{
    return det_ctx->decoder_events;
}

void FileDecompressionSetEvent(DetectEngineThreadCtx *det_ctx, uint8_t e)
{
    AppLayerDecoderEventsSetEventRaw(&det_ctx->decoder_events, e);
    det_ctx->events++;
}


