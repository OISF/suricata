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

/**
 * \brief This function decompresses a buffer with zlib/lzma algorithm
 *
 * \param buffer compressed buffer
 * \param buffer_len compressed buffer length
 * \param decompressed_buffer buffer that store decompressed data
 * \param decompressed_buffer_len decompressesd data length
 * \param swf_type decompression algorithm to use
 * \param decompress_depth how much decompressed data we want to store
 * \param compress_depth how much compressed data we want to decompress
 *
 * \retval 1 if decompression works
 * \retval 0 an error occured, and event set
 */
int FileDecompressFlashFile(const uint8_t *buffer, uint32_t buffer_len,
                            uint8_t **decompressed_buffer,
                            uint32_t *decompressed_buffer_len,
                            DetectEngineThreadCtx *det_ctx,
                            int swf_type,
                            uint32_t decompress_depth,
                            uint32_t compress_depth)
{
    int r = 0;
    uint8_t *compressed_data = NULL;
    uint8_t *decompressed_data = *decompressed_buffer;

    int compression_type = FileIsFlashFile(buffer, buffer_len);
    if (compression_type == FILE_FLASH_NO_COMPRESSION) {
        return 0;
    }

    uint32_t offset = 0;
    if (compression_type == FILE_FLASH_ZLIB_COMPRESSION) {
        /* compressed data start from the 4th bytes */
        offset = 8;
    } else if (compression_type == FILE_FLASH_LZMA_COMPRESSION) {
        /* compressed data start from the 17th bytes */
        offset = 17;
    }

    uint32_t compressed_swf_len = 0;
    if (buffer_len > offset && compress_depth == 0) {
        compressed_swf_len = buffer_len - offset;
    } else if (compress_depth > 0 && compress_depth <= buffer_len) {
        compressed_swf_len = compress_depth;
    } else if (compress_depth > 0 && compress_depth > buffer_len) {
        compressed_swf_len = buffer_len;
    } else {
        compressed_swf_len = offset;
    }

    /* if compress_depth is 0, keep the buffer length */
    uint32_t compressed_data_len = compressed_swf_len;

    /* get flash decompressed file length */
    uint32_t decompressed_swf_len = FileGetFlashDecompressedLen(buffer, buffer_len);
    if (decompressed_swf_len == 0) {
        decompressed_swf_len = MIN_SWF_LEN;
    }

    /* if decompress_depth is 0, keep the flash file length */
    uint32_t decompressed_data_len = (decompress_depth == 0) ? decompressed_swf_len : decompress_depth;
    decompressed_data = SCMalloc(decompressed_data_len + 8);
    if (decompressed_data == NULL) {
        DetectEngineSetEvent(det_ctx, FILE_DECODER_EVENT_NO_MEM);
        return 0;
    }

    /* get file flash version */
    uint8_t flash_version = FileGetFlashVersion(buffer, buffer_len);

    /*
     * FWS format
     * | 4 bytes         | 4 bytes    | n bytes |
     * | 'FWS' + version | script len | data    |
     */
    decompressed_data[0] = 'F';
    decompressed_data[1] = 'W';
    decompressed_data[2] = 'S';
    decompressed_data[3] = flash_version;
    memcpy(decompressed_data + 4, &decompressed_swf_len, 4);

    if ((swf_type == HTTP_DECOMP_FLASH_ZLIB || swf_type == HTTP_DECOMP_FLASH_BOTH) &&
        compression_type == FILE_FLASH_ZLIB_COMPRESSION)
    {
        if (flash_version < FLASH_ZLIB_MIN_VERSION) {
            DetectEngineSetEvent(det_ctx,
                                 FILE_DECODER_EVENT_INVALID_FLASH_VERSION);
            goto end;
        }

        compressed_data = SCMalloc(compressed_data_len);
        if (compressed_data == NULL) {
            DetectEngineSetEvent(det_ctx, FILE_DECODER_EVENT_NO_MEM);
            goto end;
        }

        /* put compressed data */
        memcpy(compressed_data, buffer + offset, compressed_data_len);

        r = FileDecompressFlashZlibData(det_ctx,
                                        compressed_data, compressed_data_len,
                                        decompressed_data + 8, decompressed_data_len);
        SCFree(compressed_data);
        if (r == 0)
            goto end;

    } else if ((swf_type == HTTP_DECOMP_FLASH_LZMA || swf_type == HTTP_DECOMP_FLASH_BOTH) &&
               compression_type == FILE_FLASH_LZMA_COMPRESSION)
    {
        if (flash_version < FLASH_LZMA_MIN_VERSION) {
            DetectEngineSetEvent(det_ctx,
                                 FILE_DECODER_EVENT_INVALID_FLASH_VERSION);
            goto end;
        }
        /* we need to setup the lzma header */
        /*
         * | 5 bytes         | 8 bytes             | n bytes         |
         * | LZMA properties | Uncompressed length | Compressed data |
         */
        compressed_data_len += 13;
        compressed_data = SCMalloc(compressed_data_len);
        if (compressed_data == NULL) {
            DetectEngineSetEvent(det_ctx, FILE_DECODER_EVENT_NO_MEM);
            goto end;
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
            goto end;
    } else {
        goto end;
    }

    *decompressed_buffer_len = decompressed_data_len;
    *decompressed_buffer = decompressed_data;

    return 1;

end:
    SCFree(decompressed_data);
    return 0;
}
