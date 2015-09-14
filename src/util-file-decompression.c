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
#include "util-misc.h"
#include "util-print.h"

#include <zlib.h>

#ifdef HAVE_LIBLZMA
#include <lzma.h>
#endif

#define FLASH_ZLIB_MIN_VERSION    0x06
#define FLASH_LZMA_MIN_VERSION    0x0D

int FileIsFlashFile(uint8_t *buffer, uint32_t buffer_len)
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

/*
 * Return uncompressed file length
 * in little-endian order
 */
uint32_t FileGetFlashDecompressedLen(uint8_t *buffer)
{
    int a = buffer[4];
    int b = buffer[5];
    int c = buffer[6];
    int d = buffer[7];

    uint32_t value = (((a & 0xff) << 24) | ((b & 0xff) << 16) | ((c & 0xff) << 8) | (d & 0xff));
    return ((value >> 24) & 0x000000FF) | ((value >> 8) & 0x0000FF00) | ((value << 8) & 0x00FF0000) | ((value << 24) & 0xFF000000);
}

uint8_t FileGetFlashVersion(uint8_t *buffer, uint32_t buffer_len)
{
    if (buffer_len >= 3)
        return buffer[3];

    return 0;
}

/* CWS format */
/*
 * | 4 bytes         | 4 bytes    | n bytes         |
 * | 'CWS' + version | script len | compressed data |
 */
static int FileDecompressFlashZlibData(uint8_t *compressed_data, uint32_t compressed_data_len,
                                       uint8_t *decompressed_data, uint32_t decompressed_data_len)
{
    int ret = FILE_FLASH_DECOMP_OK;
    z_stream infstream;
    infstream.zalloc = Z_NULL;
    infstream.zfree = Z_NULL;
    infstream.opaque = Z_NULL;

    infstream.avail_in = (uInt)compressed_data_len;
    infstream.next_in = (Bytef *)compressed_data;
    infstream.avail_out = (uInt)decompressed_data_len;
    infstream.next_out = (Bytef *)decompressed_data;

    inflateInit(&infstream);
    int result = inflate(&infstream, Z_NO_FLUSH);
    switch(result) {
        case Z_OK:
            SCLogDebug("Decompression completed successfully");
            break;
        case Z_STREAM_END:
            SCLogDebug("End of stream was reached, all the data was decompressed");
            break;
        case Z_DATA_ERROR:
            SCLogError(SC_ERR_FLASH_DECOMPRESSION, "Compressed file is corrupt");
            ret = FILE_FLASH_DECOMP_NOK;
            break;
        case Z_STREAM_ERROR:
            SCLogError(SC_ERR_FLASH_DECOMPRESSION, "The stream structure is inconsistent");
            ret = FILE_FLASH_DECOMP_NOK;         
            break;
        case Z_BUF_ERROR:
            SCLogError(SC_ERR_FLASH_DECOMPRESSION, "There is not enough space in the output buffer");
            ret = FILE_FLASH_DECOMP_NOK;
            break;
        default:
            SCLogError(SC_ERR_FLASH_DECOMPRESSION, "Unknown error, maybe a bug?");
            ret = FILE_FLASH_DECOMP_NOK;
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
static int FileDecompressFlashLzmaData(uint8_t *compressed_data, uint32_t compressed_data_len,
                                       uint8_t *decompressed_data, uint32_t decompressed_data_len)
{
#ifdef HAVE_LIBLZMA
    int ret = FILE_FLASH_DECOMP_OK;
    lzma_stream strm = LZMA_STREAM_INIT;
    lzma_ret result = lzma_alone_decoder(&strm, UINT64_MAX);
    if (result != LZMA_OK) {
        SCLogError(SC_ERR_FLASH_DECOMPRESSION, "Decoder initialization failed");
        return FILE_FLASH_DECOMP_NOK;
    }

    strm.avail_in = compressed_data_len;
    strm.next_in = compressed_data;
    strm.avail_out = decompressed_data_len;
    strm.next_out = decompressed_data;

    result = lzma_code(&strm, LZMA_RUN);
    switch(result) {
    case LZMA_MEMLIMIT_ERROR:
        SCLogError(SC_ERR_FLASH_DECOMPRESSION, "Memory allocation failed");
        ret = FILE_FLASH_DECOMP_NOK;
        break;
    case LZMA_OPTIONS_ERROR:
        SCLogError(SC_ERR_FLASH_DECOMPRESSION, "Unsupported decompressor flags");
        ret = FILE_FLASH_DECOMP_NOK;
        break;
    case LZMA_FORMAT_ERROR:
        SCLogError(SC_ERR_FLASH_DECOMPRESSION, "The input is an invalid format");
        ret = FILE_FLASH_DECOMP_NOK;
        break;
    case LZMA_DATA_ERROR:
        SCLogError(SC_ERR_FLASH_DECOMPRESSION, "Compressed file is corrupt");
        ret = FILE_FLASH_DECOMP_NOK;
        break;
    case LZMA_BUF_ERROR:
        SCLogError(SC_ERR_FLASH_DECOMPRESSION, "Compressed file is truncated or otherwise corrupt");
        ret = FILE_FLASH_DECOMP_NOK;
        break;
    case LZMA_OK:
        SCLogInfo("Decompression completed successfully");
        break;
    case LZMA_STREAM_END:
        SCLogInfo("End of stream was reached, all the data was decompressed");
        break;
    default:
        SCLogError(SC_ERR_FLASH_DECOMPRESSION, "Unknown error, maybe a bug?");
        ret = FILE_FLASH_DECOMP_NOK;
        break;
    }
    lzma_end(&strm);
    return ret;
#else
    SCLogError(SC_ERR_FLASH_NOSUPPORT,
               "You can't decompress flash files compressed with lzma! "
               "Library is missing.");
    return FILE_FLASH_DECOMP_NOK;
#endif /* HAVE_LIBLZMA */
}

int FileDecompressFlashFile(uint8_t **buffer, uint32_t *buffer_len, int swf_type,
                            uint32_t decompress_depth, uint32_t compress_depth)
{
    /* just for more readability */
    uint8_t *buf = *buffer;
    uint32_t buf_len = *buffer_len;

    int compression_type = FileIsFlashFile(buf, buf_len);
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
    uint32_t compressed_data_len = (compress_depth == 0) ? buf_len - offset: compress_depth;
    uint8_t *compressed_data = SCMalloc(compressed_data_len);
    if (compressed_data == NULL) {
        SCLogInfo("can't allocate memory for compressed_data");
        exit(EXIT_FAILURE);
    }

    /* get flash decompressed file length */
    uint32_t decompressed_swf_len = FileGetFlashDecompressedLen(buf);

    /* if decompress_depth is 0, keep the flash file length */
    uint32_t decompressed_data_len = (decompress_depth == 0) ? decompressed_swf_len : decompress_depth;
    uint8_t *decompressed_data = SCMalloc(decompressed_data_len);
    if (decompressed_data == NULL) {
        SCLogInfo("can't allocate memory for decompressed_data");
        exit(EXIT_FAILURE);
    }

    /* get file flash version */
    uint8_t flash_version = FileGetFlashVersion(buf, buf_len);

    if ((swf_type == HTTP_DECOMP_FLASH_ZLIB || swf_type == HTTP_DECOMP_FLASH_BOTH) &&
        compression_type == FILE_FLASH_ZLIB_COMPRESSION)
    {
        if (flash_version < FLASH_ZLIB_MIN_VERSION) {
            SCLogWarning(SC_ERR_FLASH_INVALID_VERSION,
                        "ZLIB compression is supported for "
                        "flash version 6 and later only");
            return FILE_FLASH_DECOMP_NOK;
        }
        /* put compressed data */
        memcpy(compressed_data, buf + offset, compressed_data_len);
        int r = FileDecompressFlashZlibData(compressed_data, compressed_data_len,
                                            decompressed_data, decompressed_data_len);
        if (r == FILE_FLASH_DECOMP_NOK)
            return FILE_FLASH_DECOMP_NOK;

    } else if ((swf_type == HTTP_DECOMP_FLASH_LZMA || swf_type == HTTP_DECOMP_FLASH_BOTH) &&
               compression_type == FILE_FLASH_LZMA_COMPRESSION)
    {
        if (flash_version < FLASH_LZMA_MIN_VERSION) {
            SCLogWarning(SC_ERR_FLASH_INVALID_VERSION,
                         "LZMA compression is supported for "
                         "flash version 13 and later only");
            return FILE_FLASH_DECOMP_NOK;
        }
        /* we need to setup the lzma header */
        /*
         * | 5 bytes         | 8 bytes             | n bytes         |
         * | LZMA properties | Uncompressed length | Compressed data |
         */
        compressed_data_len += 13;
        compressed_data = SCRealloc(compressed_data, compressed_data_len);
        if (compressed_data == NULL) {
            SCFree(compressed_data);
            SCLogInfo("Can't realloc memory for compressed_data");
            exit(EXIT_FAILURE);
        }
        /* put lzma properties */
        memcpy(compressed_data, buf + 12, 5);
        /* put lzma end marker */
        memset(compressed_data + 5, 0xFF, 8);
        /* put compressed data */
        memcpy(compressed_data + 13, buf + offset, buf_len - offset);

        int r = FileDecompressFlashLzmaData(compressed_data, compressed_data_len,
                                            decompressed_data, decompressed_data_len);
        if (r == FILE_FLASH_DECOMP_NOK)
            return FILE_FLASH_DECOMP_NOK;
    } else {
        goto out;
    }

    /*
     * FWS format
     * | 4 bytes         | 4 bytes    | n bytes |
     * | 'FWS' + version | script len | data    |
     */
    uint8_t *new_buffer = SCMalloc(decompressed_data_len + 8);
    if (new_buffer == NULL) {
        SCLogInfo("can't alloc memory for the buffer");
        exit(EXIT_FAILURE);
    }
    memcpy(new_buffer, "FWS", 3);
    memcpy(new_buffer + 3, &flash_version, 1);
    memcpy(new_buffer + 4, &decompressed_swf_len, 4);
    memcpy(new_buffer + 8, decompressed_data, decompressed_data_len);

    *buffer = new_buffer;
    *buffer_len = decompressed_data_len;

out:
    return FILE_FLASH_DECOMP_OK;
}
