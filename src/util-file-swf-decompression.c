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

#include <zlib.h>

#include <htp/lzma/LzmaDec.h>

#define MAX_SWF_DECOMPRESSED_LEN 50000000
/*
 * Return uncompressed file length
 * in little-endian order
 */
uint32_t FileGetSwfDecompressedLen(const uint8_t *buffer,
                                   const uint32_t buffer_len)
{
    if (buffer_len < 8) {
        return 0;
    }

    uint32_t a = buffer[4];
    uint32_t b = buffer[5];
    uint32_t c = buffer[6];
    uint32_t d = buffer[7];

    uint32_t value = (((a & 0xff) << 24UL) |
                      ((b & 0xff) << 16UL) |
                      ((c & 0xff) << 8UL) |
                       (d & 0xff));

    uint32_t len = (((value >> 24) & 0x000000FFUL) |
                    ((value >> 8)  & 0x0000FF00UL) |
                    ((value << 8)  & 0x00FF0000UL) |
                    ((value << 24) & 0xFF000000UL));

    return MIN(MAX_SWF_DECOMPRESSED_LEN, len);
}

uint8_t FileGetSwfVersion(const uint8_t *buffer, const uint32_t buffer_len)
{
    if (buffer_len > 3)
        return buffer[3];

    return 0;
}

/* CWS format */
/*
 * | 4 bytes         | 4 bytes    | n bytes         |
 * | 'CWS' + version | script len | compressed data |
 */
int FileSwfZlibDecompression(DetectEngineThreadCtx *det_ctx,
                             uint8_t *compressed_data, uint32_t compressed_data_len,
                             uint8_t *decompressed_data, uint32_t decompressed_data_len)
{
    int ret = 1;
    z_stream infstream;
    memset(&infstream, 0, sizeof(infstream));
    infstream.zalloc = Z_NULL;
    infstream.zfree = Z_NULL;
    infstream.opaque = Z_NULL;

    infstream.avail_in = (uInt)compressed_data_len;
    infstream.next_in = (Bytef *)compressed_data;
    infstream.avail_out = (uInt)decompressed_data_len;
    infstream.next_out = (Bytef *)decompressed_data;

    int result = inflateInit(&infstream);
    if (result != Z_OK) {
        DetectEngineSetEvent(det_ctx, FILE_DECODER_EVENT_Z_UNKNOWN_ERROR);
        return 0;
    }

    result = inflate(&infstream, Z_NO_FLUSH);
    switch(result) {
        case Z_STREAM_END:
            break;
        case Z_OK:
            break;
        case Z_DATA_ERROR:
            DetectEngineSetEvent(det_ctx, FILE_DECODER_EVENT_Z_DATA_ERROR);
            ret = 0;
            break;
        case Z_STREAM_ERROR:
            DetectEngineSetEvent(det_ctx, FILE_DECODER_EVENT_Z_STREAM_ERROR);
            ret = 0;
            break;
        case Z_BUF_ERROR:
            DetectEngineSetEvent(det_ctx, FILE_DECODER_EVENT_Z_BUF_ERROR);
            ret = 0;
            break;
        default:
            DetectEngineSetEvent(det_ctx, FILE_DECODER_EVENT_Z_UNKNOWN_ERROR);
            ret = 0;
            break;
    }
    inflateEnd(&infstream);

    return ret;
}

static void *SzAlloc(ISzAllocPtr p, size_t size) { return malloc(size); }
static void SzFree(ISzAllocPtr p, void *address) { free(address); }
static const ISzAlloc suri_lzma_Alloc = { SzAlloc, SzFree };

/* ZWS format */
/*
 * | 4 bytes         | 4 bytes    | 4 bytes        | 5 bytes    | n bytes   | 6 bytes         |
 * | 'ZWS' + version | script len | compressed len | LZMA props | LZMA data | LZMA end marker |
 */
int FileSwfLzmaDecompression(DetectEngineThreadCtx *det_ctx,
                             uint8_t *compressed_data, uint32_t compressed_data_len,
                             uint8_t *decompressed_data, uint32_t decompressed_data_len)
{
    int ret = 0;

    CLzmaDec strm;
    LzmaDec_Construct(&strm);
    ELzmaStatus status;

    if (compressed_data_len < LZMA_PROPS_SIZE + 8) {
        DetectEngineSetEvent(det_ctx, FILE_DECODER_EVENT_LZMA_FORMAT_ERROR);
        return 0;
    }
    ret = LzmaDec_Allocate(&strm, compressed_data, LZMA_PROPS_SIZE, &suri_lzma_Alloc);
    if (ret != SZ_OK) {
        DetectEngineSetEvent(det_ctx, FILE_DECODER_EVENT_LZMA_DECODER_ERROR);
        return 0;
    }
    LzmaDec_Init(&strm);
    compressed_data += LZMA_PROPS_SIZE + 8;
    compressed_data_len -= LZMA_PROPS_SIZE + 8;
    size_t inprocessed = compressed_data_len;
    size_t outprocessed = decompressed_data_len;

    ret = LzmaDec_DecodeToBuf(&strm, decompressed_data, &outprocessed,
                             compressed_data, &inprocessed, LZMA_FINISH_ANY, &status, MAX_SWF_DECOMPRESSED_LEN);

    switch(ret) {
        case SZ_OK:
            ret = 1;
            break;
        case SZ_ERROR_MEM:
            DetectEngineSetEvent(det_ctx, FILE_DECODER_EVENT_LZMA_MEMLIMIT_ERROR);
            ret = 0;
            break;
        case SZ_ERROR_UNSUPPORTED:
            DetectEngineSetEvent(det_ctx, FILE_DECODER_EVENT_LZMA_OPTIONS_ERROR);
            ret = 0;
            break;
        case SZ_ERROR_DATA:
            DetectEngineSetEvent(det_ctx, FILE_DECODER_EVENT_LZMA_DATA_ERROR);
            ret = 0;
            break;
        case SZ_ERROR_INPUT_EOF:
            DetectEngineSetEvent(det_ctx, FILE_DECODER_EVENT_LZMA_BUF_ERROR);
            ret = 0;
            break;
        default:
            DetectEngineSetEvent(det_ctx, FILE_DECODER_EVENT_LZMA_UNKNOWN_ERROR);
            ret = 0;
            break;
    }

    LzmaDec_Free(&strm, &suri_lzma_Alloc);
    return ret;
}
