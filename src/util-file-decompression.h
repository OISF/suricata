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
 *
 */

#ifndef __UTIL_FILE_DECOMPRESSION_H__
#define __UTIL_FILE_DECOMPRESSION_H__

#include "detect.h"

enum {
    FILE_IS_NOT_FLASH = 0,
    FILE_FLASH_NO_COMPRESSION,
    FILE_FLASH_ZLIB_COMPRESSION,
    FILE_FLASH_LZMA_COMPRESSION,
};

enum {
    FILE_DECODER_EVENT_NO_MEM,
    FILE_DECODER_EVENT_NO_FLASH_SUPPORT,
    FILE_DECODER_EVENT_INVALID_FLASH_VERSION,
    FILE_DECODER_EVENT_Z_STREAM_END,
    FILE_DECODER_EVENT_Z_OK,
    FILE_DECODER_EVENT_Z_DATA_ERROR,
    FILE_DECODER_EVENT_Z_STREAM_ERROR,
    FILE_DECODER_EVENT_Z_BUF_ERROR,
    FILE_DECODER_EVENT_Z_UNKNOWN_ERROR,
    FILE_DECODER_EVENT_LZMA_DECODER_ERROR,
    FILE_DECODER_EVENT_LZMA_STREAM_END,
    FILE_DECODER_EVENT_LZMA_OK,
    FILE_DECODER_EVENT_LZMA_MEMLIMIT_ERROR,
    FILE_DECODER_EVENT_LZMA_OPTIONS_ERROR,
    FILE_DECODER_EVENT_LZMA_FORMAT_ERROR,
    FILE_DECODER_EVENT_LZMA_DATA_ERROR,
    FILE_DECODER_EVENT_LZMA_BUF_ERROR,
    FILE_DECODER_EVENT_LZMA_UNKNOWN_ERROR,
};

int FileIsFlashFile(const uint8_t *buffer, uint32_t buffer_len);
int FileDecompressFlashFile(const uint8_t *buffer, uint32_t *buffer_len,
                            uint8_t **decompressed_buffer,
                            DetectEngineThreadCtx *det_ctx,
                            int swf_type,
                            uint32_t decompress_depth, uint32_t compress_depth);

int FileDecompressionGetEventInfo(const char *event_name, int *event_id,
                                  AppLayerEventType *event_type);
int FileDecompressionHasEvents(DetectEngineThreadCtx *det_ctx);
AppLayerDecoderEvents *FileDecompressionGetEvent(DetectEngineThreadCtx *det_ctx);
void FileDecompressionSetEvent(DetectEngineThreadCtx *det_ctx, uint8_t e);

#endif /* __UTIL_FILE_DECOMPRESSION_H__ */
