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
 *
 */

#ifndef __UTIL_FILE_SWF_DECOMPRESSION_H__
#define __UTIL_FILE_SWF_DECOMPRESSION_H__

/* If we don't have the decompressed data len,
 * we use a default value.
 */
#define MIN_SWF_LEN    2920

uint8_t FileGetSwfVersion(const uint8_t *buffer, const uint32_t buffer_len);
uint32_t FileGetSwfDecompressedLen(const uint8_t *buffer, uint32_t buffer_len);
int FileSwfZlibDecompression(DetectEngineThreadCtx *det_ctx,
                             uint8_t *compressed_data, uint32_t compressed_data_len,
                             uint8_t *decompressed_data, uint32_t decompressed_data_len);
int FileSwfLzmaDecompression(DetectEngineThreadCtx *det_ctx,
                             uint8_t *compressed_data, uint32_t compressed_data_len,
                             uint8_t *decompressed_data, uint32_t decompressed_data_len);

#endif /* __UTIL_FILE_SWF_DECOMPRESSION_H__ */
