/* Copyright (C) 2007-2022 Open Information Security Foundation
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



#ifndef __UTIL_PRINT_H__
#define __UTIL_PRINT_H__

#define PrintBufferData(buf, buf_offset_ptr, buf_size, ...) do {         \
        int cw = snprintf((buf) + *(buf_offset_ptr),                    \
                          (buf_size) - *(buf_offset_ptr),                \
                          __VA_ARGS__);                                 \
        if (cw >= 0) {                                                  \
            if ( (*(buf_offset_ptr) + cw) >= buf_size) {                \
                SCLogDebug("Truncating data write since it exceeded buffer " \
                           "limit of - %"PRIu32"\n", buf_size);         \
                *(buf_offset_ptr) = buf_size - 1;                       \
            } else {                                                    \
                *(buf_offset_ptr) += cw;                                \
            }                                                           \
        }                                                               \
    } while (0)

void PrintBufferRawLineHex(char *, int *,int, const uint8_t *, uint32_t);
void PrintRawUriFp(FILE *, uint8_t *, uint32_t);
void PrintRawUriBuf(char *, uint32_t *, uint32_t,
                    uint8_t *, uint32_t);
void PrintRawJsonFp(FILE *, uint8_t *, uint32_t);
void PrintRawDataFp(FILE *, const uint8_t *, uint32_t);
void PrintRawDataToBuffer(uint8_t *dst_buf, uint32_t *dst_buf_offset_ptr, uint32_t dst_buf_size,
                          const uint8_t *src_buf, uint32_t src_buf_len);
void PrintStringsToBuffer(uint8_t *dst_buf, uint32_t *dst_buf_offset_ptr, uint32_t dst_buf_size,
                          const uint8_t *src_buf, const uint32_t src_buf_len);
void PrintRawLineHexBuf(char *, uint32_t, const uint8_t *, uint32_t );
const char *PrintInet(int , const void *, char *, socklen_t);
void PrintHexString(char *str, size_t size, uint8_t *buf, size_t buf_len);

#endif /* __UTIL_PRINT_H__ */

