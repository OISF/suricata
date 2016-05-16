/* Copyright (C) 2007-2012 Open Information Security Foundation
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
 * \author Anoop Saldanha <anoopsaldanha@gmail.com>
 */

#ifndef __UTIL_BUFFER_H__
#define __UTIL_BUFFER_H__

typedef struct MemBuffer_ {
   uint8_t *buffer;
   uint32_t size;
   uint32_t offset;
} MemBuffer;

MemBuffer *MemBufferCreateNew(uint32_t size);
int MemBufferExpand(MemBuffer **buffer, uint32_t expand_by);
void MemBufferFree(MemBuffer *buffer);

/**
 * \brief Reset the mem buffer.
 *
 * \param mem_buffer Pointer to the mem buffer instance.
 */
#define MemBufferReset(mem_buffer) do {                     \
        (mem_buffer)->buffer[0] = 0;                        \
        (mem_buffer)->offset = 0;                           \
    } while (0)

/**
 * \brief Get the MemBuffers underlying buffer.
 */
#define MEMBUFFER_BUFFER(mem_buffer) (mem_buffer)->buffer

/**
 * \brief Get the MemBuffers current offset.
 */
#define MEMBUFFER_OFFSET(mem_buffer) (mem_buffer)->offset

/**
 * \brief Get the MemBuffers current size.
 */
#define MEMBUFFER_SIZE(mem_buffer) (mem_buffer)->size

/**
 * \brief Write a buffer to the file pointer.
 *
 *        Accepted buffers can contain both printable and non-printable
 *        characters.  Printable characters are written in the printable
 *        format and the non-printable chars are written in hex codes
 *        using the |XX| format.
 *
 *        For example this would be the kind of output in the file -
 *        onetwo|EF|three|ED|five
 *
 * \param buffer Pointer to the src MemBuffer instance to write.
 * \param fp     Pointer to the file file instance to write to.
 */
#define MemBufferPrintToFP(buffer, fp) do {             \
        uint32_t i;                                     \
                                                        \
        for (i = 0; i < (buffer)->offset; i++) {            \
            if (isprint(buffer->buffer[i]))                 \
                fprintf(fp, "%c", (buffer)->buffer[i]);     \
            else                                            \
                fprintf(fp, "|%02X|", (buffer)->buffer[i]); \
        }                                                   \
    } while (0)

/**
 * \brief Write a buffer to the file pointer as a printable char string.
 *
 * \param buffer Pointer to the src MemBuffer instance to write.
 * \param fp     Pointer to the file file instance to write to.
 */
#define MemBufferPrintToFPAsString(mem_buffer, fp) ({                           \
    fwrite((mem_buffer)->buffer, sizeof(uint8_t), (mem_buffer)->offset, fp);    \
})

/**
 * \brief Write a buffer in hex format.
 *
 * \param buffer Pointer to the src MemBuffer instance to write.
 * \param fp     Pointer to the file file instance to write to.
 */
#define MemBufferPrintToFPAsHex(buffer, fp) do {        \
        uint32_t i;                                     \
                                                        \
        for (i = 0; i < (buffer)->offset; i++) {        \
            if (((buffer)->offset % 8) == 0)            \
                fprintf(fp, "\n");                      \
            fprintf(fp, " %02X", (buffer)->buffer[i]);  \
        }                                               \
    } while (0)


/**
 * \brief Write a raw buffer to the MemBuffer dst.
 *
 *        When we say raw buffer it indicates a buffer that need not be
 *        purely a string buffer.  It can be a pure string buffer or not or
 *        a mixture of both.  Hence we don't accept any format strings.
 *
 *        If the remaining space on the buffer is lesser than the length of
 *        the buffer to write, it is truncated to fit into the empty space.
 *
 *        Also after every write a '\0' is appended.  This would indicate
 *        that the total available space to write in the buffer is
 *        MemBuffer->size - 1 and not Membuffer->size.  The reason we
 *        append the '\0' is for supporting writing pure string buffers
 *        as well, that can later be used by other string handling funcs.
 *
 * \param raw_buffer     The buffer to write.
 * \param raw_buffer_len Length of the above buffer.
 */
#define MemBufferWriteRaw(dst, raw_buffer, raw_buffer_len) do { \
        uint32_t write_len;                                     \
                                                                \
        if (((raw_buffer_len) >= (dst)->size - (dst)->offset)) {        \
            SCLogDebug("Truncating data write since it exceeded buffer limit of " \
                       "- %"PRIu32, (dst)->size);                       \
            write_len = ((dst)->size - (dst)->offset) - 1;              \
        } else {                                                        \
            write_len = (raw_buffer_len);                               \
        }                                                               \
                                                                        \
        memcpy((dst)->buffer + (dst)->offset, (raw_buffer), write_len); \
        (dst)->offset += write_len;                                     \
        dst->buffer[dst->offset] = '\0';                                \
    } while (0)

/**
 * \brief Write a string buffer to the Membuffer dst.
 *
 *        This function takes a format string and arguments for the format
 *        string like sprintf.
 *
 *        An example usage of this is -
 *        MemBufferWriteString(mem_buffer_instance, \"%d - %s\", 10, \"one\");
 *
 * \param dst    The dst MemBuffer instance.
 * \param format The format string.
 * \param ...    Variable arguments.
 */
#define MemBufferWriteString(dst, ...) do {                             \
        int cw = snprintf((char *)(dst)->buffer + (dst)->offset,        \
                          (dst)->size - (dst)->offset,                  \
                          __VA_ARGS__);                                 \
        if (cw >= 0) {                                                  \
            if ( ((dst)->offset + cw) >= (dst)->size) {                 \
                SCLogDebug("Truncating data write since it exceeded buffer " \
                           "limit of - %"PRIu32"\n", (dst)->size); \
                (dst)->offset = (dst)->size - 1;                        \
            } else {                                                    \
                (dst->offset) += cw;                                    \
            }                                                           \
        }                                                               \
    } while (0)

#endif /* __UTIL_BUFFER_H__ */
