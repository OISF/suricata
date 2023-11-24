/* Copyright (C) 2007-2023 Open Information Security Foundation
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

#include "suricata-common.h"
#include "suricata.h"
#include "util-debug.h"
#include "util-buffer.h"

/* 10 mb */
#define MAX_LIMIT 10485760

MemBuffer *MemBufferCreateNew(uint32_t size)
{
    sc_errno = SC_OK;
    if (size > MAX_LIMIT) {
        SCLogWarning("Mem buffer asked to create "
                     "buffer with size greater than API limit - %d",
                MAX_LIMIT);
        sc_errno = SC_EINVAL;
        return NULL;
    }

    size_t total_size = size + sizeof(MemBuffer);

    MemBuffer *buffer = SCCalloc(1, total_size);
    if (unlikely(buffer == NULL)) {
        sc_errno = SC_ENOMEM;
        return NULL;
    }
    buffer->size = size;
    return buffer;
}

/** \brief expand membuffer by size of 'expand_by'
 *
 *  If expansion failed, buffer will still be valid.
 *
 *  \retval result 0 ok, -1 expansion failed
 */
int MemBufferExpand(MemBuffer **buffer, uint32_t expand_by) {
    if (((*buffer)->size + expand_by) > MAX_LIMIT) {
        SCLogWarning("Mem buffer asked to create "
                     "buffer with size greater than API limit - %d",
                MAX_LIMIT);
        return -1;
    }

    size_t total_size = (*buffer)->size + sizeof(MemBuffer) + expand_by;

    MemBuffer *tbuffer = SCRealloc(*buffer, total_size);
    if (unlikely(tbuffer == NULL)) {
        return -1;
    }
    *buffer = tbuffer;
    (*buffer)->size += expand_by;

    SCLogDebug("expanded buffer by %u, size is now %u", expand_by, (*buffer)->size);
    return 0;
}

void MemBufferFree(MemBuffer *buffer)
{
    SCFree(buffer);

    return;
}

void MemBufferPrintToFP(MemBuffer *buffer, FILE *fp)
{
    for (uint32_t i = 0; i < buffer->offset; i++) {
        if (isprint(buffer->buffer[i]))
            fprintf(fp, "%c", buffer->buffer[i]);
        else
            fprintf(fp, "|%02X|", buffer->buffer[i]);
    }
}

size_t MemBufferPrintToFPAsString(MemBuffer *b, FILE *fp)
{
    return fwrite(MEMBUFFER_BUFFER(b), sizeof(uint8_t), MEMBUFFER_OFFSET(b), fp);
}

void MemBufferPrintToFPAsHex(MemBuffer *b, FILE *fp)
{
    for (uint32_t i = 0; i < MEMBUFFER_OFFSET(b); i++) {
        if (MEMBUFFER_OFFSET(b) % 8 == 0)
            fprintf(fp, "\n");
        fprintf(fp, " %02X", b->buffer[i]);
    }
}

void MemBufferWriteRaw(MemBuffer *dst, const uint8_t *raw, const uint32_t raw_len)
{
    uint32_t write_len;
    if (raw_len >= dst->size - dst->offset) {
        SCLogDebug("Truncating data write since it exceeded buffer limit of %" PRIu32, dst->size);
        write_len = dst->size - dst->offset - 1;
    } else {
        write_len = raw_len;
    }
    memcpy(dst->buffer + dst->offset, raw, write_len);
    dst->offset += write_len;
    dst->buffer[dst->offset] = '\0';
}

void MemBufferWriteString(MemBuffer *dst, const char *fmt, ...)
{
    uint32_t available = dst->size - dst->offset;
    uint32_t max_string_size = MIN(available, 2048);
    va_list ap;
    char string[max_string_size];
    va_start(ap, fmt);
    int written = vsnprintf(string, sizeof(string), fmt, ap);
    va_end(ap);
    if (written < 0) {
        return;
    } else if ((uint32_t)written > max_string_size) {
        SCLogDebug("Truncating data write since it exceeded buffer "
                   "limit of %" PRIu32,
                dst->size);
    }
    size_t string_size = strlen(string);
    memcpy(dst->buffer + dst->offset, string, string_size);
    dst->offset += string_size;
    dst->buffer[dst->offset] = '\0';
}
