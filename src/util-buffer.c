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

#include "suricata-common.h"
#include "util-debug.h"
#include "util-buffer.h"

/* 10 mb */
#define MAX_LIMIT 10485760

MemBuffer *MemBufferCreateNew(uint32_t size)
{
    if (size > MAX_LIMIT) {
        SCLogWarning(SC_ERR_MEM_BUFFER_API, "Mem buffer asked to create "
                     "buffer with size greater than API limit - %d", MAX_LIMIT);
        return NULL;
    }

    uint32_t total_size = size + sizeof(MemBuffer);

    MemBuffer *buffer = SCMalloc(total_size);
    if (unlikely(buffer == NULL)) {
        return NULL;
    }
    memset(buffer, 0, total_size);

    buffer->size = size;
    buffer->buffer = (uint8_t *)buffer + sizeof(MemBuffer);

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
        SCLogWarning(SC_ERR_MEM_BUFFER_API, "Mem buffer asked to create "
                     "buffer with size greater than API limit - %d", MAX_LIMIT);
        return -1;
    }

    uint32_t total_size = (*buffer)->size + sizeof(MemBuffer) + expand_by;

    MemBuffer *tbuffer = SCRealloc(*buffer, total_size);
    if (unlikely(tbuffer == NULL)) {
        return -1;
    }

    *buffer = tbuffer;
    (*buffer)->size += expand_by;
    (*buffer)->buffer = (uint8_t *)tbuffer + sizeof(MemBuffer);

    SCLogDebug("expanded buffer by %u, size is now %u", expand_by, (*buffer)->size);
    return 0;
}

void MemBufferFree(MemBuffer *buffer)
{
    SCFree(buffer);

    return;
}
