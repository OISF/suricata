/* Copyright (C) 2025 Open Information Security Foundation
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

#include "suricata-common.h"
#include "detect-engine-inspect-buffer.h"

#include "util-validate.h"

/**
 * \brief make sure that the buffer has at least 'min_size' bytes
 * Expand the buffer if necessary
 */
uint8_t *SCInspectionBufferCheckAndExpand(InspectionBuffer *buffer, uint32_t min_size)
{
    if (likely(buffer->size >= min_size))
        return buffer->buf;

    uint32_t new_size = (buffer->size == 0) ? 4096 : buffer->size;
    while (new_size < min_size) {
        new_size *= 2;
    }

    void *ptr = SCRealloc(buffer->buf, new_size);
    if (ptr != NULL) {
        buffer->buf = ptr;
        buffer->size = new_size;
    } else {
        return NULL;
    }
    return buffer->buf;
}

void SCInspectionBufferTruncate(InspectionBuffer *buffer, uint32_t buf_len)
{
    DEBUG_VALIDATE_BUG_ON(buffer->buf == NULL);
    DEBUG_VALIDATE_BUG_ON(buf_len > buffer->size);
    buffer->inspect = buffer->buf;
    buffer->inspect_len = buf_len;
    buffer->initialized = true;
}

void InspectionBufferCopy(InspectionBuffer *buffer, uint8_t *buf, uint32_t buf_len)
{
    SCInspectionBufferCheckAndExpand(buffer, buf_len);

    if (buffer->size) {
        uint32_t copy_size = MIN(buf_len, buffer->size);
        memcpy(buffer->buf, buf, copy_size);
        buffer->inspect = buffer->buf;
        buffer->inspect_len = copy_size;
        buffer->initialized = true;
    }
}
