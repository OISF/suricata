/* Copyright (C) 2026 Open Information Security Foundation
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

#ifndef SURICATA_UTIL_RING_BUFFER_H
#define SURICATA_UTIL_RING_BUFFER_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/** Bounded FIFO of fixed-size elements, used by one thread without synchronization.
 * Element contents remain owned by the caller; freeing the FIFO only frees storage. */
typedef struct SCRingBuffer_ SCRingBuffer;

/** Capacity must be a nonzero power of two and element_size must be nonzero.
 * Every slot is usable. Returns NULL for invalid sizes or allocation failure. */
SCRingBuffer *SCRingBufferInit(uint32_t capacity, size_t element_size);
void SCRingBufferFree(SCRingBuffer *rb);
uint32_t SCRingBufferCount(const SCRingBuffer *rb);
uint32_t SCRingBufferSpace(const SCRingBuffer *rb);

/** Transfer all count elements or return false without changing state or output.
 * Zero count succeeds for a valid buffer, including with NULL items. Nonzero
 * transfers require non-NULL items that do not overlap the FIFO's storage. */
bool SCRingBufferEnqueue(SCRingBuffer *rb, const void *items, uint32_t count);
bool SCRingBufferDequeue(SCRingBuffer *rb, void *items, uint32_t count);

/** Return writable contiguous elements and their count, or NULL/count=0 if full
 * or rb is NULL. count must be non-NULL. No storage is reserved, the pointer is
 * valid until the next state-changing enqueue, dequeue, or commit. */
void *SCRingBufferEnqueueSpanGet(SCRingBuffer *rb, uint32_t *count);

/** Publish elements filled through EnqueueSpanGet. Reject counts beyond the current
 * writable contiguous span without changing state. Zero count changes nothing. */
bool SCRingBufferEnqueueSpanCommit(SCRingBuffer *rb, uint32_t count);

void SCRingBufferRegisterTests(void);

#endif /* SURICATA_UTIL_RING_BUFFER_H */
