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

#include "suricata-common.h"
#include "util-ring-buffer.h"
#include "util-unittest.h"

// Bit-mask to wrap the index around the ring buffer capacity (power of 2)
#define SCRINGBUFFER_ADVANCE(index, count, capacity) (((index) + (count)) & ((capacity)-1))

struct SCRingBuffer_ {
    uint8_t *data;
    size_t element_size;
    uint32_t capacity;
    uint32_t head;
    uint32_t tail;
    uint32_t count;
};

SCRingBuffer *SCRingBufferInit(uint32_t capacity, size_t element_size)
{
    if (capacity == 0 || (capacity & (capacity - 1)) != 0 || element_size == 0 ||
            element_size > SIZE_MAX / capacity) {
        return NULL;
    }
    SCRingBuffer *rb = SCCalloc(1, sizeof(*rb));
    if (rb == NULL) {
        return NULL;
    }
    rb->data = SCMalloc(capacity * element_size);
    if (rb->data == NULL) {
        SCFree(rb);
        return NULL;
    }
    rb->capacity = capacity;
    rb->element_size = element_size;
    return rb;
}

void SCRingBufferFree(SCRingBuffer *rb)
{
    if (rb != NULL) {
        SCFree(rb->data);
        SCFree(rb);
    }
}

uint32_t SCRingBufferCount(const SCRingBuffer *rb)
{
    return rb == NULL ? 0 : rb->count;
}

uint32_t SCRingBufferSpace(const SCRingBuffer *rb)
{
    return rb == NULL ? 0 : rb->capacity - rb->count;
}

bool SCRingBufferEnqueue(SCRingBuffer *rb, const void *items, uint32_t count)
{
    if (rb == NULL || count > (rb->capacity - rb->count) || (count > 0 && items == NULL)) {
        return false;
    }
    if (count == 0) {
        return true;
    }
    uint32_t first_chunk_count = MIN(count, rb->capacity - rb->tail);
    size_t first_chunk_size = first_chunk_count * rb->element_size;
    memcpy(rb->data + rb->tail * rb->element_size, items, first_chunk_size);
    if (first_chunk_count < count) {
        memcpy(rb->data, (const uint8_t *)items + first_chunk_size,
                (count - first_chunk_count) * rb->element_size);
    }
    rb->tail = SCRINGBUFFER_ADVANCE(rb->tail, count, rb->capacity);
    rb->count += count;
    return true;
}

bool SCRingBufferDequeue(SCRingBuffer *rb, void *items, uint32_t count)
{
    if (rb == NULL || count > rb->count || (count > 0 && items == NULL)) {
        return false;
    }
    if (count == 0) {
        return true;
    }
    uint32_t first_chunk_count = MIN(count, rb->capacity - rb->head);
    size_t first_chunk_size = first_chunk_count * rb->element_size;
    memcpy(items, rb->data + rb->head * rb->element_size, first_chunk_size);
    if (first_chunk_count < count) {
        memcpy((uint8_t *)items + first_chunk_size, rb->data,
                (count - first_chunk_count) * rb->element_size);
    }
    rb->head = SCRINGBUFFER_ADVANCE(rb->head, count, rb->capacity);
    rb->count -= count;
    return true;
}

void *SCRingBufferEnqueueSpanGet(SCRingBuffer *rb, uint32_t *count)
{
    *count = 0;
    if (rb == NULL || rb->count == rb->capacity) {
        return NULL;
    }
    *count = MIN(rb->capacity - rb->count, rb->capacity - rb->tail);
    return rb->data + rb->tail * rb->element_size;
}

bool SCRingBufferEnqueueSpanCommit(SCRingBuffer *rb, uint32_t count)
{
    if (rb == NULL || count > MIN(rb->capacity - rb->count, rb->capacity - rb->tail)) {
        return false;
    }
    rb->tail = SCRINGBUFFER_ADVANCE(rb->tail, count, rb->capacity);
    rb->count += count;
    return true;
}

#ifdef UNITTESTS
static int SCRingBufferTestInitialization(void)
{
    FAIL_IF_NOT_NULL(SCRingBufferInit(0, sizeof(uint32_t)));
    FAIL_IF_NOT_NULL(SCRingBufferInit(3, sizeof(uint32_t)));
    FAIL_IF_NOT_NULL(SCRingBufferInit(4, 0));
    FAIL_IF_NOT_NULL(SCRingBufferInit(2, SIZE_MAX / 2 + 1));
    FAIL_IF(SCRingBufferCount(NULL) != 0);
    FAIL_IF(SCRingBufferSpace(NULL) != 0);
    SCRingBufferFree(NULL);

    SCRingBuffer *rb = SCRingBufferInit(8, sizeof(uint32_t));
    FAIL_IF_NULL(rb);
    FAIL_IF(SCRingBufferCount(rb) != 0);
    FAIL_IF(SCRingBufferSpace(rb) != 8);
    SCRingBufferFree(rb);
    PASS;
}

static int SCRingBufferTestFullCapacity(void)
{
    struct {
        uint8_t bytes[3];
    } input[] = { { { 1, 2, 3 } }, { { 4, 5, 6 } }, { { 7, 8, 9 } }, { { 10, 11, 12 } } };
    uint8_t output[sizeof(input)] = { 0 };
    SCRingBuffer *rb = SCRingBufferInit(4, sizeof(input[0]));
    FAIL_IF_NULL(rb);
    FAIL_IF_NOT(SCRingBufferEnqueue(rb, input, 4));
    FAIL_IF(SCRingBufferCount(rb) != 4 || SCRingBufferSpace(rb) != 0);
    FAIL_IF(SCRingBufferEnqueue(rb, input, 1));
    FAIL_IF_NOT(SCRingBufferDequeue(rb, output, 4));
    FAIL_IF(memcmp(input, output, sizeof(input)) != 0);
    FAIL_IF(SCRingBufferCount(rb) != 0 || SCRingBufferSpace(rb) != 4);
    SCRingBufferFree(rb);

    rb = SCRingBufferInit(1, sizeof(input[0]));
    FAIL_IF_NULL(rb);
    FAIL_IF_NOT(SCRingBufferEnqueue(rb, input, 1));
    FAIL_IF(SCRingBufferCount(rb) != 1 || SCRingBufferSpace(rb) != 0);
    FAIL_IF_NOT(SCRingBufferDequeue(rb, output, 1));
    FAIL_IF(memcmp(input, output, sizeof(input[0])) != 0);
    SCRingBufferFree(rb);
    PASS;
}

static int SCRingBufferTestWrapFifo(void)
{
    const uint32_t input[] = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12 };
    uint32_t output[8];
    SCRingBuffer *rb = SCRingBufferInit(8, sizeof(input[0]));
    FAIL_IF_NULL(rb);
    FAIL_IF_NOT(SCRingBufferEnqueue(rb, input, 6));
    FAIL_IF_NOT(SCRingBufferDequeue(rb, output, 5));
    FAIL_IF(memcmp(output, input, 5 * sizeof(input[0])) != 0);
    FAIL_IF_NOT(SCRingBufferEnqueue(rb, input + 6, 7));
    FAIL_IF(SCRingBufferCount(rb) != 8 || SCRingBufferSpace(rb) != 0);
    FAIL_IF_NOT(SCRingBufferDequeue(rb, output, 8));
    FAIL_IF(memcmp(output, input + 5, sizeof(output)) != 0);
    FAIL_IF(SCRingBufferCount(rb) != 0 || SCRingBufferSpace(rb) != 8);
    SCRingBufferFree(rb);
    PASS;
}

static int SCRingBufferTestRejectedTransfers(void)
{
    const uint32_t input[] = { 1, 2, 3, 4, 5 };
    const uint32_t sentinel[] = { 99, 99, 99, 99 };
    uint32_t output[4];
    memcpy(output, sentinel, sizeof(output));
    SCRingBuffer *rb = SCRingBufferInit(4, sizeof(input[0]));
    FAIL_IF_NULL(rb);
    FAIL_IF_NOT(SCRingBufferEnqueue(rb, input, 3));
    FAIL_IF(SCRingBufferEnqueue(rb, input + 3, 2));
    FAIL_IF(SCRingBufferDequeue(rb, output, 4));
    FAIL_IF(memcmp(output, sentinel, sizeof(output)) != 0);
    FAIL_IF(SCRingBufferEnqueue(rb, NULL, 1));
    FAIL_IF(SCRingBufferDequeue(rb, NULL, 1));
    FAIL_IF(SCRingBufferCount(rb) != 3 || SCRingBufferSpace(rb) != 1);
    FAIL_IF_NOT(SCRingBufferDequeue(rb, output, 3));
    FAIL_IF(memcmp(output, input, 3 * sizeof(input[0])) != 0);
    SCRingBufferFree(rb);
    PASS;
}

static int SCRingBufferTestZeroLength(void)
{
    uint32_t item = 7;
    SCRingBuffer *rb = SCRingBufferInit(2, sizeof(item));
    FAIL_IF_NULL(rb);
    FAIL_IF_NOT(SCRingBufferEnqueue(rb, &item, 1));
    FAIL_IF_NOT(SCRingBufferEnqueue(rb, NULL, 0));
    FAIL_IF_NOT(SCRingBufferDequeue(rb, NULL, 0));
    FAIL_IF_NOT(SCRingBufferEnqueueSpanCommit(rb, 0));
    FAIL_IF(SCRingBufferCount(rb) != 1 || SCRingBufferSpace(rb) != 1);
    uint32_t output = 0;
    FAIL_IF_NOT(SCRingBufferDequeue(rb, &output, 1));
    FAIL_IF(output != item);
    SCRingBufferFree(rb);
    PASS;
}

static int SCRingBufferTestWriteSpan(void)
{
    SCRingBuffer *rb = SCRingBufferInit(4, sizeof(uint32_t));
    FAIL_IF_NULL(rb);
    uint32_t count = 0;
    uint32_t *span = SCRingBufferEnqueueSpanGet(rb, &count);
    FAIL_IF_NULL(span);
    FAIL_IF(count != 4);
    span[0] = 1;
    span[1] = 2;
    span[2] = 3;
    uint32_t output[4] = { 99, 99, 99, 99 };
    FAIL_IF(SCRingBufferDequeue(rb, output, 1));
    FAIL_IF(output[0] != 99);
    FAIL_IF_NOT(SCRingBufferEnqueueSpanCommit(rb, 0));
    FAIL_IF(SCRingBufferCount(rb) != 0);
    FAIL_IF_NOT(SCRingBufferEnqueueSpanCommit(rb, 3));
    span = SCRingBufferEnqueueSpanGet(rb, &count);
    FAIL_IF_NULL(span);
    FAIL_IF(count != 1);
    span[0] = 4;
    FAIL_IF(SCRingBufferEnqueueSpanCommit(rb, 2));
    FAIL_IF(SCRingBufferCount(rb) != 3 || SCRingBufferSpace(rb) != 1);
    FAIL_IF_NOT(SCRingBufferEnqueueSpanCommit(rb, 1));
    FAIL_IF_NOT_NULL(SCRingBufferEnqueueSpanGet(rb, &count));
    FAIL_IF(count != 0);
    FAIL_IF_NOT(SCRingBufferEnqueueSpanCommit(rb, 0));
    FAIL_IF_NOT(SCRingBufferDequeue(rb, output, 3));
    FAIL_IF(output[0] != 1 || output[1] != 2 || output[2] != 3);

    span = SCRingBufferEnqueueSpanGet(rb, &count);
    FAIL_IF_NULL(span);
    FAIL_IF(count != 3);
    span[0] = 5;
    span[1] = 6;
    FAIL_IF_NOT(SCRingBufferEnqueueSpanCommit(rb, 2));
    FAIL_IF_NOT(SCRingBufferDequeue(rb, output, 3));
    FAIL_IF(output[0] != 4 || output[1] != 5 || output[2] != 6);
    SCRingBufferFree(rb);
    PASS;
}

static int SCRingBufferTestCallerOwnership(void)
{
    uint32_t values[] = { 11, 22 };
    uint32_t *input[] = { &values[0], &values[1] };
    uint32_t *output = NULL;
    SCRingBuffer *rb = SCRingBufferInit(2, sizeof(input[0]));
    FAIL_IF_NULL(rb);
    FAIL_IF_NOT(SCRingBufferEnqueue(rb, input, 2));
    FAIL_IF_NOT(SCRingBufferDequeue(rb, &output, 1));
    FAIL_IF(output != input[0]);
    SCRingBufferFree(rb);
    FAIL_IF(values[0] != 11 || values[1] != 22);
    PASS;
}

static int SCRingBufferTestSpanBoundary(void)
{
    const uint32_t input[] = { 1, 2, 3 };
    uint32_t output[4];
    SCRingBuffer *rb = SCRingBufferInit(4, sizeof(input[0]));
    FAIL_IF_NULL(rb);
    FAIL_IF_NOT(SCRingBufferEnqueue(rb, input, 3));
    FAIL_IF_NOT(SCRingBufferDequeue(rb, output, 2));
    uint32_t count = 0;
    uint32_t *span = SCRingBufferEnqueueSpanGet(rb, &count);
    FAIL_IF_NULL(span);
    FAIL_IF(count != 1 || SCRingBufferSpace(rb) != 3);
    span[0] = 4;
    FAIL_IF(SCRingBufferEnqueueSpanCommit(rb, 2));
    FAIL_IF(SCRingBufferCount(rb) != 1 || SCRingBufferSpace(rb) != 3);
    FAIL_IF_NOT(SCRingBufferEnqueueSpanCommit(rb, 1));
    span = SCRingBufferEnqueueSpanGet(rb, &count);
    FAIL_IF_NULL(span);
    FAIL_IF(count != 2);
    span[0] = 5;
    span[1] = 6;
    FAIL_IF_NOT(SCRingBufferEnqueueSpanCommit(rb, 2));
    FAIL_IF_NOT(SCRingBufferDequeue(rb, output, 4));
    FAIL_IF(output[0] != 3 || output[1] != 4 || output[2] != 5 || output[3] != 6);
    SCRingBufferFree(rb);
    PASS;
}

static int SCRingBufferTestRepeatedWrap(void)
{
    SCRingBuffer *rb = SCRingBufferInit(8, sizeof(uint32_t));
    FAIL_IF_NULL(rb);
    for (uint32_t cycle = 0; cycle < 32; cycle++) {
        uint32_t input[7];
        uint32_t output[4];
        for (uint32_t i = 0; i < 7; i++) {
            input[i] = cycle * 7 + i;
        }
        FAIL_IF_NOT(SCRingBufferEnqueue(rb, input, 4));
        FAIL_IF_NOT(SCRingBufferDequeue(rb, output, 3));
        FAIL_IF(memcmp(output, input, 3 * sizeof(input[0])) != 0);
        FAIL_IF(SCRingBufferCount(rb) != 1 || SCRingBufferSpace(rb) != 7);
        FAIL_IF_NOT(SCRingBufferEnqueue(rb, input + 4, 3));
        FAIL_IF_NOT(SCRingBufferDequeue(rb, output, 4));
        FAIL_IF(memcmp(output, input + 3, sizeof(output)) != 0);
        FAIL_IF(SCRingBufferCount(rb) != 0 || SCRingBufferSpace(rb) != 8);
    }
    SCRingBufferFree(rb);
    PASS;
}
#endif

void SCRingBufferRegisterTests(void)
{
#ifdef UNITTESTS
    UtRegisterTest("SCRingBufferTestInitialization", SCRingBufferTestInitialization);
    UtRegisterTest("SCRingBufferTestFullCapacity", SCRingBufferTestFullCapacity);
    UtRegisterTest("SCRingBufferTestWrapFifo", SCRingBufferTestWrapFifo);
    UtRegisterTest("SCRingBufferTestRejectedTransfers", SCRingBufferTestRejectedTransfers);
    UtRegisterTest("SCRingBufferTestZeroLength", SCRingBufferTestZeroLength);
    UtRegisterTest("SCRingBufferTestWriteSpan", SCRingBufferTestWriteSpan);
    UtRegisterTest("SCRingBufferTestCallerOwnership", SCRingBufferTestCallerOwnership);
    UtRegisterTest("SCRingBufferTestSpanBoundary", SCRingBufferTestSpanBoundary);
    UtRegisterTest("SCRingBufferTestRepeatedWrap", SCRingBufferTestRepeatedWrap);
#endif
}
