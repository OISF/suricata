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
 *
 * API has be introduced to allow buffering of data by multiple writers
 * asynronously.  The current version only allows sequential reads.
 *
 * The API works by first registering a couple of buffers, which would
 * be sliced and allocated for use by the API to potential writers.
 *
 * The registration API requires 3 buffers to be registered.  The data
 * buffer(d_buffer), into which the API buffers data, the pointer buffer
 * (p_buffer), which would hold the pointer var instance corresponding to
 * its entry in the d_buffer, and the offset buffer(o_buffer), which
 * holds an offset entry for the data corresponding to the pointer buffer
 * entry.
 *
 * A writer wishing to write data would be required to obtain a slice
 * using CudaBufferGetSlice.  Once data has been written to the slice,
 * it can report back saying the slice has been written to by setting
 * a flag in the slice - SC_ATOMIC_SET(slice->done, 1).
 *
 * A reader wishing to retrieve the data written by writers, will do
 * so using the API call - CudaBufferCullCompletedSlices().  Once data
 * has been consumed, the reader would report back using
 * CudaBufferReportCulledConsumption() so that resources can be freed
 * to be reallocated to other writers.
 */

#ifdef __SC_CUDA_SUPPORT__

#include "suricata-common.h"
#include "suricata.h"

#include "util-atomic.h"
#include "util-pool.h"
#include "util-misc.h"
#include "util-error.h"
#include "util-debug.h"
#include "util-unittest.h"
#include "util-cuda-buffer.h"

/* rotation limit for the buffers.  This basically decides at what position
 * inside alloced buffer should the API rotate and start using the buffer
 * from the start - The right value's from 0.1-1.0.  Do note that the
 * rotation decision is taken when the culling process takes place.
 * Have a look at - CudaBufferCullCompletedSlices */
#define CUDA_BUFFER_BUFFER_ROTATION_LIMIT 0.75

/* The max buffer size that be registered to CudaBufferRegisterNew */
#define CUDA_BUFFER_BUFFER_LIMIT (1 * 1024 * 1024 * 1024)

/* 100,000 * 5 = 500,000 */
#define CUDA_BUFFER_ITEM_LIMIT (100000 * 5)

/* a million slices to be prealloced = 100,000 * 10 */
#define CUDA_BUFFER_SLICE_POOL_PREALLOC (100000 * 10)

/* we store all our slices here */
static Pool *slice_pool = NULL;
/* mutex for the above slice pool */
static SCMutex slice_pool_mutex;

/**
 * \brief Used by a consumer to report back(and thus have it freed),
 *        once it has consumed data returned in the CudaBufferCulledInfo
 *        instance(obtained from the call to CudaBufferCullCompletedSlices).
 */
void CudaBufferReportCulledConsumption(CudaBufferData *cb_data,
                                       CudaBufferCulledInfo *culled_info)
{
    SCMutexLock(&cb_data->m);

    if (culled_info->d_buffer_reset) {
        cb_data->d_buffer_read = 0;
    } else {
        if (culled_info->no_of_items != 0) {
            cb_data->d_buffer_read = culled_info->d_buffer_start_offset +
                culled_info->d_buffer_len;
        }
    }

    if (culled_info->op_buffer_reset) {
        cb_data->op_buffer_read = 0;
    } else {
        if (culled_info->no_of_items != 0) {
            cb_data->op_buffer_read += culled_info->no_of_items;
        }
    }

    SCMutexUnlock(&cb_data->m);
}

/**
 * \brief Remove slices that are done.  "Done" as in worker threads are done
 *        writing data to it.
 *
 * \param cb_data Pointer to the CudaBufferData instance.
 */
void CudaBufferCullCompletedSlices(CudaBufferData *cb_data,
                                   CudaBufferCulledInfo *culled_info,
                                   uint32_t size_limit)
{
    culled_info->no_of_items = 0;
    culled_info->d_buffer_reset = 0;
    culled_info->op_buffer_reset = 0;

    SCMutexLock(&cb_data->m);

    int buffer_reset = 0;
    uint32_t d_buffer_write_temp = 0;
    uint32_t op_buffer_write_temp = 0;

    if ((cb_data->d_buffer_write >=
         (cb_data->d_buffer_len * CUDA_BUFFER_BUFFER_ROTATION_LIMIT)) &&
        (cb_data->d_buffer_read != 0))
    {
        SCLogDebug("d_buffer reset");
        d_buffer_write_temp = cb_data->d_buffer_write;
        cb_data->d_buffer_write = 0;
        buffer_reset = 1;
        culled_info->d_buffer_reset = 1;
    }

    /* reset op_buffer */
    if ((cb_data->op_buffer_write >=
         (cb_data->op_buffer_len * CUDA_BUFFER_BUFFER_ROTATION_LIMIT)) &&
        (cb_data->op_buffer_read != 0))
    {
        SCLogDebug("op_buffer reset");
        op_buffer_write_temp = cb_data->op_buffer_write;
        cb_data->op_buffer_write = 0;
        buffer_reset = 1;
        culled_info->op_buffer_reset = 1;
    }

    CudaBufferSlice *slice_temp = cb_data->slice_head;
    CudaBufferSlice *max_culled_slice = NULL;
    uint32_t curr_size = 0;

    while (slice_temp != NULL) {
        if (!SC_ATOMIC_GET(slice_temp->done)) {
            SCLogDebug("CudaBuffer waiting on an item to finish");
            if (buffer_reset) {
                while (!SC_ATOMIC_GET(slice_temp->done))
                    usleep(1);
            } else {
                break;
            }
        }

        if (curr_size + (slice_temp->end_offset - slice_temp->start_offset + 1) > size_limit) {
            if (buffer_reset) {
                cb_data->op_buffer_write = op_buffer_write_temp;
                cb_data->d_buffer_write = d_buffer_write_temp;
                culled_info->d_buffer_reset = 0;
                culled_info->op_buffer_reset = 0;
            }
            break;
        }

        max_culled_slice = slice_temp;
        curr_size += (slice_temp->end_offset - slice_temp->start_offset + 1);

        slice_temp = slice_temp->next;
    }

    CudaBufferSlice *slice_head = cb_data->slice_head;

    if (max_culled_slice != NULL) {
        cb_data->slice_head = max_culled_slice->next;
        if (max_culled_slice->next == NULL) {
            cb_data->slice_tail = NULL;
        }
        max_culled_slice->next = NULL;
    } else {
        SCMutexUnlock(&cb_data->m);
        return;
    }

    culled_info->d_buffer_start_offset = slice_head->start_offset;
    culled_info->d_buffer_len = (max_culled_slice->end_offset -
                                 slice_head->start_offset + 1);
    culled_info->op_buffer_start_offset = cb_data->op_buffer_read;
    SCMutexUnlock(&cb_data->m);

    /* push out the used slices to the the slice_pool */
    SCMutexLock(&slice_pool_mutex);
    slice_temp = slice_head;
    while (slice_temp != max_culled_slice) {
        CudaBufferSlice *tmp = slice_temp->next;

        PoolReturn(slice_pool, slice_temp);
        culled_info->no_of_items++;

        slice_temp = tmp;
    }
    PoolReturn(slice_pool, slice_temp);
    culled_info->no_of_items++;
    SCMutexUnlock(&slice_pool_mutex);

    return;
}

/**
 * \internal
 * \brief Adds a slice to the CudaBufferData slice list.
 *
 *        We expect the CudaBufferData instance to be locked.
 *
 * \param cb_data Pointer to the CudaBufferdata instance.
 * \param slice Pointer to the slice to be pushed.
 */
static inline void CudaBufferAppendSlice(CudaBufferData *cb_data, CudaBufferSlice *slice)
{
    slice->next = NULL;

    if (cb_data->slice_head == NULL) {
        cb_data->slice_head = slice;
        cb_data->slice_tail = slice;
    } else {
        cb_data->slice_tail->next = slice;
        cb_data->slice_tail = slice;
    }

    return;
}

/**
 * \brief Gets a new buffer slice for a consumer to write to.
 *
 *        All slices returned are aligned to the next 8 byte boundary.
 *
 * \param cb_data Pointer to the CudaBufferdata instance.
 * \param len     Length of the slice required.
 * \param p       Pointer to the var corresponding to the data to store.
 *
 * \retval slice Pointer to the slice if successful; NULL if unsuccessful.
 */
CudaBufferSlice *CudaBufferGetSlice(CudaBufferData *cb_data, uint32_t len, void *p)
{
#define ALIGN_UP(offset, alignment) (offset) = ((offset) + (alignment) - 1) & ~((alignment) - 1)

    SCMutexLock(&slice_pool_mutex);
    CudaBufferSlice *slice = PoolGet(slice_pool);
    SCMutexUnlock(&slice_pool_mutex);
    if (slice == NULL) {
        return NULL;
    }

    SCMutexLock(&cb_data->m);

    if (cb_data->d_buffer_write < cb_data->d_buffer_read) {
        if (cb_data->d_buffer_write + len >= cb_data->d_buffer_read) {
            SCLogDebug("d_buffer full");
            SCMutexUnlock(&cb_data->m);

            SCMutexLock(&slice_pool_mutex);
            PoolReturn(slice_pool, slice);
            SCMutexUnlock(&slice_pool_mutex);
            return NULL;
        }
    } else {
        if (cb_data->d_buffer_write + len > cb_data->d_buffer_len) {
            SCLogDebug("d_buffer limit hit - buffer_len - %"PRIu32,
                      cb_data->d_buffer_len);
            SCMutexUnlock(&cb_data->m);

            SCMutexLock(&slice_pool_mutex);
            PoolReturn(slice_pool, slice);
            SCMutexUnlock(&slice_pool_mutex);
            return NULL;
        }
    }

    if (cb_data->op_buffer_write < cb_data->op_buffer_read) {
        if (cb_data->op_buffer_write + 1 >= cb_data->op_buffer_read) {
            SCLogDebug("op_buffer full");
            SCMutexUnlock(&cb_data->m);

            SCMutexLock(&slice_pool_mutex);
            PoolReturn(slice_pool, slice);
            SCMutexUnlock(&slice_pool_mutex);
            return NULL;
        }
    } else {
        if (cb_data->op_buffer_write + 1 > cb_data->op_buffer_len) {
            SCLogDebug("op_buffer limit hit - buffer_len - %"PRIu32,
                      cb_data->op_buffer_len);
            SCMutexUnlock(&cb_data->m);

            SCMutexLock(&slice_pool_mutex);
            PoolReturn(slice_pool, slice);
            SCMutexUnlock(&slice_pool_mutex);
            return NULL;
        }
    }

    slice->start_offset = cb_data->d_buffer_write;
    cb_data->d_buffer_write = slice->start_offset + len;
    ALIGN_UP(cb_data->d_buffer_write, 8);
    slice->end_offset = cb_data->d_buffer_write - 1;
    slice->buffer = cb_data->d_buffer;
    SC_ATOMIC_SET(slice->done, 0);

    CudaBufferAppendSlice(cb_data, slice);
    cb_data->no_of_items++;

    cb_data->o_buffer[cb_data->op_buffer_write] = slice->start_offset;
    cb_data->p_buffer[cb_data->op_buffer_write] = p;
    cb_data->op_buffer_write++;

    SCMutexUnlock(&cb_data->m);

    return slice;
}

void CudaBufferDeRegister(CudaBufferData *cb_data)
{
    CudaBufferSlice *slice_temp = cb_data->slice_head;
    SCMutexLock(&slice_pool_mutex);
    while (slice_temp != NULL) {
        CudaBufferSlice *slice_temp_next = slice_temp->next;
        PoolReturn(slice_pool, slice_temp);
        slice_temp = slice_temp_next;
    }
    SCMutexUnlock(&slice_pool_mutex);

    SCMutexDestroy(&cb_data->m);
    SCFree(cb_data);

    return;
}

/**
 * \brief Registers a new buffer to be handled by the CudaBuffer API.
 *
 *        More on what this API does can be understood from the API
 *        docs at the start of this file.
 *
 * \param d_buffer     The data buffer to work with.
 * \param d_buffer_len Length of d_buffer.
 * \param o_buffer     The offset buffer.
 * \param p_buffer     The pointer buffer.
 * \param op_buffer_no_of_items Length of o_buffer and p_buffer.  Please
 *                              note that both o_buffer and p_buffer
 *                              should be of the same length.
 * \param len Length of the buffer to be assigned.
 */
CudaBufferData *CudaBufferRegisterNew(uint8_t *d_buffer, uint32_t d_buffer_len,
                                      uint32_t *o_buffer, void **p_buffer,
                                      uint32_t op_buffer_no_of_items)
{
    if (d_buffer_len > CUDA_BUFFER_BUFFER_LIMIT) {
        SCLogError(SC_ERR_CUDA_BUFFER_ERROR, "Buffer max limit exceeded.  We "
                   "accept a max limit of %u bytes", CUDA_BUFFER_BUFFER_LIMIT);
        return NULL;
    }

    if ((d_buffer_len % 8) != 0) {
        SCLogError(SC_ERR_CUDA_BUFFER_ERROR, "Please specify a buffer length which "
                   "is a multiple of 8");
        return NULL;
    }

    CudaBufferData *new = SCMalloc(sizeof(CudaBufferData));
    if (unlikely(new == NULL)) {
        return NULL;
    }
    memset(new, 0, sizeof(CudaBufferData));

    /* payload/data buffer and set its size */
    new->d_buffer = d_buffer;
    new->d_buffer_len = d_buffer_len;

    /* offset buffer and set its size */
    new->o_buffer = o_buffer;
    new->p_buffer = p_buffer;
    /* common to the above 2 malloc'ed buffers */
    new->op_buffer_len = op_buffer_no_of_items;

    /* used to lock this new instance when it's used */
    SCMutexInit(&new->m, NULL);

    return new;
}

static void *CudaBufferSlicePoolAlloc(void *null)
{
    void *ptr = SCMalloc(sizeof(CudaBufferSlice));
    if (unlikely(ptr == NULL))
        return NULL;
    memset(ptr, 0, sizeof(CudaBufferSlice));

    SC_ATOMIC_INIT(((CudaBufferSlice *)ptr)->done);

    return ptr;
}

static int CudaBufferSlicePoolInit(void *data, void *init_data)
{
    SC_ATOMIC_INIT(((CudaBufferSlice *)data)->done);

    return 1;
}

/* disabled to reflect the changes made in PoolInit */
#if 0
static void CudaBufferSlicePoolFree(void *data)
{
    SC_ATOMIC_DESTROY(((CudaBufferSlice *)data)->done);
    SCFree(data);

    return;
}
#endif

static void CudaBufferSlicePoolCleanup(void *data)
{
    SC_ATOMIC_DESTROY(((CudaBufferSlice *)data)->done);

    return;
}

/**
 * \brief Init the API.  To be called only once at startup time.
 */
void CudaBufferInit(void)
{
    SCMutexInit(&slice_pool_mutex, NULL);

    slice_pool = PoolInit(CUDA_BUFFER_SLICE_POOL_PREALLOC,
                          CUDA_BUFFER_SLICE_POOL_PREALLOC,
                          sizeof(CudaBufferSlice),
                          CudaBufferSlicePoolAlloc,
                          CudaBufferSlicePoolInit,
                          NULL,
                          CudaBufferSlicePoolCleanup,
                          NULL);
    if (slice_pool == NULL) {
        SCLogError(SC_ERR_POOL_INIT, "CudaBuffer slice_pool is not initialized");
        exit(EXIT_FAILURE);
    }

    return;
}

/****************************Unittests***************************/

#ifdef UNITTESTS

int CudaBufferTest01(void)
{
    CudaBufferSlice *slice1, *slice2, *slice3, *slice4, *slice_temp;
    int result = 0;

    uint8_t *d_buffer = SCMalloc(sizeof(uint8_t) * 64);
    uint32_t *o_buffer = SCMalloc(sizeof(uint32_t) * 64);
    void **p_buffer = SCMalloc(sizeof(void *) * 64);
    if (d_buffer == NULL || o_buffer == NULL || p_buffer == NULL) {
        printf("failure 0\n");
        SCFree(d_buffer);
        SCFree(o_buffer);
        SCFree(p_buffer);
        return 0;
    }

    CudaBufferData *data = CudaBufferRegisterNew(d_buffer, 64,
                                         o_buffer, p_buffer, 64);
    if (data == NULL) {
        goto end;
    }

    /* new slice */
    slice1 = CudaBufferGetSlice(data, 8, NULL);
    if (slice1->start_offset != 0 || slice1->end_offset != 7 ||
        SC_ATOMIC_GET(slice1->done) != 0) {
        printf("failure 1\n");
        goto end;
    }
    if (data->d_buffer_write != 8 || data->d_buffer_read != 0 ||
        data->op_buffer_write != 1 || data->op_buffer_read != 0 ||
        data->no_of_items != 1) {
        printf("failure 2\n");
        goto end;
    }
    slice_temp = data->slice_head;
    if (slice_temp->start_offset != 0 || slice_temp->end_offset != 7 ||
        SC_ATOMIC_GET(slice_temp->done) != 0) {
        printf("failure 3\n");
        goto end;
    }
    if (slice_temp->next != NULL) {
        printf("failure 4\n");
        goto end;
    }

    /* new slice */
    slice2 = CudaBufferGetSlice(data, 16, NULL);
    if (slice2->start_offset != 8 || slice2->end_offset != 23 ||
        SC_ATOMIC_GET(slice2->done) != 0) {
        printf("failure 5\n");
        goto end;
    }
    if (data->d_buffer_write != 24 || data->d_buffer_read != 0 ||
        data->op_buffer_write != 2 || data->op_buffer_read != 0 ||
        data->no_of_items != 2) {
        printf("failure 6\n");
        goto end;
    }
    slice_temp = data->slice_head;
    if (slice_temp->start_offset != 0 || slice_temp->end_offset != 7 ||
        SC_ATOMIC_GET(slice_temp->done) != 0) {
        printf("failure 7\n");
        goto end;
    }
    slice_temp = slice_temp->next;
    if (slice_temp->start_offset != 8 || slice_temp->end_offset != 23 ||
        SC_ATOMIC_GET(slice_temp->done) != 0) {
        printf("failure 8\n");
        goto end;
    }
    if (slice_temp->next != NULL) {
        printf("failure 9\n");
        goto end;
    }

    /* new slice */
    slice3 = CudaBufferGetSlice(data, 36, NULL);
    if (slice3->start_offset != 24 || slice3->end_offset != 63 ||
        SC_ATOMIC_GET(slice3->done) != 0) {
        printf("failure 10\n");
        goto end;
    }
    if (data->d_buffer_write != 64 || data->d_buffer_read != 0 ||
        data->op_buffer_write != 3 || data->op_buffer_read != 0 ||
        data->no_of_items != 3) {
        printf("failure 11\n");
        goto end;
    }
    slice_temp = data->slice_head;
    if (slice_temp->start_offset != 0 || slice_temp->end_offset != 7 ||
        SC_ATOMIC_GET(slice_temp->done) != 0) {
        printf("failure 12\n");
        goto end;
    }
    slice_temp = slice_temp->next;
    if (slice_temp->start_offset != 8 || slice_temp->end_offset != 23 ||
        SC_ATOMIC_GET(slice_temp->done) != 0) {
        printf("failure 13\n");
        goto end;
    }
    slice_temp = slice_temp->next;
    if (slice_temp->start_offset != 24 || slice_temp->end_offset != 63 ||
        SC_ATOMIC_GET(slice_temp->done) != 0) {
        printf("failure 14\n");
        goto end;
    }
    if (slice_temp->next != NULL) {
        printf("failure 15\n");
        goto end;
    }

    slice4 = CudaBufferGetSlice(data, 10, NULL);
    if (slice4 != NULL) {
        printf("failure 16\n");
        goto end;
    }

    result = 1;
 end:
    slice_temp = data->slice_head;
    while (slice_temp != NULL) {
        SC_ATOMIC_SET(slice_temp->done, 1);
        slice_temp = slice_temp->next;
    }
    CudaBufferCulledInfo culled_info;
    memset(&culled_info, 0, sizeof(CudaBufferCulledInfo));
    CudaBufferCullCompletedSlices(data, &culled_info, UTIL_MPM_CUDA_GPU_TRANSFER_SIZE);
    if (data->slice_head != NULL || data->slice_tail != NULL) {
        printf("failure 17\n");
        result = 0;
    }

    CudaBufferDeRegister(data);
    SCFree(d_buffer);
    SCFree(o_buffer);
    SCFree(p_buffer);

    return result;
}

int CudaBufferTest02(void)
{
    CudaBufferSlice *slice1, *slice2, *slice3, *slice_temp;
    int result = 0;

    uint8_t *d_buffer = SCMalloc(sizeof(uint8_t) * 64);
    uint32_t *o_buffer = SCMalloc(sizeof(uint32_t) * 64);
    void **p_buffer = SCMalloc(sizeof(void *) * 64);
    if (d_buffer == NULL || o_buffer == NULL || p_buffer == NULL) {
        printf("failure 0\n");
        SCFree(d_buffer);
        SCFree(o_buffer);
        SCFree(p_buffer);
        return 0;
    }

    CudaBufferData *data = CudaBufferRegisterNew(d_buffer, 64,
                                         o_buffer, p_buffer, 64);
    if (data == NULL) {
        goto end;
    }

    slice1 = CudaBufferGetSlice(data, 8, NULL);
    slice2 = CudaBufferGetSlice(data, 16, NULL);
    if (data->d_buffer_write != 24 || data->d_buffer_read != 0 ||
        data->op_buffer_write != 2 || data->op_buffer_read != 0 ||
        data->no_of_items != 2) {
        printf("failure 1\n");
        goto end;
    }
    slice_temp = data->slice_head;
    if (slice_temp->start_offset != 0 || slice_temp->end_offset != 7 ||
        SC_ATOMIC_GET(slice_temp->done) != 0) {
        printf("failure 2\n");
        goto end;
    }
    slice_temp = slice_temp->next;
    if (slice_temp->start_offset != 8 || slice_temp->end_offset != 23 ||
        SC_ATOMIC_GET(slice_temp->done) != 0) {
        printf("failure 3\n");
        goto end;
    }
    if (slice_temp->next != NULL) {
        printf("failure 4\n");
        goto end;
    }

    /* culling */
    CudaBufferCulledInfo culled_info;
    memset(&culled_info, 0, sizeof(CudaBufferCulledInfo));

    CudaBufferCullCompletedSlices(data, &culled_info, UTIL_MPM_CUDA_GPU_TRANSFER_SIZE);
    if (culled_info.no_of_items != 0) {
        printf("failure 5\n");
        goto end;
    }
    slice_temp = data->slice_head;
    if (slice_temp->start_offset != 0 || slice_temp->end_offset != 7 ||
        SC_ATOMIC_GET(slice_temp->done) != 0) {
        printf("failure 6\n");
        goto end;
    }
    slice_temp = slice_temp->next;
    if (slice_temp->start_offset != 8 || slice_temp->end_offset != 23 ||
        SC_ATOMIC_GET(slice_temp->done) != 0) {
        printf("failure 7\n");
        goto end;
    }
    if (slice_temp->next != NULL) {
        printf("failure 8\n");
        goto end;
    }

    SC_ATOMIC_SET(slice2->done, 1);

    CudaBufferCullCompletedSlices(data, &culled_info, UTIL_MPM_CUDA_GPU_TRANSFER_SIZE);
    if (culled_info.no_of_items != 0) {
        printf("failure 9\n");
        goto end;
    }
    slice_temp = data->slice_head;
    if (slice_temp->start_offset != 0 || slice_temp->end_offset != 7 ||
        SC_ATOMIC_GET(slice_temp->done) != 0) {
        printf("failure 10\n");
        goto end;
    }
    slice_temp = slice_temp->next;
    if (slice_temp->start_offset != 8 || slice_temp->end_offset != 23 ||
        SC_ATOMIC_GET(slice_temp->done) != 1) {
        printf("failure 11\n");
        goto end;
    }
    if (slice_temp->next != NULL) {
        printf("failure 12\n");
        goto end;
    }

    SC_ATOMIC_SET(slice1->done, 1);

    CudaBufferCullCompletedSlices(data, &culled_info, UTIL_MPM_CUDA_GPU_TRANSFER_SIZE);
    if (culled_info.no_of_items != 2) {
        printf("failure 13\n");
        goto end;
    }
    if (data->slice_head != NULL || data->slice_tail != NULL) {
        printf("failure 14\n");
        goto end;
    }
    if (culled_info.d_buffer_start_offset != 0 ||
        culled_info.d_buffer_len != 24 ||
        culled_info.op_buffer_start_offset != 0 ||
        culled_info.d_buffer_reset != 0 || culled_info.op_buffer_reset != 0) {
        printf("failure 15\n");
        goto end;
    }
    if (data->d_buffer_write != 24 || data->d_buffer_read != 0 ||
        data->op_buffer_write != 2 || data->op_buffer_read != 0 ||
        data->no_of_items != 2) {
        printf("failure 16\n");
        goto end;
    }
    CudaBufferReportCulledConsumption(data, &culled_info);
    if (data->d_buffer_write != 24 || data->d_buffer_read != 24 ||
        data->op_buffer_write != 2 || data->op_buffer_read != 2 ||
        data->no_of_items != 2) {
        printf("failure 17\n");
        goto end;
    }

    /* new slice */
    slice3 = CudaBufferGetSlice(data, 8, NULL);
    if (slice3->start_offset != 24 || slice3->end_offset != 31 ||
        SC_ATOMIC_GET(slice3->done) != 0) {
        printf("failure 18\n");
        goto end;
    }
    if (data->d_buffer_write != 32 || data->d_buffer_read != 24 ||
        data->op_buffer_write != 3 || data->op_buffer_read != 2 ||
        data->no_of_items != 3) {
        printf("failure 19\n");
        goto end;
    }
    slice_temp = data->slice_head;
    if (slice_temp->start_offset != 24 || slice_temp->end_offset != 31 ||
        SC_ATOMIC_GET(slice_temp->done) != 0) {
        printf("failure 20\n");
        goto end;
    }
    slice_temp = slice_temp->next;
    if (slice_temp != NULL) {
        printf("failure 21\n");
        goto end;
    }

    CudaBufferCullCompletedSlices(data, &culled_info, UTIL_MPM_CUDA_GPU_TRANSFER_SIZE);
    if (culled_info.no_of_items != 0) {
        printf("failure 22\n");
        goto end;
    }
    if (data->d_buffer_write != 32 || data->d_buffer_read != 24 ||
        data->op_buffer_write != 3 || data->op_buffer_read != 2 ||
        data->no_of_items != 3) {
        printf("failure 23\n");
        goto end;
    }
    slice_temp = data->slice_head;
    if (slice_temp->start_offset != 24 || slice_temp->end_offset != 31 ||
        SC_ATOMIC_GET(slice_temp->done) != 0) {
        printf("failure 24\n");
        goto end;
    }
    slice_temp = slice_temp->next;
    if (slice_temp != NULL) {
        printf("failure 25\n");
        goto end;
    }

    /* set done flag */
    SC_ATOMIC_SET(slice3->done, 1);
    if (slice3->start_offset != 24 || slice3->end_offset != 31 ||
        SC_ATOMIC_GET(slice3->done) != 1) {
        printf("failure 26\n");
        goto end;
    }
    if (data->d_buffer_write != 32 || data->d_buffer_read != 24 ||
        data->op_buffer_write != 3 || data->op_buffer_read != 2 ||
        data->no_of_items != 3) {
        printf("failure 27\n");
        goto end;
    }
    slice_temp = data->slice_head;
    if (slice_temp->start_offset != 24 || slice_temp->end_offset != 31 ||
        SC_ATOMIC_GET(slice_temp->done) != 1) {
        printf("failure 28\n");
        goto end;
    }
    slice_temp = slice_temp->next;
    if (slice_temp != NULL) {
        printf("failure 29\n");
        goto end;
    }

    /* culling */
    CudaBufferCullCompletedSlices(data, &culled_info, UTIL_MPM_CUDA_GPU_TRANSFER_SIZE);
    if (culled_info.no_of_items != 1) {
        printf("failure 30\n");
        goto end;
    }
    if (data->slice_head != NULL || data->slice_tail != NULL) {
        printf("failure 31\n");
        goto end;
    }
    if (culled_info.d_buffer_start_offset != 24 ||
        culled_info.d_buffer_len != 8 ||
        culled_info.op_buffer_start_offset != 2 ||
        culled_info.d_buffer_reset != 0 || culled_info.op_buffer_reset != 0) {
        printf("failure 32\n");
        goto end;
    }
    if (data->d_buffer_write != 32 || data->d_buffer_read != 24 ||
        data->op_buffer_write != 3 || data->op_buffer_read != 2 ||
        data->no_of_items != 3) {
        printf("failure 33\n");
        goto end;
    }
    CudaBufferReportCulledConsumption(data, &culled_info);
    if (data->d_buffer_write != 32 || data->d_buffer_read != 32 ||
        data->op_buffer_write != 3 || data->op_buffer_read != 3 ||
        data->no_of_items != 3) {
        printf("failure 34\n");
        goto end;
    }

    result = 1;
 end:
    slice_temp = data->slice_head;
    while (slice_temp != NULL) {
        SC_ATOMIC_SET(slice_temp->done, 1);
        slice_temp = slice_temp->next;
    }
    CudaBufferCullCompletedSlices(data, &culled_info, UTIL_MPM_CUDA_GPU_TRANSFER_SIZE);
    if (data->slice_head != NULL || data->slice_tail != NULL) {
        printf("failure 35\n");
        result = 0;
    }

    CudaBufferDeRegister(data);
    SCFree(d_buffer);
    SCFree(o_buffer);
    SCFree(p_buffer);

    return result;
}

int CudaBufferTest03(void)
{
    CudaBufferSlice *slice, *slice_temp;
    int result = 0;

    uint8_t *d_buffer = SCMalloc(sizeof(uint8_t) * 64);
    uint32_t *o_buffer = SCMalloc(sizeof(uint32_t) * 64);
    void **p_buffer = SCMalloc(sizeof(void *) * 64);
    if (d_buffer == NULL || o_buffer == NULL || p_buffer == NULL) {
        printf("failure 0\n");
        SCFree(d_buffer);
        SCFree(o_buffer);
        SCFree(p_buffer);
        return 0;
    }

    CudaBufferData *data = CudaBufferRegisterNew(d_buffer, 64,
                                         o_buffer, p_buffer, 64);
    if (data == NULL) {
        goto end;
    }

    slice = CudaBufferGetSlice(data, 16, NULL);
    BUG_ON(slice == NULL);
    slice = CudaBufferGetSlice(data, 16, NULL);
    BUG_ON(slice == NULL);
    slice = CudaBufferGetSlice(data, 24, NULL);
    BUG_ON(slice == NULL);

    /* culling */
    CudaBufferCulledInfo culled_info;
    memset(&culled_info, 0, sizeof(CudaBufferCulledInfo));

    CudaBufferCullCompletedSlices(data, &culled_info, UTIL_MPM_CUDA_GPU_TRANSFER_SIZE);
    if (culled_info.no_of_items != 0) {
        printf("failure 1\n");
        goto end;
    }
    if (data->d_buffer_write != 56 || data->d_buffer_read != 0 ||
        data->op_buffer_write != 3 || data->op_buffer_read != 0 ||
        data->no_of_items != 3) {
        printf("failure 2\n");
        goto end;
    }
    slice_temp = data->slice_head;
    if (slice_temp->start_offset != 0 || slice_temp->end_offset != 15 ||
        SC_ATOMIC_GET(slice_temp->done) != 0) {
        printf("failure 3\n");
        goto end;
    }
    slice_temp = slice_temp->next;
    if (slice_temp->start_offset != 16 || slice_temp->end_offset != 31 ||
        SC_ATOMIC_GET(slice_temp->done) != 0) {
        printf("failure 4\n");
        goto end;
    }
    slice_temp = slice_temp->next;
    if (slice_temp->start_offset != 32 || slice_temp->end_offset != 55 ||
        SC_ATOMIC_GET(slice_temp->done) != 0) {
        printf("failure 5\n");
        goto end;
    }
    slice_temp = slice_temp->next;
    if (slice_temp != NULL) {
        printf("failure 6\n");
        goto end;
    }

    result = 1;
 end:
    slice_temp = data->slice_head;
    while (slice_temp != NULL) {
        SC_ATOMIC_SET(slice_temp->done, 1);
        slice_temp = slice_temp->next;
    }
    CudaBufferCullCompletedSlices(data, &culled_info, UTIL_MPM_CUDA_GPU_TRANSFER_SIZE);
    if (data->slice_head != NULL || data->slice_tail != NULL) {
        printf("failure 7\n");
        result = 0;
    }

    CudaBufferDeRegister(data);
    SCFree(d_buffer);
    SCFree(o_buffer);
    SCFree(p_buffer);

    return result;
}

int CudaBufferTest04(void)
{
    CudaBufferSlice *slice1, *slice2, *slice3, *slice_temp;
    int result = 0;

    uint8_t *d_buffer = SCMalloc(sizeof(uint8_t) * 64);
    uint32_t *o_buffer = SCMalloc(sizeof(uint32_t) * 64);
    void **p_buffer = SCMalloc(sizeof(void *) * 64);
    if (d_buffer == NULL || o_buffer == NULL || p_buffer == NULL) {
        printf("failure 0\n");
        SCFree(d_buffer);
        SCFree(o_buffer);
        SCFree(p_buffer);
        return 0;
    }

    CudaBufferData *data = CudaBufferRegisterNew(d_buffer, 64,
                                         o_buffer, p_buffer, 64);
    if (data == NULL) {
        goto end;
    }

    slice1 = CudaBufferGetSlice(data, 16, NULL);
    slice2 = CudaBufferGetSlice(data, 16, NULL);
    slice3 = CudaBufferGetSlice(data, 24, NULL);

    SC_ATOMIC_SET(slice1->done, 1);

    /* culling */
    CudaBufferCulledInfo culled_info;
    memset(&culled_info, 0, sizeof(CudaBufferCulledInfo));

    if (data->d_buffer_write != 56 || data->d_buffer_read != 0 ||
        data->op_buffer_write != 3 || data->op_buffer_read != 0 ||
        data->no_of_items != 3) {
        printf("failure 1\n");
        goto end;
    }
    CudaBufferCullCompletedSlices(data, &culled_info, UTIL_MPM_CUDA_GPU_TRANSFER_SIZE);
    if (culled_info.no_of_items != 1) {
        printf("failure 2\n");
        goto end;
    }
    if (data->d_buffer_write != 56 || data->d_buffer_read != 0 ||
        data->op_buffer_write != 3 || data->op_buffer_read != 0 ||
        data->no_of_items != 3) {
        printf("failure 3\n");
        goto end;
    }
    CudaBufferReportCulledConsumption(data, &culled_info);
    if (data->d_buffer_write != 56 || data->d_buffer_read != 16 ||
        data->op_buffer_write != 3 || data->op_buffer_read != 1 ||
        data->no_of_items != 3) {
        printf("failure 4\n");
        goto end;
    }

    SC_ATOMIC_SET(slice2->done, 1);
    SC_ATOMIC_SET(slice3->done, 1);
    CudaBufferCullCompletedSlices(data, &culled_info, UTIL_MPM_CUDA_GPU_TRANSFER_SIZE);
    if (culled_info.no_of_items != 2) {
        printf("failure 5\n");
        goto end;
    }
    if (data->d_buffer_write != 0 || data->d_buffer_read != 16 ||
        data->op_buffer_write != 3 || data->op_buffer_read != 1 ||
        data->no_of_items != 3) {
        printf("failure 6\n");
        goto end;
    }
    CudaBufferReportCulledConsumption(data, &culled_info);
    if (data->d_buffer_write != 0 || data->d_buffer_read != 0 ||
        data->op_buffer_write != 3 || data->op_buffer_read != 3 ||
        data->no_of_items != 3) {
        printf("failure 7\n");
        goto end;
    }

    slice_temp = data->slice_head;
    while (slice_temp != NULL) {
        SC_ATOMIC_SET(slice_temp->done, 1);
        slice_temp = slice_temp->next;
    }
    CudaBufferCullCompletedSlices(data, &culled_info, UTIL_MPM_CUDA_GPU_TRANSFER_SIZE);
    if (data->slice_head != NULL || data->slice_tail != NULL) {
        printf("failure 8\n");
        goto end;
    }

    result = 1;
 end:
    slice_temp = data->slice_head;
    while (slice_temp != NULL) {
        SC_ATOMIC_SET(slice_temp->done, 1);
        slice_temp = slice_temp->next;
    }
    CudaBufferCullCompletedSlices(data, &culled_info, UTIL_MPM_CUDA_GPU_TRANSFER_SIZE);
    if (data->slice_head != NULL || data->slice_tail != NULL) {
        printf("failure 9\n");
        result = 0;
    }

    CudaBufferDeRegister(data);
    SCFree(d_buffer);
    SCFree(o_buffer);
    SCFree(p_buffer);

    return result;
}

int CudaBufferTest05(void)
{
    CudaBufferSlice *slice1, *slice2, *slice3, *slice_temp;
    int result = 0;

    uint8_t *d_buffer = SCMalloc(sizeof(uint8_t) * 64);
    uint32_t *o_buffer = SCMalloc(sizeof(uint32_t) * 64);
    void **p_buffer = SCMalloc(sizeof(void *) * 64);
    if (d_buffer == NULL || o_buffer == NULL || p_buffer == NULL) {
        printf("failure 0\n");
        SCFree(d_buffer);
        SCFree(o_buffer);
        SCFree(p_buffer);
        return 0;
    }

    CudaBufferData *data = CudaBufferRegisterNew(d_buffer, 64,
                                         o_buffer, p_buffer, 64);
    if (data == NULL) {
        goto end;
    }

    slice1 = CudaBufferGetSlice(data, 16, NULL);
    slice2 = CudaBufferGetSlice(data, 16, NULL);
    slice3 = CudaBufferGetSlice(data, 24, NULL);

    SC_ATOMIC_SET(slice1->done, 1);

    /* culling */
    CudaBufferCulledInfo culled_info;
    memset(&culled_info, 0, sizeof(CudaBufferCulledInfo));

    CudaBufferCullCompletedSlices(data, &culled_info, UTIL_MPM_CUDA_GPU_TRANSFER_SIZE);
    CudaBufferReportCulledConsumption(data, &culled_info);

    SC_ATOMIC_SET(slice2->done, 1);
    SC_ATOMIC_SET(slice3->done, 1);

    CudaBufferCullCompletedSlices(data, &culled_info, UTIL_MPM_CUDA_GPU_TRANSFER_SIZE);
    CudaBufferReportCulledConsumption(data, &culled_info);
    slice1 = CudaBufferGetSlice(data, 16, NULL);
    if (slice1 == NULL) {
        printf("failure 1\n");
        goto end;
    }
    slice2 = CudaBufferGetSlice(data, 16, NULL);
    if (slice2 == NULL) {
        printf("failure 2\n");
        goto end;
    }
    slice3 = CudaBufferGetSlice(data, 24, NULL);
    if (slice2 == NULL) {
        printf("failure 3\n");
        goto end;
    }

    result = 1;
 end:
    slice_temp = data->slice_head;
    while (slice_temp != NULL) {
        SC_ATOMIC_SET(slice_temp->done, 1);
        slice_temp = slice_temp->next;
    }
    CudaBufferCullCompletedSlices(data, &culled_info, UTIL_MPM_CUDA_GPU_TRANSFER_SIZE);
    if (data->slice_head != NULL || data->slice_tail != NULL) {
        printf("failure 4\n");
        result = 0;
    }

    CudaBufferDeRegister(data);
    SCFree(d_buffer);
    SCFree(o_buffer);
    SCFree(p_buffer);

    return result;
}

int CudaBufferTest06(void)
{
    CudaBufferSlice *slice, *slice_temp;
    int result = 0;
    CudaBufferCulledInfo culled_info;
    memset(&culled_info, 0, sizeof(CudaBufferCulledInfo));

    uint8_t *d_buffer = SCMalloc(sizeof(uint8_t) * 64);
    uint32_t *o_buffer = SCMalloc(sizeof(uint32_t) * 64);
    void **p_buffer = SCMalloc(sizeof(void *) * 64);
    if (d_buffer == NULL || o_buffer == NULL || p_buffer == NULL) {
        printf("failure 0\n");
        SCFree(d_buffer);
        SCFree(o_buffer);
        SCFree(p_buffer);
        return 0;
    }

    CudaBufferData *data = CudaBufferRegisterNew(d_buffer, 64,
                                         o_buffer, p_buffer, 64);
    if (data == NULL) {
        goto end;
    }

    slice = CudaBufferGetSlice(data, 3, NULL);
    memcpy(slice->buffer + slice->start_offset,
           "one", slice->end_offset - slice->start_offset + 1);
    SC_ATOMIC_SET(slice->done, 1);

    slice = CudaBufferGetSlice(data, 3, NULL);
    memcpy(slice->buffer + slice->start_offset,
           "two", slice->end_offset - slice->start_offset + 1);
    SC_ATOMIC_SET(slice->done, 1);

    if (data->d_buffer_write != 16 || data->d_buffer_read != 0 ||
        data->op_buffer_write != 2 || data->op_buffer_read != 0 ||
        data->no_of_items != 2) {
        printf("failure 1\n");
        goto end;
    }

    slice = CudaBufferGetSlice(data, 5, NULL);
    memcpy(slice->buffer + slice->start_offset,
           "three", slice->end_offset - slice->start_offset + 1);
    SC_ATOMIC_SET(slice->done, 1);

    slice = CudaBufferGetSlice(data, 4, NULL);
    memcpy(slice->buffer + slice->start_offset,
           "four", slice->end_offset - slice->start_offset + 1);
    SC_ATOMIC_SET(slice->done, 1);

    slice = CudaBufferGetSlice(data, 4, NULL);
    memcpy(slice->buffer + slice->start_offset,
           "five", slice->end_offset - slice->start_offset + 1);
    SC_ATOMIC_SET(slice->done, 1);

    if (data->d_buffer_write != 40 || data->d_buffer_read != 0 ||
        data->op_buffer_write != 5 || data->op_buffer_read != 0 ||
        data->no_of_items != 5) {
        printf("failure 2\n");
        goto end;
    }

    slice = CudaBufferGetSlice(data, 3, NULL);
    memcpy(slice->buffer + slice->start_offset,
           "six", slice->end_offset - slice->start_offset + 1);
    SC_ATOMIC_SET(slice->done, 1);

    slice = CudaBufferGetSlice(data, 5, NULL);
    memcpy(slice->buffer + slice->start_offset,
           "seven", slice->end_offset - slice->start_offset + 1);
    SC_ATOMIC_SET(slice->done, 1);

    if (memcmp(data->d_buffer, "one", 3) != 0 ||
        memcmp(data->d_buffer + 8, "two", 3) != 0 ||
        memcmp(data->d_buffer + 16, "three", 5) != 0 ||
        memcmp(data->d_buffer + 24, "four", 4) != 0 ||
        memcmp(data->d_buffer + 32, "five", 4) != 0 ||
        memcmp(data->d_buffer + 40, "six", 3) != 0 ||
        memcmp(data->d_buffer + 48, "seven", 5) != 0) {
        printf("failure 3\n");
        goto end;
    }

    if (data->d_buffer_write != 56 || data->d_buffer_read != 0 ||
        data->op_buffer_write != 7 || data->op_buffer_read != 0 ||
        data->no_of_items != 7) {
        printf("failure 4\n");
        goto end;
    }

    /* culling */
    CudaBufferCullCompletedSlices(data, &culled_info, UTIL_MPM_CUDA_GPU_TRANSFER_SIZE);
    if (data->d_buffer_write != 56 || data->d_buffer_read != 0 ||
        data->op_buffer_write != 7 || data->op_buffer_read != 0 ||
        data->no_of_items != 7) {
        printf("failure 5\n");
        goto end;
    }
    CudaBufferReportCulledConsumption(data, &culled_info);
    if (data->d_buffer_write != 56 || data->d_buffer_read != 56 ||
        data->op_buffer_write != 7 || data->op_buffer_read != 7 ||
        data->no_of_items != 7) {
        printf("failure 6\n");
        goto end;
    }

    CudaBufferCullCompletedSlices(data, &culled_info, UTIL_MPM_CUDA_GPU_TRANSFER_SIZE);
    if (data->d_buffer_write != 0 || data->d_buffer_read != 56 ||
        data->op_buffer_write != 7 || data->op_buffer_read != 7 ||
        data->no_of_items != 7) {
        printf("failure 7\n");
        goto end;
    }
    CudaBufferReportCulledConsumption(data, &culled_info);

    if (data->d_buffer_write != 0 || data->d_buffer_read != 0 ||
        data->op_buffer_write != 7 || data->op_buffer_read != 7 ||
        data->no_of_items != 7) {
        printf("failure 8\n");
        goto end;
    }

    slice = CudaBufferGetSlice(data, 5, NULL);
    memcpy(slice->buffer + slice->start_offset,
           "eight", slice->end_offset - slice->start_offset + 1);
    SC_ATOMIC_SET(slice->done, 1);

    slice = CudaBufferGetSlice(data, 4, NULL);
    memcpy(slice->buffer + slice->start_offset,
           "nine", slice->end_offset - slice->start_offset + 1);
    SC_ATOMIC_SET(slice->done, 1);

    slice = CudaBufferGetSlice(data, 3, NULL);
    memcpy(slice->buffer + slice->start_offset,
           "ten", slice->end_offset - slice->start_offset + 1);
    SC_ATOMIC_SET(slice->done, 1);

    slice = CudaBufferGetSlice(data, 6, NULL);
    memcpy(slice->buffer + slice->start_offset,
           "eleven", slice->end_offset - slice->start_offset + 1);
    SC_ATOMIC_SET(slice->done, 1);

    slice = CudaBufferGetSlice(data, 6, NULL);
    memcpy(slice->buffer + slice->start_offset,
           "twelve", slice->end_offset - slice->start_offset + 1);
    SC_ATOMIC_SET(slice->done, 1);

    if (data->d_buffer_write != 40 || data->d_buffer_read != 0 ||
        data->op_buffer_write != 12 || data->op_buffer_read != 7 ||
        data->no_of_items != 12) {
        printf("failure 9\n");
        goto end;
    }

    if (memcmp(data->d_buffer, "eight", 5) != 0 ||
        memcmp(data->d_buffer + 8, "nine", 4) != 0 ||
        memcmp(data->d_buffer + 16, "ten", 3) != 0 ||
        memcmp(data->d_buffer + 24, "eleven", 6) != 0 ||
        memcmp(data->d_buffer + 32, "twelve", 6) != 0) {
        printf("failure 10\n");
        goto end;
    }

    CudaBufferCullCompletedSlices(data, &culled_info, UTIL_MPM_CUDA_GPU_TRANSFER_SIZE);
    if (data->d_buffer_write != 40 || data->d_buffer_read != 0 ||
        data->op_buffer_write != 12 || data->op_buffer_read != 7 ||
        data->no_of_items != 12) {
        printf("failure 11\n");
        goto end;
    }
    CudaBufferReportCulledConsumption(data, &culled_info);

    if (data->d_buffer_write != 40 || data->d_buffer_read != 40 ||
        data->op_buffer_write != 12 || data->op_buffer_read != 12 ||
        data->no_of_items != 12) {
        printf("failure 12\n");
        goto end;
    }

    result = 1;
 end:
    slice_temp = data->slice_head;
    while (slice_temp != NULL) {
        SC_ATOMIC_SET(slice_temp->done, 1);
        slice_temp = slice_temp->next;
    }
    CudaBufferCullCompletedSlices(data, &culled_info, UTIL_MPM_CUDA_GPU_TRANSFER_SIZE);
    if (data->slice_head != NULL || data->slice_tail != NULL) {
        printf("failure 13\n");
        result = 0;
    }

    CudaBufferDeRegister(data);
    SCFree(d_buffer);
    SCFree(o_buffer);
    SCFree(p_buffer);

    return result;
}

#endif /* #ifdef UNITTESTS */

void CudaBufferRegisterUnittests(void)
{
#ifdef UNITTESTS
    UtRegisterTest("CudaBufferTest01", CudaBufferTest01, 1);
    UtRegisterTest("CudaBufferTest02", CudaBufferTest02, 1);
    UtRegisterTest("CudaBufferTest03", CudaBufferTest03, 1);
    UtRegisterTest("CudaBufferTest04", CudaBufferTest04, 1);
    UtRegisterTest("CudaBufferTest05", CudaBufferTest05, 1);
    UtRegisterTest("CudaBufferTest06", CudaBufferTest06, 1);
#endif

    return;
}

#endif /* __SC_CUDA_SUPPORT__ */
