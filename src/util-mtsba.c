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
#include "suricata.h"

#include "util-atomic.h"
#include "util-pool.h"
#include "util-misc.h"
#include "util-error.h"
#include "util-debug.h"
#include "util-unittest.h"
#include "util-mtsba.h"

/* rotation limit for the buffers.  This basically decides at what position
 * inside alloced buffer should the API rotate and start using the buffer from
 * the start - The right value's from 0.1-1.0.  Do note that the rotation
 * decision is taken when the culling process takes place.  Have a look at -
 * MTSBA_CullCompletedSlices */
#define MTSBA_BUFFER_ROTATION_LIMIT 0.75

/* 1 gb */
#define MTSBA_BUFFER_LIMIT (1 * 1024 * 1024 * 1024)

/* 100,000 * 5 = 500,000 */
#define MTSBA_ITEM_LIMIT (100000 * 5)

/* a million slices to be prealloced = 100,000 * 10 */
#define MTSBA_SLICE_POOL_PREALLOC (100000 * 10)

/* we store all our slices here */
static Pool *slice_pool = NULL;
/* mutex for the above slice pool */
static SCMutex slice_pool_mutex;

void MTSBA_ReportCulledConsumption(MTSBA_Data *mtsba_data,
                                   MTSBA_CulledInfo *culled_info)
{
    SCMutexLock(&mtsba_data->m);

    if (culled_info->d_buffer_reset) {
        mtsba_data->d_buffer_read = 0;
    } else {
        if (culled_info->no_of_items != 0) {
            mtsba_data->d_buffer_read = culled_info->d_buffer_start_offset +
                culled_info->d_buffer_len;
        }
    }

    if (culled_info->op_buffer_reset) {
        mtsba_data->op_buffer_read = 0;
    } else {
        if (culled_info->no_of_items != 0) {
            mtsba_data->op_buffer_read += culled_info->no_of_items;
        }
    }

    SCMutexUnlock(&mtsba_data->m);
}

/**
 * \brief Remove slices that are done.  "Done" as in worker threads are done
 *        writing data to it.
 *
 * \param mtsba_data Pointer to the MTSBA_Data instance.
 */
void MTSBA_CullCompletedSlices(MTSBA_Data *mtsba_data,
                               MTSBA_CulledInfo *culled_info)
{
    culled_info->no_of_items = 0;
    culled_info->d_buffer_reset = 0;
    culled_info->op_buffer_reset = 0;

    SCMutexLock(&mtsba_data->m);

    int buffer_reset = 0;

    if ((mtsba_data->d_buffer_write >=
         (mtsba_data->d_buffer_len * MTSBA_BUFFER_ROTATION_LIMIT)) &&
        (mtsba_data->d_buffer_read != 0)) {
        SCLogDebug("d_buffer reset");
        mtsba_data->d_buffer_write = 0;
        buffer_reset = 1;
        culled_info->d_buffer_reset = 1;
    }

    /* reset op_buffer */
    if ((mtsba_data->op_buffer_write >=
         (mtsba_data->op_buffer_len * MTSBA_BUFFER_ROTATION_LIMIT)) &&
        (mtsba_data->op_buffer_read != 0)) {
        SCLogDebug("op_buffer reset");
        mtsba_data->op_buffer_write = 0;
        buffer_reset = 1;
        culled_info->op_buffer_reset = 1;
    }

    MTSBA_Slice *slice_temp = mtsba_data->slice_head;
    MTSBA_Slice *max_culled_slice = NULL;

    while (slice_temp != NULL) {
        if (!SC_ATOMIC_GET(slice_temp->done)) {
            SCLogDebug("mtsba waiting on an item to finish");
            if (buffer_reset) {
                while (!SC_ATOMIC_GET(slice_temp->done))
                    ;
            } else {
                break;
            }
        }

        max_culled_slice = slice_temp;

        slice_temp = slice_temp->next;
    }

    MTSBA_Slice *slice_head = mtsba_data->slice_head;

    if (max_culled_slice != NULL) {
        mtsba_data->slice_head = max_culled_slice->next;
        if (max_culled_slice->next == NULL) {
            mtsba_data->slice_tail = NULL;
        }
        max_culled_slice->next = NULL;
        SCMutexUnlock(&mtsba_data->m);
    } else {
        SCMutexUnlock(&mtsba_data->m);
        return;
    }

    /* push out the used slices to the the slice_pool */
    SCMutexLock(&slice_pool_mutex);
    slice_temp = slice_head;
    while (slice_temp != max_culled_slice) {
        MTSBA_Slice *tmp = slice_temp->next;

        PoolReturn(slice_pool, slice_temp);
        culled_info->no_of_items++;

        slice_temp = tmp;
    }
    PoolReturn(slice_pool, slice_temp);
    culled_info->no_of_items++;
    SCMutexUnlock(&slice_pool_mutex);

    SCMutexLock(&mtsba_data->m);
    culled_info->d_buffer_start_offset = slice_head->start_offset;
    culled_info->d_buffer_len = (max_culled_slice->end_offset - slice_head->start_offset + 1);
    culled_info->op_buffer_start_offset = mtsba_data->op_buffer_read;
    SCMutexUnlock(&mtsba_data->m);

    return;
}

/**
 * \internal
 * \brief Adds a slice to the MTSBA_Data slice list.
 *
 *        We expect the MTSBA_Data instance to be locked.
 *
 * \param mtsba_data Pointer to the MTSBA_data instance.
 * \param slice Pointer to the slice to be pushed.
 */
static inline void MTSBA_AppendSlice(MTSBA_Data *mtsba_data, MTSBA_Slice *slice)
{
    slice->next = NULL;

    if (mtsba_data->slice_head == NULL) {
        mtsba_data->slice_head = slice;
        mtsba_data->slice_tail = slice;
    } else {
        mtsba_data->slice_tail->next = slice;
        mtsba_data->slice_tail = slice;
    }

    return;
}

/**
 * \brief Gets a new buffer slice for a consumer to write to.
 *
 *        All slices returned are aligned to the next 8 byte boundary.
 *
 * \param mtsba_data Pointer to the MTSBA_data instance.
 * \param len        Length of the slice required.
 *
 * \retval slice Pointer to the slice if successful; NULL if unsuccessful.
 */
MTSBA_Slice *MTSBA_GetSlice(MTSBA_Data *mtsba_data, uint32_t len, void *p)
{
#define ALIGN_UP(offset, alignment) (offset) = ((offset) + (alignment) - 1) & ~((alignment) - 1)

    SCMutexLock(&slice_pool_mutex);
    MTSBA_Slice *slice = PoolGet(slice_pool);
    SCMutexUnlock(&slice_pool_mutex);
    if (slice == NULL) {
        return NULL;
    }

    SCMutexLock(&mtsba_data->m);

    if (mtsba_data->d_buffer_write < mtsba_data->d_buffer_read) {
        if (mtsba_data->d_buffer_write + len >= mtsba_data->d_buffer_read) {
            SCLogInfo("d_buffer full");
            SCMutexUnlock(&mtsba_data->m);

            SCMutexLock(&slice_pool_mutex);
            PoolReturn(slice_pool, slice);
            SCMutexUnlock(&slice_pool_mutex);
            return NULL;
        }
    } else {
        if (mtsba_data->d_buffer_write + len > mtsba_data->d_buffer_len) {
            SCLogInfo("d_buffer limit hit - buffer_len - %"PRIu32,
                      mtsba_data->d_buffer_len);
            SCMutexUnlock(&mtsba_data->m);

            SCMutexLock(&slice_pool_mutex);
            PoolReturn(slice_pool, slice);
            SCMutexUnlock(&slice_pool_mutex);
            return NULL;
        }
    }

    if (mtsba_data->op_buffer_write < mtsba_data->op_buffer_read) {
        if (mtsba_data->op_buffer_write + 1 >= mtsba_data->op_buffer_read) {
            SCLogInfo("op_buffer full");
            SCMutexUnlock(&mtsba_data->m);

            SCMutexLock(&slice_pool_mutex);
            PoolReturn(slice_pool, slice);
            SCMutexUnlock(&slice_pool_mutex);
            return NULL;
        }
    } else {
        if (mtsba_data->op_buffer_write + 1 > mtsba_data->op_buffer_len) {
            SCLogInfo("op_buffer limit hit - buffer_len - %"PRIu32,
                      mtsba_data->op_buffer_len);
            SCMutexUnlock(&mtsba_data->m);

            SCMutexLock(&slice_pool_mutex);
            PoolReturn(slice_pool, slice);
            SCMutexUnlock(&slice_pool_mutex);
            return NULL;
        }
    }

    slice->start_offset = mtsba_data->d_buffer_write;
    mtsba_data->d_buffer_write = slice->start_offset + len;
    ALIGN_UP(mtsba_data->d_buffer_write, 8);
    slice->end_offset = mtsba_data->d_buffer_write - 1;
    slice->buffer = mtsba_data->d_buffer;
    SC_ATOMIC_SET(slice->done, 0);

    MTSBA_AppendSlice(mtsba_data, slice);
    mtsba_data->no_of_items++;

    mtsba_data->o_buffer[mtsba_data->op_buffer_write] = slice->start_offset;
    mtsba_data->p_buffer[mtsba_data->op_buffer_write] = p;
    mtsba_data->op_buffer_write++;

    SCMutexUnlock(&mtsba_data->m);

    return slice;
}

void MTSBA_DeRegister(MTSBA_Data *mtsba_data)
{
    SCFree(mtsba_data->d_buffer);
    SCFree(mtsba_data->o_buffer);
    SCFree(mtsba_data->p_buffer);

    MTSBA_Slice *slice_temp = mtsba_data->slice_head;
    SCMutexLock(&slice_pool_mutex);
    while (slice_temp != NULL) {
        MTSBA_Slice *slice_temp_next = slice_temp->next;
        PoolReturn(slice_pool, slice_temp);
        slice_temp = slice_temp_next;
    }
    SCMutexUnlock(&slice_pool_mutex);

    SCMutexDestroy(&mtsba_data->m);
    SCFree(mtsba_data);

    return;
}

/**
 * \brief Registers a new buffer to be used for MTSBA.
 *
 * \param len Length of the buffer to be assigned.
 */
MTSBA_Data *MTSBA_RegisterNew(const char *buffer_len_str)
{
    uint32_t buffer_len = 0;

    if (ParseSizeStringU32(buffer_len_str, &buffer_len) < 0) {
        SCLogError(SC_ERR_SIZE_PARSE, "Error parsing MTSBA buffer size "
                   "parsing for - %s.  Killing engine", buffer_len_str);
        exit(EXIT_FAILURE);
    }

    if (buffer_len > MTSBA_BUFFER_LIMIT) {
        SCLogError(SC_ERR_MTSBA_ERROR, "Buffer max limit exceeded.  We "
                   "accept a max limit of %u bytes", MTSBA_BUFFER_LIMIT);
        return NULL;
    }

    if ((buffer_len % 8) != 0) {
        SCLogError(SC_ERR_MTSBA_ERROR, "Please specify a buffer length which "
                   "is a multiple of 8");
        return NULL;
    }

    MTSBA_Data *new = SCMalloc(sizeof(MTSBA_Data));
    if (new == NULL) {
        return NULL;
    }
    memset(new, 0, sizeof(MTSBA_Data));

    /* malloc the payload/data buffer and set it's size */
    new->d_buffer = SCMalloc(sizeof(uint8_t) * buffer_len);
    if (new->d_buffer == NULL) {
        return NULL;
    }
    memset(new->d_buffer, 0, sizeof(uint8_t) * buffer_len);
    new->d_buffer_len = buffer_len;

    /* malloc the offset buffer */
    new->o_buffer = SCMalloc(sizeof(uint32_t) * MTSBA_ITEM_LIMIT);
    if (new->o_buffer == NULL) {
        return NULL;
    }
    memset(new->o_buffer, 0, sizeof(uint32_t) * MTSBA_ITEM_LIMIT);

    /* malloc the item pointer buffer */
    new->p_buffer = SCMalloc(sizeof(void *) * MTSBA_ITEM_LIMIT);
    if (new->p_buffer == NULL) {
        return NULL;
    }
    memset(new->p_buffer, 0, sizeof(void *) * MTSBA_ITEM_LIMIT);

    /* common to the above 2 malloc'ed buffers */
    new->op_buffer_len = MTSBA_ITEM_LIMIT;

    /* used to lock this new MTSBA instance when it's used */
    SCMutexInit(&new->m, NULL);

    return new;
}

static void *MTSBA_SlicePoolAlloc(void *null)
{
    void *ptr = SCMalloc(sizeof(MTSBA_Slice));
    if (ptr == NULL)
        return NULL;
    memset(ptr, 0, sizeof(MTSBA_Slice));

    SC_ATOMIC_INIT(((MTSBA_Slice *)ptr)->done);

    return ptr;
}

static int MTSBA_SlicePoolInit(void *data, void *init_data)
{
    SC_ATOMIC_INIT(((MTSBA_Slice *)data)->done);

    return 1;
}

static void MTSBA_SlicePoolFree(void *data)
{
    SC_ATOMIC_DESTROY(((MTSBA_Slice *)data)->done);
    SCFree(data);

    return;
}

static void MTSBA_SlicePoolCleanup(void *data)
{
    SC_ATOMIC_DESTROY(((MTSBA_Slice *)data)->done);

    return;
}

/**
 * \brief Init the API.  To be called only once at startup time.
 */
void MTSBA_Init(void)
{
    SCMutexInit(&slice_pool_mutex, NULL);

    slice_pool = PoolInit(MTSBA_SLICE_POOL_PREALLOC,
                          MTSBA_SLICE_POOL_PREALLOC,
                          sizeof(MTSBA_Slice),
                          MTSBA_SlicePoolAlloc,
                          MTSBA_SlicePoolInit,
                          NULL,
                          MTSBA_SlicePoolCleanup,
                          MTSBA_SlicePoolFree);
    if (slice_pool == NULL) {
        SCLogError(SC_ERR_POOL_INIT, "MTSBA slice_pool is not initialized");
        exit(EXIT_FAILURE);
    }

    return;
}

/****************************Unittests***************************/

#ifdef UNITTESTS

int MTSBA_Test01(void)
{
    MTSBA_Slice *slice1, *slice2, *slice3, *slice4, *slice_temp;
    int result = 0;

    MTSBA_Data *data = MTSBA_RegisterNew("64");
    if (data == NULL) {
        goto end;
    }

    /* new slice */
    slice1 = MTSBA_GetSlice(data, 8, NULL);
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
    slice2 = MTSBA_GetSlice(data, 16, NULL);
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
    slice3 = MTSBA_GetSlice(data, 36, NULL);
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

    slice4 = MTSBA_GetSlice(data, 10, NULL);
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
    MTSBA_CulledInfo culled_info;
    memset(&culled_info, 0, sizeof(MTSBA_CulledInfo));
    MTSBA_CullCompletedSlices(data, &culled_info);
    if (data->slice_head != NULL || data->slice_tail != NULL) {
        printf("failure 17\n");
        result = 0;
    }

    MTSBA_DeRegister(data);
    return result;
}

int MTSBA_Test02(void)
{
    MTSBA_Slice *slice1, *slice2, *slice3, *slice_temp;
    int result = 0;

    MTSBA_Data *data = MTSBA_RegisterNew("64");
    if (data == NULL) {
        goto end;
    }

    slice1 = MTSBA_GetSlice(data, 8, NULL);
    slice2 = MTSBA_GetSlice(data, 16, NULL);
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
    MTSBA_CulledInfo culled_info;
    memset(&culled_info, 0, sizeof(MTSBA_CulledInfo));

    MTSBA_CullCompletedSlices(data, &culled_info);
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

    MTSBA_CullCompletedSlices(data, &culled_info);
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

    MTSBA_CullCompletedSlices(data, &culled_info);
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
    MTSBA_ReportCulledConsumption(data, &culled_info);
    if (data->d_buffer_write != 24 || data->d_buffer_read != 24 ||
        data->op_buffer_write != 2 || data->op_buffer_read != 2 ||
        data->no_of_items != 2) {
        printf("failure 17\n");
        goto end;
    }

    /* new slice */
    slice3 = MTSBA_GetSlice(data, 8, NULL);
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

    MTSBA_CullCompletedSlices(data, &culled_info);
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
    MTSBA_CullCompletedSlices(data, &culled_info);
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
    MTSBA_ReportCulledConsumption(data, &culled_info);
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
    MTSBA_CullCompletedSlices(data, &culled_info);
    if (data->slice_head != NULL || data->slice_tail != NULL) {
        printf("failure 35\n");
        result = 0;
    }

    MTSBA_DeRegister(data);
    return result;
}

int MTSBA_Test03(void)
{
    MTSBA_Slice *slice1, *slice2, *slice3, *slice_temp;
    int result = 0;

    MTSBA_Data *data = MTSBA_RegisterNew("64");
    if (data == NULL) {
        goto end;
    }

    slice1 = MTSBA_GetSlice(data, 16, NULL);
    slice2 = MTSBA_GetSlice(data, 16, NULL);
    slice3 = MTSBA_GetSlice(data, 24, NULL);

    /* culling */
    MTSBA_CulledInfo culled_info;
    memset(&culled_info, 0, sizeof(MTSBA_CulledInfo));

    MTSBA_CullCompletedSlices(data, &culled_info);
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
    MTSBA_CullCompletedSlices(data, &culled_info);
    if (data->slice_head != NULL || data->slice_tail != NULL) {
        printf("failure 7\n");
        result = 0;
    }

    MTSBA_DeRegister(data);
    return result;
}

int MTSBA_Test04(void)
{
    MTSBA_Slice *slice1, *slice2, *slice3, *slice_temp;
    int result = 0;

    MTSBA_Data *data = MTSBA_RegisterNew("64");
    if (data == NULL) {
        goto end;
    }

    slice1 = MTSBA_GetSlice(data, 16, NULL);
    slice2 = MTSBA_GetSlice(data, 16, NULL);
    slice3 = MTSBA_GetSlice(data, 24, NULL);

    SC_ATOMIC_SET(slice1->done, 1);

    /* culling */
    MTSBA_CulledInfo culled_info;
    memset(&culled_info, 0, sizeof(MTSBA_CulledInfo));

    if (data->d_buffer_write != 56 || data->d_buffer_read != 0 ||
        data->op_buffer_write != 3 || data->op_buffer_read != 0 ||
        data->no_of_items != 3) {
        printf("failure 1\n");
        goto end;
    }
    MTSBA_CullCompletedSlices(data, &culled_info);
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
    MTSBA_ReportCulledConsumption(data, &culled_info);
    if (data->d_buffer_write != 56 || data->d_buffer_read != 16 ||
        data->op_buffer_write != 3 || data->op_buffer_read != 1 ||
        data->no_of_items != 3) {
        printf("failure 4\n");
        goto end;
    }

    SC_ATOMIC_SET(slice2->done, 1);
    SC_ATOMIC_SET(slice3->done, 1);
    MTSBA_CullCompletedSlices(data, &culled_info);
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
    MTSBA_ReportCulledConsumption(data, &culled_info);
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
    MTSBA_CullCompletedSlices(data, &culled_info);
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
    MTSBA_CullCompletedSlices(data, &culled_info);
    if (data->slice_head != NULL || data->slice_tail != NULL) {
        printf("failure 9\n");
        result = 0;
    }

    MTSBA_DeRegister(data);
    return result;
}

int MTSBA_Test05(void)
{
    MTSBA_Slice *slice1, *slice2, *slice3, *slice_temp;
    int result = 0;

    MTSBA_Data *data = MTSBA_RegisterNew("64");
    if (data == NULL) {
        goto end;
    }

    slice1 = MTSBA_GetSlice(data, 16, NULL);
    slice2 = MTSBA_GetSlice(data, 16, NULL);
    slice3 = MTSBA_GetSlice(data, 24, NULL);

    SC_ATOMIC_SET(slice1->done, 1);

    /* culling */
    MTSBA_CulledInfo culled_info;
    memset(&culled_info, 0, sizeof(MTSBA_CulledInfo));

    MTSBA_CullCompletedSlices(data, &culled_info);
    MTSBA_ReportCulledConsumption(data, &culled_info);

    SC_ATOMIC_SET(slice2->done, 1);
    SC_ATOMIC_SET(slice3->done, 1);

    MTSBA_CullCompletedSlices(data, &culled_info);
    MTSBA_ReportCulledConsumption(data, &culled_info);
    slice1 = MTSBA_GetSlice(data, 16, NULL);
    if (slice1 == NULL) {
        printf("failure 1\n");
        goto end;
    }
    slice2 = MTSBA_GetSlice(data, 16, NULL);
    if (slice2 == NULL) {
        printf("failure 2\n");
        goto end;
    }
    slice3 = MTSBA_GetSlice(data, 24, NULL);
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
    MTSBA_CullCompletedSlices(data, &culled_info);
    if (data->slice_head != NULL || data->slice_tail != NULL) {
        printf("failure 4\n");
        result = 0;
    }

    MTSBA_DeRegister(data);
    return result;
}

int MTSBA_Test06(void)
{
    MTSBA_Slice *slice, *slice_temp;
    int result = 0;
    MTSBA_CulledInfo culled_info;
    memset(&culled_info, 0, sizeof(MTSBA_CulledInfo));

    MTSBA_Data *data = MTSBA_RegisterNew("64");
    if (data == NULL) {
        goto end;
    }

    slice = MTSBA_GetSlice(data, 3, NULL);
    memcpy(slice->buffer + slice->start_offset,
           "one", slice->end_offset - slice->start_offset + 1);
    SC_ATOMIC_SET(slice->done, 1);

    slice = MTSBA_GetSlice(data, 3, NULL);
    memcpy(slice->buffer + slice->start_offset,
           "two", slice->end_offset - slice->start_offset + 1);
    SC_ATOMIC_SET(slice->done, 1);

    if (data->d_buffer_write != 16 || data->d_buffer_read != 0 ||
        data->op_buffer_write != 2 || data->op_buffer_read != 0 ||
        data->no_of_items != 2) {
        printf("failure 1\n");
        goto end;
    }

    slice = MTSBA_GetSlice(data, 5, NULL);
    memcpy(slice->buffer + slice->start_offset,
           "three", slice->end_offset - slice->start_offset + 1);
    SC_ATOMIC_SET(slice->done, 1);

    slice = MTSBA_GetSlice(data, 4, NULL);
    memcpy(slice->buffer + slice->start_offset,
           "four", slice->end_offset - slice->start_offset + 1);
    SC_ATOMIC_SET(slice->done, 1);

    slice = MTSBA_GetSlice(data, 4, NULL);
    memcpy(slice->buffer + slice->start_offset,
           "five", slice->end_offset - slice->start_offset + 1);
    SC_ATOMIC_SET(slice->done, 1);

    if (data->d_buffer_write != 40 || data->d_buffer_read != 0 ||
        data->op_buffer_write != 5 || data->op_buffer_read != 0 ||
        data->no_of_items != 5) {
        printf("failure 2\n");
        goto end;
    }

    slice = MTSBA_GetSlice(data, 3, NULL);
    memcpy(slice->buffer + slice->start_offset,
           "six", slice->end_offset - slice->start_offset + 1);
    SC_ATOMIC_SET(slice->done, 1);

    slice = MTSBA_GetSlice(data, 5, NULL);
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
    MTSBA_CullCompletedSlices(data, &culled_info);
    if (data->d_buffer_write != 56 || data->d_buffer_read != 0 ||
        data->op_buffer_write != 7 || data->op_buffer_read != 0 ||
        data->no_of_items != 7) {
        printf("failure 5\n");
        goto end;
    }
    MTSBA_ReportCulledConsumption(data, &culled_info);
    if (data->d_buffer_write != 56 || data->d_buffer_read != 56 ||
        data->op_buffer_write != 7 || data->op_buffer_read != 7 ||
        data->no_of_items != 7) {
        printf("failure 6\n");
        goto end;
    }

    MTSBA_CullCompletedSlices(data, &culled_info);
    if (data->d_buffer_write != 0 || data->d_buffer_read != 56 ||
        data->op_buffer_write != 7 || data->op_buffer_read != 7 ||
        data->no_of_items != 7) {
        printf("failure 7\n");
        goto end;
    }
    MTSBA_ReportCulledConsumption(data, &culled_info);

    if (data->d_buffer_write != 0 || data->d_buffer_read != 0 ||
        data->op_buffer_write != 7 || data->op_buffer_read != 7 ||
        data->no_of_items != 7) {
        printf("failure 8\n");
        goto end;
    }

    slice = MTSBA_GetSlice(data, 5, NULL);
    memcpy(slice->buffer + slice->start_offset,
           "eight", slice->end_offset - slice->start_offset + 1);
    SC_ATOMIC_SET(slice->done, 1);

    slice = MTSBA_GetSlice(data, 4, NULL);
    memcpy(slice->buffer + slice->start_offset,
           "nine", slice->end_offset - slice->start_offset + 1);
    SC_ATOMIC_SET(slice->done, 1);

    slice = MTSBA_GetSlice(data, 3, NULL);
    memcpy(slice->buffer + slice->start_offset,
           "ten", slice->end_offset - slice->start_offset + 1);
    SC_ATOMIC_SET(slice->done, 1);

    slice = MTSBA_GetSlice(data, 6, NULL);
    memcpy(slice->buffer + slice->start_offset,
           "eleven", slice->end_offset - slice->start_offset + 1);
    SC_ATOMIC_SET(slice->done, 1);

    slice = MTSBA_GetSlice(data, 6, NULL);
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

    MTSBA_CullCompletedSlices(data, &culled_info);
    if (data->d_buffer_write != 40 || data->d_buffer_read != 0 ||
        data->op_buffer_write != 12 || data->op_buffer_read != 7 ||
        data->no_of_items != 12) {
        printf("failure 11\n");
        goto end;
    }
    MTSBA_ReportCulledConsumption(data, &culled_info);

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
    MTSBA_CullCompletedSlices(data, &culled_info);
    if (data->slice_head != NULL || data->slice_tail != NULL) {
        printf("failure 13\n");
        result = 0;
    }

    MTSBA_DeRegister(data);
    return result;
}

#endif /* #ifdef UNITTESTS */

void MTSBA_RegisterUnittests(void)
{
#ifdef UNITTESTS
    UtRegisterTest("MTSBA_Test01", MTSBA_Test01, 1);
    UtRegisterTest("MTSBA_Test02", MTSBA_Test02, 1);
    UtRegisterTest("MTSBA_Test03", MTSBA_Test03, 1);
    UtRegisterTest("MTSBA_Test04", MTSBA_Test04, 1);
    UtRegisterTest("MTSBA_Test05", MTSBA_Test05, 1);
    UtRegisterTest("MTSBA_Test06", MTSBA_Test06, 1);
#endif

    return;
}
