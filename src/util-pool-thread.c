/* Copyright (C) 2013 Open Information Security Foundation
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
 * \defgroup utilpool Pool
 *
 * @{
 */

/**
 * \file
 *
 * \author Victor Julien <victor@inliniac.net>
 *
 * Pool utility functions
 */

#include "suricata-common.h"
#include "util-pool.h"
#include "util-pool-thread.h"
#include "util-unittest.h"
#include "util-debug.h"

PoolThread *PoolThreadInit(int threads, uint32_t size, uint32_t prealloc_size, uint32_t elt_size,  void *(*Alloc)(), int (*Init)(void *, void *), void *InitData,  void (*Cleanup)(void *), void (*Free)(void *))
{
    PoolThread *pt = NULL;
    int i;

    if (threads <= 0) {
        SCLogDebug("error");
        goto error;
    }

    pt = SCMalloc(sizeof(*pt));
    if (unlikely(pt == NULL)) {
        SCLogDebug("memory alloc error");
        goto error;
    }

    SCLogDebug("size %d", threads);
    pt->array = SCMalloc(threads * sizeof(PoolThreadElement));
    if (pt->array == NULL) {
        SCLogDebug("memory alloc error");
        goto error;
    }
    pt->size = threads;

    for (i = 0; i < threads; i++) {
        PoolThreadElement *e = &pt->array[i];

        SCMutexInit(&e->lock, NULL);
        SCMutexLock(&e->lock);
//        SCLogDebug("size %u prealloc_size %u elt_size %u Alloc %p Init %p InitData %p Cleanup %p Free %p",
//                size, prealloc_size, elt_size,
//                Alloc, Init, InitData, Cleanup, Free);
        e->pool = PoolInit(size, prealloc_size, elt_size, Alloc, Init, InitData, Cleanup, Free);
        SCMutexUnlock(&e->lock);
        if (e->pool == NULL) {
            SCLogDebug("error");
            goto error;
        }
    }

    return pt;
error:
    if (pt != NULL)
        PoolThreadFree(pt);
    return NULL;
}

/**
 *
 */
int PoolThreadGrow(PoolThread *pt, uint32_t size, uint32_t prealloc_size, uint32_t elt_size,  void *(*Alloc)(), int (*Init)(void *, void *), void *InitData,  void (*Cleanup)(void *), void (*Free)(void *)) {
    void *ptmp;
    size_t newsize;
    PoolThreadElement *e = NULL;

    if (pt == NULL || pt->array == NULL) {
        SCLogError(SC_ERR_POOL_INIT, "pool grow failed");
        return -1;
    }

    newsize = pt->size + 1;
    SCLogDebug("newsize %"PRIuMAX, (uintmax_t)newsize);

    ptmp = SCRealloc(pt->array, (newsize * sizeof(PoolThreadElement)));
    if (ptmp == NULL) {
        SCFree(pt->array);
        pt->array = NULL;
        SCLogError(SC_ERR_POOL_INIT, "pool grow failed");
        return -1;
    }
    pt->array = ptmp;

    pt->size = newsize;

    e = &pt->array[newsize - 1];
    memset(e, 0x00, sizeof(*e));
    SCMutexInit(&e->lock, NULL);
    SCMutexLock(&e->lock);
    e->pool = PoolInit(size, prealloc_size, elt_size, Alloc, Init, InitData, Cleanup, Free);
    SCMutexUnlock(&e->lock);
    if (e->pool == NULL) {
        SCLogError(SC_ERR_POOL_INIT, "pool grow failed");
        return -1;
    }

    return (int)(newsize - 1);
}

int PoolThreadSize(PoolThread *pt)
{
    if (pt == NULL)
        return -1;
    return (int)pt->size;
}

void PoolThreadFree(PoolThread *pt)
{
    int i;

    if (pt == NULL)
        return;

    if (pt->array != NULL) {
        for (i = 0; i < (int)pt->size; i++) {
            PoolThreadElement *e = &pt->array[i];
            SCMutexLock(&e->lock);
            PoolFree(e->pool);
            SCMutexUnlock(&e->lock);
            SCMutexDestroy(&e->lock);
        }
        SCFree(pt->array);
    }
    SCFree(pt);
}

void *PoolThreadGetById(PoolThread *pt, uint16_t id)
{
    void *data = NULL;

    if (pt == NULL || id >= pt->size)
        return NULL;

    PoolThreadElement *e = &pt->array[id];
    SCMutexLock(&e->lock);
    data = PoolGet(e->pool);
    SCMutexUnlock(&e->lock);
    if (data) {
        PoolThreadReserved *did = data;
        *did = id;
    }

    return data;
}

void PoolThreadReturn(PoolThread *pt, void *data)
{
    PoolThreadReserved *id = data;

    if (pt == NULL || *id >= pt->size)
        return;

    SCLogDebug("returning to id %u", *id);

    PoolThreadElement *e = &pt->array[*id];
    SCMutexLock(&e->lock);
    PoolReturn(e->pool, data);
    SCMutexUnlock(&e->lock);
}

#ifdef UNITTESTS
struct PoolThreadTestData {
    PoolThreadReserved res;
    int abc;
};

static void *PoolThreadTestAlloc(void)
{
    void *data = SCMalloc(sizeof(struct PoolThreadTestData));
    return data;
}

static
int PoolThreadTestInit(void *data, void *allocdata)
{
    if (!data)
        return 0;

    memset(data,0x00,sizeof(allocdata));
    struct PoolThreadTestData *pdata = data;
    pdata->abc = *(int *)allocdata;
    return 1;
}

static
void PoolThreadTestFree(void *data)
{
}

static int PoolThreadTestInit01(void)
{
    PoolThread *pt = PoolThreadInit(4, /* threads */
                                    10, 5, 10, PoolThreadTestAlloc, NULL, NULL, NULL, NULL);
    if (pt == NULL)
        return 0;

    PoolThreadFree(pt);
    return 1;
}

static int PoolThreadTestInit02(void)
{
    int i = 123;

    PoolThread *pt = PoolThreadInit(4, /* threads */
                                    10, 5, 10, PoolThreadTestAlloc, PoolThreadTestInit, &i, PoolThreadTestFree, NULL);
    if (pt == NULL)
        return 0;

    PoolThreadFree(pt);
    return 1;
}

static int PoolThreadTestGet01(void)
{
    int result = 0;
    PoolThread *pt = PoolThreadInit(4, /* threads */
                                    10, 5, 10, PoolThreadTestAlloc, NULL, NULL, NULL, NULL);
    if (pt == NULL)
        return 0;

    void *data = PoolThreadGetById(pt, 3);
    if (data == NULL) {
        printf("data == NULL: ");
        goto end;
    }

    struct PoolThreadTestData *pdata = data;
    if (pdata->res != 3) {
        printf("res != 3, but %d: ", pdata->res);
        goto end;
    }

    result = 1;
end:
    PoolThreadFree(pt);
    return result;
}

static int PoolThreadTestGet02(void)
{
    int i = 123;
    int result = 0;

    PoolThread *pt = PoolThreadInit(4, /* threads */
                                    10, 5, 10, PoolThreadTestAlloc, PoolThreadTestInit, &i, PoolThreadTestFree, NULL);
    if (pt == NULL)
        return 0;

    void *data = PoolThreadGetById(pt, 3);
    if (data == NULL) {
        printf("data == NULL: ");
        goto end;
    }

    struct PoolThreadTestData *pdata = data;
    if (pdata->res != 3) {
        printf("res != 3, but %d: ", pdata->res);
        goto end;
    }

    if (pdata->abc != 123) {
        printf("abc != 123, but %d: ", pdata->abc);
        goto end;
    }

    result = 1;
end:
    PoolThreadFree(pt);
    return result;
}

static int PoolThreadTestReturn01(void)
{
    int i = 123;
    int result = 0;

    PoolThread *pt = PoolThreadInit(4, /* threads */
                                    10, 5, 10, PoolThreadTestAlloc, PoolThreadTestInit, &i, PoolThreadTestFree, NULL);
    if (pt == NULL)
        return 0;

    void *data = PoolThreadGetById(pt, 3);
    if (data == NULL) {
        printf("data == NULL: ");
        goto end;
    }

    struct PoolThreadTestData *pdata = data;
    if (pdata->res != 3) {
        printf("res != 3, but %d: ", pdata->res);
        goto end;
    }

    if (pdata->abc != 123) {
        printf("abc != 123, but %d: ", pdata->abc);
        goto end;
    }

    if (pt->array[3].pool->outstanding != 1) {
        printf("pool outstanding count wrong %u: ",
                pt->array[3].pool->outstanding);
        goto end;
    }

    PoolThreadReturn(pt, data);

    if (pt->array[3].pool->outstanding != 0) {
        printf("pool outstanding count wrong %u: ",
                pt->array[3].pool->outstanding);
        goto end;
    }


    result = 1;
end:
    PoolThreadFree(pt);
    return result;
}

static int PoolThreadTestGrow01(void)
{
    PoolThread *pt = PoolThreadInit(4, /* threads */
                                    10, 5, 10, PoolThreadTestAlloc, NULL, NULL, NULL, NULL);
    if (pt == NULL)
        return 0;

    if (PoolThreadGrow(pt,
                       10, 5, 10, PoolThreadTestAlloc, NULL, NULL, NULL, NULL) < 0) {
        PoolThreadFree(pt);
        return 0;
    }

    PoolThreadFree(pt);
    return 1;
}

static int PoolThreadTestGrow02(void)
{
    int i = 123;

    PoolThread *pt = PoolThreadInit(4, /* threads */
                                    10, 5, 10, PoolThreadTestAlloc, PoolThreadTestInit, &i, PoolThreadTestFree, NULL);
    if (pt == NULL)
        return 0;

    if (PoolThreadGrow(pt,
                       10, 5, 10, PoolThreadTestAlloc, PoolThreadTestInit, &i, PoolThreadTestFree, NULL) < 0) {
        PoolThreadFree(pt);
        return 0;
    }

    PoolThreadFree(pt);
    return 1;
}

static int PoolThreadTestGrow03(void)
{
    int i = 123;
    int result = 0;

    PoolThread *pt = PoolThreadInit(4, /* threads */
                                    10, 5, 10, PoolThreadTestAlloc, PoolThreadTestInit, &i, PoolThreadTestFree, NULL);
    if (pt == NULL)
        return 0;

    if (PoolThreadGrow(pt,
                       10, 5, 10, PoolThreadTestAlloc, PoolThreadTestInit, &i, PoolThreadTestFree, NULL) < 0) {
        PoolThreadFree(pt);
        return 0;
    }

    void *data = PoolThreadGetById(pt, 4);
    if (data == NULL) {
        printf("data == NULL: ");
        goto end;
    }

    struct PoolThreadTestData *pdata = data;
    if (pdata->res != 4) {
        printf("res != 5, but %d: ", pdata->res);
        goto end;
    }

    if (pdata->abc != 123) {
        printf("abc != 123, but %d: ", pdata->abc);
        goto end;
    }

    if (pt->array[4].pool->outstanding != 1) {
        printf("pool outstanding count wrong %u: ",
                pt->array[4].pool->outstanding);
        goto end;
    }

    PoolThreadReturn(pt, data);

    if (pt->array[4].pool->outstanding != 0) {
        printf("pool outstanding count wrong %u: ",
                pt->array[4].pool->outstanding);
        goto end;
    }


    result = 1;
end:
    PoolThreadFree(pt);
    return result;
}

#endif

void PoolThreadRegisterTests(void)
{
#ifdef UNITTESTS
    UtRegisterTest("PoolThreadTestInit01", PoolThreadTestInit01, 1);
    UtRegisterTest("PoolThreadTestInit02", PoolThreadTestInit02, 1);

    UtRegisterTest("PoolThreadTestGet01", PoolThreadTestGet01, 1);
    UtRegisterTest("PoolThreadTestGet02", PoolThreadTestGet02, 1);

    UtRegisterTest("PoolThreadTestReturn01", PoolThreadTestReturn01, 1);

    UtRegisterTest("PoolThreadTestGrow01", PoolThreadTestGrow01, 1);
    UtRegisterTest("PoolThreadTestGrow02", PoolThreadTestGrow02, 1);
    UtRegisterTest("PoolThreadTestGrow03", PoolThreadTestGrow03, 1);
#endif
}

/**
 * @}
 */
