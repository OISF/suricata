/* Copyright (C) 2007-2010 Open Information Security Foundation
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
 * ::Pool are an effective way to maintain a set of ready to use
 * structures.
 *
 * To create a ::Pool, you need to use PoolInit(). You can
 * get an item from the ::Pool by using PoolGet(). When you're
 * done with it call PoolReturn().
 * To destroy the ::Pool, call PoolFree(), it will free all used
 * memory.
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

static int PoolMemset(void *pitem, void *initdata)
{
    Pool *p = (Pool *) initdata;

    memset(pitem, 0, p->elt_size);
    return 1;
}

/**
 * \brief Check if data is preallocated
 * \retval false if not inside the prealloc'd block, true if inside */
static bool PoolDataPreAllocated(Pool *p, void *data)
{
    ptrdiff_t delta = data - p->data_buffer;
    if ((delta < 0) || (delta > p->data_buffer_size)) {
        return false;
    }
    return true;
}

/** \brief Init a Pool
 *
 * PoolInit() creates a ::Pool. The Alloc function must only do
 * allocation stuff. The Cleanup function must not try to free
 * the PoolBucket::data. This is done by the ::Pool management
 * system.
 *
 * \param size
 * \param prealloc_size
 * \param elt_size Memory size of an element
 * \param Alloc An allocation function or NULL to use a standard SCMalloc
 * \param Init An init function or NULL to use a standard memset to 0
 * \param InitData Init data
 * \param Cleanup a free function or NULL if no special treatment is needed
 * \param Free free func
 * \retval the allocated Pool
 */
Pool *PoolInit(uint32_t size, uint32_t prealloc_size, uint32_t elt_size,
        void *(*Alloc)(void), int (*Init)(void *, void *), void *InitData,
        void (*Cleanup)(void *), void (*Free)(void *))
{
    sc_errno = SC_OK;

    Pool *p = NULL;

    if (size != 0 && prealloc_size > size) {
        sc_errno = SC_EINVAL;
        goto error;
    }
    if (size != 0 && elt_size == 0) {
        sc_errno = SC_EINVAL;
        goto error;
    }
    if (elt_size && Free) {
        sc_errno = SC_EINVAL;
        goto error;
    }
    if (elt_size == 0 && Alloc == NULL) {
        sc_errno = SC_EINVAL;
        goto error;
    }

    /* setup the filter */
    p = SCCalloc(1, sizeof(Pool));
    if (unlikely(p == NULL)) {
        sc_errno = SC_ENOMEM;
        goto error;
    }

    p->max_buckets = size;
    p->preallocated = prealloc_size;
    p->elt_size = elt_size;
    p->data_buffer_size = prealloc_size * elt_size;
    p->Alloc = Alloc;
    p->Init = Init;
    p->InitData = InitData;
    p->Cleanup = Cleanup;
    p->Free = Free;
    if (p->Init == NULL) {
        p->Init = PoolMemset;
        p->InitData = p;
    }

    /* alloc the buckets and place them in the empty list */
    uint32_t u32 = 0;
    if (size > 0) {
        PoolBucket *pb = SCCalloc(size, sizeof(PoolBucket));
        if (unlikely(pb == NULL)) {
            sc_errno = SC_ENOMEM;
            goto error;
        }
        memset(pb, 0, size * sizeof(PoolBucket));
        p->pb_buffer = pb;
        for (u32 = 0; u32 < size; u32++) {
            /* populate pool */
            pb->next = p->empty_stack;
            pb->flags |= POOL_BUCKET_PREALLOCATED;
            p->empty_stack = pb;
            p->empty_stack_size++;
            pb++;
        }

        p->data_buffer = SCCalloc(prealloc_size, elt_size);
        /* FIXME better goto */
        if (p->data_buffer == NULL) {
            sc_errno = SC_ENOMEM;
            goto error;
        }
    }
    /* prealloc the buckets and requeue them to the alloc list */
    for (u32 = 0; u32 < prealloc_size; u32++) {
        if (size == 0) { /* unlimited */
            PoolBucket *pb = SCCalloc(1, sizeof(PoolBucket));
            if (unlikely(pb == NULL)) {
                sc_errno = SC_ENOMEM;
                goto error;
            }

            if (p->Alloc) {
                pb->data = p->Alloc();
            } else {
                pb->data = SCMalloc(p->elt_size);
            }
            if (pb->data == NULL) {
                SCFree(pb);
                sc_errno = SC_ENOMEM;
                goto error;
            }
            if (p->Init(pb->data, p->InitData) != 1) {
                if (p->Free)
                    p->Free(pb->data);
                else
                    SCFree(pb->data);
                SCFree(pb);
                sc_errno = SC_EINVAL;
                goto error;
            }
            p->allocated++;

            pb->next = p->alloc_stack;
            p->alloc_stack = pb;
            p->alloc_stack_size++;
        } else {
            PoolBucket *pb = p->empty_stack;
            if (pb == NULL) {
                sc_errno = SC_ENOMEM;
                goto error;
            }

            pb->data = (char *)p->data_buffer + u32 * elt_size;
            if (p->Init(pb->data, p->InitData) != 1) {
                pb->data = NULL;
                sc_errno = SC_EINVAL;
                goto error;
            }

            p->empty_stack = pb->next;
            p->empty_stack_size--;

            p->allocated++;

            pb->next = p->alloc_stack;
            p->alloc_stack = pb;
            p->alloc_stack_size++;
        }
    }

    return p;

error:
    if (p != NULL) {
        PoolFree(p);
    }
    return NULL;
}

void PoolFree(Pool *p)
{
    if (p == NULL)
        return;

    while (p->alloc_stack != NULL) {
        PoolBucket *pb = p->alloc_stack;
        p->alloc_stack = pb->next;
        if (p->Cleanup)
            p->Cleanup(pb->data);
        if (!PoolDataPreAllocated(p, pb->data)) {
            if (p->Free)
                p->Free(pb->data);
            else
                SCFree(pb->data);
        }
        pb->data = NULL;
        if (!(pb->flags & POOL_BUCKET_PREALLOCATED)) {
            SCFree(pb);
        }
    }

    while (p->empty_stack != NULL) {
        PoolBucket *pb = p->empty_stack;
        p->empty_stack = pb->next;
        if (pb->data!= NULL) {
            if (p->Cleanup)
                p->Cleanup(pb->data);
            if (!PoolDataPreAllocated(p, pb->data)) {
                if (p->Free)
                    p->Free(pb->data);
                else
                    SCFree(pb->data);
            }
            pb->data = NULL;
        }
        if (!(pb->flags & POOL_BUCKET_PREALLOCATED)) {
            SCFree(pb);
        }
    }

    if (p->pb_buffer)
        SCFree(p->pb_buffer);
    if (p->data_buffer)
        SCFree(p->data_buffer);
    SCFree(p);
}

void *PoolGet(Pool *p)
{
    SCEnter();

    PoolBucket *pb = p->alloc_stack;
    if (pb != NULL) {
        /* pull from the alloc list */
        p->alloc_stack = pb->next;
        p->alloc_stack_size--;

        /* put in the empty list */
        pb->next = p->empty_stack;
        p->empty_stack = pb;
        p->empty_stack_size++;
    } else {
        if (p->max_buckets == 0 || p->allocated < p->max_buckets) {
            void *pitem;
            SCLogDebug("max_buckets %"PRIu32"", p->max_buckets);

            if (p->Alloc != NULL) {
                pitem = p->Alloc();
            } else {
                pitem = SCMalloc(p->elt_size);
            }

            if (pitem != NULL) {
                if (p->Init(pitem, p->InitData) != 1) {
                    if (p->Free != NULL)
                        p->Free(pitem);
                    else
                        SCFree(pitem);
                    SCReturnPtr(NULL, "void");
                }

                p->allocated++;
                p->outstanding++;
#ifdef DEBUG
                if (p->outstanding > p->max_outstanding)
                    p->max_outstanding = p->outstanding;
#endif
            }

            SCReturnPtr(pitem, "void");
        } else {
            SCReturnPtr(NULL, "void");
        }
    }

    void *ptr = pb->data;
    pb->data = NULL;
    p->outstanding++;
#ifdef DEBUG
    if (p->outstanding > p->max_outstanding)
        p->max_outstanding = p->outstanding;
#endif
    SCReturnPtr(ptr,"void");
}

void PoolReturn(Pool *p, void *data)
{
    SCEnter();

    PoolBucket *pb = p->empty_stack;

    SCLogDebug("pb %p", pb);

    if (pb == NULL) {
        p->allocated--;
        p->outstanding--;
        if (p->Cleanup != NULL) {
            p->Cleanup(data);
        }
        if (!PoolDataPreAllocated(p, data)) {
            if (p->Free)
                p->Free(data);
            else
                SCFree(data);
        }

        SCLogDebug("tried to return data %p to the pool %p, but no more "
                   "buckets available. Just freeing the data.", data, p);
        SCReturn;
    }

    /* pull from the alloc list */
    p->empty_stack = pb->next;
    p->empty_stack_size--;

    /* put in the alloc list */
    pb->next = p->alloc_stack;
    p->alloc_stack = pb;
    p->alloc_stack_size++;

    pb->data = data;
    p->outstanding--;
    SCReturn;
}

/*
 * ONLY TESTS BELOW THIS COMMENT
 */

#ifdef UNITTESTS
static void *PoolTestAlloc(void)
{
    void *ptr = SCMalloc(10);
    FAIL_IF_NULL(ptr);
    return ptr;
}
static int PoolTestInitArg(void *data, void *allocdata)
{
    size_t len = strlen((char *)allocdata) + 1;
    char *str = data;
    if (str != NULL)
        strlcpy(str,(char *)allocdata,len);
    return 1;
}

static void PoolTestFree(void *ptr)
{
}

static int PoolTestInit01(void)
{
    Pool *p = PoolInit(10,5,10,PoolTestAlloc,NULL,NULL,PoolTestFree, NULL);
    FAIL_IF_NULL(p);
    PoolFree(p);
    PASS;
}

static int PoolTestInit02(void)
{
    Pool *p = PoolInit(10,5,10,PoolTestAlloc,NULL,NULL,PoolTestFree, NULL);
    FAIL_IF_NULL(p);
    FAIL_IF_NULL(p->alloc_stack);
    FAIL_IF_NULL(p->empty_stack);
    FAIL_IF_NOT(p->Alloc == PoolTestAlloc);
    FAIL_IF_NOT(p->Cleanup == PoolTestFree);
    PoolFree(p);
    PASS;
}

static int PoolTestInit03(void)
{
    Pool *p = PoolInit(10,5,10,PoolTestAlloc,NULL,NULL,PoolTestFree, NULL);
    FAIL_IF_NULL(p);

    void *data = PoolGet(p);
    FAIL_IF_NULL(data);
    FAIL_IF_NOT(p->alloc_stack_size == 4);
    FAIL_IF_NOT(p->empty_stack_size == 6);

    PoolFree(p);
    PASS;
}

static int PoolTestInit04(void)
{
    Pool *p = PoolInit(10,5,strlen("test") + 1,NULL, PoolTestInitArg,(void *)"test",PoolTestFree, NULL);
    FAIL_IF_NULL(p);

    char *str = PoolGet(p);
    FAIL_IF_NULL(str);
    FAIL_IF(strcmp(str, "test") != 0);
    FAIL_IF_NOT(p->alloc_stack_size == 4);
    FAIL_IF_NOT(p->empty_stack_size == 6);

    PoolFree(p);
    PASS;
}

static int PoolTestInit05(void)
{
    Pool *p = PoolInit(10,5,10,PoolTestAlloc,NULL, NULL,PoolTestFree, NULL);
    FAIL_IF_NULL(p);

    void *data = PoolGet(p);
    FAIL_IF_NULL(data);
    FAIL_IF_NOT(p->alloc_stack_size == 4);
    FAIL_IF_NOT(p->empty_stack_size == 6);

    PoolReturn(p, data);
    FAIL_IF_NOT(p->alloc_stack_size == 5);
    FAIL_IF_NOT(p->empty_stack_size == 5);

    PoolFree(p);
    PASS;
}

static int PoolTestInit06(void)
{
    Pool *p = PoolInit(1,0,10,PoolTestAlloc,NULL,NULL,PoolTestFree, NULL);
    FAIL_IF_NULL(p);
    FAIL_IF_NOT(p->allocated == 0);

    void *data = PoolGet(p);
    FAIL_IF_NULL(data);
    FAIL_IF_NOT(p->allocated == 1);

    void *data2 = PoolGet(p);
    FAIL_IF_NOT(data2 == NULL);

    PoolReturn(p,data);
    FAIL_IF_NOT(p->allocated == 1);
    FAIL_IF_NOT(p->alloc_stack_size == 1);

    PoolFree(p);
    PASS;
}

/** \test pool with unlimited size */
static int PoolTestInit07(void)
{
    Pool *p = PoolInit(0,1,10,PoolTestAlloc,NULL,NULL,PoolTestFree, NULL);
    FAIL_IF_NULL(p);
    FAIL_IF_NOT(p->max_buckets == 0);
    FAIL_IF_NOT(p->allocated == 1);

    void *data = PoolGet(p);
    FAIL_IF_NULL(data);
    FAIL_IF_NOT(p->allocated == 1);

    void *data2 = PoolGet(p);
    FAIL_IF_NULL(data2);
    FAIL_IF_NOT(p->allocated == 2);

    PoolReturn(p,data);
    FAIL_IF_NOT(p->allocated == 2);
    FAIL_IF_NOT(p->alloc_stack_size == 1);

    PoolReturn(p,data2);
    FAIL_IF_NOT(p->allocated == 1);

    PoolFree(p);
    PASS;
}
#endif /* UNITTESTS */

void PoolRegisterTests(void)
{
#ifdef UNITTESTS
    UtRegisterTest("PoolTestInit01", PoolTestInit01);
    UtRegisterTest("PoolTestInit02", PoolTestInit02);
    UtRegisterTest("PoolTestInit03", PoolTestInit03);
    UtRegisterTest("PoolTestInit04", PoolTestInit04);
    UtRegisterTest("PoolTestInit05", PoolTestInit05);
    UtRegisterTest("PoolTestInit06", PoolTestInit06);
    UtRegisterTest("PoolTestInit07", PoolTestInit07);

    PoolThreadRegisterTests();
#endif /* UNITTESTS */
}

/**
 * @}
 */
