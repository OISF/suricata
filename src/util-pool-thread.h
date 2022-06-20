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
 * \ingroup utilpool
 *
 * @{
 */

/**
 * \file
 *
 * \author Victor Julien <victor@inliniac.net>
 */

/**
 *  Consumers of this API MUST add PoolThreadReserved as the first
 *  member in the data structure. They also MUST ignore that data
 *  completely. It's managed by this API.
 *
 *  It's purpose is to make sure thread X can return data to a pool
 *  from thread Y.
 */

#ifndef __UTIL_POOL_THREAD_H__
#define __UTIL_POOL_THREAD_H__

#include "util-pool.h"

struct PoolThreadElement_ {
    SCMutex lock;                   /**< lock, should have low contention */
    Pool *pool;                     /**< actual pool */
};
// __attribute__((aligned(CLS))); <- VJ: breaks on clang 32bit, segv in PoolThreadTestGrow01

typedef struct PoolThreadElement_ PoolThreadElement;

typedef struct PoolThread_ {
    size_t size;                    /**< size of the array */
    PoolThreadElement *array;       /**< array of elements */
} PoolThread;

/** per data item reserved data containing the
 *  thread pool id */
typedef uint16_t PoolThreadReserved;

void PoolThreadRegisterTests(void);

/** \brief initialize a thread pool
 *  \note same as PoolInit() except for "threads"
 *  \param threads number of threads to use this
 *  \retval pt thread pool or NULL on error */
PoolThread *PoolThreadInit(int threads, uint32_t size, uint32_t prealloc_size, uint32_t elt_size,  void *(*Alloc)(void), int (*Init)(void *, void *), void *InitData,  void (*Cleanup)(void *), void (*Free)(void *));

/** \brief grow a thread pool by one
 *  \note copies settings from initial PoolThreadInit() call
 *  \param pt thread pool to grow
 *  \retval r id of new entry on succes, -1 on error */
int PoolThreadExpand(PoolThread *pt);

/** \brief destroy the thread pool
 *  \note wrapper around PoolFree()
 *  \param pt thread pool */
void PoolThreadFree(PoolThread *pt);

/** \brief get data from thread pool by thread id
 *  \note wrapper around PoolGet()
 *  \param pt thread pool
 *  \param id thread id
 *  \retval ptr data or NULL */
void *PoolThreadGetById(PoolThread *pt, uint16_t id);

/** \brief return data to thread pool
 *  \note wrapper around PoolReturn()
 *  \param pt thread pool
 *  \param data memory block to return, with PoolThreadReserved as it's first member */
void PoolThreadReturn(PoolThread *pt, void *data);

/** \brief get size of PoolThread (number of 'threads', so array elements)
 *  \param pt thread pool
 *  \retval size or -1 on error */
int PoolThreadSize(PoolThread *pt);

#endif /* __UTIL_POOL_THREAD_H__ */

/**
 * @}
 */
