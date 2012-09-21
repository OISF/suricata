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
 * \ingroup utilpool
 *
 * @{
 */

/**
 * \file
 *
 * \author Victor Julien <victor@inliniac.net>
 */

#ifndef __UTIL_POOL_H__
#define __UTIL_POOL_H__

#define POOL_BUCKET_PREALLOCATED    (1 << 0)

/* pool bucket structure */
typedef struct PoolBucket_ {
    void *data;
    uint8_t flags;
    struct PoolBucket_ *next;
} PoolBucket;

/* pool structure */
typedef struct Pool_ {
    uint32_t max_buckets;
    uint32_t preallocated;
    uint32_t allocated;

    PoolBucket *alloc_list;
    uint32_t alloc_list_size;

    PoolBucket *empty_list;
    uint32_t empty_list_size;

    PoolBucket *pb_buffer;
    void *data_buffer;
    int data_buffer_size;

    void *(*Alloc)();
    int (*Init)(void *, void *);
    void *InitData;
    void (*Cleanup)(void *);
    void (*Free)(void *);

    uint32_t elt_size;
    uint32_t outstanding;
    uint32_t max_outstanding;
} Pool;

/* prototypes */
Pool* PoolInit(uint32_t, uint32_t, uint32_t, void *(*Alloc)(), int (*Init)(void *, void *), void *, void (*Cleanup)(void *), void (*Free)(void *));
void PoolFree(Pool *);
void PoolPrint(Pool *);
void PoolPrintSaturation(Pool *p);

void *PoolGet(Pool *);
void PoolReturn(Pool *, void *);

void PoolRegisterTests(void);

#endif /* __UTIL_POOL_H__ */

/**
 * @}
 */
