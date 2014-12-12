/* Copyright (C) 2007-2013 Open Information Security Foundation
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

#ifndef __HOST_H__
#define __HOST_H__

#include "decode.h"
#include "util-storage.h"

/** Spinlocks or Mutex for the flow buckets. */
//#define HRLOCK_SPIN
#define HRLOCK_MUTEX

#ifdef HRLOCK_SPIN
    #ifdef HRLOCK_MUTEX
        #error Cannot enable both HRLOCK_SPIN and HRLOCK_MUTEX
    #endif
#endif

#ifdef HRLOCK_SPIN
    #define HRLOCK_TYPE SCSpinlock
    #define HRLOCK_INIT(fb) SCSpinInit(&(fb)->lock, 0)
    #define HRLOCK_DESTROY(fb) SCSpinDestroy(&(fb)->lock)
    #define HRLOCK_LOCK(fb) SCSpinLock(&(fb)->lock)
    #define HRLOCK_TRYLOCK(fb) SCSpinTrylock(&(fb)->lock)
    #define HRLOCK_UNLOCK(fb) SCSpinUnlock(&(fb)->lock)
#elif defined HRLOCK_MUTEX
    #define HRLOCK_TYPE SCMutex
    #define HRLOCK_INIT(fb) SCMutexInit(&(fb)->lock, NULL)
    #define HRLOCK_DESTROY(fb) SCMutexDestroy(&(fb)->lock)
    #define HRLOCK_LOCK(fb) SCMutexLock(&(fb)->lock)
    #define HRLOCK_TRYLOCK(fb) SCMutexTrylock(&(fb)->lock)
    #define HRLOCK_UNLOCK(fb) SCMutexUnlock(&(fb)->lock)
#else
    #error Enable HRLOCK_SPIN or HRLOCK_MUTEX
#endif

typedef struct Host_ {
    /** host mutex */
    SCMutex m;

    /** host address -- ipv4 or ipv6 */
    Address a;

    /** use cnt, reference counter */
    SC_ATOMIC_DECLARE(unsigned int, use_cnt);

    /** pointers to iprep storage */
    void *iprep;

    /** storage api handle */
    Storage *storage;

    /** hash pointers, protected by hash row mutex/spin */
    struct Host_ *hnext;
    struct Host_ *hprev;

    /** list pointers, protected by host-queue mutex/spin */
    struct Host_ *lnext;
    struct Host_ *lprev;
} Host;

typedef struct HostHashRow_ {
    HRLOCK_TYPE lock;
    Host *head;
    Host *tail;
} __attribute__((aligned(CLS))) HostHashRow;

/** host hash table */
HostHashRow *host_hash;

#define HOST_VERBOSE    0
#define HOST_QUIET      1

typedef struct HostConfig_ {
    uint64_t memcap;
    uint32_t hash_rand;
    uint32_t hash_size;
    uint32_t prealloc;
} HostConfig;

/** \brief check if a memory alloc would fit in the memcap
 *
 *  \param size memory allocation size to check
 *
 *  \retval 1 it fits
 *  \retval 0 no fit
 */
#define HOST_CHECK_MEMCAP(size) \
    ((((uint64_t)SC_ATOMIC_GET(host_memuse) + (uint64_t)(size)) <= host_config.memcap))

#define HostIncrUsecnt(h) \
    (void)SC_ATOMIC_ADD((h)->use_cnt, 1)
#define HostDecrUsecnt(h) \
    (void)SC_ATOMIC_SUB((h)->use_cnt, 1)

#define HostReference(dst_h_ptr, h) do {            \
        if ((h) != NULL) {                          \
            HostIncrUsecnt((h));                    \
            *(dst_h_ptr) = h;                       \
        }                                           \
    } while (0)

#define HostDeReference(src_h_ptr) do {               \
        if (*(src_h_ptr) != NULL) {                   \
            HostDecrUsecnt(*(src_h_ptr));             \
            *(src_h_ptr) = NULL;                      \
        }                                             \
    } while (0)

HostConfig host_config;
SC_ATOMIC_DECLARE(unsigned long long int,host_memuse);
SC_ATOMIC_DECLARE(unsigned int,host_counter);
SC_ATOMIC_DECLARE(unsigned int,host_prune_idx);

void HostInitConfig(char quiet);
void HostShutdown(void);
void HostCleanup(void);

Host *HostLookupHostFromHash (Address *);
Host *HostGetHostFromHash (Address *);
void HostRelease(Host *);
void HostLock(Host *);
void HostClearMemory(Host *);
void HostMoveToSpare(Host *);
uint32_t HostSpareQueueGetSize(void);
void HostPrintStats (void);

void HostRegisterUnittests(void);

Host *HostAlloc();
void HostFree();

void HostUnlock(Host *h);

#endif /* __HOST_H__ */

