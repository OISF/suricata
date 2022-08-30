/* Copyright (C) 2007-2022 Open Information Security Foundation
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
 *
 * Lock profiling wrappers
 */

#ifndef __THREADS_PROFILE_H__
#define __THREADS_PROFILE_H__

/* profiling */

typedef struct ProfilingLock_ {
    char *file;
    char *func;
    int line;
    int type;
    uint32_t cont;
    uint64_t ticks;
} ProfilingLock;

extern thread_local ProfilingLock locks[PROFILING_MAX_LOCKS];
extern thread_local int locks_idx;
extern thread_local int record_locks;

extern thread_local uint64_t mutex_lock_contention;
extern thread_local uint64_t mutex_lock_wait_ticks;
extern thread_local uint64_t mutex_lock_cnt;

/* mutex */

//printf("%16s(%s:%d): (thread:%"PRIuMAX") locked mutex %p ret %" PRId32 "\n", __FUNCTION__, __FILE__, __LINE__, (uintmax_t)pthread_self(), mut, retl);
#define SCMutexLock_profile(mut) ({ \
    mutex_lock_cnt++; \
    int retl = 0; \
    int cont = 0; \
    uint64_t mutex_lock_start = UtilCpuGetTicks(); \
    if (pthread_mutex_trylock((mut)) != 0) { \
        mutex_lock_contention++; \
        cont = 1; \
        retl = pthread_mutex_lock(mut); \
    } \
    uint64_t mutex_lock_end = UtilCpuGetTicks();                                \
    mutex_lock_wait_ticks += (uint64_t)(mutex_lock_end - mutex_lock_start);     \
    \
    if (locks_idx < PROFILING_MAX_LOCKS && record_locks) {                      \
        locks[locks_idx].file = (char *)__FILE__;                               \
        locks[locks_idx].func = (char *)__func__;                               \
        locks[locks_idx].line = (int)__LINE__;                                  \
        locks[locks_idx].type = LOCK_MUTEX;                                     \
        locks[locks_idx].cont = cont;                                           \
        locks[locks_idx].ticks = (uint64_t)(mutex_lock_end - mutex_lock_start); \
        locks_idx++;                                                            \
    } \
    retl; \
})

#define SCMutex pthread_mutex_t
#define SCMutexAttr pthread_mutexattr_t
#define SCMutexInit(mut, mutattr ) pthread_mutex_init(mut, mutattr)
#define SCMutexLock(mut) SCMutexLock_profile(mut)
#define SCMutexTrylock(mut) pthread_mutex_trylock(mut)
#define SCMutexUnlock(mut) pthread_mutex_unlock(mut)
#define SCMutexDestroy pthread_mutex_destroy
#define SCMUTEX_INITIALIZER PTHREAD_MUTEX_INITIALIZER

/* conditions */

#define SCCondT pthread_cond_t
#define SCCondInit pthread_cond_init
#define SCCondSignal pthread_cond_signal
#define SCCondDestroy pthread_cond_destroy
#define SCCondWait(cond, mut) pthread_cond_wait(cond, mut)

/* spinlocks */

extern thread_local uint64_t spin_lock_contention;
extern thread_local uint64_t spin_lock_wait_ticks;
extern thread_local uint64_t spin_lock_cnt;

//printf("%16s(%s:%d): (thread:%"PRIuMAX") locked mutex %p ret %" PRId32 "\n", __FUNCTION__, __FILE__, __LINE__, (uintmax_t)pthread_self(), mut, retl);
#define SCSpinLock_profile(spin) ({ \
    spin_lock_cnt++; \
    int retl = 0; \
    int cont = 0; \
    uint64_t spin_lock_start = UtilCpuGetTicks(); \
    if (pthread_spin_trylock((spin)) != 0) { \
        spin_lock_contention++; \
        cont = 1;   \
        retl = pthread_spin_lock((spin)); \
    } \
    uint64_t spin_lock_end = UtilCpuGetTicks(); \
    spin_lock_wait_ticks += (uint64_t)(spin_lock_end - spin_lock_start); \
    \
    if (locks_idx < PROFILING_MAX_LOCKS && record_locks) {                      \
        locks[locks_idx].file = (char *)__FILE__;                               \
        locks[locks_idx].func = (char *)__func__;                               \
        locks[locks_idx].line = (int)__LINE__;                                  \
        locks[locks_idx].type = LOCK_SPIN;                                      \
        locks[locks_idx].cont = cont;                                           \
        locks[locks_idx].ticks = (uint64_t)(spin_lock_end - spin_lock_start);   \
        locks_idx++;                                                            \
    } \
    retl; \
})

#define SCSpinlock                              pthread_spinlock_t
#define SCSpinLock(mut)                         SCSpinLock_profile(mut)
#define SCSpinTrylock(spin)                     pthread_spin_trylock(spin)
#define SCSpinUnlock(spin)                      pthread_spin_unlock(spin)
#define SCSpinInit(spin, spin_attr)             pthread_spin_init(spin, spin_attr)
#define SCSpinDestroy(spin)                     pthread_spin_destroy(spin)

/* rwlocks */

extern thread_local uint64_t rww_lock_contention;
extern thread_local uint64_t rww_lock_wait_ticks;
extern thread_local uint64_t rww_lock_cnt;

#define SCRWLockWRLock_profile(mut) ({ \
    rww_lock_cnt++; \
    int retl = 0; \
    int cont = 0; \
    uint64_t rww_lock_start = UtilCpuGetTicks(); \
    if (pthread_rwlock_trywrlock((mut)) != 0) { \
        rww_lock_contention++; \
        cont = 1; \
        retl = pthread_rwlock_wrlock(mut); \
    } \
    uint64_t rww_lock_end = UtilCpuGetTicks();                                  \
    rww_lock_wait_ticks += (uint64_t)(rww_lock_end - rww_lock_start);           \
    \
    if (locks_idx < PROFILING_MAX_LOCKS && record_locks) {                      \
        locks[locks_idx].file = (char *)__FILE__;                               \
        locks[locks_idx].func = (char *)__func__;                               \
        locks[locks_idx].line = (int)__LINE__;                                  \
        locks[locks_idx].type = LOCK_RWW;                                       \
        locks[locks_idx].cont = cont;                                           \
        locks[locks_idx].ticks = (uint64_t)(rww_lock_end - rww_lock_start);     \
        locks_idx++;                                                            \
    } \
    retl; \
})

extern thread_local uint64_t rwr_lock_contention;
extern thread_local uint64_t rwr_lock_wait_ticks;
extern thread_local uint64_t rwr_lock_cnt;

#define SCRWLockRDLock_profile(mut) ({ \
    rwr_lock_cnt++; \
    int retl = 0; \
    int cont = 0; \
    uint64_t rwr_lock_start = UtilCpuGetTicks(); \
    if (pthread_rwlock_tryrdlock((mut)) != 0) { \
        rwr_lock_contention++; \
        cont = 1; \
        retl = pthread_rwlock_rdlock(mut); \
    } \
    uint64_t rwr_lock_end = UtilCpuGetTicks();                                  \
    rwr_lock_wait_ticks += (uint64_t)(rwr_lock_end - rwr_lock_start);           \
    \
    if (locks_idx < PROFILING_MAX_LOCKS && record_locks) {                      \
        locks[locks_idx].file = (char *)__FILE__;                               \
        locks[locks_idx].func = (char *)__func__;                               \
        locks[locks_idx].line = (int)__LINE__;                                  \
        locks[locks_idx].type = LOCK_RWR;                                       \
        locks[locks_idx].cont = cont;                                           \
        locks[locks_idx].ticks = (uint64_t)(rwr_lock_end - rwr_lock_start);     \
        locks_idx++;                                                            \
    } \
    retl; \
})

#define SCRWLock pthread_rwlock_t
#define SCRWLockInit(rwl, rwlattr ) pthread_rwlock_init(rwl, rwlattr)
#define SCRWLockWRLock(mut) SCRWLockWRLock_profile(mut)
#define SCRWLockRDLock(mut) SCRWLockRDLock_profile(mut)
#define SCRWLockTryWRLock(rwl) pthread_rwlock_trywrlock(rwl)
#define SCRWLockTryRDLock(rwl) pthread_rwlock_tryrdlock(rwl)
#define SCRWLockUnlock(rwl) pthread_rwlock_unlock(rwl)
#define SCRWLockDestroy pthread_rwlock_destroy

/* ctrl mutex */
#define SCCtrlMutex pthread_mutex_t
#define SCCtrlMutexAttr pthread_mutexattr_t
#define SCCtrlMutexInit(mut, mutattr ) pthread_mutex_init(mut, mutattr)
#define SCCtrlMutexLock(mut) pthread_mutex_lock(mut)
#define SCCtrlMutexTrylock(mut) pthread_mutex_trylock(mut)
#define SCCtrlMutexUnlock(mut) pthread_mutex_unlock(mut)
#define SCCtrlMutexDestroy pthread_mutex_destroy

/* ctrl conditions */
#define SCCtrlCondT pthread_cond_t
#define SCCtrlCondInit pthread_cond_init
#define SCCtrlCondSignal pthread_cond_signal
#define SCCtrlCondTimedwait pthread_cond_timedwait
#define SCCtrlCondWait pthread_cond_wait
#define SCCtrlCondDestroy pthread_cond_destroy

#endif
