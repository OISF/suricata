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
 * \author Pablo Rincon Crespo <pablo.rincon.crespo@gmail.com>
 *
 * Threading functions defined as macros: debug variants
 */

#ifndef __THREADS_DEBUG_H__
#define __THREADS_DEBUG_H__

/* mutex */

/** When dbg threads is defined, if a mutex fail to lock, it's
 * initialized, logged, and does a second try; This is to prevent the system to freeze;
 * It is for Mac OS X users;
 * If you see a mutex, spinlock or condition not initialized, report it please!
 */
#define SCMutexLock_dbg(mut) ({ \
    printf("%16s(%s:%d): (thread:%"PRIuMAX") locking mutex %p\n", __FUNCTION__, __FILE__, __LINE__, (uintmax_t)pthread_self(), mut); \
    int retl = pthread_mutex_lock(mut); \
    printf("%16s(%s:%d): (thread:%"PRIuMAX") locked mutex %p ret %" PRId32 "\n", __FUNCTION__, __FILE__, __LINE__, (uintmax_t)pthread_self(), mut, retl); \
    if (retl != 0) { \
        switch (retl) { \
            case EINVAL: \
            printf("The value specified by attr is invalid\n"); \
            retl = pthread_mutex_init(mut, NULL); \
            if (retl != 0) \
                exit(EXIT_FAILURE); \
            retl = pthread_mutex_lock(mut); \
            break; \
            case EDEADLK: \
            printf("A deadlock would occur if the thread blocked waiting for mutex\n"); \
            break; \
        } \
    } \
    retl; \
})

#define SCMutexTrylock_dbg(mut) ({ \
    printf("%16s(%s:%d): (thread:%"PRIuMAX") trylocking mutex %p\n", __FUNCTION__, __FILE__, __LINE__, (uintmax_t)pthread_self(), mut); \
    int rett = pthread_mutex_trylock(mut); \
    printf("%16s(%s:%d): (thread:%"PRIuMAX") trylocked mutex %p ret %" PRId32 "\n", __FUNCTION__, __FILE__, __LINE__, (uintmax_t)pthread_self(), mut, rett); \
    if (rett != 0) { \
        switch (rett) { \
            case EINVAL: \
            printf("%16s(%s:%d): The value specified by attr is invalid\n", __FUNCTION__, __FILE__, __LINE__); \
            break; \
            case EBUSY: \
            printf("Mutex is already locked\n"); \
            break; \
        } \
    } \
    rett; \
})

#define SCMutexInit_dbg(mut, mutattr) ({ \
    int ret; \
    ret = pthread_mutex_init(mut, mutattr); \
    if (ret != 0) { \
        switch (ret) { \
            case EINVAL: \
            printf("The value specified by attr is invalid\n"); \
            printf("%16s(%s:%d): (thread:%"PRIuMAX") mutex %p initialization returned %" PRId32 "\n", __FUNCTION__, __FILE__, __LINE__, (uintmax_t)pthread_self(), mut, ret); \
            break; \
            case EAGAIN: \
            printf("The system temporarily lacks the resources to create another mutex\n"); \
            printf("%16s(%s:%d): (thread:%"PRIuMAX") mutex %p initialization returned %" PRId32 "\n", __FUNCTION__, __FILE__, __LINE__, (uintmax_t)pthread_self(), mut, ret); \
            break; \
            case ENOMEM: \
            printf("The process cannot allocate enough memory to create another mutex\n"); \
            printf("%16s(%s:%d): (thread:%"PRIuMAX") mutex %p initialization returned %" PRId32 "\n", __FUNCTION__, __FILE__, __LINE__, (uintmax_t)pthread_self(), mut, ret); \
            break; \
        } \
    } \
    ret; \
})

#define SCMutexUnlock_dbg(mut) ({ \
    printf("%16s(%s:%d): (thread:%"PRIuMAX") unlocking mutex %p\n", __FUNCTION__, __FILE__, __LINE__, (uintmax_t)pthread_self(), mut); \
    int retu = pthread_mutex_unlock(mut); \
    printf("%16s(%s:%d): (thread:%"PRIuMAX") unlocked mutex %p ret %" PRId32 "\n", __FUNCTION__, __FILE__, __LINE__, (uintmax_t)pthread_self(), mut, retu); \
    if (retu != 0) { \
        switch (retu) { \
            case EINVAL: \
            printf("%16s(%s:%d): The value specified by attr is invalid\n", __FUNCTION__, __FILE__, __LINE__); \
            break; \
            case EPERM: \
            printf("The current thread does not hold a lock on mutex\n"); \
            break; \
        } \
    } \
    retu; \
})

#define SCMutex pthread_mutex_t
#define SCMutexAttr pthread_mutexattr_t
#define SCMutexInit(mut, mutattrs) SCMutexInit_dbg(mut, mutattrs)
#define SCMutexLock(mut) SCMutexLock_dbg(mut)
#define SCMutexTrylock(mut) SCMutexTrylock_dbg(mut)
#define SCMutexUnlock(mut) SCMutexUnlock_dbg(mut)
#define SCMutexDestroy pthread_mutex_destroy
#define SCMUTEX_INITIALIZER PTHREAD_MUTEX_INITIALIZER

/* conditions */

#define SCCondWait_dbg(cond, mut) ({ \
    int ret = pthread_cond_wait(cond, mut); \
    switch (ret) { \
        case EINVAL: \
        printf("The value specified by attr is invalid (or a SCCondT not initialized!)\n"); \
        printf("%16s(%s:%d): (thread:%"PRIuMAX") failed SCCondWait %p ret %" PRId32 "\n", __FUNCTION__, __FILE__, __LINE__, (uintmax_t)pthread_self(), mut, ret); \
        break; \
    } \
    ret; \
})

/* conditions */
#define SCCondT pthread_cond_t
#define SCCondInit pthread_cond_init
#define SCCondSignal pthread_cond_signal
#define SCCondDestroy pthread_cond_destroy
#define SCCondWait SCCondWait_dbg

/* spinlocks */

#define SCSpinLock_dbg(spin) ({ \
    printf("%16s(%s:%d): (thread:%"PRIuMAX") locking spin %p\n", __FUNCTION__, __FILE__, __LINE__, (uintmax_t)pthread_self(), spin); \
    int ret = pthread_spin_lock(spin); \
    printf("%16s(%s:%d): (thread:%"PRIuMAX") unlocked spin %p ret %" PRId32 "\n", __FUNCTION__, __FILE__, __LINE__, (uintmax_t)pthread_self(), spin, ret); \
    switch (ret) { \
        case EINVAL: \
        printf("The value specified by attr is invalid\n"); \
        break; \
        case EDEADLK: \
        printf("A deadlock would occur if the thread blocked waiting for spin\n"); \
        break; \
    } \
    ret; \
})

#define SCSpinTrylock_dbg(spin) ({ \
    printf("%16s(%s:%d): (thread:%"PRIuMAX") trylocking spin %p\n", __FUNCTION__, __FILE__, __LINE__, (uintmax_t)pthread_self(), spin); \
    int ret = pthread_spin_trylock(spin); \
    printf("%16s(%s:%d): (thread:%"PRIuMAX") trylocked spin %p ret %" PRId32 "\n", __FUNCTION__, __FILE__, __LINE__, (uintmax_t)pthread_self(), spin, ret); \
    switch (ret) { \
        case EINVAL: \
        printf("The value specified by attr is invalid\n"); \
        break; \
        case EDEADLK: \
        printf("A deadlock would occur if the thread blocked waiting for spin\n"); \
        break; \
        case EBUSY: \
        printf("A thread currently holds the lock\n"); \
        break; \
    } \
    ret; \
})

#define SCSpinUnlock_dbg(spin) ({ \
    printf("%16s(%s:%d): (thread:%"PRIuMAX") unlocking spin %p\n", __FUNCTION__, __FILE__, __LINE__, (uintmax_t)pthread_self(), spin); \
    int ret = pthread_spin_unlock(spin); \
    printf("%16s(%s:%d): (thread:%"PRIuMAX") unlockedspin %p ret %" PRId32 "\n", __FUNCTION__, __FILE__, __LINE__, (uintmax_t)pthread_self(), spin, ret); \
    switch (ret) { \
        case EINVAL: \
        printf("The value specified by attr is invalid\n"); \
        break; \
        case EPERM: \
        printf("The calling thread does not hold the lock\n"); \
        break; \
    } \
    ret; \
})

#define SCSpinInit_dbg(spin, spin_attr) ({ \
    int ret = pthread_spin_init(spin, spin_attr); \
    printf("%16s(%s:%d): (thread:%"PRIuMAX") spinlock %p initialization returned %" PRId32 "\n", __FUNCTION__, __FILE__, __LINE__, (uintmax_t)pthread_self(), spin, ret); \
    switch (ret) { \
        case EINVAL: \
        printf("The value specified by attr is invalid\n"); \
        break; \
        case EBUSY: \
        printf("A thread currently holds the lock\n"); \
        break; \
        case ENOMEM: \
        printf("The process cannot allocate enough memory to create another spin\n"); \
        break; \
        case EAGAIN: \
        printf("The system temporarily lacks the resources to create another spin\n"); \
        break; \
    } \
    ret; \
})

#define SCSpinDestroy_dbg(spin) ({ \
    printf("%16s(%s:%d): (thread:%"PRIuMAX") condition %p waiting\n", __FUNCTION__, __FILE__, __LINE__, (uintmax_t)pthread_self(), spin); \
    int ret = pthread_spin_destroy(spin); \
    printf("%16s(%s:%d): (thread:%"PRIuMAX") condition %p passed %" PRId32 "\n", __FUNCTION__, __FILE__, __LINE__, (uintmax_t)pthread_self(), spin, ret); \
    switch (ret) { \
        case EINVAL: \
        printf("The value specified by attr is invalid\n"); \
        break; \
        case EBUSY: \
        printf("A thread currently holds the lock\n"); \
        break; \
        case ENOMEM: \
        printf("The process cannot allocate enough memory to create another spin\n"); \
        break; \
        case EAGAIN: \
        printf("The system temporarily lacks the resources to create another spin\n"); \
        break; \
    } \
    ret; \
})

#define SCSpinlock                              pthread_spinlock_t
#define SCSpinLock                              SCSpinLock_dbg
#define SCSpinTrylock                           SCSpinTrylock_dbg
#define SCSpinUnlock                            SCSpinUnlock_dbg
#define SCSpinInit                              SCSpinInit_dbg
#define SCSpinDestroy                           SCSpinDestroy_dbg

/* rwlocks */

/** When dbg threads is defined, if a rwlock fail to lock, it's
 * initialized, logged, and does a second try; This is to prevent the system to freeze;
 * If you see a rwlock, spinlock or condition not initialized, report it please!
 */
#define SCRWLockRDLock_dbg(rwl) ({ \
    printf("%16s(%s:%d): (thread:%"PRIuMAX") locking rwlock %p\n", __FUNCTION__, __FILE__, __LINE__, (uintmax_t)pthread_self(), rwl); \
    int retl = pthread_rwlock_rdlock(rwl); \
    printf("%16s(%s:%d): (thread:%"PRIuMAX") locked rwlock %p ret %" PRId32 "\n", __FUNCTION__, __FILE__, __LINE__, (uintmax_t)pthread_self(), rwl, retl); \
    if (retl != 0) { \
        switch (retl) { \
            case EINVAL: \
            printf("The value specified by attr is invalid\n"); \
            retl = pthread_rwlock_init(rwl, NULL); \
            if (retl != 0) \
                exit(EXIT_FAILURE); \
            retl = pthread_rwlock_rdlock(rwl); \
            break; \
            case EDEADLK: \
            printf("A deadlock would occur if the thread blocked waiting for rwlock\n"); \
            break; \
        } \
    } \
    retl; \
})

#define SCRWLockWRLock_dbg(rwl) ({ \
    printf("%16s(%s:%d): (thread:%"PRIuMAX") locking rwlock %p\n", __FUNCTION__, __FILE__, __LINE__, (uintmax_t)pthread_self(), rwl); \
    int retl = pthread_rwlock_wrlock(rwl); \
    printf("%16s(%s:%d): (thread:%"PRIuMAX") locked rwlock %p ret %" PRId32 "\n", __FUNCTION__, __FILE__, __LINE__, (uintmax_t)pthread_self(), rwl, retl); \
    if (retl != 0) { \
        switch (retl) { \
            case EINVAL: \
            printf("The value specified by attr is invalid\n"); \
            retl = pthread_rwlock_init(rwl, NULL); \
            if (retl != 0) \
                exit(EXIT_FAILURE); \
            retl = pthread_rwlock_wrlock(rwl); \
            break; \
            case EDEADLK: \
            printf("A deadlock would occur if the thread blocked waiting for rwlock\n"); \
            break; \
        } \
    } \
    retl; \
})


#define SCRWLockTryWRLock_dbg(rwl) ({ \
    printf("%16s(%s:%d): (thread:%"PRIuMAX") trylocking rwlock %p\n", __FUNCTION__, __FILE__, __LINE__, (uintmax_t)pthread_self(), rwl); \
    int rett = pthread_rwlock_trywrlock(rwl); \
    printf("%16s(%s:%d): (thread:%"PRIuMAX") trylocked rwlock %p ret %" PRId32 "\n", __FUNCTION__, __FILE__, __LINE__, (uintmax_t)pthread_self(), rwl, rett); \
    if (rett != 0) { \
        switch (rett) { \
            case EINVAL: \
            printf("%16s(%s:%d): The value specified by attr is invalid\n", __FUNCTION__, __FILE__, __LINE__); \
            break; \
            case EBUSY: \
            printf("RWLock is already locked\n"); \
            break; \
        } \
    } \
    rett; \
})

#define SCRWLockTryRDLock_dbg(rwl) ({ \
    printf("%16s(%s:%d): (thread:%"PRIuMAX") trylocking rwlock %p\n", __FUNCTION__, __FILE__, __LINE__, (uintmax_t)pthread_self(), rwl); \
    int rett = pthread_rwlock_tryrdlock(rwl); \
    printf("%16s(%s:%d): (thread:%"PRIuMAX") trylocked rwlock %p ret %" PRId32 "\n", __FUNCTION__, __FILE__, __LINE__, (uintmax_t)pthread_self(), rwl, rett); \
    if (rett != 0) { \
        switch (rett) { \
            case EINVAL: \
            printf("%16s(%s:%d): The value specified by attr is invalid\n", __FUNCTION__, __FILE__, __LINE__); \
            break; \
            case EBUSY: \
            printf("RWLock is already locked\n"); \
            break; \
        } \
    } \
    rett; \
})

#define SCRWLockInit_dbg(rwl, rwlattr) ({ \
    int ret; \
    ret = pthread_rwlock_init(rwl, rwlattr); \
    if (ret != 0) { \
        switch (ret) { \
            case EINVAL: \
            printf("The value specified by attr is invalid\n"); \
            printf("%16s(%s:%d): (thread:%"PRIuMAX") rwlock %p initialization returned %" PRId32 "\n", __FUNCTION__, __FILE__, __LINE__, (uintmax_t)pthread_self(), rwl, ret); \
            break; \
            case EAGAIN: \
            printf("The system temporarily lacks the resources to create another rwlock\n"); \
            printf("%16s(%s:%d): (thread:%"PRIuMAX") rwlock %p initialization returned %" PRId32 "\n", __FUNCTION__, __FILE__, __LINE__, (uintmax_t)pthread_self(), rwl, ret); \
            break; \
            case ENOMEM: \
            printf("The process cannot allocate enough memory to create another rwlock\n"); \
            printf("%16s(%s:%d): (thread:%"PRIuMAX") rwlock %p initialization returned %" PRId32 "\n", __FUNCTION__, __FILE__, __LINE__, (uintmax_t)pthread_self(), rwl, ret); \
            break; \
        } \
    } \
    ret; \
})

#define SCRWLockUnlock_dbg(rwl) ({ \
    printf("%16s(%s:%d): (thread:%"PRIuMAX") unlocking rwlock %p\n", __FUNCTION__, __FILE__, __LINE__, (uintmax_t)pthread_self(), rwl); \
    int retu = pthread_rwlock_unlock(rwl); \
    printf("%16s(%s:%d): (thread:%"PRIuMAX") unlocked rwlock %p ret %" PRId32 "\n", __FUNCTION__, __FILE__, __LINE__, (uintmax_t)pthread_self(), rwl, retu); \
    if (retu != 0) { \
        switch (retu) { \
            case EINVAL: \
            printf("%16s(%s:%d): The value specified by attr is invalid\n", __FUNCTION__, __FILE__, __LINE__); \
            break; \
            case EPERM: \
            printf("The current thread does not hold a lock on rwlock\n"); \
            break; \
        } \
    } \
    retu; \
})

#define SCRWLock pthread_rwlock_t
#define SCRWLockInit(rwl, rwlattrs) SCRWLockInit_dbg(rwl, rwlattrs)
#define SCRWLockRDLock(rwl) SCRWLockRDLock_dbg(rwl)
#define SCRWLockWRLock(rwl) SCRWLockWRLock_dbg(rwl)
#define SCRWLockTryWRLock(rwl) SCRWLockTryWRLock_dbg(rwl)
#define SCRWLockTryRDLock(rwl) SCRWLockTryRDLock_dbg(rwl)
#define SCRWLockUnlock(rwl) SCRWLockUnlock_dbg(rwl)
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
