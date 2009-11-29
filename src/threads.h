/**
 * Copyright (c) 2009 Open Information Security Foundation
 *
 * \author Victor Julien <victor@inliniac.net>
 * \author Pablo Rincon Crespo <pablo.rincon.crespo@gmail.com>
 */

#ifndef __THREADS_H__
#define __THREADS_H__

#include <pthread.h>

/** The mutex/spinlock/condition definitions and functions are used
 * in the same way as the POSIX definitionsr; Anyway we are centralizing
 * them here to make an easier portability process and debugging process;
 * Please, make sure you initialize mutex and spinlocks before using them
 * because, some OS doesn't initialize them for you :)
 */

//#define DBG_THREADS

/** Suricata Mutex */
#define sc_mutex_t pthread_mutex_t
#define sc_mutexattr_t pthread_mutexattr_t
#define sc_mutex_destroy pthread_mutex_destroy

/** Mutex Functions */
#ifdef DBG_THREADS
/** When dbg threads is defined, if a mutex fail to lock, it's
 * initialized, logged, and does a second try; This is to prevent the system to freeze;
 * It is for Mac OS X users;
 * If you see a mutex, spinlock or condiion not initialized, report it please!
 */
#define sc_mutex_lock_dbg(mut) ({ \
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

#define sc_mutex_trylock_dbg(mut) ({ \
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

#define sc_mutex_init_dbg(mut, mutattr) ({ \
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

#define sc_mutex_unlock_dbg(mut) ({ \
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

#define sc_mutex_init(mut, mutattrs) sc_mutex_init_dbg(mut, mutattrs)
#define sc_mutex_lock(mut) sc_mutex_lock_dbg(mut)
#define sc_mutex_trylock(mut) sc_mutex_trylock_dbg(mut)
#define sc_mutex_unlock(mut) sc_mutex_unlock_dbg(mut)
#else
#define sc_mutex_init(mut, mutattr ) pthread_mutex_init(mut, mutattr)
#define sc_mutex_lock(mut) pthread_mutex_lock(mut)
#define sc_mutex_trylock(mut) pthread_mutex_trylock(mut)
#define sc_mutex_unlock(mut) pthread_mutex_unlock(mut)
#endif

/** Conditions/Signals */
/* Here we don't need to do nothing atm */
#define sc_cond_t pthread_cond_t
#define sc_cond_init pthread_cond_init
#define sc_cond_signal pthread_cond_signal
#define sc_cond_timedwait pthread_cond_timedwait

#ifdef DBG_THREAD
#define sc_cond_wait_dbg(cond, mut) ({ \
    int ret = pthread_cond_wait(cond, mut); \
    switch (ret) { \
        case EINVAL: \
        printf("The value specified by attr is invalid (or a sc_cond_t not initialized!)\n"); \
        printf("%16s(%s:%d): (thread:%"PRIuMAX") failed sc_cond_wait %p ret %" PRId32 "\n", __FUNCTION__, __FILE__, __LINE__, (uintmax_t)pthread_self(), mut, retu); \
        break; \
    } \
    ret; \
})
#define sc_cond_wait sc_cond_wait_dbg
#else
#define sc_cond_wait(cond, mut) pthread_cond_wait(cond, mut)
#endif

/** Spinlocks */
#define sc_spin_t               pthread_spinlock_t

/** If posix spin not supported, use mutex */
#if ((_POSIX_SPIN_LOCKS - 200112L) < 0L)
#define pthread_spinlock_t                        pthread_mutex_t
#define pthread_spin_init(target,arg)             sc_mutex_init(target, NULL)
#define pthread_spin_lock(spin)                   sc_mutex_lock(spin)
#define pthread_spin_trylock(spin)                sc_mutex_trylock(spin)
#define pthread_spin_unlock(spin)                 sc_mutex_unlock(spin)
#define pthread_spin_destroy(spin)                sc_mutex_destroy(spin)
#endif /* End Spin not supported */

#ifdef DBG_THREADS
#define sc_spin_lock_dbg(spin) ({ \
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

#define sc_spin_trylock_dbg(spin) ({ \
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

#define sc_spin_unlock_dbg(spin) ({ \
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

#define sc_spin_init_dbg(spin, spin_attr) ({ \
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

#define sc_spin_destroy_dbg(spin) ({ \
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

#define sc_spin_lock                              sc_spin_lock_dbg
#define sc_spin_trylock                           sc_spin_trylock_dbg
#define sc_spin_unlock                            sc_spin_unlock_dbg
#define sc_spin_init                              sc_spin_init_dbg
#define sc_spin_destroy                           sc_spin_destroy_dbg
#else /* if no dbg threads defined... */
#define sc_spin_lock(spin)                        pthread_spin_lock(spin)
#define sc_spin_trylock(spin)                     pthread_spin_trylock(spin)
#define sc_spin_unlock(spin)                      pthread_spin_unlock(spin)
#define sc_spin_init(spin, spin_attr)             pthread_spin_init(spin, spin_attr)
#define sc_spin_destroy(spin)                     pthread_spin_destroy(spin)
#endif /* DBG_THREADS */


void ThreadMacrosRegisterTests(void);
#endif /* __THREADS_H__ */

