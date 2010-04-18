/**
 * Copyright (c) 2009 Open Information Security Foundation
 *
 * \author Victor Julien <victor@inliniac.net>
 * \author Pablo Rincon Crespo <pablo.rincon.crespo@gmail.com>
 */

#ifndef __THREADS_H__
#define __THREADS_H__

#ifdef OS_FREEBSD

#include <sys/thr.h>
#define PRIO_LOW 2
#define PRIO_MEDIUM 0
#define PRIO_HIGH -2

#elif OS_DARWIN

#include <mach/mach_init.h>
#define PRIO_LOW 2
#define PRIO_MEDIUM 0
#define PRIO_HIGH -2

#elif OS_WIN32

#define PRIO_LOW THREAD_PRIORITY_LOWEST
#define PRIO_MEDIUM THREAD_PRIORITY_NORMAL
#define PRIO_HIGH THREAD_PRIORITY_HIGHEST

#else /* LINUX */

#if HAVE_SYS_SYSCALL_H
#include <sys/syscall.h>
#endif
#if HAVE_SYS_PRCTL_H
#include <sys/prctl.h>
#define THREAD_NAME_LEN 16
#endif

#define PRIO_LOW 2
#define PRIO_MEDIUM  0
#define PRIO_HIGH -2

#endif /* OS_FREEBSD */

#include <pthread.h>

/** The mutex/spinlock/condition definitions and functions are used
 * in the same way as the POSIX definitionsr; Anyway we are centralizing
 * them here to make an easier portability process and debugging process;
 * Please, make sure you initialize mutex and spinlocks before using them
 * because, some OS doesn't initialize them for you :)
 */

//#define DBG_THREADS

/** Suricata Mutex */
#define SCMutex pthread_mutex_t
#define SCMutexAttr pthread_mutexattr_t
#define SCMutexDestroy pthread_mutex_destroy

/** Get the Current Thread Id */
#ifdef OS_FREEBSD
#define SCGetThreadIdLong(...) ({ \
    long tmpthid; \
    thr_self(&tmpthid); \
    u_long tid = (u_long)tmpthid; \
    tid; \
})
#elif OS_WIN32
#define SCGetThreadIdLong(...) ({ \
    u_long tid = (u_long)GetCurrentThreadId(); \
	tid; \
})
#elif OS_DARWIN
#define SCGetThreadIdLong(...) ({ \
    thread_port_t tpid; \
    tpid = mach_thread_self(); \
    u_long tid = (u_long)tpid; \
    tid; \
})
#else
#define SCGetThreadIdLong(...) ({ \
   pid_t tmpthid; \
   tmpthid = syscall(SYS_gettid); \
   u_long tid = (u_long)tmpthid; \
   tid; \
})
#endif /* OS FREEBSD */

/** Mutex Functions */
#ifdef DBG_THREADS
/** When dbg threads is defined, if a mutex fail to lock, it's
 * initialized, logged, and does a second try; This is to prevent the system to freeze;
 * It is for Mac OS X users;
 * If you see a mutex, spinlock or condiion not initialized, report it please!
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

#define SCMutexInit(mut, mutattrs) SCMutexInit_dbg(mut, mutattrs)
#define SCMutexLock(mut) SCMutexLock_dbg(mut)
#define SCMutexTrylock(mut) SCMutexTrylock_dbg(mut)
#define SCMutexUnlock(mut) SCMutexUnlock_dbg(mut)
#else
#define SCMutexInit(mut, mutattr ) pthread_mutex_init(mut, mutattr)
#define SCMutexLock(mut) pthread_mutex_lock(mut)
#define SCMutexTrylock(mut) pthread_mutex_trylock(mut)
#define SCMutexUnlock(mut) pthread_mutex_unlock(mut)
#endif

/** Conditions/Signals */
/* Here we don't need to do nothing atm */
#define SCCondT pthread_cond_t
#define SCCondInit pthread_cond_init
#define SCCondSignal pthread_cond_signal
#define SCCondTimedwait pthread_cond_timedwait
#define SCCondDestroy pthread_cond_destroy

#ifdef DBG_THREAD
#define SCondWait_dbg(cond, mut) ({ \
    int ret = pthread_cond_wait(cond, mut); \
    switch (ret) { \
        case EINVAL: \
        printf("The value specified by attr is invalid (or a SCCondT not initialized!)\n"); \
        printf("%16s(%s:%d): (thread:%"PRIuMAX") failed SCondWait %p ret %" PRId32 "\n", __FUNCTION__, __FILE__, __LINE__, (uintmax_t)pthread_self(), mut, retu); \
        break; \
    } \
    ret; \
})
#define SCondWait SCondWait_dbg
#else
#define SCondWait(cond, mut) pthread_cond_wait(cond, mut)
#endif

/** Spinlocks */
#define SCSpinlock               pthread_spinlock_t

/** If posix spin not supported, use mutex */
#if ((_POSIX_SPIN_LOCKS - 200112L) < 0L)
#define pthread_spinlock_t                        pthread_mutex_t
#define pthread_spin_init(target,arg)             SCMutexInit(target, NULL)
#define pthread_spin_lock(spin)                   SCMutexLock(spin)
#define pthread_spin_trylock(spin)                SCMutexTrylock(spin)
#define pthread_spin_unlock(spin)                 SCMutexUnlock(spin)
#define pthread_spin_destroy(spin)                SCMutexDestroy(spin)
#endif /* End Spin not supported */

#ifdef DBG_THREADS
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

#define SCSpinLock                              SCSpinLock_dbg
#define SCSpinTrylock                           SCSpinTrylock_dbg
#define SCSpinUnlock                            SCSpinUnlock_dbg
#define SCSpinInit                              SCSpinInit_dbg
#define SCSpinDestroy                           SCSpinDestroy_dbg
#else /* if no dbg threads defined... */
#define SCSpinLock(spin)                        pthread_spin_lock(spin)
#define SCSpinTrylock(spin)                     pthread_spin_trylock(spin)
#define SCSpinUnlock(spin)                      pthread_spin_unlock(spin)
#define SCSpinInit(spin, spin_attr)             pthread_spin_init(spin, spin_attr)
#define SCSpinDestroy(spin)                     pthread_spin_destroy(spin)
#endif /* DBG_THREADS */

/*
 * OS specific macro's for setting the thread name. "top" can display
 * this name.
 */
#ifdef OS_FREEBSD /* FreeBSD */
/** \todo Add implementation for FreeBSD */
#define SCSetThreadName(n)
#elif OS_WIN32 /* Windows */
/** \todo Add implementation for Windows */
#define SCSetThreadName(n)
#elif OS_DARWIN /* Mac OS X */
/** \todo Add implementation for MacOS */
#define SCSetThreadName(n)
#else /* Linux */
/**
 * \brief Set the threads name
 */
#define SCSetThreadName(n) ({ \
    char tname[THREAD_NAME_LEN + 1] = ""; \
    if (strlen(n) > THREAD_NAME_LEN) \
        SCLogDebug("Thread name is too long, truncating it..."); \
    strlcpy(tname, n, THREAD_NAME_LEN); \
    int ret = 0; \
    if ((ret = prctl(PR_SET_NAME, tname, 0, 0, 0)) < 0) \
        SCLogDebug("Error setting thread name \"%s\": %s", tname, strerror(errno)); \
    ret; \
})
#endif

void ThreadMacrosRegisterTests(void);

#endif /* __THREADS_H__ */

