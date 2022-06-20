/* Copyright (C) 2007-2020 Open Information Security Foundation
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
 * Threading functions defined as macros
 */

#ifndef __THREADS_H__
#define __THREADS_H__

#ifndef THREAD_NAME_LEN
#define THREAD_NAME_LEN 16
#endif

#if defined(TLS_C11)
#define thread_local _Thread_local
#elif defined(TLS_GNU)
#define thread_local __thread
#else
#error "No supported thread local type found"
#endif

/* need this for the _POSIX_SPIN_LOCKS define */
#if HAVE_UNISTD_H
#include <unistd.h>
#endif

#ifdef PROFILING
#ifdef PROFILE_LOCKING
#endif /* PROFILE_LOCKING */
#endif /* PROFILING */

#if defined OS_FREEBSD || __OpenBSD__

#if ! defined __OpenBSD__
#include <sys/thr.h>
#endif
enum {
    PRIO_LOW = 2,
    PRIO_MEDIUM = 0,
    PRIO_HIGH = -2,
};

#elif OS_DARWIN

#include <mach/mach_init.h>
enum {
    PRIO_LOW = 2,
    PRIO_MEDIUM = 0,
    PRIO_HIGH = -2,
};

#elif OS_WIN32

#include <windows.h>
enum {
    PRIO_LOW = THREAD_PRIORITY_LOWEST,
    PRIO_MEDIUM = THREAD_PRIORITY_NORMAL,
    PRIO_HIGH = THREAD_PRIORITY_HIGHEST,
};

#else /* LINUX */

#if HAVE_SYS_SYSCALL_H
#include <sys/syscall.h>
#endif
#if HAVE_SYS_PRCTL_H
#include <sys/prctl.h>
#endif

enum {
    PRIO_LOW = 2,
    PRIO_MEDIUM = 0,
    PRIO_HIGH = -2,
};

#endif /* OS_FREEBSD */

#include <pthread.h>

/* The mutex/spinlock/condition definitions and functions are used
 * in the same way as the POSIX definitions; Anyway we are centralizing
 * them here to make an easier portability process and debugging process;
 * Please, make sure you initialize mutex and spinlocks before using them
 * because, some OS doesn't initialize them for you :)
 */

//#define DBG_THREADS

#if defined DBG_THREADS
    #ifdef PROFILE_LOCKING
        #error "Cannot mix DBG_THREADS and PROFILE_LOCKING"
    #endif
#elif defined PROFILE_LOCKING
#else /* normal */

/* mutex */
#define SCMutex pthread_mutex_t
#define SCMutexAttr pthread_mutexattr_t
#define SCMutexInit(mut, mutattr ) pthread_mutex_init(mut, mutattr)
#define SCMutexLock(mut) pthread_mutex_lock(mut)
#define SCMutexTrylock(mut) pthread_mutex_trylock(mut)
#define SCMutexUnlock(mut) pthread_mutex_unlock(mut)
#define SCMutexDestroy pthread_mutex_destroy
#define SCMUTEX_INITIALIZER PTHREAD_MUTEX_INITIALIZER

/* rwlocks */
#define SCRWLock pthread_rwlock_t
#define SCRWLockInit(rwl, rwlattr ) pthread_rwlock_init(rwl, rwlattr)
#define SCRWLockWRLock(rwl) pthread_rwlock_wrlock(rwl)
#define SCRWLockRDLock(rwl) pthread_rwlock_rdlock(rwl)
#define SCRWLockTryWRLock(rwl) pthread_rwlock_trywrlock(rwl)
#define SCRWLockTryRDLock(rwl) pthread_rwlock_tryrdlock(rwl)
#define SCRWLockUnlock(rwl) pthread_rwlock_unlock(rwl)
#define SCRWLockDestroy pthread_rwlock_destroy

/* conditions */
#define SCCondT pthread_cond_t
#define SCCondInit pthread_cond_init
#define SCCondSignal pthread_cond_signal
#define SCCondDestroy pthread_cond_destroy
#define SCCondWait(cond, mut) pthread_cond_wait(cond, mut)

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

/* spinlocks */
#if ((_POSIX_SPIN_LOCKS - 200112L) < 0L) || defined HELGRIND || !defined(HAVE_PTHREAD_SPIN_UNLOCK)
#define SCSpinlock                              SCMutex
#define SCSpinLock(spin)                        SCMutexLock((spin))
#define SCSpinTrylock(spin)                     SCMutexTrylock((spin))
#define SCSpinUnlock(spin)                      SCMutexUnlock((spin))
#define SCSpinInit(spin, spin_attr)             SCMutexInit((spin), NULL)
#define SCSpinDestroy(spin)                     SCMutexDestroy((spin))
#else /* no spinlocks */
#define SCSpinlock                              pthread_spinlock_t
#define SCSpinLock(spin)                        pthread_spin_lock(spin)
#define SCSpinTrylock(spin)                     pthread_spin_trylock(spin)
#define SCSpinUnlock(spin)                      pthread_spin_unlock(spin)
#define SCSpinInit(spin, spin_attr)             pthread_spin_init(spin, spin_attr)
#define SCSpinDestroy(spin)                     pthread_spin_destroy(spin)
#endif /* no spinlocks */

#endif

#if (!defined SCMutex       || !defined SCMutexAttr     || !defined SCMutexInit || \
     !defined SCMutexLock   || !defined SCMutexTrylock  || \
     !defined SCMutexUnlock || !defined SCMutexDestroy  || \
     !defined SCMUTEX_INITIALIZER)
#error "Mutex types and/or macro's not properly defined"
#endif
#if (!defined SCCtrlMutex       || !defined SCCtrlMutexAttr     || !defined SCCtrlMutexInit || \
     !defined SCCtrlMutexLock   || !defined SCCtrlMutexTrylock  || \
     !defined SCCtrlMutexUnlock || !defined SCCtrlMutexDestroy)
#error "SCCtrlMutex types and/or macro's not properly defined"
#endif

#if (!defined SCSpinlock    || !defined SCSpinLock      || \
     !defined SCSpinTrylock || !defined SCSpinUnlock    || \
     !defined SCSpinInit    || !defined SCSpinDestroy)
#error "Spinlock types and/or macro's not properly defined"
#endif

#if (!defined SCRWLock || !defined SCRWLockInit || !defined SCRWLockWRLock || \
     !defined SCRWLockRDLock || !defined SCRWLockTryWRLock || \
     !defined SCRWLockTryRDLock || !defined SCRWLockUnlock || !defined SCRWLockDestroy)
#error "SCRWLock types and/or macro's not properly defined"
#endif

#if (!defined SCCondT || !defined SCCondInit || !defined SCCondSignal || \
     !defined SCCondDestroy || !defined SCCondWait)
#error "SCCond types and/or macro's not properly defined"
#endif

#if (!defined SCCtrlCondT || !defined SCCtrlCondInit || !defined SCCtrlCondSignal ||\
     !defined SCCtrlCondDestroy || !defined SCCtrlCondTimedwait)
#error "SCCtrlCond types and/or macro's not properly defined"
#endif

/** Get the Current Thread Id */
#ifdef OS_FREEBSD
#include <pthread_np.h>

#define SCGetThreadIdLong(...) ({ \
    long tmpthid; \
    thr_self(&tmpthid); \
    unsigned long _scgetthread_tid = (unsigned long)tmpthid; \
    _scgetthread_tid; \
})
#elif __OpenBSD__
#define SCGetThreadIdLong(...) ({ \
    pid_t tpid; \
    tpid = getpid(); \
    unsigned long _scgetthread_tid = (unsigned long)tpid; \
    _scgetthread_tid; \
})
#elif __CYGWIN__
#define SCGetThreadIdLong(...) ({ \
    unsigned long _scgetthread_tid = (unsigned long)GetCurrentThreadId(); \
	_scgetthread_tid; \
})
#elif OS_WIN32
#define SCGetThreadIdLong(...) ({ \
    unsigned long _scgetthread_tid = (unsigned long)GetCurrentThreadId(); \
	_scgetthread_tid; \
})
#elif OS_DARWIN
#define SCGetThreadIdLong(...) ({ \
    thread_port_t tpid; \
    tpid = mach_thread_self(); \
    unsigned long _scgetthread_tid = (unsigned long)tpid; \
    _scgetthread_tid; \
})
#elif defined(sun)
#include <thread.h>
#define SCGetThreadIdLong(...) ({ \
    thread_t tmpthid = thr_self(); \
    unsigned long _scgetthread_tid = (unsigned long)tmpthid; \
    _scgetthread_tid; \
})

#else
#define SCGetThreadIdLong(...) ({ \
   pid_t tmpthid; \
   tmpthid = syscall(SYS_gettid); \
   unsigned long _scgetthread_tid = (unsigned long)tmpthid; \
   _scgetthread_tid; \
})
#endif /* OS FREEBSD */

extern thread_local char t_thread_name[THREAD_NAME_LEN + 1];
/*
 * OS specific macro's for setting the thread name. "top" can display
 * this name.
 */
#if defined OS_FREEBSD /* FreeBSD */
/** \todo Add implementation for FreeBSD */
#define SCSetThreadName(n)                                                                         \
    ({                                                                                             \
        char tname[THREAD_NAME_LEN] = "";                                                          \
        if (strlen(n) > THREAD_NAME_LEN)                                                           \
            SCLogDebug("Thread name is too long, truncating it...");                               \
        strlcpy(tname, n, THREAD_NAME_LEN);                                                        \
        strlcpy(t_thread_name, n, sizeof(t_thread_name));                                          \
        pthread_set_name_np(pthread_self(), tname);                                                \
    })
#elif defined __OpenBSD__ /* OpenBSD */
/** \todo Add implementation for OpenBSD */
#define SCSetThreadName(n) ({ strlcpy(t_thread_name, n, sizeof(t_thread_name)); })
#elif defined OS_WIN32 /* Windows */
/** \todo Add implementation for Windows */
#define SCSetThreadName(n) ({ strlcpy(t_thread_name, n, sizeof(t_thread_name)); })
#elif defined OS_DARWIN /* Mac OS X */
/** \todo Add implementation for MacOS */
#define SCSetThreadName(n) ({ strlcpy(t_thread_name, n, sizeof(t_thread_name)); })
#elif defined PR_SET_NAME /* PR_SET_NAME */
/**
 * \brief Set the threads name
 */
#define SCSetThreadName(n)                                                                         \
    ({                                                                                             \
        char tname[THREAD_NAME_LEN + 1] = "";                                                      \
        if (strlen(n) > THREAD_NAME_LEN)                                                           \
            SCLogDebug("Thread name is too long, truncating it...");                               \
        strlcpy(tname, n, THREAD_NAME_LEN);                                                        \
        strlcpy(t_thread_name, n, sizeof(t_thread_name));                                          \
        if (prctl(PR_SET_NAME, tname, 0, 0, 0) < 0)                                                \
            SCLogDebug("Error setting thread name \"%s\": %s", tname, strerror(errno));            \
    })
#else
#define SCSetThreadName(n) ({ \
    strlcpy(t_thread_name, n, sizeof(t_thread_name)); \
}
#endif


void ThreadMacrosRegisterTests(void);

#endif /* __THREADS_H__ */

