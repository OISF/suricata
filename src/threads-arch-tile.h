/* Copyright (C) 2011-2013 Open Information Security Foundation
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
 * \author Ken Steele, Tilera Corporation <suricata@tilera.com>
 */

#ifndef __THREADS_ARCH_TILE_H__
#define __THREADS_ARCH_TILE_H__

#include <tmc/spin.h>
#include <arch/cycle.h>

/* NOTE: On Tilera datapath threads use the TMC (Tilera Multicore
 * Components) library spin mutexes while the control threads use
 * pthread mutexes.  So the pthread mutex types are split out so that
 * their use can be differentiated.
 */

/* ctrl mutex */
#define SCCtrlMutex pthread_mutex_t
#define SCCtrlMutexAttr pthread_mutexattr_t
#define SCCtrlMutexInit(mut, mutattr ) pthread_mutex_init(mut, mutattr)
#define SCCtrlMutexLock(mut) pthread_mutex_lock(mut)
#define SCCtrlMutexTrylock(mut) pthread_mutex_trylock(mut)
#define SCCtrlMutexUnlock(mut) pthread_mutex_unlock(mut)
#define SCCtrlMutexDestroy pthread_mutex_destroy

/* ctrl cond */
#define SCCtrlCondT pthread_cond_t
#define SCCtrlCondInit pthread_cond_init
#define SCCtrlCondSignal pthread_cond_signal
#define SCCtrlCondTimedwait pthread_cond_timedwait
#define SCCtrlCondWait pthread_cond_wait
#define SCCtrlCondDestroy pthread_cond_destroy

/* mutex */

#define SCMutex tmc_spin_queued_mutex_t
#define SCMutexAttr
#define SCMutexDestroy(x) ({ (void)(x); 0; })
#define SCMUTEX_INITIALIZER TMC_SPIN_QUEUED_MUTEX_INIT
#define SCMutexInit(mut, mutattr) ({ \
    int ret = 0; \
    tmc_spin_queued_mutex_init(mut); \
    ret; \
})
#define SCMutexLock(mut) ({ \
    int ret = 0; \
    tmc_spin_queued_mutex_lock(mut); \
    ret; \
})
#define SCMutexTrylock(mut) ({ \
    int ret = (tmc_spin_queued_mutex_trylock(mut) == 0) ? 0 : EBUSY; \
    ret; \
})
#define SCMutexUnlock(mut) ({ \
    int ret = 0; \
    tmc_spin_queued_mutex_unlock(mut); \
    ret; \
})

/* conditions */

/* Ignore signals when using spin locks */
#define SCCondT uint8_t
#define SCCondInit(x,y) ({ 0; })
#define SCCondSignal(x) ({ 0; })
#define SCCondDestroy(x) ({ 0; })

static inline void cycle_sleep(int cycles)
{
  uint64_t end = get_cycle_count() + cycles;
  while (get_cycle_count() < end)
    ;
}
#define SCCondWait(x,y) cycle_sleep(300)

/* spinlocks */

#define SCSpinlock                              tmc_spin_queued_mutex_t
#define SCSpinLock(spin)                        ({ tmc_spin_queued_mutex_lock(spin); 0; })
#define SCSpinTrylock(spin)                     (tmc_spin_queued_mutex_trylock(spin) ? EBUSY : 0)
#define SCSpinUnlock(spin)                      ({ tmc_spin_queued_mutex_unlock(spin); 0; })
#define SCSpinInit(spin, spin_attr)             ({ tmc_spin_queued_mutex_init(spin); 0; })
#define SCSpinDestroy(spin)                     ({ (void)(spin); 0; })

/* rwlocks */

#define SCRWLock tmc_spin_rwlock_t
#define SCRWLockDestroy(x) ({ (void)(x); 0; })
#define SCRWLockInit(rwl, rwlattr ) ({ tmc_spin_rwlock_init(rwl); 0; })
#define SCRWLockWRLock(rwl) ({ tmc_spin_rwlock_wrlock(rwl); 0; })
#define SCRWLockRDLock(rwl) ({ tmc_spin_rwlock_rdlock(rwl); 0; })
#define SCRWLockTryWRLock(rwl) (tmc_spin_rwlock_trywrlock(rwl) ? EBUSY : 0)
#define SCRWLockTryRDLock(rwl) (tmc_spin_rwlock_tryrdlock(rwl) ? EBUSY : 0)
#define SCRWLockUnlock(rwl) ({ tmc_spin_rwlock_unlock(rwl); 0; })
#endif
