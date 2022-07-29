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
 * \file
 *
 * \author Victor Julien <victor@inliniac.net>
 * \author Pablo Rincon Crespo <pablo.rincon.crespo@gmail.com>
 *
 * This file now only contains unit tests see macros in threads.h
 */

#include "suricata-common.h"
#include "util-unittest.h"
#include "threads.h"

thread_local char t_thread_name[THREAD_NAME_LEN + 1];
#ifdef UNITTESTS /* UNIT TESTS */

/**
 * \brief Test Mutex macros
 */
static int ThreadMacrosTest01Mutex(void)
{
    SCMutex mut;
    int r = 0;
    r |= SCMutexInit(&mut, NULL);
    r |= SCMutexLock(&mut);
    r |= (SCMutexTrylock(&mut) == EBUSY)? 0 : 1;
    r |= SCMutexUnlock(&mut);
    r |= SCMutexDestroy(&mut);

    return (r == 0)? 1 : 0;
}

/**
 * \brief Test Spinlock Macros
 *
 * Valgrind's DRD tool (valgrind-3.5.0-Debian) reports:
 *
 * ==31156== Recursive locking not allowed: mutex 0x7fefff97c, recursion count 1, owner 1.
 * ==31156==    at 0x4C2C77E: pthread_spin_trylock (drd_pthread_intercepts.c:829)
 * ==31156==    by 0x40EB3E: ThreadMacrosTest02Spinlocks (threads.c:40)
 * ==31156==    by 0x532E8A: UtRunTests (util-unittest.c:182)
 * ==31156==    by 0x4065C3: main (suricata.c:789)
 *
 * To me this is a false positve, as the whole point of "trylock" is to see
 * if a spinlock is actually locked.
 *
 */
static int ThreadMacrosTest02Spinlocks(void)
{
    SCSpinlock mut;
    int r = 0;
    r |= SCSpinInit(&mut, 0);
    r |= SCSpinLock(&mut);
#ifndef __OpenBSD__
    r |= (SCSpinTrylock(&mut) == EBUSY)? 0 : 1;
#else
    r |= (SCSpinTrylock(&mut) == EDEADLK)? 0 : 1;
#endif
    r |= SCSpinUnlock(&mut);
    r |= SCSpinDestroy(&mut);

    return (r == 0)? 1 : 0;
}

/**
 * \brief Test RWLock macros
 */
static int ThreadMacrosTest03RWLocks(void)
{
    SCRWLock rwl_write;
    int r = 0;
    r |= SCRWLockInit(&rwl_write, NULL);
    r |= SCRWLockWRLock(&rwl_write);
/* OS X/macOS 10.10 (Yosemite) and newer return EDEADLK. Older versions
 * and other tested OS's return EBUSY. */
#if __ENVIRONMENT_MAC_OS_X_VERSION_MIN_REQUIRED__>=101000
    r |= (SCRWLockTryWRLock(&rwl_write) == EDEADLK)? 0 : 1;
#else
    r |= (SCRWLockTryWRLock(&rwl_write) == EBUSY)? 0 : 1;
#endif
    r |= SCRWLockUnlock(&rwl_write);
    r |= SCRWLockDestroy(&rwl_write);

    return (r == 0)? 1 : 0;
}

/**
 * \brief Test RWLock macros
 */
static int ThreadMacrosTest04RWLocks(void)
{
    SCRWLock rwl_read;
    int r = 0;
    r |= SCRWLockInit(&rwl_read, NULL);
    r |= SCRWLockRDLock(&rwl_read);
    r |= (SCRWLockTryWRLock(&rwl_read) == EBUSY)? 0 : 1;
    r |= SCRWLockUnlock(&rwl_read);
    r |= SCRWLockDestroy(&rwl_read);

    return (r == 0)? 1 : 0;
}

#if 0 // broken on OSX
/**
 * \brief Test RWLock macros
 */
static int ThreadMacrosTest05RWLocks(void)
{
    SCRWLock rwl_read;
    int r = 0;
    r |= SCRWLockInit(&rwl_read, NULL);
    r |= SCRWLockWRLock(&rwl_read);
    r |= (SCRWLockTryRDLock(&rwl_read) == EBUSY)? 0 : 1;
    r |= SCRWLockUnlock(&rwl_read);
    r |= SCRWLockDestroy(&rwl_read);

    return (r == 0)? 1 : 0;
}
#endif

#endif /* UNIT TESTS */

/**
 * \brief this function registers unit tests for DetectId
 */
void ThreadMacrosRegisterTests(void)
{
#ifdef UNITTESTS /* UNIT TESTS */
    UtRegisterTest("ThreadMacrosTest01Mutex", ThreadMacrosTest01Mutex);
    UtRegisterTest("ThreadMacrosTest02Spinlocks", ThreadMacrosTest02Spinlocks);
    UtRegisterTest("ThreadMacrosTest03RWLocks", ThreadMacrosTest03RWLocks);
    UtRegisterTest("ThreadMacrosTest04RWLocks", ThreadMacrosTest04RWLocks);
//    UtRegisterTest("ThreadMacrosTest05RWLocks", ThreadMacrosTest05RWLocks);
#endif /* UNIT TESTS */
}
