/**
 * Copyright (c) 2009 Open Information Security Foundation
 *
 * \author Victor Julien <victor@inliniac.net>
 * \author Pablo Rincon Crespo <pablo.rincon.crespo@gmail.com>
 */

#include "suricata-common.h"
#include "util-unittest.h"
#include "debug.h"
#include "util-debug.h"
#include "util-unittest.h"
#include "threads.h"

#ifdef UNITTESTS /* UNIT TESTS */

/**
 * \brief Test Mutex macros
 */
int ThreadMacrosTest01Mutex(void) {
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
 * \brief Test Spin Macros
 */
int ThreadMacrosTest02Spinlocks(void) {
    SCSpinlock mut;
    int r = 0;
    r |= SCSpinInit(&mut, 0);
    r |= SCSpinLock(&mut);
    r |= (SCSpinTrylock(&mut) == EBUSY)? 0 : 1;
    r |= SCSpinUnlock(&mut);
    r |= SCSpinDestroy(&mut);

    return (r == 0)? 1 : 0;
}

#endif /* UNIT TESTS */

/**
 * \brief this function registers unit tests for DetectId
 */
void ThreadMacrosRegisterTests(void)
{
#ifdef UNITTESTS /* UNIT TESTS */
    UtRegisterTest("ThreadMacrosTest01Mutex", ThreadMacrosTest01Mutex, 1);
    UtRegisterTest("ThreadMacrossTest02Spinlocks", ThreadMacrosTest02Spinlocks, 1);
#endif /* UNIT TESTS */
}
