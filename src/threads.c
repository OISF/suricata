/**
 * Copyright (c) 2009 Open Information Security Foundation
 *
 * \author Victor Julien <victor@inliniac.net>
 * \author Pablo Rincon Crespo <pablo.rincon.crespo@gmail.com>
 */

#include "eidps-common.h"
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
    sc_mutex_t mut;
    int r = 0;
    r |= sc_mutex_init(&mut, NULL);
    r |= sc_mutex_lock(&mut);
    r |= (sc_mutex_trylock(&mut) == EBUSY)? 0 : 1;
    r |= sc_mutex_unlock(&mut);
    r |= sc_mutex_destroy(&mut);

    return (r == 0)? 1 : 0;
}

/**
 * \brief Test Spin Macros
 */
int ThreadMacrosTest02Spinlocks(void) {
    sc_spin_t mut;
    int r = 0;
    r |= sc_spin_init(&mut, 0);
    r |= sc_spin_lock(&mut);
    r |= (sc_spin_trylock(&mut) == EBUSY)? 0 : 1;
    r |= sc_spin_unlock(&mut);
    r |= sc_spin_destroy(&mut);

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
