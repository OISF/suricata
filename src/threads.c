/* Copyright (c) 2008 Victor Julien <victor@inliniac.net> */

#include "decode.h"

#ifdef DBG_THREADS
#include <pthread.h>

int mutex_lock_dbg (pthread_mutex_t *m) {
    int ret;

    printf("%16s: (%p) locking mutex %p\n", __FUNCTION__, pthread_self(), m);
    ret = pthread_mutex_lock(m);
    printf("%16s: (%p) locked mutex %p ret %" PRId32 "\n", __FUNCTION__, pthread_self(), m, ret);
    return(ret);
}

int mutex_trylock_dbg (pthread_mutex_t *m) {
    int ret;

    printf("%16s: (%p) trylocking mutex %p\n", __FUNCTION__, pthread_self(), m);
    ret = pthread_mutex_trylock(m);
    printf("%16s: (%p) trylocked mutex %p ret %" PRId32 "\n", __FUNCTION__, pthread_self(), m, ret);
    return(ret);
}

int mutex_unlock_dbg (pthread_mutex_t *m) {
    int ret;

    printf("%16s: (%p) unlocking mutex %p\n", __FUNCTION__, pthread_self(), m);
    ret = pthread_mutex_unlock(m);
    printf("%16s: (%p) unlocked mutex %p ret %" PRId32 "\n", __FUNCTION__, pthread_self(), m, ret);
    return(ret);
}

#endif /* DBG_THREADS */

