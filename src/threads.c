/* Copyright (c) 2008 Victor Julien <victor@inliniac.net> */

#include "eidps-common.h"
#include "decode.h"

#ifdef DBG_THREADS

int mutex_lock_dbg (pthread_mutex_t *m) {
    int ret;

    printf("%16s: (%"PRIuMAX") locking mutex %p\n", __FUNCTION__, (uintmax_t)pthread_self(), m);
    ret = pthread_mutex_lock(m);
    printf("%16s: (%"PRIuMAX") locked mutex %p ret %" PRId32 "\n", __FUNCTION__, (uintmax_t)pthread_self(), m, ret);
    return(ret);
}

int mutex_trylock_dbg (pthread_mutex_t *m) {
    int ret;

    printf("%16s: (%"PRIuMAX") trylocking mutex %p\n", __FUNCTION__, (uintmax_t)pthread_self(), m);
    ret = pthread_mutex_trylock(m);
    printf("%16s: (%"PRIuMAX") trylocked mutex %p ret %" PRId32 "\n", __FUNCTION__, (uintmax_t)pthread_self(), m, ret);
    return(ret);
}

int mutex_unlock_dbg (pthread_mutex_t *m) {
    int ret;

    printf("%16s: (%"PRIuMAX") unlocking mutex %p\n", __FUNCTION__, (uintmax_t)pthread_self(), m);
    ret = pthread_mutex_unlock(m);
    printf("%16s: (%"PRIuMAX") unlocked mutex %p ret %" PRId32 "\n", __FUNCTION__, (uintmax_t)pthread_self(), m, ret);
    return(ret);
}

#endif /* DBG_THREADS */

