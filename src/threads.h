/* Copyright (c) 2008 Victor Julien <victor@inliniac.net> */

#ifndef __THREADS_H__
#define __THREADS_H__

#ifdef DBG_THREADS

#include <pthread.h>
int mutex_lock_dbg (pthread_mutex_t *);
int mutex_trylock_dbg (pthread_mutex_t *);
int mutex_unlock_dbg (pthread_mutex_t *);

#define mutex_lock    mutex_lock_dbg
#define mutex_trylock mutex_trylock_dbg
#define mutex_unlock  mutex_unlock_dbg

#else /* DBG_THREADS */

#define mutex_lock    pthread_mutex_lock
#define mutex_trylock pthread_mutex_trylock
#define mutex_unlock  pthread_mutex_unlock

#endif /* DBG_THREADS */

#endif /* __THREADS_H__ */

