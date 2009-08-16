/* Copyright (c) 2008 Victor Julien <victor@inliniac.net> */

#ifndef __THREADVARS_H__
#define __THREADVARS_H__

#include "util-mpm.h"
#include "tm-queues.h"
#include "counters.h"

/** Thread flags set and read by threads to control the threads */
#define THV_USE     0x01 /** thread is in use */
#define THV_PAUSE   0x02
#define THV_KILL    0x04
#define THV_CLOSED  0x08 /* thread done, should be joinable */

/** \brief Per thread variable structure */
typedef struct ThreadVars_ {
    pthread_t t;
    char *name;
    uint8_t flags;

    /** queue's */
    Tmq *inq;
    Tmq *outq;

    /** queue handlers */
    struct Packet_ * (*tmqh_in)(struct ThreadVars_ *);
    void (*tmqh_out)(struct ThreadVars_ *, struct Packet_ *);

    /** slot functions */
    void *(*tm_func)(void *);
    void *tm_slots;

    char set_cpu_affinity; /** bool: 0 no, 1 yes */
    int cpu_affinity; /** cpu or core number to set affinity to */

    PerfContext pctx;
    PerfCounterArray *pca;

    pthread_mutex_t *m;
    pthread_cond_t *cond;

    struct ThreadVars_ *next;
    struct ThreadVars_ *prev;
} ThreadVars;

#endif /* __THREADVARS_H__ */

