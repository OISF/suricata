/* Copyright (c) 2008 Victor Julien <victor@inliniac.net> */

#ifndef __THREADVARS_H__
#define __THREADVARS_H__

//#include "source-nfq.h"
#include "util-mpm.h"
#include "tm-queues.h"
#include "counters.h"

#define THV_USE     0x01
#define THV_KILL    0x02
#define THV_CLOSED  0x04 /* thread done, should be joinable */

typedef struct ThreadVars_ {
    pthread_t t;
    char *name;
    u_int8_t flags;

    /* queue's */
    Tmq *inq;
    Tmq *outq;

    /* queue handlers */
    struct Packet_ * (*tmqh_in)(struct ThreadVars_ *);
    void (*tmqh_out)(struct ThreadVars_ *, struct Packet_ *);

    /* slot functions */
    void *(*tm_func)(void *);
    void *tm_slots;

    char set_cpu_affinity; /* bool: 0 no, 1 yes */
    int cpu_affinity; /* cpu or core to set affinity to */

    PerfContext pctx;
    PerfCounterArray *pca;

    struct ThreadVars_ *next;
    struct ThreadVars_ *prev;
} ThreadVars;

#endif /* __THREADVARS_H__ */

