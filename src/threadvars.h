/* Copyright (c) 2008 Victor Julien <victor@inliniac.net> */

#ifndef __THREADVARS_H__
#define __THREADVARS_H__

//#include "source-nfq.h"
#include "util-mpm.h"
#include "tm-queues.h"

#define THV_USE  0x01
#define THV_KILL 0x02

typedef struct _ThreadVars {
    pthread_t t;
    char *name;
    u_int8_t flags;

    /* queue's */
    int pickup_q_id;
    int verdict_q_id;
    Tmq *inq;
    Tmq *outq;

    /* queue handlers */
    struct _Packet * (*tmqh_in)(struct _ThreadVars *);
    void (*tmqh_out)(struct _ThreadVars *, struct _Packet *);

    /* slot functions */
    void *(*tm_func)(void *);
    void *tm_slots;

    char set_cpu_affinity; /* bool: 0 no, 1 yes */
    int cpu_affinity; /* cpu or core to set affinity to */
//#ifdef NFQ
//    NFQThreadVars *nfq_t;
//#endif

    struct _ThreadVars *next;
    struct _ThreadVars *prev;
} ThreadVars;

#endif /* __THREADVARS_H__ */

