/* Copyright (c) 2008 Victor Julien <victor@inliniac.net> */

#ifndef __THREADVARS_H__
#define __THREADVARS_H__

#include "util-mpm.h"
#include "tm-queues.h"
#include "counters.h"
#include "threads.h"

/** Thread flags set and read by threads to control the threads */
#define THV_USE       0x01 /** thread is in use */
#define THV_INIT_DONE 0x02 /** thread initialization done */
#define THV_PAUSE     0x04 /** thread has been paused */
#define THV_KILL      0x08 /** thread has been asked to cleanup and exit */
#define THV_FAILED    0x10 /** thread has encountered an error and failed */
#define THV_CLOSED    0x20 /** thread done, should be joinable */

/** Thread flags set and read by threads, to control the threads, when they
    encounter certain conditions like failure */
#define THV_RESTART_THREAD 0x01 /** restart the thread */
#define THV_ENGINE_EXIT 0x02 /** shut the engine down gracefully */

/** Maximum no of times a thread can be restarted */
#define THV_MAX_RESTARTS 50

/** \brief Per thread variable structure */
typedef struct ThreadVars_ {
    pthread_t t;
    char *name;

    uint8_t flags;
    SCSpinlock flags_spinlock;

    /** aof(action on failure) determines what should be done with the thread
        when it encounters certain conditions like failures */
    uint8_t aof;

    /** the type of thread as defined in tm-threads.h (TVT_PPT, TVT_MGMT) */
    uint8_t type;

    /** no of times the thread has been restarted on failure */
    uint8_t restarted;

    /** queue's */
    Tmq *inq;
    Tmq *outq;
    void *outctx;

    /** queue handlers */
    struct Packet_ * (*tmqh_in)(struct ThreadVars_ *);
    void (*tmqh_out)(struct ThreadVars_ *, struct Packet_ *);

    /** slot functions */
    void *(*tm_func)(void *);
    void *tm_slots;

    uint8_t thread_setup_flags;
    uint16_t cpu_affinity; /** cpu or core number to set affinity to */
    int thread_priority; /** priority (real time) for this thread. Look at threads.h */

    /* the perf counter context and the perf counter array */
    SCPerfContext sc_perf_pctx;
    SCPerfCounterArray *sc_perf_pca;

    SCMutex *m;
    SCCondT *cond;

    struct ThreadVars_ *next;
    struct ThreadVars_ *prev;
} ThreadVars;

/** Thread setup flags: */
#define THREAD_SET_AFFINITY     0x01 /** CPU/Core affinity */
#define THREAD_SET_PRIORITY     0x02 /** Real time priority */

#endif /* __THREADVARS_H__ */

