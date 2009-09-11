/** Copyright (c) 2009 Open Information Security Foundation.
 *  \author Victor Julien <victor@inliniac.net>
 *  \author Anoop Saldanha <poonaatsoc@gmail.com>
 */

#include <sys/types.h> /* for gettid(2) */
#define _GNU_SOURCE
#define __USE_GNU
#include <sys/syscall.h>
#include <sched.h>     /* for sched_setaffinity(2) */

#include "eidps.h"
#include "stream.h"
#include "threadvars.h"
#include "tm-queues.h"
#include "tm-queuehandlers.h"
#include "tm-modules.h"
#include "tm-threads.h"
#include "tmqh-packetpool.h"

/* prototypes */
static int SetCPUAffinity(int cpu);

/* root of the threadvars list */
ThreadVars *tv_root[TVT_MAX] = { NULL };

/* lock to protect tv_root */
pthread_mutex_t tv_root_lock = PTHREAD_MUTEX_INITIALIZER;

/* Action On Failure(AOF).  Determines how the engine should behave when a
   thread encounters a failure.  Defaults to restart the failed thread */
uint8_t tv_aof = THV_RESTART_THREAD;

typedef struct TmSlot_ {
    /* function pointers */
    int (*SlotFunc)(ThreadVars *, Packet *, void *, PacketQueue *);

    int (*SlotThreadInit)(ThreadVars *, void *, void **);
    void (*SlotThreadExitPrintStats)(ThreadVars *, void *);
    int (*SlotThreadDeinit)(ThreadVars *, void *);

    /* data storage */
    void *slot_initdata;
    void *slot_data;
    PacketQueue slot_pq;

    /* linked list, only used by TmVarSlot */
    struct TmSlot_ *slot_next;
} TmSlot;

/* 1 function slot */
typedef struct Tm1Slot_ {
    TmSlot s;
} Tm1Slot;

/* Variable number of function slots */
typedef struct TmVarSlot_ {
    TmSlot *s;
} TmVarSlot;

/* 1 slot functions */

void *TmThreadsSlot1NoIn(void *td) {
    ThreadVars *tv = (ThreadVars *)td;
    Tm1Slot *s = (Tm1Slot *)tv->tm_slots;
    Packet *p = NULL;
    char run = 1;
    int r = 0;

    if (tv->set_cpu_affinity == 1)
        SetCPUAffinity(tv->cpu_affinity);

    if (s->s.SlotThreadInit != NULL) {
        r = s->s.SlotThreadInit(tv, s->s.slot_initdata, &s->s.slot_data);
        if (r != 0) {
            EngineKill();

            tv->flags |= THV_CLOSED;
            pthread_exit((void *) -1);
        }
    }
    memset(&s->s.slot_pq, 0, sizeof(PacketQueue));

    tv->flags |= THV_INIT_DONE;
    while(run) {
        TmThreadTestThreadUnPaused(tv);

        r = s->s.SlotFunc(tv, p, s->s.slot_data, &s->s.slot_pq);

        /* handle error */
        if (r == 1) {
            TmqhReleasePacketsToPacketPool(&s->s.slot_pq);
            TmqhOutputPacketpool(tv, p);
            tv->flags |= THV_FAILED;
            break;
        }

        while (s->s.slot_pq.len > 0) {
            Packet *extra = PacketDequeue(&s->s.slot_pq);
            tv->tmqh_out(tv, extra);
        }

        tv->tmqh_out(tv, p);

        if (tv->flags & THV_KILL) {
            PerfUpdateCounterArray(tv->pca, &tv->pctx, 0);
            run = 0;
        }
    }

    if (s->s.SlotThreadExitPrintStats != NULL) {
        s->s.SlotThreadExitPrintStats(tv, s->s.slot_data);
    }

    if (s->s.SlotThreadDeinit != NULL) {
        r = s->s.SlotThreadDeinit(tv, s->s.slot_data);
        if (r != 0) {
            tv->flags |= THV_CLOSED;
            pthread_exit((void *) -1);
        }
    }

    tv->flags |= THV_CLOSED;
    pthread_exit((void *) 0);
}

void *TmThreadsSlot1NoOut(void *td) {
    ThreadVars *tv = (ThreadVars *)td;
    Tm1Slot *s = (Tm1Slot *)tv->tm_slots;
    Packet *p = NULL;
    char run = 1;
    int r = 0;

    if (tv->set_cpu_affinity == 1)
        SetCPUAffinity(tv->cpu_affinity);

    if (s->s.SlotThreadInit != NULL) {
        r = s->s.SlotThreadInit(tv, s->s.slot_initdata, &s->s.slot_data);
        if (r != 0) {
            EngineKill();

            tv->flags |= THV_CLOSED;
            pthread_exit((void *) -1);
        }
    }
    memset(&s->s.slot_pq, 0, sizeof(PacketQueue));

    tv->flags |= THV_INIT_DONE;
    while(run) {
        TmThreadTestThreadUnPaused(tv);

        p = tv->tmqh_in(tv);

        r = s->s.SlotFunc(tv, p, s->s.slot_data, /* no outqh no pq */NULL);

        /* handle error */
        if (r == 1) {
            TmqhOutputPacketpool(tv, p);
            tv->flags |= THV_FAILED;
            break;
        }

        if (tv->flags & THV_KILL) {
            PerfUpdateCounterArray(tv->pca, &tv->pctx, 0);
            run = 0;
        }
    }

    if (s->s.SlotThreadExitPrintStats != NULL) {
        s->s.SlotThreadExitPrintStats(tv, s->s.slot_data);
    }

    if (s->s.SlotThreadDeinit != NULL) {
        r = s->s.SlotThreadDeinit(tv, s->s.slot_data);
        if (r != 0) {
            tv->flags |= THV_CLOSED;
            pthread_exit((void *) -1);
        }
    }

    tv->flags |= THV_CLOSED;
    pthread_exit((void *) 0);
}

void *TmThreadsSlot1NoInOut(void *td) {
    ThreadVars *tv = (ThreadVars *)td;
    Tm1Slot *s = (Tm1Slot *)tv->tm_slots;
    char run = 1;
    int r = 0;

    if (tv->set_cpu_affinity == 1)
        SetCPUAffinity(tv->cpu_affinity);

    //printf("TmThreadsSlot1NoInOut: %s starting\n", tv->name);

    if (s->s.SlotThreadInit != NULL) {
        r = s->s.SlotThreadInit(tv, s->s.slot_initdata, &s->s.slot_data);
        if (r != 0) {
            EngineKill();

            tv->flags |= THV_CLOSED;
            pthread_exit((void *) -1);
        }
    }
    memset(&s->s.slot_pq, 0, sizeof(PacketQueue));

    tv->flags |= THV_INIT_DONE;
    while(run) {
        TmThreadTestThreadUnPaused(tv);

        r = s->s.SlotFunc(tv, NULL, s->s.slot_data, /* no outqh, no pq */NULL);
        //printf("%s: TmThreadsSlot1NoInNoOut: r %" PRId32 "\n", tv->name, r);

        /* handle error */
        if (r == 1) {
            tv->flags |= THV_FAILED;
            break;
        }

        if (tv->flags & THV_KILL) {
            //printf("%s: TmThreadsSlot1NoInOut: KILL is set\n", tv->name);
            PerfUpdateCounterArray(tv->pca, &tv->pctx, 0);
            run = 0;
        }
    }

    if (s->s.SlotThreadExitPrintStats != NULL) {
        s->s.SlotThreadExitPrintStats(tv, s->s.slot_data);
    }

    if (s->s.SlotThreadDeinit != NULL) {
        r = s->s.SlotThreadDeinit(tv, s->s.slot_data);
        if (r != 0) {
            tv->flags |= THV_CLOSED;
            pthread_exit((void *) -1);
        }
    }

    //printf("TmThreadsSlot1NoInOut: %s ending\n", tv->name);
    tv->flags |= THV_CLOSED;
    pthread_exit((void *) 0);
}

void *TmThreadsSlot1(void *td) {
    ThreadVars *tv = (ThreadVars *)td;
    Tm1Slot *s = (Tm1Slot *)tv->tm_slots;
    Packet *p = NULL;
    char run = 1;
    int r = 0;

    if (tv->set_cpu_affinity == 1)
        SetCPUAffinity(tv->cpu_affinity);

    //printf("TmThreadsSlot1: %s starting\n", tv->name);

    if (s->s.SlotThreadInit != NULL) {
        r = s->s.SlotThreadInit(tv, s->s.slot_initdata, &s->s.slot_data);
        if (r != 0) {
            EngineKill();

            tv->flags |= THV_CLOSED;
            pthread_exit((void *) -1);
        }
    }
    memset(&s->s.slot_pq, 0, sizeof(PacketQueue));

    tv->flags |= THV_INIT_DONE;
    while(run) {
        TmThreadTestThreadUnPaused(tv);

        /* input a packet */
        p = tv->tmqh_in(tv);

        if (p == NULL) {
            //printf("%s: TmThreadsSlot1: p == NULL\n", tv->name);
        } else {
            r = s->s.SlotFunc(tv, p, s->s.slot_data, &s->s.slot_pq);

            /* handle error */
            if (r == 1) {
                TmqhReleasePacketsToPacketPool(&s->s.slot_pq);
                TmqhOutputPacketpool(tv, p);
                tv->flags |= THV_FAILED;
                break;
            }

            while (s->s.slot_pq.len > 0) {
                /* handle new packets from this func */
                Packet *extra_p = PacketDequeue(&s->s.slot_pq);
                tv->tmqh_out(tv, extra_p);
            }

            //printf("%s: TmThreadsSlot1: p %p, r %" PRId32 "\n", tv->name, p, r);

            /* output the packet */
            tv->tmqh_out(tv, p);
        }

        if (tv->flags & THV_KILL) {
            //printf("%s: TmThreadsSlot1: KILL is set\n", tv->name);
            PerfUpdateCounterArray(tv->pca, &tv->pctx, 0);
            run = 0;
        }
    }

    if (s->s.SlotThreadExitPrintStats != NULL) {
        s->s.SlotThreadExitPrintStats(tv, s->s.slot_data);
    }

    if (s->s.SlotThreadDeinit != NULL) {
        r = s->s.SlotThreadDeinit(tv, s->s.slot_data);
        if (r != 0) {
            tv->flags |= THV_CLOSED;
            pthread_exit((void *) -1);
        }
    }

    //printf("TmThreadsSlot1: %s ending\n", tv->name);
    tv->flags |= THV_CLOSED;
    pthread_exit((void *) 0);
}

/* separate run function so we can call it recursively */
static inline int TmThreadsSlotVarRun (ThreadVars *tv, Packet *p, TmSlot *slot) {
    int r = 0;
    TmSlot *s = NULL;

    for (s = slot; s != NULL; s = s->slot_next) {
        r = s->SlotFunc(tv, p, s->slot_data, &s->slot_pq);
        /* handle error */
        if (r == 1) {
            //printf("TmThreadsSlotVarRun: s->SlotFunc %p returned 1\n", s->SlotFunc);
            /* Encountered error.  Return packets to packetpool and return */
            TmqhReleasePacketsToPacketPool(&s->slot_pq);
            tv->flags |= THV_FAILED;
            return 1;
        }

        /* handle new packets */
        while (s->slot_pq.len > 0) {
            Packet *extra_p = PacketDequeue(&s->slot_pq);

            /* see if we need to process the packet */
            if (s->slot_next != NULL) {
                r = TmThreadsSlotVarRun(tv, extra_p, s->slot_next);
                /* XXX handle error */
                if (r == 1) {
                    //printf("TmThreadsSlotVarRun: recursive TmThreadsSlotVarRun returned 1\n");
                    TmqhReleasePacketsToPacketPool(&s->slot_pq);
                    TmqhOutputPacketpool(tv, extra_p);
                    tv->flags |= THV_FAILED;
                    return 1;
                }
            }
            tv->tmqh_out(tv, extra_p);
        }
    }

    return 0;
}

void *TmThreadsSlotVar(void *td) {
    ThreadVars *tv = (ThreadVars *)td;
    TmVarSlot *s = (TmVarSlot *)tv->tm_slots;
    Packet *p = NULL;
    char run = 1;
    int r = 0;
    TmSlot *slot = NULL;

    if (tv->set_cpu_affinity == 1)
        SetCPUAffinity(tv->cpu_affinity);

    //printf("TmThreadsSlot1: %s starting\n", tv->name);

    for (slot = s->s; slot != NULL; slot = slot->slot_next) {
        if (slot->SlotThreadInit != NULL) {
            r = slot->SlotThreadInit(tv, slot->slot_initdata, &slot->slot_data);
            if (r != 0) {
                EngineKill();

                tv->flags |= THV_CLOSED;
                pthread_exit((void *) -1);
            }
        }
        memset(&slot->slot_pq, 0, sizeof(PacketQueue));
    }

    tv->flags |= THV_INIT_DONE;
    while(run) {
        TmThreadTestThreadUnPaused(tv);

        /* input a packet */
        p = tv->tmqh_in(tv);
        //printf("TmThreadsSlotVar: %p\n", p);

        if (p == NULL) {
            //printf("%s: TmThreadsSlot1: p == NULL\n", tv->name);
        } else {
            r = TmThreadsSlotVarRun(tv, p, s->s);
            /* XXX handle error */
            if (r == 1) {
                //printf("TmThreadsSlotVar: TmThreadsSlotVarRun returned 1, breaking out of the loop.\n");
                TmqhOutputPacketpool(tv, p);
                tv->flags |= THV_FAILED;
                break;
            }

            /* output the packet */
            tv->tmqh_out(tv, p);
        }

        if (tv->flags & THV_KILL) {
            //printf("%s: TmThreadsSlot1: KILL is set\n", tv->name);
            PerfUpdateCounterArray(tv->pca, &tv->pctx, 0);
            run = 0;
        }
    }

    for (slot = s->s; slot != NULL; slot = slot->slot_next) {
        if (slot->SlotThreadExitPrintStats != NULL) {
            slot->SlotThreadExitPrintStats(tv, slot->slot_data);
        }

        if (slot->SlotThreadDeinit != NULL) {
            r = slot->SlotThreadDeinit(tv, slot->slot_data);
            if (r != 0) {
                tv->flags |= THV_CLOSED;
                pthread_exit((void *) -1);
            }
        }
    }

    //printf("TmThreadsSlot1: %s ending\n", tv->name);
    tv->flags |= THV_CLOSED;
    pthread_exit((void *) 0);
}

int TmThreadSetSlots(ThreadVars *tv, char *name, void *(*fn_p)(void *)) {
    uint16_t size = 0;

    if (name == NULL) {
        if (fn_p == NULL) {
            printf("Both slot name and function pointer can't be NULL inside "
                   "TmThreadSetSlots\n");
            goto error;
        }
        else
            name = "custom";
    }

    if (strcmp(name, "1slot") == 0) {
        size = sizeof(Tm1Slot);
        tv->tm_func = TmThreadsSlot1;
    } else if (strcmp(name, "1slot_noout") == 0) {
        size = sizeof(Tm1Slot);
        tv->tm_func = TmThreadsSlot1NoOut;
    } else if (strcmp(name, "1slot_noin") == 0) {
        size = sizeof(Tm1Slot);
        tv->tm_func = TmThreadsSlot1NoIn;
    } else if (strcmp(name, "1slot_noinout") == 0) {
        size = sizeof(Tm1Slot);
        tv->tm_func = TmThreadsSlot1NoInOut;
    } else if (strcmp(name, "varslot") == 0) {
        size = sizeof(TmVarSlot);
        tv->tm_func = TmThreadsSlotVar;
    } else if (strcmp(name, "custom") == 0) {
        if (fn_p == NULL)
            goto error;

        tv->tm_func = fn_p;
        return 0;
    } else {
        printf("Error: Slot \"%s\" not supported\n", name);
        goto error;
    }

    tv->tm_slots = malloc(size);
    if (tv->tm_slots == NULL) goto error;
    memset(tv->tm_slots, 0, size);

    return 0;
error:
    return -1;
}

void Tm1SlotSetFunc(ThreadVars *tv, TmModule *tm, void *data) {
    Tm1Slot *s1 = (Tm1Slot *)tv->tm_slots;

    if (s1->s.SlotFunc != NULL)
        printf("Warning: slot 1 is already set tp %p, "
               "overwriting with %p\n", s1->s.SlotFunc, tm->Func);

    s1->s.SlotThreadInit = tm->ThreadInit;
    s1->s.slot_initdata = data;
    s1->s.SlotFunc = tm->Func;
    s1->s.SlotThreadExitPrintStats = tm->ThreadExitPrintStats;
    s1->s.SlotThreadDeinit = tm->ThreadDeinit;
}

void TmVarSlotSetFuncAppend(ThreadVars *tv, TmModule *tm, void *data) {
    TmVarSlot *s = (TmVarSlot *)tv->tm_slots;
    TmSlot *slot = malloc(sizeof(TmSlot));
    if (slot == NULL)
        return;

    memset(slot, 0, sizeof(TmSlot));

    slot->SlotThreadInit = tm->ThreadInit;
    slot->slot_initdata = data;
    slot->SlotFunc = tm->Func;
    slot->SlotThreadExitPrintStats = tm->ThreadExitPrintStats;
    slot->SlotThreadDeinit = tm->ThreadDeinit;

    if (s->s == NULL) {
        s->s = slot;
    } else {
        TmSlot *a = s->s, *b = NULL;

        /* get the last slot */
        for ( ; a != NULL; a = a->slot_next) {
             b = a;
        }
        /* append the new slot */
        if (b != NULL) {
            b->slot_next = slot;
        }
    }
}

/* called from the thread */
static int SetCPUAffinity(int cpu) {
    //pthread_t tid = pthread_self();
    pid_t tid = syscall(SYS_gettid);
    cpu_set_t cs;

    printf("Setting CPU Affinity for thread %" PRIu32 " to CPU %" PRId32 "\n", tid, cpu);

    CPU_ZERO(&cs);
    CPU_SET(cpu,&cs);

    int r = sched_setaffinity(tid,sizeof(cpu_set_t),&cs); 
    if (r != 0) {
        printf("Warning: sched_setaffinity failed (%" PRId32 "): %s\n", r, strerror(errno));
    }

    return 0;
}

int TmThreadSetCPUAffinity(ThreadVars *tv, int cpu) {
    tv->set_cpu_affinity = 1;
    tv->cpu_affinity = cpu;
    return 0;
}

/**
 * \brief Creates and returns the TV instance for a new thread.
 *
 * \param name       Name of this TV instance
 * \param inq_name   Incoming queue name
 * \param inqh_name  Incoming queue handler name as set by TmqhSetup()
 * \param outq_name  Outgoing queue name
 * \param outqh_name Outgoing queue handler as set by TmqhSetup()
 * \param slots      String representation for the slot function to be used
 * \param fn_p       Pointer to function when \"slots\" is of type \"custom\"
 * \param mucond     Flag to indicate whether to initialize the condition
 *                   and the mutex variables for this newly created TV.
 *
 * \retval the newly created TV instance, or NULL on error
 */
ThreadVars *TmThreadCreate(char *name, char *inq_name, char *inqh_name,
                           char *outq_name, char *outqh_name, char *slots,
                           void * (*fn_p)(void *), int mucond)
{
    ThreadVars *tv = NULL;
    Tmq *tmq = NULL;
    Tmqh *tmqh = NULL;

    printf("TmThreadCreate: creating thread \"%s\"...\n", name);

    /* XXX create separate function for this: allocate a thread container */
    tv = malloc(sizeof(ThreadVars));
    if (tv == NULL) goto error;
    memset(tv, 0, sizeof(ThreadVars));

    tv->name = name;
    /* default state for every newly created thread */
    tv->flags = THV_USE | THV_PAUSE;
    /* default aof for every newly created thread */
    tv->aof = THV_RESTART_THREAD;

    /* set the incoming queue */
    if (inq_name != NULL && strcmp(inq_name,"packetpool") != 0) {
        tmq = TmqGetQueueByName(inq_name);
        if (tmq == NULL) {
            tmq = TmqCreateQueue(inq_name);
            if (tmq == NULL) goto error;
        }

        tv->inq = tmq;
        tv->inq->reader_cnt++;
        //printf("TmThreadCreate: tv->inq->id %" PRIu32 "\n", tv->inq->id);
    }
    if (inqh_name != NULL) {
        tmqh = TmqhGetQueueHandlerByName(inqh_name);
        if (tmqh == NULL) goto error;

        tv->tmqh_in = tmqh->InHandler;
        //printf("TmThreadCreate: tv->tmqh_in %p\n", tv->tmqh_in);
    }

    /* set the outgoing queue */
    if (outqh_name != NULL) {
        tmqh = TmqhGetQueueHandlerByName(outqh_name);
        if (tmqh == NULL) goto error;

        tv->tmqh_out = tmqh->OutHandler;
        //printf("TmThreadCreate: tv->tmqh_out %p\n", tv->tmqh_out);

        if (outq_name != NULL && strcmp(outq_name,"packetpool") != 0) {
            if (tmqh->OutHandlerCtxSetup != NULL) {
                tv->outctx = tmqh->OutHandlerCtxSetup(outq_name);
                tv->outq = NULL;
            } else {
                tmq = TmqGetQueueByName(outq_name);
                if (tmq == NULL) {
                    tmq = TmqCreateQueue(outq_name);
                    if (tmq == NULL) goto error;
                }

                tv->outq = tmq;
                tv->outctx = NULL;
                tv->outq->writer_cnt++;
            }
            //printf("TmThreadCreate: tv->outq->id %" PRIu32 "\n", tv->outq->id);
        }
    }

    if (TmThreadSetSlots(tv, slots, fn_p) != 0) {
        goto error;
    }

    if (mucond != 0)
        TmThreadInitMC(tv);

    return tv;
error:
    printf("ERROR: failed to setup a thread.\n");
    return NULL;
}

/**
 * \brief Creates and returns a TV instance for a Packet Processing Thread.
 *        This function doesn't support custom slots, and hence shouldn't be
 *        supplied \"custom\" as its slot type.  All PPT threads are created
 *        with a mucond(see TmThreadCreate declaration) of 0. Hence the tv
 *        conditional variables are not used to kill the thread.
 *
 * \param name       Name of this TV instance
 * \param inq_name   Incoming queue name
 * \param inqh_name  Incoming queue handler name as set by TmqhSetup()
 * \param outq_name  Outgoing queue name
 * \param outqh_name Outgoing queue handler as set by TmqhSetup()
 * \param slots      String representation for the slot function to be used
 *
 * \retval the newly created TV instance, or NULL on error
 */
ThreadVars *TmThreadCreatePacketHandler(char *name, char *inq_name,
                                        char *inqh_name, char *outq_name,
                                        char *outqh_name, char *slots)
{
    ThreadVars *tv = NULL;

    tv = TmThreadCreate(name, inq_name, inqh_name, outq_name, outqh_name,
                        slots, NULL, 0);

    if (tv != NULL)
        tv->type = TVT_PPT;

    return tv;
}

/**
 * \brief Creates and returns the TV instance for a Management thread(MGMT).
 *        This function supports only custom slot functions and hence a
 *        function pointer should be sent as an argument.
 *
 * \param name       Name of this TV instance
 * \param fn_p       Pointer to function when \"slots\" is of type \"custom\"
 * \param mucond     Flag to indicate whether to initialize the condition
 *                   and the mutex variables for this newly created TV.
 *
 * \retval the newly created TV instance, or NULL on error
 */
ThreadVars *TmThreadCreateMgmtThread(char *name, void *(fn_p)(void *),
                                     int mucond)
{
    ThreadVars *tv = NULL;

    tv = TmThreadCreate(name, NULL, NULL, NULL, NULL, "custom", fn_p, mucond);

    if (tv != NULL)
        tv->type = TVT_MGMT;

    return tv;
}

/**
 * \brief Appends this TV to tv_root based on its type
 *
 * \param type holds the type this TV belongs to.
 */
void TmThreadAppend(ThreadVars *tv, int type)
{
    if (tv_root[type] == NULL) {
        tv_root[type] = tv;
        tv->next = NULL;
        tv->prev = NULL;

        //printf("TmThreadAppend: thread \'%s\' is the first thread in the list.\n", tv->name);
        return;
    }

    ThreadVars *t = tv_root[type];

    while (t) {
        if (t->next == NULL) {
            t->next = tv;
            tv->prev = t;
            tv->next = NULL;
            break;
        }

        t = t->next;
    }

    //printf("TmThreadAppend: thread \'%s\' is added to the list.\n", tv->name);
}

void TmThreadKillThreads(void) {
    ThreadVars *t = NULL;
    int i = 0;

    for (i = 0; i < TVT_MAX; i++) {
        t = tv_root[i];


        while (t) {
            t->flags |= THV_KILL;
#ifdef DEBUG
            printf("TmThreadKillThreads: told thread %s to stop\n", t->name);
#endif

            /* XXX hack */
            StreamMsgSignalQueueHack();

            if (t->inq != NULL) {
                int i;

                //printf("TmThreadKillThreads: (t->inq->reader_cnt + t->inq->writer_cnt) %" PRIu32 "\n", (t->inq->reader_cnt + t->inq->writer_cnt));

                /* make sure our packet pending counter doesn't block */
                pthread_cond_signal(&cond_pending);

                /* signal the queue for the number of users */

                for (i = 0; i < (t->inq->reader_cnt + t->inq->writer_cnt); i++)
                    pthread_cond_signal(&trans_q[t->inq->id].cond_q);

                /* to be sure, signal more */
                int cnt = 0;
                while (1) {
                    if (t->flags & THV_CLOSED) {
#ifdef DEBUG
                        printf("signalled the thread %" PRId32 " times\n", cnt);
#endif
                        break;
                    }

                    cnt++;

                    for (i = 0; i < (t->inq->reader_cnt + t->inq->writer_cnt); i++)
                        pthread_cond_signal(&trans_q[t->inq->id].cond_q);

                    usleep(100);
                }

#ifdef DEBUG
                printf("TmThreadKillThreads: signalled t->inq->id %" PRIu32 "\n", t->inq->id);
#endif

            }

            if (t->cond != NULL ) {
                int cnt = 0;
                while (1) {
                    if (t->flags & THV_CLOSED) {
#ifdef DEBUG
                        printf("signalled the thread %" PRId32 " times\n", cnt);
#endif
                        break;
                    }

                    cnt++;

                    pthread_cond_broadcast(t->cond);

                    usleep(100);
                }
            }

            /* join it */
            pthread_join(t->t, NULL);
#ifdef DEBUG
            printf("TmThreadKillThreads: thread %s stopped\n", t->name);
#endif

            t = t->next;
        }
    }
}

/**
 * \brief Spawns a thread associated with the ThreadVars instance tv
 *
 * \retval 0 on success and -1 on failure
 */
int TmThreadSpawn(ThreadVars *tv)
{
    pthread_attr_t attr;

    if (tv->tm_func == NULL) {
        printf("ERROR: no thread function set\n");
        return -1;
    }

    /* Initialize and set thread detached attribute */
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE);

    int rc = pthread_create(&tv->t, &attr, tv->tm_func, (void *)tv);
    if (rc) {
        printf("ERROR; return code from pthread_create() is %" PRId32 "\n", rc);
        return -1;
    }

    TmThreadAppend(tv, tv->type);

    return 0;
}

/**
 * \brief Sets the thread flags for a thread instance(tv)
 *
 * \param tv    Pointer to the thread instance for which the flag has to be set
 * \param flags Holds the thread state this thread instance has to be set to
 */
void TmThreadSetFlags(ThreadVars *tv, uint8_t flags)
{
    if (tv != NULL)
        tv->flags = flags;

    return;
}

/**
 * \brief Sets the aof(Action on failure) for a thread instance(tv)
 *
 * \param tv  Pointer to the thread instance for which the aof has to be set
 * \param aof Holds the aof this thread instance has to be set to
 */
void TmThreadSetAOF(ThreadVars *tv, uint8_t aof)
{
    if (tv != NULL)
        tv->aof = aof;

    return;
}

/**
 * \brief Initializes the mutex and condition variables for this TV
 *
 * \param tv Pointer to a TV instance
 */
void TmThreadInitMC(ThreadVars *tv)
{
    if ( (tv->m = malloc(sizeof(pthread_mutex_t))) == NULL) {
        printf("Error allocating memory\n");
        exit(0);
    }

    if (pthread_mutex_init(tv->m, NULL) != 0) {
        printf("Error initializing the tv->m mutex\n");
        exit(0);
    }

    if ( (tv->cond = malloc(sizeof(pthread_cond_t))) == NULL) {
        printf("Error allocating memory\n");
        exit(0);
    }

    if (pthread_cond_init(tv->cond, NULL) != 0) {
        printf("Error initializing the tv->cond condition variable\n");
        exit(0);
    }
}

/**
 * \brief Tests if the thread represented in the arg has been unpaused or not.
 *
 *        The function would return if the thread tv has been unpaused or if the
 *        kill flag for the thread has been set.
 *
 * \param tv Pointer to the TV instance.
 */
void TmThreadTestThreadUnPaused(ThreadVars *tv)
{
    while (tv->flags & THV_PAUSE) {
        usleep(100);
        if (tv->flags & THV_KILL)
            break;
    }

    return;
}

/**
 * \brief Unpauses a thread
 *
 * \param tv Pointer to a TV instance that has to be unpaused
 */
void TmThreadContinue(ThreadVars *tv)
{
    tv->flags &= ~THV_PAUSE;

    return;
}

/**
 * \brief Unpauses all threads present in tv_root
 */
void TmThreadContinueThreads()
{
    ThreadVars *tv = NULL;
    int i = 0;

    for (i = 0; i < TVT_MAX; i++) {
        tv = tv_root[i];
        while (tv != NULL) {
            TmThreadContinue(tv);
            tv = tv->next;
        }
    }

    return;
}

/**
 * \brief Pauses a thread
 *
 * \param tv Pointer to a TV instance that has to be paused
 */
void TmThreadPause(ThreadVars *tv)
{
    tv->flags |= THV_PAUSE;

    return;
}

/**
 * \brief Pauses all threads present in tv_root
 */
void TmThreadPauseThreads()
{
    ThreadVars *tv = NULL;
    int i = 0;

    for (i = 0; i < TVT_MAX; i++) {
        tv = tv_root[i];
        while (tv != NULL) {
            TmThreadPause(tv);
            tv = tv->next;
        }
    }

    return;
}

/**
 * \brief Restarts the thread sent as the argument
 *
 * \param tv Pointer to the thread instance(tv) to be restarted
 */
static void TmThreadRestartThread(ThreadVars *tv)
{
    if (tv->restarted >= THV_MAX_RESTARTS) {
        printf("Warning: thread restarts exceeded threshhold limit for thread"
               "\"%s\"", tv->name);
        /* makes sense to reset the tv_aof to engine_exit?! */
        // tv->aof = THV_ENGINE_EXIT;
        return;
    }

    tv->flags &= ~((uint8_t)(THV_CLOSED | THV_FAILED));

    if (TmThreadSpawn(tv) != 0) {
        printf("Error: TmThreadSpawn failed\n");
        exit(EXIT_FAILURE);
    }

    tv->restarted++;
    printf("Thread \"%s\" restarted\n", tv->name);

    return;
}

/**
 * \brief Used to check the thread for certain conditions of failure.  If the
 *        thread has been specified to restart on failure, the thread is
 *        restarted.  If the thread has been specified to gracefully shutdown
 *        the engine on failure, it does so.  The global aof flag, tv_aof
 *        overrides the thread aof flag, if it holds a THV_ENGINE_EXIT;
 */
void TmThreadCheckThreadState(void)
{
    ThreadVars *tv = NULL;
    int i = 0;

    for (i = 0; i < TVT_MAX; i++) {
        tv = tv_root[i];

        while (tv) {
            if (tv->flags & THV_FAILED) {
                pthread_join(tv->t, NULL);
                if ( !(tv_aof & THV_ENGINE_EXIT) &&
                     (tv->aof & THV_RESTART_THREAD) ) {
                    TmThreadRestartThread(tv);
                } else {
                    tv->flags |= THV_CLOSED;
                    EngineKill();
                }
            }
            tv = tv->next;
        }
    }

    return;
}

/** \brief Used to check if all threads have finished their initialization.  On
 *         finding an un-initialized thread, it waits till that thread completes
 *         its initialization, before proceeding to the next thread.
 */
void TmThreadWaitOnThreadInit(void)
{
    ThreadVars *tv = NULL;
    int i = 0;

    for (i = 0; i < TVT_MAX; i++) {
        tv = tv_root[i];
        while (tv != NULL) {
            while (!(tv->flags & THV_INIT_DONE))
                ;
            tv = tv->next;
        }
    }

    return;
}
