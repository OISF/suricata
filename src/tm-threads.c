/* Copyright (c) 2008 Victor Julien <victor@inliniac.net> */

#include <sys/types.h> /* for gettid(2) */
#define _GNU_SOURCE
#define __USE_GNU
#include <sys/syscall.h>
#include <sched.h>     /* for sched_setaffinity(2) */

#include "eidps.h"
#include "threadvars.h"
#include "tm-queues.h"
#include "tm-queuehandlers.h"
#include "tm-modules.h"

/* prototypes */
static int SetCPUAffinity(int cpu);


/* root of the threadvars list */
static ThreadVars *tv_root;

typedef struct TmSlot_ {
    /* function pointers */
    int (*SlotInit)(ThreadVars *, void *, void **);
    int (*SlotFunc)(ThreadVars *, Packet *, void *, PacketQueue *);
    void (*SlotExitPrintStats)(ThreadVars *, void *);
    int (*SlotDeinit)(ThreadVars *, void *);

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

/* 2 function slot */
typedef struct Tm2Slot_ {
    TmSlot s1, s2;
} Tm2Slot;

/* 3 function slot */
typedef struct Tm3Slot_ {
    TmSlot s1, s2, s3;
} Tm3Slot;

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

    if (s->s.SlotInit != NULL) {
        r = s->s.SlotInit(tv, s->s.slot_initdata, &s->s.slot_data);
        if (r != 0) {
            tv->flags |= THV_CLOSED;
            pthread_exit((void *) -1);
        }
    }
    memset(&s->s.slot_pq, 0, sizeof(PacketQueue));

    while(run) {
        r = s->s.SlotFunc(tv, p, s->s.slot_data, &s->s.slot_pq);
        while (s->s.slot_pq.len > 0) {
            Packet *extra = PacketDequeue(&s->s.slot_pq);
            tv->tmqh_out(tv, extra);
        }

        /* XXX handle error */
        if (r == 1) {
            run = 0;
        }

        tv->tmqh_out(tv, p);

        if (tv->flags & THV_KILL)
            run = 0;
    }

    if (s->s.SlotExitPrintStats != NULL) {
        s->s.SlotExitPrintStats(tv, s->s.slot_data);
    }

    if (s->s.SlotDeinit != NULL) {
        r = s->s.SlotDeinit(tv, s->s.slot_data);
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

    if (s->s.SlotInit != NULL) {
        r = s->s.SlotInit(tv, s->s.slot_initdata, &s->s.slot_data);
        if (r != 0) {
            tv->flags |= THV_CLOSED;
            pthread_exit((void *) -1);
        }
    }
    memset(&s->s.slot_pq, 0, sizeof(PacketQueue));

    while(run) {
        p = tv->tmqh_in(tv);

        r = s->s.SlotFunc(tv, p, s->s.slot_data, /* no outqh no pq */NULL);
        /* XXX handle error */
        if (r == 1) {
            run = 0;
        }

        if (tv->flags & THV_KILL)
            run = 0;
    }

    if (s->s.SlotExitPrintStats != NULL) {
        s->s.SlotExitPrintStats(tv, s->s.slot_data);
    }

    if (s->s.SlotDeinit != NULL) {
        r = s->s.SlotDeinit(tv, s->s.slot_data);
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

    if (s->s.SlotInit != NULL) {
        r = s->s.SlotInit(tv, s->s.slot_initdata, &s->s.slot_data);
        if (r != 0) {
            tv->flags |= THV_CLOSED;
            pthread_exit((void *) -1);
        }
    }
    memset(&s->s.slot_pq, 0, sizeof(PacketQueue));

    while(run) {
        r = s->s.SlotFunc(tv, NULL, s->s.slot_data, /* no outqh, no pq */NULL);
        //printf("%s: TmThreadsSlot1NoInNoOut: r %d\n", tv->name, r);
        /* XXX handle error */
        if (r == 1) {
            run = 0;
        }

        if (tv->flags & THV_KILL) {
            //printf("%s: TmThreadsSlot1NoInOut: KILL is set\n", tv->name);
            run = 0;
        }
    }

    if (s->s.SlotExitPrintStats != NULL) {
        s->s.SlotExitPrintStats(tv, s->s.slot_data);
    }

    if (s->s.SlotDeinit != NULL) {
        r = s->s.SlotDeinit(tv, s->s.slot_data);
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

    if (s->s.SlotInit != NULL) {
        r = s->s.SlotInit(tv, s->s.slot_initdata, &s->s.slot_data);
        if (r != 0) {
            tv->flags |= THV_CLOSED;
            pthread_exit((void *) -1);
        }
    }
    memset(&s->s.slot_pq, 0, sizeof(PacketQueue));

    while(run) {
        /* input a packet */
        p = tv->tmqh_in(tv);

        if (p == NULL) {
            //printf("%s: TmThreadsSlot1: p == NULL\n", tv->name);
        } else {
            r = s->s.SlotFunc(tv, p, s->s.slot_data, &s->s.slot_pq);
            while (s->s.slot_pq.len > 0) {
                /* handle new packets from this func */
                Packet *extra_p = PacketDequeue(&s->s.slot_pq);
                tv->tmqh_out(tv, extra_p);
            }

            //printf("%s: TmThreadsSlot1: p %p, r %d\n", tv->name, p, r);
            /* XXX handle error */
            if (r == 1) {
                run = 0;
            }

            /* output the packet */
            tv->tmqh_out(tv, p);
        }

        if (tv->flags & THV_KILL) {
            //printf("%s: TmThreadsSlot1: KILL is set\n", tv->name);
            run = 0;
        }
    }

    if (s->s.SlotExitPrintStats != NULL) {
        s->s.SlotExitPrintStats(tv, s->s.slot_data);
    }

    if (s->s.SlotDeinit != NULL) {
        r = s->s.SlotDeinit(tv, s->s.slot_data);
        if (r != 0) {
            tv->flags |= THV_CLOSED;
            pthread_exit((void *) -1);
        }
    }

    //printf("TmThreadsSlot1: %s ending\n", tv->name);
    tv->flags |= THV_CLOSED;
    pthread_exit((void *) 0);
}

void *TmThreadsSlot2(void *td) {
    ThreadVars *tv = (ThreadVars *)td;
    Tm2Slot *s = (Tm2Slot *)tv->tm_slots;
    Packet *p = NULL;
    char run = 1;
    int r = 0;

    if (tv->set_cpu_affinity == 1)
        SetCPUAffinity(tv->cpu_affinity);

    //printf("TmThreadsSlot2: %s starting\n", tv->name);

    if (s->s1.SlotInit != NULL) {
        r = s->s1.SlotInit(tv, s->s1.slot_initdata, &s->s1.slot_data);
        if (r != 0) {
            tv->flags |= THV_CLOSED;
            pthread_exit((void *) -1);
        }
    }
    if (s->s2.SlotInit != NULL) {
        r = s->s2.SlotInit(tv, s->s2.slot_initdata, &s->s2.slot_data);
        if (r != 0) {
            tv->flags |= THV_CLOSED;
            pthread_exit((void *) -1);
        }
    }

    while(run) {
        /* input a packet */
        p = tv->tmqh_in(tv);

        if (p == NULL) {
            //printf("%s: TmThreadsSlot1: p == NULL\n", tv->name);
        } else {
            r = s->s1.SlotFunc(tv, p, s->s1.slot_data, &s->s1.slot_pq);
            while (s->s1.slot_pq.len > 0) {
                /* handle new packets from this func */
                Packet *extra_p = PacketDequeue(&s->s1.slot_pq);

                r = s->s2.SlotFunc(tv, extra_p, s->s2.slot_data, &s->s2.slot_pq);
                while (s->s2.slot_pq.len > 0) {
                    /* handle new packets from this func */
                    Packet *extra_p2 = PacketDequeue(&s->s2.slot_pq);
                    tv->tmqh_out(tv, extra_p2);
                }
                if (r == 1) {
                    run = 0;
                }

                tv->tmqh_out(tv, extra_p);
            }
            if (r == 1) {
                run = 0;
            }

            r = s->s2.SlotFunc(tv, p, s->s2.slot_data, &s->s2.slot_pq);
            while (s->s2.slot_pq.len > 0) {
                /* handle new packets from this func */
                Packet *extra_p = PacketDequeue(&s->s2.slot_pq);
                tv->tmqh_out(tv, extra_p);
            }

            //printf("%s: TmThreadsSlot1: p %p, r %d\n", tv->name, p, r);
            /* XXX handle error */
            if (r == 1) {
                run = 0;
            }

            /* output the packet */
            tv->tmqh_out(tv, p);
        }

        if (tv->flags & THV_KILL) {
            //printf("%s: TmThreadsSlot1: KILL is set\n", tv->name);
            run = 0;
        }
    }

    if (s->s1.SlotExitPrintStats != NULL) {
        s->s1.SlotExitPrintStats(tv, s->s1.slot_data);
    }

    if (s->s1.SlotDeinit != NULL) {
        r = s->s1.SlotDeinit(tv, s->s1.slot_data);
        if (r != 0) {
            pthread_exit((void *) -1);
            tv->flags |= THV_CLOSED;
        }
    }

    if (s->s2.SlotExitPrintStats != NULL) {
        s->s2.SlotExitPrintStats(tv, s->s2.slot_data);
    }

    if (s->s2.SlotDeinit != NULL) {
        r = s->s2.SlotDeinit(tv, s->s2.slot_data);
        if (r != 0) {
            pthread_exit((void *) -1);
            tv->flags |= THV_CLOSED;
        }
    }

    //printf("TmThreadsSlot2: %s ending\n", tv->name);
    tv->flags |= THV_CLOSED;
    pthread_exit((void *) 0);
}

void *TmThreadsSlot3(void *td) {
    ThreadVars *tv = (ThreadVars *)td;
    Tm3Slot *s = (Tm3Slot *)tv->tm_slots;
    Packet *p = NULL;
    char run = 1;
    int r = 0;

    if (tv->set_cpu_affinity == 1)
        SetCPUAffinity(tv->cpu_affinity);

    //printf("TmThreadsSlot3: %s starting\n", tv->name);

    if (s->s1.SlotInit != NULL) {
        r = s->s1.SlotInit(tv, s->s1.slot_initdata, &s->s1.slot_data);
        if (r != 0) {
            tv->flags |= THV_CLOSED;
            pthread_exit((void *) -1);
        }
    }
    if (s->s2.SlotInit != NULL) {
        r = s->s2.SlotInit(tv, s->s2.slot_initdata, &s->s2.slot_data);
        if (r != 0) {
            tv->flags |= THV_CLOSED;
            pthread_exit((void *) -1);
        }
    }
    if (s->s3.SlotInit != NULL) {
        r = s->s3.SlotInit(tv, s->s3.slot_initdata, &s->s3.slot_data);
        if (r != 0) {
            tv->flags |= THV_CLOSED;
            pthread_exit((void *) -1);
        }
    }

    while(run) {
        /* input a packet */
        p = tv->tmqh_in(tv);

        if (p == NULL) {
            //printf("%s: TmThreadsSlot1: p == NULL\n", tv->name);
        } else {
            /* slot 1 */
            r = s->s1.SlotFunc(tv, p, s->s1.slot_data, &s->s1.slot_pq);
            while (s->s1.slot_pq.len > 0) {
                /* handle new packets from this func */
                Packet *extra_p = PacketDequeue(&s->s1.slot_pq);

                r = s->s2.SlotFunc(tv, extra_p, s->s2.slot_data, &s->s2.slot_pq);
                while (s->s2.slot_pq.len > 0) {
                    /* handle new packets from this func */
                    Packet *extra_p2 = PacketDequeue(&s->s2.slot_pq);

                    r = s->s3.SlotFunc(tv, extra_p2, s->s3.slot_data, &s->s3.slot_pq);
                    while (s->s3.slot_pq.len > 0) {
                        /* handle new packets from this func */
                        Packet *extra_p3 = PacketDequeue(&s->s3.slot_pq);
                        tv->tmqh_out(tv, extra_p3);
                    }
                    if (r == 1) {
                        run = 0;
                    }
                    tv->tmqh_out(tv, extra_p2);
                }
                if (r == 1) {
                    run = 0;
                }
                tv->tmqh_out(tv, extra_p);
            }
            if (r == 1) {
                run = 0;
            }

            /* slot 2 */
            r = s->s2.SlotFunc(tv, p, s->s2.slot_data, &s->s2.slot_pq);
            while (s->s2.slot_pq.len > 0) {
                /* handle new packets from this func */
                Packet *extra_p = PacketDequeue(&s->s2.slot_pq);

                r = s->s3.SlotFunc(tv, extra_p, s->s3.slot_data, &s->s3.slot_pq);
                while (s->s3.slot_pq.len > 0) {
                    /* handle new packets from this func */
                    Packet *extra_p2 = PacketDequeue(&s->s3.slot_pq);
                    tv->tmqh_out(tv, extra_p2);
                }
                if (r == 1) {
                    run = 0;
                }
                tv->tmqh_out(tv, extra_p);
            }

            /* slot 3 */
            r = s->s3.SlotFunc(tv, p, s->s3.slot_data, &s->s3.slot_pq);
            while (s->s3.slot_pq.len > 0) {
                /* handle new packets from this func */
                Packet *extra_p = PacketDequeue(&s->s3.slot_pq);
                tv->tmqh_out(tv, extra_p);
            }

            //printf("%s: TmThreadsSlot1: p %p, r %d\n", tv->name, p, r);
            /* XXX handle error */
            if (r == 1) {
                run = 0;
            }

            /* output the packet */
            tv->tmqh_out(tv, p);
        }

        if (tv->flags & THV_KILL) {
            //printf("%s: TmThreadsSlot1: KILL is set\n", tv->name);
            run = 0;
        }
    }

    if (s->s1.SlotExitPrintStats != NULL) {
        s->s1.SlotExitPrintStats(tv, s->s1.slot_data);
    }

    if (s->s1.SlotDeinit != NULL) {
        r = s->s1.SlotDeinit(tv, s->s1.slot_data);
        if (r != 0) {
            tv->flags |= THV_CLOSED;
            pthread_exit((void *) -1);
        }
    }

    if (s->s2.SlotExitPrintStats != NULL) {
        s->s2.SlotExitPrintStats(tv, s->s2.slot_data);
    }

    if (s->s2.SlotDeinit != NULL) {
        r = s->s2.SlotDeinit(tv, s->s2.slot_data);
        if (r != 0) {
            tv->flags |= THV_CLOSED;
            pthread_exit((void *) -1);
        }
    }

    if (s->s3.SlotExitPrintStats != NULL) {
        s->s3.SlotExitPrintStats(tv, s->s3.slot_data);
    }

    if (s->s3.SlotDeinit != NULL) {
        r = s->s3.SlotDeinit(tv, s->s3.slot_data);
        if (r != 0) {
            tv->flags |= THV_CLOSED;
            pthread_exit((void *) -1);
        }
    }

    //printf("TmThreadsSlot3: %s ending\n", tv->name);
    tv->flags |= THV_CLOSED;
    pthread_exit((void *) 0);
}

/* separate run function so we can call it recursively */
static inline int TmThreadsSlotVarRun (ThreadVars *tv, Packet *p, TmSlot *slot) {
    int r = 0;
    TmSlot *s = NULL;
    int retval = 0;

    for (s = slot; s != NULL; s = s->slot_next) {
        r = s->SlotFunc(tv, p, s->slot_data, &s->slot_pq);
        /* XXX handle error */
        if (r == 1) {
            //printf("TmThreadsSlotVarRun: s->SlotFunc %p returned 1\n", s->SlotFunc);
            retval = 1;
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
                    retval = 1;
                }
            }
            tv->tmqh_out(tv, extra_p);
        }
    }

    return retval;
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
        if (slot->SlotInit != NULL) {
            r = slot->SlotInit(tv, slot->slot_initdata, &slot->slot_data);
            if (r != 0) {
                tv->flags |= THV_CLOSED;
                pthread_exit((void *) -1);
            }
        }
        memset(&slot->slot_pq, 0, sizeof(PacketQueue));
    }

    while(run) {
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
                run = 0;
            }

            /* output the packet */
            tv->tmqh_out(tv, p);
        }

        if (tv->flags & THV_KILL) {
            //printf("%s: TmThreadsSlot1: KILL is set\n", tv->name);
            run = 0;
        }
    }

    for (slot = s->s; slot != NULL; slot = slot->slot_next) {
        if (slot->SlotExitPrintStats != NULL) {
            slot->SlotExitPrintStats(tv, slot->slot_data);
        }

        if (slot->SlotDeinit != NULL) {
            r = slot->SlotDeinit(tv, slot->slot_data);
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

int TmThreadSetSlots(ThreadVars *tv, char *name) {
    u_int16_t size = 0;

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
    } else if (strcmp(name, "2slot") == 0) {
        size = sizeof(Tm2Slot);
        tv->tm_func = TmThreadsSlot2;
    } else if (strcmp(name, "3slot") == 0) {
        size = sizeof(Tm3Slot);
        tv->tm_func = TmThreadsSlot3;
    } else if (strcmp(name, "varslot") == 0) {
        size = sizeof(TmVarSlot);
        tv->tm_func = TmThreadsSlotVar;
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

    s1->s.SlotInit = tm->Init;
    s1->s.slot_initdata = data;
    s1->s.SlotFunc = tm->Func;
    s1->s.SlotExitPrintStats = tm->ExitPrintStats;
    s1->s.SlotDeinit = tm->Deinit;
}

void Tm2SlotSetFunc1(ThreadVars *tv, TmModule *tm, void *data) {
    Tm2Slot *s = (Tm2Slot *)tv->tm_slots;

    if (s->s1.SlotFunc != NULL)
        printf("Warning: slot 1 is already set tp %p, "
               "overwriting with %p\n", s->s1.SlotFunc, tm->Func);

    s->s1.SlotInit = tm->Init;
    s->s1.slot_initdata = data;
    s->s1.SlotFunc = tm->Func;
    s->s1.SlotExitPrintStats = tm->ExitPrintStats;
    s->s1.SlotDeinit = tm->Deinit;
}

void Tm2SlotSetFunc2(ThreadVars *tv, TmModule *tm, void *data) {
    Tm2Slot *s = (Tm2Slot *)tv->tm_slots;

    if (s->s2.SlotFunc != NULL)
        printf("Warning: slot 2 is already set tp %p, "
               "overwriting with %p\n", s->s2.SlotFunc, tm->Func);

    s->s2.SlotInit = tm->Init;
    s->s2.slot_initdata = data;
    s->s2.SlotFunc = tm->Func;
    s->s2.SlotExitPrintStats = tm->ExitPrintStats;
    s->s2.SlotDeinit = tm->Deinit;
}

void Tm3SlotSetFunc1(ThreadVars *tv, TmModule *tm, void *data) {
    Tm3Slot *s = (Tm3Slot *)tv->tm_slots;

    if (s->s1.SlotFunc != NULL)
        printf("Warning: slot 1 is already set tp %p, "
               "overwriting with %p\n", s->s1.SlotFunc, tm->Func);

    s->s1.SlotInit = tm->Init;
    s->s1.slot_initdata = data;
    s->s1.SlotFunc = tm->Func;
    s->s1.SlotExitPrintStats = tm->ExitPrintStats;
    s->s1.SlotDeinit = tm->Deinit;
}

void Tm3SlotSetFunc2(ThreadVars *tv, TmModule *tm, void *data) {
    Tm3Slot *s = (Tm3Slot *)tv->tm_slots;

    if (s->s2.SlotFunc != NULL)
        printf("Warning: slot 2 is already set tp %p, "
               "overwriting with %p\n", s->s2.SlotFunc, tm->Func);

    s->s2.SlotInit = tm->Init;
    s->s2.slot_initdata = data;
    s->s2.SlotFunc = tm->Func;
    s->s2.SlotExitPrintStats = tm->ExitPrintStats;
    s->s2.SlotDeinit = tm->Deinit;
}

void Tm3SlotSetFunc3(ThreadVars *tv, TmModule *tm, void *data) {
    Tm3Slot *s = (Tm3Slot *)tv->tm_slots;

    if (s->s3.SlotFunc != NULL)
        printf("Warning: slot 3 is already set tp %p, "
               "overwriting with %p\n", s->s3.SlotFunc, tm->Func);

    s->s3.SlotInit = tm->Init;
    s->s3.slot_initdata = data;
    s->s3.SlotFunc = tm->Func;
    s->s3.SlotExitPrintStats = tm->ExitPrintStats;
    s->s3.SlotDeinit = tm->Deinit;
}

void TmVarSlotSetFuncAppend(ThreadVars *tv, TmModule *tm, void *data) {
    TmVarSlot *s = (TmVarSlot *)tv->tm_slots;
    TmSlot *slot = malloc(sizeof(TmSlot));
    if (slot == NULL) 
        return;

    memset(slot, 0, sizeof(TmSlot));

    slot->SlotInit = tm->Init;
    slot->slot_initdata = data;
    slot->SlotFunc = tm->Func;
    slot->SlotExitPrintStats = tm->ExitPrintStats;
    slot->SlotDeinit = tm->Deinit;

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

    printf("Setting CPU Affinity for thread %u to CPU %d\n", tid, cpu);

    CPU_ZERO(&cs);
    CPU_SET(cpu,&cs);

    int r = sched_setaffinity(tid,sizeof(cpu_set_t),&cs); 
    if (r != 0) {
        printf("Warning: sched_setaffinity failed (%d): %s\n", r, strerror(errno));
    }

    return 0;
}

int TmThreadSetCPUAffinity(ThreadVars *tv, int cpu) {
    tv->set_cpu_affinity = 1;
    tv->cpu_affinity = cpu;
    return 0;
}

ThreadVars *TmThreadCreate(char *name, char *inq_name, char *inqh_name, char *outq_name, char *outqh_name, char *slots) {
    ThreadVars *tv = NULL;
    Tmq *tmq = NULL;
    Tmqh *tmqh = NULL;

    printf("TmThreadCreate: creating thread \"%s\"...\n", name);

    /* XXX create separate function for this: allocate a thread container */
    tv = malloc(sizeof(ThreadVars));
    if (tv == NULL) goto error;
    memset(tv, 0, sizeof(ThreadVars));

    tv->name = name;

    /* set the incoming queue */
    if (inq_name != NULL) {
        tmq = TmqGetQueueByName(inq_name);
        if (tmq == NULL) {
            tmq = TmqCreateQueue(inq_name);
            if (tmq == NULL) goto error;
        }

        tv->inq = tmq;
        tv->inq->usecnt++;
        //printf("TmThreadCreate: tv->inq->id %u\n", tv->inq->id);
    }
    if (inqh_name != NULL) {
        tmqh = TmqhGetQueueHandlerByName(inqh_name);
        if (tmqh == NULL) goto error;

        tv->tmqh_in = tmqh->InHandler;
        //printf("TmThreadCreate: tv->tmqh_in %p\n", tv->tmqh_in);
    }

    /* set the outgoing queue */
    if (outq_name != NULL) {
        tmq = TmqGetQueueByName(outq_name);
        if (tmq == NULL) {
            tmq = TmqCreateQueue(outq_name);
            if (tmq == NULL) goto error;
        }

        tv->outq = tmq;
        tv->outq->usecnt++;
        //printf("TmThreadCreate: tv->outq->id %u\n", tv->outq->id);
    }
    if (outqh_name != NULL) {
        tmqh = TmqhGetQueueHandlerByName(outqh_name);
        if (tmqh == NULL) goto error;

        tv->tmqh_out = tmqh->OutHandler;
        //printf("TmThreadCreate: tv->tmqh_out %p\n", tv->tmqh_out);
    }

    if (TmThreadSetSlots(tv, slots) != 0) {
        goto error;
    }

    return tv;
error:
    printf("ERROR: failed to setup a thread.\n");
    return NULL;
}

void TmThreadAppend(ThreadVars *tv) {
    if (tv_root == NULL) {
        tv_root = tv;
        tv->next = NULL;
        tv->prev = NULL;

        //printf("TmThreadAppend: thread \'%s\' is the first thread in the list.\n", tv->name);
        return;
    }

    ThreadVars *t = tv_root;

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
    ThreadVars *t = tv_root;

    while (t) {
        t->flags |= THV_KILL;
        printf("TmThreadKillThreads: told thread %s to stop\n", t->name);

        /* XXX hack */
        StreamMsgSignalQueueHack();

        if (t->inq != NULL) {
            int i;

            printf("TmThreadKillThreads: t->inq->usecnt %u\n", t->inq->usecnt);

            /* make sure our packet pending counter doesn't block */
            pthread_cond_signal(&cond_pending);

            /* signal the queue for the number of users */
            for (i = 0; i < t->inq->usecnt; i++)
                pthread_cond_signal(&trans_q[t->inq->id].cond_q);

            /* to be sure, signal more */
            int cnt = 0;
            while (1) {
                if (t->flags & THV_CLOSED) {
                    printf("signalled the thread %d times\n", cnt);
                    break;
                }

                cnt++;

                for (i = 0; i < t->inq->usecnt; i++)
                    pthread_cond_signal(&trans_q[t->inq->id].cond_q);

                usleep(100);
            }

            printf("TmThreadKillThreads: signalled t->inq->id %u\n", t->inq->id);
        }

        /* join it */
        pthread_join(t->t, NULL);
        printf("TmThreadKillThreads: thread %s stopped\n", t->name);

        t = t->next;
    }
}

int TmThreadSpawn(ThreadVars *tv) {
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
        printf("ERROR; return code from pthread_create() is %d\n", rc);
        return -1;
    }

    TmThreadAppend(tv);

    return 0;
}

