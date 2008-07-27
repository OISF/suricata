/* Copyright (c) 2008 Victor Julien <victor@inliniac.net> */

#include "vips.h"
#include "threadvars.h"
#include "tm-queues.h"
#include "tm-queuehandlers.h"
#include "tm-modules.h"

/* root of the threadvars list */
static ThreadVars *tv_root;

/* 1 function slot */
typedef struct _Tm1Slot {
    int (*Slot1Init)(ThreadVars *, void **);
    int (*Slot1Func)(ThreadVars *, Packet *, void *);
    int (*Slot1Deinit)(ThreadVars *, void *);
    void *slot1_data;
} Tm1Slot;

/* 2 function slot */
typedef struct _Tm2Slot {
    int (*Slot1Init)(ThreadVars *, void **);
    int (*Slot1Func)(ThreadVars *, Packet *, void *);
    int (*Slot1Deinit)(ThreadVars *, void *);
    void *slot1_data;

    int (*Slot2Init)(ThreadVars *, void **);
    int (*Slot2Func)(ThreadVars *, Packet *, void *);
    int (*Slot2Deinit)(ThreadVars *, void *);
    void *slot2_data;
} Tm2Slot;

/* 3 function slot */
typedef struct _Tm3Slot {
    int (*Slot1Init)(ThreadVars *, void **);
    int (*Slot1Func)(ThreadVars *, Packet *, void *);
    int (*Slot1Deinit)(ThreadVars *, void *);
    void *slot1_data;

    int (*Slot2Init)(ThreadVars *, void **);
    int (*Slot2Func)(ThreadVars *, Packet *, void *);
    int (*Slot2Deinit)(ThreadVars *, void *);
    void *slot2_data;

    int (*Slot3Init)(ThreadVars *, void **);
    int (*Slot3Func)(ThreadVars *, Packet *, void *);
    int (*Slot3Deinit)(ThreadVars *, void *);
    void *slot3_data;
} Tm3Slot;


void *TmThreadsSlot1NoIn(void *td) {
    ThreadVars *tv = (ThreadVars *)td;
    Tm1Slot *s1 = (Tm1Slot *)tv->tm_slots;
    Packet *p = NULL;
    char run = 1;
    int r = 0;

    if (s1->Slot1Init != NULL) {
        r = s1->Slot1Init(tv, &s1->slot1_data);
        if (r != 0) {
            pthread_exit((void *) -1);
        }
    }

    while(run) {
        r = s1->Slot1Func(tv, p, s1->slot1_data);
        /* XXX handle error */

        tv->tmqh_out(tv, p);

        if (tv->flags & THV_KILL)
            run = 0;
    }

    if (s1->Slot1Deinit != NULL) {
        r = s1->Slot1Deinit(tv, s1->slot1_data);
        if (r != 0) {
            pthread_exit((void *) -1);
        }
    }

    pthread_exit((void *) 0);
}

void *TmThreadsSlot1NoOut(void *td) {
    ThreadVars *tv = (ThreadVars *)td;
    Tm1Slot *s1 = (Tm1Slot *)tv->tm_slots;
    Packet *p = NULL;
    char run = 1;
    int r = 0;

    if (s1->Slot1Init != NULL) {
        r = s1->Slot1Init(tv, &s1->slot1_data);
        if (r != 0) {
            pthread_exit((void *) -1);
        }
    }

    while(run) {
        p = tv->tmqh_in(tv);

        r = s1->Slot1Func(tv, p, s1->slot1_data);
        /* XXX handle error */

        if (tv->flags & THV_KILL)
            run = 0;
    }

    if (s1->Slot1Deinit != NULL) {
        r = s1->Slot1Deinit(tv, s1->slot1_data);
        if (r != 0) {
            pthread_exit((void *) -1);
        }
    }

    pthread_exit((void *) 0);
}

void *TmThreadsSlot1NoInOut(void *td) {
    ThreadVars *tv = (ThreadVars *)td;
    Tm1Slot *s1 = (Tm1Slot *)tv->tm_slots;
    char run = 1;
    int r = 0;

    printf("TmThreadsSlot1NoInOut: %s starting\n", tv->name);

    if (s1->Slot1Init != NULL) {
        r = s1->Slot1Init(tv, &s1->slot1_data);
        if (r != 0) {
            pthread_exit((void *) -1);
        }
    }

    while(run) {
        r = s1->Slot1Func(tv, NULL, s1->slot1_data);
        //printf("%s: TmThreadsSlot1NoInNoOut: r %d\n", tv->name, r);
        /* XXX handle error */

        if (tv->flags & THV_KILL) {
            //printf("%s: TmThreadsSlot1NoInOut: KILL is set\n", tv->name);
            run = 0;
        }
    }

    if (s1->Slot1Deinit != NULL) {
        r = s1->Slot1Deinit(tv, s1->slot1_data);
        if (r != 0) {
            pthread_exit((void *) -1);
        }
    }

    printf("TmThreadsSlot1NoInOut: %s ending\n", tv->name);
    pthread_exit((void *) 0);
}

void *TmThreadsSlot1(void *td) {
    ThreadVars *tv = (ThreadVars *)td;
    Tm1Slot *s1 = (Tm1Slot *)tv->tm_slots;
    Packet *p = NULL;
    char run = 1;
    int r = 0;

    printf("TmThreadsSlot1: %s starting\n", tv->name);

    if (s1->Slot1Init != NULL) {
        r = s1->Slot1Init(tv, &s1->slot1_data);
        if (r != 0) {
            pthread_exit((void *) -1);
        }
    }

    while(run) {
        p = tv->tmqh_in(tv);
        if (p == NULL) {
            //printf("%s: TmThreadsSlot1: p == NULL\n", tv->name);
        } else {
            r = s1->Slot1Func(tv, p, s1->slot1_data);
            //printf("%s: TmThreadsSlot1: p %p, r %d\n", tv->name, p, r);
            /* XXX handle error */

            tv->tmqh_out(tv, p);
        }

        if (tv->flags & THV_KILL) {
            //printf("%s: TmThreadsSlot1: KILL is set\n", tv->name);
            run = 0;
        }
    }

    if (s1->Slot1Deinit != NULL) {
        r = s1->Slot1Deinit(tv, s1->slot1_data);
        if (r != 0) {
            pthread_exit((void *) -1);
        }
    }

    printf("TmThreadsSlot1: %s ending\n", tv->name);
    pthread_exit((void *) 0);
}

void *TmThreadsSlot2(void *td) {
    ThreadVars *tv = (ThreadVars *)td;
    Tm2Slot *s2 = (Tm2Slot *)tv->tm_slots;
    Packet *p = NULL;
    char run = 1;
    int r = 0;

    printf("TmThreadsSlot2: %s starting\n", tv->name);

    if (s2->Slot1Init != NULL) {
        r = s2->Slot1Init(tv, &s2->slot1_data);
        if (r != 0) {
            pthread_exit((void *) -1);
        }
    }
    if (s2->Slot2Init != NULL) {
	r = s2->Slot2Init(tv, &s2->slot2_data);
	if (r != 0) {
	    pthread_exit((void *) -1);
	}
    }

    while(run) {
        p = tv->tmqh_in(tv);
        if (p == NULL) {
            //printf("%s: TmThreadsSlot1: p == NULL\n", tv->name);
        } else {
            r = s2->Slot1Func(tv, p, s2->slot1_data);
            r = s2->Slot2Func(tv, p, s2->slot2_data);
            //printf("%s: TmThreadsSlot1: p %p, r %d\n", tv->name, p, r);
            /* XXX handle error */

            tv->tmqh_out(tv, p);
        }

        if (tv->flags & THV_KILL) {
            //printf("%s: TmThreadsSlot1: KILL is set\n", tv->name);
            run = 0;
        }
    }

    if (s2->Slot1Deinit != NULL) {
        r = s2->Slot1Deinit(tv, s2->slot1_data);
        if (r != 0) {
            pthread_exit((void *) -1);
        }
    }
    if (s2->Slot2Deinit != NULL) {
        r = s2->Slot2Deinit(tv, s2->slot2_data);
        if (r != 0) {
            pthread_exit((void *) -1);
        }
    }

    printf("TmThreadsSlot2: %s ending\n", tv->name);
    pthread_exit((void *) 0);
}

void *TmThreadsSlot3(void *td) {
    ThreadVars *tv = (ThreadVars *)td;
    Tm3Slot *s3 = (Tm3Slot *)tv->tm_slots;
    Packet *p = NULL;
    char run = 1;
    int r = 0;

    printf("TmThreadsSlot3: %s starting\n", tv->name);

    if (s3->Slot1Init != NULL) {
        r = s3->Slot1Init(tv, &s3->slot1_data);
        if (r != 0) {
            pthread_exit((void *) -1);
        }
    }
    if (s3->Slot2Init != NULL) {
	r = s3->Slot2Init(tv, &s3->slot2_data);
	if (r != 0) {
	    pthread_exit((void *) -1);
	}
    }
    if (s3->Slot3Init != NULL) {
	r = s3->Slot3Init(tv, &s3->slot3_data);
	if (r != 0) {
	    pthread_exit((void *) -1);
	}
    }

    while(run) {
        p = tv->tmqh_in(tv);
        if (p == NULL) {
            //printf("%s: TmThreadsSlot1: p == NULL\n", tv->name);
        } else {
            r = s3->Slot1Func(tv, p, s3->slot1_data);
            r = s3->Slot2Func(tv, p, s3->slot2_data);
            r = s3->Slot3Func(tv, p, s3->slot3_data);
            //printf("%s: TmThreadsSlot1: p %p, r %d\n", tv->name, p, r);
            /* XXX handle error */

            tv->tmqh_out(tv, p);
        }

        if (tv->flags & THV_KILL) {
            //printf("%s: TmThreadsSlot1: KILL is set\n", tv->name);
            run = 0;
        }
    }

    if (s3->Slot1Deinit != NULL) {
        r = s3->Slot1Deinit(tv, s3->slot1_data);
        if (r != 0) {
            pthread_exit((void *) -1);
        }
    }
    if (s3->Slot2Deinit != NULL) {
        r = s3->Slot2Deinit(tv, s3->slot2_data);
        if (r != 0) {
            pthread_exit((void *) -1);
        }
    }
    if (s3->Slot3Deinit != NULL) {
        r = s3->Slot3Deinit(tv, s3->slot3_data);
        if (r != 0) {
            pthread_exit((void *) -1);
        }
    }

    printf("TmThreadsSlot3: %s ending\n", tv->name);
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
    }

    tv->tm_slots = malloc(size);
    if (tv->tm_slots == NULL) goto error;
    memset(tv->tm_slots, 0, size);

    return 0;
error:
    return -1;
}

void Tm1SlotSetFunc(ThreadVars *tv, TmModule *tm) {
    Tm1Slot *s1 = (Tm1Slot *)tv->tm_slots;

    if (s1->Slot1Func != NULL)
        printf("Warning: slot 1 is already set tp %p, "
               "overwriting with %p\n", s1->Slot1Func, tm->Func);

    s1->Slot1Init = tm->Init;
    s1->Slot1Func = tm->Func;
    s1->Slot1Deinit = tm->Deinit;
}

void Tm2SlotSetFunc1(ThreadVars *tv, TmModule *tm) {
    Tm2Slot *s2 = (Tm2Slot *)tv->tm_slots;

    if (s2->Slot1Func != NULL)
        printf("Warning: slot 1 is already set tp %p, "
               "overwriting with %p\n", s2->Slot1Func, tm->Func);

    s2->Slot1Init = tm->Init;
    s2->Slot1Func = tm->Func;
    s2->Slot1Deinit = tm->Deinit;
}

void Tm2SlotSetFunc2(ThreadVars *tv, TmModule *tm) {
    Tm2Slot *s2 = (Tm2Slot *)tv->tm_slots;

    if (s2->Slot2Func != NULL)
        printf("Warning: slot 2 is already set tp %p, "
               "overwriting with %p\n", s2->Slot2Func, tm->Func);

    s2->Slot2Init = tm->Init;
    s2->Slot2Func = tm->Func;
    s2->Slot2Deinit = tm->Deinit;
}

void Tm3SlotSetFunc1(ThreadVars *tv, TmModule *tm) {
    Tm3Slot *s3 = (Tm3Slot *)tv->tm_slots;

    if (s3->Slot1Func != NULL)
        printf("Warning: slot 1 is already set tp %p, "
               "overwriting with %p\n", s3->Slot1Func, tm->Func);

    s3->Slot1Init = tm->Init;
    s3->Slot1Func = tm->Func;
    s3->Slot1Deinit = tm->Deinit;
}

void Tm3SlotSetFunc2(ThreadVars *tv, TmModule *tm) {
    Tm3Slot *s3 = (Tm3Slot *)tv->tm_slots;

    if (s3->Slot2Func != NULL)
        printf("Warning: slot 2 is already set tp %p, "
               "overwriting with %p\n", s3->Slot2Func, tm->Func);

    s3->Slot2Init = tm->Init;
    s3->Slot2Func = tm->Func;
    s3->Slot2Deinit = tm->Deinit;
}

void Tm3SlotSetFunc3(ThreadVars *tv, TmModule *tm) {
    Tm3Slot *s3 = (Tm3Slot *)tv->tm_slots;

    if (s3->Slot2Func != NULL)
        printf("Warning: slot 2 is already set tp %p, "
               "overwriting with %p\n", s3->Slot2Func, tm->Func);

    s3->Slot2Init = tm->Init;
    s3->Slot2Func = tm->Func;
    s3->Slot2Deinit = tm->Deinit;
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
        printf("TmThreadCreate: tv->inq->id %u\n", tv->inq->id);
    }
    if (inqh_name != NULL) {
        tmqh = TmqhGetQueueHandlerByName(inqh_name);
        if (tmqh == NULL) goto error;

        tv->tmqh_in = tmqh->InHandler;
        printf("TmThreadCreate: tv->tmqh_in %p\n", tv->tmqh_in);
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
        printf("TmThreadCreate: tv->outq->id %u\n", tv->outq->id);
    }
    if (outqh_name != NULL) {
        tmqh = TmqhGetQueueHandlerByName(outqh_name);
        if (tmqh == NULL) goto error;

        tv->tmqh_out = tmqh->OutHandler;
        printf("TmThreadCreate: tv->tmqh_out %p\n", tv->tmqh_out);
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

        printf("TmThreadAppend: thread \'%s\' is the first thread in the list.\n", tv->name);
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

    printf("TmThreadAppend: thread \'%s\' is added to the list.\n", tv->name);
}

void TmThreadKillThreads(void) {
    ThreadVars *t = tv_root;

    while (t) {
        t->flags |= THV_KILL;
        //printf("TmThreadKillThreads: told thread %s to stop\n", t->name);

        if (t->inq != NULL) {
            int i;

            //printf("TmThreadKillThreads: t->inq->usecnt %u\n", t->inq->usecnt);

            /* signal the queue for the number of users */
            for (i = 0; i < t->inq->usecnt; i++)
                pthread_cond_signal(&trans_q[t->inq->id].cond_q);
        }
        //printf("TmThreadKillThreads: signalled t->inq->id %u\n", t->inq->id);

        /* join it */
        pthread_join(t->t, NULL);
        //printf("TmThreadKillThreads: thread %s stopped\n", t->name);

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

