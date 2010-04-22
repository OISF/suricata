/* Copyright (C) 2007-2010 Open Information Security Foundation
 *
 * You can copy, redistribute or modify this Program under the terms of
 * the GNU General Public License version 2 as published by the Free
 * Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 */

/**
 * \file
 *
 * \author Victor Julien <victor@inliniac.net>
 * \author Anoop Saldanha <poonaatsoc@gmail.com>
 *
 * Thread management functions
 */

#include "suricata-common.h"
#include "suricata.h"
#include "stream.h"
#include "threadvars.h"
#include "tm-queues.h"
#include "tm-queuehandlers.h"
#include "tm-modules.h"
#include "tm-threads.h"
#include "tmqh-packetpool.h"
#include "threads.h"
#include "util-debug.h"
#include <pthread.h>
#include <unistd.h>
#include "util-privs.h"

#ifdef OS_FREEBSD
#include <sched.h>
#include <sys/param.h>
#include <sys/resource.h>
#include <sys/cpuset.h>
#include <sys/thr.h>
#define cpu_set_t cpuset_t
#elif OS_DARWIN
#include <mach/mach.h>
#include <mach/mach_init.h>
#include <mach/thread_policy.h>
#define cpu_set_t thread_affinity_policy_data_t
#define CPU_SET(cpu_id, new_mask) (*(new_mask)).affinity_tag = (cpu_id + 1)
#define CPU_ZERO(new_mask) (*(new_mask)).affinity_tag = THREAD_AFFINITY_TAG_NULL
#endif /* OS_FREEBSD */

/* prototypes */
static int SetCPUAffinity(uint16_t cpu);

/* root of the threadvars list */
ThreadVars *tv_root[TVT_MAX] = { NULL };

/* lock to protect tv_root */
SCMutex tv_root_lock = PTHREAD_MUTEX_INITIALIZER;

/* Action On Failure(AOF).  Determines how the engine should behave when a
   thread encounters a failure.  Defaults to restart the failed thread */
uint8_t tv_aof = THV_RESTART_THREAD;

typedef struct TmSlot_ {
    /* function pointers */
    TmEcode (*SlotFunc)(ThreadVars *, Packet *, void *, PacketQueue *);

    TmEcode (*SlotThreadInit)(ThreadVars *, void *, void **);
    void (*SlotThreadExitPrintStats)(ThreadVars *, void *);
    TmEcode (*SlotThreadDeinit)(ThreadVars *, void *);

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

/**
 *  \brief Check if a thread flag is set
 *
 *  \retval 1 flag is set
 *  \retval 0 flag is not set
 */
int TmThreadsCheckFlag(ThreadVars *tv, uint8_t flag) {
    int r;
    if (SCSpinLock(&(tv)->flags_spinlock) != 0) {
        SCLogError(SC_ERR_SPINLOCK,"spin lock errno=%d",errno);
        return 0;
    }
    r = (tv->flags & flag);
    SCSpinUnlock(&tv->flags_spinlock);
    return r;
}

/**
 *  \brief Set a thread flag
 */
void TmThreadsSetFlag(ThreadVars *tv, uint8_t flag) {
    if (SCSpinLock(&tv->flags_spinlock) != 0) {
        SCLogError(SC_ERR_SPINLOCK,"spin lock errno=%d",errno);
        return;
    }

    tv->flags |= flag;
    SCSpinUnlock(&tv->flags_spinlock);
}

/**
 *  \brief Unset a thread flag
 */
void TmThreadsUnsetFlag(ThreadVars *tv, uint8_t flag) {
    if (SCSpinLock(&tv->flags_spinlock) != 0) {
        SCLogError(SC_ERR_SPINLOCK,"spin lock errno=%d",errno);
        return;
    }

    tv->flags &= ~flag;
    SCSpinUnlock(&tv->flags_spinlock);
}

/* 1 slot functions */

void *TmThreadsSlot1NoIn(void *td) {
    ThreadVars *tv = (ThreadVars *)td;
    Tm1Slot *s = (Tm1Slot *)tv->tm_slots;
    Packet *p = NULL;
    char run = 1;
    TmEcode r = TM_ECODE_OK;

    /* Set the thread name */
    SCSetThreadName(tv->name);

    /* Drop the capabilities for this thread */
    SCDropCaps(tv);

    if (tv->thread_setup_flags != 0)
        TmThreadSetupOptions(tv);

    if (s->s.SlotThreadInit != NULL) {
        r = s->s.SlotThreadInit(tv, s->s.slot_initdata, &s->s.slot_data);
        if (r != TM_ECODE_OK) {
            EngineKill();

            TmThreadsSetFlag(tv, THV_CLOSED);
            pthread_exit((void *) -1);
        }
    }
    memset(&s->s.slot_pq, 0, sizeof(PacketQueue));

    TmThreadsSetFlag(tv, THV_INIT_DONE);

    while(run) {
        TmThreadTestThreadUnPaused(tv);

        r = s->s.SlotFunc(tv, p, s->s.slot_data, &s->s.slot_pq);
        /* handle error */
        if (r == TM_ECODE_FAILED) {
            TmqhReleasePacketsToPacketPool(&s->s.slot_pq);
            TmqhOutputPacketpool(tv, p);
            TmThreadsSetFlag(tv, THV_FAILED);
            break;
        }

        while (s->s.slot_pq.len > 0) {
            Packet *extra = PacketDequeue(&s->s.slot_pq);
            tv->tmqh_out(tv, extra);
        }

        tv->tmqh_out(tv, p);

        if (TmThreadsCheckFlag(tv, THV_KILL)) {
            SCPerfUpdateCounterArray(tv->sc_perf_pca, &tv->sc_perf_pctx, 0);
            run = 0;
        }
    }

    if (s->s.SlotThreadExitPrintStats != NULL) {
        s->s.SlotThreadExitPrintStats(tv, s->s.slot_data);
    }

    if (s->s.SlotThreadDeinit != NULL) {
        r = s->s.SlotThreadDeinit(tv, s->s.slot_data);
        if (r != TM_ECODE_OK) {
            TmThreadsSetFlag(tv, THV_CLOSED);
            pthread_exit((void *) -1);
        }
    }

    TmThreadsSetFlag(tv, THV_CLOSED);
    pthread_exit((void *) 0);
}

void *TmThreadsSlot1NoOut(void *td) {
    ThreadVars *tv = (ThreadVars *)td;
    Tm1Slot *s = (Tm1Slot *)tv->tm_slots;
    Packet *p = NULL;
    char run = 1;
    TmEcode r = TM_ECODE_OK;

    /* Set the thread name */
    SCSetThreadName(tv->name);

    /* Drop the capabilities for this thread */
    SCDropCaps(tv);

    if (tv->thread_setup_flags != 0)
        TmThreadSetupOptions(tv);

    if (s->s.SlotThreadInit != NULL) {
        r = s->s.SlotThreadInit(tv, s->s.slot_initdata, &s->s.slot_data);
        if (r != TM_ECODE_OK) {
            EngineKill();

            TmThreadsSetFlag(tv, THV_CLOSED);
            pthread_exit((void *) -1);
        }
    }
    memset(&s->s.slot_pq, 0, sizeof(PacketQueue));

    TmThreadsSetFlag(tv, THV_INIT_DONE);

    while(run) {
        TmThreadTestThreadUnPaused(tv);

        p = tv->tmqh_in(tv);

        r = s->s.SlotFunc(tv, p, s->s.slot_data, /* no outqh no pq */NULL);
        /* handle error */
        if (r == TM_ECODE_FAILED) {
            TmqhOutputPacketpool(tv, p);
            TmThreadsSetFlag(tv, THV_FAILED);
            break;
        }

        if (TmThreadsCheckFlag(tv, THV_KILL)) {
            SCPerfUpdateCounterArray(tv->sc_perf_pca, &tv->sc_perf_pctx, 0);
            run = 0;
        }
    }

    if (s->s.SlotThreadExitPrintStats != NULL) {
        s->s.SlotThreadExitPrintStats(tv, s->s.slot_data);
    }

    if (s->s.SlotThreadDeinit != NULL) {
        r = s->s.SlotThreadDeinit(tv, s->s.slot_data);
        if (r != TM_ECODE_OK) {
            TmThreadsSetFlag(tv, THV_CLOSED);
            pthread_exit((void *) -1);
        }
    }

    TmThreadsSetFlag(tv, THV_CLOSED);
    pthread_exit((void *) 0);
}

void *TmThreadsSlot1NoInOut(void *td) {
    ThreadVars *tv = (ThreadVars *)td;
    Tm1Slot *s = (Tm1Slot *)tv->tm_slots;
    char run = 1;
    TmEcode r = TM_ECODE_OK;

    /* Set the thread name */
    SCSetThreadName(tv->name);

    /* Drop the capabilities for this thread */
    SCDropCaps(tv);

    if (tv->thread_setup_flags != 0)
        TmThreadSetupOptions(tv);

    SCLogDebug("%s starting", tv->name);

    if (s->s.SlotThreadInit != NULL) {
        r = s->s.SlotThreadInit(tv, s->s.slot_initdata, &s->s.slot_data);
        if (r != TM_ECODE_OK) {
            EngineKill();

            TmThreadsSetFlag(tv, THV_CLOSED);
            pthread_exit((void *) -1);
        }
    }
    memset(&s->s.slot_pq, 0, sizeof(PacketQueue));

    TmThreadsSetFlag(tv, THV_INIT_DONE);

    while(run) {
        TmThreadTestThreadUnPaused(tv);

        r = s->s.SlotFunc(tv, NULL, s->s.slot_data, /* no outqh, no pq */NULL);
        //printf("%s: TmThreadsSlot1NoInNoOut: r %" PRId32 "\n", tv->name, r);

        /* handle error */
        if (r == TM_ECODE_FAILED) {
            TmThreadsSetFlag(tv, THV_FAILED);
            break;
        }

        if (TmThreadsCheckFlag(tv, THV_KILL)) {
            //printf("%s: TmThreadsSlot1NoInOut: KILL is set\n", tv->name);
            SCPerfUpdateCounterArray(tv->sc_perf_pca, &tv->sc_perf_pctx, 0);
            run = 0;
        }
    }

    if (s->s.SlotThreadExitPrintStats != NULL) {
        s->s.SlotThreadExitPrintStats(tv, s->s.slot_data);
    }

    if (s->s.SlotThreadDeinit != NULL) {
        r = s->s.SlotThreadDeinit(tv, s->s.slot_data);
        if (r != TM_ECODE_OK) {
            TmThreadsSetFlag(tv, THV_CLOSED);
            pthread_exit((void *) -1);
        }
    }

    //printf("TmThreadsSlot1NoInOut: %s ending\n", tv->name);
    TmThreadsSetFlag(tv, THV_CLOSED);
    pthread_exit((void *) 0);
}

void *TmThreadsSlot1(void *td) {
    ThreadVars *tv = (ThreadVars *)td;
    Tm1Slot *s = (Tm1Slot *)tv->tm_slots;
    Packet *p = NULL;
    char run = 1;
    TmEcode r = TM_ECODE_OK;

    /* Set the thread name */
    SCSetThreadName(tv->name);

    /* Drop the capabilities for this thread */
    SCDropCaps(tv);

    if (tv->thread_setup_flags != 0)
        TmThreadSetupOptions(tv);

    SCLogDebug("%s starting", tv->name);

    if (s->s.SlotThreadInit != NULL) {
        r = s->s.SlotThreadInit(tv, s->s.slot_initdata, &s->s.slot_data);
        if (r != TM_ECODE_OK) {
            EngineKill();

            TmThreadsSetFlag(tv, THV_CLOSED);
            pthread_exit((void *) -1);
        }
    }
    memset(&s->s.slot_pq, 0, sizeof(PacketQueue));

    TmThreadsSetFlag(tv, THV_INIT_DONE);
    while(run) {
        TmThreadTestThreadUnPaused(tv);

        /* input a packet */
        p = tv->tmqh_in(tv);

        if (p == NULL) {
            //printf("%s: TmThreadsSlot1: p == NULL\n", tv->name);
        } else {
            r = s->s.SlotFunc(tv, p, s->s.slot_data, &s->s.slot_pq);
            /* handle error */
            if (r == TM_ECODE_FAILED) {
                TmqhReleasePacketsToPacketPool(&s->s.slot_pq);
                TmqhOutputPacketpool(tv, p);
                TmThreadsSetFlag(tv, THV_FAILED);
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

        if (TmThreadsCheckFlag(tv, THV_KILL)) {
            //printf("%s: TmThreadsSlot1: KILL is set\n", tv->name);
            SCPerfUpdateCounterArray(tv->sc_perf_pca, &tv->sc_perf_pctx, 0);
            run = 0;
        }
    }

    if (s->s.SlotThreadExitPrintStats != NULL) {
        s->s.SlotThreadExitPrintStats(tv, s->s.slot_data);
    }

    if (s->s.SlotThreadDeinit != NULL) {
        r = s->s.SlotThreadDeinit(tv, s->s.slot_data);
        if (r != TM_ECODE_OK) {
            TmThreadsSetFlag(tv, THV_CLOSED);
            pthread_exit((void *) -1);
        }
    }

    SCLogDebug("%s ending", tv->name);
    TmThreadsSetFlag(tv, THV_CLOSED);
    pthread_exit((void *) 0);
}

/* separate run function so we can call it recursively */
static inline TmEcode TmThreadsSlotVarRun (ThreadVars *tv, Packet *p, TmSlot *slot) {
    TmEcode r = TM_ECODE_OK;
    TmSlot *s = NULL;

    for (s = slot; s != NULL; s = s->slot_next) {
        r = s->SlotFunc(tv, p, s->slot_data, &s->slot_pq);
        /* handle error */
        if (r == TM_ECODE_FAILED) {
            /* Encountered error.  Return packets to packetpool and return */
            TmqhReleasePacketsToPacketPool(&s->slot_pq);
            TmThreadsSetFlag(tv, THV_FAILED);
            return TM_ECODE_FAILED;
        }

        /* handle new packets */
        while (s->slot_pq.len > 0) {
            Packet *extra_p = PacketDequeue(&s->slot_pq);

            /* see if we need to process the packet */
            if (s->slot_next != NULL) {
                r = TmThreadsSlotVarRun(tv, extra_p, s->slot_next);
                /* XXX handle error */
                if (r == TM_ECODE_FAILED) {
                    //printf("TmThreadsSlotVarRun: recursive TmThreadsSlotVarRun returned 1\n");
                    TmqhReleasePacketsToPacketPool(&s->slot_pq);
                    TmqhOutputPacketpool(tv, extra_p);
                    TmThreadsSetFlag(tv, THV_FAILED);
                    return TM_ECODE_FAILED;
                }
            }
            tv->tmqh_out(tv, extra_p);
        }
    }

    return TM_ECODE_OK;
}

void *TmThreadsSlotVar(void *td) {
    ThreadVars *tv = (ThreadVars *)td;
    TmVarSlot *s = (TmVarSlot *)tv->tm_slots;
    Packet *p = NULL;
    char run = 1;
    TmEcode r = TM_ECODE_OK;
    TmSlot *slot = NULL;

    /* Set the thread name */
    SCSetThreadName(tv->name);

    /* Drop the capabilities for this thread */
    SCDropCaps(tv);

    if (tv->thread_setup_flags != 0)
        TmThreadSetupOptions(tv);

    //printf("TmThreadsSlot1: %s starting\n", tv->name);

    for (slot = s->s; slot != NULL; slot = slot->slot_next) {
        if (slot->SlotThreadInit != NULL) {
            r = slot->SlotThreadInit(tv, slot->slot_initdata, &slot->slot_data);
            if (r != TM_ECODE_OK) {
                EngineKill();

                TmThreadsSetFlag(tv, THV_CLOSED);
                pthread_exit((void *) -1);
            }
        }
        memset(&slot->slot_pq, 0, sizeof(PacketQueue));
    }

    TmThreadsSetFlag(tv, THV_INIT_DONE);

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
            if (r == TM_ECODE_FAILED) {
                //printf("TmThreadsSlotVar: TmThreadsSlotVarRun returned 1, breaking out of the loop.\n");
                TmqhOutputPacketpool(tv, p);
                TmThreadsSetFlag(tv, THV_FAILED);
                break;
            }

            /* output the packet */
            tv->tmqh_out(tv, p);
        }

        if (TmThreadsCheckFlag(tv, THV_KILL)) {
            //printf("%s: TmThreadsSlot1: KILL is set\n", tv->name);
            SCPerfUpdateCounterArray(tv->sc_perf_pca, &tv->sc_perf_pctx, 0);
            run = 0;
        }
    }

    for (slot = s->s; slot != NULL; slot = slot->slot_next) {
        if (slot->SlotThreadExitPrintStats != NULL) {
            slot->SlotThreadExitPrintStats(tv, slot->slot_data);
        }

        if (slot->SlotThreadDeinit != NULL) {
            r = slot->SlotThreadDeinit(tv, slot->slot_data);
            if (r != TM_ECODE_OK) {
                TmThreadsSetFlag(tv, THV_CLOSED);
                pthread_exit((void *) -1);
            }
        }
    }

    SCLogDebug("%s ending", tv->name);
    TmThreadsSetFlag(tv, THV_CLOSED);
    pthread_exit((void *) 0);
}

TmEcode TmThreadSetSlots(ThreadVars *tv, char *name, void *(*fn_p)(void *)) {
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
        return TM_ECODE_OK;
    } else {
        printf("Error: Slot \"%s\" not supported\n", name);
        goto error;
    }

    tv->tm_slots = SCMalloc(size);
    if (tv->tm_slots == NULL)
        goto error;
    memset(tv->tm_slots, 0, size);

    return TM_ECODE_OK;
error:
    return TM_ECODE_FAILED;
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
    tv->cap_flags |= tm->cap_flags;
}

void TmVarSlotSetFuncAppend(ThreadVars *tv, TmModule *tm, void *data) {
    TmVarSlot *s = (TmVarSlot *)tv->tm_slots;
    TmSlot *slot = SCMalloc(sizeof(TmSlot));
    if (slot == NULL)
        return;

    memset(slot, 0, sizeof(TmSlot));

    slot->SlotThreadInit = tm->ThreadInit;
    slot->slot_initdata = data;
    slot->SlotFunc = tm->Func;
    slot->SlotThreadExitPrintStats = tm->ThreadExitPrintStats;
    slot->SlotThreadDeinit = tm->ThreadDeinit;
    tv->cap_flags |= tm->cap_flags;

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

/**
 * \brief Set the thread affinity on the calling thread
 * \param cpuid id of the core/cpu to setup the affinity
 * \retval 0 if all goes well; -1 if something is wrong
 */
static int SetCPUAffinity(uint16_t cpuid) {

    int cpu = (int)cpuid;

#ifdef OS_WIN32
	DWORD cs = 1 << cpu;
#else
    cpu_set_t cs;

    CPU_ZERO(&cs);
    CPU_SET(cpu,&cs);
#endif /* OS_WIN32 */

#ifdef OS_FREEBSD
    int r = cpuset_setaffinity(CPU_LEVEL_WHICH,CPU_WHICH_TID,SCGetThreadIdLong(),sizeof(cpu_set_t),&cs);
#elif OS_DARWIN
    int r = thread_policy_set(mach_thread_self(), THREAD_AFFINITY_POLICY, (void*)&cs, THREAD_AFFINITY_POLICY_COUNT);
#elif OS_WIN32
	int r = (0 == SetThreadAffinityMask(GetCurrentThread(), cs));
#else
    pid_t tid = syscall(SYS_gettid);
    int r = sched_setaffinity(tid,sizeof(cpu_set_t),&cs);
#endif /* OS_FREEBSD */

    if (r != 0) {
        printf("Warning: sched_setaffinity failed (%" PRId32 "): %s\n", r, strerror(errno));
        return -1;
    }
    SCLogDebug("CPU Affinity for thread %lu set to CPU %" PRId32, SCGetThreadIdLong(), cpu);

    return 0;
}


/**
 * \brief Set the thread options (thread priority)
 * \param tv pointer to the ThreadVars to setup the thread priority
 * \retval TM_ECOE_OK
 */
TmEcode TmThreadSetThreadPriority(ThreadVars *tv, int prio) {
    tv->thread_setup_flags |= THREAD_SET_PRIORITY;
    tv->thread_priority = prio;
    return TM_ECODE_OK;
}

/**
 * \brief Adjusting nice value for threads
 */
void TmThreadSetPrio(ThreadVars *tv)
{
    SCEnter();
#ifdef OS_WIN32
	if (0 == SetThreadPriority(GetCurrentThread(), tv->thread_priority)) {
        SCLogError(SC_ERR_THREAD_NICE_PRIO, "Error setting priority for thread %s: %s", tv->name, strerror(errno));
    } else {
        SCLogDebug("Priority set to %"PRId32" for thread %s", tv->thread_priority, tv->name);
    }
#else
    int ret = nice(tv->thread_priority);
    if (ret == -1) {
        SCLogError(SC_ERR_THREAD_NICE_PRIO, "Error setting nice value for thread %s: %s", tv->name, strerror(errno));
    } else {
        SCLogDebug("Nice value set to %"PRId32" for thread %s", tv->thread_priority, tv->name);
    }
#endif /* OS_WIN32 */
    SCReturn;
}


/**
 * \brief Set the thread options (cpu affinity)
 * \param tv pointer to the ThreadVars to setup the affinity
 * \retval TM_ECOE_OK
 */
TmEcode TmThreadSetCPUAffinity(ThreadVars *tv, uint16_t cpu) {
    tv->thread_setup_flags |= THREAD_SET_AFFINITY;
    tv->cpu_affinity = cpu;
    return TM_ECODE_OK;
}

/**
 * \brief Set the thread options (cpu affinitythread)
 *        Priority should be already set by pthread_create
 * \param tv pointer to the ThreadVars of the calling thread
 */
TmEcode TmThreadSetupOptions(ThreadVars *tv) {
    if (tv->thread_setup_flags & THREAD_SET_AFFINITY) {
        SCLogInfo("Setting affinity for \"%s\" Module to cpu/core %"PRIu16", thread id %lu", tv->name, tv->cpu_affinity, SCGetThreadIdLong());
        SetCPUAffinity(tv->cpu_affinity);
    }
    TmThreadSetPrio(tv);
    return TM_ECODE_OK;
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

    SCLogDebug("creating thread \"%s\"...", name);

    /* XXX create separate function for this: allocate a thread container */
    tv = SCMalloc(sizeof(ThreadVars));
    if (tv == NULL)
        goto error;
    memset(tv, 0, sizeof(ThreadVars));

    SCSpinInit(&tv->flags_spinlock, PTHREAD_PROCESS_PRIVATE);
    SCMutexInit(&tv->sc_perf_pctx.m, NULL);

    tv->name = name;
    /* default state for every newly created thread */
    TmThreadsSetFlag(tv, THV_PAUSE);
    TmThreadsSetFlag(tv, THV_USE);
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

    if (TmThreadSetSlots(tv, slots, fn_p) != TM_ECODE_OK) {
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
    SCMutexLock(&tv_root_lock);

    if (tv_root[type] == NULL) {
        tv_root[type] = tv;
        tv->next = NULL;
        tv->prev = NULL;

        //printf("TmThreadAppend: thread \'%s\' is the first thread in the list.\n", tv->name);
        SCMutexUnlock(&tv_root_lock);
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

    SCMutexUnlock(&tv_root_lock);
    //printf("TmThreadAppend: thread \'%s\' is added to the list.\n", tv->name);
}

/**
 * \brief Removes this TV from tv_root based on its type
 *
 * \param tv   The tv instance to remove from the global tv list.
 * \param type Holds the type this TV belongs to.
 */
void TmThreadRemove(ThreadVars *tv, int type)
{
    SCMutexLock(&tv_root_lock);

    if (tv_root[type] == NULL) {
        SCMutexUnlock(&tv_root_lock);
        return;
    }

    ThreadVars *t = tv_root[type];
    while (t != tv) {
        t = t->next;
    }

    if (t != NULL) {
        if (t->prev != NULL)
            t->prev->next = t->next;
        if (t->next != NULL)
            t->next->prev = t->prev;

    if (t == tv_root[type])
        tv_root[type] = t->next;;
    }

    SCMutexUnlock(&tv_root_lock);

    return;
}

/**
 * \brief Kill a thread.
 *
 * \param tv A ThreadVars instance corresponding to the thread that has to be
 *           killed.
 */
void TmThreadKillThread(ThreadVars *tv)
{
    int i = 0;

    if (tv == NULL)
        return;

    /* set the thread flag informing the thread that it needs to be
     * terminated */
    TmThreadsSetFlag(tv, THV_KILL);

    if (tv->inq != NULL) {
        /* signal the queue for the number of users */
        for (i = 0; i < (tv->inq->reader_cnt + tv->inq->writer_cnt); i++)
            SCCondSignal(&trans_q[tv->inq->id].cond_q);

        /* to be sure, signal more */
        while (1) {
            if (TmThreadsCheckFlag(tv, THV_CLOSED)) {
                break;
            }

            for (i = 0; i < (tv->inq->reader_cnt + tv->inq->writer_cnt); i++)
                SCCondSignal(&trans_q[tv->inq->id].cond_q);

            usleep(100);
        }
    }

    if (tv->cond != NULL ) {
        while (1) {
            if (TmThreadsCheckFlag(tv, THV_CLOSED)) {
                break;
            }

            pthread_cond_broadcast(tv->cond);

            usleep(100);
        }
    }

    return;
}

void TmThreadKillThreads(void) {
    ThreadVars *tv = NULL;
    int i = 0;

    for (i = 0; i < TVT_MAX; i++) {
        tv = tv_root[i];


        while (tv) {
            TmThreadsSetFlag(tv, THV_KILL);
            SCLogDebug("told thread %s to stop", tv->name);

            /* XXX hack */
            StreamMsgSignalQueueHack();

            if (tv->inq != NULL) {
                int i;

                //printf("TmThreadKillThreads: (t->inq->reader_cnt + t->inq->writer_cnt) %" PRIu32 "\n", (t->inq->reader_cnt + t->inq->writer_cnt));

                /* make sure our packet pending counter doesn't block */
                //SCCondSignal(&cond_pending);

                /* signal the queue for the number of users */

                for (i = 0; i < (tv->inq->reader_cnt + tv->inq->writer_cnt); i++)
                    SCCondSignal(&trans_q[tv->inq->id].cond_q);

                /* to be sure, signal more */
                int cnt = 0;
                while (1) {
                    if (TmThreadsCheckFlag(tv, THV_CLOSED)) {
                        SCLogDebug("signalled the thread %" PRId32 " times", cnt);
                        break;
                    }

                    cnt++;

                    for (i = 0; i < (tv->inq->reader_cnt + tv->inq->writer_cnt); i++)
                        SCCondSignal(&trans_q[tv->inq->id].cond_q);

                    usleep(100);
                }

                SCLogDebug("signalled tv->inq->id %" PRIu32 "", tv->inq->id);
            }

            if (tv->cond != NULL ) {
                int cnt = 0;
                while (1) {
                    if (TmThreadsCheckFlag(tv, THV_CLOSED)) {
                        SCLogDebug("signalled the thread %" PRId32 " times", cnt);
                        break;
                    }

                    cnt++;

                    pthread_cond_broadcast(tv->cond);

                    usleep(100);
                }
            }

            /* join it */
            pthread_join(tv->t, NULL);
            SCLogDebug("thread %s stopped", tv->name);

            tv = tv->next;
        }
    }
}

/**
 * \brief Spawns a thread associated with the ThreadVars instance tv
 *
 * \retval TM_ECODE_OK on success and TM_ECODE_FAILED on failure
 */
TmEcode TmThreadSpawn(ThreadVars *tv)
{
    pthread_attr_t attr;
    if (tv->tm_func == NULL) {
        printf("ERROR: no thread function set\n");
        return TM_ECODE_FAILED;
    }

    /* Initialize and set thread detached attribute */
    pthread_attr_init(&attr);

    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE);

    int rc = pthread_create(&tv->t, &attr, tv->tm_func, (void *)tv);
    if (rc) {
        printf("ERROR; return code from pthread_create() is %" PRId32 "\n", rc);
        return TM_ECODE_FAILED;
    }

    TmThreadAppend(tv, tv->type);

    return TM_ECODE_OK;
}

/**
 * \brief Sets the thread flags for a thread instance(tv)
 *
 * \param tv    Pointer to the thread instance for which the flag has to be set
 * \param flags Holds the thread state this thread instance has to be set to
 */
#if 0
void TmThreadSetFlags(ThreadVars *tv, uint8_t flags)
{
    if (tv != NULL)
        tv->flags = flags;

    return;
}
#endif
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
    if ( (tv->m = SCMalloc(sizeof(SCMutex))) == NULL) {
        SCLogError(SC_ERR_FATAL, "Fatal error encountered in TmThreadInitMC. Exiting...");
        exit(EXIT_FAILURE);
    }

    if (SCMutexInit(tv->m, NULL) != 0) {
        printf("Error initializing the tv->m mutex\n");
        exit(0);
    }

    if ( (tv->cond = SCMalloc(sizeof(SCCondT))) == NULL) {
        SCLogError(SC_ERR_FATAL, "Fatal error encountered in TmThreadInitMC. Exiting...");
        exit(0);
    }

    if (SCCondInit(tv->cond, NULL) != 0) {
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
    while (TmThreadsCheckFlag(tv, THV_PAUSE)) {
        usleep(100);

        if (TmThreadsCheckFlag(tv, THV_KILL))
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
    TmThreadsUnsetFlag(tv, THV_PAUSE);
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
    TmThreadsSetFlag(tv, THV_PAUSE);
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
               "\"%s\"\n", tv->name);
        /* makes sense to reset the tv_aof to engine_exit?! */
        // tv->aof = THV_ENGINE_EXIT;
        return;
    }

    TmThreadsUnsetFlag(tv, THV_CLOSED);
    TmThreadsUnsetFlag(tv, THV_FAILED);

    if (TmThreadSpawn(tv) != TM_ECODE_OK) {
        SCLogError(SC_ERR_THREAD_SPAWN, "thread \"%s\" failed to spawn", tv->name);
        exit(EXIT_FAILURE);
    }

    tv->restarted++;
    SCLogInfo("thread \"%s\" restarted\n", tv->name);

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
            if (TmThreadsCheckFlag(tv, THV_FAILED)) {
                pthread_join(tv->t, NULL);
                if ( !(tv_aof & THV_ENGINE_EXIT) &&
                     (tv->aof & THV_RESTART_THREAD) ) {
                    TmThreadRestartThread(tv);
                } else {
                    TmThreadsSetFlag(tv, THV_CLOSED);
                    EngineKill();
                }
            }
            tv = tv->next;
        }
    }

    return;
}

/**
 *  \brief Used to check if all threads have finished their initialization.  On
 *         finding an un-initialized thread, it waits till that thread completes
 *         its initialization, before proceeding to the next thread.
 *
 *  \retval TM_ECODE_OK all initialized properly
 *  \retval TM_ECODE_FAILED failure
 */
TmEcode TmThreadWaitOnThreadInit(void)
{
    ThreadVars *tv = NULL;
    int i = 0;
    uint16_t mgt_num = 0;
    uint16_t ppt_num = 0;

    for (i = 0; i < TVT_MAX; i++) {
        tv = tv_root[i];
        while (tv != NULL) {
            char started = FALSE;
            while (started == FALSE) {
                if (TmThreadsCheckFlag(tv, THV_INIT_DONE)) {
                    started = TRUE;
                }

                if (TmThreadsCheckFlag(tv, THV_FAILED)) {
                    SCLogError(SC_ERR_THREAD_INIT, "thread \"%s\" failed to "
                            "initialize.", tv->name);
                    return TM_ECODE_FAILED;
                }
                if (TmThreadsCheckFlag(tv, THV_CLOSED)) {
                    SCLogError(SC_ERR_THREAD_INIT, "thread \"%s\" closed on "
                            "initialization.", tv->name);
                    return TM_ECODE_FAILED;
                }
            }

            if (i == TVT_MGMT) mgt_num++;
            else if (i == TVT_PPT) ppt_num++;

            tv = tv->next;
        }
    }

    SCLogInfo("all %"PRIu16" packet processing threads, %"PRIu16" management "
           "threads initialized, engine started.", ppt_num, mgt_num);
    return TM_ECODE_OK;
}

/**
 * \brief Returns the TV for the calling thread.
 *
 * \retval tv Pointer to the ThreadVars instance for the calling thread;
 *            NULL on no match
 */
ThreadVars *TmThreadsGetCallingThread(void)
{
    pthread_t self = pthread_self();
    ThreadVars *tv = NULL;
    int i = 0;

    SCMutexLock(&tv_root_lock);

    for (i = 0; i < TVT_MAX; i++) {
        tv = tv_root[i];
        while (tv) {
            if (pthread_equal(self, tv->t)) {
                SCMutexUnlock(&tv_root_lock);
                return tv;
            }
            tv = tv->next;
        }
    }

    SCMutexUnlock(&tv_root_lock);

    return NULL;
}
