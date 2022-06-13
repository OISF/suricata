/* Copyright (C) 2007-2022 Open Information Security Foundation
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
 * \author Anoop Saldanha <anoopsaldanha@gmail.com>
 * \author Eric Leblond <eric@regit.org>
 *
 * Thread management functions.
 */

#include "suricata-common.h"
#include "suricata.h"
#include "stream.h"
#include "runmodes.h"
#include "threadvars.h"
#include "tm-queues.h"
#include "tm-queuehandlers.h"
#include "tm-threads.h"
#include "tmqh-packetpool.h"
#include "threads.h"
#include "util-debug.h"
#include "util-privs.h"
#include "util-cpu.h"
#include "util-optimize.h"
#include "util-profiling.h"
#include "util-signal.h"
#include "queue.h"

#ifdef PROFILE_LOCKING
thread_local uint64_t mutex_lock_contention;
thread_local uint64_t mutex_lock_wait_ticks;
thread_local uint64_t mutex_lock_cnt;

thread_local uint64_t spin_lock_contention;
thread_local uint64_t spin_lock_wait_ticks;
thread_local uint64_t spin_lock_cnt;

thread_local uint64_t rww_lock_contention;
thread_local uint64_t rww_lock_wait_ticks;
thread_local uint64_t rww_lock_cnt;

thread_local uint64_t rwr_lock_contention;
thread_local uint64_t rwr_lock_wait_ticks;
thread_local uint64_t rwr_lock_cnt;
#endif

#ifdef OS_FREEBSD
#include <sched.h>
#include <sys/param.h>
#include <sys/resource.h>
#include <sys/cpuset.h>
#include <sys/thr.h>
#define cpu_set_t cpuset_t
#endif /* OS_FREEBSD */

/* prototypes */
static int SetCPUAffinity(uint16_t cpu);
static void TmThreadDeinitMC(ThreadVars *tv);

/* root of the threadvars list */
ThreadVars *tv_root[TVT_MAX] = { NULL };

/* lock to protect tv_root */
SCMutex tv_root_lock = SCMUTEX_INITIALIZER;

/**
 * \brief Check if a thread flag is set.
 *
 * \retval 1 flag is set.
 * \retval 0 flag is not set.
 */
int TmThreadsCheckFlag(ThreadVars *tv, uint32_t flag)
{
    return (SC_ATOMIC_GET(tv->flags) & flag) ? 1 : 0;
}

/**
 * \brief Set a thread flag.
 */
void TmThreadsSetFlag(ThreadVars *tv, uint32_t flag)
{
    SC_ATOMIC_OR(tv->flags, flag);
}

/**
 * \brief Unset a thread flag.
 */
void TmThreadsUnsetFlag(ThreadVars *tv, uint32_t flag)
{
    SC_ATOMIC_AND(tv->flags, ~flag);
}

/**
 * \brief Separate run function so we can call it recursively.
 */
TmEcode TmThreadsSlotVarRun(ThreadVars *tv, Packet *p, TmSlot *slot)
{
    for (TmSlot *s = slot; s != NULL; s = s->slot_next) {
        PACKET_PROFILING_TMM_START(p, s->tm_id);
        TmEcode r = s->SlotFunc(tv, p, SC_ATOMIC_GET(s->slot_data));
        PACKET_PROFILING_TMM_END(p, s->tm_id);

        /* handle error */
        if (unlikely(r == TM_ECODE_FAILED)) {
            /* Encountered error.  Return packets to packetpool and return */
            TmThreadsSlotProcessPktFail(tv, s, NULL);
            return TM_ECODE_FAILED;
        }

        /* handle new packets */
        while (tv->decode_pq.top != NULL) {
            Packet *extra_p = PacketDequeueNoLock(&tv->decode_pq);
            if (unlikely(extra_p == NULL))
                continue;

            /* see if we need to process the packet */
            if (s->slot_next != NULL) {
                r = TmThreadsSlotVarRun(tv, extra_p, s->slot_next);
                if (unlikely(r == TM_ECODE_FAILED)) {
                    TmThreadsSlotProcessPktFail(tv, s, extra_p);
                    return TM_ECODE_FAILED;
                }
            }
            tv->tmqh_out(tv, extra_p);
        }
    }

    return TM_ECODE_OK;
}

/** \internal
 *
 *  \brief Process flow timeout packets
 *
 *  Process flow timeout pseudo packets. During shutdown this loop
 *  is run until the flow engine kills the thread and the queue is
 *  empty.
 */
static int TmThreadTimeoutLoop(ThreadVars *tv, TmSlot *s)
{
    TmSlot *fw_slot = tv->tm_flowworker;
    int r = TM_ECODE_OK;

    if (tv->stream_pq == NULL || fw_slot == NULL) {
        SCLogDebug("not running TmThreadTimeoutLoop %p/%p", tv->stream_pq, fw_slot);
        return r;
    }

    SCLogDebug("flow end loop starting");
    while (1) {
        SCMutexLock(&tv->stream_pq->mutex_q);
        uint32_t len = tv->stream_pq->len;
        SCMutexUnlock(&tv->stream_pq->mutex_q);
        if (len > 0) {
            while (len--) {
                SCMutexLock(&tv->stream_pq->mutex_q);
                Packet *p = PacketDequeue(tv->stream_pq);
                SCMutexUnlock(&tv->stream_pq->mutex_q);
                if (likely(p)) {
                    if ((r = TmThreadsSlotProcessPkt(tv, fw_slot, p) != TM_ECODE_OK)) {
                        if (r == TM_ECODE_FAILED)
                            break;
                    }
                }
            }
        } else {
            if (TmThreadsCheckFlag(tv, THV_KILL)) {
                break;
            }
            SleepUsec(1);
        }
    }
    SCLogDebug("flow end loop complete");
    StatsSyncCounters(tv);

    return r;
}

/*

    pcap/nfq

    pkt read
        callback
            process_pkt

    pfring

    pkt read
        process_pkt

    slot:
        setup

        pkt_ack_loop(tv, slot_data)

        deinit

    process_pkt:
        while(s)
            run s;
        queue;

 */

static void *TmThreadsSlotPktAcqLoop(void *td)
{
    ThreadVars *tv = (ThreadVars *)td;
    TmSlot *s = tv->tm_slots;
    char run = 1;
    TmEcode r = TM_ECODE_OK;
    TmSlot *slot = NULL;

    SCSetThreadName(tv->name);

    if (tv->thread_setup_flags != 0)
        TmThreadSetupOptions(tv);

    /* Drop the capabilities for this thread */
    SCDropCaps(tv);

    PacketPoolInit();

    /* check if we are setup properly */
    if (s == NULL || s->PktAcqLoop == NULL || tv->tmqh_in == NULL || tv->tmqh_out == NULL) {
        SCLogError(SC_ERR_FATAL, "TmSlot or ThreadVars badly setup: s=%p,"
                                 " PktAcqLoop=%p, tmqh_in=%p,"
                                 " tmqh_out=%p",
                   s, s ? s->PktAcqLoop : NULL, tv->tmqh_in, tv->tmqh_out);
        TmThreadsSetFlag(tv, THV_CLOSED | THV_RUNNING_DONE);
        pthread_exit((void *) -1);
        return NULL;
    }

    for (slot = s; slot != NULL; slot = slot->slot_next) {
        if (slot->SlotThreadInit != NULL) {
            void *slot_data = NULL;
            r = slot->SlotThreadInit(tv, slot->slot_initdata, &slot_data);
            if (r != TM_ECODE_OK) {
                if (r == TM_ECODE_DONE) {
                    EngineDone();
                    TmThreadsSetFlag(tv, THV_CLOSED | THV_INIT_DONE | THV_RUNNING_DONE);
                    goto error;
                } else {
                    TmThreadsSetFlag(tv, THV_CLOSED | THV_RUNNING_DONE);
                    goto error;
                }
            }
            (void)SC_ATOMIC_SET(slot->slot_data, slot_data);
        }

        /* if the flowworker module is the first, get the threads input queue */
        if (slot == (TmSlot *)tv->tm_slots && (slot->tm_id == TMM_FLOWWORKER)) {
            tv->stream_pq = tv->inq->pq;
            tv->tm_flowworker = slot;
            SCLogDebug("pre-stream packetqueue %p (inq)", tv->stream_pq);
            tv->flow_queue = FlowQueueNew();
            if (tv->flow_queue == NULL) {
                TmThreadsSetFlag(tv, THV_CLOSED | THV_RUNNING_DONE);
                pthread_exit((void *) -1);
                return NULL;
            }
        /* setup a queue */
        } else if (slot->tm_id == TMM_FLOWWORKER) {
            tv->stream_pq_local = SCCalloc(1, sizeof(PacketQueue));
            if (tv->stream_pq_local == NULL)
                FatalError(SC_ERR_MEM_ALLOC, "failed to alloc PacketQueue");
            SCMutexInit(&tv->stream_pq_local->mutex_q, NULL);
            tv->stream_pq = tv->stream_pq_local;
            tv->tm_flowworker = slot;
            SCLogDebug("pre-stream packetqueue %p (local)", tv->stream_pq);
            tv->flow_queue = FlowQueueNew();
            if (tv->flow_queue == NULL) {
                TmThreadsSetFlag(tv, THV_CLOSED | THV_RUNNING_DONE);
                pthread_exit((void *) -1);
                return NULL;
            }
        }
    }

    StatsSetupPrivate(tv);

    TmThreadsSetFlag(tv, THV_INIT_DONE);

    while(run) {
        if (TmThreadsCheckFlag(tv, THV_PAUSE)) {
            TmThreadsSetFlag(tv, THV_PAUSED);
            TmThreadTestThreadUnPaused(tv);
            TmThreadsUnsetFlag(tv, THV_PAUSED);
        }

        r = s->PktAcqLoop(tv, SC_ATOMIC_GET(s->slot_data), s);

        if (r == TM_ECODE_FAILED) {
            TmThreadsSetFlag(tv, THV_FAILED);
            run = 0;
        }
        if (TmThreadsCheckFlag(tv, THV_KILL_PKTACQ) || suricata_ctl_flags) {
            run = 0;
        }
        if (r == TM_ECODE_DONE) {
            run = 0;
        }
    }
    StatsSyncCounters(tv);

    TmThreadsSetFlag(tv, THV_FLOW_LOOP);

    /* process all pseudo packets the flow timeout may throw at us */
    TmThreadTimeoutLoop(tv, s);

    TmThreadsSetFlag(tv, THV_RUNNING_DONE);
    TmThreadWaitForFlag(tv, THV_DEINIT);

    PacketPoolDestroy();

    for (slot = s; slot != NULL; slot = slot->slot_next) {
        if (slot->SlotThreadExitPrintStats != NULL) {
            slot->SlotThreadExitPrintStats(tv, SC_ATOMIC_GET(slot->slot_data));
        }

        if (slot->SlotThreadDeinit != NULL) {
            r = slot->SlotThreadDeinit(tv, SC_ATOMIC_GET(slot->slot_data));
            if (r != TM_ECODE_OK) {
                TmThreadsSetFlag(tv, THV_CLOSED);
                goto error;
            }
        }
    }

    tv->stream_pq = NULL;
    SCLogDebug("%s ending", tv->name);
    TmThreadsSetFlag(tv, THV_CLOSED);
    pthread_exit((void *) 0);
    return NULL;

error:
    tv->stream_pq = NULL;
    pthread_exit((void *) -1);
    return NULL;
}

static void *TmThreadsSlotVar(void *td)
{
    ThreadVars *tv = (ThreadVars *)td;
    TmSlot *s = (TmSlot *)tv->tm_slots;
    Packet *p = NULL;
    char run = 1;
    TmEcode r = TM_ECODE_OK;

    PacketPoolInit();//Empty();

    SCSetThreadName(tv->name);

    if (tv->thread_setup_flags != 0)
        TmThreadSetupOptions(tv);

    /* Drop the capabilities for this thread */
    SCDropCaps(tv);

    /* check if we are setup properly */
    if (s == NULL || tv->tmqh_in == NULL || tv->tmqh_out == NULL) {
        TmThreadsSetFlag(tv, THV_CLOSED | THV_RUNNING_DONE);
        pthread_exit((void *) -1);
        return NULL;
    }

    for (; s != NULL; s = s->slot_next) {
        if (s->SlotThreadInit != NULL) {
            void *slot_data = NULL;
            r = s->SlotThreadInit(tv, s->slot_initdata, &slot_data);
            if (r != TM_ECODE_OK) {
                TmThreadsSetFlag(tv, THV_CLOSED | THV_RUNNING_DONE);
                goto error;
            }
            (void)SC_ATOMIC_SET(s->slot_data, slot_data);
        }

        /* special case: we need to access the stream queue
         * from the flow timeout code */

        /* if the flowworker module is the first, get the threads input queue */
        if (s == (TmSlot *)tv->tm_slots && (s->tm_id == TMM_FLOWWORKER)) {
            tv->stream_pq = tv->inq->pq;
            tv->tm_flowworker = s;
            SCLogDebug("pre-stream packetqueue %p (inq)", tv->stream_pq);
            tv->flow_queue = FlowQueueNew();
            if (tv->flow_queue == NULL) {
                TmThreadsSetFlag(tv, THV_CLOSED | THV_RUNNING_DONE);
                pthread_exit((void *) -1);
                return NULL;
            }
        /* setup a queue */
        } else if (s->tm_id == TMM_FLOWWORKER) {
            tv->stream_pq_local = SCCalloc(1, sizeof(PacketQueue));
            if (tv->stream_pq_local == NULL)
                FatalError(SC_ERR_MEM_ALLOC, "failed to alloc PacketQueue");
            SCMutexInit(&tv->stream_pq_local->mutex_q, NULL);
            tv->stream_pq = tv->stream_pq_local;
            tv->tm_flowworker = s;
            SCLogDebug("pre-stream packetqueue %p (local)", tv->stream_pq);
            tv->flow_queue = FlowQueueNew();
            if (tv->flow_queue == NULL) {
                TmThreadsSetFlag(tv, THV_CLOSED | THV_RUNNING_DONE);
                pthread_exit((void *) -1);
                return NULL;
            }
        }
    }

    StatsSetupPrivate(tv);

    // Each 'worker' thread uses this func to process/decode the packet read.
    // Each decode method is different to receive methods in that they do not
    // enter infinite loops. They use this as the core loop. As a result, at this
    // point the worker threads can be considered both initialized and running.
    TmThreadsSetFlag(tv, THV_INIT_DONE | THV_RUNNING);

    s = (TmSlot *)tv->tm_slots;

    while (run) {
        if (TmThreadsCheckFlag(tv, THV_PAUSE)) {
            TmThreadsSetFlag(tv, THV_PAUSED);
            TmThreadTestThreadUnPaused(tv);
            TmThreadsUnsetFlag(tv, THV_PAUSED);
        }

        /* input a packet */
        p = tv->tmqh_in(tv);

        /* if we didn't get a packet see if we need to do some housekeeping */
        if (unlikely(p == NULL)) {
            if (tv->flow_queue && SC_ATOMIC_GET(tv->flow_queue->non_empty) == true) {
                p = PacketGetFromQueueOrAlloc();
                if (p != NULL) {
                    p->flags |= PKT_PSEUDO_STREAM_END;
                    PKT_SET_SRC(p, PKT_SRC_CAPTURE_TIMEOUT);
                }
            }
        }

        if (p != NULL) {
            /* run the thread module(s) */
            r = TmThreadsSlotVarRun(tv, p, s);
            if (r == TM_ECODE_FAILED) {
                TmqhOutputPacketpool(tv, p);
                TmThreadsSetFlag(tv, THV_FAILED);
                break;
            }

            /* output the packet */
            tv->tmqh_out(tv, p);

            /* now handle the stream pq packets */
            TmThreadsHandleInjectedPackets(tv);
        }

        if (TmThreadsCheckFlag(tv, THV_KILL)) {
            run = 0;
        }
    } /* while (run) */
    StatsSyncCounters(tv);

    TmThreadsSetFlag(tv, THV_RUNNING_DONE);
    TmThreadWaitForFlag(tv, THV_DEINIT);

    PacketPoolDestroy();

    s = (TmSlot *)tv->tm_slots;

    for ( ; s != NULL; s = s->slot_next) {
        if (s->SlotThreadExitPrintStats != NULL) {
            s->SlotThreadExitPrintStats(tv, SC_ATOMIC_GET(s->slot_data));
        }

        if (s->SlotThreadDeinit != NULL) {
            r = s->SlotThreadDeinit(tv, SC_ATOMIC_GET(s->slot_data));
            if (r != TM_ECODE_OK) {
                TmThreadsSetFlag(tv, THV_CLOSED);
                goto error;
            }
        }
    }

    SCLogDebug("%s ending", tv->name);
    tv->stream_pq = NULL;
    TmThreadsSetFlag(tv, THV_CLOSED);
    pthread_exit((void *) 0);
    return NULL;

error:
    tv->stream_pq = NULL;
    pthread_exit((void *) -1);
    return NULL;
}

static void *TmThreadsManagement(void *td)
{
    ThreadVars *tv = (ThreadVars *)td;
    TmSlot *s = (TmSlot *)tv->tm_slots;
    TmEcode r = TM_ECODE_OK;

    BUG_ON(s == NULL);

    SCSetThreadName(tv->name);

    if (tv->thread_setup_flags != 0)
        TmThreadSetupOptions(tv);

    /* Drop the capabilities for this thread */
    SCDropCaps(tv);

    SCLogDebug("%s starting", tv->name);

    if (s->SlotThreadInit != NULL) {
        void *slot_data = NULL;
        r = s->SlotThreadInit(tv, s->slot_initdata, &slot_data);
        if (r != TM_ECODE_OK) {
            TmThreadsSetFlag(tv, THV_CLOSED | THV_RUNNING_DONE);
            pthread_exit((void *) -1);
            return NULL;
        }
        (void)SC_ATOMIC_SET(s->slot_data, slot_data);
    }

    StatsSetupPrivate(tv);

    TmThreadsSetFlag(tv, THV_INIT_DONE);

    r = s->Management(tv, SC_ATOMIC_GET(s->slot_data));
    /* handle error */
    if (r == TM_ECODE_FAILED) {
        TmThreadsSetFlag(tv, THV_FAILED);
    }

    if (TmThreadsCheckFlag(tv, THV_KILL)) {
        StatsSyncCounters(tv);
    }

    TmThreadsSetFlag(tv, THV_RUNNING_DONE);
    TmThreadWaitForFlag(tv, THV_DEINIT);

    if (s->SlotThreadExitPrintStats != NULL) {
        s->SlotThreadExitPrintStats(tv, SC_ATOMIC_GET(s->slot_data));
    }

    if (s->SlotThreadDeinit != NULL) {
        r = s->SlotThreadDeinit(tv, SC_ATOMIC_GET(s->slot_data));
        if (r != TM_ECODE_OK) {
            TmThreadsSetFlag(tv, THV_CLOSED);
            pthread_exit((void *) -1);
            return NULL;
        }
    }

    TmThreadsSetFlag(tv, THV_CLOSED);
    pthread_exit((void *) 0);
    return NULL;
}

/**
 * \brief We set the slot functions.
 *
 * \param tv   Pointer to the TV to set the slot function for.
 * \param name Name of the slot variant.
 * \param fn_p Pointer to a custom slot function.  Used only if slot variant
 *             "name" is "custom".
 *
 * \retval TmEcode TM_ECODE_OK on success; TM_ECODE_FAILED on failure.
 */
static TmEcode TmThreadSetSlots(ThreadVars *tv, const char *name, void *(*fn_p)(void *))
{
    if (name == NULL) {
        if (fn_p == NULL) {
            printf("Both slot name and function pointer can't be NULL inside "
                   "TmThreadSetSlots\n");
            goto error;
        } else {
            name = "custom";
        }
    }

    if (strcmp(name, "varslot") == 0) {
        tv->tm_func = TmThreadsSlotVar;
    } else if (strcmp(name, "pktacqloop") == 0) {
        tv->tm_func = TmThreadsSlotPktAcqLoop;
    } else if (strcmp(name, "management") == 0) {
        tv->tm_func = TmThreadsManagement;
    } else if (strcmp(name, "command") == 0) {
        tv->tm_func = TmThreadsManagement;
    } else if (strcmp(name, "custom") == 0) {
        if (fn_p == NULL)
            goto error;
        tv->tm_func = fn_p;
    } else {
        printf("Error: Slot \"%s\" not supported\n", name);
        goto error;
    }

    return TM_ECODE_OK;

error:
    return TM_ECODE_FAILED;
}

/**
 * \brief Appends a new entry to the slots.
 *
 * \param tv   TV the slot is attached to.
 * \param tm   TM to append.
 * \param data Data to be passed on to the slot init function.
 *
 * \retval The allocated TmSlot or NULL if there is an error
 */
void TmSlotSetFuncAppend(ThreadVars *tv, TmModule *tm, const void *data)
{
    TmSlot *slot = SCMalloc(sizeof(TmSlot));
    if (unlikely(slot == NULL))
        return;
    memset(slot, 0, sizeof(TmSlot));
    SC_ATOMIC_INITPTR(slot->slot_data);
    slot->SlotThreadInit = tm->ThreadInit;
    slot->slot_initdata = data;
    if (tm->Func) {
        slot->SlotFunc = tm->Func;
    } else if (tm->PktAcqLoop) {
        slot->PktAcqLoop = tm->PktAcqLoop;
        if (tm->PktAcqBreakLoop) {
            tv->break_loop = true;
        }
    } else if (tm->Management) {
        slot->Management = tm->Management;
    }
    slot->SlotThreadExitPrintStats = tm->ThreadExitPrintStats;
    slot->SlotThreadDeinit = tm->ThreadDeinit;
    /* we don't have to check for the return value "-1".  We wouldn't have
     * received a TM as arg, if it didn't exist */
    slot->tm_id = TmModuleGetIDForTM(tm);

    tv->tmm_flags |= tm->flags;
    tv->cap_flags |= tm->cap_flags;

    if (tv->tm_slots == NULL) {
        tv->tm_slots = slot;
    } else {
        TmSlot *a = (TmSlot *)tv->tm_slots, *b = NULL;

        /* get the last slot */
        for ( ; a != NULL; a = a->slot_next) {
             b = a;
        }
        /* append the new slot */
        if (b != NULL) {
            b->slot_next = slot;
        }
    }
    return;
}

#if !defined __CYGWIN__ && !defined OS_WIN32 && !defined __OpenBSD__ && !defined sun
static int SetCPUAffinitySet(cpu_set_t *cs)
{
#if defined OS_FREEBSD
    int r = cpuset_setaffinity(CPU_LEVEL_WHICH, CPU_WHICH_TID,
                               SCGetThreadIdLong(), sizeof(cpu_set_t),cs);
#elif OS_DARWIN
    int r = thread_policy_set(mach_thread_self(), THREAD_AFFINITY_POLICY,
                              (void*)cs, THREAD_AFFINITY_POLICY_COUNT);
#else
    pid_t tid = syscall(SYS_gettid);
    int r = sched_setaffinity(tid, sizeof(cpu_set_t), cs);
#endif /* OS_FREEBSD */

    if (r != 0) {
        printf("Warning: sched_setaffinity failed (%" PRId32 "): %s\n", r,
               strerror(errno));
        return -1;
    }

    return 0;
}
#endif


/**
 * \brief Set the thread affinity on the calling thread.
 *
 * \param cpuid Id of the core/cpu to setup the affinity.
 *
 * \retval 0 If all goes well; -1 if something is wrong.
 */
static int SetCPUAffinity(uint16_t cpuid)
{
#if defined __OpenBSD__ || defined sun
    return 0;
#else
    int cpu = (int)cpuid;

#if defined OS_WIN32 || defined __CYGWIN__
    DWORD cs = 1 << cpu;

    int r = (0 == SetThreadAffinityMask(GetCurrentThread(), cs));
    if (r != 0) {
        printf("Warning: sched_setaffinity failed (%" PRId32 "): %s\n", r,
               strerror(errno));
        return -1;
    }
    SCLogDebug("CPU Affinity for thread %lu set to CPU %" PRId32,
               SCGetThreadIdLong(), cpu);

    return 0;

#else
    cpu_set_t cs;

    CPU_ZERO(&cs);
    CPU_SET(cpu, &cs);
    return SetCPUAffinitySet(&cs);
#endif /* windows */
#endif /* not supported */
}


/**
 * \brief Set the thread options (thread priority).
 *
 * \param tv Pointer to the ThreadVars to setup the thread priority.
 *
 * \retval TM_ECODE_OK.
 */
TmEcode TmThreadSetThreadPriority(ThreadVars *tv, int prio)
{
    tv->thread_setup_flags |= THREAD_SET_PRIORITY;
    tv->thread_priority = prio;

    return TM_ECODE_OK;
}

/**
 * \brief Adjusting nice value for threads.
 */
void TmThreadSetPrio(ThreadVars *tv)
{
    SCEnter();
#ifndef __CYGWIN__
#ifdef OS_WIN32
	if (0 == SetThreadPriority(GetCurrentThread(), tv->thread_priority)) {
        SCLogError(SC_ERR_THREAD_NICE_PRIO, "Error setting priority for "
                   "thread %s: %s", tv->name, strerror(errno));
    } else {
        SCLogDebug("Priority set to %"PRId32" for thread %s",
                   tv->thread_priority, tv->name);
    }
#else
    int ret = nice(tv->thread_priority);
    if (ret == -1) {
        SCLogError(SC_ERR_THREAD_NICE_PRIO, "Error setting nice value %d "
                   "for thread %s: %s", tv->thread_priority, tv->name,
                   strerror(errno));
    } else {
        SCLogDebug("Nice value set to %"PRId32" for thread %s",
                   tv->thread_priority, tv->name);
    }
#endif /* OS_WIN32 */
#endif
    SCReturn;
}


/**
 * \brief Set the thread options (cpu affinity).
 *
 * \param tv pointer to the ThreadVars to setup the affinity.
 * \param cpu cpu on which affinity is set.
 *
 * \retval TM_ECODE_OK
 */
TmEcode TmThreadSetCPUAffinity(ThreadVars *tv, uint16_t cpu)
{
    tv->thread_setup_flags |= THREAD_SET_AFFINITY;
    tv->cpu_affinity = cpu;

    return TM_ECODE_OK;
}


TmEcode TmThreadSetCPU(ThreadVars *tv, uint8_t type)
{
    if (!threading_set_cpu_affinity)
        return TM_ECODE_OK;

    if (type > MAX_CPU_SET) {
        SCLogError(SC_ERR_INVALID_ARGUMENT, "invalid cpu type family");
        return TM_ECODE_FAILED;
    }

    tv->thread_setup_flags |= THREAD_SET_AFFTYPE;
    tv->cpu_affinity = type;

    return TM_ECODE_OK;
}

int TmThreadGetNbThreads(uint8_t type)
{
    if (type >= MAX_CPU_SET) {
        SCLogError(SC_ERR_INVALID_ARGUMENT, "invalid cpu type family");
        return 0;
    }

    return thread_affinity[type].nb_threads;
}

/**
 * \brief Set the thread options (cpu affinitythread).
 *        Priority should be already set by pthread_create.
 *
 * \param tv pointer to the ThreadVars of the calling thread.
 */
TmEcode TmThreadSetupOptions(ThreadVars *tv)
{
    if (tv->thread_setup_flags & THREAD_SET_AFFINITY) {
        SCLogPerf("Setting affinity for thread \"%s\"to cpu/core "
                  "%"PRIu16", thread id %lu", tv->name, tv->cpu_affinity,
                  SCGetThreadIdLong());
        SetCPUAffinity(tv->cpu_affinity);
    }

#if !defined __CYGWIN__ && !defined OS_WIN32 && !defined __OpenBSD__ && !defined sun
    if (tv->thread_setup_flags & THREAD_SET_PRIORITY)
        TmThreadSetPrio(tv);
    if (tv->thread_setup_flags & THREAD_SET_AFFTYPE) {
        ThreadsAffinityType *taf = &thread_affinity[tv->cpu_affinity];
        if (taf->mode_flag == EXCLUSIVE_AFFINITY) {
            uint16_t cpu = AffinityGetNextCPU(taf);
            SetCPUAffinity(cpu);
            /* If CPU is in a set overwrite the default thread prio */
            if (CPU_ISSET(cpu, &taf->lowprio_cpu)) {
                tv->thread_priority = PRIO_LOW;
            } else if (CPU_ISSET(cpu, &taf->medprio_cpu)) {
                tv->thread_priority = PRIO_MEDIUM;
            } else if (CPU_ISSET(cpu, &taf->hiprio_cpu)) {
                tv->thread_priority = PRIO_HIGH;
            } else {
                tv->thread_priority = taf->prio;
            }
            SCLogPerf("Setting prio %d for thread \"%s\" to cpu/core "
                      "%d, thread id %lu", tv->thread_priority,
                      tv->name, cpu, SCGetThreadIdLong());
        } else {
            SetCPUAffinitySet(&taf->cpu_set);
            tv->thread_priority = taf->prio;
            SCLogPerf("Setting prio %d for thread \"%s\", "
                      "thread id %lu", tv->thread_priority,
                      tv->name, SCGetThreadIdLong());
        }
        TmThreadSetPrio(tv);
    }
#endif

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
ThreadVars *TmThreadCreate(const char *name, const char *inq_name, const char *inqh_name,
                           const char *outq_name, const char *outqh_name, const char *slots,
                           void * (*fn_p)(void *), int mucond)
{
    ThreadVars *tv = NULL;
    Tmq *tmq = NULL;
    Tmqh *tmqh = NULL;

    SCLogDebug("creating thread \"%s\"...", name);

    /* XXX create separate function for this: allocate a thread container */
    tv = SCMalloc(sizeof(ThreadVars));
    if (unlikely(tv == NULL))
        goto error;
    memset(tv, 0, sizeof(ThreadVars));

    SC_ATOMIC_INIT(tv->flags);
    SCMutexInit(&tv->perf_public_ctx.m, NULL);

    strlcpy(tv->name, name, sizeof(tv->name));

    /* default state for every newly created thread */
    TmThreadsSetFlag(tv, THV_PAUSE);
    TmThreadsSetFlag(tv, THV_USE);

    /* set the incoming queue */
    if (inq_name != NULL && strcmp(inq_name, "packetpool") != 0) {
        SCLogDebug("inq_name \"%s\"", inq_name);

        tmq = TmqGetQueueByName(inq_name);
        if (tmq == NULL) {
            tmq = TmqCreateQueue(inq_name);
            if (tmq == NULL)
                goto error;
        }
        SCLogDebug("tmq %p", tmq);

        tv->inq = tmq;
        tv->inq->reader_cnt++;
        SCLogDebug("tv->inq %p", tv->inq);
    }
    if (inqh_name != NULL) {
        SCLogDebug("inqh_name \"%s\"", inqh_name);

        int id = TmqhNameToID(inqh_name);
        if (id <= 0) {
            goto error;
        }
        tmqh = TmqhGetQueueHandlerByName(inqh_name);
        if (tmqh == NULL)
            goto error;

        tv->tmqh_in = tmqh->InHandler;
        tv->inq_id = (uint8_t)id;
        SCLogDebug("tv->tmqh_in %p", tv->tmqh_in);
    }

    /* set the outgoing queue */
    if (outqh_name != NULL) {
        SCLogDebug("outqh_name \"%s\"", outqh_name);

        int id = TmqhNameToID(outqh_name);
        if (id <= 0) {
            goto error;
        }

        tmqh = TmqhGetQueueHandlerByName(outqh_name);
        if (tmqh == NULL)
            goto error;

        tv->tmqh_out = tmqh->OutHandler;
        tv->outq_id = (uint8_t)id;

        if (outq_name != NULL && strcmp(outq_name, "packetpool") != 0) {
            SCLogDebug("outq_name \"%s\"", outq_name);

            if (tmqh->OutHandlerCtxSetup != NULL) {
                tv->outctx = tmqh->OutHandlerCtxSetup(outq_name);
                if (tv->outctx == NULL)
                    goto error;
                tv->outq = NULL;
            } else {
                tmq = TmqGetQueueByName(outq_name);
                if (tmq == NULL) {
                    tmq = TmqCreateQueue(outq_name);
                    if (tmq == NULL)
                        goto error;
                }
                SCLogDebug("tmq %p", tmq);

                tv->outq = tmq;
                tv->outctx = NULL;
                tv->outq->writer_cnt++;
            }
        }
    }

    if (TmThreadSetSlots(tv, slots, fn_p) != TM_ECODE_OK) {
        goto error;
    }

    if (mucond != 0)
        TmThreadInitMC(tv);

    return tv;

error:
    SCLogError(SC_ERR_THREAD_CREATE, "failed to setup a thread");

    if (tv != NULL)
        SCFree(tv);
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
ThreadVars *TmThreadCreatePacketHandler(const char *name, const char *inq_name,
                                        const char *inqh_name, const char *outq_name,
                                        const char *outqh_name, const char *slots)
{
    ThreadVars *tv = NULL;

    tv = TmThreadCreate(name, inq_name, inqh_name, outq_name, outqh_name,
                        slots, NULL, 0);

    if (tv != NULL) {
        tv->type = TVT_PPT;
        tv->id = TmThreadsRegisterThread(tv, tv->type);
    }

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
ThreadVars *TmThreadCreateMgmtThread(const char *name, void *(fn_p)(void *),
                                     int mucond)
{
    ThreadVars *tv = NULL;

    tv = TmThreadCreate(name, NULL, NULL, NULL, NULL, "custom", fn_p, mucond);

    if (tv != NULL) {
        tv->type = TVT_MGMT;
        tv->id = TmThreadsRegisterThread(tv, tv->type);
        TmThreadSetCPU(tv, MANAGEMENT_CPU_SET);
    }

    return tv;
}

/**
 * \brief Creates and returns the TV instance for a Management thread(MGMT).
 *        This function supports only custom slot functions and hence a
 *        function pointer should be sent as an argument.
 *
 * \param name       Name of this TV instance
 * \param module     Name of TmModule with MANAGEMENT flag set.
 * \param mucond     Flag to indicate whether to initialize the condition
 *                   and the mutex variables for this newly created TV.
 *
 * \retval the newly created TV instance, or NULL on error
 */
ThreadVars *TmThreadCreateMgmtThreadByName(const char *name, const char *module,
                                     int mucond)
{
    ThreadVars *tv = NULL;

    tv = TmThreadCreate(name, NULL, NULL, NULL, NULL, "management", NULL, mucond);

    if (tv != NULL) {
        tv->type = TVT_MGMT;
        tv->id = TmThreadsRegisterThread(tv, tv->type);
        TmThreadSetCPU(tv, MANAGEMENT_CPU_SET);

        TmModule *m = TmModuleGetByName(module);
        if (m) {
            TmSlotSetFuncAppend(tv, m, NULL);
        }
    }

    return tv;
}

/**
 * \brief Creates and returns the TV instance for a Command thread (CMD).
 *        This function supports only custom slot functions and hence a
 *        function pointer should be sent as an argument.
 *
 * \param name       Name of this TV instance
 * \param module     Name of TmModule with COMMAND flag set.
 * \param mucond     Flag to indicate whether to initialize the condition
 *                   and the mutex variables for this newly created TV.
 *
 * \retval the newly created TV instance, or NULL on error
 */
ThreadVars *TmThreadCreateCmdThreadByName(const char *name, const char *module,
                                     int mucond)
{
    ThreadVars *tv = NULL;

    tv = TmThreadCreate(name, NULL, NULL, NULL, NULL, "command", NULL, mucond);

    if (tv != NULL) {
        tv->type = TVT_CMD;
        tv->id = TmThreadsRegisterThread(tv, tv->type);
        TmThreadSetCPU(tv, MANAGEMENT_CPU_SET);

        TmModule *m = TmModuleGetByName(module);
        if (m) {
            TmSlotSetFuncAppend(tv, m, NULL);
        }
    }

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

        SCMutexUnlock(&tv_root_lock);

        return;
    }

    ThreadVars *t = tv_root[type];

    while (t) {
        if (t->next == NULL) {
            t->next = tv;
            tv->next = NULL;
            break;
        }

        t = t->next;
    }

    SCMutexUnlock(&tv_root_lock);

    return;
}

static bool ThreadStillHasPackets(ThreadVars *tv)
{
    if (tv->inq != NULL && !tv->inq->is_packet_pool) {
        /* we wait till we dry out all the inq packets, before we
         * kill this thread.  Do note that you should have disabled
         * packet acquire by now using TmThreadDisableReceiveThreads()*/
        PacketQueue *q = tv->inq->pq;
        SCMutexLock(&q->mutex_q);
        uint32_t len = q->len;
        SCMutexUnlock(&q->mutex_q);
        if (len != 0) {
            return true;
        }
    }

    if (tv->stream_pq != NULL) {
        SCMutexLock(&tv->stream_pq->mutex_q);
        uint32_t len = tv->stream_pq->len;
        SCMutexUnlock(&tv->stream_pq->mutex_q);

        if (len != 0) {
            return true;
        }
    }
    return false;
}

/**
 * \brief Kill a thread.
 *
 * \param tv A ThreadVars instance corresponding to the thread that has to be
 *           killed.
 *
 * \retval r 1 killed succesfully
 *           0 not yet ready, needs another look
 */
static int TmThreadKillThread(ThreadVars *tv)
{
    BUG_ON(tv == NULL);

    /* kill only once :) */
    if (TmThreadsCheckFlag(tv, THV_DEAD)) {
        return 1;
    }

    /* set the thread flag informing the thread that it needs to be
     * terminated */
    TmThreadsSetFlag(tv, THV_KILL);
    TmThreadsSetFlag(tv, THV_DEINIT);

    /* to be sure, signal more */
    if (!(TmThreadsCheckFlag(tv, THV_CLOSED))) {
        if (tv->inq_id != TMQH_NOT_SET) {
            Tmqh *qh = TmqhGetQueueHandlerByID(tv->inq_id);
            if (qh != NULL && qh->InShutdownHandler != NULL) {
                qh->InShutdownHandler(tv);
            }
        }
        if (tv->inq != NULL) {
            for (int i = 0; i < (tv->inq->reader_cnt + tv->inq->writer_cnt); i++) {
                SCCondSignal(&tv->inq->pq->cond_q);
            }
            SCLogDebug("signalled tv->inq->id %" PRIu32 "", tv->inq->id);
        }

        if (tv->ctrl_cond != NULL ) {
            pthread_cond_broadcast(tv->ctrl_cond);
        }
        return 0;
    }

    if (tv->outctx != NULL) {
        if (tv->outq_id != TMQH_NOT_SET) {
            Tmqh *qh = TmqhGetQueueHandlerByID(tv->outq_id);
            if (qh != NULL && qh->OutHandlerCtxFree != NULL) {
                qh->OutHandlerCtxFree(tv->outctx);
                tv->outctx = NULL;
            }
        }
    }

    /* join it and flag it as dead */
    pthread_join(tv->t, NULL);
    SCLogDebug("thread %s stopped", tv->name);
    TmThreadsSetFlag(tv, THV_DEAD);
    return 1;
}

/** \internal
 *
 *  \brief make sure that all packet threads are done processing their
 *         in-flight packets, including 'injected' flow packets.
 */
static void TmThreadDrainPacketThreads(void)
{
    ThreadVars *tv = NULL;
    struct timeval start_ts;
    struct timeval cur_ts;
    gettimeofday(&start_ts, NULL);

again:
    gettimeofday(&cur_ts, NULL);
    if ((cur_ts.tv_sec - start_ts.tv_sec) > 60) {
        SCLogWarning(SC_ERR_SHUTDOWN, "unable to get all packet threads "
                "to process their packets in time");
        return;
    }

    SCMutexLock(&tv_root_lock);

    /* all receive threads are part of packet processing threads */
    tv = tv_root[TVT_PPT];
    while (tv) {
        if (ThreadStillHasPackets(tv)) {
            /* we wait till we dry out all the inq packets, before we
             * kill this thread.  Do note that you should have disabled
             * packet acquire by now using TmThreadDisableReceiveThreads()*/
            SCMutexUnlock(&tv_root_lock);

            /* sleep outside lock */
            SleepMsec(1);
            goto again;
        }
        if (tv->flow_queue) {
            FQLOCK_LOCK(tv->flow_queue);
            bool fq_done = (tv->flow_queue->qlen == 0);
            FQLOCK_UNLOCK(tv->flow_queue);
            if (!fq_done) {
                SCMutexUnlock(&tv_root_lock);

                Packet *p = PacketGetFromAlloc();
                if (p != NULL) {
                    p->flags |= PKT_PSEUDO_STREAM_END;
                    PKT_SET_SRC(p, PKT_SRC_DETECT_RELOAD_FLUSH);
                    PacketQueue *q = tv->stream_pq;
                    SCMutexLock(&q->mutex_q);
                    PacketEnqueue(q, p);
                    SCCondSignal(&q->cond_q);
                    SCMutexUnlock(&q->mutex_q);
                }

                /* don't sleep while holding a lock */
                SleepMsec(1);
                goto again;
            }
        }
        tv = tv->next;
    }

    SCMutexUnlock(&tv_root_lock);
    return;
}

/**
 *  \brief Disable all threads having the specified TMs.
 *
 *  Breaks out of the packet acquisition loop, and bumps
 *  into the 'flow loop', where it will process packets
 *  from the flow engine's shutdown handling.
 */
void TmThreadDisableReceiveThreads(void)
{
    ThreadVars *tv = NULL;
    struct timeval start_ts;
    struct timeval cur_ts;
    gettimeofday(&start_ts, NULL);

again:
    gettimeofday(&cur_ts, NULL);
    if ((cur_ts.tv_sec - start_ts.tv_sec) > 60) {
        FatalError(SC_ERR_FATAL, "Engine unable to disable detect "
                "thread - \"%s\". Killing engine", tv->name);
    }

    SCMutexLock(&tv_root_lock);

    /* all receive threads are part of packet processing threads */
    tv = tv_root[TVT_PPT];

    /* we do have to keep in mind that TVs are arranged in the order
     * right from receive to log.  The moment we fail to find a
     * receive TM amongst the slots in a tv, it indicates we are done
     * with all receive threads */
    while (tv) {
        int disable = 0;
        TmModule *tm = NULL;
        /* obtain the slots for this TV */
        TmSlot *slots = tv->tm_slots;
        while (slots != NULL) {
            tm = TmModuleGetById(slots->tm_id);

            if (tm->flags & TM_FLAG_RECEIVE_TM) {
                disable = 1;
                break;
            }

            slots = slots->slot_next;
            continue;
        }

        if (disable) {
            if (ThreadStillHasPackets(tv)) {
                /* we wait till we dry out all the inq packets, before we
                 * kill this thread.  Do note that you should have disabled
                 * packet acquire by now using TmThreadDisableReceiveThreads()*/
                SCMutexUnlock(&tv_root_lock);
                /* don't sleep while holding a lock */
                SleepMsec(1);
                goto again;
            }

            if (tv->flow_queue) {
                FQLOCK_LOCK(tv->flow_queue);
                bool fq_done = (tv->flow_queue->qlen == 0);
                FQLOCK_UNLOCK(tv->flow_queue);
                if (!fq_done) {
                    SCMutexUnlock(&tv_root_lock);

                    Packet *p = PacketGetFromAlloc();
                    if (p != NULL) {
                        p->flags |= PKT_PSEUDO_STREAM_END;
                        PKT_SET_SRC(p, PKT_SRC_DETECT_RELOAD_FLUSH);
                        PacketQueue *q = tv->stream_pq;
                        SCMutexLock(&q->mutex_q);
                        PacketEnqueue(q, p);
                        SCCondSignal(&q->cond_q);
                        SCMutexUnlock(&q->mutex_q);
                    }

                    /* don't sleep while holding a lock */
                    SleepMsec(1);
                    goto again;
                }
            }

            /* we found a receive TV. Send it a KILL_PKTACQ signal. */
            if (tm && tm->PktAcqBreakLoop != NULL) {
                tm->PktAcqBreakLoop(tv, SC_ATOMIC_GET(slots->slot_data));
            }
            TmThreadsSetFlag(tv, THV_KILL_PKTACQ);

            if (tv->inq != NULL) {
                for (int i = 0; i < (tv->inq->reader_cnt + tv->inq->writer_cnt); i++) {
                    SCCondSignal(&tv->inq->pq->cond_q);
                }
                SCLogDebug("signalled tv->inq->id %" PRIu32 "", tv->inq->id);
            }

            /* wait for it to enter the 'flow loop' stage */
            while (!TmThreadsCheckFlag(tv, THV_FLOW_LOOP)) {
                SCMutexUnlock(&tv_root_lock);

                SleepMsec(1);
                goto again;
            }
        }

        tv = tv->next;
    }

    SCMutexUnlock(&tv_root_lock);

    /* finally wait for all packet threads to have
     * processed all of their 'live' packets so we
     * don't process the last live packets together
     * with FFR packets */
    TmThreadDrainPacketThreads();
    return;
}

#ifdef DEBUG_VALIDATION
static void TmThreadDumpThreads(void);
#endif

static void TmThreadDebugValidateNoMorePackets(void)
{
#ifdef DEBUG_VALIDATION
    SCMutexLock(&tv_root_lock);
    for (ThreadVars *tv = tv_root[TVT_PPT]; tv != NULL; tv = tv->next) {
        if (ThreadStillHasPackets(tv)) {
            SCMutexUnlock(&tv_root_lock);
            TmThreadDumpThreads();
            abort();
        }
    }
    SCMutexUnlock(&tv_root_lock);
#endif
}

/**
 * \brief Disable all packet threads
 */
void TmThreadDisablePacketThreads(void)
{
    struct timeval start_ts;
    struct timeval cur_ts;

    /* first drain all packet threads of their packets */
    TmThreadDrainPacketThreads();

    /* since all the threads possibly able to produce more packets
     * are now gone or inactive, we should see no packets anywhere
     * anymore. */
    TmThreadDebugValidateNoMorePackets();

    gettimeofday(&start_ts, NULL);
again:
    gettimeofday(&cur_ts, NULL);
    if ((cur_ts.tv_sec - start_ts.tv_sec) > 60) {
        FatalError(SC_ERR_FATAL, "Engine unable to disable packet  "
                "threads. Killing engine");
    }

    /* loop through the packet threads and kill them */
    SCMutexLock(&tv_root_lock);
    for (ThreadVars *tv = tv_root[TVT_PPT]; tv != NULL; tv = tv->next) {
        TmThreadsSetFlag(tv, THV_KILL);

        /* separate worker threads (autofp) will still wait at their
         * input queues. So nudge them here so they will observe the
         * THV_KILL flag. */
        if (tv->inq != NULL) {
            for (int i = 0; i < (tv->inq->reader_cnt + tv->inq->writer_cnt); i++) {
                SCCondSignal(&tv->inq->pq->cond_q);
            }
            SCLogDebug("signalled tv->inq->id %" PRIu32 "", tv->inq->id);
        }

        while (!TmThreadsCheckFlag(tv, THV_RUNNING_DONE)) {
            SCMutexUnlock(&tv_root_lock);

            SleepMsec(1);
            goto again;
        }
    }
    SCMutexUnlock(&tv_root_lock);
    return;
}

#define MIN_WAIT_TIME 100
#define MAX_WAIT_TIME 999999
void TmThreadKillThreadsFamily(int family)
{
    ThreadVars *tv = NULL;
    unsigned int sleep_usec = MIN_WAIT_TIME;

    BUG_ON((family < 0) || (family >= TVT_MAX));

again:
    SCMutexLock(&tv_root_lock);
    tv = tv_root[family];

    while (tv) {
        int r = TmThreadKillThread(tv);
        if (r == 0) {
            SCMutexUnlock(&tv_root_lock);
            SleepUsec(sleep_usec);
            sleep_usec *= 2; /* slowly back off */
            sleep_usec = MIN(sleep_usec, MAX_WAIT_TIME);
            goto again;
        }
        sleep_usec = MIN_WAIT_TIME; /* reset */

        tv = tv->next;
    }
    SCMutexUnlock(&tv_root_lock);
}
#undef MIN_WAIT_TIME
#undef MAX_WAIT_TIME

void TmThreadKillThreads(void)
{
    int i = 0;

    for (i = 0; i < TVT_MAX; i++) {
        TmThreadKillThreadsFamily(i);
    }

    return;
}

static void TmThreadFree(ThreadVars *tv)
{
    TmSlot *s;
    TmSlot *ps;
    if (tv == NULL)
        return;

    SCLogDebug("Freeing thread '%s'.", tv->name);

    if (tv->flow_queue) {
        BUG_ON(tv->flow_queue->qlen != 0);
        SCFree(tv->flow_queue);
    }

    StatsThreadCleanup(tv);

    TmThreadDeinitMC(tv);

    if (tv->thread_group_name) {
        SCFree(tv->thread_group_name);
    }

    if (tv->printable_name) {
        SCFree(tv->printable_name);
    }

    if (tv->stream_pq_local) {
        BUG_ON(tv->stream_pq_local->len);
        SCMutexDestroy(&tv->stream_pq_local->mutex_q);
        SCFree(tv->stream_pq_local);
    }

    s = (TmSlot *)tv->tm_slots;
    while (s) {
        ps = s;
        s = s->slot_next;
        SCFree(ps);
    }

    TmThreadsUnregisterThread(tv->id);
    SCFree(tv);
}

void TmThreadSetGroupName(ThreadVars *tv, const char *name)
{
    char *thread_group_name = NULL;

    if (name == NULL)
        return;

    if (tv == NULL)
        return;

    thread_group_name = SCStrdup(name);
    if (unlikely(thread_group_name == NULL)) {
        SCLogError(SC_ERR_RUNMODE, "error allocating memory");
        return;
    }
    tv->thread_group_name = thread_group_name;
}

void TmThreadClearThreadsFamily(int family)
{
    ThreadVars *tv = NULL;
    ThreadVars *ptv = NULL;

    if ((family < 0) || (family >= TVT_MAX))
        return;

    SCMutexLock(&tv_root_lock);
    tv = tv_root[family];

    while (tv) {
        ptv = tv;
        tv = tv->next;
        TmThreadFree(ptv);
    }
    tv_root[family] = NULL;
    SCMutexUnlock(&tv_root_lock);
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
        FatalError(SC_ERR_TM_THREADS_ERROR, "No thread function set");
    }

    /* Initialize and set thread detached attribute */
    pthread_attr_init(&attr);

    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE);

    /* Adjust thread stack size if configured */
    if (threading_set_stack_size) {
        SCLogDebug("Setting per-thread stack size to %" PRIu64, threading_set_stack_size);
        if (pthread_attr_setstacksize(&attr, (size_t)threading_set_stack_size)) {
            FatalError(SC_ERR_TM_THREADS_ERROR,
                    "Unable to increase stack size to %" PRIu64 " in thread attributes",
                    threading_set_stack_size);
        }
    }

    int rc = pthread_create(&tv->t, &attr, tv->tm_func, (void *)tv);
    if (rc) {
        FatalError(SC_ERR_THREAD_CREATE,
                "Unable to create thread with pthread_create() is %" PRId32, rc);
    }

#if DEBUG && HAVE_PTHREAD_GETATTR_NP
    if (threading_set_stack_size) {
        if (pthread_getattr_np(tv->t, &attr) == 0) {
            size_t stack_size;
            void *stack_addr;
            pthread_attr_getstack(&attr, &stack_addr, &stack_size);
            SCLogDebug("stack: %p;  size %" PRIu64, stack_addr, (uintmax_t)stack_size);
        } else {
            SCLogDebug("Unable to retrieve current stack-size for display; return code from "
                       "pthread_getattr_np() is %" PRId32,
                    rc);
        }
    }
#endif

    TmThreadWaitForFlag(tv, THV_INIT_DONE | THV_RUNNING_DONE);

    TmThreadAppend(tv, tv->type);
    return TM_ECODE_OK;
}

/**
 * \brief Initializes the mutex and condition variables for this TV
 *
 * It can be used by a thread to control a wait loop that can also be
 * influenced by other threads.
 *
 * \param tv Pointer to a TV instance
 */
void TmThreadInitMC(ThreadVars *tv)
{
    if ( (tv->ctrl_mutex = SCMalloc(sizeof(*tv->ctrl_mutex))) == NULL) {
        FatalError(SC_ERR_FATAL,
                   "Fatal error encountered in TmThreadInitMC.  "
                   "Exiting...");
    }

    if (SCCtrlMutexInit(tv->ctrl_mutex, NULL) != 0) {
        printf("Error initializing the tv->m mutex\n");
        exit(EXIT_FAILURE);
    }

    if ( (tv->ctrl_cond = SCMalloc(sizeof(*tv->ctrl_cond))) == NULL) {
        FatalError(SC_ERR_FATAL,
                   "Fatal error encountered in TmThreadInitMC.  "
                   "Exiting...");
    }

    if (SCCtrlCondInit(tv->ctrl_cond, NULL) != 0) {
        FatalError(SC_ERR_FATAL, "Error initializing the tv->cond condition "
                   "variable");
    }

    return;
}

static void TmThreadDeinitMC(ThreadVars *tv)
{
    if (tv->ctrl_mutex) {
        SCCtrlMutexDestroy(tv->ctrl_mutex);
        SCFree(tv->ctrl_mutex);
    }
    if (tv->ctrl_cond) {
        SCCtrlCondDestroy(tv->ctrl_cond);
        SCFree(tv->ctrl_cond);
    }
    return;
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
        SleepUsec(100);

        if (TmThreadsCheckFlag(tv, THV_KILL))
            break;
    }

    return;
}

/**
 * \brief Waits till the specified flag(s) is(are) set.  We don't bother if
 *        the kill flag has been set or not on the thread.
 *
 * \param tv Pointer to the TV instance.
 */
void TmThreadWaitForFlag(ThreadVars *tv, uint32_t flags)
{
    while (!TmThreadsCheckFlag(tv, flags)) {
        SleepUsec(100);
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
 * \brief Waits for all threads to be in a running state
 *
 * \retval TM_ECODE_OK if all are running or error if a thread failed
 */
TmEcode TmThreadWaitOnThreadRunning(void)
{
    struct timeval start_ts;
    struct timeval cur_ts;
    gettimeofday(&start_ts, NULL);

again:
    SCMutexLock(&tv_root_lock);
    for (int i = 0; i < TVT_MAX; i++) {
        ThreadVars *tv = tv_root[i];
        while (tv != NULL) {
            if (TmThreadsCheckFlag(tv, (THV_FAILED | THV_CLOSED | THV_DEAD))) {
                SCMutexUnlock(&tv_root_lock);

                SCLogError(SC_ERR_THREAD_INIT,
                        "thread \"%s\" failed to "
                        "start: flags %04x",
                        tv->name, SC_ATOMIC_GET(tv->flags));
                return TM_ECODE_FAILED;
            }

            if (!(TmThreadsCheckFlag(tv, THV_RUNNING))) {
                SCMutexUnlock(&tv_root_lock);

                gettimeofday(&cur_ts, NULL);
                if ((cur_ts.tv_sec - start_ts.tv_sec) > 60) {
                    SCLogError(SC_ERR_THREAD_INIT,
                            "thread \"%s\" failed to "
                            "start in time: flags %04x",
                            tv->name, SC_ATOMIC_GET(tv->flags));
                    return TM_ECODE_FAILED;
                }

                /* sleep a little to give the thread some
                 * time to start running */
                SleepUsec(100);
                goto again;
            }
            tv = tv->next;
        }
    }
    SCMutexUnlock(&tv_root_lock);
    return TM_ECODE_OK;
}

/**
 * \brief Unpauses all threads present in tv_root
 */
void TmThreadContinueThreads()
{
    SCMutexLock(&tv_root_lock);
    for (int i = 0; i < TVT_MAX; i++) {
        ThreadVars *tv = tv_root[i];
        while (tv != NULL) {
            TmThreadContinue(tv);
            tv = tv->next;
        }
    }
    SCMutexUnlock(&tv_root_lock);
    return;
}

/**
 * \brief Used to check the thread for certain conditions of failure.
 */
void TmThreadCheckThreadState(void)
{
    SCMutexLock(&tv_root_lock);
    for (int i = 0; i < TVT_MAX; i++) {
        ThreadVars *tv = tv_root[i];
        while (tv) {
            if (TmThreadsCheckFlag(tv, THV_FAILED)) {
                FatalError(SC_ERR_FATAL, "thread %s failed", tv->name);
            }
            tv = tv->next;
        }
    }
    SCMutexUnlock(&tv_root_lock);
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
    uint16_t RX_num = 0;
    uint16_t W_num = 0;
    uint16_t FM_num = 0;
    uint16_t FR_num = 0;
    uint16_t TX_num = 0;

    struct timeval start_ts;
    struct timeval cur_ts;
    gettimeofday(&start_ts, NULL);

again:
    SCMutexLock(&tv_root_lock);
    for (int i = 0; i < TVT_MAX; i++) {
        ThreadVars *tv = tv_root[i];
        while (tv != NULL) {
            if (TmThreadsCheckFlag(tv, (THV_CLOSED|THV_DEAD))) {
                SCMutexUnlock(&tv_root_lock);

                SCLogError(SC_ERR_THREAD_INIT, "thread \"%s\" failed to "
                        "initialize: flags %04x", tv->name,
                        SC_ATOMIC_GET(tv->flags));
                return TM_ECODE_FAILED;
            }

            if (!(TmThreadsCheckFlag(tv, THV_INIT_DONE))) {
                SCMutexUnlock(&tv_root_lock);

                gettimeofday(&cur_ts, NULL);
                if ((cur_ts.tv_sec - start_ts.tv_sec) > 120) {
                    SCLogError(SC_ERR_THREAD_INIT, "thread \"%s\" failed to "
                            "initialize in time: flags %04x", tv->name,
                            SC_ATOMIC_GET(tv->flags));
                    return TM_ECODE_FAILED;
                }

                /* sleep a little to give the thread some
                 * time to finish initialization */
                SleepUsec(100);
                goto again;
            }

            if (TmThreadsCheckFlag(tv, THV_FAILED)) {
                SCMutexUnlock(&tv_root_lock);
                SCLogError(SC_ERR_THREAD_INIT, "thread \"%s\" failed to "
                        "initialize.", tv->name);
                return TM_ECODE_FAILED;
            }
            if (TmThreadsCheckFlag(tv, THV_CLOSED)) {
                SCMutexUnlock(&tv_root_lock);
                SCLogError(SC_ERR_THREAD_INIT, "thread \"%s\" closed on "
                        "initialization.", tv->name);
                return TM_ECODE_FAILED;
            }

            if (strncmp(thread_name_autofp, tv->name, strlen(thread_name_autofp)) == 0)
                RX_num++;
            else if (strncmp(thread_name_workers, tv->name, strlen(thread_name_workers)) == 0)
                W_num++;
            else if (strncmp(thread_name_verdict, tv->name, strlen(thread_name_verdict)) == 0)
                TX_num++;
            else if (strncmp(thread_name_flow_mgr, tv->name, strlen(thread_name_flow_mgr)) == 0)
                FM_num++;
            else if (strncmp(thread_name_flow_rec, tv->name, strlen(thread_name_flow_rec)) == 0)
                FR_num++;

            tv = tv->next;
        }
    }
    SCMutexUnlock(&tv_root_lock);

    /* Construct a welcome string displaying
     * initialized thread types and counts */
    uint16_t app_len = 32;
    uint16_t buf_len = 256;

    char append_str[app_len];
    char thread_counts[buf_len];

    strlcpy(thread_counts, "Threads created -> ", strlen("Threads created -> ") + 1);
    if (RX_num > 0) {
        snprintf(append_str, app_len, "RX: %u ", RX_num);
        strlcat(thread_counts, append_str, buf_len);
    }
    if (W_num > 0) {
        snprintf(append_str, app_len, "W: %u ", W_num);
        strlcat(thread_counts, append_str, buf_len);
    }
    if (TX_num > 0) {
        snprintf(append_str, app_len, "TX: %u ", TX_num);
        strlcat(thread_counts, append_str, buf_len);
    }
    if (FM_num > 0) {
        snprintf(append_str, app_len, "FM: %u ", FM_num);
        strlcat(thread_counts, append_str, buf_len);
    }
    if (FR_num > 0) {
        snprintf(append_str, app_len, "FR: %u ", FR_num);
        strlcat(thread_counts, append_str, buf_len);
    }
    snprintf(append_str, app_len, "  Engine started.");
    strlcat(thread_counts, append_str, buf_len);
    SCLogNotice("%s", thread_counts);

    return TM_ECODE_OK;
}

/**
 * \brief returns a count of all the threads that match the flag
 */
uint32_t TmThreadCountThreadsByTmmFlags(uint8_t flags)
{
    uint32_t cnt = 0;
    SCMutexLock(&tv_root_lock);
    for (int i = 0; i < TVT_MAX; i++) {
        ThreadVars *tv = tv_root[i];
        while (tv != NULL) {
            if ((tv->tmm_flags & flags) == flags)
                cnt++;

            tv = tv->next;
        }
    }
    SCMutexUnlock(&tv_root_lock);
    return cnt;
}

#ifdef DEBUG_VALIDATION
static void TmThreadDoDumpSlots(const ThreadVars *tv)
{
    for (TmSlot *s = tv->tm_slots; s != NULL; s = s->slot_next) {
        TmModule *m = TmModuleGetById(s->tm_id);
        SCLogNotice("tv %p: -> slot %p tm_id %d name %s",
            tv, s, s->tm_id, m->name);
    }
}

static void TmThreadDumpThreads(void)
{
    SCMutexLock(&tv_root_lock);
    for (int i = 0; i < TVT_MAX; i++) {
        ThreadVars *tv = tv_root[i];
        while (tv != NULL) {
            const uint32_t flags = SC_ATOMIC_GET(tv->flags);
            SCLogNotice("tv %p: type %u name %s tmm_flags %02X flags %X stream_pq %p",
                    tv, tv->type, tv->name, tv->tmm_flags, flags, tv->stream_pq);
            if (tv->inq && tv->stream_pq == tv->inq->pq) {
                SCLogNotice("tv %p: stream_pq at tv->inq %u", tv, tv->inq->id);
            } else if (tv->stream_pq_local != NULL) {
                for (Packet *xp = tv->stream_pq_local->top; xp != NULL; xp = xp->next) {
                    SCLogNotice("tv %p: ==> stream_pq_local: pq.len %u packet src %s",
                            tv, tv->stream_pq_local->len, PktSrcToString(xp->pkt_src));
                }
            }
            for (Packet *xp = tv->decode_pq.top; xp != NULL; xp = xp->next) {
                SCLogNotice("tv %p: ==> decode_pq: decode_pq.len %u packet src %s",
                        tv, tv->decode_pq.len, PktSrcToString(xp->pkt_src));
            }
            TmThreadDoDumpSlots(tv);
            tv = tv->next;
        }
    }
    SCMutexUnlock(&tv_root_lock);
    TmThreadsListThreads();
}
#endif

typedef struct Thread_ {
    ThreadVars *tv;     /**< threadvars structure */
    const char *name;
    int type;
    int in_use;         /**< bool to indicate this is in use */

    struct timeval pktts;   /**< current packet time of this thread
                             *   (offline mode) */
    uint32_t sys_sec_stamp; /**< timestamp in seconds of the real system
                             *   time when the pktts was last updated. */
} Thread;

typedef struct Threads_ {
    Thread *threads;
    size_t threads_size;
    int threads_cnt;
} Threads;

static Threads thread_store = { NULL, 0, 0 };
static SCMutex thread_store_lock = SCMUTEX_INITIALIZER;

void TmThreadsListThreads(void)
{
    SCMutexLock(&thread_store_lock);
    for (size_t s = 0; s < thread_store.threads_size; s++) {
        Thread *t = &thread_store.threads[s];
        if (t == NULL || t->in_use == 0)
            continue;

        SCLogNotice("Thread %"PRIuMAX", %s type %d, tv %p in_use %d",
                (uintmax_t)s+1, t->name, t->type, t->tv, t->in_use);
        if (t->tv) {
            ThreadVars *tv = t->tv;
            const uint32_t flags = SC_ATOMIC_GET(tv->flags);
            SCLogNotice("tv %p type %u name %s tmm_flags %02X flags %X",
                    tv, tv->type, tv->name, tv->tmm_flags, flags);
        }
    }
    SCMutexUnlock(&thread_store_lock);
}

#define STEP 32
/**
 *  \retval id thread id, or 0 if not found
 */
int TmThreadsRegisterThread(ThreadVars *tv, const int type)
{
    SCMutexLock(&thread_store_lock);
    if (thread_store.threads == NULL) {
        thread_store.threads = SCCalloc(STEP, sizeof(Thread));
        BUG_ON(thread_store.threads == NULL);
        thread_store.threads_size = STEP;
    }

    size_t s;
    for (s = 0; s < thread_store.threads_size; s++) {
        if (thread_store.threads[s].in_use == 0) {
            Thread *t = &thread_store.threads[s];
            t->name = tv->name;
            t->type = type;
            t->tv = tv;
            t->in_use = 1;

            SCMutexUnlock(&thread_store_lock);
            return (int)(s+1);
        }
    }

    /* if we get here the array is completely filled */
    void *newmem = SCRealloc(thread_store.threads, ((thread_store.threads_size + STEP) * sizeof(Thread)));
    BUG_ON(newmem == NULL);
    thread_store.threads = newmem;
    memset((uint8_t *)thread_store.threads + (thread_store.threads_size * sizeof(Thread)), 0x00, STEP * sizeof(Thread));

    Thread *t = &thread_store.threads[thread_store.threads_size];
    t->name = tv->name;
    t->type = type;
    t->tv = tv;
    t->in_use = 1;

    s = thread_store.threads_size;
    thread_store.threads_size += STEP;

    SCMutexUnlock(&thread_store_lock);
    return (int)(s+1);
}
#undef STEP

void TmThreadsUnregisterThread(const int id)
{
    SCMutexLock(&thread_store_lock);
    if (id <= 0 || id > (int)thread_store.threads_size) {
        SCMutexUnlock(&thread_store_lock);
        return;
    }

    /* id is one higher than index */
    int idx = id - 1;

    /* reset thread_id, which serves as clearing the record */
    thread_store.threads[idx].in_use = 0;

    /* check if we have at least one registered thread left */
    size_t s;
    for (s = 0; s < thread_store.threads_size; s++) {
        Thread *t = &thread_store.threads[s];
        if (t->in_use == 1) {
            goto end;
        }
    }

    /* if we get here no threads are registered */
    SCFree(thread_store.threads);
    thread_store.threads = NULL;
    thread_store.threads_size = 0;
    thread_store.threads_cnt = 0;

end:
    SCMutexUnlock(&thread_store_lock);
}

void TmThreadsSetThreadTimestamp(const int id, const struct timeval *ts)
{
    SCMutexLock(&thread_store_lock);
    if (unlikely(id <= 0 || id > (int)thread_store.threads_size)) {
        SCMutexUnlock(&thread_store_lock);
        return;
    }

    int idx = id - 1;
    Thread *t = &thread_store.threads[idx];
    t->pktts = *ts;
    struct timeval systs;
    gettimeofday(&systs, NULL);
    t->sys_sec_stamp = (uint32_t)systs.tv_sec;
    SCMutexUnlock(&thread_store_lock);
}

bool TmThreadsTimeSubsysIsReady(void)
{
    bool ready = true;
    SCMutexLock(&thread_store_lock);
    for (size_t s = 0; s < thread_store.threads_size; s++) {
        Thread *t = &thread_store.threads[s];
        if (!t->in_use)
            break;
        if (t->sys_sec_stamp == 0) {
            ready = false;
            break;
        }
    }
    SCMutexUnlock(&thread_store_lock);
    return ready;
}

void TmThreadsInitThreadsTimestamp(const struct timeval *ts)
{
    struct timeval systs;
    gettimeofday(&systs, NULL);
    SCMutexLock(&thread_store_lock);

    for (size_t s = 0; s < thread_store.threads_size; s++) {
        Thread *t = &thread_store.threads[s];
        if (!t->in_use)
            break;
        t->pktts = *ts;
        t->sys_sec_stamp = (uint32_t)systs.tv_sec;
    }
    SCMutexUnlock(&thread_store_lock);
}

void TmThreadsGetMinimalTimestamp(struct timeval *ts)
{
    struct timeval local, nullts;
    memset(&local, 0, sizeof(local));
    memset(&nullts, 0, sizeof(nullts));
    int set = 0;
    size_t s;
    struct timeval systs;
    gettimeofday(&systs, NULL);

    SCMutexLock(&thread_store_lock);
    for (s = 0; s < thread_store.threads_size; s++) {
        Thread *t = &thread_store.threads[s];
        if (t->in_use == 0)
            break;
        if (!(timercmp(&t->pktts, &nullts, ==))) {
            /* ignore sleeping threads */
            if (t->sys_sec_stamp + 1 < (uint32_t)systs.tv_sec)
                continue;

            if (!set) {
                local = t->pktts;
                set = 1;
            } else {
                if (timercmp(&t->pktts, &local, <)) {
                    local = t->pktts;
                }
            }
        }
    }
    SCMutexUnlock(&thread_store_lock);
    *ts = local;
    SCLogDebug("ts->tv_sec %"PRIuMAX, (uintmax_t)ts->tv_sec);
}

uint16_t TmThreadsGetWorkerThreadMax()
{
    uint16_t ncpus = UtilCpuGetNumProcessorsOnline();
    int thread_max = TmThreadGetNbThreads(WORKER_CPU_SET);
    /* always create at least one thread */
    if (thread_max == 0)
        thread_max = ncpus * threading_detect_ratio;
    if (thread_max < 1)
        thread_max = 1;
    if (thread_max > 1024) {
        SCLogWarning(SC_ERR_RUNMODE, "limited number of 'worker' threads to 1024. Wanted %d", thread_max);
        thread_max = 1024;
    }
    return (uint16_t)thread_max;
}

static inline void ThreadBreakLoop(ThreadVars *tv)
{
    if ((tv->tmm_flags & TM_FLAG_RECEIVE_TM) == 0) {
        return;
    }
    /* find the correct slot */
    TmSlot *s = tv->tm_slots;
    TmModule *tm = TmModuleGetById(s->tm_id);
    if (tm->flags & TM_FLAG_RECEIVE_TM) {
        /* if the method supports it, BreakLoop. Otherwise we rely on
         * the capture method's recv timeout */
        if (tm->PktAcqLoop && tm->PktAcqBreakLoop) {
            tm->PktAcqBreakLoop(tv, SC_ATOMIC_GET(s->slot_data));
        }
    }
}

/** \brief inject a flow into a threads flow queue
 */
void TmThreadsInjectFlowById(Flow *f, const int id)
{
    BUG_ON(id <= 0 || id > (int)thread_store.threads_size);

    int idx = id - 1;

    Thread *t = &thread_store.threads[idx];
    ThreadVars *tv = t->tv;

    BUG_ON(tv == NULL || tv->flow_queue == NULL);

    FlowEnqueue(tv->flow_queue, f);

    /* wake up listening thread(s) if necessary */
    if (tv->inq != NULL) {
        SCCondSignal(&tv->inq->pq->cond_q);
    } else if (tv->break_loop) {
        ThreadBreakLoop(tv);
    }
}
