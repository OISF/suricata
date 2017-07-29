/* Copyright (C) 2007-2013 Open Information Security Foundation
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
__thread uint64_t mutex_lock_contention;
__thread uint64_t mutex_lock_wait_ticks;
__thread uint64_t mutex_lock_cnt;

__thread uint64_t spin_lock_contention;
__thread uint64_t spin_lock_wait_ticks;
__thread uint64_t spin_lock_cnt;

__thread uint64_t rww_lock_contention;
__thread uint64_t rww_lock_wait_ticks;
__thread uint64_t rww_lock_cnt;

__thread uint64_t rwr_lock_contention;
__thread uint64_t rwr_lock_wait_ticks;
__thread uint64_t rwr_lock_cnt;
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
int TmThreadsCheckFlag(ThreadVars *tv, uint16_t flag)
{
    return (SC_ATOMIC_GET(tv->flags) & flag) ? 1 : 0;
}

/**
 * \brief Set a thread flag.
 */
void TmThreadsSetFlag(ThreadVars *tv, uint16_t flag)
{
    SC_ATOMIC_OR(tv->flags, flag);
}

/**
 * \brief Unset a thread flag.
 */
void TmThreadsUnsetFlag(ThreadVars *tv, uint16_t flag)
{
    SC_ATOMIC_AND(tv->flags, ~flag);
}

/**
 * \brief Separate run function so we can call it recursively.
 *
 * \todo Deal with post_pq for slots beyond the first.
 */
TmEcode TmThreadsSlotVarRun(ThreadVars *tv, Packet *p,
                                          TmSlot *slot)
{
    TmEcode r;
    TmSlot *s;
    Packet *extra_p;

    for (s = slot; s != NULL; s = s->slot_next) {
        TmSlotFunc SlotFunc = SC_ATOMIC_GET(s->SlotFunc);
        PACKET_PROFILING_TMM_START(p, s->tm_id);

        if (unlikely(s->id == 0)) {
            r = SlotFunc(tv, p, SC_ATOMIC_GET(s->slot_data), &s->slot_pre_pq, &s->slot_post_pq);
        } else {
            r = SlotFunc(tv, p, SC_ATOMIC_GET(s->slot_data), &s->slot_pre_pq, NULL);
        }

        PACKET_PROFILING_TMM_END(p, s->tm_id);

        /* handle error */
        if (unlikely(r == TM_ECODE_FAILED)) {
            /* Encountered error.  Return packets to packetpool and return */
            TmqhReleasePacketsToPacketPool(&s->slot_pre_pq);

            SCMutexLock(&s->slot_post_pq.mutex_q);
            TmqhReleasePacketsToPacketPool(&s->slot_post_pq);
            SCMutexUnlock(&s->slot_post_pq.mutex_q);

            TmThreadsSetFlag(tv, THV_FAILED);
            return TM_ECODE_FAILED;
        }

        /* handle new packets */
        while (s->slot_pre_pq.top != NULL) {
            extra_p = PacketDequeue(&s->slot_pre_pq);
            if (unlikely(extra_p == NULL))
                continue;

            /* see if we need to process the packet */
            if (s->slot_next != NULL) {
                r = TmThreadsSlotVarRun(tv, extra_p, s->slot_next);
                if (unlikely(r == TM_ECODE_FAILED)) {
                    TmqhReleasePacketsToPacketPool(&s->slot_pre_pq);

                    SCMutexLock(&s->slot_post_pq.mutex_q);
                    TmqhReleasePacketsToPacketPool(&s->slot_post_pq);
                    SCMutexUnlock(&s->slot_post_pq.mutex_q);

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
    TmSlot *stream_slot = NULL, *slot = NULL;
    int run = 1;
    int r = TM_ECODE_OK;

    for (slot = s; slot != NULL; slot = slot->slot_next) {
        if (slot->tm_id == TMM_FLOWWORKER)
        {
            stream_slot = slot;
            break;
        }
    }

    if (tv->stream_pq == NULL || stream_slot == NULL) {
        SCLogDebug("not running TmThreadTimeoutLoop %p/%p", tv->stream_pq, stream_slot);
        return r;
    }

    SCLogDebug("flow end loop starting");
    while(run) {
        Packet *p;
        if (tv->stream_pq->len != 0) {
            SCMutexLock(&tv->stream_pq->mutex_q);
            p = PacketDequeue(tv->stream_pq);
            SCMutexUnlock(&tv->stream_pq->mutex_q);
            BUG_ON(p == NULL);

            if ((r = TmThreadsSlotProcessPkt(tv, stream_slot, p) != TM_ECODE_OK)) {
                if (r == TM_ECODE_FAILED)
                    run = 0;
            }
        } else {
            usleep(1);
        }

        if (tv->stream_pq->len == 0 && TmThreadsCheckFlag(tv, THV_KILL)) {
            run = 0;
        }
    }
    SCLogDebug("flow end loop complete");

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
    /* block usr2.  usr2 to be handled by the main thread only */
    UtilSignalBlock(SIGUSR2);

    ThreadVars *tv = (ThreadVars *)td;
    TmSlot *s = tv->tm_slots;
    char run = 1;
    TmEcode r = TM_ECODE_OK;
    TmSlot *slot = NULL;

    /* Set the thread name */
    if (SCSetThreadName(tv->name) < 0) {
        SCLogWarning(SC_ERR_THREAD_INIT, "Unable to set thread name");
    }

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
        memset(&slot->slot_pre_pq, 0, sizeof(PacketQueue));
        SCMutexInit(&slot->slot_pre_pq.mutex_q, NULL);
        memset(&slot->slot_post_pq, 0, sizeof(PacketQueue));
        SCMutexInit(&slot->slot_post_pq.mutex_q, NULL);

        /* get the 'pre qeueue' from module before the stream module */
        if (slot->slot_next != NULL && (slot->slot_next->tm_id == TMM_FLOWWORKER)) {
            SCLogDebug("pre-stream packetqueue %p (postq)", &s->slot_post_pq);
            tv->stream_pq = &slot->slot_post_pq;
        /* if the stream module is the first, get the threads input queue */
        } else if (slot == (TmSlot *)tv->tm_slots && (slot->tm_id == TMM_FLOWWORKER)) {
            tv->stream_pq = &trans_q[tv->inq->id];
            SCLogDebug("pre-stream packetqueue %p (inq)", &slot->slot_pre_pq);
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

        BUG_ON(slot->slot_pre_pq.len);
        BUG_ON(slot->slot_post_pq.len);
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

#ifdef AFLFUZZ_PCAP_RUNMODE
/** \brief simplified loop to speed up AFL
 *
 *  The loop runs in the caller's thread. No separate thread.
 */
static void *TmThreadsSlotPktAcqLoopAFL(void *td)
{
    SCLogNotice("AFL mode starting");

    ThreadVars *tv = (ThreadVars *)td;
    TmSlot *s = tv->tm_slots;
    char run = 1;
    TmEcode r = TM_ECODE_OK;
    TmSlot *slot = NULL;

    PacketPoolInit();

    /* check if we are setup properly */
    if (s == NULL || s->PktAcqLoop == NULL || tv->tmqh_in == NULL || tv->tmqh_out == NULL) {
        SCLogError(SC_ERR_FATAL, "TmSlot or ThreadVars badly setup: s=%p,"
                                 " PktAcqLoop=%p, tmqh_in=%p,"
                                 " tmqh_out=%p",
                   s, s ? s->PktAcqLoop : NULL, tv->tmqh_in, tv->tmqh_out);
        TmThreadsSetFlag(tv, THV_CLOSED | THV_RUNNING_DONE);
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
        memset(&slot->slot_pre_pq, 0, sizeof(PacketQueue));
        SCMutexInit(&slot->slot_pre_pq.mutex_q, NULL);
        memset(&slot->slot_post_pq, 0, sizeof(PacketQueue));
        SCMutexInit(&slot->slot_post_pq.mutex_q, NULL);

        /* get the 'pre qeueue' from module before the stream module */
        if (slot->slot_next != NULL && (slot->slot_next->tm_id == TMM_FLOWWORKER)) {
            SCLogDebug("pre-stream packetqueue %p (postq)", &s->slot_post_pq);
            tv->stream_pq = &slot->slot_post_pq;
        /* if the stream module is the first, get the threads input queue */
        } else if (slot == (TmSlot *)tv->tm_slots && (slot->tm_id == TMM_FLOWWORKER)) {
            tv->stream_pq = &trans_q[tv->inq->id];
            SCLogDebug("pre-stream packetqueue %p (inq)", &slot->slot_pre_pq);
        }
    }

    StatsSetupPrivate(tv);

    TmThreadsSetFlag(tv, THV_INIT_DONE);

    while(run) {
        /* run right away */

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

    TmThreadsSetFlag(tv, THV_RUNNING_DONE);

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

        BUG_ON(slot->slot_pre_pq.len);
        BUG_ON(slot->slot_post_pq.len);
    }

    tv->stream_pq = NULL;
    SCLogDebug("%s ending", tv->name);
    TmThreadsSetFlag(tv, THV_CLOSED);
    return NULL;

error:
    tv->stream_pq = NULL;
    return NULL;
}
#endif

/**
 * \todo Only the first "slot" currently makes the "post_pq" available
 *       to the thread module.
 */
static void *TmThreadsSlotVar(void *td)
{
    /* block usr2.  usr2 to be handled by the main thread only */
    UtilSignalBlock(SIGUSR2);

    ThreadVars *tv = (ThreadVars *)td;
    TmSlot *s = (TmSlot *)tv->tm_slots;
    Packet *p = NULL;
    char run = 1;
    TmEcode r = TM_ECODE_OK;

    PacketPoolInitEmpty();

    /* Set the thread name */
    if (SCSetThreadName(tv->name) < 0) {
        SCLogWarning(SC_ERR_THREAD_INIT, "Unable to set thread name");
    }

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
        memset(&s->slot_pre_pq, 0, sizeof(PacketQueue));
        SCMutexInit(&s->slot_pre_pq.mutex_q, NULL);
        memset(&s->slot_post_pq, 0, sizeof(PacketQueue));
        SCMutexInit(&s->slot_post_pq.mutex_q, NULL);

        /* special case: we need to access the stream queue
         * from the flow timeout code */

        /* get the 'pre qeueue' from module before the stream module */
        if (s->slot_next != NULL && (s->slot_next->tm_id == TMM_FLOWWORKER)) {
            SCLogDebug("pre-stream packetqueue %p (preq)", &s->slot_pre_pq);
            tv->stream_pq = &s->slot_pre_pq;
        /* if the stream module is the first, get the threads input queue */
        } else if (s == (TmSlot *)tv->tm_slots && (s->tm_id == TMM_FLOWWORKER)) {
            tv->stream_pq = &trans_q[tv->inq->id];
            SCLogDebug("pre-stream packetqueue %p (inq)", &s->slot_pre_pq);
        }
    }

    StatsSetupPrivate(tv);

    TmThreadsSetFlag(tv, THV_INIT_DONE);

    s = (TmSlot *)tv->tm_slots;

    while (run) {
        if (TmThreadsCheckFlag(tv, THV_PAUSE)) {
            TmThreadsSetFlag(tv, THV_PAUSED);
            TmThreadTestThreadUnPaused(tv);
            TmThreadsUnsetFlag(tv, THV_PAUSED);
        }

        /* input a packet */
        p = tv->tmqh_in(tv);

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

        } /* if (p != NULL) */

        /* now handle the post_pq packets */
        TmSlot *slot;
        for (slot = s; slot != NULL; slot = slot->slot_next) {
            if (slot->slot_post_pq.top != NULL) {
                while (1) {
                    SCMutexLock(&slot->slot_post_pq.mutex_q);
                    Packet *extra_p = PacketDequeue(&slot->slot_post_pq);
                    SCMutexUnlock(&slot->slot_post_pq.mutex_q);

                    if (extra_p == NULL)
                        break;

                    if (slot->slot_next != NULL) {
                        r = TmThreadsSlotVarRun(tv, extra_p, slot->slot_next);
                        if (r == TM_ECODE_FAILED) {
                            SCMutexLock(&slot->slot_post_pq.mutex_q);
                            TmqhReleasePacketsToPacketPool(&slot->slot_post_pq);
                            SCMutexUnlock(&slot->slot_post_pq.mutex_q);

                            TmqhOutputPacketpool(tv, extra_p);
                            TmThreadsSetFlag(tv, THV_FAILED);
                            break;
                        }
                    }
                    /* output the packet */
                    tv->tmqh_out(tv, extra_p);
                } /* while */
            } /* if */
        } /* for */

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
        BUG_ON(s->slot_pre_pq.len);
        BUG_ON(s->slot_post_pq.len);
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
    /* block usr2.  usr2 to be handled by the main thread only */
    UtilSignalBlock(SIGUSR2);

    ThreadVars *tv = (ThreadVars *)td;
    TmSlot *s = (TmSlot *)tv->tm_slots;
    TmEcode r = TM_ECODE_OK;

    BUG_ON(s == NULL);

    /* Set the thread name */
    if (SCSetThreadName(tv->name) < 0) {
        SCLogWarning(SC_ERR_THREAD_INIT, "Unable to set thread name");
    }

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
    memset(&s->slot_pre_pq, 0, sizeof(PacketQueue));
    memset(&s->slot_post_pq, 0, sizeof(PacketQueue));

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
#ifndef AFLFUZZ_PCAP_RUNMODE
        tv->tm_func = TmThreadsSlotPktAcqLoop;
#else
        tv->tm_func = TmThreadsSlotPktAcqLoopAFL;
#endif
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

ThreadVars *TmThreadsGetTVContainingSlot(TmSlot *tm_slot)
{
    ThreadVars *tv;
    int i;

    SCMutexLock(&tv_root_lock);

    for (i = 0; i < TVT_MAX; i++) {
        tv = tv_root[i];

        while (tv) {
            TmSlot *slots = tv->tm_slots;
            while (slots != NULL) {
                if (slots == tm_slot) {
                    SCMutexUnlock(&tv_root_lock);
                    return tv;
                }
                slots = slots->slot_next;
            }
            tv = tv->next;
        }
    }

    SCMutexUnlock(&tv_root_lock);

    return NULL;
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
    SC_ATOMIC_INIT(slot->slot_data);
    slot->tv = tv;
    slot->SlotThreadInit = tm->ThreadInit;
    slot->slot_initdata = data;
    SC_ATOMIC_INIT(slot->SlotFunc);
    (void)SC_ATOMIC_SET(slot->SlotFunc, tm->Func);
    slot->PktAcqLoop = tm->PktAcqLoop;
    slot->Management = tm->Management;
    slot->SlotThreadExitPrintStats = tm->ThreadExitPrintStats;
    slot->SlotThreadDeinit = tm->ThreadDeinit;
    /* we don't have to check for the return value "-1".  We wouldn't have
     * received a TM as arg, if it didn't exist */
    slot->tm_id = TmModuleGetIDForTM(tm);

    tv->tmm_flags |= tm->flags;
    tv->cap_flags |= tm->cap_flags;

    if (tv->tm_slots == NULL) {
        tv->tm_slots = slot;
        slot->id = 0;
    } else {
        TmSlot *a = (TmSlot *)tv->tm_slots, *b = NULL;

        /* get the last slot */
        for ( ; a != NULL; a = a->slot_next) {
             b = a;
        }
        /* append the new slot */
        if (b != NULL) {
            b->slot_next = slot;
            slot->id = b->id + 1;
        }
    }
    return;
}

/**
 * \brief Returns the slot holding a TM with the particular tm_id.
 *
 * \param tm_id TM id of the TM whose slot has to be returned.
 *
 * \retval slots Pointer to the slot.
 */
TmSlot *TmSlotGetSlotForTM(int tm_id)
{
    ThreadVars *tv = NULL;
    TmSlot *slots;
    int i;

    SCMutexLock(&tv_root_lock);

    for (i = 0; i < TVT_MAX; i++) {
        tv = tv_root[i];
        while (tv) {
            slots = tv->tm_slots;
            while (slots != NULL) {
                if (slots->tm_id == tm_id) {
                    SCMutexUnlock(&tv_root_lock);
                    return slots;
                }
                slots = slots->slot_next;
            }
            tv = tv->next;
        }
    }

    SCMutexUnlock(&tv_root_lock);

    return NULL;
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
            int cpu = AffinityGetNextCPU(taf);
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

        tmqh = TmqhGetQueueHandlerByName(inqh_name);
        if (tmqh == NULL)
            goto error;

        tv->tmqh_in = tmqh->InHandler;
        tv->InShutdownHandler = tmqh->InShutdownHandler;
        SCLogDebug("tv->tmqh_in %p", tv->tmqh_in);
    }

    /* set the outgoing queue */
    if (outqh_name != NULL) {
        SCLogDebug("outqh_name \"%s\"", outqh_name);

        tmqh = TmqhGetQueueHandlerByName(outqh_name);
        if (tmqh == NULL)
            goto error;

        tv->tmqh_out = tmqh->OutHandler;
        tv->outqh_name = tmqh->name;

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
        tv->prev = NULL;

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

    return;
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
 *
 * \retval r 1 killed succesfully
 *           0 not yet ready, needs another look
 */
static int TmThreadKillThread(ThreadVars *tv)
{
    int i = 0;

    BUG_ON(tv == NULL);

    /* kill only once :) */
    if (TmThreadsCheckFlag(tv, THV_DEAD)) {
        return 1;
    }

    if (tv->inq != NULL) {
        /* we wait till we dry out all the inq packets, before we
         * kill this thread.  Do note that you should have disabled
         * packet acquire by now using TmThreadDisableReceiveThreads()*/
        if (!(strlen(tv->inq->name) == strlen("packetpool") &&
              strcasecmp(tv->inq->name, "packetpool") == 0)) {
            PacketQueue *q = &trans_q[tv->inq->id];
            if (q->len != 0) {
                return 0;
            }
        }
    }

    /* set the thread flag informing the thread that it needs to be
     * terminated */
    TmThreadsSetFlag(tv, THV_KILL);
    TmThreadsSetFlag(tv, THV_DEINIT);

    /* to be sure, signal more */
    if (!(TmThreadsCheckFlag(tv, THV_CLOSED))) {
        if (tv->InShutdownHandler != NULL) {
            tv->InShutdownHandler(tv);
        }
        if (tv->inq != NULL) {
            for (i = 0; i < (tv->inq->reader_cnt + tv->inq->writer_cnt); i++) {
                if (tv->inq->q_type == 0)
                    SCCondSignal(&trans_q[tv->inq->id].cond_q);
                else
                    SCCondSignal(&data_queues[tv->inq->id].cond_q);
            }
            SCLogDebug("signalled tv->inq->id %" PRIu32 "", tv->inq->id);
        }

        if (tv->ctrl_cond != NULL ) {
            pthread_cond_broadcast(tv->ctrl_cond);
        }
        return 0;
    }

    if (tv->outctx != NULL) {
        Tmqh *tmqh = TmqhGetQueueHandlerByName(tv->outqh_name);
        if (tmqh == NULL)
            BUG_ON(1);

        if (tmqh->OutHandlerCtxFree != NULL) {
            tmqh->OutHandlerCtxFree(tv->outctx);
            tv->outctx = NULL;
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
 *         in-flight packets
 */
static void TmThreadDrainPacketThreads(void)
{
    /* value in seconds */
#define THREAD_KILL_MAX_WAIT_TIME 60
    /* value in microseconds */
#define WAIT_TIME 1000

    uint64_t total_wait_time = 0;

    ThreadVars *tv = NULL;

again:
    if (total_wait_time > (THREAD_KILL_MAX_WAIT_TIME * 1000000)) {
        SCLogWarning(SC_ERR_SHUTDOWN, "unable to get all packet threads "
                "to process their packets in time");
        return;
    }

    SCMutexLock(&tv_root_lock);

    /* all receive threads are part of packet processing threads */
    tv = tv_root[TVT_PPT];

    while (tv) {
        if (tv->inq != NULL) {
            /* we wait till we dry out all the inq packets, before we
             * kill this thread.  Do note that you should have disabled
             * packet acquire by now using TmThreadDisableReceiveThreads()*/
            if (!(strlen(tv->inq->name) == strlen("packetpool") &&
                        strcasecmp(tv->inq->name, "packetpool") == 0)) {
                PacketQueue *q = &trans_q[tv->inq->id];
                if (q->len != 0) {
                    SCMutexUnlock(&tv_root_lock);

                    total_wait_time += WAIT_TIME;

                    /* don't sleep while holding a lock */
                    usleep(WAIT_TIME);
                    goto again;
                }
            }
        }

        tv = tv->next;
    }

    SCMutexUnlock(&tv_root_lock);
    return;

#undef THREAD_KILL_MAX_WAIT_TIME
#undef WAIT_TIME
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
    /* value in seconds */
#define THREAD_KILL_MAX_WAIT_TIME 60
    /* value in microseconds */
#define WAIT_TIME 100

    double total_wait_time = 0;

    ThreadVars *tv = NULL;

again:
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
            if (tv->inq != NULL) {
                /* we wait till we dry out all the inq packets, before we
                 * kill this thread.  Do note that you should have disabled
                 * packet acquire by now using TmThreadDisableReceiveThreads()*/
                if (!(strlen(tv->inq->name) == strlen("packetpool") &&
                      strcasecmp(tv->inq->name, "packetpool") == 0)) {
                    PacketQueue *q = &trans_q[tv->inq->id];
                    if (q->len != 0) {
                        SCMutexUnlock(&tv_root_lock);
                        /* don't sleep while holding a lock */
                        usleep(1000);
                        goto again;
                    }
                }
            }

            /* we found a receive TV. Send it a KILL_PKTACQ signal. */
            if (tm && tm->PktAcqBreakLoop != NULL) {
                tm->PktAcqBreakLoop(tv, SC_ATOMIC_GET(slots->slot_data));
            }
            TmThreadsSetFlag(tv, THV_KILL_PKTACQ);

            if (tv->inq != NULL) {
                int i;
                for (i = 0; i < (tv->inq->reader_cnt + tv->inq->writer_cnt); i++) {
                    if (tv->inq->q_type == 0)
                        SCCondSignal(&trans_q[tv->inq->id].cond_q);
                    else
                        SCCondSignal(&data_queues[tv->inq->id].cond_q);
                }
                SCLogDebug("signalled tv->inq->id %" PRIu32 "", tv->inq->id);
            }

            /* wait for it to enter the 'flow loop' stage */
            while (!TmThreadsCheckFlag(tv, THV_FLOW_LOOP)) {
                SCMutexUnlock(&tv_root_lock);

                usleep(WAIT_TIME);
                total_wait_time += WAIT_TIME / 1000000.0;
                if (total_wait_time > THREAD_KILL_MAX_WAIT_TIME) {
                    SCLogError(SC_ERR_FATAL, "Engine unable to "
                               "disable detect thread - \"%s\".  "
                               "Killing engine", tv->name);
                    exit(EXIT_FAILURE);
                }
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

/**
 * \brief Disable all threads having the specified TMs.
 */
void TmThreadDisablePacketThreads(void)
{
    /* value in seconds */
#define THREAD_KILL_MAX_WAIT_TIME 60
    /* value in microseconds */
#define WAIT_TIME 100

    double total_wait_time = 0;

    ThreadVars *tv = NULL;

    /* first drain all packet threads of their packets */
    TmThreadDrainPacketThreads();
again:
    SCMutexLock(&tv_root_lock);

    /* all receive threads are part of packet processing threads */
    tv = tv_root[TVT_PPT];

    /* we do have to keep in mind that TVs are arranged in the order
     * right from receive to log.  The moment we fail to find a
     * receive TM amongst the slots in a tv, it indicates we are done
     * with all receive threads */
    while (tv) {
        if (tv->inq != NULL) {
            /* we wait till we dry out all the inq packets, before we
             * kill this thread.  Do note that you should have disabled
             * packet acquire by now using TmThreadDisableReceiveThreads()*/
            if (!(strlen(tv->inq->name) == strlen("packetpool") &&
                        strcasecmp(tv->inq->name, "packetpool") == 0)) {
                PacketQueue *q = &trans_q[tv->inq->id];
                if (q->len != 0) {
                    SCMutexUnlock(&tv_root_lock);
                    /* don't sleep while holding a lock */
                    usleep(1000);
                    goto again;
                }
            }
        }

        /* we found our receive TV.  Send it a KILL signal.  This is all
         * we need to do to kill receive threads */
        TmThreadsSetFlag(tv, THV_KILL);

        if (tv->inq != NULL) {
            int i;
            for (i = 0; i < (tv->inq->reader_cnt + tv->inq->writer_cnt); i++) {
                if (tv->inq->q_type == 0)
                    SCCondSignal(&trans_q[tv->inq->id].cond_q);
                else
                    SCCondSignal(&data_queues[tv->inq->id].cond_q);
            }
            SCLogDebug("signalled tv->inq->id %" PRIu32 "", tv->inq->id);
        }

        while (!TmThreadsCheckFlag(tv, THV_RUNNING_DONE)) {
            SCMutexUnlock(&tv_root_lock);

            usleep(WAIT_TIME);
            total_wait_time += WAIT_TIME / 1000000.0;
            if (total_wait_time > THREAD_KILL_MAX_WAIT_TIME) {
                SCLogError(SC_ERR_FATAL, "Engine unable to "
                        "disable detect thread - \"%s\".  "
                        "Killing engine", tv->name);
                exit(EXIT_FAILURE);
            }
            goto again;
        }

        tv = tv->next;
    }

    SCMutexUnlock(&tv_root_lock);

    return;
}

TmSlot *TmThreadGetFirstTmSlotForPartialPattern(const char *tm_name)
{
    ThreadVars *tv = NULL;
    TmSlot *slots = NULL;

    SCMutexLock(&tv_root_lock);

    /* all receive threads are part of packet processing threads */
    tv = tv_root[TVT_PPT];

    while (tv) {
        slots = tv->tm_slots;

        while (slots != NULL) {
            TmModule *tm = TmModuleGetById(slots->tm_id);

            char *found = strstr(tm->name, tm_name);
            if (found != NULL)
                goto end;

            slots = slots->slot_next;
        }

        tv = tv->next;
    }

 end:
    SCMutexUnlock(&tv_root_lock);
    return slots;
}

#define MIN_WAIT_TIME 100
void TmThreadKillThreadsFamily(int family)
{
    ThreadVars *tv = NULL;
    unsigned int sleep = MIN_WAIT_TIME;

    BUG_ON((family < 0) || (family >= TVT_MAX));

again:
    SCMutexLock(&tv_root_lock);
    tv = tv_root[family];

    while (tv) {
        int r = TmThreadKillThread(tv);
        if (r == 0) {
            SCMutexUnlock(&tv_root_lock);
            usleep(sleep);
            sleep += MIN_WAIT_TIME; /* slowly back off */
            goto again;
        }
        sleep = MIN_WAIT_TIME; /* reset */

        tv = tv->next;
    }
    SCMutexUnlock(&tv_root_lock);
}

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

    StatsThreadCleanup(tv);

    TmThreadDeinitMC(tv);

    if (tv->thread_group_name) {
        SCFree(tv->thread_group_name);
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

    TmThreadWaitForFlag(tv, THV_INIT_DONE | THV_RUNNING_DONE);

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
        SCLogError(SC_ERR_FATAL, "Fatal error encountered in TmThreadInitMC.  "
                   "Exiting...");
        exit(EXIT_FAILURE);
    }

    if (SCCtrlMutexInit(tv->ctrl_mutex, NULL) != 0) {
        printf("Error initializing the tv->m mutex\n");
        exit(EXIT_FAILURE);
    }

    if ( (tv->ctrl_cond = SCMalloc(sizeof(*tv->ctrl_cond))) == NULL) {
        SCLogError(SC_ERR_FATAL, "Fatal error encountered in TmThreadInitMC.  "
                   "Exiting...");
        exit(EXIT_FAILURE);
    }

    if (SCCtrlCondInit(tv->ctrl_cond, NULL) != 0) {
        SCLogError(SC_ERR_FATAL, "Error initializing the tv->cond condition "
                   "variable");
        exit(EXIT_FAILURE);
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
        usleep(100);

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
void TmThreadWaitForFlag(ThreadVars *tv, uint16_t flags)
{
    while (!TmThreadsCheckFlag(tv, flags)) {
        usleep(100);
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

    SCMutexLock(&tv_root_lock);
    for (i = 0; i < TVT_MAX; i++) {
        tv = tv_root[i];
        while (tv != NULL) {
            TmThreadContinue(tv);
            tv = tv->next;
        }
    }
    SCMutexUnlock(&tv_root_lock);

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

    TmThreadsListThreads();

    SCMutexLock(&tv_root_lock);
    for (i = 0; i < TVT_MAX; i++) {
        tv = tv_root[i];
        while (tv != NULL) {
            TmThreadPause(tv);
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
    ThreadVars *tv = NULL;
    int i = 0;

    SCMutexLock(&tv_root_lock);
    for (i = 0; i < TVT_MAX; i++) {
        tv = tv_root[i];

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
    ThreadVars *tv = NULL;
    int i = 0;
    uint16_t mgt_num = 0;
    uint16_t ppt_num = 0;

    uint64_t slept = 0;

again:
    SCMutexLock(&tv_root_lock);
    for (i = 0; i < TVT_MAX; i++) {
        tv = tv_root[i];
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

                if (slept > (120*1000000)) {
                    SCLogError(SC_ERR_THREAD_INIT, "thread \"%s\" failed to "
                            "initialize in time: flags %04x", tv->name,
                            SC_ATOMIC_GET(tv->flags));
                    return TM_ECODE_FAILED;
                }

                /* sleep a little to give the thread some
                 * time to finish initialization */
                usleep(100);
                slept += 100;
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

            if (i == TVT_MGMT)
                mgt_num++;
            else if (i == TVT_PPT)
                ppt_num++;

            tv = tv->next;
        }
    }
    SCMutexUnlock(&tv_root_lock);

    SCLogNotice("all %"PRIu16" packet processing threads, %"PRIu16" management "
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

/**
 * \brief returns a count of all the threads that match the flag
 */
uint32_t TmThreadCountThreadsByTmmFlags(uint8_t flags)
{
    ThreadVars *tv = NULL;
    int i = 0;
    uint32_t cnt = 0;

    SCMutexLock(&tv_root_lock);
    for (i = 0; i < TVT_MAX; i++) {
        tv = tv_root[i];
        while (tv != NULL) {
            if ((tv->tmm_flags & flags) == flags)
                cnt++;

            tv = tv->next;
        }
    }
    SCMutexUnlock(&tv_root_lock);
    return cnt;
}

typedef struct Thread_ {
    ThreadVars *tv;     /**< threadvars structure */
    const char *name;
    int type;
    int in_use;         /**< bool to indicate this is in use */

    struct timeval ts;  /**< current time of this thread (offline mode) */
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
    Thread *t;
    size_t s;

    SCMutexLock(&thread_store_lock);

    for (s = 0; s < thread_store.threads_size; s++) {
        t = &thread_store.threads[s];
        if (t == NULL || t->in_use == 0)
            continue;
        SCLogInfo("Thread %"PRIuMAX", %s type %d, tv %p", (uintmax_t)s+1, t->name, t->type, t->tv);
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
    t->ts.tv_sec = ts->tv_sec;
    t->ts.tv_usec = ts->tv_usec;
    SCMutexUnlock(&thread_store_lock);
}

#define COPY_TIMESTAMP(src,dst) ((dst)->tv_sec = (src)->tv_sec, (dst)->tv_usec = (src)->tv_usec) // XXX unify with flow-util.h
void TmreadsGetMinimalTimestamp(struct timeval *ts)
{
    struct timeval local, nullts;
    memset(&local, 0, sizeof(local));
    memset(&nullts, 0, sizeof(nullts));
    int set = 0;
    size_t s;

    SCMutexLock(&thread_store_lock);
    for (s = 0; s < thread_store.threads_size; s++) {
        Thread *t = &thread_store.threads[s];
        if (t == NULL || t->in_use == 0)
            continue;
        if (!(timercmp(&t->ts, &nullts, ==))) {
            if (!set) {
                local.tv_sec = t->ts.tv_sec;
                local.tv_usec = t->ts.tv_usec;
                set = 1;
            } else {
                if (timercmp(&t->ts, &local, <)) {
                    COPY_TIMESTAMP(&t->ts, &local);
                }
            }
        }
    }
    SCMutexUnlock(&thread_store_lock);
    COPY_TIMESTAMP(&local, ts);
    SCLogDebug("ts->tv_sec %"PRIuMAX, (uintmax_t)ts->tv_sec);
}
#undef COPY_TIMESTAMP

/**
 *  \retval r 1 if packet was accepted, 0 otherwise
 *  \note if packet was not accepted, it's still the responsibility
 *        of the caller.
 */
int TmThreadsInjectPacketsById(Packet **packets, const int id)
{
    if (id <= 0 || id > (int)thread_store.threads_size)
        return 0;

    int idx = id - 1;

    Thread *t = &thread_store.threads[idx];
    ThreadVars *tv = t->tv;

    if (tv == NULL || tv->stream_pq == NULL)
        return 0;

    SCMutexLock(&tv->stream_pq->mutex_q);
    while (*packets != NULL) {
        PacketEnqueue(tv->stream_pq, *packets);
        packets++;
    }
    SCMutexUnlock(&tv->stream_pq->mutex_q);

    /* wake up listening thread(s) if necessary */
    if (tv->inq != NULL) {
        SCCondSignal(&trans_q[tv->inq->id].cond_q);
    }
    return 1;
}
