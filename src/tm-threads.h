/* Copyright (C) 2007-2011 Open Information Security Foundation
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
 */

#ifndef __TM_THREADS_H__
#define __TM_THREADS_H__

#include "tmqh-packetpool.h"
#include "tm-threads-common.h"
#include "tm-modules.h"

#ifdef OS_WIN32
static inline void SleepUsec(uint64_t usec)
{
    uint64_t msec = 1;
    if (usec > 1000) {
        msec = usec / 1000;
    }
    Sleep(msec);
}
#define SleepMsec(msec) Sleep((msec))
#else
#define SleepUsec(usec) usleep((usec))
#define SleepMsec(msec) usleep((msec) * 1000)
#endif

#define TM_QUEUE_NAME_MAX 16
#define TM_THREAD_NAME_MAX 16

typedef TmEcode (*TmSlotFunc)(ThreadVars *, Packet *, void *);

typedef struct TmSlot_ {
    /* function pointers */
    union {
        TmSlotFunc SlotFunc;
        TmEcode (*PktAcqLoop)(ThreadVars *, void *, void *);
        TmEcode (*Management)(ThreadVars *, void *);
    };
    /** linked list of slots, used when a pipeline has multiple slots
     *  in a single thread. */
    struct TmSlot_ *slot_next;

    SC_ATOMIC_DECLARE(void *, slot_data);

    TmEcode (*SlotThreadInit)(ThreadVars *, const void *, void **);
    void (*SlotThreadExitPrintStats)(ThreadVars *, void *);
    TmEcode (*SlotThreadDeinit)(ThreadVars *, void *);

    /* data storage */
    const void *slot_initdata;
    /* store the thread module id */
    int tm_id;

} TmSlot;

extern ThreadVars *tv_root[TVT_MAX];

extern SCMutex tv_root_lock;

void TmSlotSetFuncAppend(ThreadVars *, TmModule *, const void *);

ThreadVars *TmThreadCreate(const char *, const char *, const char *, const char *, const char *, const char *,
                           void *(fn_p)(void *), int);
ThreadVars *TmThreadCreatePacketHandler(const char *, const char *, const char *, const char *, const char *,
                                        const char *);
ThreadVars *TmThreadCreateMgmtThread(const char *name, void *(fn_p)(void *), int);
ThreadVars *TmThreadCreateMgmtThreadByName(const char *name, const char *module,
                                     int mucond);
ThreadVars *TmThreadCreateCmdThreadByName(const char *name, const char *module,
                                     int mucond);
TmEcode TmThreadSpawn(ThreadVars *);
void TmThreadSetFlags(ThreadVars *, uint8_t);
void TmThreadKillThreadsFamily(int family);
void TmThreadKillThreads(void);
void TmThreadClearThreadsFamily(int family);
void TmThreadAppend(ThreadVars *, int);
void TmThreadSetGroupName(ThreadVars *tv, const char *name);

TmEcode TmThreadSetCPUAffinity(ThreadVars *, uint16_t);
TmEcode TmThreadSetThreadPriority(ThreadVars *, int);
TmEcode TmThreadSetCPU(ThreadVars *, uint8_t);
TmEcode TmThreadSetupOptions(ThreadVars *);
void TmThreadSetPrio(ThreadVars *);
int TmThreadGetNbThreads(uint8_t type);

void TmThreadInitMC(ThreadVars *);
void TmThreadTestThreadUnPaused(ThreadVars *);
void TmThreadContinue(ThreadVars *);
void TmThreadContinueThreads(void);
void TmThreadCheckThreadState(void);
TmEcode TmThreadWaitOnThreadInit(void);

int TmThreadsCheckFlag(ThreadVars *, uint32_t);
void TmThreadsSetFlag(ThreadVars *, uint32_t);
void TmThreadsUnsetFlag(ThreadVars *, uint32_t);
void TmThreadWaitForFlag(ThreadVars *, uint32_t);

TmEcode TmThreadsSlotVarRun (ThreadVars *tv, Packet *p, TmSlot *slot);

void TmThreadDisablePacketThreads(void);
void TmThreadDisableReceiveThreads(void);

uint32_t TmThreadCountThreadsByTmmFlags(uint8_t flags);

TmEcode TmThreadWaitOnThreadRunning(void);

static inline void TmThreadsCleanDecodePQ(PacketQueueNoLock *pq)
{
    while (1) {
        Packet *p = PacketDequeueNoLock(pq);
        if (unlikely(p == NULL))
            break;
        TmqhOutputPacketpool(NULL, p);
    }
}

static inline void TmThreadsSlotProcessPktFail(ThreadVars *tv, TmSlot *s, Packet *p)
{
    if (p != NULL) {
        TmqhOutputPacketpool(tv, p);
    }
    TmThreadsCleanDecodePQ(&tv->decode_pq);
    if (tv->stream_pq_local) {
        SCMutexLock(&tv->stream_pq_local->mutex_q);
        TmqhReleasePacketsToPacketPool(tv->stream_pq_local);
        SCMutexUnlock(&tv->stream_pq_local->mutex_q);
    }
    TmThreadsSetFlag(tv, THV_FAILED);
}

/**
 *  \brief Handle timeout from the capture layer. Checks
 *         stream_pq which may have been filled by the flow
 *         manager.
 *  \param s pipeline to run on these packets.
 */
static inline bool TmThreadsHandleInjectedPackets(ThreadVars *tv)
{
    PacketQueue *pq = tv->stream_pq_local;
    if (pq && pq->len > 0) {
        while (1) {
            SCMutexLock(&pq->mutex_q);
            Packet *extra_p = PacketDequeue(pq);
            SCMutexUnlock(&pq->mutex_q);
            if (extra_p == NULL)
                break;
            TmEcode r = TmThreadsSlotVarRun(tv, extra_p, tv->tm_flowworker);
            if (r == TM_ECODE_FAILED) {
                TmThreadsSlotProcessPktFail(tv, tv->tm_flowworker, extra_p);
                break;
            }
            tv->tmqh_out(tv, extra_p);
        }
        return true;
    } else {
        return false;
    }
}

/**
 *  \brief Process the rest of the functions (if any) and queue.
 */
static inline TmEcode TmThreadsSlotProcessPkt(ThreadVars *tv, TmSlot *s, Packet *p)
{
    if (s == NULL) {
        tv->tmqh_out(tv, p);
        return TM_ECODE_OK;
    }

    TmEcode r = TmThreadsSlotVarRun(tv, p, s);
    if (unlikely(r == TM_ECODE_FAILED)) {
        TmThreadsSlotProcessPktFail(tv, s, p);
        return TM_ECODE_FAILED;
    }

    tv->tmqh_out(tv, p);

    TmThreadsHandleInjectedPackets(tv);

    return TM_ECODE_OK;
}

/** \brief inject packet if THV_CAPTURE_INJECT_PKT is set
 *  Allow caller to supply their own packet
 *
 *  Meant for detect reload process that interupts an sleeping capture thread
 *  to force a packet through the engine to complete a reload */
static inline void TmThreadsCaptureInjectPacket(ThreadVars *tv, Packet *p)
{
    TmThreadsUnsetFlag(tv, THV_CAPTURE_INJECT_PKT);
    if (p == NULL)
        p = PacketGetFromQueueOrAlloc();
    if (p != NULL) {
        p->flags |= PKT_PSEUDO_STREAM_END;
        PKT_SET_SRC(p, PKT_SRC_CAPTURE_TIMEOUT);
        if (TmThreadsSlotProcessPkt(tv, tv->tm_flowworker, p) != TM_ECODE_OK) {
            TmqhOutputPacketpool(tv, p);
        }
    }
}

/** \brief handle capture timeout
 *  When a capture method times out we check for house keeping
 *  tasks in the capture thread.
 *
 *  \param p packet. Capture method may have taken a packet from
 *           the pool prior to the timing out call. We will then
 *           use that packet. Otherwise we can get our own.
 */
static inline void TmThreadsCaptureHandleTimeout(ThreadVars *tv, Packet *p)
{
    if (TmThreadsCheckFlag(tv, THV_CAPTURE_INJECT_PKT)) {
        TmThreadsCaptureInjectPacket(tv, p); /* consumes 'p' */
        return;

    } else {
        if (TmThreadsHandleInjectedPackets(tv) == false) {
            /* see if we have to do some house keeping */
            if (tv->flow_queue && SC_ATOMIC_GET(tv->flow_queue->non_empty) == true) {
                TmThreadsCaptureInjectPacket(tv, p); /* consumes 'p' */
                return;
            }
        }
    }

    /* packet could have been passed to us that we won't use
     * return it to the pool. */
    if (p != NULL)
        tv->tmqh_out(tv, p);
}

void TmThreadsListThreads(void);
int TmThreadsRegisterThread(ThreadVars *tv, const int type);
void TmThreadsUnregisterThread(const int id);
void TmThreadsInjectFlowById(Flow *f, const int id);

void TmThreadsInitThreadsTimestamp(const struct timeval *ts);
void TmThreadsSetThreadTimestamp(const int id, const struct timeval *ts);
void TmThreadsGetMinimalTimestamp(struct timeval *ts);
uint16_t TmThreadsGetWorkerThreadMax(void);
bool TmThreadsTimeSubsysIsReady(void);

#endif /* __TM_THREADS_H__ */
