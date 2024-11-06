/* Copyright (C) 2007-2024 Open Information Security Foundation
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
 * \author Anoop Saldanha <anoopsaldanha@gmail.com>
 * \author Victor Julien <victor@inliniac.net>
 */

#include "suricata-common.h"
#include "conf.h"
#include "threadvars.h"
#include "tm-threads.h"
#include "runmodes.h"

#include "util-time.h"

#include "flow.h"
#include "flow-queue.h"
#include "flow-hash.h"
#include "flow-util.h"
#include "flow-private.h"
#include "flow-timeout.h"
#include "flow-manager.h"
#include "flow-storage.h"
#include "flow-spare-pool.h"
#include "flow-callbacks.h"

#include "stream-tcp.h"
#include "stream-tcp-cache.h"

#include "util-device.h"

#include "util-debug.h"

#include "threads.h"
#include "detect-engine-threshold.h"

#include "host-timeout.h"
#include "defrag-hash.h"
#include "defrag-timeout.h"
#include "ippair-timeout.h"
#include "app-layer-htp-range.h"

#include "output-flow.h"

#include "runmode-unix-socket.h"

/** queue to pass flows to cleanup/log thread(s) */
FlowQueue flow_recycle_q;

/* multi flow manager support */
static uint32_t flowmgr_number = 1;
/* atomic counter for flow managers, to assign instance id */
SC_ATOMIC_DECLARE(uint32_t, flowmgr_cnt);

/* multi flow recycler support */
static uint32_t flowrec_number = 1;
/* atomic counter for flow recyclers, to assign instance id */
SC_ATOMIC_DECLARE(uint32_t, flowrec_cnt);
SC_ATOMIC_DECLARE(uint32_t, flowrec_busy);
SC_ATOMIC_EXTERN(unsigned int, flow_flags);

static SCCtrlCondT flow_manager_ctrl_cond = PTHREAD_COND_INITIALIZER;
static SCCtrlMutex flow_manager_ctrl_mutex = PTHREAD_MUTEX_INITIALIZER;
static SCCtrlCondT flow_recycler_ctrl_cond = PTHREAD_COND_INITIALIZER;
static SCCtrlMutex flow_recycler_ctrl_mutex = PTHREAD_MUTEX_INITIALIZER;

void FlowWakeupFlowManagerThread(void)
{
    SCCtrlMutexLock(&flow_manager_ctrl_mutex);
    SCCtrlCondSignal(&flow_manager_ctrl_cond);
    SCCtrlMutexUnlock(&flow_manager_ctrl_mutex);
}

void FlowWakeupFlowRecyclerThread(void)
{
    SCCtrlMutexLock(&flow_recycler_ctrl_mutex);
    SCCtrlCondSignal(&flow_recycler_ctrl_cond);
    SCCtrlMutexUnlock(&flow_recycler_ctrl_mutex);
}

void FlowTimeoutsInit(void)
{
    SC_ATOMIC_SET(flow_timeouts, flow_timeouts_normal);
}

void FlowTimeoutsEmergency(void)
{
    SC_ATOMIC_SET(flow_timeouts, flow_timeouts_emerg);
}

typedef struct FlowTimeoutCounters_ {
    uint32_t rows_checked;
    uint32_t rows_skipped;
    uint32_t rows_empty;
    uint32_t rows_maxlen;

    uint32_t flows_checked;
    uint32_t flows_notimeout;
    uint32_t flows_timeout;
    uint32_t flows_removed;
    uint32_t flows_aside;
    uint32_t flows_aside_needs_work;

    uint32_t bypassed_count;
    uint64_t bypassed_pkts;
    uint64_t bypassed_bytes;
} FlowTimeoutCounters;

/**
 * \brief Used to disable flow manager thread(s).
 *
 * \todo Kinda hackish since it uses the tv name to identify flow manager
 *       thread.  We need an all weather identification scheme.
 */
void FlowDisableFlowManagerThread(void)
{
    SCMutexLock(&tv_root_lock);
    /* flow manager thread(s) is/are a part of mgmt threads */
    for (ThreadVars *tv = tv_root[TVT_MGMT]; tv != NULL; tv = tv->next) {
        if (strncasecmp(tv->name, thread_name_flow_mgr,
            strlen(thread_name_flow_mgr)) == 0)
        {
            TmThreadsSetFlag(tv, THV_KILL);
        }
    }
    SCMutexUnlock(&tv_root_lock);

    struct timeval start_ts;
    struct timeval cur_ts;
    gettimeofday(&start_ts, NULL);

again:
    gettimeofday(&cur_ts, NULL);
    if ((cur_ts.tv_sec - start_ts.tv_sec) > 60) {
        FatalError("unable to get all flow manager "
                   "threads to shutdown in time");
    }

    SCMutexLock(&tv_root_lock);
    for (ThreadVars *tv = tv_root[TVT_MGMT]; tv != NULL; tv = tv->next) {
        if (strncasecmp(tv->name, thread_name_flow_mgr,
            strlen(thread_name_flow_mgr)) == 0)
        {
            if (!TmThreadsCheckFlag(tv, THV_RUNNING_DONE)) {
                SCMutexUnlock(&tv_root_lock);
                /* sleep outside lock */
                SleepMsec(1);
                goto again;
            }
        }
    }
    SCMutexUnlock(&tv_root_lock);

    /* reset count, so we can kill and respawn (unix socket) */
    SC_ATOMIC_SET(flowmgr_cnt, 0);
}

/** \internal
 *  \brief check if a flow is timed out
 *
 *  \param f flow
 *  \param ts timestamp
 *
 *  \retval false not timed out
 *  \retval true timed out
 */
static bool FlowManagerFlowTimeout(Flow *f, SCTime_t ts, uint32_t *next_ts, const bool emerg)
{
    uint32_t flow_times_out_at = f->timeout_at;
    if (emerg) {
        extern FlowProtoTimeout flow_timeouts_delta[FLOW_PROTO_MAX];
        flow_times_out_at -= FlowGetFlowTimeoutDirect(flow_timeouts_delta, f->flow_state, f->protomap);
    }
    if (*next_ts == 0 || flow_times_out_at < *next_ts)
        *next_ts = flow_times_out_at;

    /* do the timeout check */
    if ((uint64_t)flow_times_out_at >= SCTIME_SECS(ts)) {
        return false;
    }

    return true;
}

#ifdef CAPTURE_OFFLOAD
/** \internal
 *  \brief check timeout of captured bypassed flow by querying capture method
 *
 *  \param f Flow
 *  \param ts timestamp
 *  \param counters Flow timeout counters
 *
 *  \retval false not timeout
 *  \retval true timeout (or not capture bypassed)
 */
static inline bool FlowBypassedTimeout(Flow *f, SCTime_t ts, FlowTimeoutCounters *counters)
{
    if (f->flow_state != FLOW_STATE_CAPTURE_BYPASSED) {
        return true;
    }

    FlowBypassInfo *fc = FlowGetStorageById(f, GetFlowBypassInfoID());
    if (fc && fc->BypassUpdate) {
        /* flow will be possibly updated */
        uint64_t pkts_tosrc = fc->tosrcpktcnt;
        uint64_t bytes_tosrc = fc->tosrcbytecnt;
        uint64_t pkts_todst = fc->todstpktcnt;
        uint64_t bytes_todst = fc->todstbytecnt;
        bool update = fc->BypassUpdate(f, fc->bypass_data, SCTIME_SECS(ts));
        if (update) {
            SCLogDebug("Updated flow: %"PRId64"", FlowGetId(f));
            pkts_tosrc = fc->tosrcpktcnt - pkts_tosrc;
            bytes_tosrc = fc->tosrcbytecnt - bytes_tosrc;
            pkts_todst = fc->todstpktcnt - pkts_todst;
            bytes_todst = fc->todstbytecnt - bytes_todst;
            if (f->livedev) {
                SC_ATOMIC_ADD(f->livedev->bypassed,
                        pkts_tosrc + pkts_todst);
            }
            counters->bypassed_pkts += pkts_tosrc + pkts_todst;
            counters->bypassed_bytes += bytes_tosrc + bytes_todst;
            return false;
        }
        SCLogDebug("No new packet, dead flow %" PRId64 "", FlowGetId(f));
        if (f->livedev) {
            if (FLOW_IS_IPV4(f)) {
                LiveDevSubBypassStats(f->livedev, 1, AF_INET);
            } else if (FLOW_IS_IPV6(f)) {
                LiveDevSubBypassStats(f->livedev, 1, AF_INET6);
            }
        }
        counters->bypassed_count++;
    }
    return true;
}
#endif /* CAPTURE_OFFLOAD */

typedef struct FlowManagerTimeoutThread {
    /* used to temporarily store flows that have timed out and are
     * removed from the hash to reduce locking contention */
    FlowQueuePrivate aside_queue;
} FlowManagerTimeoutThread;

/**
 * \internal
 *
 * \brief Process the temporary Aside Queue
 *        This means that as long as a flow f is not waiting on detection
 *        engine to finish dealing with it, f will be put in the recycle
 *        queue for further processing later on.
 *
 * \param td FM Timeout Thread instance
 * \param counters Flow Timeout counters to be updated
 *
 * \retval Number of flows that were recycled
 */
static uint32_t ProcessAsideQueue(FlowManagerTimeoutThread *td, FlowTimeoutCounters *counters)
{
    FlowQueuePrivate recycle = { NULL, NULL, 0 };
    counters->flows_aside += td->aside_queue.len;

    uint32_t cnt = 0;
    Flow *f;
    while ((f = FlowQueuePrivateGetFromTop(&td->aside_queue)) != NULL) {
        /* flow is still locked */

        if (f->proto == IPPROTO_TCP &&
                !(f->flags & (FLOW_TIMEOUT_REASSEMBLY_DONE | FLOW_ACTION_DROP)) &&
                !FlowIsBypassed(f) && FlowNeedsReassembly(f)) {
            /* Send the flow to its thread */
            FlowSendToLocalThread(f);
            FLOWLOCK_UNLOCK(f);
            /* flow ownership is already passed to the worker thread */

            counters->flows_aside_needs_work++;
            continue;
        }
        FLOWLOCK_UNLOCK(f);

        FlowQueuePrivateAppendFlow(&recycle, f);
        if (recycle.len == 100) {
            FlowQueueAppendPrivate(&flow_recycle_q, &recycle);
            FlowWakeupFlowRecyclerThread();
        }
        cnt++;
    }
    if (recycle.len) {
        FlowQueueAppendPrivate(&flow_recycle_q, &recycle);
        FlowWakeupFlowRecyclerThread();
    }
    return cnt;
}

/**
 *  \internal
 *
 *  \brief check all flows in a hash row for timing out
 *
 *  \param f last flow in the hash row
 *  \param ts timestamp
 *  \param emergency bool indicating emergency mode
 *  \param counters ptr to FlowTimeoutCounters structure
 */
static void FlowManagerHashRowTimeout(FlowManagerTimeoutThread *td, Flow *f, SCTime_t ts,
        int emergency, FlowTimeoutCounters *counters, uint32_t *next_ts)
{
    uint32_t checked = 0;
    Flow *prev_f = NULL;

    do {
        checked++;

        /* check flow timeout based on lastts and state. Both can be
         * accessed w/o Flow lock as we do have the hash row lock (so flow
         * can't disappear) and flow_state is atomic. lastts can only
         * be modified when we have both the flow and hash row lock */

        /* timeout logic goes here */
        if (FlowManagerFlowTimeout(f, ts, next_ts, emergency) == false) {
            counters->flows_notimeout++;

            prev_f = f;
            f = f->next;
            continue;
        }

        FLOWLOCK_WRLOCK(f);

        Flow *next_flow = f->next;

#ifdef CAPTURE_OFFLOAD
        /* never prune a flow that is used by a packet we
         * are currently processing in one of the threads */
        if (!FlowBypassedTimeout(f, ts, counters)) {
            FLOWLOCK_UNLOCK(f);
            prev_f = f;
            f = f->next;
            continue;
        }
#endif
        f->flow_end_flags |= FLOW_END_FLAG_TIMEOUT;

        counters->flows_timeout++;

        RemoveFromHash(f, prev_f);

        FlowQueuePrivateAppendFlow(&td->aside_queue, f);
        /* flow is still locked in the queue */

        f = next_flow;
    } while (f != NULL);

    counters->flows_checked += checked;
    if (checked > counters->rows_maxlen)
        counters->rows_maxlen = checked;
}

/**
 * \internal
 *
 * \brief Clear evicted list from Flow Manager.
 *        All the evicted flows are removed from the Flow bucket and added
 *        to the temporary Aside Queue.
 *
 * \param td FM timeout thread instance
 * \param f head of the evicted list
 */
static void FlowManagerHashRowClearEvictedList(FlowManagerTimeoutThread *td, Flow *f)
{
    do {
        FLOWLOCK_WRLOCK(f);
        Flow *next_flow = f->next;
        f->next = NULL;
        f->fb = NULL;

        FlowQueuePrivateAppendFlow(&td->aside_queue, f);
        /* flow is still locked in the queue */

        f = next_flow;
    } while (f != NULL);
}

/**
 *  \brief time out flows from the hash
 *
 *  \param ts timestamp
 *  \param hash_min min hash index to consider
 *  \param hash_max max hash index to consider
 *  \param counters ptr to FlowTimeoutCounters structure
 *
 *  \retval cnt number of timed out flow
 */
static uint32_t FlowTimeoutHash(FlowManagerTimeoutThread *td, SCTime_t ts, const uint32_t hash_min,
        const uint32_t hash_max, FlowTimeoutCounters *counters)
{
    uint32_t cnt = 0;
    const int emergency = ((SC_ATOMIC_GET(flow_flags) & FLOW_EMERGENCY));
    const uint32_t rows_checked = hash_max - hash_min;
    uint32_t rows_skipped = 0;
    uint32_t rows_empty = 0;

#if __WORDSIZE==64
#define BITS 64
#define TYPE uint64_t
#else
#define BITS 32
#define TYPE uint32_t
#endif

    const uint32_t ts_secs = (uint32_t)SCTIME_SECS(ts);
    for (uint32_t idx = hash_min; idx < hash_max; idx+=BITS) {
        TYPE check_bits = 0;
        const uint32_t check = MIN(BITS, (hash_max - idx));
        for (uint32_t i = 0; i < check; i++) {
            FlowBucket *fb = &flow_hash[idx+i];
            check_bits |= (TYPE)(SC_ATOMIC_LOAD_EXPLICIT(
                                         fb->next_ts, SC_ATOMIC_MEMORY_ORDER_RELAXED) <= ts_secs)
                          << (TYPE)i;
        }
        if (check_bits == 0)
            continue;

        for (uint32_t i = 0; i < check; i++) {
            FlowBucket *fb = &flow_hash[idx+i];
            if ((check_bits & ((TYPE)1 << (TYPE)i)) != 0 && SC_ATOMIC_GET(fb->next_ts) <= ts_secs) {
                FBLOCK_LOCK(fb);
                Flow *evicted = NULL;
                if (fb->evicted != NULL || fb->head != NULL) {
                    if (fb->evicted != NULL) {
                        /* transfer out of bucket so we can do additional work outside
                         * of the bucket lock */
                        evicted = fb->evicted;
                        fb->evicted = NULL;
                    }
                    if (fb->head != NULL) {
                        uint32_t next_ts = 0;
                        FlowManagerHashRowTimeout(td, fb->head, ts, emergency, counters, &next_ts);

                        if (SC_ATOMIC_GET(fb->next_ts) != next_ts)
                            SC_ATOMIC_SET(fb->next_ts, next_ts);
                    }
                    if (fb->evicted == NULL && fb->head == NULL) {
                        /* row is empty */
                        SC_ATOMIC_SET(fb->next_ts, UINT_MAX);
                    }
                } else {
                    SC_ATOMIC_SET(fb->next_ts, UINT_MAX);
                    rows_empty++;
                }
                FBLOCK_UNLOCK(fb);
                /* processed evicted list */
                if (evicted) {
                    FlowManagerHashRowClearEvictedList(td, evicted);
                }
            } else {
                rows_skipped++;
            }
        }
        if (td->aside_queue.len) {
            cnt += ProcessAsideQueue(td, counters);
        }
    }

    counters->rows_checked += rows_checked;
    counters->rows_skipped += rows_skipped;
    counters->rows_empty += rows_empty;

    if (td->aside_queue.len) {
        cnt += ProcessAsideQueue(td, counters);
    }
    counters->flows_removed += cnt;
    /* coverity[missing_unlock : FALSE] */
    return cnt;
}

/** \internal
 *
 *  \brief handle timeout for a slice of hash rows
 *         If we wrap around we call FlowTimeoutHash twice
 *  \param td FM timeout thread
 *  \param ts timeout in seconds
 *  \param hash_min lower bound of the row slice
 *  \param hash_max upper bound of the row slice
 *  \param counters Flow timeout counters to be passed
 *  \param rows number of rows for this worker unit
 *  \param pos position of the beginning of row slice in the hash table
 *
 *  \retval number of successfully timed out flows
 */
static uint32_t FlowTimeoutHashInChunks(FlowManagerTimeoutThread *td, SCTime_t ts,
        const uint32_t hash_min, const uint32_t hash_max, FlowTimeoutCounters *counters,
        const uint32_t rows, uint32_t *pos)
{
    uint32_t start = 0;
    uint32_t end = 0;
    uint32_t cnt = 0;
    uint32_t rows_left = rows;

again:
    start = hash_min + (*pos);
    if (start >= hash_max) {
        start = hash_min;
    }
    end = start + rows_left;
    if (end > hash_max) {
        end = hash_max;
    }
    *pos = (end == hash_max) ? hash_min : end;
    rows_left = rows_left - (end - start);

    cnt += FlowTimeoutHash(td, ts, start, end, counters);
    if (rows_left) {
        goto again;
    }
    return cnt;
}

/**
 *  \internal
 *
 *  \brief move all flows out of a hash row
 *
 *  \param f last flow in the hash row
 *  \param recycle_q Flow recycle queue
 *  \param mode emergency or not
 *
 *  \retval cnt number of flows removed from the hash and added to the recycle queue
 */
static uint32_t FlowManagerHashRowCleanup(Flow *f, FlowQueuePrivate *recycle_q, const int mode)
{
    uint32_t cnt = 0;

    do {
        FLOWLOCK_WRLOCK(f);

        Flow *next_flow = f->next;

        /* remove from the hash */
        if (mode == 0) {
            RemoveFromHash(f, NULL);
        } else {
            FlowBucket *fb = f->fb;
            fb->evicted = f->next;
            f->next = NULL;
            f->fb = NULL;
        }
        f->flow_end_flags |= FLOW_END_FLAG_SHUTDOWN;

        /* no one is referring to this flow, removed from hash
         * so we can unlock it and move it to the recycle queue. */
        FLOWLOCK_UNLOCK(f);
        FlowQueuePrivateAppendFlow(recycle_q, f);

        cnt++;

        f = next_flow;
    } while (f != NULL);

    return cnt;
}

#define RECYCLE_MAX_QUEUE_ITEMS 25
/**
 *  \brief remove all flows from the hash
 *
 *  \retval cnt number of removes out flows
 */
static uint32_t FlowCleanupHash(void)
{
    FlowQueuePrivate local_queue = { NULL, NULL, 0 };
    uint32_t cnt = 0;

    for (uint32_t idx = 0; idx < flow_config.hash_size; idx++) {
        FlowBucket *fb = &flow_hash[idx];

        FBLOCK_LOCK(fb);

        if (fb->head != NULL) {
            /* we have a flow, or more than one */
            cnt += FlowManagerHashRowCleanup(fb->head, &local_queue, 0);
        }
        if (fb->evicted != NULL) {
            /* we have a flow, or more than one */
            cnt += FlowManagerHashRowCleanup(fb->evicted, &local_queue, 1);
        }

        FBLOCK_UNLOCK(fb);
        if (local_queue.len >= RECYCLE_MAX_QUEUE_ITEMS) {
            FlowQueueAppendPrivate(&flow_recycle_q, &local_queue);
            FlowWakeupFlowRecyclerThread();
        }
    }
    DEBUG_VALIDATE_BUG_ON(local_queue.len >= RECYCLE_MAX_QUEUE_ITEMS);
    FlowQueueAppendPrivate(&flow_recycle_q, &local_queue);
    FlowWakeupFlowRecyclerThread();

    return cnt;
}

typedef struct FlowCounters_ {
    uint16_t flow_mgr_full_pass;
    uint16_t flow_mgr_rows_sec;

    uint16_t flow_mgr_spare;
    uint16_t flow_emerg_mode_enter;
    uint16_t flow_emerg_mode_over;

    uint16_t flow_mgr_flows_checked;
    uint16_t flow_mgr_flows_notimeout;
    uint16_t flow_mgr_flows_timeout;
    uint16_t flow_mgr_flows_aside;
    uint16_t flow_mgr_flows_aside_needs_work;

    uint16_t flow_mgr_rows_maxlen;

    uint16_t flow_bypassed_cnt_clo;
    uint16_t flow_bypassed_pkts;
    uint16_t flow_bypassed_bytes;

    uint16_t memcap_pressure;
    uint16_t memcap_pressure_max;
} FlowCounters;

typedef struct FlowManagerThreadData_ {
    uint32_t instance;
    uint32_t min;
    uint32_t max;

    FlowCounters cnt;

    FlowManagerTimeoutThread timeout;
    uint16_t counter_defrag_timeout;
    uint16_t counter_defrag_memuse;
} FlowManagerThreadData;

static void FlowCountersInit(ThreadVars *t, FlowCounters *fc)
{
    fc->flow_mgr_full_pass = StatsRegisterCounter("flow.mgr.full_hash_pass", t);
    fc->flow_mgr_rows_sec = StatsRegisterCounter("flow.mgr.rows_per_sec", t);

    fc->flow_mgr_spare = StatsRegisterCounter("flow.spare", t);
    fc->flow_emerg_mode_enter = StatsRegisterCounter("flow.emerg_mode_entered", t);
    fc->flow_emerg_mode_over = StatsRegisterCounter("flow.emerg_mode_over", t);

    fc->flow_mgr_rows_maxlen = StatsRegisterMaxCounter("flow.mgr.rows_maxlen", t);
    fc->flow_mgr_flows_checked = StatsRegisterCounter("flow.mgr.flows_checked", t);
    fc->flow_mgr_flows_notimeout = StatsRegisterCounter("flow.mgr.flows_notimeout", t);
    fc->flow_mgr_flows_timeout = StatsRegisterCounter("flow.mgr.flows_timeout", t);
    fc->flow_mgr_flows_aside = StatsRegisterCounter("flow.mgr.flows_evicted", t);
    fc->flow_mgr_flows_aside_needs_work = StatsRegisterCounter("flow.mgr.flows_evicted_needs_work", t);

    fc->flow_bypassed_cnt_clo = StatsRegisterCounter("flow_bypassed.closed", t);
    fc->flow_bypassed_pkts = StatsRegisterCounter("flow_bypassed.pkts", t);
    fc->flow_bypassed_bytes = StatsRegisterCounter("flow_bypassed.bytes", t);

    fc->memcap_pressure = StatsRegisterCounter("memcap.pressure", t);
    fc->memcap_pressure_max = StatsRegisterMaxCounter("memcap.pressure_max", t);
}

static void FlowCountersUpdate(
        ThreadVars *th_v, const FlowManagerThreadData *ftd, const FlowTimeoutCounters *counters)
{
    StatsAddUI64(th_v, ftd->cnt.flow_mgr_flows_checked, (uint64_t)counters->flows_checked);
    StatsAddUI64(th_v, ftd->cnt.flow_mgr_flows_notimeout, (uint64_t)counters->flows_notimeout);

    StatsAddUI64(th_v, ftd->cnt.flow_mgr_flows_timeout, (uint64_t)counters->flows_timeout);
    StatsAddUI64(th_v, ftd->cnt.flow_mgr_flows_aside, (uint64_t)counters->flows_aside);
    StatsAddUI64(th_v, ftd->cnt.flow_mgr_flows_aside_needs_work,
            (uint64_t)counters->flows_aside_needs_work);

    StatsAddUI64(th_v, ftd->cnt.flow_bypassed_cnt_clo, (uint64_t)counters->bypassed_count);
    StatsAddUI64(th_v, ftd->cnt.flow_bypassed_pkts, (uint64_t)counters->bypassed_pkts);
    StatsAddUI64(th_v, ftd->cnt.flow_bypassed_bytes, (uint64_t)counters->bypassed_bytes);

    StatsSetUI64(th_v, ftd->cnt.flow_mgr_rows_maxlen, (uint64_t)counters->rows_maxlen);
}

static TmEcode FlowManagerThreadInit(ThreadVars *t, const void *initdata, void **data)
{
    FlowManagerThreadData *ftd = SCCalloc(1, sizeof(FlowManagerThreadData));
    if (ftd == NULL)
        return TM_ECODE_FAILED;

    ftd->instance = SC_ATOMIC_ADD(flowmgr_cnt, 1);
    SCLogDebug("flow manager instance %u", ftd->instance);

    /* set the min and max value used for hash row walking
     * each thread has it's own section of the flow hash */
    uint32_t range = flow_config.hash_size / flowmgr_number;

    ftd->min = ftd->instance * range;
    ftd->max = (ftd->instance + 1) * range;

    /* last flow-manager takes on hash_size % flowmgr_number extra rows */
    if ((ftd->instance + 1) == flowmgr_number) {
        ftd->max = flow_config.hash_size;
    }
    BUG_ON(ftd->min > flow_config.hash_size || ftd->max > flow_config.hash_size);

    SCLogDebug("instance %u hash range %u %u", ftd->instance, ftd->min, ftd->max);

    /* pass thread data back to caller */
    *data = ftd;

    FlowCountersInit(t, &ftd->cnt);
    ftd->counter_defrag_timeout = StatsRegisterCounter("defrag.mgr.tracker_timeout", t);
    ftd->counter_defrag_memuse = StatsRegisterCounter("defrag.memuse", t);

    PacketPoolInit();
    return TM_ECODE_OK;
}

static TmEcode FlowManagerThreadDeinit(ThreadVars *t, void *data)
{
    StreamTcpThreadCacheCleanup();
    PacketPoolDestroy();
    SCFree(data);
    return TM_ECODE_OK;
}

/** \internal
 *  \brief calculate number of rows to scan and how much time to sleep
 *         based on the busy score `mp` (0 idle, 100 max busy).
 *
 *  We try to to make sure we scan the hash once a second. The number size
 *  of the slice of the hash scanned is determined by our busy score 'mp'.
 *  We sleep for the remainder of the second after processing the slice,
 *  or at least an approximation of it.
 *  A minimum busy score of 10 is assumed to avoid a longer than 10 second
 *  full hash pass. This is to avoid burstiness in scanning when there is
 *  a rapid increase of the busy score, which could lead to the flow manager
 *  suddenly scanning a much larger slice of the hash leading to a burst
 *  in scan/eviction work.
 *
 *  \param rows number of rows for the work unit
 *  \param mp current memcap pressure value
 *  \param emergency emergency mode is set or not
 *  \param wu_sleep holds value of sleep time per worker unit
 *  \param wu_rows holds value of calculated rows to be processed per second
 *  \param rows_sec same as wu_rows, only used for counter updates
 */
static void GetWorkUnitSizing(const uint32_t rows, const uint32_t mp, const bool emergency,
        uint64_t *wu_sleep, uint32_t *wu_rows, uint32_t *rows_sec)
{
    if (emergency) {
        *wu_rows = rows;
        *wu_sleep = 250;
        return;
    }
    /* minimum busy score is 10 */
    const uint32_t emp = MAX(mp, 10);
    const uint32_t rows_per_sec = (uint32_t)((float)rows * (float)((float)emp / (float)100));
    /* calc how much time we estimate the work will take, in ms. We assume
     * each row takes an average of 1usec. Maxing out at 1sec. */
    const uint32_t work_per_unit = MIN(rows_per_sec / 1000, 1000);
    /* calc how much time we need to sleep to get to the per second cadence
     * but sleeping for at least 250ms. */
    const uint32_t sleep_per_unit = MAX(250, 1000 - work_per_unit);
    SCLogDebug("mp %u emp %u rows %u rows_sec %u sleep %ums", mp, emp, rows, rows_per_sec,
            sleep_per_unit);

    *wu_sleep = sleep_per_unit;
    *wu_rows = rows_per_sec;
    *rows_sec = rows_per_sec;
}

/** \brief Thread that manages the flow table and times out flows.
 *
 *  \param td ThreadVars cast to void ptr
 *
 *  Keeps an eye on the spare list, alloc flows if needed...
 */
static TmEcode FlowManager(ThreadVars *th_v, void *thread_data)
{
    FlowManagerThreadData *ftd = thread_data;
    const uint32_t rows = ftd->max - ftd->min;
    const bool time_is_live = TimeModeIsLive();

    uint32_t emerg_over_cnt = 0;
    uint64_t next_run_ms = 0;
    uint32_t pos = 0;
    uint32_t rows_sec = 0;
    uint32_t rows_per_wu = 0;
    uint64_t sleep_per_wu = 0;
    bool prev_emerg = false;
    uint32_t other_last_sec = 0; /**< last sec stamp when defrag etc ran */
    SCTime_t ts;

    /* don't start our activities until time is setup */
    while (!TimeModeIsReady()) {
        if (suricata_ctl_flags != 0)
            return TM_ECODE_OK;
        usleep(10);
    }

    uint32_t mp = MemcapsGetPressure() * 100;
    if (ftd->instance == 0) {
        StatsSetUI64(th_v, ftd->cnt.memcap_pressure, mp);
        StatsSetUI64(th_v, ftd->cnt.memcap_pressure_max, mp);
    }
    GetWorkUnitSizing(rows, mp, false, &sleep_per_wu, &rows_per_wu, &rows_sec);
    StatsSetUI64(th_v, ftd->cnt.flow_mgr_rows_sec, rows_sec);

    TmThreadsSetFlag(th_v, THV_RUNNING);
    bool run = TmThreadsWaitForUnpause(th_v);

    while (run) {
        bool emerg = ((SC_ATOMIC_GET(flow_flags) & FLOW_EMERGENCY) != 0);

        /* Get the time */
        ts = TimeGet();
        SCLogDebug("ts %" PRIdMAX "", (intmax_t)SCTIME_SECS(ts));
        uint64_t ts_ms = SCTIME_MSECS(ts);
        const bool emerge_p = (emerg && !prev_emerg);
        if (emerge_p) {
            next_run_ms = 0;
            prev_emerg = true;
            SCLogNotice("Flow emergency mode entered...");
            StatsIncr(th_v, ftd->cnt.flow_emerg_mode_enter);
        }
        if (ts_ms >= next_run_ms) {
            if (ftd->instance == 0) {
                const uint32_t sq_len = FlowSpareGetPoolSize();
                const uint32_t spare_perc = sq_len * 100 / MAX(flow_config.prealloc, 1);
                /* see if we still have enough spare flows */
                if (spare_perc < 90 || spare_perc > 110) {
                    FlowSparePoolUpdate(sq_len);
                }
            }

            /* try to time out flows */
            // clang-format off
            FlowTimeoutCounters counters = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, };
            // clang-format on

            if (emerg) {
                /* in emergency mode, do a full pass of the hash table */
                FlowTimeoutHash(&ftd->timeout, ts, ftd->min, ftd->max, &counters);
                StatsIncr(th_v, ftd->cnt.flow_mgr_full_pass);
            } else {
                SCLogDebug("hash %u:%u slice starting at %u with %u rows", ftd->min, ftd->max, pos,
                        rows_per_wu);

                const uint32_t ppos = pos;
                FlowTimeoutHashInChunks(
                        &ftd->timeout, ts, ftd->min, ftd->max, &counters, rows_per_wu, &pos);
                if (ppos > pos) {
                    StatsIncr(th_v, ftd->cnt.flow_mgr_full_pass);
                }
            }

            const uint32_t spare_pool_len = FlowSpareGetPoolSize();
            StatsSetUI64(th_v, ftd->cnt.flow_mgr_spare, (uint64_t)spare_pool_len);

            FlowCountersUpdate(th_v, ftd, &counters);

            if (emerg == true) {
                SCLogDebug("flow_sparse_q.len = %" PRIu32 " prealloc: %" PRIu32
                           "flow_spare_q status: %" PRIu32 "%% flows at the queue",
                        spare_pool_len, flow_config.prealloc,
                        spare_pool_len * 100 / MAX(flow_config.prealloc, 1));

                /* only if we have pruned this "emergency_recovery" percentage
                 * of flows, we will unset the emergency bit */
                if ((spare_pool_len * 100 / MAX(flow_config.prealloc, 1)) >
                        flow_config.emergency_recovery) {
                    emerg_over_cnt++;
                } else {
                    emerg_over_cnt = 0;
                }

                if (emerg_over_cnt >= 30) {
                    SC_ATOMIC_AND(flow_flags, ~FLOW_EMERGENCY);
                    FlowTimeoutsReset();

                    emerg = false;
                    prev_emerg = false;
                    emerg_over_cnt = 0;
                    SCLogNotice("Flow emergency mode over, back to normal... unsetting"
                                " FLOW_EMERGENCY bit (ts.tv_sec: %" PRIuMAX ", "
                                "ts.tv_usec:%" PRIuMAX ") flow_spare_q status(): %" PRIu32
                                "%% flows at the queue",
                            (uintmax_t)SCTIME_SECS(ts), (uintmax_t)SCTIME_USECS(ts),
                            spare_pool_len * 100 / MAX(flow_config.prealloc, 1));

                    StatsIncr(th_v, ftd->cnt.flow_emerg_mode_over);
                }
            }

            /* update work units */
            const uint32_t pmp = mp;
            mp = MemcapsGetPressure() * 100;
            if (ftd->instance == 0) {
                StatsSetUI64(th_v, ftd->cnt.memcap_pressure, mp);
                StatsSetUI64(th_v, ftd->cnt.memcap_pressure_max, mp);
            }
            GetWorkUnitSizing(rows, mp, emerg, &sleep_per_wu, &rows_per_wu, &rows_sec);
            if (pmp != mp) {
                StatsSetUI64(th_v, ftd->cnt.flow_mgr_rows_sec, rows_sec);
            }

            next_run_ms = ts_ms + sleep_per_wu;
        }
        if (other_last_sec == 0 || other_last_sec < (uint32_t)SCTIME_SECS(ts)) {
            if (ftd->instance == 0) {
                StatsSetUI64(th_v, ftd->counter_defrag_memuse, DefragTrackerGetMemcap());
                uint32_t defrag_cnt = DefragTimeoutHash(ts);
                if (defrag_cnt) {
                    StatsAddUI64(th_v, ftd->counter_defrag_timeout, defrag_cnt);
                }
                HostTimeoutHash(ts);
                IPPairTimeoutHash(ts);
                HttpRangeContainersTimeoutHash(ts);
                ThresholdsExpire(ts);
                other_last_sec = (uint32_t)SCTIME_SECS(ts);
            }
        }

        if (TmThreadsCheckFlag(th_v, THV_KILL)) {
            StatsSyncCounters(th_v);
            break;
        }

        if (emerg || !time_is_live) {
            usleep(250);
        } else {
            struct timeval cond_tv;
            gettimeofday(&cond_tv, NULL);
            struct timeval add_tv;
            add_tv.tv_sec = sleep_per_wu / 1000;
            add_tv.tv_usec = (sleep_per_wu % 1000) * 1000;
            timeradd(&cond_tv, &add_tv, &cond_tv);

            struct timespec cond_time = FROM_TIMEVAL(cond_tv);
            SCCtrlMutexLock(&flow_manager_ctrl_mutex);
            while (1) {
                int rc = SCCtrlCondTimedwait(
                        &flow_manager_ctrl_cond, &flow_manager_ctrl_mutex, &cond_time);
                if (rc == ETIMEDOUT || rc < 0)
                    break;
                if (SC_ATOMIC_GET(flow_flags) & FLOW_EMERGENCY) {
                    break;
                }
            }
            SCCtrlMutexUnlock(&flow_manager_ctrl_mutex);
        }

        SCLogDebug("woke up... %s", SC_ATOMIC_GET(flow_flags) & FLOW_EMERGENCY ? "emergency":"");

        StatsSyncCountersIfSignalled(th_v);
    }
    return TM_ECODE_OK;
}

/** \brief spawn the flow manager thread */
void FlowManagerThreadSpawn(void)
{
    intmax_t setting = 1;
    (void)ConfGetInt("flow.managers", &setting);

    if (setting < 1 || setting > 1024) {
        FatalError("invalid flow.managers setting %" PRIdMAX, setting);
    }
    flowmgr_number = (uint32_t)setting;

    SCLogConfig("using %u flow manager threads", flowmgr_number);
    StatsRegisterGlobalCounter("flow.memuse", FlowGetMemuse);

    for (uint32_t u = 0; u < flowmgr_number; u++) {
        char name[TM_THREAD_NAME_MAX];
        snprintf(name, sizeof(name), "%s#%02u", thread_name_flow_mgr, u+1);

        ThreadVars *tv_flowmgr = TmThreadCreateMgmtThreadByName(name,
                "FlowManager", 0);
        BUG_ON(tv_flowmgr == NULL);

        if (tv_flowmgr == NULL) {
            FatalError("flow manager thread creation failed");
        }
        if (TmThreadSpawn(tv_flowmgr) != TM_ECODE_OK) {
            FatalError("flow manager thread spawn failed");
        }
    }
}

typedef struct FlowRecyclerThreadData_ {
    void *output_thread_data;

    uint16_t counter_flows;
    uint16_t counter_queue_avg;
    uint16_t counter_queue_max;

    uint16_t counter_flow_active;
    uint16_t counter_tcp_active_sessions;
    FlowEndCounters fec;
} FlowRecyclerThreadData;

static TmEcode FlowRecyclerThreadInit(ThreadVars *t, const void *initdata, void **data)
{
    FlowRecyclerThreadData *ftd = SCCalloc(1, sizeof(FlowRecyclerThreadData));
    if (ftd == NULL)
        return TM_ECODE_FAILED;
    if (OutputFlowLogThreadInit(t, &ftd->output_thread_data) != TM_ECODE_OK) {
        SCLogError("initializing flow log API for thread failed");
        SCFree(ftd);
        return TM_ECODE_FAILED;
    }
    SCLogDebug("output_thread_data %p", ftd->output_thread_data);

    ftd->counter_flows = StatsRegisterCounter("flow.recycler.recycled", t);
    ftd->counter_queue_avg = StatsRegisterAvgCounter("flow.recycler.queue_avg", t);
    ftd->counter_queue_max = StatsRegisterMaxCounter("flow.recycler.queue_max", t);

    ftd->counter_flow_active = StatsRegisterCounter("flow.active", t);
    ftd->counter_tcp_active_sessions = StatsRegisterCounter("tcp.active_sessions", t);

    FlowEndCountersRegister(t, &ftd->fec);

    *data = ftd;
    return TM_ECODE_OK;
}

static TmEcode FlowRecyclerThreadDeinit(ThreadVars *t, void *data)
{
    StreamTcpThreadCacheCleanup();

    FlowRecyclerThreadData *ftd = (FlowRecyclerThreadData *)data;
    if (ftd->output_thread_data != NULL)
        OutputFlowLogThreadDeinit(t, ftd->output_thread_data);

    SCFree(data);
    return TM_ECODE_OK;
}

static void Recycler(ThreadVars *tv, FlowRecyclerThreadData *ftd, Flow *f)
{
    FLOWLOCK_WRLOCK(f);

    (void)OutputFlowLog(tv, ftd->output_thread_data, f);

    FlowEndCountersUpdate(tv, &ftd->fec, f);
    if (f->proto == IPPROTO_TCP && f->protoctx != NULL) {
        StatsDecr(tv, ftd->counter_tcp_active_sessions);
    }
    StatsDecr(tv, ftd->counter_flow_active);
    SCFlowRunFinishCallbacks(tv, f);
    FlowClearMemory(f, f->protomap);
    FLOWLOCK_UNLOCK(f);
}

/** \brief Thread that manages timed out flows.
 *
 *  \param td ThreadVars cast to void ptr
 */
static TmEcode FlowRecycler(ThreadVars *th_v, void *thread_data)
{
    FlowRecyclerThreadData *ftd = (FlowRecyclerThreadData *)thread_data;
    BUG_ON(ftd == NULL);
    const bool time_is_live = TimeModeIsLive();
    uint64_t recycled_cnt = 0;
    FlowQueuePrivate ret_queue = { NULL, NULL, 0 };

    TmThreadsSetFlag(th_v, THV_RUNNING);
    bool run = TmThreadsWaitForUnpause(th_v);

    while (run) {
        SC_ATOMIC_ADD(flowrec_busy,1);
        FlowQueuePrivate list = FlowQueueExtractPrivate(&flow_recycle_q);

        StatsAddUI64(th_v, ftd->counter_queue_avg, list.len);
        StatsSetUI64(th_v, ftd->counter_queue_max, list.len);

        const int bail = (TmThreadsCheckFlag(th_v, THV_KILL));

        /* Get the time */
        SCLogDebug("ts %" PRIdMAX "", (intmax_t)SCTIME_SECS(TimeGet()));

        uint64_t cnt = 0;
        Flow *f;
        while ((f = FlowQueuePrivateGetFromTop(&list)) != NULL) {
            Recycler(th_v, ftd, f);
            cnt++;

            /* for every full sized block, add it to the spare pool */
            FlowQueuePrivateAppendFlow(&ret_queue, f);
            if (ret_queue.len == FLOW_SPARE_POOL_BLOCK_SIZE) {
                FlowSparePoolReturnFlows(&ret_queue);
            }
        }
        if (ret_queue.len > 0) {
            FlowSparePoolReturnFlows(&ret_queue);
        }
        if (cnt > 0) {
            recycled_cnt += cnt;
            StatsAddUI64(th_v, ftd->counter_flows, cnt);
        }
        SC_ATOMIC_SUB(flowrec_busy,1);

        if (bail) {
            break;
        }

        const bool emerg = (SC_ATOMIC_GET(flow_flags) & FLOW_EMERGENCY);
        if (emerg || !time_is_live) {
            usleep(250);
        } else {
            struct timeval cond_tv;
            gettimeofday(&cond_tv, NULL);
            cond_tv.tv_sec += 1;
            struct timespec cond_time = FROM_TIMEVAL(cond_tv);
            SCCtrlMutexLock(&flow_recycler_ctrl_mutex);
            while (1) {
                int rc = SCCtrlCondTimedwait(
                        &flow_recycler_ctrl_cond, &flow_recycler_ctrl_mutex, &cond_time);
                if (rc == ETIMEDOUT || rc < 0) {
                    break;
                }
                if (SC_ATOMIC_GET(flow_flags) & FLOW_EMERGENCY) {
                    break;
                }
                if (SC_ATOMIC_GET(flow_recycle_q.non_empty) == true) {
                    break;
                }
            }
            SCCtrlMutexUnlock(&flow_recycler_ctrl_mutex);
        }

        SCLogDebug("woke up...");

        StatsSyncCountersIfSignalled(th_v);
    }
    StatsSyncCounters(th_v);
    SCLogPerf("%"PRIu64" flows processed", recycled_cnt);
    return TM_ECODE_OK;
}

static bool FlowRecyclerReadyToShutdown(void)
{
    if (SC_ATOMIC_GET(flowrec_busy) != 0) {
        return false;
    }
    uint32_t len = 0;
    FQLOCK_LOCK(&flow_recycle_q);
    len = flow_recycle_q.qlen;
    FQLOCK_UNLOCK(&flow_recycle_q);

    return ((len == 0));
}

/** \brief spawn the flow recycler thread */
void FlowRecyclerThreadSpawn(void)
{
    intmax_t setting = 1;
    (void)ConfGetInt("flow.recyclers", &setting);

    if (setting < 1 || setting > 1024) {
        FatalError("invalid flow.recyclers setting %" PRIdMAX, setting);
    }
    flowrec_number = (uint32_t)setting;

    SCLogConfig("using %u flow recycler threads", flowrec_number);

    for (uint32_t u = 0; u < flowrec_number; u++) {
        char name[TM_THREAD_NAME_MAX];
        snprintf(name, sizeof(name), "%s#%02u", thread_name_flow_rec, u+1);

        ThreadVars *tv_flowrec = TmThreadCreateMgmtThreadByName(name,
                "FlowRecycler", 0);

        if (tv_flowrec == NULL) {
            FatalError("flow recycler thread creation failed");
        }
        if (TmThreadSpawn(tv_flowrec) != TM_ECODE_OK) {
            FatalError("flow recycler thread spawn failed");
        }
    }
}

/**
 * \brief Used to disable flow recycler thread(s).
 *
 * \note this should only be called when the flow manager is already gone
 *
 * \todo Kinda hackish since it uses the tv name to identify flow recycler
 *       thread.  We need an all weather identification scheme.
 */
void FlowDisableFlowRecyclerThread(void)
{
    /* move all flows still in the hash to the recycler queue */
#ifndef DEBUG
    (void)FlowCleanupHash();
#else
    uint32_t flows = FlowCleanupHash();
    SCLogDebug("flows to progress: %u", flows);
#endif

    /* make sure all flows are processed */
    do {
        FlowWakeupFlowRecyclerThread();
        usleep(10);
    } while (FlowRecyclerReadyToShutdown() == false);

    SCMutexLock(&tv_root_lock);
    /* flow recycler thread(s) is/are a part of mgmt threads */
    for (ThreadVars *tv = tv_root[TVT_MGMT]; tv != NULL; tv = tv->next) {
        if (strncasecmp(tv->name, thread_name_flow_rec,
            strlen(thread_name_flow_rec)) == 0)
        {
            TmThreadsSetFlag(tv, THV_KILL);
        }
    }
    SCMutexUnlock(&tv_root_lock);

    struct timeval start_ts;
    struct timeval cur_ts;
    gettimeofday(&start_ts, NULL);

again:
    gettimeofday(&cur_ts, NULL);
    if ((cur_ts.tv_sec - start_ts.tv_sec) > 60) {
        FatalError("unable to get all flow recycler "
                   "threads to shutdown in time");
    }

    SCMutexLock(&tv_root_lock);
    for (ThreadVars *tv = tv_root[TVT_MGMT]; tv != NULL; tv = tv->next) {
        if (strncasecmp(tv->name, thread_name_flow_rec,
            strlen(thread_name_flow_rec)) == 0)
        {
            if (!TmThreadsCheckFlag(tv, THV_RUNNING_DONE)) {
                SCMutexUnlock(&tv_root_lock);
                FlowWakeupFlowRecyclerThread();
                /* sleep outside lock */
                SleepMsec(1);
                goto again;
            }
        }
    }
    SCMutexUnlock(&tv_root_lock);

    /* reset count, so we can kill and respawn (unix socket) */
    SC_ATOMIC_SET(flowrec_cnt, 0);
}

void TmModuleFlowManagerRegister (void)
{
    tmm_modules[TMM_FLOWMANAGER].name = "FlowManager";
    tmm_modules[TMM_FLOWMANAGER].ThreadInit = FlowManagerThreadInit;
    tmm_modules[TMM_FLOWMANAGER].ThreadDeinit = FlowManagerThreadDeinit;
    tmm_modules[TMM_FLOWMANAGER].Management = FlowManager;
    tmm_modules[TMM_FLOWMANAGER].cap_flags = 0;
    tmm_modules[TMM_FLOWMANAGER].flags = TM_FLAG_MANAGEMENT_TM;
    SCLogDebug("%s registered", tmm_modules[TMM_FLOWMANAGER].name);

    SC_ATOMIC_INIT(flowmgr_cnt);
    SC_ATOMIC_INITPTR(flow_timeouts);
}

void TmModuleFlowRecyclerRegister (void)
{
    tmm_modules[TMM_FLOWRECYCLER].name = "FlowRecycler";
    tmm_modules[TMM_FLOWRECYCLER].ThreadInit = FlowRecyclerThreadInit;
    tmm_modules[TMM_FLOWRECYCLER].ThreadDeinit = FlowRecyclerThreadDeinit;
    tmm_modules[TMM_FLOWRECYCLER].Management = FlowRecycler;
    tmm_modules[TMM_FLOWRECYCLER].cap_flags = 0;
    tmm_modules[TMM_FLOWRECYCLER].flags = TM_FLAG_MANAGEMENT_TM;
    SCLogDebug("%s registered", tmm_modules[TMM_FLOWRECYCLER].name);

    SC_ATOMIC_INIT(flowrec_cnt);
    SC_ATOMIC_INIT(flowrec_busy);
}
