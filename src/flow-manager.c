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
 * \author Anoop Saldanha <anoopsaldanha@gmail.com>
 * \author Victor Julien <victor@inliniac.net>
 */

#include "suricata-common.h"
#include "suricata.h"
#include "decode.h"
#include "conf.h"
#include "threadvars.h"
#include "tm-threads.h"
#include "runmodes.h"

#include "util-random.h"
#include "util-time.h"

#include "flow.h"
#include "flow-queue.h"
#include "flow-hash.h"
#include "flow-util.h"
#include "flow-var.h"
#include "flow-private.h"
#include "flow-timeout.h"
#include "flow-manager.h"

#include "stream-tcp-private.h"
#include "stream-tcp-reassemble.h"
#include "stream-tcp.h"

#include "util-unittest.h"
#include "util-unittest-helper.h"
#include "util-byte.h"

#include "util-debug.h"
#include "util-privs.h"
#include "util-signal.h"

#include "threads.h"
#include "detect.h"
#include "detect-engine-state.h"
#include "stream.h"

#include "app-layer-parser.h"

#include "host-timeout.h"
#include "defrag-timeout.h"

#include "output-flow.h"

/* Run mode selected at suricata.c */
extern int run_mode;

SC_ATOMIC_EXTERN(unsigned int, flow_flags);

/* 1 seconds */
#define FLOW_NORMAL_MODE_UPDATE_DELAY_SEC 1
#define FLOW_NORMAL_MODE_UPDATE_DELAY_NSEC 0
/* 0.1 seconds */
#define FLOW_EMERG_MODE_UPDATE_DELAY_SEC 0
#define FLOW_EMERG_MODE_UPDATE_DELAY_NSEC 100000
#define NEW_FLOW_COUNT_COND 10

typedef struct FlowTimeoutCounters_ {
    uint32_t new;
    uint32_t est;
    uint32_t clo;
} FlowTimeoutCounters;

/**
 * \brief Used to kill flow manager thread(s).
 *
 * \todo Kinda hackish since it uses the tv name to identify flow manager
 *       thread.  We need an all weather identification scheme.
 */
void FlowKillFlowManagerThread(void)
{
    ThreadVars *tv = NULL;
    int cnt = 0;

    SCCtrlCondSignal(&flow_manager_ctrl_cond);

    SCMutexLock(&tv_root_lock);

    /* flow manager thread(s) is/are a part of mgmt threads */
    tv = tv_root[TVT_MGMT];

    while (tv != NULL) {
        if (strcasecmp(tv->name, "FlowManagerThread") == 0) {
            TmThreadsSetFlag(tv, THV_KILL);
            TmThreadsSetFlag(tv, THV_DEINIT);

            /* be sure it has shut down */
            while (!TmThreadsCheckFlag(tv, THV_CLOSED)) {
                usleep(100);
            }
            cnt++;
        }
        tv = tv->next;
    }

    /* not possible, unless someone decides to rename FlowManagerThread */
    if (cnt == 0) {
        SCMutexUnlock(&tv_root_lock);
        abort();
    }

    SCMutexUnlock(&tv_root_lock);
    return;
}

/** \internal
 *  \brief Get the flow's state
 *
 *  \param f flow
 *
 *  \retval state either FLOW_STATE_NEW, FLOW_STATE_ESTABLISHED or FLOW_STATE_CLOSED
 */
static inline int FlowGetFlowState(Flow *f) {
    if (flow_proto[f->protomap].GetProtoState != NULL) {
        return flow_proto[f->protomap].GetProtoState(f->protoctx);
    } else {
        if ((f->flags & FLOW_TO_SRC_SEEN) && (f->flags & FLOW_TO_DST_SEEN))
            return FLOW_STATE_ESTABLISHED;
        else
            return FLOW_STATE_NEW;
    }
}

/** \internal
 *  \brief get timeout for flow
 *
 *  \param f flow
 *  \param state flow state
 *  \param emergency bool indicating emergency mode 1 yes, 0 no
 *
 *  \retval timeout timeout in seconds
 */
static inline uint32_t FlowGetFlowTimeout(Flow *f, int state, int emergency) {
    uint32_t timeout;

    if (emergency) {
        switch(state) {
            default:
            case FLOW_STATE_NEW:
                timeout = flow_proto[f->protomap].emerg_new_timeout;
                break;
            case FLOW_STATE_ESTABLISHED:
                timeout = flow_proto[f->protomap].emerg_est_timeout;
                break;
            case FLOW_STATE_CLOSED:
                timeout = flow_proto[f->protomap].emerg_closed_timeout;
                break;
        }
    } else { /* implies no emergency */
        switch(state) {
            default:
            case FLOW_STATE_NEW:
                timeout = flow_proto[f->protomap].new_timeout;
                break;
            case FLOW_STATE_ESTABLISHED:
                timeout = flow_proto[f->protomap].est_timeout;
                break;
            case FLOW_STATE_CLOSED:
                timeout = flow_proto[f->protomap].closed_timeout;
                break;
        }
    }

    return timeout;
}

/** \internal
 *  \brief check if a flow is timed out
 *
 *  \param f flow
 *  \param ts timestamp
 *  \param emergency bool indicating emergency mode
 *
 *  \retval 0 not timed out
 *  \retval 1 timed out
 */
static int FlowManagerFlowTimeout(Flow *f, int state, struct timeval *ts, int emergency) {
    /* set the timeout value according to the flow operating mode,
     * flow's state and protocol.*/
    uint32_t timeout = FlowGetFlowTimeout(f, state, emergency);

    /* do the timeout check */
    if ((int32_t)(f->lastts.tv_sec + timeout) >= ts->tv_sec) {
        return 0;
    }

    return 1;
}

/** \internal
 *  \brief See if we can really discard this flow. Check use_cnt reference
 *         counter and force reassembly if necessary.
 *
 *  \param f flow
 *  \param ts timestamp
 *  \param emergency bool indicating emergency mode
 *
 *  \retval 0 not timed out just yet
 *  \retval 1 fully timed out, lets kill it
 */
static int FlowManagerFlowTimedOut(Flow *f, struct timeval *ts) {
    /** never prune a flow that is used by a packet or stream msg
     *  we are currently processing in one of the threads */
    if (SC_ATOMIC_GET(f->use_cnt) > 0) {
        return 0;
    }

    int server = 0, client = 0;
    if (!(f->flags & FLOW_TIMEOUT_REASSEMBLY_DONE) &&
            FlowForceReassemblyNeedReassembly(f, &server, &client) == 1) {
        FlowForceReassemblyForFlowV2(f, server, client);
        return 0;
    }
#ifdef DEBUG
    /* this should not be possible */
    BUG_ON(SC_ATOMIC_GET(f->use_cnt) > 0);
#endif

    return 1;
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
 *
 *  \retval cnt timed out flows
 */
static uint32_t FlowManagerHashRowTimeout(Flow *f, struct timeval *ts,
        int emergency, FlowTimeoutCounters *counters)
{
    uint32_t cnt = 0;

    do {
        if (FLOWLOCK_TRYWRLOCK(f) != 0) {
            f = f->hprev;
            continue;
        }

        Flow *next_flow = f->hprev;

        int state = FlowGetFlowState(f);

        /* timeout logic goes here */
        if (FlowManagerFlowTimeout(f, state, ts, emergency) == 0) {
            FLOWLOCK_UNLOCK(f);
            f = f->hprev;
            continue;
        }

        /* check if the flow is fully timed out and
         * ready to be discarded. */
        if (FlowManagerFlowTimedOut(f, ts) == 1) {
            /* remove from the hash */
            if (f->hprev != NULL)
                f->hprev->hnext = f->hnext;
            if (f->hnext != NULL)
                f->hnext->hprev = f->hprev;
            if (f->fb->head == f)
                f->fb->head = f->hnext;
            if (f->fb->tail == f)
                f->fb->tail = f->hprev;

            f->hnext = NULL;
            f->hprev = NULL;

//            FlowClearMemory (f, f->protomap);

            /* no one is referring to this flow, use_cnt 0, removed from hash
             * so we can unlock it and move it back to the spare queue. */
            FLOWLOCK_UNLOCK(f);
            FlowEnqueue(&flow_recycle_q, f);
            /* move to spare list */
//            FlowMoveToSpare(f);

            cnt++;

            switch (state) {
                case FLOW_STATE_NEW:
                default:
                    counters->new++;
                    break;
                case FLOW_STATE_ESTABLISHED:
                    counters->est++;
                    break;
                case FLOW_STATE_CLOSED:
                    counters->clo++;
                    break;
            }
        } else {
            FLOWLOCK_UNLOCK(f);
        }

        f = next_flow;
    } while (f != NULL);

    return cnt;
}

/**
 *  \brief time out flows from the hash
 *
 *  \param ts timestamp
 *  \param try_cnt number of flows to time out max (0 is unlimited)
 *  \param counters ptr to FlowTimeoutCounters structure
 *
 *  \retval cnt number of timed out flow
 */
uint32_t FlowTimeoutHash(struct timeval *ts, uint32_t try_cnt, FlowTimeoutCounters *counters) {
    uint32_t idx = 0;
    uint32_t cnt = 0;
    int emergency = 0;

    if (SC_ATOMIC_GET(flow_flags) & FLOW_EMERGENCY)
        emergency = 1;

    for (idx = 0; idx < flow_config.hash_size; idx++) {
        FlowBucket *fb = &flow_hash[idx];

        if (FBLOCK_TRYLOCK(fb) != 0)
            continue;

        /* flow hash bucket is now locked */

        if (fb->tail == NULL)
            goto next;

        /* we have a flow, or more than one */
        cnt += FlowManagerHashRowTimeout(fb->tail, ts, emergency, counters);

next:
        FBLOCK_UNLOCK(fb);

        if (try_cnt > 0 && cnt >= try_cnt)
            break;
    }

    return cnt;
}

extern int g_detect_disabled;

/** \brief Thread that manages the flow table and times out flows.
 *
 *  \param td ThreadVars casted to void ptr
 *
 *  Keeps an eye on the spare list, alloc flows if needed...
 */
void *FlowManagerThread(void *td)
{
    /* block usr1.  usr1 to be handled by the main thread only */
    UtilSignalBlock(SIGUSR2);

    ThreadVars *th_v = (ThreadVars *)td;
    struct timeval ts;
    uint32_t established_cnt = 0, new_cnt = 0, closing_cnt = 0;
    int emerg = FALSE;
    int prev_emerg = FALSE;
    uint32_t last_sec = 0;
    struct timespec cond_time;
    int flow_update_delay_sec = FLOW_NORMAL_MODE_UPDATE_DELAY_SEC;
    int flow_update_delay_nsec = FLOW_NORMAL_MODE_UPDATE_DELAY_NSEC;
/* VJ leaving disabled for now, as hosts are only used by tags and the numbers
 * are really low. Might confuse ppl
    uint16_t flow_mgr_host_prune = SCPerfTVRegisterCounter("hosts.pruned", th_v,
            SC_PERF_TYPE_UINT64,
            "NULL");
    uint16_t flow_mgr_host_active = SCPerfTVRegisterCounter("hosts.active", th_v,
            SC_PERF_TYPE_Q_NORMAL,
            "NULL");
    uint16_t flow_mgr_host_spare = SCPerfTVRegisterCounter("hosts.spare", th_v,
            SC_PERF_TYPE_Q_NORMAL,
            "NULL");
*/
    uint16_t flow_mgr_cnt_clo = SCPerfTVRegisterCounter("flow_mgr.closed_pruned", th_v,
            SC_PERF_TYPE_UINT64,
            "NULL");
    uint16_t flow_mgr_cnt_new = SCPerfTVRegisterCounter("flow_mgr.new_pruned", th_v,
            SC_PERF_TYPE_UINT64,
            "NULL");
    uint16_t flow_mgr_cnt_est = SCPerfTVRegisterCounter("flow_mgr.est_pruned", th_v,
            SC_PERF_TYPE_UINT64,
            "NULL");
    uint16_t flow_mgr_memuse = SCPerfTVRegisterCounter("flow.memuse", th_v,
            SC_PERF_TYPE_UINT64,
            "NULL");
    uint16_t flow_mgr_spare = SCPerfTVRegisterCounter("flow.spare", th_v,
            SC_PERF_TYPE_UINT64,
            "NULL");
    uint16_t flow_emerg_mode_enter = SCPerfTVRegisterCounter("flow.emerg_mode_entered", th_v,
            SC_PERF_TYPE_UINT64,
            "NULL");
    uint16_t flow_emerg_mode_over = SCPerfTVRegisterCounter("flow.emerg_mode_over", th_v,
            SC_PERF_TYPE_UINT64,
            "NULL");

    if (th_v->thread_setup_flags != 0)
        TmThreadSetupOptions(th_v);

    memset(&ts, 0, sizeof(ts));

    FlowForceReassemblySetup(g_detect_disabled);

    /* set the thread name */
    if (SCSetThreadName(th_v->name) < 0) {
        SCLogWarning(SC_ERR_THREAD_INIT, "Unable to set thread name");
    } else {
        SCLogDebug("%s started...", th_v->name);
    }

    th_v->sc_perf_pca = SCPerfGetAllCountersArray(&th_v->sc_perf_pctx);
    SCPerfAddToClubbedTMTable(th_v->name, &th_v->sc_perf_pctx);

    /* Set the threads capability */
    th_v->cap_flags = 0;
    SCDropCaps(th_v);
    PacketPoolInit();

    FlowHashDebugInit();

    TmThreadsSetFlag(th_v, THV_INIT_DONE);
    while (1)
    {
        if (TmThreadsCheckFlag(th_v, THV_PAUSE)) {
            TmThreadsSetFlag(th_v, THV_PAUSED);
            TmThreadTestThreadUnPaused(th_v);
            TmThreadsUnsetFlag(th_v, THV_PAUSED);
        }

        if (SC_ATOMIC_GET(flow_flags) & FLOW_EMERGENCY) {
            emerg = TRUE;

            if (emerg == TRUE && prev_emerg == FALSE) {
                prev_emerg = TRUE;

                SCLogDebug("Flow emergency mode entered...");

                SCPerfCounterIncr(flow_emerg_mode_enter, th_v->sc_perf_pca);
            }
        }

        /* Get the time */
        memset(&ts, 0, sizeof(ts));
        TimeGet(&ts);
        SCLogDebug("ts %" PRIdMAX "", (intmax_t)ts.tv_sec);

        if (((uint32_t)ts.tv_sec - last_sec) > 600) {
            FlowHashDebugPrint((uint32_t)ts.tv_sec);
            last_sec = (uint32_t)ts.tv_sec;
        }

        /* see if we still have enough spare flows */
        FlowUpdateSpareFlows();

        /* try to time out flows */
        FlowTimeoutCounters counters = { 0, 0, 0, };
        FlowTimeoutHash(&ts, 0 /* check all */, &counters);


        DefragTimeoutHash(&ts);
        //uint32_t hosts_pruned =
        HostTimeoutHash(&ts);
/*
        SCPerfCounterAddUI64(flow_mgr_host_prune, th_v->sc_perf_pca, (uint64_t)hosts_pruned);
        uint32_t hosts_active = HostGetActiveCount();
        SCPerfCounterSetUI64(flow_mgr_host_active, th_v->sc_perf_pca, (uint64_t)hosts_active);
        uint32_t hosts_spare = HostGetSpareCount();
        SCPerfCounterSetUI64(flow_mgr_host_spare, th_v->sc_perf_pca, (uint64_t)hosts_spare);
*/
        SCPerfCounterAddUI64(flow_mgr_cnt_clo, th_v->sc_perf_pca, (uint64_t)counters.clo);
        SCPerfCounterAddUI64(flow_mgr_cnt_new, th_v->sc_perf_pca, (uint64_t)counters.new);
        SCPerfCounterAddUI64(flow_mgr_cnt_est, th_v->sc_perf_pca, (uint64_t)counters.est);
        long long unsigned int flow_memuse = SC_ATOMIC_GET(flow_memuse);
        SCPerfCounterSetUI64(flow_mgr_memuse, th_v->sc_perf_pca, (uint64_t)flow_memuse);

        uint32_t len = 0;
        FQLOCK_LOCK(&flow_spare_q);
        len = flow_spare_q.len;
        FQLOCK_UNLOCK(&flow_spare_q);
        SCPerfCounterSetUI64(flow_mgr_spare, th_v->sc_perf_pca, (uint64_t)len);

        /* Don't fear, FlowManagerThread is here...
         * clear emergency bit if we have at least xx flows pruned. */
        if (emerg == TRUE) {
            SCLogDebug("flow_sparse_q.len = %"PRIu32" prealloc: %"PRIu32
                       "flow_spare_q status: %"PRIu32"%% flows at the queue",
                       len, flow_config.prealloc, len * 100 / flow_config.prealloc);
            /* only if we have pruned this "emergency_recovery" percentage
             * of flows, we will unset the emergency bit */
            if (len * 100 / flow_config.prealloc > flow_config.emergency_recovery) {
                SC_ATOMIC_AND(flow_flags, ~FLOW_EMERGENCY);

                emerg = FALSE;
                prev_emerg = FALSE;

                flow_update_delay_sec = FLOW_NORMAL_MODE_UPDATE_DELAY_SEC;
                flow_update_delay_nsec = FLOW_NORMAL_MODE_UPDATE_DELAY_NSEC;
                SCLogInfo("Flow emergency mode over, back to normal... unsetting"
                          " FLOW_EMERGENCY bit (ts.tv_sec: %"PRIuMAX", "
                          "ts.tv_usec:%"PRIuMAX") flow_spare_q status(): %"PRIu32
                          "%% flows at the queue", (uintmax_t)ts.tv_sec,
                          (uintmax_t)ts.tv_usec, len * 100 / flow_config.prealloc);

                SCPerfCounterIncr(flow_emerg_mode_over, th_v->sc_perf_pca);
            } else {
                flow_update_delay_sec = FLOW_EMERG_MODE_UPDATE_DELAY_SEC;
                flow_update_delay_nsec = FLOW_EMERG_MODE_UPDATE_DELAY_NSEC;
            }
        }

        if (TmThreadsCheckFlag(th_v, THV_KILL)) {
            SCPerfSyncCounters(th_v);
            break;
        }

        cond_time.tv_sec = time(NULL) + flow_update_delay_sec;
        cond_time.tv_nsec = flow_update_delay_nsec;
        SCCtrlMutexLock(&flow_manager_ctrl_mutex);
        SCCtrlCondTimedwait(&flow_manager_ctrl_cond, &flow_manager_ctrl_mutex,
                            &cond_time);
        SCCtrlMutexUnlock(&flow_manager_ctrl_mutex);

        SCLogDebug("woke up... %s", SC_ATOMIC_GET(flow_flags) & FLOW_EMERGENCY ? "emergency":"");

        SCPerfSyncCountersIfSignalled(th_v);
    }

    TmThreadsSetFlag(th_v, THV_RUNNING_DONE);
    TmThreadWaitForFlag(th_v, THV_DEINIT);

    FlowHashDebugDeinit();

    SCLogInfo("%" PRIu32 " new flows, %" PRIu32 " established flows were "
              "timed out, %"PRIu32" flows in closed state", new_cnt,
              established_cnt, closing_cnt);

    TmThreadsSetFlag(th_v, THV_CLOSED);
    pthread_exit((void *) 0);
    return NULL;
}

/** \brief spawn the flow manager thread */
void FlowManagerThreadSpawn()
{
    ThreadVars *tv_flowmgr = NULL;

    SCCtrlCondInit(&flow_manager_ctrl_cond, NULL);
    SCCtrlMutexInit(&flow_manager_ctrl_mutex, NULL);

    tv_flowmgr = TmThreadCreateMgmtThread("FlowManagerThread",
                                          FlowManagerThread, 0);

    TmThreadSetCPU(tv_flowmgr, MANAGEMENT_CPU_SET);

    if (tv_flowmgr == NULL) {
        printf("ERROR: TmThreadsCreate failed\n");
        exit(1);
    }
    if (TmThreadSpawn(tv_flowmgr) != TM_ECODE_OK) {
        printf("ERROR: TmThreadSpawn failed\n");
        exit(1);
    }

    return;
}

/** \brief Thread that manages timed out flows.
 *
 *  \param td ThreadVars casted to void ptr
 */
void *FlowRecyclerThread(void *td)
{
    /* block usr2. usr2 to be handled by the main thread only */
    UtilSignalBlock(SIGUSR2);

    ThreadVars *th_v = (ThreadVars *)td;
    struct timeval ts;
    struct timespec cond_time;
    int flow_update_delay_sec = FLOW_NORMAL_MODE_UPDATE_DELAY_SEC;
    int flow_update_delay_nsec = FLOW_NORMAL_MODE_UPDATE_DELAY_NSEC;
    uint64_t recycled_cnt = 0;
    void *output_thread_data = NULL;

    if (th_v->thread_setup_flags != 0)
        TmThreadSetupOptions(th_v);

    memset(&ts, 0, sizeof(ts));

    /* set the thread name */
    if (SCSetThreadName(th_v->name) < 0) {
        SCLogWarning(SC_ERR_THREAD_INIT, "Unable to set thread name");
    } else {
        SCLogDebug("%s started...", th_v->name);
    }

    /* Set the threads capability */
    th_v->cap_flags = 0;
    SCDropCaps(th_v);

    if (OutputFlowLogThreadInit(th_v, NULL, &output_thread_data) != TM_ECODE_OK) {
        SCLogError(SC_ERR_THREAD_INIT, "initializing flow log API for thread failed");

        /* failure */
        TmThreadsSetFlag(th_v, THV_RUNNING_DONE);
        TmThreadWaitForFlag(th_v, THV_DEINIT);
        TmThreadsSetFlag(th_v, THV_CLOSED);
        pthread_exit((void *) 0);
        return NULL;
    }
    SCLogDebug("output_thread_data %p", output_thread_data);

    TmThreadsSetFlag(th_v, THV_INIT_DONE);
    while (1)
    {
        if (TmThreadsCheckFlag(th_v, THV_PAUSE)) {
            TmThreadsSetFlag(th_v, THV_PAUSED);
            TmThreadTestThreadUnPaused(th_v);
            TmThreadsUnsetFlag(th_v, THV_PAUSED);
        }

        /* Get the time */
        memset(&ts, 0, sizeof(ts));
        TimeGet(&ts);
        SCLogDebug("ts %" PRIdMAX "", (intmax_t)ts.tv_sec);

        uint32_t len = 0;
        FQLOCK_LOCK(&flow_recycle_q);
        len = flow_recycle_q.len;
        FQLOCK_UNLOCK(&flow_recycle_q);

        /* Loop through the queue and clean up all flows in it */
        if (len) {
            Flow *f;

            while ((f = FlowDequeue(&flow_recycle_q)) != NULL) {
                FLOWLOCK_WRLOCK(f);

                (void)OutputFlowLog(th_v, output_thread_data, f);

                FlowClearMemory (f, f->protomap);
                FLOWLOCK_UNLOCK(f);
                FlowMoveToSpare(f);
                recycled_cnt++;
            }
        }

        SCLogDebug("%u flows to recycle", len);

        if (TmThreadsCheckFlag(th_v, THV_KILL)) {
            SCPerfSyncCounters(th_v);
            break;
        }

        cond_time.tv_sec = time(NULL) + flow_update_delay_sec;
        cond_time.tv_nsec = flow_update_delay_nsec;
        SCCtrlMutexLock(&flow_recycler_ctrl_mutex);
        SCCtrlCondTimedwait(&flow_recycler_ctrl_cond,
                &flow_recycler_ctrl_mutex, &cond_time);
        SCCtrlMutexUnlock(&flow_recycler_ctrl_mutex);

        SCLogDebug("woke up...");

        SCPerfSyncCountersIfSignalled(th_v);
    }

    if (output_thread_data != NULL)
        OutputFlowLogThreadDeinit(th_v, output_thread_data);

    SCLogInfo("%"PRIu64" flows processed", recycled_cnt);

    TmThreadsSetFlag(th_v, THV_RUNNING_DONE);
    TmThreadWaitForFlag(th_v, THV_DEINIT);

    TmThreadsSetFlag(th_v, THV_CLOSED);
    pthread_exit((void *) 0);
    return NULL;
}

int FlowRecyclerReadyToShutdown(void)
{
    uint32_t len = 0;
    FQLOCK_LOCK(&flow_recycle_q);
    len = flow_recycle_q.len;
    FQLOCK_UNLOCK(&flow_recycle_q);

    return ((len == 0));
}

/** \brief spawn the flow recycler thread */
void FlowRecyclerThreadSpawn()
{
    ThreadVars *tv_flowmgr = NULL;

    SCCtrlCondInit(&flow_recycler_ctrl_cond, NULL);
    SCCtrlMutexInit(&flow_recycler_ctrl_mutex, NULL);

    tv_flowmgr = TmThreadCreateMgmtThread("FlowRecyclerThread",
                                          FlowRecyclerThread, 0);

    TmThreadSetCPU(tv_flowmgr, MANAGEMENT_CPU_SET);

    if (tv_flowmgr == NULL) {
        printf("ERROR: TmThreadsCreate failed\n");
        exit(1);
    }
    if (TmThreadSpawn(tv_flowmgr) != TM_ECODE_OK) {
        printf("ERROR: TmThreadSpawn failed\n");
        exit(1);
    }

    return;
}

/**
 * \brief Used to kill flow recycler thread(s).
 *
 * \note this should only be called when the flow manager is already gone
 *
 * \todo Kinda hackish since it uses the tv name to identify flow recycler
 *       thread.  We need an all weather identification scheme.
 */
void FlowKillFlowRecyclerThread(void)
{
    ThreadVars *tv = NULL;
    int cnt = 0;

    /* make sure all flows are processed */
    do {
        SCCtrlCondSignal(&flow_recycler_ctrl_cond);
        usleep(10);
    } while (FlowRecyclerReadyToShutdown() == 0);

    SCMutexLock(&tv_root_lock);

    /* flow manager thread(s) is/are a part of mgmt threads */
    tv = tv_root[TVT_MGMT];

    while (tv != NULL) {
        if (strcasecmp(tv->name, "FlowRecyclerThread") == 0) {
            TmThreadsSetFlag(tv, THV_KILL);
            TmThreadsSetFlag(tv, THV_DEINIT);

            /* be sure it has shut down */
            while (!TmThreadsCheckFlag(tv, THV_CLOSED)) {
                usleep(100);
            }
            cnt++;
        }
        tv = tv->next;
    }

    /* not possible, unless someone decides to rename FlowManagerThread */
    if (cnt == 0) {
        SCMutexUnlock(&tv_root_lock);
        abort();
    }

    SCMutexUnlock(&tv_root_lock);
    return;
}

#ifdef UNITTESTS

/**
 *  \test   Test the timing out of a flow with a fresh TcpSession
 *          (just initialized, no data segments) in normal mode.
 *
 *  \retval On success it returns 1 and on failure 0.
 */

static int FlowMgrTest01 (void) {
    TcpSession ssn;
    Flow f;
    FlowBucket fb;
    struct timeval ts;

    FlowQueueInit(&flow_spare_q);

    memset(&ssn, 0, sizeof(TcpSession));
    memset(&f, 0, sizeof(Flow));
    memset(&ts, 0, sizeof(ts));
    memset(&fb, 0, sizeof(FlowBucket));

    FBLOCK_INIT(&fb);

    FLOW_INITIALIZE(&f);
    f.flags |= FLOW_TIMEOUT_REASSEMBLY_DONE;

    TimeGet(&ts);
    f.lastts.tv_sec = ts.tv_sec - 5000;
    f.protoctx = &ssn;
    f.fb = &fb;

    f.proto = IPPROTO_TCP;

    int state = FlowGetFlowState(&f);
    if (FlowManagerFlowTimeout(&f, state, &ts, 0) != 1 && FlowManagerFlowTimedOut(&f, &ts) != 1) {
        FBLOCK_DESTROY(&fb);
        FLOW_DESTROY(&f);
        FlowQueueDestroy(&flow_spare_q);
        return 0;
    }

    FBLOCK_DESTROY(&fb);
    FLOW_DESTROY(&f);

    FlowQueueDestroy(&flow_spare_q);
    return 1;
}

/**
 *  \test   Test the timing out of a flow with a TcpSession
 *          (with data segments) in normal mode.
 *
 *  \retval On success it returns 1 and on failure 0.
 */

static int FlowMgrTest02 (void) {
    TcpSession ssn;
    Flow f;
    FlowBucket fb;
    struct timeval ts;
    TcpSegment seg;
    TcpStream client;
    uint8_t payload[3] = {0x41, 0x41, 0x41};

    FlowQueueInit(&flow_spare_q);

    memset(&ssn, 0, sizeof(TcpSession));
    memset(&f, 0, sizeof(Flow));
    memset(&fb, 0, sizeof(FlowBucket));
    memset(&ts, 0, sizeof(ts));
    memset(&seg, 0, sizeof(TcpSegment));
    memset(&client, 0, sizeof(TcpSegment));

    FBLOCK_INIT(&fb);
    FLOW_INITIALIZE(&f);
    f.flags |= FLOW_TIMEOUT_REASSEMBLY_DONE;

    TimeGet(&ts);
    seg.payload = payload;
    seg.payload_len = 3;
    seg.next = NULL;
    seg.prev = NULL;
    client.seg_list = &seg;
    ssn.client = client;
    ssn.server = client;
    ssn.state = TCP_ESTABLISHED;
    f.lastts.tv_sec = ts.tv_sec - 5000;
    f.protoctx = &ssn;
    f.fb = &fb;
    f.proto = IPPROTO_TCP;

    int state = FlowGetFlowState(&f);
    if (FlowManagerFlowTimeout(&f, state, &ts, 0) != 1 && FlowManagerFlowTimedOut(&f, &ts) != 1) {
        FBLOCK_DESTROY(&fb);
        FLOW_DESTROY(&f);
        FlowQueueDestroy(&flow_spare_q);
        return 0;
    }
    FBLOCK_DESTROY(&fb);
    FLOW_DESTROY(&f);
    FlowQueueDestroy(&flow_spare_q);
    return 1;

}

/**
 *  \test   Test the timing out of a flow with a fresh TcpSession
 *          (just initialized, no data segments) in emergency mode.
 *
 *  \retval On success it returns 1 and on failure 0.
 */

static int FlowMgrTest03 (void) {
    TcpSession ssn;
    Flow f;
    FlowBucket fb;
    struct timeval ts;

    FlowQueueInit(&flow_spare_q);

    memset(&ssn, 0, sizeof(TcpSession));
    memset(&f, 0, sizeof(Flow));
    memset(&ts, 0, sizeof(ts));
    memset(&fb, 0, sizeof(FlowBucket));

    FBLOCK_INIT(&fb);
    FLOW_INITIALIZE(&f);
    f.flags |= FLOW_TIMEOUT_REASSEMBLY_DONE;

    TimeGet(&ts);
    ssn.state = TCP_SYN_SENT;
    f.lastts.tv_sec = ts.tv_sec - 300;
    f.protoctx = &ssn;
    f.fb = &fb;
    f.proto = IPPROTO_TCP;
    f.flags |= FLOW_EMERGENCY;

    int state = FlowGetFlowState(&f);
    if (FlowManagerFlowTimeout(&f, state, &ts, 0) != 1 && FlowManagerFlowTimedOut(&f, &ts) != 1) {
        FBLOCK_DESTROY(&fb);
        FLOW_DESTROY(&f);
        FlowQueueDestroy(&flow_spare_q);
        return 0;
    }

    FBLOCK_DESTROY(&fb);
    FLOW_DESTROY(&f);
    FlowQueueDestroy(&flow_spare_q);
    return 1;
}

/**
 *  \test   Test the timing out of a flow with a TcpSession
 *          (with data segments) in emergency mode.
 *
 *  \retval On success it returns 1 and on failure 0.
 */

static int FlowMgrTest04 (void) {

    TcpSession ssn;
    Flow f;
    FlowBucket fb;
    struct timeval ts;
    TcpSegment seg;
    TcpStream client;
    uint8_t payload[3] = {0x41, 0x41, 0x41};

    FlowQueueInit(&flow_spare_q);

    memset(&ssn, 0, sizeof(TcpSession));
    memset(&f, 0, sizeof(Flow));
    memset(&fb, 0, sizeof(FlowBucket));
    memset(&ts, 0, sizeof(ts));
    memset(&seg, 0, sizeof(TcpSegment));
    memset(&client, 0, sizeof(TcpSegment));

    FBLOCK_INIT(&fb);
    FLOW_INITIALIZE(&f);
    f.flags |= FLOW_TIMEOUT_REASSEMBLY_DONE;

    TimeGet(&ts);
    seg.payload = payload;
    seg.payload_len = 3;
    seg.next = NULL;
    seg.prev = NULL;
    client.seg_list = &seg;
    ssn.client = client;
    ssn.server = client;
    ssn.state = TCP_ESTABLISHED;
    f.lastts.tv_sec = ts.tv_sec - 5000;
    f.protoctx = &ssn;
    f.fb = &fb;
    f.proto = IPPROTO_TCP;
    f.flags |= FLOW_EMERGENCY;

    int state = FlowGetFlowState(&f);
    if (FlowManagerFlowTimeout(&f, state, &ts, 0) != 1 && FlowManagerFlowTimedOut(&f, &ts) != 1) {
        FBLOCK_DESTROY(&fb);
        FLOW_DESTROY(&f);
        FlowQueueDestroy(&flow_spare_q);
        return 0;
    }

    FBLOCK_DESTROY(&fb);
    FLOW_DESTROY(&f);
    FlowQueueDestroy(&flow_spare_q);
    return 1;
}

/**
 *  \test   Test flow allocations when it reach memcap
 *
 *
 *  \retval On success it returns 1 and on failure 0.
 */

static int FlowMgrTest05 (void) {
    int result = 0;

    FlowInitConfig(FLOW_QUIET);
    FlowConfig backup;
    memcpy(&backup, &flow_config, sizeof(FlowConfig));

    uint32_t ini = 0;
    uint32_t end = flow_spare_q.len;
    flow_config.memcap = 10000;
    flow_config.prealloc = 100;

    /* Let's get the flow_spare_q empty */
    UTHBuildPacketOfFlows(ini, end, 0);

    /* And now let's try to reach the memcap val */
    while (FLOW_CHECK_MEMCAP(sizeof(Flow))) {
        ini = end + 1;
        end = end + 2;
        UTHBuildPacketOfFlows(ini, end, 0);
    }

    /* should time out normal */
    TimeSetIncrementTime(2000);
    ini = end + 1;
    end = end + 2;;
    UTHBuildPacketOfFlows(ini, end, 0);

    struct timeval ts;
    TimeGet(&ts);
    /* try to time out flows */
    FlowTimeoutCounters counters = { 0, 0, 0, };
    FlowTimeoutHash(&ts, 0 /* check all */, &counters);

    if (flow_recycle_q.len > 0) {
        result = 1;
    }

    memcpy(&flow_config, &backup, sizeof(FlowConfig));
    FlowShutdown();

    return result;
}
#endif /* UNITTESTS */

/**
 *  \brief   Function to register the Flow Unitests.
 */
void FlowMgrRegisterTests (void) {
#ifdef UNITTESTS
    UtRegisterTest("FlowMgrTest01 -- Timeout a flow having fresh TcpSession", FlowMgrTest01, 1);
    UtRegisterTest("FlowMgrTest02 -- Timeout a flow having TcpSession with segments", FlowMgrTest02, 1);
    UtRegisterTest("FlowMgrTest03 -- Timeout a flow in emergency having fresh TcpSession", FlowMgrTest03, 1);
    UtRegisterTest("FlowMgrTest04 -- Timeout a flow in emergency having TcpSession with segments", FlowMgrTest04, 1);
    UtRegisterTest("FlowMgrTest05 -- Test flow Allocations when it reach memcap", FlowMgrTest05, 1);
#endif /* UNITTESTS */
}
