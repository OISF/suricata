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
 * \author Anoop Saldanha <anoopsaldanha@gmail.com>
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

#include "threads.h"
#include "detect.h"
#include "detect-engine-state.h"
#include "stream.h"

#include "app-layer-parser.h"

/* Run mode selected at suricata.c */
extern int run_mode;

/* 0.4 seconds */
#define FLOW_NORMAL_MODE_UPDATE_DELAY_SEC 1
#define FLOW_NORMAL_MODE_UPDATE_DELAY_NSEC 0
/* 0.01 seconds */
#define FLOW_EMERG_MODE_UPDATE_DELAY_SEC 0
#define FLOW_EMERG_MODE_UPDATE_DELAY_NSEC 10000000
#define NEW_FLOW_COUNT_COND 10

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

    SCCondSignal(&flow_manager_cond);

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

/** \brief Thread that manages the various queue's and removes timed out flows.
 *  \param td ThreadVars casted to void ptr
 *
 * IDEAS/TODO
 * Create a 'emergency mode' in which flow handling threads can indicate
 * we are/seem to be under attack..... maybe this thread should check
 * key indicators for that like:
 * - number of flows created in the last x time
 * - avg number of pkts per flow (how?)
 * - avg flow age
 *
 * Keep an eye on the spare list, alloc flows if needed...
 */
void *FlowManagerThread(void *td)
{
    ThreadVars *th_v = (ThreadVars *)td;
    struct timeval ts;
    uint32_t established_cnt = 0, new_cnt = 0, closing_cnt = 0, nowcnt;
    int emerg = FALSE;
    int prev_emerg = FALSE;
    uint32_t last_sec = 0;
    struct timespec cond_time;
    int flow_update_delay_sec = FLOW_NORMAL_MODE_UPDATE_DELAY_SEC;
    int flow_update_delay_nsec = FLOW_NORMAL_MODE_UPDATE_DELAY_NSEC;

    uint16_t flow_mgr_closing_cnt = SCPerfTVRegisterCounter("flow_mgr.closed_pruned", th_v,
            SC_PERF_TYPE_UINT64,
            "NULL");
    uint16_t flow_mgr_new_cnt = SCPerfTVRegisterCounter("flow_mgr.new_pruned", th_v,
            SC_PERF_TYPE_UINT64,
            "NULL");
    uint16_t flow_mgr_established_cnt = SCPerfTVRegisterCounter("flow_mgr.est_pruned", th_v,
            SC_PERF_TYPE_UINT64,
            "NULL");
    uint16_t flow_mgr_memuse = SCPerfTVRegisterCounter("flow.memuse", th_v,
            SC_PERF_TYPE_Q_NORMAL,
            "NULL");
    uint16_t flow_emerg_mode_enter = SCPerfTVRegisterCounter("flow.emerg_mode_entered", th_v,
            SC_PERF_TYPE_UINT64,
            "NULL");
    uint16_t flow_emerg_mode_over = SCPerfTVRegisterCounter("flow.emerg_mode_over", th_v,
            SC_PERF_TYPE_UINT64,
            "NULL");

    memset(&ts, 0, sizeof(ts));

    FlowForceReassemblySetup();

    /* set the thread name */
    SCSetThreadName(th_v->name);
    SCLogDebug("%s started...", th_v->name);

    th_v->sc_perf_pca = SCPerfGetAllCountersArray(&th_v->sc_perf_pctx);
    SCPerfAddToClubbedTMTable(th_v->name, &th_v->sc_perf_pctx);

    /* Set the threads capability */
    th_v->cap_flags = 0;
    SCDropCaps(th_v);

    FlowHashDebugInit();

    TmThreadsSetFlag(th_v, THV_INIT_DONE);
    while (1)
    {
        TmThreadTestThreadUnPaused(th_v);

        if (flow_flags & FLOW_EMERGENCY) {
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

        int i;
        closing_cnt = 0;
        new_cnt = 0;
        established_cnt = 0;
        for (i = 0; i < FLOW_PROTO_MAX; i++) {
            /* prune closing list */
            nowcnt = FlowPruneFlowQueue(&flow_close_q[i], &ts);
            if (nowcnt) {
                SCLogDebug("Pruned %" PRIu32 " closing flows...", nowcnt);
                closing_cnt += nowcnt;
            }

            /* prune new list */
            nowcnt = FlowPruneFlowQueue(&flow_new_q[i], &ts);
            if (nowcnt) {
                SCLogDebug("Pruned %" PRIu32 " new flows...", nowcnt);
                new_cnt += nowcnt;
            }

            /* prune established list */
            nowcnt = FlowPruneFlowQueue(&flow_est_q[i], &ts);
            if (nowcnt) {
                SCLogDebug("Pruned %" PRIu32 " established flows...", nowcnt);
                established_cnt += nowcnt;
            }
        }
        SCPerfCounterAddUI64(flow_mgr_closing_cnt, th_v->sc_perf_pca, (uint64_t)closing_cnt);
        SCPerfCounterAddUI64(flow_mgr_new_cnt, th_v->sc_perf_pca, (uint64_t)new_cnt);
        SCPerfCounterAddUI64(flow_mgr_established_cnt, th_v->sc_perf_pca, (uint64_t)established_cnt);
        long long unsigned int flow_memuse = SC_ATOMIC_GET(flow_memuse);
        SCPerfCounterSetUI64(flow_mgr_memuse, th_v->sc_perf_pca, (uint64_t)flow_memuse);

        /* Don't fear, FlowManagerThread is here...
         * clear emergency bit if we have at least xx flows pruned. */
        if (emerg == TRUE) {
            uint32_t len = 0;

            SCMutexLock(&flow_spare_q.mutex_q);

            len = flow_spare_q.len;

            SCMutexUnlock(&flow_spare_q.mutex_q);

            SCLogDebug("flow_sparse_q.len = %"PRIu32" prealloc: %"PRIu32
                       "flow_spare_q status: %"PRIu32"%% flows at the queue",
                       len, flow_config.prealloc, len * 100 / flow_config.prealloc);
            /* only if we have pruned this "emergency_recovery" percentage
             * of flows, we will unset the emergency bit */
            if (len * 100 / flow_config.prealloc > flow_config.emergency_recovery) {
                flow_flags &= ~FLOW_EMERGENCY;
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
            SCPerfSyncCounters(th_v, 0);
            break;
        }

        cond_time.tv_sec = time(NULL) + flow_update_delay_sec;
        cond_time.tv_nsec = flow_update_delay_nsec;
        SCMutexLock(&flow_manager_mutex);
        SCCondTimedwait(&flow_manager_cond, &flow_manager_mutex, &cond_time);
        SCMutexUnlock(&flow_manager_mutex);

        SCPerfSyncCountersIfSignalled(th_v, 0);
    }

    TmThreadWaitForFlag(th_v, THV_DEINIT);

    FlowHashDebugDeinit();

    SCLogInfo("%" PRIu32 " new flows, %" PRIu32 " established flows were "
              "timed out, %"PRIu32" flows in closed state", new_cnt,
              established_cnt, closing_cnt);

#ifdef FLOW_PRUNE_DEBUG
    SCLogInfo("prune_queue_lock %"PRIu64, prune_queue_lock);
    SCLogInfo("prune_queue_empty %"PRIu64, prune_queue_empty);
    SCLogInfo("prune_flow_lock %"PRIu64, prune_flow_lock);
    SCLogInfo("prune_bucket_lock %"PRIu64, prune_bucket_lock);
    SCLogInfo("prune_no_timeout %"PRIu64, prune_no_timeout);
    SCLogInfo("prune_usecnt %"PRIu64, prune_usecnt);
#endif

    TmThreadsSetFlag(th_v, THV_CLOSED);
    pthread_exit((void *) 0);
}

/** \brief spawn the flow manager thread */
void FlowManagerThreadSpawn()
{
    ThreadVars *tv_flowmgr = NULL;

    SCCondInit(&flow_manager_cond, NULL);

    tv_flowmgr = TmThreadCreateMgmtThread("FlowManagerThread",
                                          FlowManagerThread, 0);

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
