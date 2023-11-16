/* Copyright (C) 2023 Open Information Security Foundation
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
 * \author Jeff Lucovsky <jlucovsky@oisf.net>
 */

#include "suricata-common.h"
#include "suricata.h"
#include "detect.h"
#include "detect-engine.h"
#include "flow-worker.h"
#include "log-flush.h"
#include "tm-threads.h"
#include "conf.h"
#include "conf-yaml-loader.h"
#include "util-privs.h"

/**
 * \brief Trigger detect threads to flush their output logs
 *
 * This function is intended to be called at regular intervals to force
 * buffered log data to be persisted
 */
static void WorkerFlushLogs(void)
{
    SCEnter();
    /* count detect threads in use */
    uint32_t no_of_detect_tvs = TmThreadCountThreadsByTmmFlags(TM_FLAG_DETECT_TM);
    /* can be zero in unix socket mode */
    if (no_of_detect_tvs == 0) {
        return;
    }

    /* prepare swap structures */
    DetectEngineThreadCtx *det_ctx[no_of_detect_tvs];
    ThreadVars *detect_tvs[no_of_detect_tvs];
    memset(det_ctx, 0x00, (no_of_detect_tvs * sizeof(DetectEngineThreadCtx *)));
    memset(detect_tvs, 0x00, (no_of_detect_tvs * sizeof(ThreadVars *)));

    /* start the process of swapping detect threads ctxs */

    uint32_t i = 0;
    /* get reference to tv's and setup new_det_ctx array */
    SCMutexLock(&tv_root_lock);
    for (ThreadVars *tv = tv_root[TVT_PPT]; tv != NULL; tv = tv->next) {
        if ((tv->tmm_flags & TM_FLAG_DETECT_TM) == 0) {
            continue;
        }
        for (TmSlot *s = tv->tm_slots; s != NULL; s = s->slot_next) {
            TmModule *tm = TmModuleGetById(s->tm_id);
            if (!(tm->flags & TM_FLAG_DETECT_TM)) {
                continue;
            }

            if (suricata_ctl_flags != 0) {
                SCMutexUnlock(&tv_root_lock);
                goto error;
            }

            det_ctx[i] = FlowWorkerGetDetectCtxPtr(SC_ATOMIC_GET(s->slot_data));
            SC_ATOMIC_SET(det_ctx[i]->flush_ack, 0);
            detect_tvs[i] = tv;

            i++;
            break;
        }
    }
    BUG_ON(i != no_of_detect_tvs);

    SCMutexUnlock(&tv_root_lock);

    SCLogDebug("Creating flush pseudo packets for %d threads", no_of_detect_tvs);
    InjectPackets(detect_tvs, det_ctx, no_of_detect_tvs, true);

    uint32_t threads_done = 0;
retry:
    for (i = 0; i < no_of_detect_tvs; i++) {
        if (suricata_ctl_flags != 0) {
            threads_done = no_of_detect_tvs;
            break;
        }
        usleep(1000);
        if (SC_ATOMIC_GET(det_ctx[i]->flush_ack) == 1) {
            SCLogDebug("thread slot %d has ack'd flush request", i);
            threads_done++;
        } else {
            SCLogDebug("thread slot %d not yet ack'd flush request", i);
            TmThreadsCaptureBreakLoop(detect_tvs[i]);
        }
    }
    if (threads_done < no_of_detect_tvs) {
        threads_done = 0;
        SleepMsec(250);
        goto retry;
    }

    /* this is to make sure that if someone initiated shutdown during
     * this process
     *
     * TODO: needed?
     *
     * .rule swap, the live rule swap won't clean up the old det_ctx and
     * de_ctx, till all detect threads have stopped working and sitting
     * silently after setting RUNNING_DONE flag and while waiting for
     * THV_DEINIT flag */
    if (i != no_of_detect_tvs) { // not all threads we swapped
        for (ThreadVars *tv = tv_root[TVT_PPT]; tv != NULL; tv = tv->next) {
            if ((tv->tmm_flags & TM_FLAG_DETECT_TM) == 0) {
                continue;
            }

            while (!TmThreadsCheckFlag(tv, THV_RUNNING_DONE)) {
                usleep(100);
            }
        }
    }

error:
    return;
}

static void *LogFlusherWakeupThread(void *arg)
{
    ThreadVars *tv_local = (ThreadVars *)arg;

    intmax_t output_flush_interval = 0;
    if (ConfGetInt("logging.flush-interval", &output_flush_interval) == 0) {
        output_flush_interval = 0;
    }
    if (output_flush_interval < 0 || output_flush_interval > 60) {
        SCLogConfig("flush_interval must be 0 or less than 60; using 0");
        output_flush_interval = 0;
    }
    SCLogNotice("Using flush-interval of %d seconds", (int)output_flush_interval);

    SCSetThreadName(tv_local->name);

    if (tv_local->thread_setup_flags != 0)
        TmThreadSetupOptions(tv_local);

    /* Set the threads capability */
    tv_local->cap_flags = 0;
    SCDropCaps(tv_local);

    TmThreadsSetFlag(tv_local, THV_INIT_DONE | THV_RUNNING);

    while (1) {
        if (TmThreadsCheckFlag(tv_local, THV_PAUSE)) {
            TmThreadsSetFlag(tv_local, THV_PAUSED);
            TmThreadTestThreadUnPaused(tv_local);
            TmThreadsUnsetFlag(tv_local, THV_PAUSED);
        }

        WorkerFlushLogs();
        sleep(output_flush_interval);

        if (TmThreadsCheckFlag(tv_local, THV_KILL)) {
            break;
        }
    }

    TmThreadsSetFlag(tv_local, THV_RUNNING_DONE);
    TmThreadWaitForFlag(tv_local, THV_DEINIT);
    TmThreadsSetFlag(tv_local, THV_CLOSED);
    return NULL;
}

void LogFlushThreads(void)
{
    intmax_t output_flush_interval = 0;
    if (ConfGetInt("logging.flush-interval", &output_flush_interval) == 0) {
        output_flush_interval = 0;
    }
    if (output_flush_interval < 0 || output_flush_interval > 60) {
        output_flush_interval = 0;
    }

    if (output_flush_interval) {
        ThreadVars *tv_log_flush =
                TmThreadCreateMgmtThread(thread_name_log_flusher, LogFlusherWakeupThread, 1);
        if (tv_log_flush == NULL) {
            FatalError("Unable to create log flush thread");
        }
        if (TmThreadSpawn(tv_log_flush) != 0) {
            FatalError("Unable to spawn log flush thread");
        }
    } else {
        SCLogConfig("log flusher thread not started since flush-interval is %d",
                (int)output_flush_interval);
    }
}
