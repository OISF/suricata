/* Copyright (C) 2026 Open Information Security Foundation
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
#include "log-flush.h"
#include "util-logopenfile.h"
#include "tm-threads.h"
#include "conf.h"
#include "conf-yaml-loader.h"
#include "util-privs.h"

/**
 * \brief Trigger flush of all registered log files
 *
 * This function is intended to be called at regular intervals to force
 * buffered log data to be persisted. With the new design, this simply calls
 * LogFileFlushAll() which directly flushes all registered file contexts.
 */
static void WorkerFlushLogs(void)
{
    LogFileFlushAll();
}

static int OutputFlushInterval(void)
{
    intmax_t output_flush_interval = 0;
    if (SCConfGetInt("heartbeat.output-flush-interval", &output_flush_interval) == 0) {
        output_flush_interval = 0;
    }
    if (output_flush_interval < 0 || output_flush_interval > 60) {
        SCLogConfig("flush_interval must be 0 or less than 60; using 0");
        output_flush_interval = 0;
    }

    return (int)output_flush_interval;
}

static void *LogFlusherWakeupThread(void *arg)
{
    int output_flush_interval = OutputFlushInterval();
    /* This was checked by the logic creating this thread */
    BUG_ON(output_flush_interval == 0);

    SCLogConfig("Using output-flush-interval of %d seconds", output_flush_interval);
    /*
     * Calculate the number of sleep intervals based on the output flush interval. This is necessary
     * because this thread pauses a fixed amount of time to react to shutdown situations more
     * quickly.
     */
    const int log_flush_sleep_time = 500; /* milliseconds */
    const int flush_wait_count = (1000 * output_flush_interval) / log_flush_sleep_time;

    ThreadVars *tv_local = (ThreadVars *)arg;
    SCSetThreadName(tv_local->name);

    if (tv_local->thread_setup_flags != 0)
        TmThreadSetupOptions(tv_local);

    /* Set the threads capability */
    tv_local->cap_flags = 0;
    SCDropCaps(tv_local);

    TmThreadsSetFlag(tv_local, THV_INIT_DONE | THV_RUNNING);

    int wait_count = 0;
    uint64_t worker_flush_count = 0;
    bool run = TmThreadsWaitForUnpause(tv_local);
    while (run) {
        SleepMsec(log_flush_sleep_time);

        if (++wait_count == flush_wait_count) {
            worker_flush_count++;
            WorkerFlushLogs();
            wait_count = 0;
        }

        if (TmThreadsCheckFlag(tv_local, THV_KILL)) {
            break;
        }
    }

    TmThreadsSetFlag(tv_local, THV_RUNNING_DONE);
    TmThreadWaitForFlag(tv_local, THV_DEINIT);
    TmThreadsSetFlag(tv_local, THV_CLOSED);
    SCLogInfo("%s: initiated %" PRIu64 " flushes", tv_local->name, worker_flush_count);
    return NULL;
}

void LogFlushThreads(void)
{
    if (0 == OutputFlushInterval()) {
        SCLogConfig("log flusher thread not used with heartbeat.output-flush-interval of 0");
        return;
    }

    ThreadVars *tv_log_flush =
            TmThreadCreateMgmtThread(thread_name_heartbeat, LogFlusherWakeupThread, 1);
    if (!tv_log_flush || (TmThreadSpawn(tv_log_flush) != 0)) {
        FatalError("Unable to create and start log flush thread");
    }
}
