/* Copyright (C) 2007-2026 Open Information Security Foundation
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
#include "log-maintenance.h"
#include "util-logopenfile.h"
#include "tm-threads.h"
#include "conf.h"
#include "conf-yaml-loader.h"
#include "util-privs.h"

int OutputFlushInterval(void)
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

static void *LogMaintenanceThread(void *arg)
{
    int output_flush_interval = OutputFlushInterval();

    if (output_flush_interval > 0) {
        SCLogConfig("Log maintenance thread started: rotation every 1s, flush interval %ds",
                output_flush_interval);
    } else {
        SCLogConfig("Log maintenance thread started: rotation every 1s, flush disabled");
    }

    /*
     * Calculate the number of sleep intervals based on the output flush interval. This is necessary
     * because this thread pauses a fixed amount of time to react to shutdown situations more
     * quickly.
     */
    const int maintenance_sleep_time = 500;                        /* milliseconds */
    const int rotation_wait_count = 1000 / maintenance_sleep_time; /* = 2, check every 1 second */
    const int flush_wait_count =
            output_flush_interval > 0 ? (1000 * output_flush_interval) / maintenance_sleep_time : 0;

    ThreadVars *tv_local = (ThreadVars *)arg;
    SCSetThreadName(tv_local->name);

    if (tv_local->thread_setup_flags != 0)
        TmThreadSetupOptions(tv_local);

    /* Set the threads capability */
    tv_local->cap_flags = 0;
    SCDropCaps(tv_local);

    TmThreadsSetFlag(tv_local, THV_INIT_DONE | THV_RUNNING);

    int rotation_counter = 0;
    int flush_counter = 0;
    uint64_t rotation_check_count = 0;
    uint64_t worker_flush_count = 0;
    bool run = TmThreadsWaitForUnpause(tv_local);
    while (run) {
        SleepMsec(maintenance_sleep_time);

        /* Check rotation every 1 second */
        if (++rotation_counter >= rotation_wait_count) {
            rotation_check_count++;
            LogFileRotateAll();
            rotation_counter = 0;
        }

        /* Flush at configured interval (if enabled) */
        if (flush_wait_count > 0 && ++flush_counter >= flush_wait_count) {
            worker_flush_count++;
            LogFileFlushAll();
            flush_counter = 0;
        }

        if (TmThreadsCheckFlag(tv_local, THV_KILL)) {
            break;
        }
    }

    TmThreadsSetFlag(tv_local, THV_RUNNING_DONE);
    TmThreadWaitForFlag(tv_local, THV_DEINIT);
    TmThreadsSetFlag(tv_local, THV_CLOSED);
    SCLogInfo("%s: performed %" PRIu64 " rotation checks, %" PRIu64 " flushes", tv_local->name,
            rotation_check_count, worker_flush_count);
    return NULL;
}

void LogMaintenanceThreadSpawn(void)
{
    ThreadVars *tv_maintenance =
            TmThreadCreateMgmtThread(thread_name_heartbeat, LogMaintenanceThread, 1);
    if (!tv_maintenance || (TmThreadSpawn(tv_maintenance) != 0)) {
        FatalError("Unable to create and start log maintenance thread");
    }
}
