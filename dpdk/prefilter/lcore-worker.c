/* Copyright (C) 2022 Open Information Security Foundation
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
 * \author Lukas Sismis <lukas.sismis@cesnet.cz>
 */

#include <sys/types.h>

#include <rte_atomic.h>

#include "lcore-worker.h"
#include "dev-conf.h"
#include "lcores-manager.h"
#include "lcore-worker-suricata.h"

#include "util-dpdk-bypass.h"
#include "logger.h"
#include "util-prefilter.h"

int ThreadMain(void *init_values)
{
    struct lcore_init *vals = (struct lcore_init *)init_values;
    struct lcore_values *lv = NULL;
    while (1) {
        if (ShouldStop() && LcoreStateCheck(vals->state, LCORE_WAIT)) {
            Log().info("Lcore %s:%d shutting down", vals->re->main_ring.name_base, vals->lcore_id);
            ThreadSuricataDeinit(vals, lv);
            vals = NULL; lv = NULL;
            break;
        }
        if (LcoreStateCheck(vals->state, LCORE_INIT)) {
            lv = ThreadSuricataInit(init_values);
            if (lv == NULL)
                return -EINVAL;
            LcoreStateSet(lv->state, LCORE_INIT_DONE);
            Log().debug("Lcore %d initialised", rte_lcore_id());
        } else if (LcoreStateCheck(vals->state, LCORE_RUN)) {
            Log().debug("Lcore %d PKTS process", rte_lcore_id());
            ThreadSuricataRun(lv);
            LcoreStateSet(lv->state, LCORE_RUNNING_DONE);
            Log().debug("Lcore %d PKTS process finished", rte_lcore_id());
        } else if (LcoreStateCheck(vals->state, LCORE_STAT_DUMP)) {
            Log().info("DUMP start");
            ThreadSuricataStatsDump(lv);
            ThreadSuricataStatsExit(lv, vals->stats);
            Log().info("DUMP finish");
            // only work with tasks and result ring/s and bt
        } else if (LcoreStateCheck(vals->state, LCORE_DETACH)) {
            Log().debug("Lcore %d detach", rte_lcore_id());
            LcoreStateSet(vals->state, LCORE_WAIT);
        }
        rte_delay_us_sleep(1000);
    }

    // todo: ipc: tomorrow: alternative: fix the possibility of using multiple ring-entries
    // wait for the dump flag
    // walk the table and sequentially push it to the ring
    // on failure use sleep

    return 0;
}
