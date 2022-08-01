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

// debug function for printing out xstats
static void print_stats(unsigned  int port_id)
{
    int len, ret, i;
    struct rte_eth_xstat *xstats;
    struct rte_eth_xstat_name *xstats_names;
    static const char *stats_border = "_______";
    const char clr[] = { 27, '[', '2', 'J', '\0' };
    const char topLeft[] = { 27, '[', '1', ';', '1', 'H', '\0' };
    /* Clear screen and move to top left */
    printf("PORT STATISTICS:\n================\n");
    len = rte_eth_xstats_get(port_id, NULL, 0);
    if (len < 0)
        rte_exit(EXIT_FAILURE,
                "rte_eth_xstats_get(%u) failed: %d", port_id,
                len);
    xstats = calloc(len, sizeof(*xstats));
    if (xstats == NULL)
        rte_exit(EXIT_FAILURE,
                "Failed to calloc memory for xstats");
    ret = rte_eth_xstats_get(port_id, xstats, len);
    if (ret < 0 || ret > len) {
        free(xstats);
        rte_exit(EXIT_FAILURE,
                "rte_eth_xstats_get(%u) len%i failed: %d",
                port_id, len, ret);
    }
    xstats_names = calloc(len, sizeof(*xstats_names));
    if (xstats_names == NULL) {
        free(xstats);
        rte_exit(EXIT_FAILURE,
                "Failed to calloc memory for xstats_names");
    }
    ret = rte_eth_xstats_get_names(port_id, xstats_names, len);
    if (ret < 0 || ret > len) {
        free(xstats);
        free(xstats_names);
        rte_exit(EXIT_FAILURE,
                "rte_eth_xstats_get_names(%u) len%i failed: %d",
                port_id, len, ret);
    }
    for (i = 0; i < len; i++) {
        if (xstats[i].value > 0)
            printf("Port %u: %s %s:\t\t%"PRIu64"\n",
                    port_id, stats_border,
                    xstats_names[i].name,
                    xstats[i].value);
    }
    fflush(stdout);
    free(xstats);
    free(xstats_names);
}

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

            if (lv->qid == 0) {
                print_stats(lv->port1_id);
                print_stats(lv->port2_id);
            }

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
