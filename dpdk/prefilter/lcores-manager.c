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

#include <stdint-gcc.h>
#include <sys/queue.h>
#include <rte_launch.h>
#include <rte_lcore.h>
#include <rte_malloc.h>

#include "lcores-manager.h"
#include "lcore-worker.h"
#include "dev-conf.h"
#include "logger.h"
#include "util-prefilter.h"

/**
 * For use-cases when the prefilter app has less lcores than the secondary app.
 */
uint16_t LcoreManagerCalcRingsPerLcore(uint16_t sec_app_lcores_cnt, uint16_t pf_lcores_cnt)
{
    return sec_app_lcores_cnt / pf_lcores_cnt;
}

uint16_t LcoreManagerCalcLeftoverRingsPerLcore(uint16_t sec_app_lcores_cnt, uint16_t pf_lcores_cnt)
{
    return sec_app_lcores_cnt % pf_lcores_cnt;
}

void LcoreManagerAssignRingsToLcore(
        struct lcore_init *init_vals, uint16_t rpl, uint16_t *next_ring_id, uint16_t *leftovers)
{
    init_vals->ring_offset_start = *next_ring_id;
    if (*leftovers > 0) {
        init_vals->rings_cnt = rpl + 1;
        (*leftovers)--;
    } else {
        init_vals->rings_cnt = rpl;
    }

    *next_ring_id = init_vals->ring_offset_start + init_vals->rings_cnt;
    Log().info("Start ring %d, Stop ring %d, next ring %d lefties %d rpl %d",
            init_vals->ring_offset_start, init_vals->ring_offset_start + init_vals->rings_cnt,
            *next_ring_id, *leftovers, rpl);
}

int LcoreManagerRunWorker(
        struct ring_list_entry *re, int32_t *last_lcore_id, struct pf_stats *stats)
{
    uint16_t next_ring = 0;
    uint16_t rings_per_lcore =
            LcoreManagerCalcRingsPerLcore(re->sec_app_cores_cnt, re->pf_cores_cnt);
    uint16_t leftover_rings =
            LcoreManagerCalcLeftoverRingsPerLcore(re->sec_app_cores_cnt, re->pf_cores_cnt);

    for (uint32_t spawned_lcores = 0; spawned_lcores < re->pf_cores_cnt; spawned_lcores++) {
        *last_lcore_id = (int32_t)rte_get_next_lcore(*last_lcore_id, 1, 0);
        if (*last_lcore_id >= RTE_MAX_LCORE) {
            Log().error(EINVAL, "Not enough lcores configured");
            return -EINVAL;
        }

        struct lcore_init *val = rte_calloc("struct lcore_init", sizeof(struct lcore_init), 1, 0);
        if (val == NULL) {
            Log().error(ENOMEM, "Memory allocation failed for lcore init");
            return -ENOMEM;
        }

        LcoreManagerAssignRingsToLcore(val, rings_per_lcore, &next_ring, &leftover_rings);
        val->re = re;
        val->lcore_id = spawned_lcores;
        val->stats = stats;

        rte_eal_remote_launch(ThreadMain, (void *)val, *last_lcore_id);
    }

    return 0;
}

int LcoreManagerRunWorkers(struct pf_stats *stats)
{
    int retval;
    int32_t last_lcore_id = -1; // -1 to get the first
    struct ring_list_entry *re;
    TAILQ_FOREACH (re, &tailq_ring_head, entries) {
        Log().info("Spawning workers for %s", re->main_ring.name_base);
        retval = LcoreManagerRunWorker(re, &last_lcore_id, stats);
        if (retval != 0) {
            Log().error(EINVAL, "Not able to spawn all workers, halting!");
            StopWorkers();
            return retval;
        }
    }
    return 0;
}