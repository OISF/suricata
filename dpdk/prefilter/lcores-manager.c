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
#include <sys/types.h>
#include <rte_launch.h>
#include <rte_lcore.h>
#include <rte_malloc.h>
#include <time.h>

#include "lcores-manager.h"
#include "lcore-worker.h"
#include "dev-conf.h"
#include "logger.h"
#include "util-prefilter.h"

struct lcore_init *LcoreMainAsWorker = NULL;

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

uint32_t LcoreManagerGetLcoreIdFromRingId(
        uint16_t ring_id, uint16_t sec_app_lcores_cnt, uint16_t pf_lcores_cnt)
{
    if (ring_id > sec_app_lcores_cnt) {
        Log().error(EINVAL, "Ring ID is bigger than number of secondary app lcores");
        return LCORE_ID_ANY;
    }

    uint16_t rpl = LcoreManagerCalcRingsPerLcore(sec_app_lcores_cnt, pf_lcores_cnt);
    uint16_t leftovers = LcoreManagerCalcLeftoverRingsPerLcore(sec_app_lcores_cnt, pf_lcores_cnt);
    uint16_t lcore_min_ring_id = 0;
    uint16_t lcore_max_ring_id;

    for (int lcore_id = 0; lcore_id < pf_lcores_cnt; lcore_id++) {
        if (leftovers > 0) {
            lcore_max_ring_id = lcore_min_ring_id + rpl + 1;
            leftovers--;
        } else {
            lcore_max_ring_id = lcore_min_ring_id + rpl;
        }

        if (ring_id >= lcore_min_ring_id && ring_id < lcore_max_ring_id) {
            return lcore_id;
        }

        lcore_min_ring_id = lcore_max_ring_id;
    }

    Log().error(EINVAL, "Unable to get lcore ID of ring ID %d", ring_id);
    return LCORE_ID_ANY;
}

rte_atomic16_t *LcoreStateInit(void)
{
    rte_atomic16_t *state;
    state = (rte_atomic16_t *)rte_calloc("rte_atomic16_t", sizeof(rte_atomic16_t), 1, 0);
    if (state == NULL) {
        Log().error(ENOMEM, "Memory allocation failed for thread flags");
        return NULL;
    }
    rte_atomic16_init(state);
    return state;
}

void LcoreStateSet(rte_atomic16_t *state, enum LcoreStateEnum new_state)
{
    rte_atomic16_set(state, new_state);
}

int LcoreStateCheck(rte_atomic16_t *state, enum LcoreStateEnum check_state)
{
    return (check_state == rte_atomic16_read(state));
}

int LcoreStateWaitWithTimeout(
        rte_atomic16_t *state, enum LcoreStateEnum check_state, uint16_t timeout_sec)
{
    time_t init_time, tmp_time;
    time(&init_time);

    while (!LcoreStateCheck(state, check_state)) {
        rte_delay_us_sleep(100);
        time(&tmp_time);
        if (tmp_time - init_time > timeout_sec)
            return -ETIMEDOUT;
    }

    return 0;
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
            // if we are missing only the very last lcore and are on the very last ring entry..
            if (re->pf_cores_cnt - spawned_lcores == 1) {
                *last_lcore_id = rte_get_main_lcore();
                if (rte_lcore_id() != rte_get_main_lcore()) {
                    Log().error(EINVAL, "Configuring but not the main lcore!");
                    return -EINVAL;
                }
            } else {
                Log().error(EINVAL, "Not enough lcores configured");
                return -EINVAL;
            }
        }

        struct lcore_init *val = (struct lcore_init *)rte_calloc(
                "struct lcore_init", sizeof(struct lcore_init), 1, 0);
        if (val == NULL) {
            Log().error(ENOMEM, "Memory allocation failed for lcore init");
            return -ENOMEM;
        }

        rte_atomic16_t *lcore_state = LcoreStateInit();
        if (lcore_state == NULL)
            return -ENOMEM;
        LcoreStateSet(lcore_state, LCORE_INIT);

        const char *table_name =
                DevConfBypassHashTableGetName(re->bypass_table_base.name, spawned_lcores);
        struct rte_table_hash *t;
        t = BypassHashTableInit(table_name, re->bypass_table_base.entries);
        if (t == NULL) {
            rte_free(lcore_state);
            return -rte_errno;
        }

        ctx.lcores_state.lcores_arr[ctx.lcores_state.lcores_arr_len].state = lcore_state;
        ctx.lcores_state.lcores_arr[ctx.lcores_state.lcores_arr_len].bypass_table = t;
        ctx.lcores_state.lcores_arr_len++;

        LcoreManagerAssignRingsToLcore(val, rings_per_lcore, &next_ring, &leftover_rings);
        val->re = re;
        val->lcore_id = spawned_lcores;
        val->stats = stats;
        val->state = lcore_state;
        val->bypass_table = t;

        if (*last_lcore_id != rte_get_main_lcore()) {
            Log().debug("Launching lcore id %d", val->lcore_id);
            rte_eal_remote_launch(ThreadMain, (void *)val, *last_lcore_id);
        } else {
            Log().debug("Main lcore id %d will try to join the workers", val->lcore_id);
            LcoreMainAsWorker = val;
        }
    }

    return 0;
}

int LcoreManagerRunWorkers(struct pf_stats *stats)
{
    int retval;
    int32_t last_lcore_id = -1; // -1 to get the first
    struct ring_list_entry *re;
    uint8_t is_last_re = 0; // flag to check if the entry is the very last in the list

    TAILQ_FOREACH (re, &tailq_ring_head, entries) {
        if (is_last_re == 1) {
            // this means this is not the last entry == not enough lcores are configured
            Log().error(EINVAL, "Trying to spawn more workers than detected");
            StopWorkers();
            return retval;
        }

        Log().info("Spawning workers for %s", re->main_ring.name_base);
        retval = LcoreManagerRunWorker(re, &last_lcore_id, stats);
        if (retval != 0) {
            Log().error(EINVAL, "Not able to spawn all workers, halting!");
            rte_delay_us_sleep(100000); // wait for thread sync
            StopWorkers();
            return retval;
        }

        if (LcoreMainAsWorker != NULL) {
            // if this is the last entry and only 1 worker is missing, the main can work
            is_last_re = 1;
        }

        if (ctx.lcores_state.lcores_arr_len > ctx.lcores_state.lcores_arr_capa) {
            Log().error(EINVAL, "Trying to spawn more workers than detected");
            return -EINVAL;
        }
    }

    if (ctx.lcores_state.lcores_arr_len != ctx.lcores_state.lcores_arr_capa) {
        Log().error(EINVAL, "Number of spawned workers is not as calculated!");
        StopWorkers();
        return -EINVAL;
    }

    if (is_last_re == 1) {
        Log().info("Main lcore joins workers");
    }

    return 0;
}