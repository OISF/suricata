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

int ThreadMain(void *init_values)
{
    struct lcore_values *lv;

    lv = ThreadSuricataInit(init_values);
    if (lv == NULL)
        return -EINVAL;

    if (rte_lcore_id() == rte_get_main_lcore()) {
        for (uint16_t i = 0; i < ctx.lcores_state.lcores_arr_len; i++) {
            LcoreStateSet(ctx.lcores_state.lcores_arr[i].state, LCORE_RUN);
        }
    }

    ThreadSuricataRun(lv);
    ThreadSuricataExitStats(lv);

    struct lcore_init *vals = (struct lcore_init *)init_values;

    rte_atomic64_add(&vals->stats->p1_rx, (int64_t)lv->stats.pkts_p1_rx);
    rte_atomic64_add(&vals->stats->p1_tx, (int64_t)lv->stats.pkts_p1_tx_success);
    rte_atomic64_add(&vals->stats->p1_tx_all, (int64_t)lv->stats.pkts_p1_tx_total);
    rte_atomic64_add(&vals->stats->p2_rx, (int64_t)lv->stats.pkts_p2_rx);
    rte_atomic64_add(&vals->stats->p2_tx, (int64_t)lv->stats.pkts_p2_tx_success);
    rte_atomic64_add(&vals->stats->p2_tx_all, (int64_t)lv->stats.pkts_p2_tx_total);

    uint64_t enq_total, enq_success, deq_success = enq_total = enq_success = 0;
    for (uint16_t i = 0; i < (uint16_t)MIN(lv->rings_cnt, MAX_WORKERS_TO_PREFILTER_LCORE); i++) {
        enq_total += lv->stats.pkts_to_ring_enq_total[i];
        enq_success += lv->stats.pkts_to_ring_enq_success[i];
        deq_success += lv->stats.pkts_from_ring_deq_success[i];
    }
    rte_atomic64_add(&vals->stats->pkts_enqueue_tries, (int64_t)enq_total);
    rte_atomic64_add(&vals->stats->pkts_enqueues, (int64_t)enq_success);
    rte_atomic64_add(&vals->stats->pkts_dequeues, (int64_t)deq_success);

    rte_atomic64_add(&vals->stats->pkts_inspects, (int64_t)lv->stats.pkts_inspected);
    rte_atomic64_add(&vals->stats->pkts_bypasses, (int64_t)lv->stats.pkts_bypassed);

    rte_atomic64_add(&vals->stats->msgs_rx, (int64_t)lv->stats.msgs_deq);
    uint64_t msgs_enq_total = 0;
    for (uint16_t i = 0; i < (uint16_t)PF_MESSAGE_CNT; i++) {
        msgs_enq_total += lv->stats.msgs_type_tx[i];
    }
    rte_atomic64_add(&vals->stats->msgs_tx, (int64_t)msgs_enq_total);

    rte_atomic64_add(&vals->stats->flow_bypasses, (int64_t)lv->stats.flow_bypass_success);
    rte_atomic64_add(&vals->stats->flow_bypass_updates, (int64_t)lv->stats.flow_bypass_update);
    rte_atomic64_add(&vals->stats->flow_bypass_dels, (int64_t)lv->stats.flow_bypass_del_success);
    rte_atomic64_add(&vals->stats->msgs_tx_fail, (int64_t)lv->stats.msgs_enq_fail);
    rte_atomic64_add(&vals->stats->msgs_mp_puts, (int64_t)lv->stats.msgs_mempool_put);

    Log().info("Lcore %s:%d shutting down", vals->re->main_ring.name_base, lv->qid);
    // clean lcore_values and lcore_init
    ThreadSuricataDeinit(vals, lv);

    return 0;
}
