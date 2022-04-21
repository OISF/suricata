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

#include "lcore-worker.h"
#include "dev-conf.h"
#include "lcores-manager.h"
#include "lcore-worker-suricata.h"

#include <rte_atomic.h>

int ThreadMain(void *init_values)
{
    struct lcore_values *lv;

    lv = ThreadSuricataInit(init_values);
    if (lv == NULL)
        return -EINVAL;

    ThreadSuricataRun(lv);
    ThreadSuricataExitStats(lv);

    struct lcore_init *vals = (struct lcore_init *)init_values;

    rte_atomic64_add(&vals->stats->pkts_rx, lv->stats.pkts_rx);
    rte_atomic64_add(&vals->stats->pkts_tx, lv->stats.pkts_tx);
    rte_atomic64_add(&vals->stats->pkts_enq, lv->stats.pkts_enq);
    rte_atomic64_add(&vals->stats->pkts_deq, lv->stats.pkts_deq);

    // clean lcore_values and lcore_init
    ThreadSuricataDeinit(vals, lv);

    return 0;
}
