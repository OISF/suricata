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

#include <rte_malloc.h>
#include "stats.h"
#include "logger.h"

int PFStatsInit(struct pf_stats **s)
{
    *s = (struct pf_stats *)rte_calloc("struct pf_stats", sizeof(struct pf_stats), 1, 0);
    if (*s == NULL) {
        Log().error(ENOMEM, "Memory allocation failed for prefilter stats");
        return -ENOMEM;
    }

    rte_atomic64_init(&(*s)->p1_rx);
    rte_atomic64_init(&(*s)->p2_rx);
    rte_atomic64_init(&(*s)->p1_tx);
    rte_atomic64_init(&(*s)->p2_tx);
    rte_atomic64_init(&(*s)->pkts_enqueue_tries);
    rte_atomic64_init(&(*s)->pkts_enqueues);
    rte_atomic64_init(&(*s)->pkts_dequeues);
    rte_atomic64_init(&(*s)->pkts_inspects);
    rte_atomic64_init(&(*s)->pkts_bypasses);
    rte_atomic64_init(&(*s)->msgs_rx);
    rte_atomic64_init(&(*s)->msgs_tx);
    rte_atomic64_init(&(*s)->flow_bypasses);
    rte_atomic64_init(&(*s)->flow_bypass_dels);
    rte_atomic64_init(&(*s)->flow_bypass_updates);
    rte_atomic64_init(&(*s)->msgs_mp_puts);

    return 0;
}

void PFStatsExitLog(struct pf_stats *s)
{
    Log().notice("APP PORT1 rx: %lu tx: %lu", rte_atomic64_read(&s->p1_rx),
            rte_atomic64_read(&s->p1_tx));
    Log().notice("APP PORT2 rx: %lu tx: %lu", rte_atomic64_read(&s->p2_rx),
            rte_atomic64_read(&s->p2_tx));

    Log().notice("APP PKTS: rx: %lu, "
                 "inspected %lu, bypassed %lu, "
                 "enqueue attempts %lu "
                 "enqueued to Suricata %lu dequeued from Suricata %lu "
                 "transmit attempts %lu "
                 "transmits %lu",
            rte_atomic64_read(&s->p1_rx) + rte_atomic64_read(&s->p2_rx),
            rte_atomic64_read(&s->pkts_inspects), rte_atomic64_read(&s->pkts_bypasses),
            rte_atomic64_read(&s->pkts_enqueue_tries), rte_atomic64_read(&s->pkts_enqueues),
            rte_atomic64_read(&s->pkts_dequeues),
            rte_atomic64_read(&s->p1_tx) + rte_atomic64_read(&s->p2_tx),
            rte_atomic64_read(&s->p1_tx_all) + rte_atomic64_read(&s->p2_tx_all));

    Log().notice("APP MSGS: received %lu sent %lu mempool putbacks %lu",
            rte_atomic64_read(&s->msgs_rx), rte_atomic64_read(&s->msgs_tx),
            rte_atomic64_read(&s->msgs_mp_puts));

    Log().notice("BYPASS: adds %lu updates %lu deletes %lu", rte_atomic64_read(&s->flow_bypasses),
            rte_atomic64_read(&s->flow_bypass_updates), rte_atomic64_read(&s->flow_bypass_dels));
}

void PFStatsDeinit(struct pf_stats *s)
{
    if (s != NULL)
        rte_free(s);
}