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

    rte_atomic64_init(&(*s)->pkts_rx);
    rte_atomic64_init(&(*s)->pkts_tx);
    rte_atomic64_init(&(*s)->pkts_enq);
    rte_atomic64_init(&(*s)->pkts_deq);

    return 0;
}

void PFStatsExitLog(struct pf_stats *s)
{
    Log().notice("Packets received: %lu", rte_atomic64_read(&s->pkts_rx));
    Log().notice("Packets enqueued: %lu", rte_atomic64_read(&s->pkts_enq));
    Log().notice("Packets dequeued: %lu", rte_atomic64_read(&s->pkts_deq));
    Log().notice("Packets transmitted: %lu", rte_atomic64_read(&s->pkts_tx));
}

void PFStatsDeinit(struct pf_stats *s)
{
    if (s != NULL)
        rte_free(s);
}