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

#ifndef LCORE_WORKER_SURICATA_H
#define LCORE_WORKER_SURICATA_H

#include "dev-conf.h"
#include "lcore-worker.h"
#include "lcores-manager.h"

struct lcore_values *ThreadSuricataInit(struct lcore_init *init_vals);
void ThreadSuricataRun(struct lcore_values *lv);
void ThreadSuricataStatsDump(struct lcore_values *lv);
void ThreadSuricataStatsExit(struct lcore_values *lv, struct pf_stats *stats);
void ThreadSuricataDeinit(struct lcore_init *vals, struct lcore_values *lv);

#endif // LCORE_WORKER_SURICATA_H
