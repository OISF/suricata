/* Copyright (C) 2014 Open Information Security Foundation
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
 * \author Tom DeCanio <td@npulsetech.com>
 */

#ifndef __OUTPUT_JSON_COUNTERS_H__
#define __OUTPUT_JSON_COUNTERS_H__

#include "output-stats.h"

#define JSON_STATS_TOTALS  (1<<0)
#define JSON_STATS_THREADS (1<<1)
#define JSON_STATS_DELTAS  (1<<2)

#ifdef HAVE_LIBJANSSON
json_t *StatsToJSON(const StatsTable *st, uint8_t flags);
#endif
void JsonStatsLogRegister(void);

#endif /* __OUTPUT_JSON_COUNTERS_H__ */
