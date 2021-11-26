/* Copyright (C) 2007-2013 Open Information Security Foundation
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
 * \author Victor Julien <victor@inliniac.net>
 *
 * Stats Logger Output registration functions
 */

#ifndef __OUTPUT_STATS_H__
#define __OUTPUT_STATS_H__

typedef struct StatsRecord_ {
    const char *name;
    const char *tm_name;
    int64_t value;  /**< total value */
    int64_t pvalue; /**< prev value (may be higher for memuse counters) */
} StatsRecord;

typedef struct StatsTable_ {
    StatsRecord *stats;     /**< array of global stats, indexed by counters gid */
    StatsRecord *tstats;    /**< array of arrays with per thread stats */
    uint32_t nstats;        /**< size in records of 'stats' */
    uint32_t ntstats;       /**< number of threads for which tstats stores stats */
    time_t start_time;
    struct timeval ts;
} StatsTable;

TmEcode OutputStatsLog(ThreadVars *tv, void *thread_data, StatsTable *st);

typedef int (*StatsLogger)(ThreadVars *, void *thread_data, const StatsTable *);

int OutputRegisterStatsLogger(const char *name, StatsLogger LogFunc,
    OutputCtx *, ThreadInitFunc ThreadInit, ThreadDeinitFunc ThreadDeinit,
    ThreadExitPrintStatsFunc ThreadExitPrintStats);

void TmModuleStatsLoggerRegister (void);

int OutputStatsLoggersRegistered(void);

void OutputStatsShutdown(void);

#endif /* __OUTPUT_STATS_H__ */
