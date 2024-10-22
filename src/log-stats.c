/* Copyright (C) 2014-2024 Open Information Security Foundation
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
 */

#include "suricata-common.h"
#include "detect.h"
#include "pkt-var.h"
#include "conf.h"

#include "threads.h"
#include "threadvars.h"
#include "tm-threads.h"

#include "util-print.h"
#include "util-unittest.h"

#include "util-debug.h"

#include "output.h"
#include "log-stats.h"
#include "util-privs.h"
#include "util-buffer.h"

#include "util-logopenfile.h"
#include "util-time.h"

#define DEFAULT_LOG_FILENAME "stats.log"
#define MODULE_NAME "LogStatsLog"
#define OUTPUT_BUFFER_SIZE 16384

#define LOG_STATS_TOTALS  (1<<0)
#define LOG_STATS_THREADS (1<<1)
#define LOG_STATS_NULLS   (1<<2)

TmEcode LogStatsLogThreadInit(ThreadVars *, const void *, void **);
TmEcode LogStatsLogThreadDeinit(ThreadVars *, void *);
static void LogStatsLogDeInitCtx(OutputCtx *);

typedef struct LogStatsFileCtx_ {
    LogFileCtx *file_ctx;
    uint32_t flags; /** Store mode */
} LogStatsFileCtx;

typedef struct LogStatsLogThread_ {
    LogStatsFileCtx *statslog_ctx;
    MemBuffer *buffer;
} LogStatsLogThread;

static int LogStatsLogger(ThreadVars *tv, void *thread_data, const StatsTable *st)
{
    SCEnter();
    LogStatsLogThread *aft = (LogStatsLogThread *)thread_data;

    struct timeval tval;
    struct tm *tms;

    gettimeofday(&tval, NULL);
    struct tm local_tm;
    tms = SCLocalTime(tval.tv_sec, &local_tm);

    /* Calculate the Engine uptime */
    double up_time_d = difftime(tval.tv_sec, st->start_time);
    int up_time = (int)up_time_d; // ignoring risk of overflow here
    int sec = up_time % 60;     // Seconds in a minute
    int in_min = up_time / 60;
    int min = in_min % 60;      // Minutes in a hour
    int in_hours = in_min / 60;
    int hours = in_hours % 24;  // Hours in a day
    int days = in_hours / 24;

    MemBufferWriteString(aft->buffer, "----------------------------------------------"
                                      "-----------------------------------------------------\n");
    MemBufferWriteString(aft->buffer, "Date: %" PRId32 "/%" PRId32 "/%04d -- "
            "%02d:%02d:%02d (uptime: %"PRId32"d, %02dh %02dm %02ds)\n",
            tms->tm_mon + 1, tms->tm_mday, tms->tm_year + 1900, tms->tm_hour,
            tms->tm_min, tms->tm_sec, days, hours, min, sec);
    MemBufferWriteString(aft->buffer, "----------------------------------------------"
                                      "-----------------------------------------------------\n");
    MemBufferWriteString(aft->buffer, "%-60s | %-25s | %-s\n", "Counter", "TM Name", "Value");
    MemBufferWriteString(aft->buffer, "----------------------------------------------"
                                      "-----------------------------------------------------\n");

    /* global stats */
    uint32_t u = 0;
    if (aft->statslog_ctx->flags & LOG_STATS_TOTALS) {
        for (u = 0; u < st->nstats; u++) {
            if (st->stats[u].name == NULL)
                continue;

            if (!(aft->statslog_ctx->flags & LOG_STATS_NULLS) && st->stats[u].value == 0)
                continue;

            char line[256];
            size_t len = snprintf(line, sizeof(line), "%-60s | %-25s | %-" PRIu64 "\n",
                    st->stats[u].name, st->stats[u].tm_name, st->stats[u].value);

            /* since we can have many threads, the buffer might not be big enough.
             * Expand if necessary. */
            if (MEMBUFFER_OFFSET(aft->buffer) + len >= MEMBUFFER_SIZE(aft->buffer)) {
                MemBufferExpand(&aft->buffer, OUTPUT_BUFFER_SIZE);
            }

            MemBufferWriteString(aft->buffer, "%s", line);
        }
    }

    /* per thread stats */
    if (st->tstats != NULL && aft->statslog_ctx->flags & LOG_STATS_THREADS) {
        /* for each thread (store) */
        uint32_t x;
        for (x = 0; x < st->ntstats; x++) {
            uint32_t offset = x * st->nstats;

            /* for each counter */
            for (u = offset; u < (offset + st->nstats); u++) {
                if (st->tstats[u].name == NULL)
                    continue;

                if (!(aft->statslog_ctx->flags & LOG_STATS_NULLS) && st->tstats[u].value == 0)
                    continue;

                char line[256];
                size_t len = snprintf(line, sizeof(line), "%-45s | %-25s | %-" PRIi64 "\n",
                        st->tstats[u].name, st->tstats[u].tm_name, st->tstats[u].value);

                /* since we can have many threads, the buffer might not be big enough.
                 * Expand if necessary. */
                if (MEMBUFFER_OFFSET(aft->buffer) + len >= MEMBUFFER_SIZE(aft->buffer)) {
                    MemBufferExpand(&aft->buffer, OUTPUT_BUFFER_SIZE);
                }

                MemBufferWriteString(aft->buffer, "%s", line);
            }
        }
    }

    aft->statslog_ctx->file_ctx->Write((const char *)MEMBUFFER_BUFFER(aft->buffer),
        MEMBUFFER_OFFSET(aft->buffer), aft->statslog_ctx->file_ctx);

    MemBufferReset(aft->buffer);

    SCReturnInt(0);
}

TmEcode LogStatsLogThreadInit(ThreadVars *t, const void *initdata, void **data)
{
    LogStatsLogThread *aft = SCMalloc(sizeof(LogStatsLogThread));
    if (unlikely(aft == NULL))
        return TM_ECODE_FAILED;
    memset(aft, 0, sizeof(LogStatsLogThread));

    if(initdata == NULL)
    {
        SCLogDebug("Error getting context for LogStats.  \"initdata\" argument NULL");
        SCFree(aft);
        return TM_ECODE_FAILED;
    }

    aft->buffer = MemBufferCreateNew(OUTPUT_BUFFER_SIZE);
    if (aft->buffer == NULL) {
        SCFree(aft);
        return TM_ECODE_FAILED;
    }

    /* Use the Output Context (file pointer and mutex) */
    aft->statslog_ctx= ((OutputCtx *)initdata)->data;

    *data = (void *)aft;
    return TM_ECODE_OK;
}

TmEcode LogStatsLogThreadDeinit(ThreadVars *t, void *data)
{
    LogStatsLogThread *aft = (LogStatsLogThread *)data;
    if (aft == NULL) {
        return TM_ECODE_OK;
    }

    MemBufferFree(aft->buffer);
    /* clear memory */
    memset(aft, 0, sizeof(LogStatsLogThread));

    SCFree(aft);
    return TM_ECODE_OK;
}

/** \brief Create a new http log LogFileCtx.
 *  \param conf Pointer to ConfNode containing this loggers configuration.
 *  \return NULL if failure, LogFileCtx* to the file_ctx if successful
 * */
static OutputInitResult LogStatsLogInitCtx(ConfNode *conf)
{
    OutputInitResult result = { NULL, false };
    LogFileCtx *file_ctx = LogFileNewCtx();
    if (file_ctx == NULL) {
        SCLogError("couldn't create new file_ctx");
        return result;
    }

    if (SCConfLogOpenGeneric(conf, file_ctx, DEFAULT_LOG_FILENAME, 1) < 0) {
        LogFileFreeCtx(file_ctx);
        return result;
    }

    LogStatsFileCtx *statslog_ctx = SCMalloc(sizeof(LogStatsFileCtx));
    if (unlikely(statslog_ctx == NULL)) {
        LogFileFreeCtx(file_ctx);
        return result;
    }
    memset(statslog_ctx, 0x00, sizeof(LogStatsFileCtx));

    statslog_ctx->flags = LOG_STATS_TOTALS;

    if (conf != NULL) {
        const char *totals = ConfNodeLookupChildValue(conf, "totals");
        const char *threads = ConfNodeLookupChildValue(conf, "threads");
        const char *nulls = ConfNodeLookupChildValue(conf, "null-values");
        SCLogDebug("totals %s threads %s", totals, threads);

        if ((totals != NULL && ConfValIsFalse(totals)) &&
                (threads != NULL && ConfValIsFalse(threads))) {
            LogFileFreeCtx(file_ctx);
            SCFree(statslog_ctx);
            SCLogError("Cannot disable both totals and threads in stats logging");
            return result;
        }

        if (totals != NULL && ConfValIsFalse(totals)) {
            statslog_ctx->flags &= ~LOG_STATS_TOTALS;
        }
        if (threads != NULL && ConfValIsTrue(threads)) {
            statslog_ctx->flags |= LOG_STATS_THREADS;
        }
        if (nulls != NULL && ConfValIsTrue(nulls)) {
            statslog_ctx->flags |= LOG_STATS_NULLS;
        }
        SCLogDebug("statslog_ctx->flags %08x", statslog_ctx->flags);
    }

    statslog_ctx->file_ctx = file_ctx;

    OutputCtx *output_ctx = SCCalloc(1, sizeof(OutputCtx));
    if (unlikely(output_ctx == NULL)) {
        LogFileFreeCtx(file_ctx);
        SCFree(statslog_ctx);
        return result;
    }

    output_ctx->data = statslog_ctx;
    output_ctx->DeInit = LogStatsLogDeInitCtx;

    SCLogDebug("STATS log output initialized");

    result.ctx = output_ctx;
    result.ok = true;
    return result;
}

static void LogStatsLogDeInitCtx(OutputCtx *output_ctx)
{
    LogStatsFileCtx *statslog_ctx = (LogStatsFileCtx *)output_ctx->data;
    LogFileFreeCtx(statslog_ctx->file_ctx);
    SCFree(statslog_ctx);
    SCFree(output_ctx);
}

void LogStatsLogRegister (void)
{
    OutputRegisterStatsModule(LOGGER_STATS, MODULE_NAME, "stats",
        LogStatsLogInitCtx, LogStatsLogger, LogStatsLogThreadInit,
        LogStatsLogThreadDeinit, NULL);
}
