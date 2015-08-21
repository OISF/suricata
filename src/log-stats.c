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
 * \author Victor Julien <victor@inliniac.net>
 *
 */

#include "suricata-common.h"
#include "debug.h"
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

TmEcode LogStatsLogThreadInit(ThreadVars *, void *, void **);
TmEcode LogStatsLogThreadDeinit(ThreadVars *, void *);
void LogStatsLogExitPrintStats(ThreadVars *, void *);
static void LogStatsLogDeInitCtx(OutputCtx *);

typedef struct LogStatsFileCtx_ {
    LogFileCtx *file_ctx;
    uint32_t flags; /** Store mode */
} LogStatsFileCtx;

typedef struct LogStatsLogThread_ {
    LogStatsFileCtx *statslog_ctx;
    MemBuffer *buffer;
} LogStatsLogThread;

int LogStatsLogger(ThreadVars *tv, void *thread_data, const StatsTable *st)
{
    SCEnter();
    LogStatsLogThread *aft = (LogStatsLogThread *)thread_data;

    struct timeval tval;
    struct tm *tms;

    gettimeofday(&tval, NULL);
    struct tm local_tm;
    tms = SCLocalTime(tval.tv_sec, &local_tm);

    /* Calculate the Engine uptime */
    int up_time = (int)difftime(tval.tv_sec, st->start_time);
    int sec = up_time % 60;     // Seconds in a minute
    int in_min = up_time / 60;
    int min = in_min % 60;      // Minutes in a hour
    int in_hours = in_min / 60;
    int hours = in_hours % 24;  // Hours in a day
    int days = in_hours / 24;

    MemBufferWriteString(aft->buffer, "----------------------------------------------"
            "---------------------\n");
    MemBufferWriteString(aft->buffer, "Date: %" PRId32 "/%" PRId32 "/%04d -- "
            "%02d:%02d:%02d (uptime: %"PRId32"d, %02dh %02dm %02ds)\n",
            tms->tm_mon + 1, tms->tm_mday, tms->tm_year + 1900, tms->tm_hour,
            tms->tm_min, tms->tm_sec, days, hours, min, sec);
    MemBufferWriteString(aft->buffer, "----------------------------------------------"
            "---------------------\n");
    MemBufferWriteString(aft->buffer, "%-25s | %-25s | %-s\n", "Counter", "TM Name",
            "Value");
    MemBufferWriteString(aft->buffer, "----------------------------------------------"
            "---------------------\n");

    /* global stats */
    uint32_t u = 0;
    if (aft->statslog_ctx->flags & LOG_STATS_TOTALS) {
        for (u = 0; u < st->nstats; u++) {
            if (st->stats[u].name == NULL)
                continue;

            char line[1024];
            size_t len = snprintf(line, sizeof(line), "%-25s | %-25s | %-" PRIu64 "\n",
                    st->stats[u].name, st->stats[u].tm_name, st->stats[u].value);

            /* since we can have many threads, the buffer might not be big enough.
             * Expand if necessary. */
            if (MEMBUFFER_OFFSET(aft->buffer) + len > MEMBUFFER_SIZE(aft->buffer)) {
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

                char line[1024];
                size_t len = snprintf(line, sizeof(line), "%-25s | %-25s | %-" PRIu64 "\n",
                        st->tstats[u].name, st->tstats[u].tm_name, st->tstats[u].value);

                /* since we can have many threads, the buffer might not be big enough.
                 * Expand if necessary. */
                if (MEMBUFFER_OFFSET(aft->buffer) + len > MEMBUFFER_SIZE(aft->buffer)) {
                    MemBufferExpand(&aft->buffer, OUTPUT_BUFFER_SIZE);
                }

                MemBufferWriteString(aft->buffer, "%s", line);
            }
        }
    }

    SCMutexLock(&aft->statslog_ctx->file_ctx->fp_mutex);
    aft->statslog_ctx->file_ctx->Write((const char *)MEMBUFFER_BUFFER(aft->buffer),
        MEMBUFFER_OFFSET(aft->buffer), aft->statslog_ctx->file_ctx);
    SCMutexUnlock(&aft->statslog_ctx->file_ctx->fp_mutex);

    MemBufferReset(aft->buffer);

    SCReturnInt(0);
}

TmEcode LogStatsLogThreadInit(ThreadVars *t, void *initdata, void **data)
{
    LogStatsLogThread *aft = SCMalloc(sizeof(LogStatsLogThread));
    if (unlikely(aft == NULL))
        return TM_ECODE_FAILED;
    memset(aft, 0, sizeof(LogStatsLogThread));

    if(initdata == NULL)
    {
        SCLogDebug("Error getting context for HTTPLog.  \"initdata\" argument NULL");
        SCFree(aft);
        return TM_ECODE_FAILED;
    }

    aft->buffer = MemBufferCreateNew(OUTPUT_BUFFER_SIZE);
    if (aft->buffer == NULL) {
        SCFree(aft);
        return TM_ECODE_FAILED;
    }

    /* Use the Ouptut Context (file pointer and mutex) */
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

void LogStatsLogExitPrintStats(ThreadVars *tv, void *data)
{
    LogStatsLogThread *aft = (LogStatsLogThread *)data;
    if (aft == NULL) {
        return;
    }
}

/** \brief Create a new http log LogFileCtx.
 *  \param conf Pointer to ConfNode containing this loggers configuration.
 *  \return NULL if failure, LogFileCtx* to the file_ctx if succesful
 * */
OutputCtx *LogStatsLogInitCtx(ConfNode *conf)
{
    LogFileCtx *file_ctx = LogFileNewCtx();
    if (file_ctx == NULL) {
        SCLogError(SC_ERR_HTTP_LOG_GENERIC, "couldn't create new file_ctx");
        return NULL;
    }

    if (SCConfLogOpenGeneric(conf, file_ctx, DEFAULT_LOG_FILENAME, 1) < 0) {
        LogFileFreeCtx(file_ctx);
        return NULL;
    }

    LogStatsFileCtx *statslog_ctx = SCMalloc(sizeof(LogStatsFileCtx));
    if (unlikely(statslog_ctx == NULL)) {
        LogFileFreeCtx(file_ctx);
        return NULL;
    }
    memset(statslog_ctx, 0x00, sizeof(LogStatsFileCtx));

    statslog_ctx->flags = LOG_STATS_TOTALS;

    if (conf != NULL) {
        const char *totals = ConfNodeLookupChildValue(conf, "totals");
        const char *threads = ConfNodeLookupChildValue(conf, "threads");
        SCLogDebug("totals %s threads %s", totals, threads);

        if (totals != NULL && ConfValIsFalse(totals)) {
            statslog_ctx->flags &= ~LOG_STATS_TOTALS;
        }
        if (threads != NULL && ConfValIsTrue(threads)) {
            statslog_ctx->flags |= LOG_STATS_THREADS;
        }
        SCLogDebug("statslog_ctx->flags %08x", statslog_ctx->flags);
    }

    statslog_ctx->file_ctx = file_ctx;

    OutputCtx *output_ctx = SCCalloc(1, sizeof(OutputCtx));
    if (unlikely(output_ctx == NULL)) {
        LogFileFreeCtx(file_ctx);
        SCFree(statslog_ctx);
        return NULL;
    }

    output_ctx->data = statslog_ctx;
    output_ctx->DeInit = LogStatsLogDeInitCtx;

    SCLogDebug("STATS log output initialized");

    return output_ctx;
}

static void LogStatsLogDeInitCtx(OutputCtx *output_ctx)
{
    LogStatsFileCtx *statslog_ctx = (LogStatsFileCtx *)output_ctx->data;
    LogFileFreeCtx(statslog_ctx->file_ctx);
    SCFree(statslog_ctx);
    SCFree(output_ctx);
}

void TmModuleLogStatsLogRegister (void)
{
    tmm_modules[TMM_LOGSTATSLOG].name = MODULE_NAME;
    tmm_modules[TMM_LOGSTATSLOG].ThreadInit = LogStatsLogThreadInit;
    tmm_modules[TMM_LOGSTATSLOG].ThreadExitPrintStats = LogStatsLogExitPrintStats;
    tmm_modules[TMM_LOGSTATSLOG].ThreadDeinit = LogStatsLogThreadDeinit;
    tmm_modules[TMM_LOGSTATSLOG].RegisterTests = NULL;
    tmm_modules[TMM_LOGSTATSLOG].cap_flags = 0;
    tmm_modules[TMM_LOGSTATSLOG].flags = TM_FLAG_LOGAPI_TM;

    OutputRegisterStatsModule(MODULE_NAME, "stats", LogStatsLogInitCtx, LogStatsLogger);
}
