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
 * Stats Logger Output registration functions
 */

#include "suricata-common.h"
#include "tm-modules.h"
#include "output-stats.h"
#include "util-validate.h"

typedef struct OutputLoggerThreadStore_ {
    void *thread_data;
    struct OutputLoggerThreadStore_ *next;
} OutputLoggerThreadStore;

/** per thread data for this module, contains a list of per thread
 *  data for the packet loggers. */
typedef struct OutputLoggerThreadData_ {
    OutputLoggerThreadStore *store;
} OutputLoggerThreadData;

/* logger instance, a module + a output ctx,
 * it's perfectly valid that have multiple instances of the same
 * log module (e.g. http.log) with different output ctx'. */
typedef struct OutputStatsLogger_ {
    StatsLogger LogFunc;
    OutputCtx *output_ctx;
    struct OutputStatsLogger_ *next;
    const char *name;
    ThreadInitFunc ThreadInit;
    ThreadDeinitFunc ThreadDeinit;
    ThreadExitPrintStatsFunc ThreadExitPrintStats;
} OutputStatsLogger;

static OutputStatsLogger *list = NULL;

int OutputRegisterStatsLogger(const char *name, StatsLogger LogFunc,
    OutputCtx *output_ctx, ThreadInitFunc ThreadInit,
    ThreadDeinitFunc ThreadDeinit,
    ThreadExitPrintStatsFunc ThreadExitPrintStats)
{
    OutputStatsLogger *op = SCMalloc(sizeof(*op));
    if (op == NULL)
        return -1;
    memset(op, 0x00, sizeof(*op));

    op->LogFunc = LogFunc;
    op->output_ctx = output_ctx;
    op->name = name;
    op->ThreadInit = ThreadInit;
    op->ThreadDeinit = ThreadDeinit;
    op->ThreadExitPrintStats = ThreadExitPrintStats;

    if (list == NULL)
        list = op;
    else {
        OutputStatsLogger *t = list;
        while (t->next)
            t = t->next;
        t->next = op;
    }

    SCLogDebug("OutputRegisterStatsLogger happy");
    return 0;
}

TmEcode OutputStatsLog(ThreadVars *tv, void *thread_data, StatsTable *st)
{
    DEBUG_VALIDATE_BUG_ON(thread_data == NULL);
    DEBUG_VALIDATE_BUG_ON(list == NULL);

    OutputLoggerThreadData *op_thread_data = (OutputLoggerThreadData *)thread_data;
    OutputStatsLogger *logger = list;
    OutputLoggerThreadStore *store = op_thread_data->store;

    DEBUG_VALIDATE_BUG_ON(logger == NULL && store != NULL);
    DEBUG_VALIDATE_BUG_ON(logger != NULL && store == NULL);
    DEBUG_VALIDATE_BUG_ON(logger == NULL && store == NULL);

    while (logger && store) {
        DEBUG_VALIDATE_BUG_ON(logger->LogFunc == NULL);

        logger->LogFunc(tv, store->thread_data, st);

        logger = logger->next;
        store = store->next;

        DEBUG_VALIDATE_BUG_ON(logger == NULL && store != NULL);
        DEBUG_VALIDATE_BUG_ON(logger != NULL && store == NULL);
    }

    return TM_ECODE_OK;
}

/** \brief thread init for the tx logger
 *  This will run the thread init functions for the individual registered
 *  loggers */
static TmEcode OutputStatsLogThreadInit(ThreadVars *tv, const void *initdata, void **data)
{
    OutputLoggerThreadData *td = SCMalloc(sizeof(*td));
    if (td == NULL)
        return TM_ECODE_FAILED;
    memset(td, 0x00, sizeof(*td));

    *data = (void *)td;

    SCLogDebug("OutputStatsLogThreadInit happy (*data %p)", *data);

    OutputStatsLogger *logger = list;
    while (logger) {
        if (logger->ThreadInit) {
            void *retptr = NULL;
            if (logger->ThreadInit(tv, (void *)logger->output_ctx, &retptr) == TM_ECODE_OK) {
                OutputLoggerThreadStore *ts = SCMalloc(sizeof(*ts));
/* todo */      BUG_ON(ts == NULL);
                memset(ts, 0x00, sizeof(*ts));

                /* store thread handle */
                ts->thread_data = retptr;

                if (td->store == NULL) {
                    td->store = ts;
                } else {
                    OutputLoggerThreadStore *tmp = td->store;
                    while (tmp->next != NULL)
                        tmp = tmp->next;
                    tmp->next = ts;
                }

                SCLogDebug("%s is now set up", logger->name);
            }
        }

        logger = logger->next;
    }

    SCLogDebug("OutputStatsLogThreadInit happy (*data %p)", *data);
    return TM_ECODE_OK;
}

static TmEcode OutputStatsLogThreadDeinit(ThreadVars *tv, void *thread_data)
{
    OutputLoggerThreadData *op_thread_data = (OutputLoggerThreadData *)thread_data;
    OutputLoggerThreadStore *store = op_thread_data->store;
    OutputStatsLogger *logger = list;

    while (logger && store) {
        if (logger->ThreadDeinit) {
            logger->ThreadDeinit(tv, store->thread_data);
        }
        OutputLoggerThreadStore *next_store = store->next;
        SCFree(store);
        store = next_store;
        logger = logger->next;
    }

    SCFree(op_thread_data);
    return TM_ECODE_OK;
}

static void OutputStatsLogExitPrintStats(ThreadVars *tv, void *thread_data)
{
    OutputLoggerThreadData *op_thread_data = (OutputLoggerThreadData *)thread_data;
    OutputLoggerThreadStore *store = op_thread_data->store;
    OutputStatsLogger *logger = list;

    while (logger && store) {
        if (logger->ThreadExitPrintStats) {
            logger->ThreadExitPrintStats(tv, store->thread_data);
        }

        logger = logger->next;
        store = store->next;
    }
}

void TmModuleStatsLoggerRegister (void)
{
    tmm_modules[TMM_STATSLOGGER].name = "__stats_logger__";
    tmm_modules[TMM_STATSLOGGER].ThreadInit = OutputStatsLogThreadInit;
    tmm_modules[TMM_STATSLOGGER].ThreadExitPrintStats = OutputStatsLogExitPrintStats;
    tmm_modules[TMM_STATSLOGGER].ThreadDeinit = OutputStatsLogThreadDeinit;
    tmm_modules[TMM_STATSLOGGER].cap_flags = 0;
}

int OutputStatsLoggersRegistered(void)
{
    if (list != NULL)
        return 1;
    return 0;
}

void OutputStatsShutdown(void)
{
    OutputStatsLogger *logger = list;
    while (logger) {
        OutputStatsLogger *next_logger = logger->next;
        SCFree(logger);
        logger = next_logger;
    }
    list = NULL;
}
