/* Copyright (C) 2007-2022 Open Information Security Foundation
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
 * Packet Logger Output registration functions
 */

#include "suricata-common.h"
#include "tm-modules.h"
#include "output.h"
#include "output-packet.h"
#include "util-profiling.h"
#include "util-validate.h"

/** per thread data for this module, contains a list of per thread
 *  data for the packet loggers. */
typedef struct OutputPacketLoggerThreadData_ {
    OutputLoggerThreadStore *store;
} OutputPacketLoggerThreadData;

/* logger instance, a module + a output ctx,
 * it's perfectly valid that have multiple instances of the same
 * log module (e.g. fast.log) with different output ctx'. */
typedef struct OutputPacketLogger_ {
    PacketLogger LogFunc;
    PacketLogCondition ConditionFunc;
    OutputCtx *output_ctx;
    struct OutputPacketLogger_ *next;
    const char *name;
    LoggerId logger_id;
    ThreadInitFunc ThreadInit;
    ThreadDeinitFunc ThreadDeinit;
    ThreadExitPrintStatsFunc ThreadExitPrintStats;
} OutputPacketLogger;

static OutputPacketLogger *list = NULL;

int OutputRegisterPacketLogger(LoggerId logger_id, const char *name,
    PacketLogger LogFunc, PacketLogCondition ConditionFunc,
    OutputCtx *output_ctx, ThreadInitFunc ThreadInit,
    ThreadDeinitFunc ThreadDeinit,
    ThreadExitPrintStatsFunc ThreadExitPrintStats)
{
    OutputPacketLogger *op = SCMalloc(sizeof(*op));
    if (op == NULL)
        return -1;
    memset(op, 0x00, sizeof(*op));

    op->LogFunc = LogFunc;
    op->ConditionFunc = ConditionFunc;
    op->output_ctx = output_ctx;
    op->name = name;
    op->ThreadInit = ThreadInit;
    op->ThreadDeinit = ThreadDeinit;
    op->ThreadExitPrintStats = ThreadExitPrintStats;
    op->logger_id = logger_id;

    if (list == NULL)
        list = op;
    else {
        OutputPacketLogger *t = list;
        while (t->next)
            t = t->next;
        t->next = op;
    }

    SCLogDebug("OutputRegisterPacketLogger happy");
    return 0;
}

static TmEcode OutputPacketLog(ThreadVars *tv, Packet *p, void *thread_data)
{
    DEBUG_VALIDATE_BUG_ON(thread_data == NULL);

    if (list == NULL) {
        /* No child loggers. */
        return TM_ECODE_OK;
    }

    OutputPacketLoggerThreadData *op_thread_data = (OutputPacketLoggerThreadData *)thread_data;
    OutputPacketLogger *logger = list;
    OutputLoggerThreadStore *store = op_thread_data->store;

    DEBUG_VALIDATE_BUG_ON(logger == NULL && store != NULL);
    DEBUG_VALIDATE_BUG_ON(logger != NULL && store == NULL);
    DEBUG_VALIDATE_BUG_ON(logger == NULL && store == NULL);

    while (logger && store) {
        DEBUG_VALIDATE_BUG_ON(logger->LogFunc == NULL || logger->ConditionFunc == NULL);

        if ((logger->ConditionFunc(tv, store->thread_data, (const Packet *)p)) == TRUE) {
            PACKET_PROFILING_LOGGER_START(p, logger->logger_id);
            logger->LogFunc(tv, store->thread_data, (const Packet *)p);
            PACKET_PROFILING_LOGGER_END(p, logger->logger_id);
        }

        logger = logger->next;
        store = store->next;

        DEBUG_VALIDATE_BUG_ON(logger == NULL && store != NULL);
        DEBUG_VALIDATE_BUG_ON(logger != NULL && store == NULL);
    }

    return TM_ECODE_OK;
}

/** \brief thread init for the packet logger
 *  This will run the thread init functions for the individual registered
 *  loggers */
static TmEcode OutputPacketLogThreadInit(ThreadVars *tv, const void *initdata, void **data)
{
    OutputPacketLoggerThreadData *td = SCMalloc(sizeof(*td));
    if (td == NULL)
        return TM_ECODE_FAILED;
    memset(td, 0x00, sizeof(*td));

    *data = (void *)td;

    SCLogDebug("OutputPacketLogThreadInit happy (*data %p)", *data);

    OutputPacketLogger *logger = list;
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

    return TM_ECODE_OK;
}

static TmEcode OutputPacketLogThreadDeinit(ThreadVars *tv, void *thread_data)
{
    OutputPacketLoggerThreadData *op_thread_data = (OutputPacketLoggerThreadData *)thread_data;
    OutputLoggerThreadStore *store = op_thread_data->store;
    OutputPacketLogger *logger = list;

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

static void OutputPacketLogExitPrintStats(ThreadVars *tv, void *thread_data)
{
    OutputPacketLoggerThreadData *op_thread_data = (OutputPacketLoggerThreadData *)thread_data;
    OutputLoggerThreadStore *store = op_thread_data->store;
    OutputPacketLogger *logger = list;

    while (logger && store) {
        if (logger->ThreadExitPrintStats) {
            logger->ThreadExitPrintStats(tv, store->thread_data);
        }

        logger = logger->next;
        store = store->next;
    }
}

static uint32_t OutputPacketLoggerGetActiveCount(void)
{
    uint32_t cnt = 0;
    for (OutputPacketLogger *p = list; p != NULL; p = p->next) {
        cnt++;
    }
    return cnt;
}

void OutputPacketLoggerRegister(void)
{
    OutputRegisterRootLogger(OutputPacketLogThreadInit,
        OutputPacketLogThreadDeinit, OutputPacketLogExitPrintStats,
        OutputPacketLog, OutputPacketLoggerGetActiveCount);
}

void OutputPacketShutdown(void)
{
    OutputPacketLogger *logger = list;
    while (logger) {
        OutputPacketLogger *next_logger = logger->next;
        SCFree(logger);
        logger = next_logger;
    }

    /* reset list pointer */
    list = NULL;
}
