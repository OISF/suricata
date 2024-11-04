/* Copyright (C) 2007-2024 Open Information Security Foundation
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
 * Flow Logger Output registration functions
 */

#include "suricata-common.h"
#include "output.h"
#include "output-flow.h"
#include "util-profiling.h"
#include "util-validate.h"

/** per thread data for this module, contains a list of per thread
 *  data for the packet loggers. */
typedef struct OutputFlowLoggerThreadData_ {
    OutputLoggerThreadStore *store;
} OutputFlowLoggerThreadData;

/* logger instance, a module + a output ctx,
 * it's perfectly valid that have multiple instances of the same
 * log module (e.g. http.log) with different output ctx'. */
typedef struct OutputFlowLogger_ {
    FlowLogger LogFunc;

    /** Data that will be passed to the ThreadInit callback. */
    void *initdata;

    struct OutputFlowLogger_ *next;

    /** A name for this logger, used for debugging only. */
    const char *name;

    TmEcode (*ThreadInit)(ThreadVars *, const void *, void **);
    TmEcode (*ThreadDeinit)(ThreadVars *, void *);
} OutputFlowLogger;

static OutputFlowLogger *list = NULL;

int SCOutputRegisterFlowLogger(const char *name, FlowLogger LogFunc, void *initdata,
        ThreadInitFunc ThreadInit, ThreadDeinitFunc ThreadDeinit)
{
    OutputFlowLogger *op = SCCalloc(1, sizeof(*op));
    if (op == NULL)
        return -1;

    op->LogFunc = LogFunc;
    op->initdata = initdata;
    op->name = name;
    op->ThreadInit = ThreadInit;
    op->ThreadDeinit = ThreadDeinit;

    if (list == NULL)
        list = op;
    else {
        OutputFlowLogger *t = list;
        while (t->next)
            t = t->next;
        t->next = op;
    }

    SCLogDebug("OutputRegisterFlowLogger happy");
    return 0;
}

/** \brief Run flow logger(s)
 *  \note flow is already write locked
 */
TmEcode OutputFlowLog(ThreadVars *tv, void *thread_data, Flow *f)
{
    DEBUG_VALIDATE_BUG_ON(thread_data == NULL);

    if (list == NULL)
        return TM_ECODE_OK;

    OutputFlowLoggerThreadData *op_thread_data = (OutputFlowLoggerThreadData *)thread_data;
    OutputFlowLogger *logger = list;
    OutputLoggerThreadStore *store = op_thread_data->store;

    DEBUG_VALIDATE_BUG_ON(logger == NULL && store != NULL);
    DEBUG_VALIDATE_BUG_ON(logger != NULL && store == NULL);
    DEBUG_VALIDATE_BUG_ON(logger == NULL && store == NULL);

    while (logger && store) {
        DEBUG_VALIDATE_BUG_ON(logger->LogFunc == NULL);

        SCLogDebug("logger %p", logger);
        //PACKET_PROFILING_LOGGER_START(p, logger->module_id);
        logger->LogFunc(tv, store->thread_data, f);
        //PACKET_PROFILING_LOGGER_END(p, logger->module_id);

        logger = logger->next;
        store = store->next;

        DEBUG_VALIDATE_BUG_ON(logger == NULL && store != NULL);
        DEBUG_VALIDATE_BUG_ON(logger != NULL && store == NULL);
    }

    return TM_ECODE_OK;
}

/** \brief thread init for the flow logger
 *  This will run the thread init functions for the individual registered
 *  loggers */
TmEcode OutputFlowLogThreadInit(ThreadVars *tv, void **data)
{
    OutputFlowLoggerThreadData *td = SCCalloc(1, sizeof(*td));
    if (td == NULL)
        return TM_ECODE_FAILED;

    *data = (void *)td;

    SCLogDebug("OutputFlowLogThreadInit happy (*data %p)", *data);

    OutputFlowLogger *logger = list;
    while (logger) {
        if (logger->ThreadInit) {
            void *retptr = NULL;
            if (logger->ThreadInit(tv, (void *)logger->initdata, &retptr) == TM_ECODE_OK) {
                OutputLoggerThreadStore *ts = SCCalloc(1, sizeof(*ts));
                /* todo */ BUG_ON(ts == NULL);

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

TmEcode OutputFlowLogThreadDeinit(ThreadVars *tv, void *thread_data)
{
    OutputFlowLoggerThreadData *op_thread_data = (OutputFlowLoggerThreadData *)thread_data;
    if (op_thread_data == NULL)
        return TM_ECODE_OK;

    OutputLoggerThreadStore *store = op_thread_data->store;
    OutputFlowLogger *logger = list;

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

void OutputFlowShutdown(void)
{
    OutputFlowLogger *logger = list;
    while (logger) {
        OutputFlowLogger *next_logger = logger->next;
        SCFree(logger);
        logger = next_logger;
    }
    list = NULL;
}
