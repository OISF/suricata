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
 * Packet Logger Output registration functions
 */

#include "suricata-common.h"
#include "tm-modules.h"
#include "output-packet.h"
#include "util-profiling.h"

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
 * log module (e.g. fast.log) with different output ctx'. */
typedef struct OutputPacketLogger_ {
    PacketLogger LogFunc;
    PacketLogCondition ConditionFunc;
    OutputCtx *output_ctx;
    struct OutputPacketLogger_ *next;
    const char *name;
    TmmId module_id;
} OutputPacketLogger;

static OutputPacketLogger *list = NULL;

int OutputRegisterPacketLogger(const char *name, PacketLogger LogFunc, PacketLogCondition ConditionFunc, OutputCtx *output_ctx)
{
    int module_id = TmModuleGetIdByName(name);
    if (module_id < 0)
        return -1;

    OutputPacketLogger *op = SCMalloc(sizeof(*op));
    if (op == NULL)
        return -1;
    memset(op, 0x00, sizeof(*op));

    op->LogFunc = LogFunc;
    op->ConditionFunc = ConditionFunc;
    op->output_ctx = output_ctx;
    op->name = name;
    op->module_id = (TmmId) module_id;

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

static TmEcode OutputPacketLog(ThreadVars *tv, Packet *p, void *thread_data, PacketQueue *pq, PacketQueue *postpq)
{
    BUG_ON(thread_data == NULL);
    BUG_ON(list == NULL);

    OutputLoggerThreadData *op_thread_data = (OutputLoggerThreadData *)thread_data;
    OutputPacketLogger *logger = list;
    OutputLoggerThreadStore *store = op_thread_data->store;

    BUG_ON(logger == NULL && store != NULL);
    BUG_ON(logger != NULL && store == NULL);
    BUG_ON(logger == NULL && store == NULL);

    while (logger && store) {
        BUG_ON(logger->LogFunc == NULL || logger->ConditionFunc == NULL);

        if ((logger->ConditionFunc(tv, (const Packet *)p)) == TRUE) {
            PACKET_PROFILING_TMM_START(p, logger->module_id);
            logger->LogFunc(tv, store->thread_data, (const Packet *)p);
            PACKET_PROFILING_TMM_END(p, logger->module_id);
        }

        logger = logger->next;
        store = store->next;

        BUG_ON(logger == NULL && store != NULL);
        BUG_ON(logger != NULL && store == NULL);
    }

    return TM_ECODE_OK;
}

/** \brief thread init for the packet logger
 *  This will run the thread init functions for the individual registered
 *  loggers */
static TmEcode OutputPacketLogThreadInit(ThreadVars *tv, void *initdata, void **data)
{
    OutputLoggerThreadData *td = SCMalloc(sizeof(*td));
    if (td == NULL)
        return TM_ECODE_FAILED;
    memset(td, 0x00, sizeof(*td));

    *data = (void *)td;

    SCLogDebug("OutputPacketLogThreadInit happy (*data %p)", *data);

    OutputPacketLogger *logger = list;
    while (logger) {
        TmModule *tm_module = TmModuleGetByName((char *)logger->name);
        if (tm_module == NULL) {
            SCLogError(SC_ERR_INVALID_ARGUMENT,
                    "TmModuleGetByName for %s failed", logger->name);
            exit(EXIT_FAILURE);
        }

        if (tm_module->ThreadInit) {
            void *retptr = NULL;
            if (tm_module->ThreadInit(tv, (void *)logger->output_ctx, &retptr) == TM_ECODE_OK) {
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
    OutputLoggerThreadData *op_thread_data = (OutputLoggerThreadData *)thread_data;
    OutputLoggerThreadStore *store = op_thread_data->store;
    OutputPacketLogger *logger = list;

    while (logger && store) {
        TmModule *tm_module = TmModuleGetByName((char *)logger->name);
        if (tm_module == NULL) {
            SCLogError(SC_ERR_INVALID_ARGUMENT,
                    "TmModuleGetByName for %s failed", logger->name);
            exit(EXIT_FAILURE);
        }

        if (tm_module->ThreadDeinit) {
            tm_module->ThreadDeinit(tv, store->thread_data);
        }

        OutputLoggerThreadStore *next_store = store->next;
        SCFree(store);
        store = next_store;

        logger = logger->next;
    }
    return TM_ECODE_OK;
}

static void OutputPacketLogExitPrintStats(ThreadVars *tv, void *thread_data)
{
    OutputLoggerThreadData *op_thread_data = (OutputLoggerThreadData *)thread_data;
    OutputLoggerThreadStore *store = op_thread_data->store;
    OutputPacketLogger *logger = list;

    while (logger && store) {
        TmModule *tm_module = TmModuleGetByName((char *)logger->name);
        if (tm_module == NULL) {
            SCLogError(SC_ERR_INVALID_ARGUMENT,
                    "TmModuleGetByName for %s failed", logger->name);
            exit(EXIT_FAILURE);
        }

        if (tm_module->ThreadExitPrintStats) {
            tm_module->ThreadExitPrintStats(tv, store->thread_data);
        }

        logger = logger->next;
        store = store->next;
    }
}

void TmModulePacketLoggerRegister (void)
{
    tmm_modules[TMM_PACKETLOGGER].name = "__packet_logger__";
    tmm_modules[TMM_PACKETLOGGER].ThreadInit = OutputPacketLogThreadInit;
    tmm_modules[TMM_PACKETLOGGER].Func = OutputPacketLog;
    tmm_modules[TMM_PACKETLOGGER].ThreadExitPrintStats = OutputPacketLogExitPrintStats;
    tmm_modules[TMM_PACKETLOGGER].ThreadDeinit = OutputPacketLogThreadDeinit;
    tmm_modules[TMM_PACKETLOGGER].cap_flags = 0;
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
