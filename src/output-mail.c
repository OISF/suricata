/* Copyright (C) 2007-2014 Open Information Security Foundation
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
 * \author Tom DeCanio <decanio.tom@gmail.com>
 *
 * AppLayer Mail Logger Output registration functions
 */

#include "suricata-common.h"
#include "tm-modules.h"
#include "output-file.h"
#include "app-layer.h"
#include "app-layer-parser.h"
#include "detect-filemagic.h"
#include "util-profiling.h"

#include "conf.h"

typedef struct OutputLoggerThreadStore_ {
    void *thread_data;
    struct OutputLoggerThreadStore_ *next;
} OutputLoggerThreadStore;

/** per thread data for this module, contains a list of per thread
 *  data for the packet loggers. */
typedef struct OutputLoggerThreadData_ {
    OutputLoggerThreadStore *store;
    magic_t ctx;
} OutputLoggerThreadData;

/* logger instance, a module + a output ctx,
 * it's perfectly valid that have multiple instances of the same
 * log module (e.g. http.log) with different output ctx'. */
typedef struct OutputFileLogger_ {
    FileLogger LogFunc;
    OutputCtx *output_ctx;
    struct OutputFileLogger_ *next;
    const char *name;
    TmmId module_id;
} OutputFileLogger;

static OutputFileLogger *list = NULL;

int OutputRegisterMailLogger(const char *name, FileLogger LogFunc, OutputCtx *output_ctx)
{
    int module_id = TmModuleGetIdByName(name);
    if (module_id < 0)
        return -1;

    OutputFileLogger *op = SCMalloc(sizeof(*op));
    if (op == NULL)
        return -1;
    memset(op, 0x00, sizeof(*op));

    op->LogFunc = LogFunc;
    op->output_ctx = output_ctx;
    op->name = name;
    op->module_id = (TmmId) module_id;

    if (list == NULL)
        list = op;
    else {
        OutputFileLogger *t = list;
        while (t->next)
            t = t->next;
        t->next = op;
    }

    SCLogDebug("OutputRegisterMailLogger happy");
    return 0;
}

static TmEcode OutputMailLog(ThreadVars *tv, Packet *p, void *thread_data, PacketQueue *pq, PacketQueue *postpq)
{
    BUG_ON(thread_data == NULL);
    BUG_ON(list == NULL);

    OutputLoggerThreadData *op_thread_data = (OutputLoggerThreadData *)thread_data;
    OutputFileLogger *logger = list;
    OutputLoggerThreadStore *store = op_thread_data->store;

    BUG_ON(logger == NULL && store != NULL);
    BUG_ON(logger != NULL && store == NULL);
    BUG_ON(logger == NULL && store == NULL);

    uint8_t flags = 0;
    Flow * const f = p->flow;

    /* no flow, no files */
    if (f == NULL) {
        SCReturnInt(TM_ECODE_OK);
    }

    if (p->flowflags & FLOW_PKT_TOCLIENT)
        flags |= STREAM_TOCLIENT;
    else
        flags |= STREAM_TOSERVER;

    int file_close = (p->flags & PKT_PSEUDO_STREAM_END) ? 1 : 0;
    int file_trunc = 0;

    FLOWLOCK_WRLOCK(f); // < need write lock for FilePrune below
    file_trunc = StreamTcpReassembleDepthReached(p);

    FileContainer *ffc = AppLayerParserGetMail(p->proto, f->alproto,
                                               f->alstate, flags);
    SCLogDebug("ffc %p", ffc);
    if (ffc != NULL) {
        File *ff;
        for (ff = ffc->head; ff != NULL; ff = ff->next) {
            if (ff->flags & FILE_LOGGED)
                continue;

            SCLogDebug("ff %p", ff);

            if (file_trunc && ff->state < FILE_STATE_CLOSED)
                ff->state = FILE_STATE_TRUNCATED;

            if (file_close && ff->state < FILE_STATE_CLOSED)
                ff->state = FILE_STATE_TRUNCATED;

            if (ff->state == FILE_STATE_CLOSED    ||
                ff->state == FILE_STATE_TRUNCATED ||
                ff->state == FILE_STATE_ERROR)
            {
                int file_logged = 0;

                logger = list;
                store = op_thread_data->store;
                while (logger && store) {
                    BUG_ON(logger->LogFunc == NULL);

                    SCLogDebug("logger %p", logger);
                    PACKET_PROFILING_TMM_START(p, logger->module_id);
                    logger->LogFunc(tv, store->thread_data, (const Packet *)p, (const File *)ff);
                    PACKET_PROFILING_TMM_END(p, logger->module_id);
                    file_logged = 1;

                    logger = logger->next;
                    store = store->next;

                    BUG_ON(logger == NULL && store != NULL);
                    BUG_ON(logger != NULL && store == NULL);
                }

                if (file_logged) {
                    ff->flags |= FILE_LOGGED;
                }
            }
        }

        FilePrune(ffc);
    }

    FLOWLOCK_UNLOCK(f);
    return TM_ECODE_OK;
}

/** \brief thread init for the tx logger
 *  This will run the thread init functions for the individual registered
 *  loggers */
static TmEcode OutputMailLogThreadInit(ThreadVars *tv, void *initdata, void **data)
{
    OutputLoggerThreadData *td = SCMalloc(sizeof(*td));
    if (td == NULL)
        return TM_ECODE_FAILED;
    memset(td, 0x00, sizeof(*td));

    *data = (void *)td;

    SCLogDebug("OutputMailLogThreadInit happy (*data %p)", *data);

    OutputFileLogger *logger = list;
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

static TmEcode OutputMailLogThreadDeinit(ThreadVars *tv, void *thread_data)
{
    OutputLoggerThreadData *op_thread_data = (OutputLoggerThreadData *)thread_data;
    OutputLoggerThreadStore *store = op_thread_data->store;
    OutputFileLogger *logger = list;

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

    SCFree(op_thread_data);
    return TM_ECODE_OK;
}

static void OutputMailLogExitPrintStats(ThreadVars *tv, void *thread_data)
{
    OutputLoggerThreadData *op_thread_data = (OutputLoggerThreadData *)thread_data;
    OutputLoggerThreadStore *store = op_thread_data->store;
    OutputFileLogger *logger = list;

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

void TmModuleMailLoggerRegister (void)
{
    tmm_modules[TMM_MAILLOGGER].name = "__mail_logger__";
    tmm_modules[TMM_MAILLOGGER].ThreadInit = OutputMailLogThreadInit;
    tmm_modules[TMM_MAILLOGGER].Func = OutputMailLog;
    tmm_modules[TMM_MAILLOGGER].ThreadExitPrintStats = OutputMailLogExitPrintStats;
    tmm_modules[TMM_MAILLOGGER].ThreadDeinit = OutputMailLogThreadDeinit;
    tmm_modules[TMM_MAILLOGGER].cap_flags = 0;
}

void OutputMailShutdown(void)
{
    OutputFileLogger *logger = list;
    while (logger) {
        OutputFileLogger *next_logger = logger->next;
        SCFree(logger);
        logger = next_logger;
    }

    list = NULL;
}
