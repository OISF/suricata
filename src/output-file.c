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
 * AppLayer File Logger Output registration functions
 */

#include "suricata-common.h"
#include "tm-modules.h"
#include "output.h"
#include "output-file.h"
#include "app-layer.h"
#include "app-layer-parser.h"
#include "detect-filemagic.h"
#include "util-file.h"
#include "util-profiling.h"
#include "util-validate.h"
#include "util-magic.h"
#include "util-mimetype.h"

bool g_file_logger_enabled = false;

/** per thread data for this module, contains a list of per thread
 *  data for the packet loggers. */
typedef struct OutputFileLoggerThreadData_ {
    OutputLoggerThreadStore *store;
#ifdef HAVE_MAGIC
    magic_t magic_ctx;
#endif
} OutputFileLoggerThreadData;

/* logger instance, a module + a output ctx,
 * it's perfectly valid that have multiple instances of the same
 * log module (e.g. http.log) with different output ctx'. */
typedef struct OutputFileLogger_ {
    FileLogger LogFunc;
    OutputCtx *output_ctx;
    struct OutputFileLogger_ *next;
    const char *name;
    LoggerId logger_id;
    ThreadInitFunc ThreadInit;
    ThreadDeinitFunc ThreadDeinit;
    ThreadExitPrintStatsFunc ThreadExitPrintStats;
} OutputFileLogger;

static OutputFileLogger *list = NULL;

int OutputRegisterFileLogger(LoggerId id, const char *name, FileLogger LogFunc,
    OutputCtx *output_ctx, ThreadInitFunc ThreadInit,
    ThreadDeinitFunc ThreadDeinit,
    ThreadExitPrintStatsFunc ThreadExitPrintStats)
{
    OutputFileLogger *op = SCMalloc(sizeof(*op));
    if (op == NULL)
        return -1;
    memset(op, 0x00, sizeof(*op));

    op->LogFunc = LogFunc;
    op->output_ctx = output_ctx;
    op->name = name;
    op->logger_id = id;
    op->ThreadInit = ThreadInit;
    op->ThreadDeinit = ThreadDeinit;
    op->ThreadExitPrintStats = ThreadExitPrintStats;

    if (list == NULL)
        list = op;
    else {
        OutputFileLogger *t = list;
        while (t->next)
            t = t->next;
        t->next = op;
    }

    SCLogDebug("OutputRegisterFileLogger happy");

    g_file_logger_enabled = true;
    return 0;
}

static void CloseFile(const Packet *p, Flow *f, File *file)
{
    DEBUG_VALIDATE_BUG_ON((file->flags & FILE_LOGGED) != 0);
    void *txv = AppLayerParserGetTx(f->proto, f->alproto, f->alstate, file->txid);
    if (txv) {
        AppLayerTxData *txd = AppLayerParserGetTxData(f->proto, f->alproto, txv);
        if (txd) {
            txd->files_logged++;
            DEBUG_VALIDATE_BUG_ON(txd->files_logged > txd->files_opened);
        }
    }
    file->flags |= FILE_LOGGED;
}

static void OutputFileLogFfc(ThreadVars *tv, OutputFileLoggerThreadData *op_thread_data, Packet *p,
        FileContainer *ffc, const bool file_close, const bool file_trunc, uint8_t dir)
{
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

            SCLogDebug("ff %p state %u", ff, ff->state);

            if (ff->state > FILE_STATE_OPENED) {
                bool file_logged = false;
#ifdef HAVE_MAGIC
                if (FileForceMagic() && ff->magic == NULL) {
                    FilemagicThreadLookup(&op_thread_data->magic_ctx, ff);
                }
#endif
                if (FileForceMimetype() && ff->mimetype == NULL) {
                    FileMimetypeLookup(ff);
                }

                const OutputFileLogger *logger = list;
                const OutputLoggerThreadStore *store = op_thread_data->store;
                while (logger && store) {
                    DEBUG_VALIDATE_BUG_ON(logger->LogFunc == NULL);

                    SCLogDebug("logger %p", logger);
                    PACKET_PROFILING_LOGGER_START(p, logger->logger_id);
                    logger->LogFunc(tv, store->thread_data, (const Packet *)p, (const File *)ff, dir);
                    PACKET_PROFILING_LOGGER_END(p, logger->logger_id);
                    file_logged = true;

                    logger = logger->next;
                    store = store->next;

                    DEBUG_VALIDATE_BUG_ON(logger == NULL && store != NULL);
                    DEBUG_VALIDATE_BUG_ON(logger != NULL && store == NULL);
                }

                if (file_logged) {
                    CloseFile(p, p->flow, ff);
                }
            }
        }
    }
}

static TmEcode OutputFileLog(ThreadVars *tv, Packet *p, void *thread_data)
{
    DEBUG_VALIDATE_BUG_ON(thread_data == NULL);

    if (list == NULL) {
        /* No child loggers. */
        return TM_ECODE_OK;
    }

    OutputFileLoggerThreadData *op_thread_data = (OutputFileLoggerThreadData *)thread_data;

    /* no flow, no files */
    Flow * const f = p->flow;
    if (f == NULL || f->alstate == NULL) {
        SCReturnInt(TM_ECODE_OK);
    }

    if (p->proto == IPPROTO_TCP) {
        const bool file_trunc = StreamTcpReassembleDepthReached(p);
        if (p->flowflags & FLOW_PKT_TOSERVER) {
            const bool file_close_ts = ((p->flags & PKT_PSEUDO_STREAM_END));
            FileContainer *ffc_ts = AppLayerParserGetFiles(f, STREAM_TOSERVER);
            OutputFileLogFfc(
                    tv, op_thread_data, p, ffc_ts, file_close_ts, file_trunc, STREAM_TOSERVER);
        } else {
            const bool file_close_tc = ((p->flags & PKT_PSEUDO_STREAM_END));
            FileContainer *ffc_tc = AppLayerParserGetFiles(f, STREAM_TOCLIENT);
            OutputFileLogFfc(
                    tv, op_thread_data, p, ffc_tc, file_close_tc, file_trunc, STREAM_TOCLIENT);
        }
    } else if (p->proto == IPPROTO_UDP) {
        FileContainer *ffc_ts = AppLayerParserGetFiles(f, STREAM_TOSERVER);
        OutputFileLogFfc(tv, op_thread_data, p, ffc_ts, false, false, STREAM_TOSERVER);
        FileContainer *ffc_tc = AppLayerParserGetFiles(f, STREAM_TOCLIENT);
        OutputFileLogFfc(tv, op_thread_data, p, ffc_tc, false, false, STREAM_TOCLIENT);
    }
    return TM_ECODE_OK;
}

/** \brief thread init for the tx logger
 *  This will run the thread init functions for the individual registered
 *  loggers */
static TmEcode OutputFileLogThreadInit(ThreadVars *tv, const void *initdata, void **data)
{
    OutputFileLoggerThreadData *td = SCMalloc(sizeof(*td));
    if (td == NULL)
        return TM_ECODE_FAILED;
    memset(td, 0x00, sizeof(*td));

    *data = (void *)td;

#ifdef HAVE_MAGIC
    td->magic_ctx = MagicInitContext();
    if (td->magic_ctx == NULL) {
        SCFree(td);
        return TM_ECODE_FAILED;
    }
#endif

    SCLogDebug("OutputFileLogThreadInit happy (*data %p)", *data);

    OutputFileLogger *logger = list;
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

static TmEcode OutputFileLogThreadDeinit(ThreadVars *tv, void *thread_data)
{
    OutputFileLoggerThreadData *op_thread_data = (OutputFileLoggerThreadData *)thread_data;
    OutputLoggerThreadStore *store = op_thread_data->store;
    OutputFileLogger *logger = list;

    while (logger && store) {
        if (logger->ThreadDeinit) {
            logger->ThreadDeinit(tv, store->thread_data);
        }

        OutputLoggerThreadStore *next_store = store->next;
        SCFree(store);
        store = next_store;
        logger = logger->next;
    }

#ifdef HAVE_MAGIC
    MagicDeinitContext(op_thread_data->magic_ctx);
#endif

    SCFree(op_thread_data);
    return TM_ECODE_OK;
}

static void OutputFileLogExitPrintStats(ThreadVars *tv, void *thread_data)
{
    OutputFileLoggerThreadData *op_thread_data = (OutputFileLoggerThreadData *)thread_data;
    OutputLoggerThreadStore *store = op_thread_data->store;
    OutputFileLogger *logger = list;

    while (logger && store) {
        if (logger->ThreadExitPrintStats) {
            logger->ThreadExitPrintStats(tv, store->thread_data);
        }

        logger = logger->next;
        store = store->next;
    }
}

static uint32_t OutputFileLoggerGetActiveCount(void)
{
    uint32_t cnt = 0;
    for (OutputFileLogger *p = list; p != NULL; p = p->next) {
        cnt++;
    }
    return cnt;
}

void OutputFileLoggerRegister(void)
{
    OutputRegisterRootLogger(OutputFileLogThreadInit,
        OutputFileLogThreadDeinit, OutputFileLogExitPrintStats,
        OutputFileLog, OutputFileLoggerGetActiveCount);
}

void OutputFileShutdown(void)
{
    OutputFileLogger *logger = list;
    while (logger) {
        OutputFileLogger *next_logger = logger->next;
        SCFree(logger);
        logger = next_logger;
    }

    list = NULL;
}
