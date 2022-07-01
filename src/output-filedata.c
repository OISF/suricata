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
 * AppLayer Filedata Logger Output registration functions
 */

#include "suricata-common.h"
#include "tm-modules.h"
#include "output.h"
#include "output-filedata.h"
#include "app-layer.h"
#include "app-layer-parser.h"
#include "detect-filemagic.h"
#include "conf.h"
#include "util-profiling.h"
#include "util-validate.h"
#include "util-magic.h"

bool g_filedata_logger_enabled = false;

/** per thread data for this module, contains a list of per thread
 *  data for the packet loggers. */
typedef struct OutputFiledataLoggerThreadData_ {
    OutputLoggerThreadStore *store;
#ifdef HAVE_MAGIC
    magic_t magic_ctx;
#endif
} OutputFiledataLoggerThreadData;

/* logger instance, a module + a output ctx,
 * it's perfectly valid that have multiple instances of the same
 * log module (e.g. http.log) with different output ctx'. */
typedef struct OutputFiledataLogger_ {
    FiledataLogger LogFunc;
    OutputCtx *output_ctx;
    struct OutputFiledataLogger_ *next;
    const char *name;
    LoggerId logger_id;
    ThreadInitFunc ThreadInit;
    ThreadDeinitFunc ThreadDeinit;
    ThreadExitPrintStatsFunc ThreadExitPrintStats;
} OutputFiledataLogger;

static OutputFiledataLogger *list = NULL;

int OutputRegisterFiledataLogger(LoggerId id, const char *name,
    FiledataLogger LogFunc, OutputCtx *output_ctx, ThreadInitFunc ThreadInit,
    ThreadDeinitFunc ThreadDeinit,
    ThreadExitPrintStatsFunc ThreadExitPrintStats)
{
    OutputFiledataLogger *op = SCMalloc(sizeof(*op));
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
        OutputFiledataLogger *t = list;
        while (t->next)
            t = t->next;
        t->next = op;
    }

    SCLogDebug("OutputRegisterFiledataLogger happy");
    g_filedata_logger_enabled = true;
    return 0;
}

SC_ATOMIC_DECLARE(unsigned int, g_file_store_id);

static int CallLoggers(ThreadVars *tv, OutputLoggerThreadStore *store_list,
        Packet *p, File *ff,
        const uint8_t *data, uint32_t data_len, uint8_t flags, uint8_t dir)
{
    OutputFiledataLogger *logger = list;
    OutputLoggerThreadStore *store = store_list;
    int file_logged = 0;

    while (logger && store) {
        DEBUG_VALIDATE_BUG_ON(logger->LogFunc == NULL);

        SCLogDebug("logger %p", logger);
        PACKET_PROFILING_LOGGER_START(p, logger->logger_id);
        logger->LogFunc(tv, store->thread_data, (const Packet *)p, ff, data, data_len, flags, dir);
        PACKET_PROFILING_LOGGER_END(p, logger->logger_id);

        file_logged = 1;

        logger = logger->next;
        store = store->next;

        DEBUG_VALIDATE_BUG_ON(logger == NULL && store != NULL);
        DEBUG_VALIDATE_BUG_ON(logger != NULL && store == NULL);
    }
    return file_logged;
}

static void CloseFile(const Packet *p, Flow *f, File *file)
{
    void *txv = AppLayerParserGetTx(f->proto, f->alproto, f->alstate, file->txid);
    if (txv) {
        AppLayerTxData *txd = AppLayerParserGetTxData(f->proto, f->alproto, txv);
        if (txd)
            txd->files_stored++;
    }
    file->flags |= FILE_STORED;
}

static void OutputFiledataLogFfc(ThreadVars *tv, OutputFiledataLoggerThreadData *td, Packet *p,
        FileContainer *ffc, const uint8_t call_flags, const bool file_close, const bool file_trunc,
        const uint8_t dir)
{
    if (ffc != NULL) {
        OutputLoggerThreadStore *store = td->store;
        File *ff;
        for (ff = ffc->head; ff != NULL; ff = ff->next) {
            uint8_t file_flags = call_flags;
#ifdef HAVE_MAGIC
            if (FileForceMagic() && ff->magic == NULL) {
                FilemagicThreadLookup(&td->magic_ctx, ff);
            }
#endif
            SCLogDebug("ff %p", ff);
            if (ff->flags & FILE_STORED) {
                SCLogDebug("stored flag set");
                continue;
            }

            if (!(ff->flags & FILE_STORE)) {
                SCLogDebug("ff FILE_STORE not set");
                continue;
            }

            /* if we have no data chunks left to log, we should still
             * close the logger(s) */
            if (FileDataSize(ff) == ff->content_stored &&
                (file_trunc || file_close)) {
                if (ff->state < FILE_STATE_CLOSED) {
                    FileCloseFilePtr(ff, NULL, 0, FILE_TRUNCATED);
                }
                CallLoggers(tv, store, p, ff, NULL, 0, OUTPUT_FILEDATA_FLAG_CLOSE, dir);
                CloseFile(p, p->flow, ff);
                continue;
            }

            /* store */

            /* if file_store_id == 0, this is the first store of this file */
            if (ff->file_store_id == 0) {
                /* new file */
                ff->file_store_id = SC_ATOMIC_ADD(g_file_store_id, 1);
                file_flags |= OUTPUT_FILEDATA_FLAG_OPEN;
            } else {
                /* existing file */
            }

            /* if file needs to be closed or truncated, inform
             * loggers */
            if ((file_close || file_trunc) && ff->state < FILE_STATE_CLOSED) {
                FileCloseFilePtr(ff, NULL, 0, FILE_TRUNCATED);
            }

            /* tell the logger we're closing up */
            if (ff->state >= FILE_STATE_CLOSED)
                file_flags |= OUTPUT_FILEDATA_FLAG_CLOSE;

            /* do the actual logging */
            const uint8_t *data = NULL;
            uint32_t data_len = 0;

            StreamingBufferGetDataAtOffset(ff->sb,
                    &data, &data_len,
                    ff->content_stored);

            const int file_logged = CallLoggers(tv, store, p, ff, data, data_len, file_flags, dir);
            if (file_logged) {
                ff->content_stored += data_len;

                /* all done */
                if (file_flags & OUTPUT_FILEDATA_FLAG_CLOSE) {
                    CloseFile(p, p->flow, ff);
                }
            }
        }
    }
}

static TmEcode OutputFiledataLog(ThreadVars *tv, Packet *p, void *thread_data)
{
    DEBUG_VALIDATE_BUG_ON(thread_data == NULL);

    if (list == NULL) {
        /* No child loggers. */
        return TM_ECODE_OK;
    }

    OutputFiledataLoggerThreadData *op_thread_data = (OutputFiledataLoggerThreadData *)thread_data;

    /* no flow, no files */
    Flow * const f = p->flow;
    if (f == NULL || f->alstate == NULL) {
        SCReturnInt(TM_ECODE_OK);
    }

    const bool file_trunc = StreamTcpReassembleDepthReached(p);
    if (p->flowflags & FLOW_PKT_TOSERVER) {
        const bool file_close_ts = ((p->flags & PKT_PSEUDO_STREAM_END));
        FileContainer *ffc_ts = AppLayerParserGetFiles(f, STREAM_TOSERVER);
        SCLogDebug("ffc_ts %p", ffc_ts);
        OutputFiledataLogFfc(tv, op_thread_data, p, ffc_ts, STREAM_TOSERVER, file_close_ts,
                file_trunc, STREAM_TOSERVER);
    } else {
        const bool file_close_tc = ((p->flags & PKT_PSEUDO_STREAM_END));
        FileContainer *ffc_tc = AppLayerParserGetFiles(f, STREAM_TOCLIENT);
        SCLogDebug("ffc_tc %p", ffc_tc);
        OutputFiledataLogFfc(tv, op_thread_data, p, ffc_tc, STREAM_TOCLIENT, file_close_tc,
                file_trunc, STREAM_TOCLIENT);
    }

    return TM_ECODE_OK;
}

/** \brief thread init for the tx logger
 *  This will run the thread init functions for the individual registered
 *  loggers */
static TmEcode OutputFiledataLogThreadInit(ThreadVars *tv, const void *initdata, void **data)
{
    OutputFiledataLoggerThreadData *td = SCMalloc(sizeof(*td));
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

    SCLogDebug("OutputFiledataLogThreadInit happy (*data %p)", *data);

    OutputFiledataLogger *logger = list;
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

static TmEcode OutputFiledataLogThreadDeinit(ThreadVars *tv, void *thread_data)
{
    OutputFiledataLoggerThreadData *op_thread_data = (OutputFiledataLoggerThreadData *)thread_data;
    OutputLoggerThreadStore *store = op_thread_data->store;
    OutputFiledataLogger *logger = list;

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

static void OutputFiledataLogExitPrintStats(ThreadVars *tv, void *thread_data)
{
    OutputFiledataLoggerThreadData *op_thread_data = (OutputFiledataLoggerThreadData *)thread_data;
    OutputLoggerThreadStore *store = op_thread_data->store;
    OutputFiledataLogger *logger = list;

    while (logger && store) {
        if (logger->ThreadExitPrintStats) {
            logger->ThreadExitPrintStats(tv, store->thread_data);
        }

        logger = logger->next;
        store = store->next;
    }
}

static uint32_t OutputFiledataLoggerGetActiveCount(void)
{
    uint32_t cnt = 0;
    for (OutputFiledataLogger *p = list; p != NULL; p = p->next) {
        cnt++;
    }
    return cnt;
}

void OutputFiledataLoggerRegister(void)
{
    OutputRegisterRootLogger(OutputFiledataLogThreadInit,
        OutputFiledataLogThreadDeinit, OutputFiledataLogExitPrintStats,
        OutputFiledataLog, OutputFiledataLoggerGetActiveCount);
    SC_ATOMIC_INIT(g_file_store_id);
    SC_ATOMIC_SET(g_file_store_id, 1);
}

void OutputFiledataShutdown(void)
{
    OutputFiledataLogger *logger = list;
    while (logger) {
        OutputFiledataLogger *next_logger = logger->next;
        SCFree(logger);
        logger = next_logger;
    }

    list = NULL;
}
