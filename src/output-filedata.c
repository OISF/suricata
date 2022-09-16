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
#include "output.h"
#include "output-filedata.h"
#include "app-layer-parser.h"
#include "detect-filemagic.h"
#include "conf.h"
#include "util-profiling.h"
#include "util-validate.h"
#include "util-magic.h"
#include "util-path.h"

bool g_filedata_logger_enabled = false;

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

static int CallLoggers(ThreadVars *tv, OutputLoggerThreadStore *store_list, Packet *p, File *ff,
        void *tx, const uint64_t tx_id, const uint8_t *data, uint32_t data_len, uint8_t flags,
        uint8_t dir)
{
    OutputFiledataLogger *logger = list;
    OutputLoggerThreadStore *store = store_list;
    int file_logged = 0;

    while (logger && store) {
        DEBUG_VALIDATE_BUG_ON(logger->LogFunc == NULL);

        SCLogDebug("logger %p", logger);
        PACKET_PROFILING_LOGGER_START(p, logger->logger_id);
        logger->LogFunc(tv, store->thread_data, (const Packet *)p, ff, tx, tx_id, data, data_len,
                flags, dir);
        PACKET_PROFILING_LOGGER_END(p, logger->logger_id);

        file_logged = 1;

        logger = logger->next;
        store = store->next;

        DEBUG_VALIDATE_BUG_ON(logger == NULL && store != NULL);
        DEBUG_VALIDATE_BUG_ON(logger != NULL && store == NULL);
    }
    return file_logged;
}

static void CloseFile(const Packet *p, Flow *f, File *file, void *txv)
{
    DEBUG_VALIDATE_BUG_ON((file->flags & FILE_STORED) != 0);

    AppLayerTxData *txd = AppLayerParserGetTxData(f->proto, f->alproto, txv);
    if (txd) {
        BUG_ON(f->alproto == ALPROTO_SMB && txd->files_logged != 0);
        txd->files_stored++;
    }
    file->flags |= FILE_STORED;
}

void OutputFiledataLogFfc(ThreadVars *tv, OutputFiledataLoggerThreadData *td, Packet *p,
        FileContainer *ffc, void *txv, const uint64_t tx_id, AppLayerTxData *txd,
        const uint8_t call_flags, const bool file_close, const bool file_trunc, const uint8_t dir)
{
    SCLogDebug("ffc %p", ffc);

    OutputLoggerThreadStore *store = td->store;
    File *ff;
    for (ff = ffc->head; ff != NULL; ff = ff->next) {

        FileApplyTxFlags(txd, dir, ff);

        uint8_t file_flags = call_flags;
#ifdef HAVE_MAGIC
        if (FileForceMagic() && ff->magic == NULL) {
            FilemagicThreadLookup(&td->magic_ctx, ff);
        }
#endif
        if (ff->flags & FILE_STORED) {
            continue;
        }

        if (!(ff->flags & FILE_STORE)) {
            continue;
        }

        /* if we have no data chunks left to log, we should still
         * close the logger(s) */
        if (FileDataSize(ff) == ff->content_stored && (file_trunc || file_close)) {
            if (ff->state < FILE_STATE_CLOSED) {
                FileCloseFilePtr(ff, NULL, 0, FILE_TRUNCATED);
            }
            CallLoggers(tv, store, p, ff, txv, tx_id, NULL, 0, OUTPUT_FILEDATA_FLAG_CLOSE, dir);
            CloseFile(p, p->flow, ff, txv);
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

        StreamingBufferGetDataAtOffset(ff->sb, &data, &data_len, ff->content_stored);

        const int file_logged =
                CallLoggers(tv, store, p, ff, txv, tx_id, data, data_len, file_flags, dir);
        if (file_logged) {
            ff->content_stored += data_len;

            /* all done */
            if (file_flags & OUTPUT_FILEDATA_FLAG_CLOSE) {
                CloseFile(p, p->flow, ff, txv);
            }
        }
    }
}

/** \brief thread init for the filedata logger
 *  This will run the thread init functions for the individual registered
 *  loggers */
TmEcode OutputFiledataLogThreadInit(ThreadVars *tv, OutputFiledataLoggerThreadData **data)
{
    OutputFiledataLoggerThreadData *td = SCMalloc(sizeof(*td));
    if (td == NULL)
        return TM_ECODE_FAILED;
    memset(td, 0x00, sizeof(*td));
    *data = td;

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
                /* todo */ BUG_ON(ts == NULL);
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

TmEcode OutputFiledataLogThreadDeinit(
        ThreadVars *tv, OutputFiledataLoggerThreadData *op_thread_data)
{
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

void OutputFiledataLoggerRegister(void)
{
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
