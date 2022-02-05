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
#include "util-profiling.h"
#include "util-validate.h"
#include "util-magic.h"

bool g_file_logger_enabled = false;

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

static void CloseFile(const Packet *p, Flow *f, AppLayerTxData *txd, File *file)
{
    DEBUG_VALIDATE_BUG_ON((file->flags & FILE_LOGGED) != 0);
    DEBUG_VALIDATE_BUG_ON(f->alproto == ALPROTO_SMB && txd->files_logged != 0);
    DEBUG_VALIDATE_BUG_ON(f->alproto == ALPROTO_FTPDATA && txd->files_logged != 0);
    txd->files_logged++;
    DEBUG_VALIDATE_BUG_ON(txd->files_logged > txd->files_opened);
    file->flags |= FILE_LOGGED;
    SCLogDebug("ff %p FILE_LOGGED", file);
}

void OutputFileLogFfc(ThreadVars *tv, OutputFileLoggerThreadData *op_thread_data, Packet *p,
        FileContainer *ffc, void *txv, const uint64_t tx_id, AppLayerTxData *txd,
        const bool file_close, const bool file_trunc, uint8_t dir)
{
    if (ffc->head == NULL)
        return;

    SCLogDebug("ffc %p ffc->head %p file_close %d file_trunc %d dir %s", ffc,
            ffc ? ffc->head : NULL, file_close, file_trunc, dir == STREAM_TOSERVER ? "ts" : "tc");
    File *ff;
    for (ff = ffc->head; ff != NULL; ff = ff->next) {
        SCLogDebug("ff %p pre-FILE_LOGGED", ff);
        if (ff->flags & FILE_LOGGED)
            continue;

        FileApplyTxFlags(txd, dir, ff);

        SCLogDebug("ff %p state %u post-FILE_LOGGED", ff, ff->state);

        if (file_trunc && ff->state < FILE_STATE_CLOSED) {
            SCLogDebug("file_trunc %d ff->state %u => FILE_STATE_TRUNCATED", file_trunc, ff->state);
            ff->state = FILE_STATE_TRUNCATED;
        }

        if (file_close && ff->state < FILE_STATE_CLOSED) {
            SCLogDebug("file_close %d ff->state %u => FILE_STATE_TRUNCATED", file_close, ff->state);
            ff->state = FILE_STATE_TRUNCATED;
        }

        SCLogDebug("ff %p state %u", ff, ff->state);

        if (ff->state > FILE_STATE_OPENED) {
            SCLogDebug("FILE LOGGING");
            bool file_logged = false;
#ifdef HAVE_MAGIC
            if (FileForceMagic() && ff->magic == NULL) {
                FilemagicThreadLookup(&op_thread_data->magic_ctx, ff);
            }
#endif
            const OutputFileLogger *logger = list;
            const OutputLoggerThreadStore *store = op_thread_data->store;
            while (logger && store) {
                DEBUG_VALIDATE_BUG_ON(logger->LogFunc == NULL);

                SCLogDebug("logger %p", logger);
                PACKET_PROFILING_LOGGER_START(p, logger->logger_id);
                logger->LogFunc(tv, store->thread_data, (const Packet *)p, (const File *)ff, txv,
                        tx_id, dir);
                PACKET_PROFILING_LOGGER_END(p, logger->logger_id);
                file_logged = true;

                logger = logger->next;
                store = store->next;

                DEBUG_VALIDATE_BUG_ON(logger == NULL && store != NULL);
                DEBUG_VALIDATE_BUG_ON(logger != NULL && store == NULL);
            }

            if (file_logged) {
                CloseFile(p, p->flow, txd, ff);
            }
        }
    }
}

/** \brief thread init for the file logger
 *  This will run the thread init functions for the individual registered
 *  loggers */
TmEcode OutputFileLogThreadInit(ThreadVars *tv, OutputFileLoggerThreadData **data)
{
    OutputFileLoggerThreadData *td = SCCalloc(1, sizeof(*td));
    if (td == NULL)
        return TM_ECODE_FAILED;
    *data = td;

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

TmEcode OutputFileLogThreadDeinit(ThreadVars *tv, OutputFileLoggerThreadData *op_thread_data)
{
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

void OutputFileLoggerRegister(void)
{
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
