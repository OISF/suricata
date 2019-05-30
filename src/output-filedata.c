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
static char g_waldo[PATH_MAX] = "";
static SCMutex g_waldo_mutex = SCMUTEX_INITIALIZER;
static int g_waldo_init = 0;
static int g_waldo_deinit = 0;

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

static void OutputFiledataLogFfc(ThreadVars *tv, OutputLoggerThreadStore *store,
        Packet *p, FileContainer *ffc, const uint8_t call_flags,
        const bool file_close, const bool file_trunc, const uint8_t dir)
{
    if (ffc != NULL) {
        File *ff;
        for (ff = ffc->head; ff != NULL; ff = ff->next) {
            uint8_t file_flags = call_flags;
#ifdef HAVE_MAGIC
            if (FileForceMagic() && ff->magic == NULL) {
                FilemagicGlobalLookup(ff);
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
                ff->flags |= FILE_STORED;
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
                    ff->flags |= FILE_STORED;
                }
            }
        }

        FilePrune(ffc);
    }
}

static TmEcode OutputFiledataLog(ThreadVars *tv, Packet *p, void *thread_data)
{
    DEBUG_VALIDATE_BUG_ON(thread_data == NULL);

    if (list == NULL) {
        /* No child loggers. */
        return TM_ECODE_OK;
    }

    OutputLoggerThreadData *op_thread_data = (OutputLoggerThreadData *)thread_data;
    OutputLoggerThreadStore *store = op_thread_data->store;

    /* no flow, no files */
    Flow * const f = p->flow;
    if (f == NULL || f->alstate == NULL) {
        SCReturnInt(TM_ECODE_OK);
    }

    const bool file_close_ts = ((p->flags & PKT_PSEUDO_STREAM_END) &&
            (p->flowflags & FLOW_PKT_TOSERVER));
    const bool file_close_tc = ((p->flags & PKT_PSEUDO_STREAM_END) &&
            (p->flowflags & FLOW_PKT_TOCLIENT));
    const bool file_trunc = StreamTcpReassembleDepthReached(p);

    FileContainer *ffc_ts = AppLayerParserGetFiles(p->proto, f->alproto,
                                                   f->alstate, STREAM_TOSERVER);
    FileContainer *ffc_tc = AppLayerParserGetFiles(p->proto, f->alproto,
                                                   f->alstate, STREAM_TOCLIENT);
    SCLogDebug("ffc_ts %p", ffc_ts);
    OutputFiledataLogFfc(tv, store, p, ffc_ts, STREAM_TOSERVER, file_close_ts, file_trunc, STREAM_TOSERVER);
    SCLogDebug("ffc_tc %p", ffc_tc);
    OutputFiledataLogFfc(tv, store, p, ffc_tc, STREAM_TOCLIENT, file_close_tc, file_trunc, STREAM_TOCLIENT);

    return TM_ECODE_OK;
}

/**
 *  \internal
 *
 *  \brief Open the waldo file (if available) and load the file_id
 *
 *  \param path full path for the waldo file
 */
static void LogFiledataLogLoadWaldo(const char *path)
{
    char line[16] = "";
    unsigned int id = 0;

    FILE *fp = fopen(path, "r");
    if (fp == NULL) {
        SCLogInfo("couldn't open waldo: %s", strerror(errno));
        SCReturn;
    }

    if (fgets(line, (int)sizeof(line), fp) != NULL) {
        if (sscanf(line, "%10u", &id) == 1) {
            SCLogInfo("id %u", id);
            (void) SC_ATOMIC_CAS(&g_file_store_id, 0, id);
        }
    }
    fclose(fp);
}

/**
 *  \internal
 *
 *  \brief Store the waldo file based on the file_id
 *
 *  \param path full path for the waldo file
 */
static void LogFiledataLogStoreWaldo(const char *path)
{
    char line[16] = "";

    if (SC_ATOMIC_GET(g_file_store_id) == 0) {
        SCReturn;
    }

    FILE *fp = fopen(path, "w");
    if (fp == NULL) {
        SCLogInfo("couldn't open waldo: %s", strerror(errno));
        SCReturn;
    }

    snprintf(line, sizeof(line), "%u\n", SC_ATOMIC_GET(g_file_store_id));
    if (fwrite(line, strlen(line), 1, fp) != 1) {
        SCLogError(SC_ERR_FWRITE, "fwrite failed: %s", strerror(errno));
    }
    fclose(fp);
}

/** \brief thread init for the tx logger
 *  This will run the thread init functions for the individual registered
 *  loggers */
static TmEcode OutputFiledataLogThreadInit(ThreadVars *tv, const void *initdata, void **data)
{
    OutputLoggerThreadData *td = SCMalloc(sizeof(*td));
    if (td == NULL)
        return TM_ECODE_FAILED;
    memset(td, 0x00, sizeof(*td));

    *data = (void *)td;

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

    SCMutexLock(&g_waldo_mutex);
    if (g_waldo_init == 0) {
        ConfNode *node = ConfGetNode("file-store-waldo");
        if (node == NULL) {
            ConfNode *outputs = ConfGetNode("outputs");
            if (outputs) {
                ConfNode *output;
                TAILQ_FOREACH(output, &outputs->head, next) {
                    /* we only care about file and file-store */
                    if (!(strcmp(output->val, "file") == 0 || strcmp(output->val, "file-store") == 0))
                        continue;

                    ConfNode *file = ConfNodeLookupChild(output, output->val);
                    BUG_ON(file == NULL);
                    if (file == NULL) {
                        SCLogDebug("file-store failed, lets try 'file'");
                        file = ConfNodeLookupChild(outputs, "file");
                        if (file == NULL)
                            SCLogDebug("file failed as well, giving up");
                    }

                    if (file != NULL) {
                        node = ConfNodeLookupChild(file, "waldo");
                        if (node == NULL)
                            SCLogDebug("no waldo node");
                    }
                }
            }
        }
        if (node != NULL) {
            const char *s_default_log_dir = NULL;
            s_default_log_dir = ConfigGetLogDirectory();

            const char *waldo = node->val;
            SCLogDebug("loading waldo %s", waldo);
            if (waldo != NULL && strlen(waldo) > 0) {
                if (PathIsAbsolute(waldo)) {
                    snprintf(g_waldo, sizeof(g_waldo), "%s", waldo);
                } else {
                    snprintf(g_waldo, sizeof(g_waldo), "%s/%s", s_default_log_dir, waldo);
                }

                SCLogDebug("loading waldo file %s", g_waldo);
                LogFiledataLogLoadWaldo(g_waldo);
            }
        }
        g_waldo_init = 1;
    }
    SCMutexUnlock(&g_waldo_mutex);
    return TM_ECODE_OK;
}

static TmEcode OutputFiledataLogThreadDeinit(ThreadVars *tv, void *thread_data)
{
    OutputLoggerThreadData *op_thread_data = (OutputLoggerThreadData *)thread_data;
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

    SCMutexLock(&g_waldo_mutex);
    if (g_waldo_deinit == 0) {
        if (strlen(g_waldo) > 0) {
            SCLogDebug("we have a waldo at %s", g_waldo);
            LogFiledataLogStoreWaldo(g_waldo);
        }
        g_waldo_deinit = 1;
    }
    SCMutexUnlock(&g_waldo_mutex);

    SCFree(op_thread_data);
    return TM_ECODE_OK;
}

static void OutputFiledataLogExitPrintStats(ThreadVars *tv, void *thread_data)
{
    OutputLoggerThreadData *op_thread_data = (OutputLoggerThreadData *)thread_data;
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

void OutputFiledataLoggerRegister(void)
{
    OutputRegisterRootLogger(OutputFiledataLogThreadInit,
        OutputFiledataLogThreadDeinit, OutputFiledataLogExitPrintStats,
        OutputFiledataLog);
    SC_ATOMIC_INIT(g_file_store_id);
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
