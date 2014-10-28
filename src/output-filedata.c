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
#include "output-filedata.h"
#include "app-layer.h"
#include "app-layer-parser.h"
#include "detect-filemagic.h"
#include "conf.h"
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
 * log module (e.g. http.log) with different output ctx'. */
typedef struct OutputFiledataLogger_ {
    FiledataLogger LogFunc;
    OutputCtx *output_ctx;
    struct OutputFiledataLogger_ *next;
    const char *name;
    TmmId module_id;
} OutputFiledataLogger;

static OutputFiledataLogger *list = NULL;
static char g_waldo[PATH_MAX] = "";
static SCMutex g_waldo_mutex = SCMUTEX_INITIALIZER;
static int g_waldo_init = 0;
static int g_waldo_deinit = 0;

int OutputRegisterFiledataLogger(const char *name, FiledataLogger LogFunc, OutputCtx *output_ctx)
{
    int module_id = TmModuleGetIdByName(name);
    if (module_id < 0)
        return -1;

    OutputFiledataLogger *op = SCMalloc(sizeof(*op));
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
        OutputFiledataLogger *t = list;
        while (t->next)
            t = t->next;
        t->next = op;
    }

    SCLogDebug("OutputRegisterTxLogger happy");
    return 0;
}

SC_ATOMIC_DECLARE(unsigned int, file_id);

static int CallLoggers(ThreadVars *tv, OutputLoggerThreadStore *store_list,
        Packet *p, const File *ff, const FileData *ffd, uint8_t flags)
{
    OutputFiledataLogger *logger = list;
    OutputLoggerThreadStore *store = store_list;
    int file_logged = 0;

    while (logger && store) {
        BUG_ON(logger->LogFunc == NULL);

        SCLogDebug("logger %p", logger);
        PACKET_PROFILING_TMM_START(p, logger->module_id);
        logger->LogFunc(tv, store->thread_data, (const Packet *)p, ff, ffd, flags);
        PACKET_PROFILING_TMM_END(p, logger->module_id);

        file_logged = 1;

        logger = logger->next;
        store = store->next;

        BUG_ON(logger == NULL && store != NULL);
        BUG_ON(logger != NULL && store == NULL);
    }
    return file_logged;
}

static TmEcode OutputFiledataLog(ThreadVars *tv, Packet *p, void *thread_data, PacketQueue *pq, PacketQueue *postpq)
{
    BUG_ON(thread_data == NULL);
    BUG_ON(list == NULL);

    OutputLoggerThreadData *op_thread_data = (OutputLoggerThreadData *)thread_data;
    OutputFiledataLogger *logger = list;
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

    FLOWLOCK_WRLOCK(f); // < need write lock for FiledataPrune below
    file_trunc = StreamTcpReassembleDepthReached(p);

    FileContainer *ffc = AppLayerParserGetFiles(p->proto, f->alproto,
                                                f->alstate, flags);
    SCLogDebug("ffc %p", ffc);
    if (ffc != NULL) {
        File *ff;
        for (ff = ffc->head; ff != NULL; ff = ff->next) {
            if (FileForceMagic() && ff->magic == NULL) {
                FilemagicGlobalLookup(ff);
            }

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
            if (ff->chunks_head == NULL && (file_trunc || file_close)) {
                CallLoggers(tv, store, p, ff, NULL, OUTPUT_FILEDATA_FLAG_CLOSE);
                ff->flags |= FILE_STORED;
                continue;
            }

            FileData *ffd;
            for (ffd = ff->chunks_head; ffd != NULL; ffd = ffd->next) {
                uint8_t flags = 0;
                int file_logged = 0;
                FileData *write_ffd = ffd;

                SCLogDebug("ffd %p", ffd);

                /* special case: on stream end we may inform the
                 * loggers that the file is truncated. In this
                 * case we already logged the current ffd, which
                 * is the last in our list. */
                if (ffd->stored == 1) {
                    if (!(file_close == 1 || ffd->next == NULL)) {
                        continue;
                    }

                    // call writer with NULL ffd, so it can 'close'
                    // so really a 'close' msg
                    write_ffd = NULL;
                    flags |= OUTPUT_FILEDATA_FLAG_CLOSE;
                }

                /* store */

                /* if file_id == 0, this is the first store of this file */
                if (ff->file_id == 0) {
                    /* new file */
                    ff->file_id = SC_ATOMIC_ADD(file_id, 1);
                    flags |= OUTPUT_FILEDATA_FLAG_OPEN;
                } else {
                    /* existing file */
                }

                /* if file needs to be closed or truncated, inform
                 * loggers */
                if ((file_close || file_trunc) && ff->state < FILE_STATE_CLOSED) {
                    ff->state = FILE_STATE_TRUNCATED;
                }

                /* for the last data chunk we have, also tell the logger
                 * we're closing up */
                if (ffd->next == NULL && ff->state >= FILE_STATE_CLOSED)
                    flags |= OUTPUT_FILEDATA_FLAG_CLOSE;

                /* do the actual logging */
                file_logged = CallLoggers(tv, store, p, ff, write_ffd, flags);

                if (file_logged) {
                    ffd->stored = 1;

                    /* all done */
                    if (flags & OUTPUT_FILEDATA_FLAG_CLOSE) {
                        ff->flags |= FILE_STORED;
                        break;
                    }
                }
            }
        }

        FilePrune(ffc);
    }

    FLOWLOCK_UNLOCK(f);
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
            (void) SC_ATOMIC_CAS(&file_id, 0, id);
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

    if (SC_ATOMIC_GET(file_id) == 0) {
        SCReturn;
    }

    FILE *fp = fopen(path, "w");
    if (fp == NULL) {
        SCLogInfo("couldn't open waldo: %s", strerror(errno));
        SCReturn;
    }

    snprintf(line, sizeof(line), "%u\n", SC_ATOMIC_GET(file_id));
    if (fwrite(line, strlen(line), 1, fp) != 1) {
        SCLogError(SC_ERR_FWRITE, "fwrite failed: %s", strerror(errno));
    }
    fclose(fp);
}

/** \brief thread init for the tx logger
 *  This will run the thread init functions for the individual registered
 *  loggers */
static TmEcode OutputFiledataLogThreadInit(ThreadVars *tv, void *initdata, void **data)
{
    OutputLoggerThreadData *td = SCMalloc(sizeof(*td));
    if (td == NULL)
        return TM_ECODE_FAILED;
    memset(td, 0x00, sizeof(*td));

    *data = (void *)td;

    SCLogDebug("OutputFiledataLogThreadInit happy (*data %p)", *data);

    OutputFiledataLogger *logger = list;
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
            char *s_default_log_dir = NULL;
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

    SCMutexLock(&g_waldo_mutex);
    if (g_waldo_deinit == 0) {
        if (strlen(g_waldo) > 0) {
            SCLogDebug("we have a waldo at %s", g_waldo);
            LogFiledataLogStoreWaldo(g_waldo);
        }
        g_waldo_deinit = 1;
    }
    SCMutexUnlock(&g_waldo_mutex);
    return TM_ECODE_OK;
}

static void OutputFiledataLogExitPrintStats(ThreadVars *tv, void *thread_data)
{
    OutputLoggerThreadData *op_thread_data = (OutputLoggerThreadData *)thread_data;
    OutputLoggerThreadStore *store = op_thread_data->store;
    OutputFiledataLogger *logger = list;

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

void TmModuleFiledataLoggerRegister (void)
{
    tmm_modules[TMM_FILEDATALOGGER].name = "__filedata_logger__";
    tmm_modules[TMM_FILEDATALOGGER].ThreadInit = OutputFiledataLogThreadInit;
    tmm_modules[TMM_FILEDATALOGGER].Func = OutputFiledataLog;
    tmm_modules[TMM_FILEDATALOGGER].ThreadExitPrintStats = OutputFiledataLogExitPrintStats;
    tmm_modules[TMM_FILEDATALOGGER].ThreadDeinit = OutputFiledataLogThreadDeinit;
    tmm_modules[TMM_FILEDATALOGGER].cap_flags = 0;

    SC_ATOMIC_INIT(file_id);
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
