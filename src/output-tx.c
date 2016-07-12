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
 * AppLayer TX Logger Output registration functions
 */

#include "suricata-common.h"
#include "tm-modules.h"
#include "output-tx.h"
#include "app-layer.h"
#include "app-layer-parser.h"
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
typedef struct OutputTxLogger_ {
    AppProto alproto;
    TxLogger LogFunc;
    TxLoggerCondition LogCondition;
    OutputCtx *output_ctx;
    struct OutputTxLogger_ *next;
    const char *name;
    TmmId module_id;
    uint32_t id;
    int tc_log_progress;
    int ts_log_progress;
} OutputTxLogger;

static OutputTxLogger *list = NULL;

int OutputRegisterTxLogger(const char *name, AppProto alproto, TxLogger LogFunc,
                           OutputCtx *output_ctx, int tc_log_progress,
                           int ts_log_progress, TxLoggerCondition LogCondition)
{
    int module_id = TmModuleGetIdByName(name);
    if (module_id < 0)
        return -1;

    if (!(AppLayerParserIsTxAware(alproto))) {
        SCLogNotice("%s logger not enabled: protocol %s is disabled",
            name, AppProtoToString(alproto));
        return -1;
    }

    OutputTxLogger *op = SCMalloc(sizeof(*op));
    if (op == NULL)
        return -1;
    memset(op, 0x00, sizeof(*op));

    op->alproto = alproto;
    op->LogFunc = LogFunc;
    op->LogCondition = LogCondition;
    op->output_ctx = output_ctx;
    op->name = name;
    op->module_id = (TmmId) module_id;

    if (tc_log_progress < 0) {
        op->tc_log_progress =
            AppLayerParserGetStateProgressCompletionStatus(alproto,
                                                           STREAM_TOCLIENT);
    } else {
        op->tc_log_progress = tc_log_progress;
    }

    if (ts_log_progress < 0) {
        op->ts_log_progress =
            AppLayerParserGetStateProgressCompletionStatus(alproto,
                                                           STREAM_TOSERVER);
    } else {
        op->ts_log_progress = ts_log_progress;
    }

    if (list == NULL) {
        op->id = 1;
        list = op;
    } else {
        OutputTxLogger *t = list;
        while (t->next)
            t = t->next;
        if (t->id * 2 > UINT32_MAX) {
            SCLogError(SC_ERR_FATAL, "Too many loggers registered.");
            exit(EXIT_FAILURE);
        }
        op->id = t->id * 2;
        t->next = op;
    }

    SCLogDebug("OutputRegisterTxLogger happy");
    return 0;
}

static TmEcode OutputTxLog(ThreadVars *tv, Packet *p, void *thread_data, PacketQueue *pq, PacketQueue *postpq)
{
    BUG_ON(thread_data == NULL);
    BUG_ON(list == NULL);

    OutputLoggerThreadData *op_thread_data = (OutputLoggerThreadData *)thread_data;
    OutputTxLogger *logger = list;
    OutputLoggerThreadStore *store = op_thread_data->store;

    BUG_ON(logger == NULL && store != NULL);
    BUG_ON(logger != NULL && store == NULL);
    BUG_ON(logger == NULL && store == NULL);

    if (p->flow == NULL)
        return TM_ECODE_OK;

    Flow * const f = p->flow;

    FLOWLOCK_WRLOCK(f); /* WRITE lock before we updated flow logged id */
    AppProto alproto = f->alproto;

    if (AppLayerParserProtocolIsTxAware(p->proto, alproto) == 0)
        goto end;
    if (AppLayerParserProtocolHasLogger(p->proto, alproto) == 0)
        goto end;

    void *alstate = f->alstate;
    if (alstate == NULL) {
        SCLogDebug("no alstate");
        goto end;
    }

    uint64_t total_txs = AppLayerParserGetTxCnt(p->proto, alproto, alstate);
    uint64_t tx_id = AppLayerParserGetTransactionLogId(f->alparser);

    for (; tx_id < total_txs; tx_id++)
    {
        int logger_not_logged = 0;

        void *tx = AppLayerParserGetTx(p->proto, alproto, alstate, tx_id);
        if (tx == NULL) {
            SCLogDebug("tx is NULL not logging");
            continue;
        }

        int tx_progress_ts = AppLayerParserGetStateProgress(p->proto, alproto,
                tx, FlowGetDisruptionFlags(f, STREAM_TOSERVER));

        int tx_progress_tc = AppLayerParserGetStateProgress(p->proto, alproto,
                tx, FlowGetDisruptionFlags(f, STREAM_TOCLIENT));

        SCLogDebug("tx_progress_ts %d tx_progress_tc %d",
                tx_progress_ts, tx_progress_tc);

        // call each logger here (pseudo code)
        logger = list;
        store = op_thread_data->store;
        while (logger && store) {
            BUG_ON(logger->LogFunc == NULL);

            SCLogDebug("logger %p, LogCondition %p, ts_log_progress %d "
                    "tc_log_progress %d", logger, logger->LogCondition,
                    logger->ts_log_progress, logger->tc_log_progress);
            if (logger->alproto == alproto) {
                SCLogDebug("alproto match, logging tx_id %ju", tx_id);

                if (AppLayerParserGetTxLogged(p->proto, alproto, alstate, tx,
                        logger->id)) {
                    SCLogDebug("logger has already logged this transaction");

                    goto next;
                }

                if (!(AppLayerParserStateIssetFlag(f->alparser,
                                                   APP_LAYER_PARSER_EOF))) {
                    if (logger->LogCondition) {
                        int r = logger->LogCondition(tv, p, alstate, tx, tx_id);
                        if (r == FALSE) {
                            SCLogDebug("conditions not met, not logging");
                            logger_not_logged = 1;
                            goto next;
                        }
                    } else {
                        if (tx_progress_tc < logger->tc_log_progress) {
                            SCLogDebug("progress not far enough, not logging");
                            logger_not_logged = 1;
                            goto next;
                        }

                        if (tx_progress_ts < logger->ts_log_progress) {
                            SCLogDebug("progress not far enough, not logging");
                            logger_not_logged = 1;
                            goto next;
                        }
                    }
                }

                PACKET_PROFILING_TMM_START(p, logger->module_id);
                logger->LogFunc(tv, store->thread_data, p, f, alstate, tx, tx_id);
                PACKET_PROFILING_TMM_END(p, logger->module_id);

                AppLayerParserSetTxLogged(p->proto, alproto, alstate, tx,
                                          logger->id);
            }

next:
            logger = logger->next;
            store = store->next;

            BUG_ON(logger == NULL && store != NULL);
            BUG_ON(logger != NULL && store == NULL);
        }

        if (!logger_not_logged) {
            SCLogDebug("updating log tx_id %ju", tx_id);
            AppLayerParserSetTransactionLogId(f->alparser);
        }
    }

end:
    FLOWLOCK_UNLOCK(f);
    return TM_ECODE_OK;
}

/** \brief thread init for the tx logger
 *  This will run the thread init functions for the individual registered
 *  loggers */
static TmEcode OutputTxLogThreadInit(ThreadVars *tv, void *initdata, void **data)
{
    OutputLoggerThreadData *td = SCMalloc(sizeof(*td));
    if (td == NULL)
        return TM_ECODE_FAILED;
    memset(td, 0x00, sizeof(*td));

    *data = (void *)td;

    SCLogDebug("OutputTxLogThreadInit happy (*data %p)", *data);

    OutputTxLogger *logger = list;
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

static TmEcode OutputTxLogThreadDeinit(ThreadVars *tv, void *thread_data)
{
    OutputLoggerThreadData *op_thread_data = (OutputLoggerThreadData *)thread_data;
    OutputLoggerThreadStore *store = op_thread_data->store;
    OutputTxLogger *logger = list;

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

static void OutputTxLogExitPrintStats(ThreadVars *tv, void *thread_data)
{
    OutputLoggerThreadData *op_thread_data = (OutputLoggerThreadData *)thread_data;
    OutputLoggerThreadStore *store = op_thread_data->store;
    OutputTxLogger *logger = list;

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

void TmModuleTxLoggerRegister (void)
{
    tmm_modules[TMM_TXLOGGER].name = "__tx_logger__";
    tmm_modules[TMM_TXLOGGER].ThreadInit = OutputTxLogThreadInit;
    tmm_modules[TMM_TXLOGGER].Func = OutputTxLog;
    tmm_modules[TMM_TXLOGGER].ThreadExitPrintStats = OutputTxLogExitPrintStats;
    tmm_modules[TMM_TXLOGGER].ThreadDeinit = OutputTxLogThreadDeinit;
    tmm_modules[TMM_TXLOGGER].cap_flags = 0;
}

void OutputTxShutdown(void)
{
    OutputTxLogger *logger = list;
    while (logger) {
        OutputTxLogger *next_logger = logger->next;
        SCFree(logger);
        logger = next_logger;
    }
    list = NULL;
}
