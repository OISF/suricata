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
    OutputCtx *output_ctx;
    struct OutputTxLogger_ *next;
    const char *name;
    TmmId module_id;
    int directional;
} OutputTxLogger;

static OutputTxLogger *list = NULL;

int OutputRegisterTxLogger(const char *name, AppProto alproto, TxLogger LogFunc, OutputCtx *output_ctx, int directional)
{
    int module_id = TmModuleGetIdByName(name);
    if (module_id < 0)
        return -1;

    OutputTxLogger *op = SCMalloc(sizeof(*op));
    if (op == NULL)
        return -1;
    memset(op, 0x00, sizeof(*op));

    op->alproto = alproto;
    op->LogFunc = LogFunc;
    op->output_ctx = output_ctx;
    op->name = name;
    op->module_id = (TmmId) module_id;
    op->directional = directional;

    if (list == NULL)
        list = op;
    else {
        OutputTxLogger *t = list;
        while (t->next)
            t = t->next;
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
    int tx_progress_done_value_ts =
        AppLayerParserGetStateProgressCompletionStatus(p->proto, alproto,
                                                       STREAM_TOSERVER);
    int tx_progress_done_value_tc =
        AppLayerParserGetStateProgressCompletionStatus(p->proto, alproto,
                                                       STREAM_TOCLIENT);

    uint64_t tx_id_ts = AppLayerParserGetTransactionLogId(f->alparser,
        STREAM_TOSERVER);
    uint64_t tx_id_tc = AppLayerParserGetTransactionLogId(f->alparser,
        STREAM_TOCLIENT);
    uint64_t tx_id = MIN(tx_id_ts, tx_id_tc);

    for (; tx_id < total_txs; tx_id++)
    {
        int ts_ready = 0;
        int tc_ready = 0;
        int proto_logged = 0;

        void *tx = AppLayerParserGetTx(p->proto, alproto, alstate, tx_id);
        if (tx == NULL) {
            SCLogDebug("tx is NULL not logging");
            continue;
        }

        if (!(AppLayerParserStateIssetFlag(f->alparser, APP_LAYER_PARSER_EOF)))
        {
            int tx_progress = AppLayerParserGetStateProgress(p->proto, alproto,
                tx, FlowGetDisruptionFlags(f, STREAM_TOSERVER));
            if (tx_progress == tx_progress_done_value_ts) {
                ts_ready = 1;
            }

            tx_progress = AppLayerParserGetStateProgress(p->proto, alproto,
                tx, FlowGetDisruptionFlags(f, STREAM_TOCLIENT));
            if (tx_progress == tx_progress_done_value_tc) {
                tc_ready = 1;
            }
        }

        if (!(ts_ready || tc_ready)) {
            SCLogNotice("progress not for enough, not logging");
            break;
        }

        /* Prevent the processing of one direction getting farther
         * ahead than the other.
         *
         * This is possible if over lapping transactions happen where
         * a response for a newer TX is seen before the response for
         * an older TX.
         *
         * This basically serializes the logging in transaction order,
         * but loses the order the messages may have been seen on the
         * wire, but is consistent with the behaviour prior to
         * per-direction TX logging.
         */
        if (tc_ready && tx_id > tx_id_tc) {
            break;
        }
        if (ts_ready && tx_id > tx_id_ts) {
            break;
        }

        // call each logger here (pseudo code)
        logger = list;
        store = op_thread_data->store;
        while (logger && store) {
            BUG_ON(logger->LogFunc == NULL);

            /* Immediately skip to next if this logger is not
             * directional and both sides are not ready. */
            if (!logger->directional) {
                if (!(ts_ready && tc_ready)) {
                    goto next;
                }
            }

            SCLogDebug("logger %p", logger);
            if (logger->alproto == alproto) {

                SCLogDebug("alproto match, logging tx_id %ju", tx_id);

                PACKET_PROFILING_TMM_START(p, logger->module_id);
                if (logger->directional) {
                    SCLogInfo("Logging directional TX: "
                        "ts_ready: %d; tc_ready: %d; tx_id: %"PRIu64"; "
                        "tx_id_ts: %"PRIu64"; tx_id_tc: %"PRIu64,
                        ts_ready, tc_ready, tx_id, tx_id_ts, tx_id_tc);
                    if (ts_ready && tx_id_ts <= tx_id) {
                        logger->LogFunc(tv, store->thread_data, p, f,
                            STREAM_TOSERVER, alstate, tx, tx_id);
                        proto_logged = 1;
                    }
                    if (tc_ready && tx_id_tc <= tx_id) {
                        logger->LogFunc(tv, store->thread_data, p, f,
                            STREAM_TOCLIENT, alstate, tx, tx_id);
                        proto_logged = 1;
                    }
                }
                else {
                    logger->LogFunc(tv, store->thread_data, p, f, 0, alstate,
                        tx, tx_id);
                    proto_logged = 1;
                }
                PACKET_PROFILING_TMM_END(p, logger->module_id);
            }

        next:
            logger = logger->next;
            store = store->next;

            BUG_ON(logger == NULL && store != NULL);
            BUG_ON(logger != NULL && store == NULL);
        }

        if (proto_logged) {
            SCLogDebug("updating log tx_id %ju", tx_id);
            if (ts_ready && tx_id_ts <= tx_id) {
                AppLayerParserSetTransactionLogId(f->alparser, STREAM_TOSERVER);
            }
            if (tc_ready && tx_id_tc <= tx_id) {
                AppLayerParserSetTransactionLogId(f->alparser, STREAM_TOCLIENT);
            }
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
