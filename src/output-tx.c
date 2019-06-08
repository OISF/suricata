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
#include "output.h"
#include "output-tx.h"
#include "app-layer.h"
#include "app-layer-parser.h"
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
typedef struct OutputTxLogger_ {
    AppProto alproto;
    TxLogger LogFunc;
    TxLoggerCondition LogCondition;
    OutputCtx *output_ctx;
    struct OutputTxLogger_ *next;
    const char *name;
    LoggerId logger_id;
    uint32_t id;
    int tc_log_progress;
    int ts_log_progress;
    TmEcode (*ThreadInit)(ThreadVars *, const void *, void **);
    TmEcode (*ThreadDeinit)(ThreadVars *, void *);
    void (*ThreadExitPrintStats)(ThreadVars *, void *);
} OutputTxLogger;

static OutputTxLogger *list = NULL;

int OutputRegisterTxLogger(LoggerId id, const char *name, AppProto alproto,
                           TxLogger LogFunc,
                           OutputCtx *output_ctx, int tc_log_progress,
                           int ts_log_progress, TxLoggerCondition LogCondition,
                           ThreadInitFunc ThreadInit,
                           ThreadDeinitFunc ThreadDeinit,
                           void (*ThreadExitPrintStats)(ThreadVars *, void *))
{
    if (alproto != ALPROTO_UNKNOWN && !(AppLayerParserIsTxAware(alproto))) {
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
    op->logger_id = id;
    op->ThreadInit = ThreadInit;
    op->ThreadDeinit = ThreadDeinit;
    op->ThreadExitPrintStats = ThreadExitPrintStats;

    if (alproto == ALPROTO_UNKNOWN) {
        op->tc_log_progress = 0;
    } else if (tc_log_progress < 0) {
        op->tc_log_progress =
            AppLayerParserGetStateProgressCompletionStatus(alproto,
                                                           STREAM_TOCLIENT);
    } else {
        op->tc_log_progress = tc_log_progress;
    }

    if (alproto == ALPROTO_UNKNOWN) {
        op->ts_log_progress = 0;
    } else if (ts_log_progress < 0) {
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

static TmEcode OutputTxLog(ThreadVars *tv, Packet *p, void *thread_data)
{
    DEBUG_VALIDATE_BUG_ON(thread_data == NULL);
    if (list == NULL) {
        /* No child loggers registered. */
        return TM_ECODE_OK;
    }

    OutputLoggerThreadData *op_thread_data = (OutputLoggerThreadData *)thread_data;
    if (p->flow == NULL)
        return TM_ECODE_OK;

    Flow * const f = p->flow;
    const uint8_t ipproto = f->proto;
    const AppProto alproto = f->alproto;

    if (AppLayerParserProtocolHasLogger(p->proto, alproto) == 0)
        goto end;
    const LoggerId logger_expectation = AppLayerParserProtocolGetLoggerBits(p->proto, alproto);
    if (logger_expectation == 0)
        goto end;

    void *alstate = f->alstate;
    if (alstate == NULL) {
        SCLogDebug("no alstate");
        goto end;
    }

    const uint8_t ts_disrupt_flags = FlowGetDisruptionFlags(f, STREAM_TOSERVER);
    const uint8_t tc_disrupt_flags = FlowGetDisruptionFlags(f, STREAM_TOCLIENT);
    const uint64_t total_txs = AppLayerParserGetTxCnt(f, alstate);
    uint64_t tx_id = AppLayerParserGetTransactionLogId(f->alparser);
    uint64_t max_id = tx_id;
    int logged = 0;
    int gap = 0;

    AppLayerGetTxIteratorFunc IterFunc = AppLayerGetTxIterator(ipproto, alproto);
    AppLayerGetTxIterState state;
    memset(&state, 0, sizeof(state));

    while (1) {
        AppLayerGetTxIterTuple ires = IterFunc(ipproto, alproto, alstate, tx_id, total_txs, &state);
        if (ires.tx_ptr == NULL)
            break;
        void * const tx = ires.tx_ptr;
        tx_id = ires.tx_id;

        LoggerId tx_logged = AppLayerParserGetTxLogged(f, alstate, tx);
        const LoggerId tx_logged_old = tx_logged;
        SCLogDebug("logger: expect %08x, have %08x", logger_expectation, tx_logged);
        if (tx_logged == logger_expectation) {
            /* tx already fully logged */
            goto next_tx;
        }

        int tx_progress_ts = AppLayerParserGetStateProgress(p->proto, alproto,
                tx, ts_disrupt_flags);
        int tx_progress_tc = AppLayerParserGetStateProgress(p->proto, alproto,
                tx, tc_disrupt_flags);
        SCLogDebug("tx_progress_ts %d tx_progress_tc %d",
                tx_progress_ts, tx_progress_tc);

        const OutputTxLogger *logger = list;
        const OutputLoggerThreadStore *store = op_thread_data->store;

        DEBUG_VALIDATE_BUG_ON(logger == NULL && store != NULL);
        DEBUG_VALIDATE_BUG_ON(logger != NULL && store == NULL);
        DEBUG_VALIDATE_BUG_ON(logger == NULL && store == NULL);

        while (logger && store) {
            DEBUG_VALIDATE_BUG_ON(logger->LogFunc == NULL);

            SCLogDebug("logger %p, Alproto %d LogCondition %p, ts_log_progress %d "
                    "tc_log_progress %d", logger, logger->alproto, logger->LogCondition,
                    logger->ts_log_progress, logger->tc_log_progress);
            /* always invoke "wild card" tx loggers */
            if (logger->alproto == ALPROTO_UNKNOWN ||
                (logger->alproto == alproto &&
                 (tx_logged_old & (1<<logger->logger_id)) == 0)) {

                SCLogDebug("alproto match %d, logging tx_id %"PRIu64, logger->alproto, tx_id);

                if (!(AppLayerParserStateIssetFlag(f->alparser,
                                                   APP_LAYER_PARSER_EOF))) {
                    if (logger->LogCondition) {
                        int r = logger->LogCondition(tv, p, alstate, tx, tx_id);
                        if (r == FALSE) {
                            SCLogDebug("conditions not met, not logging");
                            goto next_logger;
                        }
                    } else {
                        if (tx_progress_tc < logger->tc_log_progress) {
                            SCLogDebug("progress not far enough, not logging");
                            goto next_logger;
                        }

                        if (tx_progress_ts < logger->ts_log_progress) {
                            SCLogDebug("progress not far enough, not logging");
                            goto next_logger;
                        }
                    }
                }

                SCLogDebug("Logging tx_id %"PRIu64" to logger %d", tx_id, logger->logger_id);
                PACKET_PROFILING_LOGGER_START(p, logger->logger_id);
                logger->LogFunc(tv, store->thread_data, p, f, alstate, tx, tx_id);
                PACKET_PROFILING_LOGGER_END(p, logger->logger_id);

                if (logger->alproto != ALPROTO_UNKNOWN) {
                    tx_logged |= (1<<logger->logger_id);
                }
            }

next_logger:
            logger = logger->next;
            store = store->next;

            DEBUG_VALIDATE_BUG_ON(logger == NULL && store != NULL);
            DEBUG_VALIDATE_BUG_ON(logger != NULL && store == NULL);
        }

        if (tx_logged != tx_logged_old) {
            SCLogDebug("logger: storing %08x (was %08x)",
                tx_logged, tx_logged_old);
            AppLayerParserSetTxLogged(p->proto, alproto, alstate, tx,
                    tx_logged);
        }

        /* If all loggers logged set a flag and update the last tx_id
         * that was logged.
         *
         * If not all loggers were logged we flag that there was a gap
         * so any subsequent transactions in this loop don't increase
         * the maximum ID that was logged. */
        if (!gap && tx_logged == logger_expectation) {
            logged = 1;
            max_id = tx_id;
        } else {
            gap = 1;
        }
next_tx:
        if (!ires.has_next)
            break;
        tx_id++;
    }

    /* Update the the last ID that has been logged with all
     * transactions before it. */
    if (logged) {
        SCLogDebug("updating log tx_id %"PRIu64, max_id);
        AppLayerParserSetTransactionLogId(f->alparser, max_id + 1);
    }

end:
    return TM_ECODE_OK;
}

/** \brief thread init for the tx logger
 *  This will run the thread init functions for the individual registered
 *  loggers */
static TmEcode OutputTxLogThreadInit(ThreadVars *tv, const void *initdata, void **data)
{
    OutputLoggerThreadData *td = SCMalloc(sizeof(*td));
    if (td == NULL)
        return TM_ECODE_FAILED;
    memset(td, 0x00, sizeof(*td));

    *data = (void *)td;
    SCLogDebug("OutputTxLogThreadInit happy (*data %p)", *data);

    OutputTxLogger *logger = list;
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

static TmEcode OutputTxLogThreadDeinit(ThreadVars *tv, void *thread_data)
{
    OutputLoggerThreadData *op_thread_data = (OutputLoggerThreadData *)thread_data;
    OutputLoggerThreadStore *store = op_thread_data->store;
    OutputTxLogger *logger = list;

    while (logger && store) {
        if (logger->ThreadDeinit) {
            logger->ThreadDeinit(tv, store->thread_data);
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
        if (logger->ThreadExitPrintStats) {
            logger->ThreadExitPrintStats(tv, store->thread_data);
        }

        logger = logger->next;
        store = store->next;
    }
}

void OutputTxLoggerRegister (void)
{
    OutputRegisterRootLogger(OutputTxLogThreadInit, OutputTxLogThreadDeinit,
        OutputTxLogExitPrintStats, OutputTxLog);
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
