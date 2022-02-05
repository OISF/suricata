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

/** per thread data for this module, contains a list of per thread
 *  data for the packet loggers. */
typedef struct OutputTxLoggerThreadData_ {
    OutputLoggerThreadStore *store[ALPROTO_MAX];

    /* thread local data from file api */
    OutputFileLoggerThreadData *file;
    /* thread local data from filedata api */
    OutputFiledataLoggerThreadData *filedata;
} OutputTxLoggerThreadData;

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

static OutputTxLogger *list[ALPROTO_MAX] = { NULL };

int OutputRegisterTxLogger(LoggerId id, const char *name, AppProto alproto,
                           TxLogger LogFunc,
                           OutputCtx *output_ctx, int tc_log_progress,
                           int ts_log_progress, TxLoggerCondition LogCondition,
                           ThreadInitFunc ThreadInit,
                           ThreadDeinitFunc ThreadDeinit,
                           void (*ThreadExitPrintStats)(ThreadVars *, void *))
{
    if (alproto != ALPROTO_UNKNOWN && !(AppLayerParserIsEnabled(alproto))) {
        SCLogDebug(
                "%s logger not enabled: protocol %s is disabled", name, AppProtoToString(alproto));
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

    if (list[alproto] == NULL) {
        op->id = 1;
        list[alproto] = op;
    } else {
        OutputTxLogger *t = list[alproto];
        while (t->next)
            t = t->next;
        if (t->id * 2 > UINT32_MAX) {
            FatalError(SC_ERR_FATAL, "Too many loggers registered.");
        }
        op->id = t->id * 2;
        t->next = op;
    }

    SCLogDebug("OutputRegisterTxLogger happy");
    return 0;
}

extern bool g_file_logger_enabled;
extern bool g_filedata_logger_enabled;

/** \brief run the per tx file logging
 *  \todo clean up various end of tx/stream etc indicators
 */
static inline void OutputTxLogFiles(ThreadVars *tv, OutputFileLoggerThreadData *file_td,
        OutputFiledataLoggerThreadData *filedata_td, Packet *p, Flow *f, void *tx,
        const uint64_t tx_id, AppLayerTxData *txd, const bool tx_complete, const bool ts_ready,
        const bool tc_ready, const bool ts_eof, const bool tc_eof, const bool eof)
{
    int packet_dir;
    int opposing_dir;
    bool packet_dir_ready;
    const bool opposing_dir_ready = eof;
    bool opposing_tx_ready;
    if (p->flowflags & FLOW_PKT_TOSERVER) {
        packet_dir = STREAM_TOSERVER;
        opposing_dir = STREAM_TOCLIENT;
        packet_dir_ready = eof | ts_ready | ts_eof;
        opposing_tx_ready = tc_ready;
    } else if (p->flowflags & FLOW_PKT_TOCLIENT) {
        packet_dir = STREAM_TOCLIENT;
        opposing_dir = STREAM_TOSERVER;
        packet_dir_ready = eof | tc_ready | tc_eof;
        opposing_tx_ready = ts_ready;
    } else {
        abort();
    }

    SCLogDebug("eof %d ts_ready %d ts_eof %d", eof, ts_ready, ts_eof);
    SCLogDebug("eof %d tc_ready %d tc_eof %d", eof, tc_ready, tc_eof);

    SCLogDebug("packet dir %s opposing %s packet_dir_ready %d opposing_dir_ready %d",
            packet_dir == STREAM_TOSERVER ? "TOSERVER" : "TOCLIENT",
            opposing_dir == STREAM_TOSERVER ? "TOSERVER" : "TOCLIENT", packet_dir_ready,
            opposing_dir_ready);

    FileContainer *ffc = AppLayerParserGetTxFiles(f, tx, packet_dir);
    FileContainer *ffc_opposing = AppLayerParserGetTxFiles(f, tx, opposing_dir);

    /* see if opposing side is finished: if no file support in this direction, of is not
     * files and tx is done for opposing dir. */
    bool opposing_finished =
            ffc_opposing == NULL || (ffc_opposing->head == NULL && opposing_tx_ready);
    SCLogDebug("opposing_finished %d ffc_opposing %p ffc_opposing->head %p opposing_tx_ready %d",
            opposing_finished, ffc_opposing, ffc_opposing ? ffc_opposing->head : NULL,
            opposing_tx_ready);

    if (ffc || ffc_opposing)
        SCLogDebug("pcap_cnt %" PRIu64 " flow %p tx %p tx_id %" PRIu64
                   " ffc %p ffc_opposing %p tx_complete %d",
                p->pcap_cnt, f, tx, tx_id, ffc, ffc_opposing, tx_complete);

    if (ffc) {
        const bool file_close = ((p->flags & PKT_PSEUDO_STREAM_END)) | eof;
        const bool file_trunc = StreamTcpReassembleDepthReached(p) | eof;
        SCLogDebug("tx: calling files: ffc %p head %p file_close %d file_trunc %d", ffc, ffc->head,
                file_close, file_trunc);
        if (filedata_td)
            OutputFiledataLogFfc(tv, filedata_td, p, ffc, tx, tx_id, txd, packet_dir, file_close,
                    file_trunc, packet_dir);
        if (file_td)
            OutputFileLogFfc(
                    tv, file_td, p, ffc, tx, tx_id, txd, file_close, file_trunc, packet_dir);
    }
    /* if EOF and we support files, do a final write out */
    if (opposing_dir_ready && ffc_opposing != NULL) {
        const bool file_close = ((p->flags & PKT_PSEUDO_STREAM_END)) | tx_complete | eof;
        const bool file_trunc = StreamTcpReassembleDepthReached(p) | eof;
        opposing_finished = true;
        SCLogDebug("tx: calling for opposing direction files: file_close:%s file_trunc:%s",
                file_close ? "true" : "false", file_trunc ? "true" : "false");
        if (filedata_td)
            OutputFiledataLogFfc(tv, filedata_td, p, ffc_opposing, tx, tx_id, txd, opposing_dir,
                    file_close, file_trunc, opposing_dir);
        if (file_td)
            OutputFileLogFfc(tv, file_td, p, ffc_opposing, tx, tx_id, txd, file_close, file_trunc,
                    opposing_dir);
    } else {
        // BUG_ON(opposing_finished);
    }

    const bool tx_done =
            packet_dir_ready && opposing_finished; // TODO rename. Idea is to only flag as complete
                                                   // if we are TC or if there are no TC files
    SCLogDebug("tx_done %d packet_dir_ready %d opposing_finished %d", tx_done, packet_dir_ready,
            opposing_finished);

    /* if not a file tx or if tx is done, set logger flags so tx can move on */
    const bool is_file_tx = (ffc != NULL || ffc_opposing != NULL);
    if (!is_file_tx || tx_done) {
        SCLogDebug("is_file_tx %d tx_done %d", is_file_tx, tx_done);
        if (file_td) {
            txd->logged.flags |= BIT_U32(LOGGER_FILE);
            SCLogDebug("setting LOGGER_FILE => %08x", txd->logged.flags);
        }
        if (filedata_td) {
            txd->logged.flags |= BIT_U32(LOGGER_FILEDATA);
            SCLogDebug("setting LOGGER_FILEDATA => %08x", txd->logged.flags);
        }
    } else {
        SCLogDebug("pcap_cnt %" PRIu64 " flow %p tx %p tx_id %" PRIu64
                   " NOT SETTING FILE FLAGS ffc %p ffc_opposing %p tx_complete %d",
                p->pcap_cnt, f, tx, tx_id, ffc, ffc_opposing, tx_complete);
    }
}

static void OutputTxLogList0(ThreadVars *tv, OutputTxLoggerThreadData *op_thread_data, Packet *p,
        Flow *f, void *tx, const uint64_t tx_id)
{
    const OutputTxLogger *logger = list[ALPROTO_UNKNOWN];
    const OutputLoggerThreadStore *store = op_thread_data->store[ALPROTO_UNKNOWN];

    DEBUG_VALIDATE_BUG_ON(logger == NULL && store != NULL);
    DEBUG_VALIDATE_BUG_ON(logger != NULL && store == NULL);
    DEBUG_VALIDATE_BUG_ON(logger == NULL && store == NULL);

    while (logger && store) {
        DEBUG_VALIDATE_BUG_ON(logger->LogFunc == NULL);

        SCLogDebug("logger %p", logger);

        /* always invoke "wild card" tx loggers */
        SCLogDebug("Logging tx_id %"PRIu64" to logger %d", tx_id, logger->logger_id);
        PACKET_PROFILING_LOGGER_START(p, logger->logger_id);
        logger->LogFunc(tv, store->thread_data, p, f, f->alstate, tx, tx_id);
        PACKET_PROFILING_LOGGER_END(p, logger->logger_id);

        logger = logger->next;
        store = store->next;

        DEBUG_VALIDATE_BUG_ON(logger == NULL && store != NULL);
        DEBUG_VALIDATE_BUG_ON(logger != NULL && store == NULL);
    }
}

struct Ctx {
    uint32_t tx_logged_old;
    uint32_t tx_logged;
};

static void OutputTxLogCallLoggers(ThreadVars *tv, OutputTxLoggerThreadData *op_thread_data,
        const OutputTxLogger *logger, const OutputLoggerThreadStore *store, Packet *p, Flow *f,
        void *alstate, void *tx, const uint64_t tx_id, const AppProto alproto, const bool eof,
        const int tx_progress_ts, const int tx_progress_tc, struct Ctx *ctx)
{
    DEBUG_VALIDATE_BUG_ON(logger == NULL && store != NULL);
    DEBUG_VALIDATE_BUG_ON(logger != NULL && store == NULL);
    // DEBUG_VALIDATE_BUG_ON(logger == NULL && store == NULL);

    while (logger && store) {
        DEBUG_VALIDATE_BUG_ON(logger->LogFunc == NULL);
        DEBUG_VALIDATE_BUG_ON(logger->alproto != alproto);

        SCLogDebug("logger %p, Alproto %d LogCondition %p, ts_log_progress %d "
                   "tc_log_progress %d",
                logger, logger->alproto, logger->LogCondition, logger->ts_log_progress,
                logger->tc_log_progress);
        if ((ctx->tx_logged_old & BIT_U32(logger->logger_id)) == 0) {
            SCLogDebug("alproto match %d, logging tx_id %" PRIu64, logger->alproto, tx_id);

            SCLogDebug("pcap_cnt %" PRIu64 ", tx_id %" PRIu64 " logger %d. EOF %s", p->pcap_cnt,
                    tx_id, logger->logger_id, eof ? "true" : "false");

            if (eof) {
                SCLogDebug("EOF, so log now");
            } else {
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

            SCLogDebug("Logging tx_id %" PRIu64 " to logger %d", tx_id, logger->logger_id);
            PACKET_PROFILING_LOGGER_START(p, logger->logger_id);
            logger->LogFunc(tv, store->thread_data, p, f, alstate, tx, tx_id);
            PACKET_PROFILING_LOGGER_END(p, logger->logger_id);

            ctx->tx_logged |= BIT_U32(logger->logger_id);
        }

    next_logger:
        logger = logger->next;
        store = store->next;

        DEBUG_VALIDATE_BUG_ON(logger == NULL && store != NULL);
        DEBUG_VALIDATE_BUG_ON(logger != NULL && store == NULL);
    }
}

static TmEcode OutputTxLog(ThreadVars *tv, Packet *p, void *thread_data)
{
    DEBUG_VALIDATE_BUG_ON(thread_data == NULL);
    if (p->flow == NULL)
        return TM_ECODE_OK;

    OutputTxLoggerThreadData *op_thread_data = (OutputTxLoggerThreadData *)thread_data;

    Flow * const f = p->flow;
    const uint8_t ipproto = f->proto;
    const AppProto alproto = f->alproto;
    SCLogDebug("pcap_cnt %u tx logging %u/%s", (uint32_t)p->pcap_cnt, alproto,
            AppProtoToString(alproto));

    if (op_thread_data->file == NULL && op_thread_data->filedata == NULL) {
        if (list[alproto] == NULL && list[ALPROTO_UNKNOWN] == NULL) {
            SCLogDebug("bail");
            /* No child loggers registered. */
            return TM_ECODE_OK;
        }
        if (AppLayerParserProtocolHasLogger(p->proto, alproto) == 0)
            goto end;
    }
    const LoggerId logger_expectation = AppLayerParserProtocolGetLoggerBits(p->proto, alproto);
    if (logger_expectation == 0) {
        SCLogDebug("bail: logger_expectation %u. LOGGER_FILE %u LOGGER_FILEDATA %u",
                logger_expectation, LOGGER_FILE, LOGGER_FILEDATA);
        goto end;
    }
    void *alstate = f->alstate;
    if (alstate == NULL) {
        SCLogDebug("no alstate");
        goto end;
    }

    SCLogDebug("pcap_cnt %" PRIu64, p->pcap_cnt);

    const bool last_pseudo = (p->flowflags & FLOW_PKT_LAST_PSEUDO) != 0;
    const bool ts_eof = AppLayerParserStateIssetFlag(f->alparser,
                                (APP_LAYER_PARSER_EOF_TS | APP_LAYER_PARSER_TRUNC_TS)) != 0;
    const bool tc_eof = AppLayerParserStateIssetFlag(f->alparser,
                                (APP_LAYER_PARSER_EOF_TC | APP_LAYER_PARSER_TRUNC_TC)) != 0;

    const bool eof = last_pseudo || (ts_eof && tc_eof);
    SCLogDebug("eof %d last_pseudo %d ts_eof %d tc_eof %d", eof, last_pseudo, ts_eof, tc_eof);

    const uint8_t ts_disrupt_flags = FlowGetDisruptionFlags(f, STREAM_TOSERVER);
    const uint8_t tc_disrupt_flags = FlowGetDisruptionFlags(f, STREAM_TOCLIENT);
    SCLogDebug("ts_disrupt_flags %02x tc_disrupt_flags %02x", ts_disrupt_flags, tc_disrupt_flags);
    const uint64_t total_txs = AppLayerParserGetTxCnt(f, alstate);
    uint64_t tx_id = AppLayerParserGetTransactionLogId(f->alparser);
    uint64_t max_id = tx_id;
    int logged = 0;
    int gap = 0;

    SCLogDebug("tx_id %" PRIu64 " total_txs %" PRIu64, tx_id, total_txs);

    AppLayerGetTxIteratorFunc IterFunc = AppLayerGetTxIterator(ipproto, alproto);
    AppLayerGetTxIterState state;
    memset(&state, 0, sizeof(state));

    while (1) {
        AppLayerGetTxIterTuple ires = IterFunc(ipproto, alproto, alstate, tx_id, total_txs, &state);
        if (ires.tx_ptr == NULL)
            break;
        void * const tx = ires.tx_ptr;
        tx_id = ires.tx_id;
        SCLogDebug("STARTING tx_id %" PRIu64 ", tx %p", tx_id, tx);

        const int tx_progress_ts =
                AppLayerParserGetStateProgress(p->proto, alproto, tx, ts_disrupt_flags);
        const int tx_progress_tc =
                AppLayerParserGetStateProgress(p->proto, alproto, tx, tc_disrupt_flags);
        const bool tx_complete = (tx_progress_ts == AppLayerParserGetStateProgressCompletionStatus(
                                                            alproto, STREAM_TOSERVER) &&
                                  tx_progress_tc == AppLayerParserGetStateProgressCompletionStatus(
                                                            alproto, STREAM_TOCLIENT));
        const bool ts_ready = tx_progress_ts == AppLayerParserGetStateProgressCompletionStatus(
                                                        alproto, STREAM_TOSERVER);
        const bool tc_ready = tx_progress_tc == AppLayerParserGetStateProgressCompletionStatus(
                                                        alproto, STREAM_TOCLIENT);
        SCLogDebug("ts_ready %d tc_ready %d", ts_ready, tc_ready);

        SCLogDebug("file_thread_data %p filedata_thread_data %p", op_thread_data->file,
                op_thread_data->filedata);

        AppLayerTxData *txd = AppLayerParserGetTxData(ipproto, alproto, tx);
        if (txd && (op_thread_data->file || op_thread_data->filedata) &&
                AppLayerParserSupportsFiles(p->proto, alproto)) {
            OutputTxLogFiles(tv, op_thread_data->file, op_thread_data->filedata, p, f, tx, tx_id,
                    txd, tx_complete, ts_ready, tc_ready, ts_eof, tc_eof, eof);
        }
        if (txd)
            SCLogDebug("logger: expect %08x, have %08x", logger_expectation, txd->logged.flags);

        if (txd == NULL) {
            /* make sure this tx, which can't be properly logged is skipped */
            logged = 1;
            max_id = tx_id;
            goto next_tx;
        }

        if (list[ALPROTO_UNKNOWN] != 0) {
            OutputTxLogList0(tv, op_thread_data, p, f, tx, tx_id);
            if (list[alproto] == NULL)
                goto next_tx;
        }

        SCLogDebug("tx %p/%" PRIu64 " txd %p: log_flags %x logger_expectation %x", tx, tx_id, txd,
                txd->config.log_flags, logger_expectation);
        if (txd->config.log_flags & BIT_U8(CONFIG_TYPE_TX)) {
            SCLogDebug("SKIP tx %p/%"PRIu64, tx, tx_id);
            goto next_tx;
        }

        if (txd->logged.flags == logger_expectation) {
            SCLogDebug("fully logged");
            /* tx already fully logged */
            goto next_tx;
        }

        SCLogDebug("logger: expect %08x, have %08x", logger_expectation, txd->logged.flags);
        const OutputTxLogger *logger = list[alproto];
        const OutputLoggerThreadStore *store = op_thread_data->store[alproto];
        struct Ctx ctx = { .tx_logged = txd->logged.flags, .tx_logged_old = txd->logged.flags };
        SCLogDebug("logger: expect %08x, have %08x", logger_expectation, ctx.tx_logged);

        OutputTxLogCallLoggers(tv, op_thread_data, logger, store, p, f, alstate, tx, tx_id, alproto,
                eof, tx_progress_ts, tx_progress_tc, &ctx);

        SCLogDebug("logger: expect %08x, have %08x", logger_expectation, ctx.tx_logged);
        if (ctx.tx_logged != ctx.tx_logged_old) {
            SCLogDebug("logger: storing %08x (was %08x)", ctx.tx_logged, ctx.tx_logged_old);
            DEBUG_VALIDATE_BUG_ON(txd == NULL);
            txd->logged.flags |= ctx.tx_logged;
        }

        /* If all loggers logged set a flag and update the last tx_id
         * that was logged.
         *
         * If not all loggers were logged we flag that there was a gap
         * so any subsequent transactions in this loop don't increase
         * the maximum ID that was logged. */
        if (!gap && ctx.tx_logged == logger_expectation) {
            SCLogDebug("no gap %d, %08x == %08x", gap, ctx.tx_logged, logger_expectation);
            logged = 1;
            max_id = tx_id;
            SCLogDebug("max_id %" PRIu64, max_id);
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
static TmEcode OutputTxLogThreadInit(ThreadVars *tv, const void *_initdata, void **data)
{
    OutputTxLoggerThreadData *td = SCMalloc(sizeof(*td));
    if (td == NULL)
        return TM_ECODE_FAILED;
    memset(td, 0x00, sizeof(*td));

    *data = (void *)td;
    SCLogDebug("OutputTxLogThreadInit happy (*data %p)", *data);

    for (AppProto alproto = 0; alproto < ALPROTO_MAX; alproto++) {
        OutputTxLogger *logger = list[alproto];
        while (logger) {
            if (logger->ThreadInit) {
                void *retptr = NULL;
                if (logger->ThreadInit(tv, (void *)logger->output_ctx, &retptr) == TM_ECODE_OK) {
                    OutputLoggerThreadStore *ts = SCMalloc(sizeof(*ts));
    /* todo */      BUG_ON(ts == NULL);
                    memset(ts, 0x00, sizeof(*ts));

                    /* store thread handle */
                    ts->thread_data = retptr;

                    if (td->store[alproto] == NULL) {
                        td->store[alproto] = ts;
                    } else {
                        OutputLoggerThreadStore *tmp = td->store[alproto];
                        while (tmp->next != NULL)
                            tmp = tmp->next;
                        tmp->next = ts;
                    }

                    SCLogDebug("%s is now set up", logger->name);
                }
            }

            logger = logger->next;
        }
    }

    if (g_file_logger_enabled) {
        if (OutputFileLogThreadInit(tv, &td->file) != TM_ECODE_OK) {
            FatalError(SC_ERR_FATAL, "failed to set up file thread data");
        }
    }
    if (g_filedata_logger_enabled) {
        if (OutputFiledataLogThreadInit(tv, &td->filedata) != TM_ECODE_OK) {
            FatalError(SC_ERR_FATAL, "failed to set up filedata thread data");
        }
    }

    SCLogDebug("file_thread_data %p filedata_thread_data %p", td->file, td->filedata);

    return TM_ECODE_OK;
}

static TmEcode OutputTxLogThreadDeinit(ThreadVars *tv, void *thread_data)
{
    OutputTxLoggerThreadData *op_thread_data = (OutputTxLoggerThreadData *)thread_data;

    for (AppProto alproto = 0; alproto < ALPROTO_MAX; alproto++) {
        OutputLoggerThreadStore *store = op_thread_data->store[alproto];
        OutputTxLogger *logger = list[alproto];

        while (logger && store) {
            if (logger->ThreadDeinit) {
                logger->ThreadDeinit(tv, store->thread_data);
            }

            OutputLoggerThreadStore *next_store = store->next;
            SCFree(store);
            store = next_store;
            logger = logger->next;
        }
    }

    if (op_thread_data->file) {
        OutputFileLogThreadDeinit(tv, op_thread_data->file);
    }
    if (op_thread_data->filedata) {
        OutputFiledataLogThreadDeinit(tv, op_thread_data->filedata);
    }

    SCFree(op_thread_data);
    return TM_ECODE_OK;
}

static void OutputTxLogExitPrintStats(ThreadVars *tv, void *thread_data)
{
    OutputTxLoggerThreadData *op_thread_data = (OutputTxLoggerThreadData *)thread_data;

    for (AppProto alproto = 0; alproto < ALPROTO_MAX; alproto++) {
        OutputLoggerThreadStore *store = op_thread_data->store[alproto];
        OutputTxLogger *logger = list[alproto];

        while (logger && store) {
            if (logger->ThreadExitPrintStats) {
                logger->ThreadExitPrintStats(tv, store->thread_data);
            }

            logger = logger->next;
            store = store->next;
        }
    }
}

static uint32_t OutputTxLoggerGetActiveCount(void)
{
    uint32_t cnt = 0;
    for (AppProto alproto = 0; alproto < ALPROTO_MAX; alproto++) {
        for (OutputTxLogger *p = list[alproto]; p != NULL; p = p->next) {
            cnt++;
        }
    }

    if (g_file_logger_enabled) {
        cnt++;
        SCLogDebug("g_file_logger_enabled");
    }
    if (g_filedata_logger_enabled) {
        cnt++;
        SCLogDebug("g_filedata_logger_enabled");
    }

    return cnt;
}


void OutputTxLoggerRegister (void)
{
    OutputRegisterRootLogger(OutputTxLogThreadInit, OutputTxLogThreadDeinit,
        OutputTxLogExitPrintStats, OutputTxLog, OutputTxLoggerGetActiveCount);
}

void OutputTxShutdown(void)
{
    for (AppProto alproto = 0; alproto < ALPROTO_MAX; alproto++) {
        OutputTxLogger *logger = list[alproto];
        while (logger) {
            OutputTxLogger *next_logger = logger->next;
            SCFree(logger);
            logger = next_logger;
        }
        list[alproto] = NULL;
    }
}
