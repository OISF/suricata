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
 * Logger for streaming data
 */

#include "suricata-common.h"
#include "tm-modules.h"
#include "output.h"
#include "output-streaming.h"
#include "app-layer.h"
#include "app-layer-parser.h"
#include "app-layer-htp.h"
#include "util-print.h"
#include "conf.h"
#include "util-profiling.h"
#include "stream-tcp.h"
#include "stream-tcp-inline.h"
#include "stream-tcp-reassemble.h"
#include "util-validate.h"

/** per thread data for this module, contains a list of per thread
 *  data for the packet loggers. */
typedef struct OutputStreamingLoggerThreadData_ {
    OutputLoggerThreadStore *store;
    uint32_t loggers;
} OutputStreamingLoggerThreadData;

/* logger instance, a module + a output ctx,
 * it's perfectly valid that have multiple instances of the same
 * log module (e.g. http.log) with different output ctx'. */
typedef struct OutputStreamingLogger_ {
    StreamingLogger LogFunc;
    OutputCtx *output_ctx;
    struct OutputStreamingLogger_ *next;
    const char *name;
    LoggerId logger_id;
    enum OutputStreamingType type;
    ThreadInitFunc ThreadInit;
    ThreadDeinitFunc ThreadDeinit;
    ThreadExitPrintStatsFunc ThreadExitPrintStats;
} OutputStreamingLogger;

static OutputStreamingLogger *list = NULL;

int OutputRegisterStreamingLogger(LoggerId id, const char *name,
    StreamingLogger LogFunc, OutputCtx *output_ctx,
    enum OutputStreamingType type, ThreadInitFunc ThreadInit,
    ThreadDeinitFunc ThreadDeinit,
    ThreadExitPrintStatsFunc ThreadExitPrintStats)
{
    OutputStreamingLogger *op = SCMalloc(sizeof(*op));
    if (op == NULL)
        return -1;
    memset(op, 0x00, sizeof(*op));

    op->LogFunc = LogFunc;
    op->output_ctx = output_ctx;
    op->name = name;
    op->logger_id = id;
    op->type = type;
    op->ThreadInit = ThreadInit;
    op->ThreadDeinit = ThreadDeinit;
    op->ThreadExitPrintStats = ThreadExitPrintStats;

    if (list == NULL)
        list = op;
    else {
        OutputStreamingLogger *t = list;
        while (t->next)
            t = t->next;
        t->next = op;
    }

    if (op->type == STREAMING_TCP_DATA) {
        stream_config.streaming_log_api = true;
    }

    SCLogDebug("OutputRegisterStreamingLogger happy");
    return 0;
}

typedef struct StreamerCallbackData_ {
    OutputStreamingLogger *logger;
    OutputLoggerThreadStore *store;
    ThreadVars *tv;
    Packet *p;
    enum OutputStreamingType type;
} StreamerCallbackData;

static int Streamer(void *cbdata, Flow *f, const uint8_t *data, uint32_t data_len, uint64_t tx_id, uint8_t flags)
{
    StreamerCallbackData *streamer_cbdata = (StreamerCallbackData *)cbdata;
    DEBUG_VALIDATE_BUG_ON(streamer_cbdata == NULL);
    OutputStreamingLogger *logger = streamer_cbdata->logger;
    OutputLoggerThreadStore *store = streamer_cbdata->store;
    ThreadVars *tv = streamer_cbdata->tv;
#ifdef PROFILING
    Packet *p = streamer_cbdata->p;
#endif
    DEBUG_VALIDATE_BUG_ON(logger == NULL);
    DEBUG_VALIDATE_BUG_ON(store == NULL);

    while (logger && store) {
        DEBUG_VALIDATE_BUG_ON(logger->LogFunc == NULL);

        if (logger->type == streamer_cbdata->type) {
            SCLogDebug("logger %p", logger);
            PACKET_PROFILING_LOGGER_START(p, logger->logger_id);
            logger->LogFunc(tv, store->thread_data, (const Flow *)f, data, data_len, tx_id, flags);
            PACKET_PROFILING_LOGGER_END(p, logger->logger_id);
        }

        logger = logger->next;
        store = store->next;

        DEBUG_VALIDATE_BUG_ON(logger == NULL && store != NULL);
        DEBUG_VALIDATE_BUG_ON(logger != NULL && store == NULL);
    }

    return 0;
}

/** \brief Http Body Iterator for logging
 *
 *  Global logic:
 *
 *  - For each tx
 *    - For each body chunk
 *      - Invoke Streamer
 */

static int HttpBodyIterator(Flow *f, int close, void *cbdata, uint8_t iflags)
{
    SCLogDebug("called with %p, %d, %p, %02x", f, close, cbdata, iflags);

    HtpState *s = f->alstate;
    if (s == NULL || s->conn == NULL) {
        return 0;
    }

    const int tx_progress_done_value_ts =
            AppLayerParserGetStateProgressCompletionStatus(ALPROTO_HTTP1, STREAM_TOSERVER);
    const int tx_progress_done_value_tc =
            AppLayerParserGetStateProgressCompletionStatus(ALPROTO_HTTP1, STREAM_TOCLIENT);
    const uint64_t total_txs = AppLayerParserGetTxCnt(f, f->alstate);

    uint64_t tx_id = 0;
    for (tx_id = 0; tx_id < total_txs; tx_id++) { // TODO optimization store log tx
        htp_tx_t *tx = AppLayerParserGetTx(f->proto, f->alproto, f->alstate, tx_id);
        if (tx == NULL) {
            continue;
        }

        int tx_done = 0;
        int tx_logged = 0;
        int tx_progress_ts = AppLayerParserGetStateProgress(
                IPPROTO_TCP, ALPROTO_HTTP1, tx, FlowGetDisruptionFlags(f, STREAM_TOSERVER));
        if (tx_progress_ts >= tx_progress_done_value_ts) {
            int tx_progress_tc = AppLayerParserGetStateProgress(
                    IPPROTO_TCP, ALPROTO_HTTP1, tx, FlowGetDisruptionFlags(f, STREAM_TOCLIENT));
            if (tx_progress_tc >= tx_progress_done_value_tc) {
                tx_done = 1;
            }
        }

        SCLogDebug("tx %p", tx);
        HtpTxUserData *htud = (HtpTxUserData *) htp_tx_get_user_data(tx);
        if (htud != NULL) {
            SCLogDebug("htud %p", htud);
            HtpBody *body = NULL;
            if (iflags & OUTPUT_STREAMING_FLAG_TOSERVER)
                body = &htud->request_body;
            else if (iflags & OUTPUT_STREAMING_FLAG_TOCLIENT)
                body = &htud->response_body;

            if (body == NULL) {
                SCLogDebug("no body");
                goto next;
            }
            if (body->first == NULL) {
                SCLogDebug("no body chunks");
                goto next;
            }
            if (body->last->logged == 1) {
                SCLogDebug("all logged already");
                goto next;
            }

            // for each chunk
            HtpBodyChunk *chunk = body->first;
            for ( ; chunk != NULL; chunk = chunk->next) {
                if (chunk->logged) {
                    SCLogDebug("logged %d", chunk->logged);
                    continue;
                }

                uint8_t flags = iflags | OUTPUT_STREAMING_FLAG_TRANSACTION;
                if (chunk->sbseg.stream_offset == 0)
                    flags |= OUTPUT_STREAMING_FLAG_OPEN;
                /* if we need to close and we're at the last segment in the list
                 * we add the 'close' flag so the logger can close up. */
                if ((tx_done || close) && chunk->next == NULL) {
                    flags |= OUTPUT_STREAMING_FLAG_CLOSE;
                }

                const uint8_t *data = NULL;
                uint32_t data_len = 0;
                StreamingBufferSegmentGetData(body->sb, &chunk->sbseg, &data, &data_len);

                // invoke Streamer
                Streamer(cbdata, f, data, data_len, tx_id, flags);
                //PrintRawDataFp(stdout, data, data_len);
                chunk->logged = 1;
                tx_logged = 1;
            }

        next:
            /* if we need to close we need to invoke the Streamer for sure. If we
             * logged no chunks, we call the Streamer with NULL data so it can
             * close up. */
            if (tx_logged == 0 && (close||tx_done)) {
                Streamer(cbdata, f, NULL, 0, tx_id,
                         iflags|OUTPUT_STREAMING_FLAG_CLOSE|OUTPUT_STREAMING_FLAG_TRANSACTION);
            }
        }
    }
    return 0;
}

struct StreamLogData {
    uint8_t flags;
    void *streamer_cbdata;
    Flow *f;
};

static int StreamLogFunc(void *cb_data, const uint8_t *data, const uint32_t data_len)
{
    struct StreamLogData *log = cb_data;

    Streamer(log->streamer_cbdata, log->f, data, data_len, 0, log->flags);

    /* hack: unset open flag after first run */
    log->flags &= ~OUTPUT_STREAMING_FLAG_OPEN;

    return 0;
}

static int TcpDataLogger (Flow *f, TcpSession *ssn, TcpStream *stream,
        bool eof, uint8_t iflags, void *streamer_cbdata)
{
    uint8_t flags = iflags;
    uint64_t progress = STREAM_LOG_PROGRESS(stream);

    if (progress == 0)
        flags |= OUTPUT_STREAMING_FLAG_OPEN;

    struct StreamLogData log_data = { flags, streamer_cbdata, f };
    StreamReassembleLog(ssn, stream,
            StreamLogFunc, &log_data,
            progress, &progress, eof);

    if (progress > STREAM_LOG_PROGRESS(stream)) {
        uint32_t slide = progress - STREAM_LOG_PROGRESS(stream);
        stream->log_progress_rel += slide;
    }

    if (eof) {
        Streamer(streamer_cbdata, f, NULL, 0, 0, flags|OUTPUT_STREAMING_FLAG_CLOSE);
    }
    return 0;
}

static TmEcode OutputStreamingLog(ThreadVars *tv, Packet *p, void *thread_data)
{
    DEBUG_VALIDATE_BUG_ON(thread_data == NULL);

    if (list == NULL) {
        /* No child loggers. */
        return TM_ECODE_OK;
    }

    OutputStreamingLoggerThreadData *op_thread_data =
            (OutputStreamingLoggerThreadData *)thread_data;
    OutputStreamingLogger *logger = list;
    OutputLoggerThreadStore *store = op_thread_data->store;

    StreamerCallbackData streamer_cbdata = { logger, store, tv, p , 0};

    DEBUG_VALIDATE_BUG_ON(logger == NULL && store != NULL);
    DEBUG_VALIDATE_BUG_ON(logger != NULL && store == NULL);
    DEBUG_VALIDATE_BUG_ON(logger == NULL && store == NULL);

    uint8_t flags = 0;
    Flow * const f = p->flow;

    /* no flow, no streaming */
    if (f == NULL) {
        SCReturnInt(TM_ECODE_OK);
    }

    if (!(StreamTcpInlineMode())) {
        if (PKT_IS_TOCLIENT(p)) {
            flags |= OUTPUT_STREAMING_FLAG_TOSERVER;
        } else {
            flags |= OUTPUT_STREAMING_FLAG_TOCLIENT;
        }
    } else {
        if (PKT_IS_TOSERVER(p)) {
            flags |= OUTPUT_STREAMING_FLAG_TOSERVER;
        } else {
            flags |= OUTPUT_STREAMING_FLAG_TOCLIENT;
        }
    }

    if (op_thread_data->loggers & (1<<STREAMING_TCP_DATA)) {
        TcpSession *ssn = f->protoctx;
        if (ssn) {
            int close = (ssn->state >= TCP_CLOSED);
            close |= ((p->flags & PKT_PSEUDO_STREAM_END) ? 1 : 0);
            SCLogDebug("close ? %s", close ? "yes" : "no");

            TcpStream *stream = flags & OUTPUT_STREAMING_FLAG_TOSERVER ? &ssn->client : &ssn->server;
            streamer_cbdata.type = STREAMING_TCP_DATA;
            TcpDataLogger(f, ssn, stream, close, flags, (void *)&streamer_cbdata);
        }
    }
    if (op_thread_data->loggers & (1<<STREAMING_HTTP_BODIES)) {
        if (f->alproto == ALPROTO_HTTP1 && f->alstate != NULL) {
            int close = 0;
            TcpSession *ssn = f->protoctx;
            if (ssn) {
                close = (ssn->state >= TCP_CLOSED);
                close |= ((p->flags & PKT_PSEUDO_STREAM_END) ? 1 : 0);
            }
            SCLogDebug("close ? %s", close ? "yes" : "no");
            streamer_cbdata.type = STREAMING_HTTP_BODIES;
            HttpBodyIterator(f, close, (void *)&streamer_cbdata, flags);
        }
    }

    return TM_ECODE_OK;
}

/** \brief thread init for the tx logger
 *  This will run the thread init functions for the individual registered
 *  loggers */
static TmEcode OutputStreamingLogThreadInit(ThreadVars *tv, const void *initdata, void **data) {
    OutputStreamingLoggerThreadData *td = SCMalloc(sizeof(*td));
    if (td == NULL)
        return TM_ECODE_FAILED;
    memset(td, 0x00, sizeof(*td));

    *data = (void *)td;

    SCLogDebug("OutputStreamingLogThreadInit happy (*data %p)", *data);

    OutputStreamingLogger *logger = list;
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

                SCLogInfo("%s is now set up", logger->name);
            }
        }

        td->loggers |= (1<<logger->type);

        logger = logger->next;
    }

    return TM_ECODE_OK;
}

static TmEcode OutputStreamingLogThreadDeinit(ThreadVars *tv, void *thread_data) {
    OutputStreamingLoggerThreadData *op_thread_data =
            (OutputStreamingLoggerThreadData *)thread_data;
    OutputLoggerThreadStore *store = op_thread_data->store;
    OutputStreamingLogger *logger = list;

    while (logger && store) {
        if (logger->ThreadDeinit) {
            logger->ThreadDeinit(tv, store->thread_data);
        }

        OutputLoggerThreadStore *next_store = store->next;
        SCFree(store);
        logger = logger->next;
        store = next_store;
    }

    SCFree(op_thread_data);
    return TM_ECODE_OK;
}

static void OutputStreamingLogExitPrintStats(ThreadVars *tv, void *thread_data) {
    OutputStreamingLoggerThreadData *op_thread_data =
            (OutputStreamingLoggerThreadData *)thread_data;
    OutputLoggerThreadStore *store = op_thread_data->store;
    OutputStreamingLogger *logger = list;

    while (logger && store) {
        if (logger->ThreadExitPrintStats) {
            logger->ThreadExitPrintStats(tv, store->thread_data);
        }

        logger = logger->next;
        store = store->next;
    }
}

static uint32_t OutputStreamingLoggerGetActiveCount(void)
{
    uint32_t cnt = 0;
    for (OutputStreamingLogger *p = list; p != NULL; p = p->next) {
        cnt++;
    }
    return cnt;
}

void OutputStreamingLoggerRegister(void) {
    OutputRegisterRootLogger(OutputStreamingLogThreadInit,
        OutputStreamingLogThreadDeinit, OutputStreamingLogExitPrintStats,
        OutputStreamingLog, OutputStreamingLoggerGetActiveCount);
}

void OutputStreamingShutdown(void)
{
    OutputStreamingLogger *logger = list;
    while (logger) {
        OutputStreamingLogger *next_logger = logger->next;
        SCFree(logger);
        logger = next_logger;
    }
    list = NULL;
}
