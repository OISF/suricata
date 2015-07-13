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
 * Logger for streaming data
 */

#include "suricata-common.h"
#include "tm-modules.h"
#include "output-streaming.h"
#include "app-layer.h"
#include "app-layer-parser.h"
#include "app-layer-htp.h"
#include "util-print.h"
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
    uint32_t loggers;
} OutputLoggerThreadData;

/* logger instance, a module + a output ctx,
 * it's perfectly valid that have multiple instances of the same
 * log module (e.g. http.log) with different output ctx'. */
typedef struct OutputStreamingLogger_ {
    StreamingLogger LogFunc;
    OutputCtx *output_ctx;
    struct OutputStreamingLogger_ *next;
    const char *name;
    TmmId module_id;
    enum OutputStreamingType type;
} OutputStreamingLogger;

static OutputStreamingLogger *list = NULL;

int OutputRegisterStreamingLogger(const char *name, StreamingLogger LogFunc,
        OutputCtx *output_ctx, enum OutputStreamingType type )
{
    int module_id = TmModuleGetIdByName(name);
    if (module_id < 0)
        return -1;

    OutputStreamingLogger *op = SCMalloc(sizeof(*op));
    if (op == NULL)
        return -1;
    memset(op, 0x00, sizeof(*op));

    op->LogFunc = LogFunc;
    op->output_ctx = output_ctx;
    op->name = name;
    op->module_id = (TmmId) module_id;
    op->type = type;

    if (list == NULL)
        list = op;
    else {
        OutputStreamingLogger *t = list;
        while (t->next)
            t = t->next;
        t->next = op;
    }

    SCLogDebug("OutputRegisterTxLogger happy");
    return 0;
}

typedef struct StreamerCallbackData_ {
    OutputStreamingLogger *logger;
    OutputLoggerThreadStore *store;
    ThreadVars *tv;
    Packet *p;
    enum OutputStreamingType type;
} StreamerCallbackData;

int Streamer(void *cbdata, Flow *f, uint8_t *data, uint32_t data_len, uint64_t tx_id, uint8_t flags)
{
    StreamerCallbackData *streamer_cbdata = (StreamerCallbackData *)cbdata;
    BUG_ON(streamer_cbdata == NULL);
    OutputStreamingLogger *logger = streamer_cbdata->logger;
    OutputLoggerThreadStore *store = streamer_cbdata->store;
    ThreadVars *tv = streamer_cbdata->tv;
#ifdef PROFILING
    Packet *p = streamer_cbdata->p;
#endif
    BUG_ON(logger == NULL);
    BUG_ON(store == NULL);

    while (logger && store) {
        BUG_ON(logger->LogFunc == NULL);

        if (logger->type == streamer_cbdata->type) {
            SCLogDebug("logger %p", logger);
            PACKET_PROFILING_TMM_START(p, logger->module_id);
            logger->LogFunc(tv, store->thread_data, (const Flow *)f, data, data_len, tx_id, flags);
            PACKET_PROFILING_TMM_END(p, logger->module_id);
        }

        logger = logger->next;
        store = store->next;

        BUG_ON(logger == NULL && store != NULL);
        BUG_ON(logger != NULL && store == NULL);
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

int HttpBodyIterator(Flow *f, int close, void *cbdata, uint8_t iflags)
{
    SCLogDebug("called with %p, %d, %p, %02x", f, close, cbdata, iflags);

    HtpState *s = f->alstate;
    if (s != NULL && s->conn != NULL) {
        int tx_progress_done_value_ts =
            AppLayerParserGetStateProgressCompletionStatus(IPPROTO_TCP,
                                                           ALPROTO_HTTP, STREAM_TOSERVER);
        int tx_progress_done_value_tc =
            AppLayerParserGetStateProgressCompletionStatus(IPPROTO_TCP,
                                                           ALPROTO_HTTP, STREAM_TOCLIENT);

        // for each tx
        uint64_t tx_id = 0;
        uint64_t total_txs = AppLayerParserGetTxCnt(f->proto, f->alproto, f->alstate);
        SCLogDebug("s->conn %p", s->conn);
        for (tx_id = 0; tx_id < total_txs; tx_id++) { // TODO optimization store log tx
            htp_tx_t *tx = AppLayerParserGetTx(f->proto, f->alproto, f->alstate, tx_id);
            if (tx != NULL) {
                int tx_done = 0;
                int tx_logged = 0;

                int tx_progress_ts = AppLayerParserGetStateProgress(
                        IPPROTO_TCP, ALPROTO_HTTP, tx, FlowGetDisruptionFlags(f, STREAM_TOSERVER));
                if (tx_progress_ts >= tx_progress_done_value_ts) {
                    int tx_progress_tc = AppLayerParserGetStateProgress(
                            IPPROTO_TCP, ALPROTO_HTTP, tx, FlowGetDisruptionFlags(f, STREAM_TOCLIENT));
                    if (tx_progress_tc >= tx_progress_done_value_tc) {
                        tx_done = 1;
                    }
                }

                SCLogDebug("tx %p", tx);
                HtpTxUserData *htud = (HtpTxUserData *) htp_tx_get_user_data(tx);
                if (htud != NULL) {
                    SCLogDebug("htud %p", htud);
                    HtpBody *body = NULL;
                    if (iflags & OUTPUT_STREAMING_FLAG_TOCLIENT)
                        body = &htud->request_body;
                    else if (iflags & OUTPUT_STREAMING_FLAG_TOSERVER)
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
                        if (chunk->stream_offset == 0)
                            flags |= OUTPUT_STREAMING_FLAG_OPEN;
                        /* if we need to close and we're at the last segment in the list
                         * we add the 'close' flag so the logger can close up. */
                        if ((tx_done || close) && chunk->next == NULL) {
                            flags |= OUTPUT_STREAMING_FLAG_CLOSE;
                        }

                        // invoke Streamer
                        Streamer(cbdata, f, chunk->data, (uint32_t)chunk->len, tx_id, flags);
                        //PrintRawDataFp(stdout, chunk->data, chunk->len);
                        chunk->logged = 1;
                        tx_logged = 1;
                    }

                  next:
                    /* if we need to close we need to invoke the Streamer for sure. If we
                     * logged no chunks, we call the Streamer with NULL data so it can
                     * close up. */
                    if (tx_logged == 0 && (close||tx_done)) {
                        Streamer(cbdata, f, NULL, 0, tx_id,
                                OUTPUT_STREAMING_FLAG_CLOSE|OUTPUT_STREAMING_FLAG_TRANSACTION);
                    }
                }
            }
        }
    }


    return 0;
}

int StreamIterator(Flow *f, TcpStream *stream, int close, void *cbdata, uint8_t iflags)
{
    SCLogDebug("called with %p, %d, %p, %02x", f, close, cbdata, iflags);
    int logged = 0;

    /* optimization: don't iterate list if we've logged all,
     * so check the last segment's flags */
    if (stream->seg_list_tail != NULL &&
        (!(stream->seg_list_tail->flags & SEGMENTTCP_FLAG_LOGAPI_PROCESSED)))
    {
        TcpSegment *seg = stream->seg_list;
        while (seg) {
            uint8_t flags = iflags;

            if (seg->flags & SEGMENTTCP_FLAG_LOGAPI_PROCESSED) {
                seg = seg->next;
                continue;
            }

            if (SEQ_GT(seg->seq + seg->payload_len, stream->last_ack)) {
                SCLogDebug("seg not (fully) acked yet");
                break;
            }

            if (seg->seq == stream->isn + 1)
                flags |= OUTPUT_STREAMING_FLAG_OPEN;
            /* if we need to close and we're at the last segment in the list
             * we add the 'close' flag so the logger can close up. */
            if (close && seg->next == NULL)
                flags |= OUTPUT_STREAMING_FLAG_CLOSE;

            Streamer(cbdata, f, seg->payload, (uint32_t)seg->payload_len, 0, flags);

            seg->flags |= SEGMENTTCP_FLAG_LOGAPI_PROCESSED;

            seg = seg->next;

            logged = 1;
        }
    }

    /* if we need to close we need to invoke the Streamer for sure. If we
     * logged no segments, we call the Streamer with NULL data so it can
     * close up. */
    if (logged == 0 && close) {
        Streamer(cbdata, f, NULL, 0, 0, OUTPUT_STREAMING_FLAG_CLOSE);
    }

    return 0;
}

static TmEcode OutputStreamingLog(ThreadVars *tv, Packet *p, void *thread_data, PacketQueue *pq, PacketQueue *postpq)
{
    BUG_ON(thread_data == NULL);
    BUG_ON(list == NULL);

    OutputLoggerThreadData *op_thread_data = (OutputLoggerThreadData *)thread_data;
    OutputStreamingLogger *logger = list;
    OutputLoggerThreadStore *store = op_thread_data->store;

    StreamerCallbackData streamer_cbdata = { logger, store, tv, p , 0};

    BUG_ON(logger == NULL && store != NULL);
    BUG_ON(logger != NULL && store == NULL);
    BUG_ON(logger == NULL && store == NULL);

    uint8_t flags = 0;
    Flow * const f = p->flow;

    /* no flow, no streaming */
    if (f == NULL) {
        SCReturnInt(TM_ECODE_OK);
    }

    if (p->flowflags & FLOW_PKT_TOCLIENT)
        flags |= OUTPUT_STREAMING_FLAG_TOCLIENT;
    else
        flags |= OUTPUT_STREAMING_FLAG_TOSERVER;

    FLOWLOCK_WRLOCK(f);

    if (op_thread_data->loggers & (1<<STREAMING_TCP_DATA)) {
        TcpSession *ssn = f->protoctx;
        if (ssn) {
            int close = (ssn->state >= TCP_CLOSED);
            close |= ((p->flags & PKT_PSEUDO_STREAM_END) ? 1 : 0);
            SCLogDebug("close ? %s", close ? "yes" : "no");

            TcpStream *stream = flags & OUTPUT_STREAMING_FLAG_TOSERVER ? &ssn->client : &ssn->server;

            streamer_cbdata.type = STREAMING_TCP_DATA;
            StreamIterator(p->flow, stream, close, (void *)&streamer_cbdata, flags);
        }
    }
    if (op_thread_data->loggers & (1<<STREAMING_HTTP_BODIES)) {
        if (f->alproto == ALPROTO_HTTP && f->alstate != NULL) {
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

    FLOWLOCK_UNLOCK(f);
    return TM_ECODE_OK;
}

/** \brief thread init for the tx logger
 *  This will run the thread init functions for the individual registered
 *  loggers */
static TmEcode OutputStreamingLogThreadInit(ThreadVars *tv, void *initdata, void **data) {
    OutputLoggerThreadData *td = SCMalloc(sizeof(*td));
    if (td == NULL)
        return TM_ECODE_FAILED;
    memset(td, 0x00, sizeof(*td));

    *data = (void *)td;

    SCLogDebug("OutputStreamingLogThreadInit happy (*data %p)", *data);

    OutputStreamingLogger *logger = list;
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

                SCLogInfo("%s is now set up", logger->name);
            }
        }

        td->loggers |= (1<<logger->type);

        logger = logger->next;
    }

    return TM_ECODE_OK;
}

static TmEcode OutputStreamingLogThreadDeinit(ThreadVars *tv, void *thread_data) {
    OutputLoggerThreadData *op_thread_data = (OutputLoggerThreadData *)thread_data;
    OutputLoggerThreadStore *store = op_thread_data->store;
    OutputStreamingLogger *logger = list;

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

        logger = logger->next;
        store = store->next;
    }

    return TM_ECODE_OK;
}

static void OutputStreamingLogExitPrintStats(ThreadVars *tv, void *thread_data) {
    OutputLoggerThreadData *op_thread_data = (OutputLoggerThreadData *)thread_data;
    OutputLoggerThreadStore *store = op_thread_data->store;
    OutputStreamingLogger *logger = list;

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

void TmModuleStreamingLoggerRegister (void) {
    tmm_modules[TMM_STREAMINGLOGGER].name = "__streaming_logger__";
    tmm_modules[TMM_STREAMINGLOGGER].ThreadInit = OutputStreamingLogThreadInit;
    tmm_modules[TMM_STREAMINGLOGGER].Func = OutputStreamingLog;
    tmm_modules[TMM_STREAMINGLOGGER].ThreadExitPrintStats = OutputStreamingLogExitPrintStats;
    tmm_modules[TMM_STREAMINGLOGGER].ThreadDeinit = OutputStreamingLogThreadDeinit;
    tmm_modules[TMM_STREAMINGLOGGER].cap_flags = 0;
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
