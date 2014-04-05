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
 * Logger for stremaing data
 */

#include "suricata-common.h"
#include "tm-modules.h"
#include "output-streaming.h"
#include "app-layer.h"
#include "app-layer-parser.h"
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
typedef struct OutputStreamingLogger_ {
    StreamingLogger LogFunc;
    OutputCtx *output_ctx;
    struct OutputStreamingLogger_ *next;
    const char *name;
    TmmId module_id;
} OutputStreamingLogger;

static OutputStreamingLogger *list = NULL;

int OutputRegisterStreamingLogger(const char *name, StreamingLogger LogFunc, OutputCtx *output_ctx)
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
} StreamerCallbackData;

int Streamer(void *cbdata, Flow *f, uint8_t *data, uint32_t data_len, uint8_t flags)
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

        SCLogDebug("logger %p", logger);
        PACKET_PROFILING_TMM_START(p, logger->module_id);
        logger->LogFunc(tv, store->thread_data, (const Flow *)f, data, data_len, flags);
        PACKET_PROFILING_TMM_END(p, logger->module_id);

        logger = logger->next;
        store = store->next;

        BUG_ON(logger == NULL && store != NULL);
        BUG_ON(logger != NULL && store == NULL);
    }

    return 0;
}

int StreamIterator(Flow *f, TcpStream *stream, int close, void *cbdata, uint8_t iflags)
{
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

            Streamer(cbdata, f, seg->payload, (uint32_t)seg->payload_len, flags);

            seg->flags |= SEGMENTTCP_FLAG_LOGAPI_PROCESSED;

            seg = seg->next;

            logged = 1;
        }
    }

    /* if we need to close we need to invoke the Streamer for sure. If we
     * logged no segments, we call the Streamer with NULL data so it can
     * close up. */
    if (logged == 0 && close) {
        Streamer(cbdata, f, NULL, 0, OUTPUT_STREAMING_FLAG_CLOSE);
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

    StreamerCallbackData streamer_cbdata = { logger, store, tv, p };

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

    TcpSession *ssn = f->protoctx;
    if (ssn) {
        int close = (ssn->state >= TCP_CLOSED);
        close |= ((p->flags & PKT_PSEUDO_STREAM_END) ? 1 : 0);
        SCLogDebug("close ? %s", close ? "yes" : "no");

        TcpStream *stream = flags & OUTPUT_STREAMING_FLAG_TOSERVER ? &ssn->client : &ssn->server;

        StreamIterator(p->flow, stream, close, (void *)&streamer_cbdata, flags);
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

                SCLogDebug("%s is now set up", logger->name);
            }
        }

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
