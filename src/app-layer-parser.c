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
 * Generic App-layer parsing functions.
 */

#include "suricata-common.h"
#include "debug.h"
#include "util-unittest.h"
#include "decode.h"
#include "threads.h"

#include "util-print.h"
#include "util-pool.h"

#include "flow-util.h"
#include "flow-private.h"

#include "detect-engine-state.h"
#include "detect-engine-port.h"

#include "stream-tcp.h"
#include "stream-tcp-private.h"
#include "stream.h"
#include "stream-tcp-reassemble.h"

#include "app-layer.h"
#include "app-layer-protos.h"
#include "app-layer-parser.h"
#include "app-layer-smb.h"
#include "app-layer-smb2.h"
#include "app-layer-dcerpc.h"
#include "app-layer-dcerpc-udp.h"
#include "app-layer-htp.h"
#include "app-layer-ftp.h"
#include "app-layer-ssl.h"
#include "app-layer-ssh.h"
#include "app-layer-smtp.h"
#include "app-layer-dns-udp.h"
#include "app-layer-dns-tcp.h"

#include "conf.h"
#include "util-spm.h"

#include "util-debug.h"
#include "decode-events.h"
#include "util-unittest-helper.h"
#include "util-validate.h"

#include "runmodes.h"

typedef struct AppLayerParserCtxThread_ {
    void *alproto_local_storage[FLOW_PROTO_MAX][ALPROTO_MAX];
} AppLayerParserCtxThread;


/**
 * \brief App layer protocol parser context.
 */
typedef struct AppLayerParserpCtx_
{
    /* 0 - to_server, 1 - to_client. */
    int (*Parser[2])(Flow *f, void *protocol_state,
                     void *pstate,
                     uint8_t *input, uint32_t input_len,
                     void *local_storage);
    char logger;

    void *(*StateAlloc)(void);
    void (*StateFree)(void *);
    void (*StateTransactionFree)(void *, uint64_t);
    void *(*LocalStorageAlloc)(void);
    void (*LocalStorageFree)(void *);

    void (*Truncate)(void *, uint8_t);
    FileContainer *(*StateGetFiles)(void *, uint8_t);
    AppLayerDecoderEvents *(*StateGetEvents)(void *, uint64_t);
    int (*StateHasEvents)(void *);

    int (*StateGetProgress)(void *alstate, uint8_t direction);
    uint64_t (*StateGetTxCnt)(void *alstate);
    void *(*StateGetTx)(void *alstate, uint64_t tx_id);
    int (*StateGetProgressCompletionStatus)(uint8_t direction);
    int (*StateGetEventInfo)(const char *event_name,
                             int *event_id, AppLayerEventType *event_type);

    /* Indicates the direction the parser is ready to see the data
     * the first time for a flow.  Values accepted -
     * STREAM_TOSERVER, STREAM_TOCLIENT */
    uint8_t first_data_dir;

#ifdef UNITTESTS
    void (*RegisterUnittests)(void);
#endif
} AppLayerParserpCtx;

typedef struct AppLayerParserCtx_ {
    AppLayerParserpCtx ctxs[FLOW_PROTO_MAX][ALPROTO_MAX];
} AppLayerParserCtx;

typedef struct AppLayerParserParserState_ {
    uint8_t flags;

    /* Indicates the current transaction that is being inspected.
     * We have a var per direction. */
    uint64_t inspect_id[2];
    /* Indicates the current transaction being logged.  Unlike inspect_id,
     * we don't need a var per direction since we don't log a transaction
     * unless we have the entire transaction. */
    uint64_t log_id;
    /* State version, incremented for each update.  Can wrap around. */
    uint16_t version;

    /* Used to store decoder events. */
    AppLayerDecoderEvents *decoder_events;
} AppLayerParserParserState;

/* Static global version of the parser context.
 * Post 2.0 let's look at changing this to move it out to app-layer.c. */
static AppLayerParserCtx alp_ctx;

static void AppLayerParserTransactionsCleanup(uint16_t ipproto, AppProto alproto,
                                              void *alstate, void *pstate)
{
    SCEnter();

    AppLayerParserParserState *parser_state_store = pstate;
    uint64_t inspect = 0, log = 0;
    uint64_t min;
    AppLayerParserpCtx *ctx = &alp_ctx.ctxs[FlowGetProtoMapping(ipproto)][alproto];

    if (ctx->StateTransactionFree == NULL)
        goto end;

    if (parser_state_store->inspect_id[0] < parser_state_store->inspect_id[1])
        inspect = parser_state_store->inspect_id[0];
    else
        inspect = parser_state_store->inspect_id[1];
    log = parser_state_store->log_id;

    if (ctx->logger == TRUE) {
        min = log < inspect ? log : inspect;
        if (min > 0)
            ctx->StateTransactionFree(alstate, min - 1);
    } else {
        if (inspect > 0)
            ctx->StateTransactionFree(alstate, inspect - 1);
    }

 end:
    SCReturn;
}

void *AppLayerParserAllocAppLayerParserParserState(void)
{
    SCEnter();

    AppLayerParserParserState *pstate = (AppLayerParserParserState *)SCMalloc(sizeof(*pstate));
    if (pstate == NULL)
        goto end;
    memset(pstate, 0, sizeof(*pstate));

 end:
    SCReturnPtr(pstate, "pstate");
}

void AppLayerParserDeAllocAppLayerParserParserState(void *pstate)
{
    SCEnter();

    if (((AppLayerParserParserState *)pstate)->decoder_events != NULL)
        AppLayerDecoderEventsFreeEvents(((AppLayerParserParserState *)pstate)->decoder_events);
    SCFree(pstate);

    SCReturn;
}

int AppLayerParserSetup(void)
{
    SCEnter();

    memset(&alp_ctx, 0, sizeof(alp_ctx));

    SCReturnInt(0);
}

int AppLayerParserDeSetup(void)
{
    SCEnter();

    SCReturnInt(0);
}

void *AppLayerParserGetCtxThread(void)
{
    SCEnter();

    AppProto i = 0;
    int j = 0;
    AppLayerParserCtxThread *tctx;

    tctx = SCMalloc(sizeof(*tctx));
    if (tctx == NULL)
        goto end;
    memset(tctx, 0, sizeof(*tctx));

    for (i = 0; i < FLOW_PROTO_DEFAULT; i++) {
        for (j = 0; j < ALPROTO_MAX; j++) {
            tctx->alproto_local_storage[i][j] =
                AppLayerParserGetProtocolParserLocalStorage(FlowGetReverseProtoMapping(i),
                                                 j);
        }
    }

 end:
    SCReturnPtr(tctx, "void *");
}

void AppLayerParserDestroyCtxThread(void *alpd_tctx)
{
    SCEnter();

    AppProto i = 0;
    int j = 0;
    AppLayerParserCtxThread *tctx = (AppLayerParserCtxThread *)alpd_tctx;

    for (i = 0; i < FLOW_PROTO_DEFAULT; i++) {
        for (j = 0; j < ALPROTO_MAX; j++) {
            AppLayerParserDestroyProtocolParserLocalStorage(FlowGetReverseProtoMapping(i),
                                                            j,
                                                            tctx->alproto_local_storage[i][j]);
        }
    }

    SCReturn;
}

int AppLayerParserConfParserEnabled(const char *ipproto,
                                    const char *alproto_name)
{
    SCEnter();

    int enabled = 1;
    char param[100];
    ConfNode *node;
    int r;

    if (RunmodeIsUnittests())
        goto enabled;

    r = snprintf(param, sizeof(param), "%s%s%s", "app-layer.protocols.",
                 alproto_name, ".enabled");
    if (r < 0) {
        SCLogError(SC_ERR_FATAL, "snprintf failure.");
        exit(EXIT_FAILURE);
    } else if (r > (int)sizeof(param)) {
        SCLogError(SC_ERR_FATAL, "buffer not big enough to write param.");
        exit(EXIT_FAILURE);
    }

    node = ConfGetNode(param);
    if (node == NULL) {
        SCLogDebug("Entry for %s not found.", param);
        r = snprintf(param, sizeof(param), "%s%s%s%s%s", "app-layer.protocols.",
                     alproto_name, ".", ipproto, ".enabled");
        if (r < 0) {
            SCLogError(SC_ERR_FATAL, "snprintf failure.");
            exit(EXIT_FAILURE);
        } else if (r > (int)sizeof(param)) {
            SCLogError(SC_ERR_FATAL, "buffer not big enough to write param.");
            exit(EXIT_FAILURE);
        }

        node = ConfGetNode(param);
        if (node == NULL) {
            SCLogDebug("Entry for %s not found.", param);
            goto enabled;
        }
    }

    if (strcasecmp(node->val, "yes") == 0) {
        goto enabled;
    } else if (strcasecmp(node->val, "no") == 0) {
        goto disabled;
    } else if (strcasecmp(node->val, "detection-only") == 0) {
        goto enabled;
    } else {
        SCLogError(SC_ERR_FATAL, "Invalid value found for %s.", param);
        exit(EXIT_FAILURE);
    }

 disabled:
    enabled = 0;
 enabled:
    SCReturnInt(enabled);
}

/***** Parser related registration *****/

int AppLayerParserRegisterParser(uint16_t ipproto, AppProto alproto,
                      uint8_t direction,
                      int (*Parser)(Flow *f, void *protocol_state,
                                    void *pstate,
                                    uint8_t *buf, uint32_t buf_len,
                                    void *local_storage))
{
    SCEnter();

    alp_ctx.ctxs[FlowGetProtoMapping(ipproto)][alproto].
        Parser[(direction & STREAM_TOSERVER) ? 0 : 1] = Parser;

    SCReturnInt(0);
}

void AppLayerParserRegisterParserAcceptableDataDirection(uint16_t ipproto, AppProto alproto,
                                              uint8_t direction)
{
    SCEnter();

    alp_ctx.ctxs[FlowGetProtoMapping(ipproto)][alproto].first_data_dir |=
        (direction & (STREAM_TOSERVER | STREAM_TOCLIENT));

    SCReturn;
}

void AppLayerParserRegisterStateFuncs(uint16_t ipproto, AppProto alproto,
                           void *(*StateAlloc)(void),
                           void (*StateFree)(void *))
{
    SCEnter();

    alp_ctx.ctxs[FlowGetProtoMapping(ipproto)][alproto].StateAlloc =
        StateAlloc;
    alp_ctx.ctxs[FlowGetProtoMapping(ipproto)][alproto].StateFree =
        StateFree;

    SCReturn;
}

void AppLayerParserRegisterLocalStorageFunc(uint16_t ipproto, AppProto alproto,
                                 void *(*LocalStorageAlloc)(void),
                                 void (*LocalStorageFree)(void *))
{
    SCEnter();

    alp_ctx.ctxs[FlowGetProtoMapping(ipproto)][alproto].LocalStorageAlloc =
        LocalStorageAlloc;
    alp_ctx.ctxs[FlowGetProtoMapping(ipproto)][alproto].LocalStorageFree =
        LocalStorageFree;

    SCReturn;
}

void AppLayerParserRegisterGetFilesFunc(uint16_t ipproto, AppProto alproto,
                             FileContainer *(*StateGetFiles)(void *, uint8_t))
{
    SCEnter();

    alp_ctx.ctxs[FlowGetProtoMapping(ipproto)][alproto].StateGetFiles =
        StateGetFiles;

    SCReturn;
}

void AppLayerParserRegisterGetEventsFunc(uint16_t ipproto, AppProto alproto,
    AppLayerDecoderEvents *(*StateGetEvents)(void *, uint64_t))
{
    SCEnter();

    alp_ctx.ctxs[FlowGetProtoMapping(ipproto)][alproto].StateGetEvents =
        StateGetEvents;

    SCReturn;
}

void AppLayerParserRegisterHasEventsFunc(uint16_t ipproto, AppProto alproto,
                              int (*StateHasEvents)(void *))
{
    SCEnter();

    alp_ctx.ctxs[FlowGetProtoMapping(ipproto)][alproto].StateHasEvents =
        StateHasEvents;

    SCReturn;
}

void AppLayerParserRegisterLogger(uint16_t ipproto, AppProto alproto)
{
    SCEnter();

    alp_ctx.ctxs[FlowGetProtoMapping(ipproto)][alproto].logger = TRUE;

    SCReturn;
}

void AppLayerParserRegisterTruncateFunc(uint16_t ipproto, AppProto alproto,
                                        void (*Truncate)(void *, uint8_t))
{
    SCEnter();

    alp_ctx.ctxs[FlowGetProtoMapping(ipproto)][alproto].Truncate = Truncate;

    SCReturn;
}

void AppLayerParserRegisterGetStateProgressFunc(uint16_t ipproto, AppProto alproto,
    int (*StateGetProgress)(void *alstate, uint8_t direction))
{
    SCEnter();

    alp_ctx.ctxs[FlowGetProtoMapping(ipproto)][alproto].
        StateGetProgress = StateGetProgress;

    SCReturn;
}

void AppLayerParserRegisterTxFreeFunc(uint16_t ipproto, AppProto alproto,
                           void (*StateTransactionFree)(void *, uint64_t))
{
    SCEnter();

    alp_ctx.ctxs[FlowGetProtoMapping(ipproto)][alproto].
        StateTransactionFree = StateTransactionFree;

    SCReturn;
}

void AppLayerParserRegisterGetTxCnt(uint16_t ipproto, AppProto alproto,
                         uint64_t (*StateGetTxCnt)(void *alstate))
{
    SCEnter();

    alp_ctx.ctxs[FlowGetProtoMapping(ipproto)][alproto].
        StateGetTxCnt = StateGetTxCnt;

    SCReturn;
}

void AppLayerParserRegisterGetTx(uint16_t ipproto, AppProto alproto,
                      void *(StateGetTx)(void *alstate, uint64_t tx_id))
{
    SCEnter();

    alp_ctx.ctxs[FlowGetProtoMapping(ipproto)][alproto].
        StateGetTx = StateGetTx;

    SCReturn;
}

void AppLayerParserRegisterGetStateProgressCompletionStatus(uint16_t ipproto,
                                                   uint16_t alproto,
    int (*StateGetProgressCompletionStatus)(uint8_t direction))
{
    SCEnter();

    alp_ctx.ctxs[FlowGetProtoMapping(ipproto)][alproto].
        StateGetProgressCompletionStatus = StateGetProgressCompletionStatus;

    SCReturn;
}

void AppLayerParserRegisterGetEventInfo(uint16_t ipproto, AppProto alproto,
    int (*StateGetEventInfo)(const char *event_name, int *event_id,
                             AppLayerEventType *event_type))
{
    SCEnter();

    alp_ctx.ctxs[FlowGetProtoMapping(ipproto)][alproto].
        StateGetEventInfo = StateGetEventInfo;

    SCReturn;
}

/***** Get and transaction functions *****/

void *AppLayerParserGetProtocolParserLocalStorage(uint16_t ipproto, AppProto alproto)
{
    SCEnter();

    if (alp_ctx.ctxs[FlowGetProtoMapping(ipproto)][alproto].
        LocalStorageAlloc != NULL)
    {
        SCReturnPtr(alp_ctx.ctxs[FlowGetProtoMapping(ipproto)][alproto].
                    LocalStorageAlloc(), "void *");
    }

    SCReturnPtr(NULL, "void *");
}

void AppLayerParserDestroyProtocolParserLocalStorage(uint16_t ipproto, AppProto alproto,
                                          void *local_data)
{
    SCEnter();

    if (alp_ctx.ctxs[FlowGetProtoMapping(ipproto)][alproto].
        LocalStorageFree != NULL)
    {
        alp_ctx.ctxs[FlowGetProtoMapping(ipproto)][alproto].
            LocalStorageFree(local_data);
    }

    SCReturn;
}

uint64_t AppLayerParserGetTransactionLogId(void *pstate)
{
    SCEnter();

    SCReturnCT(((AppLayerParserParserState *)pstate)->log_id, "uint64_t");
}

void AppLayerParserSetTransactionLogId(void *pstate)
{
    SCEnter();

    ((AppLayerParserParserState *)pstate)->log_id++;

    SCReturn;
}

uint64_t AppLayerParserGetTransactionInspectId(void *pstate, uint8_t direction)
{
    SCEnter();

    SCReturnCT(((AppLayerParserParserState *)pstate)->
               inspect_id[direction & STREAM_TOSERVER ? 0 : 1], "uint64_t");
}

void AppLayerParserSetTransactionInspectId(void *pstate,
                                           uint16_t ipproto, AppProto alproto, void *alstate,
                                           uint8_t direction)
{
    SCEnter();

    uint8_t dir = (direction & STREAM_TOSERVER) ? 0 : 1;
    uint64_t total_txs = AppLayerParserGetTxCnt(ipproto, alproto, alstate);
    uint64_t idx = AppLayerParserGetTransactionInspectId(pstate, direction);
    int state_done_progress = AppLayerParserGetStateProgressCompletionStatus(ipproto, alproto, direction);
    void *tx;
    int state_progress;

    for (; idx < total_txs; idx++) {
        tx = AppLayerParserGetTx(ipproto, alproto, alstate, idx);
        if (tx == NULL)
            continue;
        state_progress = AppLayerParserGetStateProgress(ipproto, alproto, tx, direction);
        if (state_progress >= state_done_progress)
            continue;
        else
            break;
    }
    ((AppLayerParserParserState *)pstate)->inspect_id[dir] = idx;

    SCReturn;
}

AppLayerDecoderEvents *AppLayerParserGetDecoderEvents(void *pstate)
{
    SCEnter();

    SCReturnPtr(((AppLayerParserParserState *)pstate)->decoder_events,
                "AppLayerDecoderEvents *");
}

void AppLayerParserSetDecoderEvents(void *pstate, AppLayerDecoderEvents *devents)
{
    (((AppLayerParserParserState *)pstate)->decoder_events) = devents;
}

AppLayerDecoderEvents *AppLayerParserGetEventsByTx(uint16_t ipproto, AppProto alproto,
                                        void *alstate, uint64_t tx_id)
{
    SCEnter();

    AppLayerDecoderEvents *ptr = NULL;

    if (alp_ctx.ctxs[FlowGetProtoMapping(ipproto)][alproto].
        StateGetEvents != NULL)
    {
        ptr = alp_ctx.ctxs[FlowGetProtoMapping(ipproto)][alproto].
            StateGetEvents(alstate, tx_id);
    }

    SCReturnPtr(ptr, "AppLayerDecoderEvents *");
}

uint16_t AppLayerParserGetStateVersion(void *pstate)
{
    SCEnter();
    SCReturnCT((pstate == NULL) ? 0 : ((AppLayerParserParserState *)pstate)->version,
               "uint16_t");
}

FileContainer *AppLayerParserGetFiles(uint16_t ipproto, AppProto alproto,
                           void *alstate, uint8_t direction)
{
    SCEnter();

    FileContainer *ptr = NULL;

    if (alp_ctx.ctxs[FlowGetProtoMapping(ipproto)][alproto].
        StateGetFiles != NULL)
    {
        ptr = alp_ctx.ctxs[FlowGetProtoMapping(ipproto)][alproto].
            StateGetFiles(alstate, direction);
    }

    SCReturnPtr(ptr, "FileContainer *");
}

int AppLayerParserGetStateProgress(uint16_t ipproto, AppProto alproto,
                        void *alstate, uint8_t direction)
{
    SCEnter();
    SCReturnInt(alp_ctx.ctxs[FlowGetProtoMapping(ipproto)][alproto].
                StateGetProgress(alstate, direction));
}

uint64_t AppLayerParserGetTxCnt(uint16_t ipproto, AppProto alproto, void *alstate)
{
    SCEnter();
    SCReturnCT(alp_ctx.ctxs[FlowGetProtoMapping(ipproto)][alproto].
               StateGetTxCnt(alstate), "uint64_t");
}

void *AppLayerParserGetTx(uint16_t ipproto, AppProto alproto, void *alstate, uint64_t tx_id)
{
    SCEnter();
    SCReturnPtr(alp_ctx.ctxs[FlowGetProtoMapping(ipproto)][alproto].
                StateGetTx(alstate, tx_id), "void *");
}

int AppLayerParserGetStateProgressCompletionStatus(uint16_t ipproto, AppProto alproto,
                                        uint8_t direction)
{
    SCEnter();
    SCReturnInt(alp_ctx.ctxs[FlowGetProtoMapping(ipproto)][alproto].
                StateGetProgressCompletionStatus(direction));

}

int AppLayerParserGetEventInfo(uint16_t ipproto, AppProto alproto, const char *event_name,
                    int *event_id, AppLayerEventType *event_type)
{
    SCEnter();
    int ipproto_map = FlowGetProtoMapping(ipproto);
    SCReturnInt((alp_ctx.ctxs[ipproto_map][alproto].StateGetEventInfo == NULL) ?
                -1 :
                alp_ctx.ctxs[ipproto_map][alproto].
                StateGetEventInfo(event_name, event_id, event_type));
}

uint8_t AppLayerParserGetFirstDataDir(uint16_t ipproto, uint16_t alproto)
{
    SCEnter();
    SCReturnCT(alp_ctx.ctxs[FlowGetProtoMapping(ipproto)][alproto].
               first_data_dir, "uint8_t");
}

uint64_t AppLayerParserGetTransactionActive(uint16_t ipproto, AppProto alproto, void *pstate, uint8_t direction)
{
    SCEnter();

    AppLayerParserParserState *pstate_1 = (AppLayerParserParserState *)pstate;
    uint64_t active_id;

    uint64_t log_id = pstate_1->log_id;
    uint64_t inspect_id = pstate_1->inspect_id[direction & STREAM_TOSERVER ? 0 : 1];
    if (alp_ctx.ctxs[FlowGetProtoMapping(ipproto)][alproto].logger == TRUE) {
        active_id = (log_id < inspect_id) ? log_id : inspect_id;
    } else {
        active_id = inspect_id;
    }

    SCReturnCT(active_id, "uint64_t");
}

/***** General *****/

int AppLayerParserParse(void *tctx, Flow *f, AppProto alproto,
                        uint8_t flags, uint8_t *input, uint32_t input_len)
{
    SCEnter();

    AppLayerParserParserState *pstate = NULL;
    AppLayerParserpCtx *p = &alp_ctx.ctxs[FlowGetProtoMapping(f->proto)][alproto];
    TcpSession *ssn = NULL;
    void *alstate = NULL;
    AppLayerParserCtxThread *alp_tctx = (AppLayerParserCtxThread *)tctx;

    /* we don't have the parser registered for this protocol */
    if (p->StateAlloc == NULL)
        goto end;

    /* Used only if it's TCP */
    ssn = f->protoctx;

    /* Do this check before calling AppLayerParse */
    if (flags & STREAM_GAP) {
        SCLogDebug("stream gap detected (missing packets), "
                   "this is not yet supported.");

        if (f->alstate != NULL)
            AppLayerParserStreamTruncated(f->proto, alproto, f->alstate, flags);
        goto error;
    }

    /* Get the parser state (if any) */
    pstate = f->alparser;
    if (pstate == NULL) {
        f->alparser = pstate = AppLayerParserAllocAppLayerParserParserState();
        if (pstate == NULL)
            goto error;
    }
    pstate->version++;
    SCLogDebug("app layer parser state version incremented to %"PRIu16,
               pstate->version);

    if (flags & STREAM_EOF)
        AppLayerParserParserStateSetFlag(pstate, APP_LAYER_PARSER_EOF);

    alstate = f->alstate;
    if (alstate == NULL) {
        f->alstate = alstate = p->StateAlloc();
        if (alstate == NULL)
            goto error;
        SCLogDebug("alloced new app layer state %p (name %s)",
                   alstate, AppLayerGetProtoName(f->alproto));
    } else {
        SCLogDebug("using existing app layer state %p (name %s))",
                   alstate, AppLayerGetProtoName(f->alproto));
    }

    /* invoke the recursive parser, but only on data. We may get empty msgs on EOF */
    if (input_len > 0) {
        /* invoke the parser */
        if (p->Parser[(flags & STREAM_TOSERVER) ? 0 : 1](f, alstate, pstate,
                input, input_len,
                alp_tctx->alproto_local_storage[FlowGetProtoMapping(f->proto)][alproto]) < 0)
            {
                goto error;
            }
    }

    /* set the packets to no inspection and reassembly if required */
    if (pstate->flags & APP_LAYER_PARSER_NO_INSPECTION) {
        AppLayerParserSetEOF(pstate);
        FlowSetNoPayloadInspectionFlag(f);
        FlowSetSessionNoApplayerInspectionFlag(f);

        /* Set the no reassembly flag for both the stream in this TcpSession */
        if (pstate->flags & APP_LAYER_PARSER_NO_REASSEMBLY) {
            if (ssn != NULL) {
                StreamTcpSetSessionNoReassemblyFlag(ssn,
                                                    flags & STREAM_TOCLIENT ? 1 : 0);
                StreamTcpSetSessionNoReassemblyFlag(ssn,
                                                    flags & STREAM_TOSERVER ? 1 : 0);
            }
        }
    }

    /* next, see if we can get rid of transactions now */
    AppLayerParserTransactionsCleanup(f->proto, alproto, alstate, pstate);

    /* stream truncated, inform app layer */
    if (flags & STREAM_DEPTH)
        AppLayerParserStreamTruncated(f->proto, alproto, alstate, flags);

 end:
    SCReturnInt(0);
 error:
    if (ssn != NULL) {
        /* Set the no app layer inspection flag for both
         * the stream in this Flow */
        FlowSetSessionNoApplayerInspectionFlag(f);
        AppLayerParserSetEOF(pstate);
    }
    SCReturnInt(-1);
}

void AppLayerParserSetEOF(void *pstate)
{
    SCEnter();

    if (pstate == NULL)
        goto end;

    AppLayerParserParserStateSetFlag(pstate, APP_LAYER_PARSER_EOF);
    /* increase version so we will inspect it one more time
     * with the EOF flags now set */
    ((AppLayerParserParserState *)pstate)->version++;

 end:
    SCReturn;
}

int AppLayerParserHasDecoderEvents(uint16_t ipproto, AppProto alproto,
                                   void *alstate, void *pstate,
                                   uint8_t flags)
{
    SCEnter();

    if (alstate == NULL || pstate == NULL)
        goto not_present;

    AppLayerDecoderEvents *decoder_events;
    uint64_t tx_id;
    uint64_t max_id;

    if (AppLayerParserProtocolIsTxEventAware(ipproto, alproto)) {
        /* fast path if supported by alproto */
        if (alp_ctx.ctxs[FlowGetProtoMapping(ipproto)][alproto].StateHasEvents != NULL) {
            if (alp_ctx.ctxs[FlowGetProtoMapping(ipproto)][alproto].
                StateHasEvents(alstate) == 1)
            {
                goto present;
            }
        } else {
            /* check each tx */
            tx_id = AppLayerParserGetTransactionInspectId(pstate, flags);
            max_id = AppLayerParserGetTxCnt(ipproto, alproto, alstate);
            for ( ; tx_id < max_id; tx_id++) {
                decoder_events = AppLayerParserGetEventsByTx(ipproto, alproto, alstate, tx_id);
                if (decoder_events && decoder_events->cnt)
                    goto present;
            }
        }
    }

    decoder_events = AppLayerParserGetDecoderEvents(pstate);
    if (decoder_events && decoder_events->cnt)
        goto present;

    /* if we have reached here, we don't have events */
 not_present:
    SCReturnInt(0);
 present:
    SCReturnInt(1);
}

int AppLayerParserProtocolIsTxEventAware(uint16_t ipproto, AppProto alproto)
{
    SCEnter();
    int ipproto_map = FlowGetProtoMapping(ipproto);
    SCReturnInt((alp_ctx.ctxs[ipproto_map][alproto].StateHasEvents == NULL) ?
                0 : 1);
}

int AppLayerParserProtocolSupportsTxs(uint16_t ipproto, AppProto alproto)
{
    SCEnter();
    int ipproto_map = FlowGetProtoMapping(ipproto);
    SCReturnInt((alp_ctx.ctxs[ipproto_map][alproto].StateTransactionFree == NULL) ?
                0 : 1);
}

void AppLayerParserTriggerRawStreamReassembly(Flow *f)
{
    SCEnter();

    if (f != NULL && f->protoctx != NULL)
        StreamTcpReassembleTriggerRawReassembly(f->protoctx);

    SCReturn;
}

/***** Cleanup *****/

void AppLayerParserCleanupParserState(uint16_t ipproto, AppProto alproto, void *alstate, void *pstate)
{
    SCEnter();

    AppLayerParserpCtx *ctx = &alp_ctx.ctxs[FlowGetProtoMapping(ipproto)][alproto];

    if (ctx->StateFree != NULL && alstate != NULL)
        ctx->StateFree(alstate);

    /* free the app layer parser api state */
    if (pstate != NULL)
        AppLayerParserDeAllocAppLayerParserParserState(pstate);

    SCReturn;
}


void AppLayerParserRegisterProtocolParsers(void)
{
    SCEnter();

    RegisterHTPParsers();
    RegisterSSLParsers();
    RegisterSMBParsers();
    /** \todo bug 719 */
    //RegisterSMB2Parsers();
    RegisterDCERPCParsers();
    RegisterDCERPCUDPParsers();
    RegisterFTPParsers();
    /* we are disabling the ssh parser temporarily, since we are moving away
     * from some of the archaic features we use in the app layer.  We will
     * reintroduce this parser.  Also do note that keywords that rely on
     * the ssh parser would now be disabled */
#if 0
    RegisterSSHParsers();
#endif
    RegisterSMTPParsers();
    RegisterDNSUDPParsers();
    RegisterDNSTCPParsers();

    /** IMAP */
    AppLayerProtoDetectRegisterProtocol(ALPROTO_IMAP, "imap");
    if (AppLayerProtoDetectConfProtoDetectionEnabled("tcp", "imap")) {
        if (AppLayerProtoDetectPMRegisterPatternCS(IPPROTO_TCP, ALPROTO_IMAP,
                                  "1|20|capability", 12, 0, STREAM_TOSERVER) < 0)
        {
            SCLogInfo("imap proto registration failure\n");
            exit(EXIT_FAILURE);
        }
    } else {
        SCLogInfo("Protocol detection and parser disabled for %s protocol.",
                  "imap");
    }

    /** MSN Messenger */
    AppLayerProtoDetectRegisterProtocol(ALPROTO_MSN, "msn");
    if (AppLayerProtoDetectConfProtoDetectionEnabled("tcp", "msn")) {
        if (AppLayerProtoDetectPMRegisterPatternCS(IPPROTO_TCP, ALPROTO_MSN,
                                    "msn", 10, 6, STREAM_TOSERVER) < 0)
        {
            SCLogInfo("msn proto registration failure\n");
            exit(EXIT_FAILURE);
        }
    } else {
        SCLogInfo("Protocol detection and parser disabled for %s protocol.",
                  "msn");
    }

    return;
}


void AppLayerParserParserStateSetFlag(void *pstate, uint8_t flag)
{
    SCEnter();
    ((AppLayerParserParserState *)pstate)->flags |= flag;
    SCReturn;
}

int AppLayerParserParserStateIssetFlag(void *pstate, uint8_t flag)
{
    SCEnter();
    SCReturnInt(((AppLayerParserParserState *)pstate)->flags & flag);
}


void AppLayerParserStreamTruncated(uint16_t ipproto, AppProto alproto, void *alstate,
                                   uint8_t direction)
{
    SCEnter();


    if (alp_ctx.ctxs[FlowGetProtoMapping(ipproto)][alproto].Truncate != NULL)
        alp_ctx.ctxs[FlowGetProtoMapping(ipproto)][alproto].Truncate(alstate, direction);

    SCReturn;
}

#ifdef DEBUG
void AppLayerParserPrintDetailsParserState(void *pstate)
{
    SCEnter();

    if (pstate == NULL)
        SCReturn;

    AppLayerParserParserState *p = (AppLayerParserParserState *)pstate;
    SCLogDebug("AppLayerParser parser state information for parser state p(%p). "
               "p->inspect_id[0](%"PRIu64"), "
               "p->inspect_id[1](%"PRIu64"), "
               "p->log_id(%"PRIu64"), "
               "p->version(%"PRIu16"), "
               "p->decoder_events(%p).",
               pstate, p->inspect_id[0], p->inspect_id[1], p->log_id,
               p->version, p->decoder_events);

    SCReturn;
}
#endif


/***** Unittests *****/

#ifdef UNITTESTS

static AppLayerParserCtx alp_ctx_backup_unittest;

typedef struct TestState_ {
    uint8_t test;
} TestState;

/**
 *  \brief  Test parser function to test the memory deallocation of app layer
 *          parser of occurence of an error.
 */
static int TestProtocolParser(Flow *f, void *test_state, void *pstate,
                              uint8_t *input, uint32_t input_len,
                              void *local_data)
{
    SCEnter();
    SCReturnInt(-1);
}

/** \brief Function to allocates the Test protocol state memory
 */
static void *TestProtocolStateAlloc(void)
{
    SCEnter();
    void *s = SCMalloc(sizeof(TestState));
    if (unlikely(s == NULL))
        goto end;
    memset(s, 0, sizeof(TestState));
 end:
    SCReturnPtr(s, "TestState");
}

/** \brief Function to free the Test Protocol state memory
 */
static void TestProtocolStateFree(void *s)
{
    SCFree(s);
}

void AppLayerParserRegisterProtocolUnittests(uint16_t ipproto, AppProto alproto,
                                  void (*RegisterUnittests)(void))
{
    SCEnter();
    alp_ctx.ctxs[FlowGetProtoMapping(ipproto)][alproto].
        RegisterUnittests = RegisterUnittests;
    SCReturn;
}

void AppLayerParserBackupParserTable(void)
{
    SCEnter();
    alp_ctx_backup_unittest = alp_ctx;
    memset(&alp_ctx, 0, sizeof(alp_ctx));
    SCReturn;
}

void AppLayerParserRestoreParserTable(void)
{
    SCEnter();
    alp_ctx = alp_ctx_backup_unittest;
    memset(&alp_ctx_backup_unittest, 0, sizeof(alp_ctx_backup_unittest));
    SCReturn;
}

/**
 * \test Test the deallocation of app layer parser memory on occurance of
 *       error in the parsing process.
 */
static int AppLayerParserTest01(void)
{
    AppLayerParserBackupParserTable();

    int result = 0;
    Flow *f = NULL;
    uint8_t testbuf[] = { 0x11 };
    uint32_t testlen = sizeof(testbuf);
    TcpSession ssn;
    void *alp_tctx = AppLayerParserGetCtxThread();

    memset(&ssn, 0, sizeof(ssn));

    /* Register the Test protocol state and parser functions */
    AppLayerParserRegisterParser(IPPROTO_TCP, ALPROTO_TEST, STREAM_TOSERVER,
                      TestProtocolParser);
    AppLayerParserRegisterStateFuncs(IPPROTO_TCP, ALPROTO_TEST,
                          TestProtocolStateAlloc, TestProtocolStateFree);

    f = UTHBuildFlow(AF_INET, "1.2.3.4", "4.3.2.1", 20, 40);
    if (f == NULL)
        goto end;
    f->protoctx = &ssn;
    f->alproto = ALPROTO_TEST;
    f->proto = IPPROTO_TCP;

    StreamTcpInitConfig(TRUE);

    SCMutexLock(&f->m);
    int r = AppLayerParserParse(alp_tctx, f, ALPROTO_TEST, STREAM_TOSERVER|STREAM_EOF,
                           testbuf, testlen);
    if (r != -1) {
        printf("returned %" PRId32 ", expected -1: ", r);
        SCMutexUnlock(&f->m);
        goto end;
    }
    SCMutexUnlock(&f->m);

    if (!(f->flags & FLOW_NO_APPLAYER_INSPECTION)) {
        printf("flag should have been set, but is not: ");
        goto end;
    }

    result = 1;
 end:
    AppLayerParserRestoreParserTable();
    StreamTcpFreeConfig(TRUE);

    UTHFreeFlow(f);
    return result;
}

/**
 * \test Test the deallocation of app layer parser memory on occurance of
 *       error in the parsing process for UDP.
 */
static int AppLayerParserTest02(void)
{
    AppLayerParserBackupParserTable();

    int result = 1;
    Flow *f = NULL;
    uint8_t testbuf[] = { 0x11 };
    uint32_t testlen = sizeof(testbuf);
    void *alp_tctx = AppLayerParserGetCtxThread();

    /* Register the Test protocol state and parser functions */
    AppLayerParserRegisterParser(IPPROTO_UDP, ALPROTO_TEST, STREAM_TOSERVER,
                      TestProtocolParser);
    AppLayerParserRegisterStateFuncs(IPPROTO_UDP, ALPROTO_TEST,
                          TestProtocolStateAlloc, TestProtocolStateFree);

    f = UTHBuildFlow(AF_INET, "1.2.3.4", "4.3.2.1", 20, 40);
    if (f == NULL)
        goto end;
    f->alproto = ALPROTO_TEST;
    f->proto = IPPROTO_UDP;

    StreamTcpInitConfig(TRUE);

    SCMutexLock(&f->m);
    int r = AppLayerParserParse(alp_tctx, f, ALPROTO_TEST, STREAM_TOSERVER|STREAM_EOF, testbuf,
                          testlen);
    if (r != -1) {
        printf("returned %" PRId32 ", expected -1: \n", r);
        result = 0;
        SCMutexUnlock(&f->m);
        goto end;
    }
    SCMutexUnlock(&f->m);

 end:
    AppLayerParserRestoreParserTable();
    StreamTcpFreeConfig(TRUE);
    UTHFreeFlow(f);
    return result;
}


void AppLayerParserRegisterUnittests(void)
{
    SCEnter();

    int ip;
    uint16_t alproto;
    AppLayerParserpCtx *ctx;

    for (ip = 0; ip < FLOW_PROTO_DEFAULT; ip++) {
        for (alproto = 0; alproto < ALPROTO_MAX; alproto++) {
            ctx = &alp_ctx.ctxs[ip][alproto];
            if (ctx->RegisterUnittests == NULL)
                continue;
            ctx->RegisterUnittests();
        }
    }

    UtRegisterTest("AppLayerParserTest01", AppLayerParserTest01, 1);
    UtRegisterTest("AppLayerParserTest02", AppLayerParserTest02, 1);

    SCReturn;
}

#endif
