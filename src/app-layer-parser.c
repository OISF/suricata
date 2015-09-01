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
#include "app-layer-modbus.h"
#include "app-layer-template.h"

#include "conf.h"
#include "util-spm.h"

#include "util-debug.h"
#include "decode-events.h"
#include "util-unittest-helper.h"
#include "util-validate.h"

#include "runmodes.h"

static GetActiveTxIdFunc AppLayerGetActiveTxIdFuncPtr = NULL;

struct AppLayerParserThreadCtx_ {
    void *alproto_local_storage[FLOW_PROTO_MAX][ALPROTO_MAX];
};


/**
 * \brief App layer protocol parser context.
 */
typedef struct AppLayerParserProtoCtx_
{
    /* 0 - to_server, 1 - to_client. */
    int (*Parser[2])(Flow *f, void *protocol_state,
                     AppLayerParserState *pstate,
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

    int (*StateHasTxDetectState)(void *alstate);
    DetectEngineState *(*GetTxDetectState)(void *tx);
    int (*SetTxDetectState)(void *alstate, void *tx, DetectEngineState *);

    /* Indicates the direction the parser is ready to see the data
     * the first time for a flow.  Values accepted -
     * STREAM_TOSERVER, STREAM_TOCLIENT */
    uint8_t first_data_dir;

#ifdef UNITTESTS
    void (*RegisterUnittests)(void);
#endif
} AppLayerParserProtoCtx;

typedef struct AppLayerParserCtx_ {
    AppLayerParserProtoCtx ctxs[FLOW_PROTO_MAX][ALPROTO_MAX];
} AppLayerParserCtx;

struct AppLayerParserState_ {
    uint8_t flags;

    /* State version, incremented for each update.  Can wrap around. */
    uint8_t version;
    /* Indicates the current transaction that is being inspected.
     * We have a var per direction. */
    uint64_t inspect_id[2];
    /* Indicates the current transaction being logged.  Unlike inspect_id,
     * we don't need a var per direction since we don't log a transaction
     * unless we have the entire transaction. */
    uint64_t log_id;

    /* Used to store decoder events. */
    AppLayerDecoderEvents *decoder_events;
};

/* Static global version of the parser context.
 * Post 2.0 let's look at changing this to move it out to app-layer.c. */
static AppLayerParserCtx alp_ctx;

AppLayerParserState *AppLayerParserStateAlloc(void)
{
    SCEnter();

    AppLayerParserState *pstate = (AppLayerParserState *)SCMalloc(sizeof(*pstate));
    if (pstate == NULL)
        goto end;
    memset(pstate, 0, sizeof(*pstate));

 end:
    SCReturnPtr(pstate, "AppLayerParserState");
}

void AppLayerParserStateFree(AppLayerParserState *pstate)
{
    SCEnter();

    if (pstate->decoder_events != NULL)
        AppLayerDecoderEventsFreeEvents(&pstate->decoder_events);
    SCFree(pstate);

    SCReturn;
}

int AppLayerParserSetup(void)
{
    SCEnter();

    memset(&alp_ctx, 0, sizeof(alp_ctx));

    /* set the default tx handler if none was set explicitly */
    if (AppLayerGetActiveTxIdFuncPtr == NULL) {
        RegisterAppLayerGetActiveTxIdFunc(AppLayerTransactionGetActiveDetectLog);
    }

    SCReturnInt(0);
}

int AppLayerParserDeSetup(void)
{
    SCEnter();

    SCReturnInt(0);
}

AppLayerParserThreadCtx *AppLayerParserThreadCtxAlloc(void)
{
    SCEnter();

    AppProto alproto = 0;
    int flow_proto = 0;
    AppLayerParserThreadCtx *tctx;

    tctx = SCMalloc(sizeof(*tctx));
    if (tctx == NULL)
        goto end;
    memset(tctx, 0, sizeof(*tctx));

    for (flow_proto = 0; flow_proto < FLOW_PROTO_DEFAULT; flow_proto++) {
        for (alproto = 0; alproto < ALPROTO_MAX; alproto++) {
            uint8_t ipproto = FlowGetReverseProtoMapping(flow_proto);

            tctx->alproto_local_storage[flow_proto][alproto] =
                AppLayerParserGetProtocolParserLocalStorage(ipproto, alproto);
        }
    }

 end:
    SCReturnPtr(tctx, "void *");
}

void AppLayerParserThreadCtxFree(AppLayerParserThreadCtx *tctx)
{
    SCEnter();

    AppProto alproto = 0;
    int flow_proto = 0;

    for (flow_proto = 0; flow_proto < FLOW_PROTO_DEFAULT; flow_proto++) {
        for (alproto = 0; alproto < ALPROTO_MAX; alproto++) {
            uint8_t ipproto = FlowGetReverseProtoMapping(flow_proto);

            AppLayerParserDestroyProtocolParserLocalStorage(ipproto, alproto,
                                                            tctx->alproto_local_storage[flow_proto][alproto]);
        }
    }

    SCFree(tctx);
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
        goto disabled;
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

int AppLayerParserRegisterParser(uint8_t ipproto, AppProto alproto,
                      uint8_t direction,
                      int (*Parser)(Flow *f, void *protocol_state,
                                    AppLayerParserState *pstate,
                                    uint8_t *buf, uint32_t buf_len,
                                    void *local_storage))
{
    SCEnter();

    alp_ctx.ctxs[FlowGetProtoMapping(ipproto)][alproto].
        Parser[(direction & STREAM_TOSERVER) ? 0 : 1] = Parser;

    SCReturnInt(0);
}

void AppLayerParserRegisterParserAcceptableDataDirection(uint8_t ipproto, AppProto alproto,
                                              uint8_t direction)
{
    SCEnter();

    alp_ctx.ctxs[FlowGetProtoMapping(ipproto)][alproto].first_data_dir |=
        (direction & (STREAM_TOSERVER | STREAM_TOCLIENT));

    SCReturn;
}

void AppLayerParserRegisterStateFuncs(uint8_t ipproto, AppProto alproto,
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

void AppLayerParserRegisterLocalStorageFunc(uint8_t ipproto, AppProto alproto,
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

void AppLayerParserRegisterGetFilesFunc(uint8_t ipproto, AppProto alproto,
                             FileContainer *(*StateGetFiles)(void *, uint8_t))
{
    SCEnter();

    alp_ctx.ctxs[FlowGetProtoMapping(ipproto)][alproto].StateGetFiles =
        StateGetFiles;

    SCReturn;
}

void AppLayerParserRegisterGetEventsFunc(uint8_t ipproto, AppProto alproto,
    AppLayerDecoderEvents *(*StateGetEvents)(void *, uint64_t))
{
    SCEnter();

    alp_ctx.ctxs[FlowGetProtoMapping(ipproto)][alproto].StateGetEvents =
        StateGetEvents;

    SCReturn;
}

void AppLayerParserRegisterHasEventsFunc(uint8_t ipproto, AppProto alproto,
                              int (*StateHasEvents)(void *))
{
    SCEnter();

    alp_ctx.ctxs[FlowGetProtoMapping(ipproto)][alproto].StateHasEvents =
        StateHasEvents;

    SCReturn;
}

void AppLayerParserRegisterLogger(uint8_t ipproto, AppProto alproto)
{
    SCEnter();

    alp_ctx.ctxs[FlowGetProtoMapping(ipproto)][alproto].logger = TRUE;

    SCReturn;
}

void AppLayerParserRegisterTruncateFunc(uint8_t ipproto, AppProto alproto,
                                        void (*Truncate)(void *, uint8_t))
{
    SCEnter();

    alp_ctx.ctxs[FlowGetProtoMapping(ipproto)][alproto].Truncate = Truncate;

    SCReturn;
}

void AppLayerParserRegisterGetStateProgressFunc(uint8_t ipproto, AppProto alproto,
    int (*StateGetProgress)(void *alstate, uint8_t direction))
{
    SCEnter();

    alp_ctx.ctxs[FlowGetProtoMapping(ipproto)][alproto].
        StateGetProgress = StateGetProgress;

    SCReturn;
}

void AppLayerParserRegisterTxFreeFunc(uint8_t ipproto, AppProto alproto,
                           void (*StateTransactionFree)(void *, uint64_t))
{
    SCEnter();

    alp_ctx.ctxs[FlowGetProtoMapping(ipproto)][alproto].
        StateTransactionFree = StateTransactionFree;

    SCReturn;
}

void AppLayerParserRegisterGetTxCnt(uint8_t ipproto, AppProto alproto,
                         uint64_t (*StateGetTxCnt)(void *alstate))
{
    SCEnter();

    alp_ctx.ctxs[FlowGetProtoMapping(ipproto)][alproto].
        StateGetTxCnt = StateGetTxCnt;

    SCReturn;
}

void AppLayerParserRegisterGetTx(uint8_t ipproto, AppProto alproto,
                      void *(StateGetTx)(void *alstate, uint64_t tx_id))
{
    SCEnter();

    alp_ctx.ctxs[FlowGetProtoMapping(ipproto)][alproto].
        StateGetTx = StateGetTx;

    SCReturn;
}

void AppLayerParserRegisterGetStateProgressCompletionStatus(uint8_t ipproto,
                                                   AppProto alproto,
    int (*StateGetProgressCompletionStatus)(uint8_t direction))
{
    SCEnter();

    alp_ctx.ctxs[FlowGetProtoMapping(ipproto)][alproto].
        StateGetProgressCompletionStatus = StateGetProgressCompletionStatus;

    SCReturn;
}

void AppLayerParserRegisterGetEventInfo(uint8_t ipproto, AppProto alproto,
    int (*StateGetEventInfo)(const char *event_name, int *event_id,
                             AppLayerEventType *event_type))
{
    SCEnter();

    alp_ctx.ctxs[FlowGetProtoMapping(ipproto)][alproto].
        StateGetEventInfo = StateGetEventInfo;

    SCReturn;
}

void AppLayerParserRegisterDetectStateFuncs(uint8_t ipproto, AppProto alproto,
        int (*StateHasTxDetectState)(void *alstate),
        DetectEngineState *(*GetTxDetectState)(void *tx),
        int (*SetTxDetectState)(void *alstate, void *tx, DetectEngineState *))
{
    SCEnter();

    alp_ctx.ctxs[FlowGetProtoMapping(ipproto)][alproto].StateHasTxDetectState = StateHasTxDetectState;
    alp_ctx.ctxs[FlowGetProtoMapping(ipproto)][alproto].GetTxDetectState = GetTxDetectState;
    alp_ctx.ctxs[FlowGetProtoMapping(ipproto)][alproto].SetTxDetectState = SetTxDetectState;

    SCReturn;
}

/***** Get and transaction functions *****/

void *AppLayerParserGetProtocolParserLocalStorage(uint8_t ipproto, AppProto alproto)
{
    SCEnter();
    void * r = NULL;

    if (alp_ctx.ctxs[FlowGetProtoMapping(ipproto)][alproto].
        LocalStorageAlloc != NULL)
    {
        r = alp_ctx.ctxs[FlowGetProtoMapping(ipproto)][alproto].
                    LocalStorageAlloc();
    }

    SCReturnPtr(r, "void *");
}

void AppLayerParserDestroyProtocolParserLocalStorage(uint8_t ipproto, AppProto alproto,
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

uint64_t AppLayerParserGetTransactionLogId(AppLayerParserState *pstate)
{
    SCEnter();

    SCReturnCT((pstate == NULL) ? 0 : pstate->log_id, "uint64_t");
}

void AppLayerParserSetTransactionLogId(AppLayerParserState *pstate)
{
    SCEnter();

    if (pstate != NULL)
        pstate->log_id++;

    SCReturn;
}

uint64_t AppLayerParserGetTransactionInspectId(AppLayerParserState *pstate, uint8_t direction)
{
    SCEnter();

    if (pstate == NULL)
        SCReturnCT(0ULL, "uint64_t");

    SCReturnCT(pstate->inspect_id[direction & STREAM_TOSERVER ? 0 : 1], "uint64_t");
}

void AppLayerParserSetTransactionInspectId(AppLayerParserState *pstate,
                                           const uint8_t ipproto, const AppProto alproto,
                                           void *alstate, const uint8_t flags)
{
    SCEnter();

    int direction = (flags & STREAM_TOSERVER) ? 0 : 1;
    uint64_t total_txs = AppLayerParserGetTxCnt(ipproto, alproto, alstate);
    uint64_t idx = AppLayerParserGetTransactionInspectId(pstate, flags);
    int state_done_progress = AppLayerParserGetStateProgressCompletionStatus(ipproto, alproto, flags);
    void *tx;
    int state_progress;

    for (; idx < total_txs; idx++) {
        tx = AppLayerParserGetTx(ipproto, alproto, alstate, idx);
        if (tx == NULL)
            continue;
        state_progress = AppLayerParserGetStateProgress(ipproto, alproto, tx, flags);
        if (state_progress >= state_done_progress)
            continue;
        else
            break;
    }
    pstate->inspect_id[direction] = idx;

    SCReturn;
}

AppLayerDecoderEvents *AppLayerParserGetDecoderEvents(AppLayerParserState *pstate)
{
    SCEnter();

    SCReturnPtr(pstate->decoder_events,
                "AppLayerDecoderEvents *");
}

void AppLayerParserSetDecoderEvents(AppLayerParserState *pstate, AppLayerDecoderEvents *devents)
{
    pstate->decoder_events = devents;
}

AppLayerDecoderEvents *AppLayerParserGetEventsByTx(uint8_t ipproto, AppProto alproto,
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

uint16_t AppLayerParserGetStateVersion(AppLayerParserState *pstate)
{
    SCEnter();
    SCReturnCT((pstate == NULL) ? 0 : pstate->version, "uint8_t");
}

FileContainer *AppLayerParserGetFiles(uint8_t ipproto, AppProto alproto,
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

/** \brief active TX retrieval for normal ops: so with detection and logging
 *
 *  \retval tx_id lowest tx_id that still needs work */
uint64_t AppLayerTransactionGetActiveDetectLog(Flow *f, uint8_t flags)
{
    AppLayerParserProtoCtx *p = &alp_ctx.ctxs[FlowGetProtoMapping(f->proto)][f->alproto];
    uint64_t log_id = f->alparser->log_id;
    uint64_t inspect_id = f->alparser->inspect_id[flags & STREAM_TOSERVER ? 0 : 1];
    if (p->logger == TRUE) {
        return (log_id < inspect_id) ? log_id : inspect_id;
    } else {
        return inspect_id;
    }
}

/** \brief active TX retrieval for logging only: so NO detection
 *
 *  If the logger is enabled, we simply return the log_id here.
 *
 *  Otherwise, we go look for the tx id. There probably is no point
 *  in running this function in that case though. With no detection
 *  and no logging, why run a parser in the first place?
 **/
uint64_t AppLayerTransactionGetActiveLogOnly(Flow *f, uint8_t flags)
{
    AppLayerParserProtoCtx *p = &alp_ctx.ctxs[f->protomap][f->alproto];

    if (p->logger == TRUE) {
        uint64_t log_id = f->alparser->log_id;
        SCLogDebug("returning %"PRIu64, log_id);
        return log_id;
    }

    /* logger is disabled, return highest 'complete' tx id */
    uint64_t total_txs = AppLayerParserGetTxCnt(f->proto, f->alproto, f->alstate);
    uint64_t idx = AppLayerParserGetTransactionInspectId(f->alparser, flags);
    int state_done_progress = AppLayerParserGetStateProgressCompletionStatus(f->proto, f->alproto, flags);
    void *tx;
    int state_progress;

    for (; idx < total_txs; idx++) {
        tx = AppLayerParserGetTx(f->proto, f->alproto, f->alstate, idx);
        if (tx == NULL)
            continue;
        state_progress = AppLayerParserGetStateProgress(f->proto, f->alproto, tx, flags);
        if (state_progress >= state_done_progress)
            continue;
        else
            break;
    }
    SCLogDebug("returning %"PRIu64, idx);
    return idx;
}

void RegisterAppLayerGetActiveTxIdFunc(GetActiveTxIdFunc FuncPtr)
{
    //BUG_ON(AppLayerGetActiveTxIdFuncPtr != NULL);
    AppLayerGetActiveTxIdFuncPtr = FuncPtr;
    SCLogDebug("AppLayerGetActiveTxIdFuncPtr is now %p", AppLayerGetActiveTxIdFuncPtr);
}

/**
 *  \brief Get 'active' tx id, meaning the lowest id that still need work.
 *
 *  \retval id tx id
 */
static uint64_t AppLayerTransactionGetActive(Flow *f, uint8_t flags)
{
    BUG_ON(AppLayerGetActiveTxIdFuncPtr == NULL);

    return AppLayerGetActiveTxIdFuncPtr(f, flags);
}

#ifndef MIN
#define MIN(a, b) (((a) < (b)) ? (a) : (b))
#endif

/**
 * \brief remove obsolete (inspected and logged) transactions
 */
static void AppLayerParserTransactionsCleanup(Flow *f)
{
    DEBUG_ASSERT_FLOW_LOCKED(f);

    AppLayerParserProtoCtx *p = &alp_ctx.ctxs[FlowGetProtoMapping(f->proto)][f->alproto];
    if (p->StateTransactionFree == NULL)
        return;

    uint64_t tx_id_ts = AppLayerTransactionGetActive(f, STREAM_TOSERVER);
    uint64_t tx_id_tc = AppLayerTransactionGetActive(f, STREAM_TOCLIENT);

    uint64_t min = MIN(tx_id_ts, tx_id_tc);
    if (min > 0) {
        SCLogDebug("freeing %"PRIu64" %p", min - 1, p->StateTransactionFree);
        p->StateTransactionFree(f->alstate, min - 1);
    }
}

#define IS_DISRUPTED(flags) \
    ((flags) & (STREAM_DEPTH|STREAM_GAP))

/**
 *  \brief get the progress value for a tx/protocol
 *
 *  If the stream is disrupted, we return the 'completion' value.
 */
int AppLayerParserGetStateProgress(uint8_t ipproto, AppProto alproto,
                        void *alstate, uint8_t flags)
{
    SCEnter();
    int r = 0;
    if (unlikely(IS_DISRUPTED(flags))) {
        r = alp_ctx.ctxs[FlowGetProtoMapping(ipproto)][alproto].
            StateGetProgressCompletionStatus(flags);
    } else {
        r = alp_ctx.ctxs[FlowGetProtoMapping(ipproto)][alproto].
            StateGetProgress(alstate, flags);
    }
    SCReturnInt(r);
}

uint64_t AppLayerParserGetTxCnt(uint8_t ipproto, AppProto alproto, void *alstate)
{
    SCEnter();
    uint64_t r = 0;
    r = alp_ctx.ctxs[FlowGetProtoMapping(ipproto)][alproto].
               StateGetTxCnt(alstate);
    SCReturnCT(r, "uint64_t");
}

void *AppLayerParserGetTx(uint8_t ipproto, AppProto alproto, void *alstate, uint64_t tx_id)
{
    SCEnter();
    void * r = NULL;
    r = alp_ctx.ctxs[FlowGetProtoMapping(ipproto)][alproto].
                StateGetTx(alstate, tx_id);
    SCReturnPtr(r, "void *");
}

int AppLayerParserGetStateProgressCompletionStatus(uint8_t ipproto, AppProto alproto,
                                        uint8_t direction)
{
    SCEnter();
    int r = 0;
    r = alp_ctx.ctxs[FlowGetProtoMapping(ipproto)][alproto].
                StateGetProgressCompletionStatus(direction);
    SCReturnInt(r);
}

int AppLayerParserGetEventInfo(uint8_t ipproto, AppProto alproto, const char *event_name,
                    int *event_id, AppLayerEventType *event_type)
{
    SCEnter();
    int ipproto_map = FlowGetProtoMapping(ipproto);
    int r = (alp_ctx.ctxs[ipproto_map][alproto].StateGetEventInfo == NULL) ?
                -1 : alp_ctx.ctxs[ipproto_map][alproto].StateGetEventInfo(event_name, event_id, event_type);
    SCReturnInt(r);
}

uint8_t AppLayerParserGetFirstDataDir(uint8_t ipproto, AppProto alproto)
{
    SCEnter();
    uint8_t r = 0;
    r = alp_ctx.ctxs[FlowGetProtoMapping(ipproto)][alproto].
               first_data_dir;
    SCReturnCT(r, "uint8_t");
}

uint64_t AppLayerParserGetTransactionActive(uint8_t ipproto, AppProto alproto,
                                            AppLayerParserState *pstate, uint8_t direction)
{
    SCEnter();

    uint64_t active_id;

    uint64_t log_id = pstate->log_id;
    uint64_t inspect_id = pstate->inspect_id[direction & STREAM_TOSERVER ? 0 : 1];
    if (alp_ctx.ctxs[FlowGetProtoMapping(ipproto)][alproto].logger == TRUE) {
        active_id = (log_id < inspect_id) ? log_id : inspect_id;
    } else {
        active_id = inspect_id;
    }

    SCReturnCT(active_id, "uint64_t");
}

int AppLayerParserSupportsTxDetectState(uint8_t ipproto, AppProto alproto)
{
    if (alp_ctx.ctxs[FlowGetProtoMapping(ipproto)][alproto].GetTxDetectState != NULL)
        return TRUE;
    return FALSE;
}

int AppLayerParserHasTxDetectState(uint8_t ipproto, AppProto alproto, void *alstate)
{
    int r;
    SCEnter();
    if (alp_ctx.ctxs[FlowGetProtoMapping(ipproto)][alproto].StateHasTxDetectState == NULL)
        return -ENOSYS;
    r = alp_ctx.ctxs[FlowGetProtoMapping(ipproto)][alproto].StateHasTxDetectState(alstate);
    SCReturnInt(r);
}

DetectEngineState *AppLayerParserGetTxDetectState(uint8_t ipproto, AppProto alproto, void *tx)
{
    SCEnter();
    DetectEngineState *s;
    s = alp_ctx.ctxs[FlowGetProtoMapping(ipproto)][alproto].GetTxDetectState(tx);
    SCReturnPtr(s, "DetectEngineState");
}

int AppLayerParserSetTxDetectState(uint8_t ipproto, AppProto alproto,
                                   void *alstate, void *tx, DetectEngineState *s)
{
    int r;
    SCEnter();
    if ((alp_ctx.ctxs[FlowGetProtoMapping(ipproto)][alproto].GetTxDetectState(tx) != NULL))
        SCReturnInt(-EBUSY);
    r = alp_ctx.ctxs[FlowGetProtoMapping(ipproto)][alproto].SetTxDetectState(alstate, tx, s);
    SCReturnInt(r);
}

/***** General *****/

int AppLayerParserParse(AppLayerParserThreadCtx *alp_tctx, Flow *f, AppProto alproto,
                        uint8_t flags, uint8_t *input, uint32_t input_len)
{
    SCEnter();
#ifdef DEBUG_VALIDATION
    BUG_ON(f->protomap != FlowGetProtoMapping(f->proto));
#endif
    AppLayerParserState *pstate = NULL;
    AppLayerParserProtoCtx *p = &alp_ctx.ctxs[f->protomap][alproto];
    void *alstate = NULL;

    /* we don't have the parser registered for this protocol */
    if (p->StateAlloc == NULL)
        goto end;

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
        f->alparser = pstate = AppLayerParserStateAlloc();
        if (pstate == NULL)
            goto error;
    }
    pstate->version++;
    SCLogDebug("app layer parser state version incremented to %"PRIu8,
               pstate->version);

    if (flags & STREAM_EOF)
        AppLayerParserStateSetFlag(pstate, APP_LAYER_PARSER_EOF);

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
    if (input_len > 0 || (flags & STREAM_EOF)) {
        /* invoke the parser */
        if (p->Parser[(flags & STREAM_TOSERVER) ? 0 : 1](f, alstate, pstate,
                input, input_len,
                alp_tctx->alproto_local_storage[f->protomap][alproto]) < 0)
        {
            goto error;
        }
    }

    /* set the packets to no inspection and reassembly if required */
    if (pstate->flags & APP_LAYER_PARSER_NO_INSPECTION) {
        AppLayerParserSetEOF(pstate);
        FlowSetNoPayloadInspectionFlag(f);

        if (f->proto == IPPROTO_TCP) {
            StreamTcpDisableAppLayer(f);

            /* Set the no reassembly flag for both the stream in this TcpSession */
            if (pstate->flags & APP_LAYER_PARSER_NO_REASSEMBLY) {
                /* Used only if it's TCP */
                TcpSession *ssn = f->protoctx;
                if (ssn != NULL) {
                    StreamTcpSetSessionNoReassemblyFlag(ssn,
                            flags & STREAM_TOCLIENT ? 1 : 0);
                    StreamTcpSetSessionNoReassemblyFlag(ssn,
                            flags & STREAM_TOSERVER ? 1 : 0);
                }
            }
        }
    }

    /* In cases like HeartBleed for TLS we need to inspect AppLayer but not Payload */
    if (!(f->flags & FLOW_NOPAYLOAD_INSPECTION) && pstate->flags & APP_LAYER_PARSER_NO_INSPECTION_PAYLOAD) {
        FlowSetNoPayloadInspectionFlag(f);
        /* Set the no reassembly flag for both the stream in this TcpSession */
        if (f->proto == IPPROTO_TCP) {
            /* Used only if it's TCP */
            TcpSession *ssn = f->protoctx;
            if (ssn != NULL) {
                StreamTcpSetDisableRawReassemblyFlag(ssn, 0);
                StreamTcpSetDisableRawReassemblyFlag(ssn, 1);
            }
        }
    }

    /* next, see if we can get rid of transactions now */
    AppLayerParserTransactionsCleanup(f);

    /* stream truncated, inform app layer */
    if (flags & STREAM_DEPTH)
        AppLayerParserStreamTruncated(f->proto, alproto, alstate, flags);

 end:
    SCReturnInt(0);
 error:
    /* Set the no app layer inspection flag for both
     * the stream in this Flow */
    if (f->proto == IPPROTO_TCP) {
        StreamTcpDisableAppLayer(f);
    }
    AppLayerParserSetEOF(pstate);
    SCReturnInt(-1);
}

void AppLayerParserSetEOF(AppLayerParserState *pstate)
{
    SCEnter();

    if (pstate == NULL)
        goto end;

    AppLayerParserStateSetFlag(pstate, APP_LAYER_PARSER_EOF);
    /* increase version so we will inspect it one more time
     * with the EOF flags now set */
    pstate->version++;

 end:
    SCReturn;
}

int AppLayerParserHasDecoderEvents(uint8_t ipproto, AppProto alproto,
                                   void *alstate, AppLayerParserState *pstate,
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

int AppLayerParserProtocolIsTxAware(uint8_t ipproto, AppProto alproto)
{
    SCEnter();
    int ipproto_map = FlowGetProtoMapping(ipproto);
    int r = (alp_ctx.ctxs[ipproto_map][alproto].StateGetTx == NULL) ? 0 : 1;
    SCReturnInt(r);
}

int AppLayerParserProtocolIsTxEventAware(uint8_t ipproto, AppProto alproto)
{
    SCEnter();
    int ipproto_map = FlowGetProtoMapping(ipproto);
    int r = (alp_ctx.ctxs[ipproto_map][alproto].StateGetEvents == NULL) ? 0 : 1;
    SCReturnInt(r);
}

int AppLayerParserProtocolSupportsTxs(uint8_t ipproto, AppProto alproto)
{
    SCEnter();
    int ipproto_map = FlowGetProtoMapping(ipproto);
    int r = (alp_ctx.ctxs[ipproto_map][alproto].StateTransactionFree == NULL) ? 0 : 1;
    SCReturnInt(r);
}

int AppLayerParserProtocolHasLogger(uint8_t ipproto, AppProto alproto)
{
    SCEnter();
    int ipproto_map = FlowGetProtoMapping(ipproto);
    int r = (alp_ctx.ctxs[ipproto_map][alproto].logger == 0) ? 0 : 1;
    SCReturnInt(r);
}

void AppLayerParserTriggerRawStreamReassembly(Flow *f)
{
    SCEnter();

    if (f != NULL && f->protoctx != NULL)
        StreamTcpReassembleTriggerRawReassembly(f->protoctx);

    SCReturn;
}

/***** Cleanup *****/

void AppLayerParserStateCleanup(uint8_t ipproto, AppProto alproto, void *alstate,
                                AppLayerParserState *pstate)
{
    SCEnter();

    AppLayerParserProtoCtx *ctx = &alp_ctx.ctxs[FlowGetProtoMapping(ipproto)][alproto];

    if (ctx->StateFree != NULL && alstate != NULL)
        ctx->StateFree(alstate);

    /* free the app layer parser api state */
    if (pstate != NULL)
        AppLayerParserStateFree(pstate);

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
    RegisterSSHParsers();
    RegisterSMTPParsers();
    RegisterDNSUDPParsers();
    RegisterDNSTCPParsers();
    RegisterModbusParsers();
    RegisterTemplateParsers();

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


void AppLayerParserStateSetFlag(AppLayerParserState *pstate, uint8_t flag)
{
    SCEnter();
    pstate->flags |= flag;
    SCReturn;
}

int AppLayerParserStateIssetFlag(AppLayerParserState *pstate, uint8_t flag)
{
    SCEnter();
    SCReturnInt(pstate->flags & flag);
}


void AppLayerParserStreamTruncated(uint8_t ipproto, AppProto alproto, void *alstate,
                                   uint8_t direction)
{
    SCEnter();


    if (alp_ctx.ctxs[FlowGetProtoMapping(ipproto)][alproto].Truncate != NULL)
        alp_ctx.ctxs[FlowGetProtoMapping(ipproto)][alproto].Truncate(alstate, direction);

    SCReturn;
}

#ifdef DEBUG
void AppLayerParserStatePrintDetails(AppLayerParserState *pstate)
{
    SCEnter();

    if (pstate == NULL)
        SCReturn;

    AppLayerParserState *p = pstate;
    SCLogDebug("AppLayerParser parser state information for parser state p(%p). "
               "p->inspect_id[0](%"PRIu64"), "
               "p->inspect_id[1](%"PRIu64"), "
               "p->log_id(%"PRIu64"), "
               "p->version(%"PRIu8"), "
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
static int TestProtocolParser(Flow *f, void *test_state, AppLayerParserState *pstate,
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

void AppLayerParserRegisterProtocolUnittests(uint8_t ipproto, AppProto alproto,
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
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

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

    if (!(ssn.flags & STREAMTCP_FLAG_APP_LAYER_DISABLED)) {
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
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

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
    f->protomap = FlowGetProtoMapping(f->proto);

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
    AppProto alproto;
    AppLayerParserProtoCtx *ctx;

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
