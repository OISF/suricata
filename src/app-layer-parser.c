/* Copyright (C) 2007-2020 Open Information Security Foundation
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
#include "app-layer-detect-proto.h"
#include "app-layer-protos.h"
#include "app-layer-parser.h"
#include "app-layer-smb.h"
#include "app-layer-htp.h"
#include "app-layer-ftp.h"
#include "app-layer-ssl.h"
#include "app-layer-ssh.h"
#include "app-layer-smtp.h"
#include "app-layer-modbus.h"
#include "app-layer-enip.h"
#include "app-layer-dnp3.h"
#include "app-layer-nfs-tcp.h"
#include "app-layer-nfs-udp.h"
#include "app-layer-ntp.h"
#include "app-layer-tftp.h"
#include "app-layer-ike.h"
#include "app-layer-krb5.h"
#include "app-layer-snmp.h"
#include "app-layer-sip.h"
#include "app-layer-rfb.h"
#include "app-layer-mqtt.h"
#include "app-layer-quic.h"
#include "app-layer-template.h"
#include "app-layer-template-rust.h"
#include "app-layer-rdp.h"
#include "app-layer-http2.h"

#include "conf.h"
#include "util-spm.h"

#include "util-debug.h"
#include "decode-events.h"
#include "util-unittest-helper.h"
#include "util-validate.h"

#include "runmodes.h"

#include "rust.h"

struct AppLayerParserThreadCtx_ {
    void *alproto_local_storage[FLOW_PROTO_MAX][ALPROTO_MAX];
};


/**
 * \brief App layer protocol parser context.
 */
typedef struct AppLayerParserProtoCtx_
{
    /* 0 - to_server, 1 - to_client. */
    AppLayerParserFPtr Parser[2];

    bool logger;

    /* Indicates the direction the parser is ready to see the data
     * the first time for a flow.  Values accepted -
     * STREAM_TOSERVER, STREAM_TOCLIENT */
    uint8_t first_data_dir;

    uint32_t logger_bits;   /**< registered loggers for this proto */

    void *(*StateAlloc)(void *, AppProto);
    void (*StateFree)(void *);
    void (*StateTransactionFree)(void *, uint64_t);
    void *(*LocalStorageAlloc)(void);
    void (*LocalStorageFree)(void *);

    void (*Truncate)(void *, uint8_t);
    FileContainer *(*StateGetFiles)(void *, uint8_t);

    int (*StateGetProgress)(void *alstate, uint8_t direction);
    uint64_t (*StateGetTxCnt)(void *alstate);
    void *(*StateGetTx)(void *alstate, uint64_t tx_id);
    AppLayerGetTxIteratorFunc StateGetTxIterator;
    int complete_ts;
    int complete_tc;
    int (*StateGetEventInfoById)(int event_id, const char **event_name,
                                 AppLayerEventType *event_type);
    int (*StateGetEventInfo)(const char *event_name,
                             int *event_id, AppLayerEventType *event_type);

    AppLayerTxData *(*GetTxData)(void *tx);
    bool (*ApplyTxConfig)(void *state, void *tx, int mode, AppLayerTxConfig);

    void (*SetStreamDepthFlag)(void *tx, uint8_t flags);

    AppLayerParserGetFrameIdByNameFn GetFrameIdByName;
    AppLayerParserGetFrameNameByIdFn GetFrameNameById;

    /* each app-layer has its own value */
    uint32_t stream_depth;

    /* Option flags such as supporting gaps or not. */
    uint32_t option_flags;
    /* coccinelle: AppLayerParserProtoCtx:option_flags:APP_LAYER_PARSER_OPT_ */

    uint32_t internal_flags;
    /* coccinelle: AppLayerParserProtoCtx:internal_flags:APP_LAYER_PARSER_INT_ */

#ifdef UNITTESTS
    void (*RegisterUnittests)(void);
#endif
} AppLayerParserProtoCtx;

typedef struct AppLayerParserCtx_ {
    AppLayerParserProtoCtx ctxs[FLOW_PROTO_MAX][ALPROTO_MAX];
} AppLayerParserCtx;

struct AppLayerParserState_ {
    /* coccinelle: AppLayerParserState:flags:APP_LAYER_PARSER_ */
    uint8_t flags;

    /* Indicates the current transaction that is being inspected.
     * We have a var per direction. */
    uint64_t inspect_id[2];
    /* Indicates the current transaction being logged.  Unlike inspect_id,
     * we don't need a var per direction since we don't log a transaction
     * unless we have the entire transaction. */
    uint64_t log_id;

    uint64_t min_id;

    /* Used to store decoder events. */
    AppLayerDecoderEvents *decoder_events;

    FramesContainer *frames;
};

enum ExceptionPolicy g_applayerparser_error_policy = EXCEPTION_POLICY_IGNORE;

static void AppLayerConfig(void)
{
    g_applayerparser_error_policy = ExceptionPolicyParse("app-layer.error-policy", true);
}

static void AppLayerParserFramesFreeContainer(FramesContainer *frames)
{
    if (frames != NULL) {
        FramesFree(&frames->toserver);
        FramesFree(&frames->toclient);
        SCFree(frames);
    }
}

void AppLayerFramesFreeContainer(Flow *f)
{
    if (f == NULL || f->alparser == NULL || f->alparser->frames == NULL)
        return;
    AppLayerParserFramesFreeContainer(f->alparser->frames);
    f->alparser->frames = NULL;
}

FramesContainer *AppLayerFramesGetContainer(Flow *f)
{
    if (f == NULL || f->alparser == NULL)
        return NULL;
    return f->alparser->frames;
}

FramesContainer *AppLayerFramesSetupContainer(Flow *f)
{
#ifdef UNITTESTS
    if (f == NULL || f->alparser == NULL || (f->proto == IPPROTO_TCP && f->protoctx == NULL))
        return NULL;
#endif
    DEBUG_VALIDATE_BUG_ON(f == NULL || f->alparser == NULL);
    if (f->alparser->frames == NULL) {
        f->alparser->frames = SCCalloc(1, sizeof(FramesContainer));
        if (f->alparser->frames == NULL) {
            return NULL;
        }
#ifdef DEBUG
        f->alparser->frames->toserver.ipproto = f->proto;
        f->alparser->frames->toserver.alproto = f->alproto;
        f->alparser->frames->toclient.ipproto = f->proto;
        f->alparser->frames->toclient.alproto = f->alproto;
#endif
    }
    return f->alparser->frames;
}

#ifdef UNITTESTS
void UTHAppLayerParserStateGetIds(void *ptr, uint64_t *i1, uint64_t *i2, uint64_t *log, uint64_t *min)
{
    struct AppLayerParserState_ *s = ptr;
    *i1 = s->inspect_id[0];
    *i2 = s->inspect_id[1];
    *log = s->log_id;
    *min = s->min_id;
}
#endif

/* Static global version of the parser context.
 * Post 2.0 let's look at changing this to move it out to app-layer.c. */
static AppLayerParserCtx alp_ctx;

int AppLayerParserProtoIsRegistered(uint8_t ipproto, AppProto alproto)
{
    uint8_t ipproto_map = FlowGetProtoMapping(ipproto);

    return (alp_ctx.ctxs[ipproto_map][alproto].StateAlloc != NULL) ? 1 : 0;
}

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
    AppLayerParserFramesFreeContainer(pstate->frames);
    SCFree(pstate);

    SCReturn;
}

int AppLayerParserSetup(void)
{
    SCEnter();
    memset(&alp_ctx, 0, sizeof(alp_ctx));
    SCReturnInt(0);
}

void AppLayerParserPostStreamSetup(void)
{
    /* lets set a default value for stream_depth */
    for (int flow_proto = 0; flow_proto < FLOW_PROTO_DEFAULT; flow_proto++) {
        for (AppProto alproto = 0; alproto < ALPROTO_MAX; alproto++) {
            if (!(alp_ctx.ctxs[flow_proto][alproto].internal_flags &
                        APP_LAYER_PARSER_INT_STREAM_DEPTH_SET)) {
                alp_ctx.ctxs[flow_proto][alproto].stream_depth =
                    stream_config.reassembly_depth;
            }
        }
    }
}

int AppLayerParserDeSetup(void)
{
    SCEnter();

    FTPParserCleanup();
    SMTPParserCleanup();

    SCReturnInt(0);
}

AppLayerParserThreadCtx *AppLayerParserThreadCtxAlloc(void)
{
    SCEnter();

    AppLayerParserThreadCtx *tctx = SCCalloc(1, sizeof(*tctx));
    if (tctx == NULL)
        goto end;

    for (uint8_t flow_proto = 0; flow_proto < FLOW_PROTO_DEFAULT; flow_proto++) {
        for (AppProto alproto = 0; alproto < ALPROTO_MAX; alproto++) {
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

    for (uint8_t flow_proto = 0; flow_proto < FLOW_PROTO_DEFAULT; flow_proto++) {
        for (AppProto alproto = 0; alproto < ALPROTO_MAX; alproto++) {
            uint8_t ipproto = FlowGetReverseProtoMapping(flow_proto);

            AppLayerParserDestroyProtocolParserLocalStorage(ipproto, alproto,
                                                            tctx->alproto_local_storage[flow_proto][alproto]);
        }
    }

    SCFree(tctx);
    SCReturn;
}

/** \brief check if a parser is enabled in the config
 *  Returns enabled always if: were running unittests
 */
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
        FatalError(SC_ERR_FATAL, "snprintf failure.");
    } else if (r > (int)sizeof(param)) {
        FatalError(SC_ERR_FATAL, "buffer not big enough to write param.");
    }

    node = ConfGetNode(param);
    if (node == NULL) {
        SCLogDebug("Entry for %s not found.", param);
        r = snprintf(param, sizeof(param), "%s%s%s%s%s", "app-layer.protocols.",
                     alproto_name, ".", ipproto, ".enabled");
        if (r < 0) {
            FatalError(SC_ERR_FATAL, "snprintf failure.");
        } else if (r > (int)sizeof(param)) {
            FatalError(SC_ERR_FATAL, "buffer not big enough to write param.");
        }

        node = ConfGetNode(param);
        if (node == NULL) {
            SCLogDebug("Entry for %s not found.", param);
            goto enabled;
        }
    }

    if (ConfValIsTrue(node->val)) {
        goto enabled;
    } else if (ConfValIsFalse(node->val)) {
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
                      AppLayerParserFPtr Parser)
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

void AppLayerParserRegisterOptionFlags(uint8_t ipproto, AppProto alproto,
        uint32_t flags)
{
    SCEnter();

    alp_ctx.ctxs[FlowGetProtoMapping(ipproto)][alproto].option_flags |= flags;

    SCReturn;
}

uint32_t AppLayerParserGetOptionFlags(uint8_t protomap, AppProto alproto)
{
    SCEnter();
    SCReturnUInt(alp_ctx.ctxs[protomap][alproto].option_flags);
}

void AppLayerParserRegisterStateFuncs(uint8_t ipproto, AppProto alproto,
        void *(*StateAlloc)(void *, AppProto), void (*StateFree)(void *))
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

void AppLayerParserRegisterLoggerBits(uint8_t ipproto, AppProto alproto, LoggerId bits)
{
    SCEnter();

    alp_ctx.ctxs[FlowGetProtoMapping(ipproto)][alproto].logger_bits = bits;

    SCReturn;
}

void AppLayerParserRegisterLogger(uint8_t ipproto, AppProto alproto)
{
    SCEnter();

    alp_ctx.ctxs[FlowGetProtoMapping(ipproto)][alproto].logger = true;

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

void AppLayerParserRegisterGetTxIterator(uint8_t ipproto, AppProto alproto,
                      AppLayerGetTxIteratorFunc Func)
{
    SCEnter();
    alp_ctx.ctxs[FlowGetProtoMapping(ipproto)][alproto].StateGetTxIterator = Func;
    SCReturn;
}

void AppLayerParserRegisterStateProgressCompletionStatus(
        AppProto alproto, const int ts, const int tc)
{
    BUG_ON(ts == 0);
    BUG_ON(tc == 0);
    BUG_ON(!AppProtoIsValid(alproto));
    BUG_ON(alp_ctx.ctxs[FLOW_PROTO_DEFAULT][alproto].complete_ts != 0 &&
            alp_ctx.ctxs[FLOW_PROTO_DEFAULT][alproto].complete_ts != ts);
    BUG_ON(alp_ctx.ctxs[FLOW_PROTO_DEFAULT][alproto].complete_tc != 0 &&
            alp_ctx.ctxs[FLOW_PROTO_DEFAULT][alproto].complete_tc != tc);

    alp_ctx.ctxs[FLOW_PROTO_DEFAULT][alproto].complete_ts = ts;
    alp_ctx.ctxs[FLOW_PROTO_DEFAULT][alproto].complete_tc = tc;
}

void AppLayerParserRegisterGetEventInfoById(uint8_t ipproto, AppProto alproto,
    int (*StateGetEventInfoById)(int event_id, const char **event_name,
                                 AppLayerEventType *event_type))
{
    SCEnter();

    alp_ctx.ctxs[FlowGetProtoMapping(ipproto)][alproto].
        StateGetEventInfoById = StateGetEventInfoById;

    SCReturn;
}

void AppLayerParserRegisterGetFrameFuncs(uint8_t ipproto, AppProto alproto,
        AppLayerParserGetFrameIdByNameFn GetIdByNameFunc,
        AppLayerParserGetFrameNameByIdFn GetNameByIdFunc)
{
    SCEnter();
    alp_ctx.ctxs[FlowGetProtoMapping(ipproto)][alproto].GetFrameIdByName = GetIdByNameFunc;
    alp_ctx.ctxs[FlowGetProtoMapping(ipproto)][alproto].GetFrameNameById = GetNameByIdFunc;
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

void AppLayerParserRegisterTxDataFunc(uint8_t ipproto, AppProto alproto,
        AppLayerTxData *(*GetTxData)(void *tx))
{
    SCEnter();

    alp_ctx.ctxs[FlowGetProtoMapping(ipproto)][alproto].GetTxData = GetTxData;

    SCReturn;
}

void AppLayerParserRegisterApplyTxConfigFunc(uint8_t ipproto, AppProto alproto,
        bool (*ApplyTxConfig)(void *state, void *tx, int mode, AppLayerTxConfig))
{
    SCEnter();

    alp_ctx.ctxs[FlowGetProtoMapping(ipproto)][alproto].ApplyTxConfig = ApplyTxConfig;

    SCReturn;
}

void AppLayerParserRegisterSetStreamDepthFlag(uint8_t ipproto, AppProto alproto,
        void (*SetStreamDepthFlag)(void *tx, uint8_t flags))
{
    SCEnter();

    alp_ctx.ctxs[FlowGetProtoMapping(ipproto)][alproto].SetStreamDepthFlag = SetStreamDepthFlag;

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

/** \brief default tx iterator
 *
 *  Used if the app layer parser doesn't register its own iterator.
 *  Simply walks the tx_id space until it finds a tx. Uses 'state' to
 *  keep track of where it left off.
 *
 *  \retval txptr or NULL if no more txs in list
 */
static AppLayerGetTxIterTuple AppLayerDefaultGetTxIterator(
        const uint8_t ipproto, const AppProto alproto,
        void *alstate, uint64_t min_tx_id, uint64_t max_tx_id,
        AppLayerGetTxIterState *state)
{
    uint64_t ustate = *(uint64_t *)state;
    uint64_t tx_id = MAX(min_tx_id, ustate);
    for ( ; tx_id < max_tx_id; tx_id++) {
        void *tx_ptr = AppLayerParserGetTx(ipproto, alproto, alstate, tx_id);
        if (tx_ptr != NULL) {
            ustate = tx_id + 1;
            *state = *(AppLayerGetTxIterState *)&ustate;
            AppLayerGetTxIterTuple tuple = {
                .tx_ptr = tx_ptr,
                .tx_id = tx_id,
                .has_next = (tx_id + 1 < max_tx_id),
            };
            SCLogDebug("tuple: %p/%"PRIu64"/%s", tuple.tx_ptr, tuple.tx_id,
                    tuple.has_next ? "true" : "false");
            return tuple;
        }
    }

    AppLayerGetTxIterTuple no_tuple = { NULL, 0, false };
    return no_tuple;
}

AppLayerGetTxIteratorFunc AppLayerGetTxIterator(const uint8_t ipproto,
        const AppProto alproto)
{
    AppLayerGetTxIteratorFunc Func =
        alp_ctx.ctxs[FlowGetProtoMapping(ipproto)][alproto].StateGetTxIterator;
    return Func ? Func : AppLayerDefaultGetTxIterator;
}

uint64_t AppLayerParserGetTransactionLogId(AppLayerParserState *pstate)
{
    SCEnter();

    SCReturnCT((pstate == NULL) ? 0 : pstate->log_id, "uint64_t");
}

void AppLayerParserSetTransactionLogId(AppLayerParserState *pstate, uint64_t tx_id)
{
    SCEnter();

    if (pstate != NULL)
        pstate->log_id = tx_id;

    SCReturn;
}

uint64_t AppLayerParserGetTransactionInspectId(AppLayerParserState *pstate, uint8_t direction)
{
    SCEnter();

    if (pstate == NULL)
        SCReturnCT(0ULL, "uint64_t");

    SCReturnCT(pstate->inspect_id[(direction & STREAM_TOSERVER) ? 0 : 1], "uint64_t");
}

static inline uint64_t GetTxDetectFlags(AppLayerTxData *txd, const uint8_t dir)
{
    uint64_t detect_flags =
        (dir & STREAM_TOSERVER) ? txd->detect_flags_ts : txd->detect_flags_tc;
    return detect_flags;
}

static inline void SetTxDetectFlags(AppLayerTxData *txd, const uint8_t dir, const uint64_t detect_flags)
{
    if (dir & STREAM_TOSERVER) {
        txd->detect_flags_ts = detect_flags;
    } else {
        txd->detect_flags_tc = detect_flags;
    }
}

static inline uint32_t GetTxLogged(AppLayerTxData *txd)
{
    return txd->logged.flags;
}

void AppLayerParserSetTransactionInspectId(const Flow *f, AppLayerParserState *pstate,
                                           void *alstate, const uint8_t flags,
                                           bool tag_txs_as_inspected)
{
    SCEnter();

    const int direction = (flags & STREAM_TOSERVER) ? 0 : 1;
    const uint64_t total_txs = AppLayerParserGetTxCnt(f, alstate);
    uint64_t idx = AppLayerParserGetTransactionInspectId(pstate, flags);
    const int state_done_progress = AppLayerParserGetStateProgressCompletionStatus(f->alproto, flags);
    const uint8_t ipproto = f->proto;
    const AppProto alproto = f->alproto;

    AppLayerGetTxIteratorFunc IterFunc = AppLayerGetTxIterator(ipproto, alproto);
    AppLayerGetTxIterState state;
    memset(&state, 0, sizeof(state));

    SCLogDebug("called: %s, tag_txs_as_inspected %s",direction==0?"toserver":"toclient",
            tag_txs_as_inspected?"true":"false");

    /* mark all txs as inspected if the applayer progress is
     * at the 'end state'. */
    while (1) {
        AppLayerGetTxIterTuple ires = IterFunc(ipproto, alproto, alstate, idx, total_txs, &state);
        if (ires.tx_ptr == NULL)
            break;

        void *tx = ires.tx_ptr;
        idx = ires.tx_id;

        int state_progress = AppLayerParserGetStateProgress(ipproto, alproto, tx, flags);
        if (state_progress < state_done_progress)
            break;

        AppLayerTxData *txd = AppLayerParserGetTxData(ipproto, alproto, tx);
        if (txd && tag_txs_as_inspected) {
            uint64_t detect_flags = GetTxDetectFlags(txd, flags);
            if ((detect_flags & APP_LAYER_TX_INSPECTED_FLAG) == 0) {
                detect_flags |= APP_LAYER_TX_INSPECTED_FLAG;
                SetTxDetectFlags(txd, flags, detect_flags);
                SCLogDebug("%p/%"PRIu64" in-order tx is done for direction %s. Flag %016"PRIx64,
                        tx, idx, flags & STREAM_TOSERVER ? "toserver" : "toclient", detect_flags);
            }
        }
        idx++;
        if (!ires.has_next)
            break;
    }
    pstate->inspect_id[direction] = idx;
    SCLogDebug("inspect_id now %"PRIu64, pstate->inspect_id[direction]);

    /* if necessary we flag all txs that are complete as 'inspected'
     * also move inspect_id forward. */
    if (tag_txs_as_inspected) {
        /* continue at idx */
        while (1) {
            AppLayerGetTxIterTuple ires = IterFunc(ipproto, alproto, alstate, idx, total_txs, &state);
            if (ires.tx_ptr == NULL)
                break;

            void *tx = ires.tx_ptr;
            /* if we got a higher id than the minimum we requested, we
             * skipped a bunch of 'null-txs'. Lets see if we can up the
             * inspect tracker */
            if (ires.tx_id > idx && pstate->inspect_id[direction] == idx) {
                pstate->inspect_id[direction] = ires.tx_id;
            }
            idx = ires.tx_id;

            const int state_progress = AppLayerParserGetStateProgress(ipproto, alproto, tx, flags);
            if (state_progress < state_done_progress)
                break;

            /* txd can be NULL for HTTP sessions where the user data alloc failed */
            AppLayerTxData *txd = AppLayerParserGetTxData(ipproto, alproto, tx);
            if (likely(txd)) {
                uint64_t detect_flags = GetTxDetectFlags(txd, flags);
                if ((detect_flags & APP_LAYER_TX_INSPECTED_FLAG) == 0) {
                    detect_flags |= APP_LAYER_TX_INSPECTED_FLAG;
                    SetTxDetectFlags(txd, flags, detect_flags);
                    SCLogDebug("%p/%"PRIu64" out of order tx is done for direction %s. Flag %016"PRIx64,
                            tx, idx, flags & STREAM_TOSERVER ? "toserver" : "toclient", detect_flags);

                    SCLogDebug("%p/%"PRIu64" out of order tx. Update inspect_id? %"PRIu64,
                            tx, idx, pstate->inspect_id[direction]);
                    if (pstate->inspect_id[direction]+1 == idx)
                        pstate->inspect_id[direction] = idx;
                }
            } else {
                if (pstate->inspect_id[direction]+1 == idx)
                    pstate->inspect_id[direction] = idx;
            }
            if (!ires.has_next)
                break;
            idx++;
        }
    }

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
                                        void *tx)
{
    SCEnter();

    AppLayerDecoderEvents *ptr = NULL;

    /* Access events via the tx_data. */
    AppLayerTxData *txd = AppLayerParserGetTxData(ipproto, alproto, tx);
    if (txd != NULL && txd->events != NULL) {
        ptr = txd->events;
    }

    SCReturnPtr(ptr, "AppLayerDecoderEvents *");
}

FileContainer *AppLayerParserGetFiles(const Flow *f, const uint8_t direction)
{
    SCEnter();

    FileContainer *ptr = NULL;

    if (alp_ctx.ctxs[f->protomap][f->alproto].StateGetFiles != NULL)
    {
        ptr = alp_ctx.ctxs[f->protomap][f->alproto].
            StateGetFiles(f->alstate, direction);
    }

    SCReturnPtr(ptr, "FileContainer *");
}

#define IS_DISRUPTED(flags) ((flags) & (STREAM_DEPTH | STREAM_GAP))

extern int g_detect_disabled;
extern bool g_file_logger_enabled;
extern bool g_filedata_logger_enabled;

/**
 * \brief remove obsolete (inspected and logged) transactions
 */
void AppLayerParserTransactionsCleanup(Flow *f)
{
    SCEnter();
    DEBUG_ASSERT_FLOW_LOCKED(f);

    AppLayerParserProtoCtx *p = &alp_ctx.ctxs[f->protomap][f->alproto];
    if (unlikely(p->StateTransactionFree == NULL))
        SCReturn;

    const bool has_tx_detect_flags = !g_detect_disabled;
    const uint8_t ipproto = f->proto;
    const AppProto alproto = f->alproto;
    void * const alstate = f->alstate;
    AppLayerParserState * const alparser = f->alparser;

    if (alstate == NULL || alparser == NULL)
        SCReturn;

    const uint64_t min = alparser->min_id;
    const uint64_t total_txs = AppLayerParserGetTxCnt(f, alstate);
    const LoggerId logger_expectation = AppLayerParserProtocolGetLoggerBits(ipproto, alproto);
    const int tx_end_state_ts = AppLayerParserGetStateProgressCompletionStatus(alproto, STREAM_TOSERVER);
    const int tx_end_state_tc = AppLayerParserGetStateProgressCompletionStatus(alproto, STREAM_TOCLIENT);
    const uint8_t ts_disrupt_flags = FlowGetDisruptionFlags(f, STREAM_TOSERVER);
    const uint8_t tc_disrupt_flags = FlowGetDisruptionFlags(f, STREAM_TOCLIENT);

    AppLayerGetTxIteratorFunc IterFunc = AppLayerGetTxIterator(ipproto, alproto);
    AppLayerGetTxIterState state;
    memset(&state, 0, sizeof(state));
    uint64_t i = min;
    uint64_t new_min = min;
    SCLogDebug("start min %"PRIu64, min);
    bool skipped = false;
    const bool is_unidir =
            AppLayerParserGetOptionFlags(f->protomap, f->alproto) & APP_LAYER_PARSER_OPT_UNIDIR_TXS;

    while (1) {
        AppLayerGetTxIterTuple ires = IterFunc(ipproto, alproto, alstate, i, total_txs, &state);
        if (ires.tx_ptr == NULL)
            break;

        bool tx_skipped = false;
        void *tx = ires.tx_ptr;
        i = ires.tx_id; // actual tx id for the tx the IterFunc returned

        SCLogDebug("%p/%"PRIu64" checking", tx, i);

        const int tx_progress_tc =
                AppLayerParserGetStateProgress(ipproto, alproto, tx, tc_disrupt_flags);
        if (tx_progress_tc < tx_end_state_tc) {
            SCLogDebug("%p/%"PRIu64" skipping: tc parser not done", tx, i);
            skipped = true;
            goto next;
        }
        const int tx_progress_ts =
                AppLayerParserGetStateProgress(ipproto, alproto, tx, ts_disrupt_flags);
        if (tx_progress_ts < tx_end_state_ts) {
            SCLogDebug("%p/%"PRIu64" skipping: ts parser not done", tx, i);
            skipped = true;
            goto next;
        }

        AppLayerTxData *txd = AppLayerParserGetTxData(ipproto, alproto, tx);
        bool inspected = false;
        if (txd && has_tx_detect_flags) {
            if (!IS_DISRUPTED(ts_disrupt_flags) && f->sgh_toserver != NULL) {
                uint64_t detect_flags_ts = GetTxDetectFlags(txd, STREAM_TOSERVER);
                if (!(detect_flags_ts & APP_LAYER_TX_INSPECTED_FLAG)) {
                    SCLogDebug("%p/%"PRIu64" skipping: TS inspect not done: ts:%"PRIx64,
                            tx, i, detect_flags_ts);
                    tx_skipped = true;
                } else {
                    inspected = true;
                }
            }
            if (!IS_DISRUPTED(tc_disrupt_flags) && f->sgh_toclient != NULL) {
                uint64_t detect_flags_tc = GetTxDetectFlags(txd, STREAM_TOCLIENT);
                if (!(detect_flags_tc & APP_LAYER_TX_INSPECTED_FLAG)) {
                    SCLogDebug("%p/%"PRIu64" skipping: TC inspect not done: tc:%"PRIx64,
                            tx, i, detect_flags_tc);
                    tx_skipped = true;
                } else {
                    inspected = true;
                }
            }
        }

        // If not a unidirectional transaction both sides are required to have
        // been inspected.
        if (!is_unidir && tx_skipped) {
            SCLogDebug("%p/%" PRIu64 " !is_unidir && tx_skipped", tx, i);
            skipped = true;
            goto next;
        }

        // If this is a unidirectional transaction require only one side to be
        // inspected, which the inspected flag tells us. This is also guarded
        // with skip to limit this check to transactions that actually had the
        // tx inspected flag checked.
        if (is_unidir && tx_skipped && !inspected) {
            SCLogDebug("%p/%" PRIu64 " is_unidir && tx_skipped && !inspected", tx, i);
            skipped = true;
            goto next;
        }

        if (txd && logger_expectation != 0) {
            LoggerId tx_logged = GetTxLogged(txd);
            if (tx_logged != logger_expectation) {
                SCLogDebug("%p/%"PRIu64" skipping: logging not done: want:%"PRIx32", have:%"PRIx32,
                        tx, i, logger_expectation, tx_logged);
                skipped = true;
                goto next;
            }
        }

        /* if file logging is enabled, we keep a tx active while some of the files aren't
         * logged yet. */
        if (txd && txd->files_opened) {
            if (g_file_logger_enabled && txd->files_opened != txd->files_logged) {
                skipped = true;
                goto next;
            }
            if (g_filedata_logger_enabled && txd->files_opened != txd->files_stored) {
                skipped = true;
                goto next;
            }
        }

        /* if we are here, the tx can be freed. */
        p->StateTransactionFree(alstate, i);
        SCLogDebug("%p/%"PRIu64" freed", tx, i);

        /* if we didn't skip any tx so far, up the minimum */
        SCLogDebug("skipped? %s i %"PRIu64", new_min %"PRIu64, skipped ? "true" : "false", i, new_min);
        if (!skipped)
            new_min = i + 1;
        SCLogDebug("final i %"PRIu64", new_min %"PRIu64, i, new_min);

next:
        if (!ires.has_next) {
            /* this was the last tx. See if we skipped any. If not
             * we removed all and can update the minimum to the max
             * id. */
            SCLogDebug("no next: cur tx i %"PRIu64", total %"PRIu64, i, total_txs);
            if (!skipped) {
                new_min = total_txs;
                SCLogDebug("no next: cur tx i %"PRIu64", total %"PRIu64": "
                        "new_min updated to %"PRIu64, i, total_txs, new_min);
            }
            break;
        }
        i++;
    }

    /* see if we need to bring all trackers up to date. */
    SCLogDebug("update f->alparser->min_id? %"PRIu64" vs %"PRIu64, new_min, alparser->min_id);
    if (new_min > alparser->min_id) {
        const uint64_t next_id = new_min;
        alparser->min_id = next_id;
        alparser->inspect_id[0] = MAX(alparser->inspect_id[0], next_id);
        alparser->inspect_id[1] = MAX(alparser->inspect_id[1], next_id);
        alparser->log_id = MAX(alparser->log_id, next_id);
        SCLogDebug("updated f->alparser->min_id %"PRIu64, alparser->min_id);
    }
    SCReturn;
}

static inline int StateGetProgressCompletionStatus(const AppProto alproto, const uint8_t flags)
{
    if (flags & STREAM_TOSERVER) {
        return alp_ctx.ctxs[FLOW_PROTO_DEFAULT][alproto].complete_ts;
    } else if (flags & STREAM_TOCLIENT) {
        return alp_ctx.ctxs[FLOW_PROTO_DEFAULT][alproto].complete_tc;
    } else {
        DEBUG_VALIDATE_BUG_ON(1);
        return 0;
    }
}

/**
 *  \brief get the progress value for a tx/protocol
 *
 *  If the stream is disrupted, we return the 'completion' value.
 */
int AppLayerParserGetStateProgress(uint8_t ipproto, AppProto alproto,
                        void *alstate, uint8_t flags)
{
    SCEnter();
    int r;
    if (unlikely(IS_DISRUPTED(flags))) {
        r = StateGetProgressCompletionStatus(alproto, flags);
    } else {
        r = alp_ctx.ctxs[FlowGetProtoMapping(ipproto)][alproto].
            StateGetProgress(alstate, flags);
    }
    SCReturnInt(r);
}

uint64_t AppLayerParserGetTxCnt(const Flow *f, void *alstate)
{
    SCEnter();
    uint64_t r = alp_ctx.ctxs[f->protomap][f->alproto].StateGetTxCnt(alstate);
    SCReturnCT(r, "uint64_t");
}

void *AppLayerParserGetTx(uint8_t ipproto, AppProto alproto, void *alstate, uint64_t tx_id)
{
    SCEnter();
    void *r = alp_ctx.ctxs[FlowGetProtoMapping(ipproto)][alproto].StateGetTx(alstate, tx_id);
    SCReturnPtr(r, "void *");
}

int AppLayerParserGetStateProgressCompletionStatus(AppProto alproto,
                                                   uint8_t direction)
{
    SCEnter();
    int r = StateGetProgressCompletionStatus(alproto, direction);
    SCReturnInt(r);
}

int AppLayerParserGetEventInfo(uint8_t ipproto, AppProto alproto, const char *event_name,
                    int *event_id, AppLayerEventType *event_type)
{
    SCEnter();
    const int ipproto_map = FlowGetProtoMapping(ipproto);
    int r = (alp_ctx.ctxs[ipproto_map][alproto].StateGetEventInfo == NULL) ?
                -1 : alp_ctx.ctxs[ipproto_map][alproto].StateGetEventInfo(event_name, event_id, event_type);
    SCReturnInt(r);
}

int AppLayerParserGetEventInfoById(uint8_t ipproto, AppProto alproto, int event_id,
                    const char **event_name, AppLayerEventType *event_type)
{
    SCEnter();
    const int ipproto_map = FlowGetProtoMapping(ipproto);
    *event_name = (const char *)NULL;
    int r = (alp_ctx.ctxs[ipproto_map][alproto].StateGetEventInfoById == NULL) ?
                -1 : alp_ctx.ctxs[ipproto_map][alproto].StateGetEventInfoById(event_id, event_name, event_type);
    SCReturnInt(r);
}

uint8_t AppLayerParserGetFirstDataDir(uint8_t ipproto, AppProto alproto)
{
    SCEnter();
    uint8_t r = alp_ctx.ctxs[FlowGetProtoMapping(ipproto)][alproto].first_data_dir;
    SCReturnCT(r, "uint8_t");
}

uint64_t AppLayerParserGetTransactionActive(const Flow *f,
        AppLayerParserState *pstate, uint8_t direction)
{
    SCEnter();

    uint64_t active_id;
    uint64_t log_id = pstate->log_id;
    uint64_t inspect_id = pstate->inspect_id[(direction & STREAM_TOSERVER) ? 0 : 1];
    if (alp_ctx.ctxs[f->protomap][f->alproto].logger == true) {
        active_id = MIN(log_id, inspect_id);
    } else {
        active_id = inspect_id;
    }

    SCReturnCT(active_id, "uint64_t");
}

int AppLayerParserSupportsFiles(uint8_t ipproto, AppProto alproto)
{
    // Custom case for only signature-only protocol so far
    if (alproto == ALPROTO_HTTP) {
        return AppLayerParserSupportsFiles(ipproto, ALPROTO_HTTP1) ||
               AppLayerParserSupportsFiles(ipproto, ALPROTO_HTTP2);
    }
    if (alp_ctx.ctxs[FlowGetProtoMapping(ipproto)][alproto].StateGetFiles != NULL)
        return TRUE;
    return FALSE;
}

AppLayerTxData *AppLayerParserGetTxData(uint8_t ipproto, AppProto alproto, void *tx)
{
    SCEnter();
    AppLayerTxData *d = alp_ctx.ctxs[FlowGetProtoMapping(ipproto)][alproto].GetTxData(tx);
    SCReturnPtr(d, "AppLayerTxData");
}

void AppLayerParserApplyTxConfig(uint8_t ipproto, AppProto alproto,
        void *state, void *tx, enum ConfigAction mode, AppLayerTxConfig config)
{
    SCEnter();
    const int ipproto_map = FlowGetProtoMapping(ipproto);
    if (alp_ctx.ctxs[ipproto_map][alproto].ApplyTxConfig) {
        alp_ctx.ctxs[ipproto_map][alproto].ApplyTxConfig(state, tx, mode, config);
    }
    SCReturn;
}

/***** General *****/

static inline void SetEOFFlags(AppLayerParserState *pstate, const uint8_t flags)
{
    if ((flags & (STREAM_EOF|STREAM_TOSERVER)) == (STREAM_EOF|STREAM_TOSERVER)) {
        SCLogDebug("setting APP_LAYER_PARSER_EOF_TS");
        AppLayerParserStateSetFlag(pstate, APP_LAYER_PARSER_EOF_TS);
    } else if ((flags & (STREAM_EOF|STREAM_TOCLIENT)) == (STREAM_EOF|STREAM_TOCLIENT)) {
        SCLogDebug("setting APP_LAYER_PARSER_EOF_TC");
        AppLayerParserStateSetFlag(pstate, APP_LAYER_PARSER_EOF_TC);
    }
}

static void Setup(Flow *f, const uint8_t direction, const uint8_t *input, uint32_t input_len,
        const uint8_t flags, StreamSlice *as)
{
    memset(as, 0, sizeof(*as));
    as->input = input;
    as->input_len = input_len;
    as->flags = flags;

    if (f->proto == IPPROTO_TCP && f->protoctx != NULL) {
        TcpSession *ssn = f->protoctx;
        TcpStream *stream = (direction & STREAM_TOSERVER) ? &ssn->client : &ssn->server;
        as->offset = STREAM_APP_PROGRESS(stream);
    }
}

/** \retval int -1 in case of unrecoverable error. App-layer tracking stops for this flow.
 *  \retval int 0 ok: we did not update app_progress
 *  \retval int 1 ok: we updated app_progress */
int AppLayerParserParse(ThreadVars *tv, AppLayerParserThreadCtx *alp_tctx, Flow *f, AppProto alproto,
                        uint8_t flags, const uint8_t *input, uint32_t input_len)
{
    SCEnter();
#ifdef DEBUG_VALIDATION
    BUG_ON(f->protomap != FlowGetProtoMapping(f->proto));
#endif
    AppLayerParserState *pstate = f->alparser;
    AppLayerParserProtoCtx *p = &alp_ctx.ctxs[f->protomap][alproto];
    StreamSlice stream_slice;
    void *alstate = NULL;
    uint64_t p_tx_cnt = 0;
    uint32_t consumed = input_len;
    const uint8_t direction = (flags & STREAM_TOSERVER) ? 0 : 1;

    /* we don't have the parser registered for this protocol */
    if (p->StateAlloc == NULL) {
        if (f->proto == IPPROTO_TCP) {
            StreamTcpDisableAppLayer(f);
        }
        goto end;
    }

    if (flags & STREAM_GAP) {
        if (!(p->option_flags & APP_LAYER_PARSER_OPT_ACCEPT_GAPS)) {
            SCLogDebug("app-layer parser does not accept gaps");
            if (f->alstate != NULL && !FlowChangeProto(f)) {
                AppLayerParserStreamTruncated(f->proto, alproto, f->alstate,
                        flags);
            }
            AppLayerIncGapErrorCounter(tv, f);
            goto error;
        }
    }

    /* Get the parser state (if any) */
    if (pstate == NULL) {
        f->alparser = pstate = AppLayerParserStateAlloc();
        if (pstate == NULL) {
            AppLayerIncAllocErrorCounter(tv, f);
            goto error;
        }
    }

    SetEOFFlags(pstate, flags);

    alstate = f->alstate;
    if (alstate == NULL || FlowChangeProto(f)) {
        f->alstate = alstate = p->StateAlloc(alstate, f->alproto_orig);
        if (alstate == NULL) {
            AppLayerIncAllocErrorCounter(tv, f);
            goto error;
        }
        SCLogDebug("alloced new app layer state %p (name %s)",
                   alstate, AppLayerGetProtoName(f->alproto));
    } else {
        SCLogDebug("using existing app layer state %p (name %s))",
                   alstate, AppLayerGetProtoName(f->alproto));
    }

    p_tx_cnt = AppLayerParserGetTxCnt(f, f->alstate);

    /* invoke the recursive parser, but only on data. We may get empty msgs on EOF */
    if (input_len > 0 || (flags & STREAM_EOF)) {
        Setup(f, flags & (STREAM_TOSERVER | STREAM_TOCLIENT), input, input_len, flags,
                &stream_slice);
#ifdef DEBUG
        if (((stream_slice.flags & STREAM_TOSERVER) &&
                    stream_slice.offset >= g_eps_applayer_error_offset_ts)) {
            SCLogNotice("putting parser %s into an error state from toserver offset %" PRIu64,
                    AppProtoToString(alproto), g_eps_applayer_error_offset_ts);
            AppLayerIncParserErrorCounter(tv, f);
            goto error;
        }
        if (((stream_slice.flags & STREAM_TOCLIENT) &&
                    stream_slice.offset >= g_eps_applayer_error_offset_tc)) {
            SCLogNotice("putting parser %s into an error state from toclient offset %" PRIu64,
                    AppProtoToString(alproto), g_eps_applayer_error_offset_tc);
            AppLayerIncParserErrorCounter(tv, f);
            goto error;
        }
#endif
        /* invoke the parser */
        AppLayerResult res = p->Parser[direction](f, alstate, pstate, stream_slice,
                alp_tctx->alproto_local_storage[f->protomap][alproto]);
        if (res.status < 0) {
            AppLayerIncParserErrorCounter(tv, f);
            goto error;
        } else if (res.status > 0) {
            DEBUG_VALIDATE_BUG_ON(res.consumed > input_len);
            DEBUG_VALIDATE_BUG_ON(res.needed + res.consumed < input_len);
            DEBUG_VALIDATE_BUG_ON(res.needed == 0);
            /* incomplete is only supported for TCP */
            DEBUG_VALIDATE_BUG_ON(f->proto != IPPROTO_TCP);

            /* put protocol in error state on improper use of the
             * return codes. */
            if (res.consumed > input_len || res.needed + res.consumed < input_len) {
                AppLayerIncInternalErrorCounter(tv, f);
                goto error;
            }

            if (f->proto == IPPROTO_TCP && f->protoctx != NULL) {
                TcpSession *ssn = f->protoctx;
                SCLogDebug("direction %d/%s", direction,
                        (flags & STREAM_TOSERVER) ? "toserver" : "toclient");
                if (direction == 0) {
                    /* parser told us how much data it needs on top of what it
                     * consumed. So we need tell stream engine how much we need
                     * before the next call */
                    ssn->client.data_required = res.needed;
                    SCLogDebug("setting data_required %u", ssn->client.data_required);
                } else {
                    /* parser told us how much data it needs on top of what it
                     * consumed. So we need tell stream engine how much we need
                     * before the next call */
                    ssn->server.data_required = res.needed;
                    SCLogDebug("setting data_required %u", ssn->server.data_required);
                }
            }
            consumed = res.consumed;
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
                    StreamTcpSetSessionNoReassemblyFlag(ssn, 0);
                    StreamTcpSetSessionNoReassemblyFlag(ssn, 1);
                }
            }
            /* Set the bypass flag for both the stream in this TcpSession */
            if (pstate->flags & APP_LAYER_PARSER_BYPASS_READY) {
                /* Used only if it's TCP */
                TcpSession *ssn = f->protoctx;
                if (ssn != NULL) {
                    StreamTcpSetSessionBypassFlag(ssn);
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

    /* get the diff in tx cnt for stats keeping */
    uint64_t cur_tx_cnt = AppLayerParserGetTxCnt(f, f->alstate);
    if (cur_tx_cnt > p_tx_cnt && tv) {
        AppLayerIncTxCounter(tv, f, cur_tx_cnt - p_tx_cnt);
    }

    /* stream truncated, inform app layer */
    if (flags & STREAM_DEPTH)
        AppLayerParserStreamTruncated(f->proto, alproto, alstate, flags);

 end:
    /* update app progress */
    if (consumed != input_len && f->proto == IPPROTO_TCP && f->protoctx != NULL) {
        TcpSession *ssn = f->protoctx;
        StreamTcpUpdateAppLayerProgress(ssn, direction, consumed);
        SCReturnInt(1);
    }

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

    SCLogDebug("setting APP_LAYER_PARSER_EOF_TC and APP_LAYER_PARSER_EOF_TS");
    AppLayerParserStateSetFlag(pstate, (APP_LAYER_PARSER_EOF_TS|APP_LAYER_PARSER_EOF_TC));

 end:
    SCReturn;
}

/* return true if there are app parser decoder events. These are
 * only the ones that are set during protocol detection. */
bool AppLayerParserHasDecoderEvents(AppLayerParserState *pstate)
{
    SCEnter();

    if (pstate == NULL)
        return false;

    const AppLayerDecoderEvents *decoder_events = AppLayerParserGetDecoderEvents(pstate);
    if (decoder_events && decoder_events->cnt)
        return true;

    /* if we have reached here, we don't have events */
    return false;
}

/** \brief simple way to globally test if a alproto is registered
 *         and fully enabled in the configuration.
 */
int AppLayerParserIsEnabled(AppProto alproto)
{
    for (int i = 0; i < FLOW_PROTO_APPLAYER_MAX; i++) {
        if (alp_ctx.ctxs[i][alproto].StateGetProgress != NULL) {
            return 1;
        }
    }
    return 0;
}

int AppLayerParserProtocolHasLogger(uint8_t ipproto, AppProto alproto)
{
    SCEnter();
    int ipproto_map = FlowGetProtoMapping(ipproto);
    int r = (alp_ctx.ctxs[ipproto_map][alproto].logger == false) ? 0 : 1;
    SCReturnInt(r);
}

LoggerId AppLayerParserProtocolGetLoggerBits(uint8_t ipproto, AppProto alproto)
{
    SCEnter();
    const int ipproto_map = FlowGetProtoMapping(ipproto);
    LoggerId r = alp_ctx.ctxs[ipproto_map][alproto].logger_bits;
    SCReturnUInt(r);
}

void AppLayerParserTriggerRawStreamReassembly(Flow *f, int direction)
{
    SCEnter();

    SCLogDebug("f %p tcp %p direction %d", f, f ? f->protoctx : NULL, direction);
    if (f != NULL && f->protoctx != NULL)
        StreamTcpReassembleTriggerRawReassembly(f->protoctx, direction);

    SCReturn;
}

void AppLayerParserSetStreamDepth(uint8_t ipproto, AppProto alproto, uint32_t stream_depth)
{
    SCEnter();

    alp_ctx.ctxs[FlowGetProtoMapping(ipproto)][alproto].stream_depth = stream_depth;
    alp_ctx.ctxs[FlowGetProtoMapping(ipproto)][alproto].internal_flags |=
        APP_LAYER_PARSER_INT_STREAM_DEPTH_SET;

    SCReturn;
}

uint32_t AppLayerParserGetStreamDepth(const Flow *f)
{
    SCReturnInt(alp_ctx.ctxs[f->protomap][f->alproto].stream_depth);
}

void AppLayerParserSetStreamDepthFlag(uint8_t ipproto, AppProto alproto, void *state, uint64_t tx_id, uint8_t flags)
{
    SCEnter();
    void *tx = NULL;
    if (state != NULL) {
        if ((tx = AppLayerParserGetTx(ipproto, alproto, state, tx_id)) != NULL) {
            if (alp_ctx.ctxs[FlowGetProtoMapping(ipproto)][alproto].SetStreamDepthFlag != NULL) {
                alp_ctx.ctxs[FlowGetProtoMapping(ipproto)][alproto].SetStreamDepthFlag(tx, flags);
            }
        }
    }
    SCReturn;
}

int AppLayerParserGetFrameIdByName(uint8_t ipproto, AppProto alproto, const char *name)
{
    if (alp_ctx.ctxs[FlowGetProtoMapping(ipproto)][alproto].GetFrameIdByName != NULL) {
        return alp_ctx.ctxs[FlowGetProtoMapping(ipproto)][alproto].GetFrameIdByName(name);
    } else {
        return -1;
    }
}

const char *AppLayerParserGetFrameNameById(uint8_t ipproto, AppProto alproto, const uint8_t id)
{
    if (alp_ctx.ctxs[FlowGetProtoMapping(ipproto)][alproto].GetFrameNameById != NULL) {
        return alp_ctx.ctxs[FlowGetProtoMapping(ipproto)][alproto].GetFrameNameById(id);
    } else {
        return NULL;
    }
}

/***** Cleanup *****/

void AppLayerParserStateProtoCleanup(
        uint8_t protomap, AppProto alproto, void *alstate, AppLayerParserState *pstate)
{
    SCEnter();

    AppLayerParserProtoCtx *ctx = &alp_ctx.ctxs[protomap][alproto];

    if (ctx->StateFree != NULL && alstate != NULL)
        ctx->StateFree(alstate);

    /* free the app layer parser api state */
    if (pstate != NULL)
        AppLayerParserStateFree(pstate);

    SCReturn;
}

void AppLayerParserStateCleanup(const Flow *f, void *alstate, AppLayerParserState *pstate)
{
    AppLayerParserStateProtoCleanup(f->protomap, f->alproto, alstate, pstate);
}

static void ValidateParserProtoDump(AppProto alproto, uint8_t ipproto)
{
    uint8_t map = FlowGetProtoMapping(ipproto);
    const AppLayerParserProtoCtx *ctx = &alp_ctx.ctxs[map][alproto];
    printf("ERROR: incomplete app-layer registration\n");
    printf("AppLayer protocol %s ipproto %u\n", AppProtoToString(alproto), ipproto);
    printf("- option flags %"PRIx32"\n", ctx->option_flags);
    printf("- first_data_dir %"PRIx8"\n", ctx->first_data_dir);
    printf("Mandatory:\n");
    printf("- Parser[0] %p Parser[1] %p\n", ctx->Parser[0], ctx->Parser[1]);
    printf("- StateAlloc %p StateFree %p\n", ctx->StateAlloc, ctx->StateFree);
    printf("- StateGetTx %p StateGetTxCnt %p StateTransactionFree %p\n",
            ctx->StateGetTx, ctx->StateGetTxCnt, ctx->StateTransactionFree);
    printf("- GetTxData %p\n", ctx->GetTxData);
    printf("- StateGetProgress %p\n", ctx->StateGetProgress);
    printf("Optional:\n");
    printf("- LocalStorageAlloc %p LocalStorageFree %p\n", ctx->LocalStorageAlloc, ctx->LocalStorageFree);
    printf("- StateGetEventInfo %p StateGetEventInfoById %p\n", ctx->StateGetEventInfo,
            ctx->StateGetEventInfoById);
}

#define BOTH_SET(a, b) ((a) != NULL && (b) != NULL)
#define BOTH_SET_OR_BOTH_UNSET(a, b) (((a) == NULL && (b) == NULL) || ((a) != NULL && (b) != NULL))
#define THREE_SET_OR_THREE_UNSET(a, b, c) (((a) == NULL && (b) == NULL && (c) == NULL) || ((a) != NULL && (b) != NULL && (c) != NULL))
#define THREE_SET(a, b, c) ((a) != NULL && (b) != NULL && (c) != NULL)

static void ValidateParserProto(AppProto alproto, uint8_t ipproto)
{
    uint8_t map = FlowGetProtoMapping(ipproto);
    const AppLayerParserProtoCtx *ctx = &alp_ctx.ctxs[map][alproto];

    if (ctx->Parser[0] == NULL && ctx->Parser[1] == NULL)
        return;

    if (!(BOTH_SET(ctx->Parser[0], ctx->Parser[1]))) {
        goto bad;
    }
    if (!(BOTH_SET(ctx->StateFree, ctx->StateAlloc))) {
        goto bad;
    }
    if (!(THREE_SET(ctx->StateGetTx, ctx->StateGetTxCnt, ctx->StateTransactionFree))) {
        goto bad;
    }
    if (ctx->StateGetProgress == NULL) {
        goto bad;
    }
    /* local storage is optional, but needs both set if used */
    if (!(BOTH_SET_OR_BOTH_UNSET(ctx->LocalStorageAlloc, ctx->LocalStorageFree))) {
        goto bad;
    }
    if (ctx->GetTxData == NULL) {
        goto bad;
    }
    return;
bad:
    ValidateParserProtoDump(alproto, ipproto);
    exit(EXIT_FAILURE);
}
#undef BOTH_SET
#undef BOTH_SET_OR_BOTH_UNSET
#undef THREE_SET_OR_THREE_UNSET
#undef THREE_SET

static void ValidateParser(AppProto alproto)
{
    ValidateParserProto(alproto, IPPROTO_TCP);
    ValidateParserProto(alproto, IPPROTO_UDP);
}

static void ValidateParsers(void)
{
    AppProto p = 0;
    for ( ; p < ALPROTO_MAX; p++) {
        ValidateParser(p);
    }
}

void AppLayerParserRegisterProtocolParsers(void)
{
    SCEnter();

    AppLayerConfig();

    RegisterHTPParsers();
    RegisterSSLParsers();
    rs_dcerpc_register_parser();
    rs_dcerpc_udp_register_parser();
    RegisterSMBParsers();
    RegisterFTPParsers();
    RegisterSSHParsers();
    RegisterSMTPParsers();
    rs_dns_udp_register_parser();
    rs_dns_tcp_register_parser();
    RegisterModbusParsers();
    RegisterENIPUDPParsers();
    RegisterENIPTCPParsers();
    RegisterDNP3Parsers();
    RegisterNFSTCPParsers();
    RegisterNFSUDPParsers();
    RegisterNTPParsers();
    RegisterTFTPParsers();
    RegisterIKEParsers();
    RegisterKRB5Parsers();
    rs_dhcp_register_parser();
    RegisterSNMPParsers();
    RegisterSIPParsers();
    RegisterQuicParsers();
    RegisterTemplateRustParsers();
    RegisterRFBParsers();
    RegisterMQTTParsers();
    rs_pgsql_register_parser();
    RegisterTemplateParsers();
    RegisterRdpParsers();
    RegisterHTTP2Parsers();
    rs_telnet_register_parser();

    /** IMAP */
    AppLayerProtoDetectRegisterProtocol(ALPROTO_IMAP, "imap");
    if (AppLayerProtoDetectConfProtoDetectionEnabled("tcp", "imap")) {
        if (AppLayerProtoDetectPMRegisterPatternCS(IPPROTO_TCP, ALPROTO_IMAP,
                                  "1|20|capability", 12, 0, STREAM_TOSERVER) < 0)
        {
            SCLogInfo("imap proto registration failure");
            exit(EXIT_FAILURE);
        }
    } else {
        SCLogInfo("Protocol detection and parser disabled for %s protocol.",
                  "imap");
    }

    ValidateParsers();
    return;
}


/* coccinelle: AppLayerParserStateSetFlag():2,2:APP_LAYER_PARSER_ */
void AppLayerParserStateSetFlag(AppLayerParserState *pstate, uint8_t flag)
{
    SCEnter();
    pstate->flags |= flag;
    SCReturn;
}

/* coccinelle: AppLayerParserStateIssetFlag():2,2:APP_LAYER_PARSER_ */
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
               "p->decoder_events(%p).",
               pstate, p->inspect_id[0], p->inspect_id[1], p->log_id,
               p->decoder_events);

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
 *          parser of occurrence of an error.
 */
static AppLayerResult TestProtocolParser(Flow *f, void *test_state, AppLayerParserState *pstate,
        StreamSlice stream_slice, void *local_data)
{
    SCEnter();
    SCReturnStruct(APP_LAYER_ERROR);
}

/** \brief Function to allocates the Test protocol state memory
 */
static void *TestProtocolStateAlloc(void *orig_state, AppProto proto_orig)
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

static uint64_t TestGetTxCnt(void *state)
{
    /* single tx */
    return 1;
}

static void TestStateTransactionFree(void *state, uint64_t tx_id)
{
    /* do nothing */
}

static void *TestGetTx(void *state, uint64_t tx_id)
{
    TestState *test_state = (TestState *)state;
    return test_state;
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
 * \test Test the deallocation of app layer parser memory on occurrence of
 *       error in the parsing process.
 */
static int AppLayerParserTest01(void)
{
    AppLayerParserBackupParserTable();

    Flow *f = NULL;
    uint8_t testbuf[] = { 0x11 };
    uint32_t testlen = sizeof(testbuf);
    TcpSession ssn;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&ssn, 0, sizeof(ssn));

    /* Register the Test protocol state and parser functions */
    AppLayerParserRegisterParser(IPPROTO_TCP, ALPROTO_TEST, STREAM_TOSERVER, TestProtocolParser);
    AppLayerParserRegisterStateFuncs(IPPROTO_TCP, ALPROTO_TEST,
                          TestProtocolStateAlloc, TestProtocolStateFree);
    AppLayerParserRegisterTxFreeFunc(IPPROTO_TCP, ALPROTO_TEST, TestStateTransactionFree);
    AppLayerParserRegisterGetTx(IPPROTO_TCP, ALPROTO_TEST, TestGetTx);
    AppLayerParserRegisterGetTxCnt(IPPROTO_TCP, ALPROTO_TEST, TestGetTxCnt);

    f = UTHBuildFlow(AF_INET, "1.2.3.4", "4.3.2.1", 20, 40);
    FAIL_IF_NULL(f);
    f->protoctx = &ssn;
    f->alproto = ALPROTO_TEST;
    f->proto = IPPROTO_TCP;

    StreamTcpInitConfig(true);

    int r = AppLayerParserParse(NULL, alp_tctx, f, ALPROTO_TEST,
                                STREAM_TOSERVER | STREAM_EOF, testbuf,
                                testlen);
    FAIL_IF(r != -1);

    FAIL_IF(!(ssn.flags & STREAMTCP_FLAG_APP_LAYER_DISABLED));

    AppLayerParserRestoreParserTable();
    StreamTcpFreeConfig(true);
    UTHFreeFlow(f);
    PASS;
}

/**
 * \test Test the deallocation of app layer parser memory on occurrence of
 *       error in the parsing process for UDP.
 */
static int AppLayerParserTest02(void)
{
    AppLayerParserBackupParserTable();

    Flow *f = NULL;
    uint8_t testbuf[] = { 0x11 };
    uint32_t testlen = sizeof(testbuf);
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    /* Register the Test protocol state and parser functions */
    AppLayerParserRegisterParser(IPPROTO_UDP, ALPROTO_TEST, STREAM_TOSERVER,
                      TestProtocolParser);
    AppLayerParserRegisterStateFuncs(IPPROTO_UDP, ALPROTO_TEST,
                          TestProtocolStateAlloc, TestProtocolStateFree);
    AppLayerParserRegisterTxFreeFunc(IPPROTO_UDP, ALPROTO_TEST, TestStateTransactionFree);
    AppLayerParserRegisterGetTx(IPPROTO_UDP, ALPROTO_TEST, TestGetTx);
    AppLayerParserRegisterGetTxCnt(IPPROTO_UDP, ALPROTO_TEST, TestGetTxCnt);

    f = UTHBuildFlow(AF_INET, "1.2.3.4", "4.3.2.1", 20, 40);
    FAIL_IF_NULL(f);
    f->alproto = ALPROTO_TEST;
    f->proto = IPPROTO_UDP;
    f->protomap = FlowGetProtoMapping(f->proto);

    StreamTcpInitConfig(true);

    int r = AppLayerParserParse(NULL, alp_tctx, f, ALPROTO_TEST,
                                STREAM_TOSERVER | STREAM_EOF, testbuf,
                                testlen);
    FAIL_IF(r != -1);

    AppLayerParserRestoreParserTable();
    StreamTcpFreeConfig(true);
    UTHFreeFlow(f);
    PASS;
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

    UtRegisterTest("AppLayerParserTest01", AppLayerParserTest01);
    UtRegisterTest("AppLayerParserTest02", AppLayerParserTest02);

    SCReturn;
}

#endif
