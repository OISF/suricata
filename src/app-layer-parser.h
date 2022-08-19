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
 * \author Anoop Saldanha <anoopsaldanha@gmail.com>
 */

#ifndef __APP_LAYER_PARSER_H__
#define __APP_LAYER_PARSER_H__

#include "app-layer-events.h"
#include "util-file.h"
#include "rust.h"
#include "util-config.h"

/* Flags for AppLayerParserState. */
// flag available                               BIT_U16(0)
#define APP_LAYER_PARSER_NO_INSPECTION         BIT_U16(1)
#define APP_LAYER_PARSER_NO_REASSEMBLY         BIT_U16(2)
#define APP_LAYER_PARSER_NO_INSPECTION_PAYLOAD BIT_U16(3)
#define APP_LAYER_PARSER_BYPASS_READY          BIT_U16(4)
#define APP_LAYER_PARSER_EOF_TS                BIT_U16(5)
#define APP_LAYER_PARSER_EOF_TC                BIT_U16(6)

/* Flags for AppLayerParserProtoCtx. */
#define APP_LAYER_PARSER_OPT_ACCEPT_GAPS        BIT_U32(0)
#define APP_LAYER_PARSER_OPT_UNIDIR_TXS         BIT_U32(1)

#define APP_LAYER_PARSER_INT_STREAM_DEPTH_SET   BIT_U32(0)

/* applies to DetectFlags uint64_t field */

/** reserved for future use */
#define APP_LAYER_TX_RESERVED1_FLAG  BIT_U64(48)
#define APP_LAYER_TX_RESERVED2_FLAG  BIT_U64(49)
#define APP_LAYER_TX_RESERVED3_FLAG  BIT_U64(50)
#define APP_LAYER_TX_RESERVED4_FLAG  BIT_U64(51)
#define APP_LAYER_TX_RESERVED5_FLAG  BIT_U64(52)
#define APP_LAYER_TX_RESERVED6_FLAG  BIT_U64(53)
#define APP_LAYER_TX_RESERVED7_FLAG  BIT_U64(54)
#define APP_LAYER_TX_RESERVED8_FLAG  BIT_U64(55)
#define APP_LAYER_TX_RESERVED9_FLAG  BIT_U64(56)
#define APP_LAYER_TX_RESERVED10_FLAG BIT_U64(57)
#define APP_LAYER_TX_RESERVED11_FLAG BIT_U64(58)
#define APP_LAYER_TX_RESERVED12_FLAG BIT_U64(59)
#define APP_LAYER_TX_RESERVED13_FLAG BIT_U64(60)
#define APP_LAYER_TX_RESERVED14_FLAG BIT_U64(61)
#define APP_LAYER_TX_RESERVED15_FLAG BIT_U64(62)

#define APP_LAYER_TX_RESERVED_FLAGS                                                                \
    (APP_LAYER_TX_RESERVED1_FLAG | APP_LAYER_TX_RESERVED2_FLAG | APP_LAYER_TX_RESERVED3_FLAG |     \
            APP_LAYER_TX_RESERVED4_FLAG | APP_LAYER_TX_RESERVED5_FLAG |                            \
            APP_LAYER_TX_RESERVED6_FLAG | APP_LAYER_TX_RESERVED7_FLAG |                            \
            APP_LAYER_TX_RESERVED8_FLAG | APP_LAYER_TX_RESERVED9_FLAG |                            \
            APP_LAYER_TX_RESERVED10_FLAG | APP_LAYER_TX_RESERVED11_FLAG |                          \
            APP_LAYER_TX_RESERVED12_FLAG | APP_LAYER_TX_RESERVED13_FLAG |                          \
            APP_LAYER_TX_RESERVED14_FLAG | APP_LAYER_TX_RESERVED15_FLAG)

/** is tx fully inspected? */
#define APP_LAYER_TX_INSPECTED_FLAG             BIT_U64(63)
/** other 63 bits are for tracking which prefilter engine is already
 *  completely inspected */
#define APP_LAYER_TX_PREFILTER_MASK ~(APP_LAYER_TX_INSPECTED_FLAG | APP_LAYER_TX_RESERVED_FLAGS)

/** parser has successfully processed in the input, and has consumed
 *  all of it. */
#define APP_LAYER_OK (AppLayerResult) { 0, 0, 0 }

/** parser has hit an unrecoverable error. Returning this to the API
 *  leads to no further calls to the parser. */
#define APP_LAYER_ERROR (AppLayerResult) { -1, 0, 0 }

/** parser needs more data. Through 'c' it will indicate how many
 *  of the input bytes it has consumed. Through 'n' it will indicate
 *  how many more bytes it needs before getting called again.
 *  \note consumed (c) should never be more than the input len
 *        needed (n) + consumed (c) should be more than the input len
 */
#define APP_LAYER_INCOMPLETE(c,n) (AppLayerResult) { 1, (c), (n) }

int AppLayerParserProtoIsRegistered(uint8_t ipproto, AppProto alproto);

/***** transaction handling *****/

int AppLayerParserSetup(void);
void AppLayerParserPostStreamSetup(void);
int AppLayerParserDeSetup(void);

typedef struct AppLayerParserThreadCtx_ AppLayerParserThreadCtx;

/**
 * \brief Gets a new app layer protocol's parser thread context.
 *
 * \retval Non-NULL pointer on success.
 *         NULL pointer on failure.
 */
AppLayerParserThreadCtx *AppLayerParserThreadCtxAlloc(void);

/**
 * \brief Destroys the app layer parser thread context obtained
 *        using AppLayerParserThreadCtxAlloc().
 *
 * \param tctx Pointer to the thread context to be destroyed.
 */
void AppLayerParserThreadCtxFree(AppLayerParserThreadCtx *tctx);

/**
 * \brief Given a protocol name, checks if the parser is enabled in
 *        the conf file.
 *
 * \param alproto_name Name of the app layer protocol.
 *
 * \retval 1 If enabled.
 * \retval 0 If disabled.
 */
int AppLayerParserConfParserEnabled(const char *ipproto,
                                    const char *alproto_name);

/** \brief Prototype for parsing functions */
typedef AppLayerResult (*AppLayerParserFPtr)(Flow *f, void *protocol_state,
        AppLayerParserState *pstate, StreamSlice stream_slice, void *local_storage);

typedef struct AppLayerGetTxIterState {
    union {
        void *ptr;
        uint64_t u64;
    } un;
} AppLayerGetTxIterState;

/** \brief tx iterator prototype */
typedef AppLayerGetTxIterTuple (*AppLayerGetTxIteratorFunc)
       (const uint8_t ipproto, const AppProto alproto,
        void *alstate, uint64_t min_tx_id, uint64_t max_tx_id,
        AppLayerGetTxIterState *state);

/***** Parser related registration *****/

typedef int (*AppLayerParserGetFrameIdByNameFn)(const char *frame_name);
typedef const char *(*AppLayerParserGetFrameNameByIdFn)(const uint8_t id);

/**
 * \brief Register app layer parser for the protocol.
 *
 * \retval 0 On success.
 * \retval -1 On failure.
 */
int AppLayerParserRegisterParser(uint8_t ipproto, AppProto alproto,
                      uint8_t direction,
                      AppLayerParserFPtr Parser);
void AppLayerParserRegisterParserAcceptableDataDirection(uint8_t ipproto,
                                              AppProto alproto,
                                              uint8_t direction);
void AppLayerParserRegisterOptionFlags(uint8_t ipproto, AppProto alproto,
        uint32_t flags);
void AppLayerParserRegisterStateFuncs(uint8_t ipproto, AppProto alproto,
        void *(*StateAlloc)(void *, AppProto), void (*StateFree)(void *));
void AppLayerParserRegisterLocalStorageFunc(uint8_t ipproto, AppProto proto,
                                 void *(*LocalStorageAlloc)(void),
                                 void (*LocalStorageFree)(void *));
void AppLayerParserRegisterGetFilesFunc(uint8_t ipproto, AppProto alproto,
                             FileContainer *(*StateGetFiles)(void *, uint8_t));
// void AppLayerParserRegisterGetEventsFunc(uint8_t ipproto, AppProto proto,
//     AppLayerDecoderEvents *(*StateGetEvents)(void *) __attribute__((nonnull)));
void AppLayerParserRegisterLoggerFuncs(uint8_t ipproto, AppProto alproto,
                         LoggerId (*StateGetTxLogged)(void *, void *),
                         void (*StateSetTxLogged)(void *, void *, LoggerId));
void AppLayerParserRegisterLogger(uint8_t ipproto, AppProto alproto);
void AppLayerParserRegisterLoggerBits(uint8_t ipproto, AppProto alproto, LoggerId bits);
void AppLayerParserRegisterTruncateFunc(uint8_t ipproto, AppProto alproto,
                             void (*Truncate)(void *, uint8_t));
void AppLayerParserRegisterGetStateProgressFunc(uint8_t ipproto, AppProto alproto,
    int (*StateGetStateProgress)(void *alstate, uint8_t direction));
void AppLayerParserRegisterTxFreeFunc(uint8_t ipproto, AppProto alproto,
                           void (*StateTransactionFree)(void *, uint64_t));
void AppLayerParserRegisterGetTxCnt(uint8_t ipproto, AppProto alproto,
                         uint64_t (*StateGetTxCnt)(void *alstate));
void AppLayerParserRegisterGetTx(uint8_t ipproto, AppProto alproto,
                      void *(StateGetTx)(void *alstate, uint64_t tx_id));
void AppLayerParserRegisterGetTxIterator(uint8_t ipproto, AppProto alproto,
                      AppLayerGetTxIteratorFunc Func);
void AppLayerParserRegisterStateProgressCompletionStatus(
        AppProto alproto, const int ts, const int tc);
void AppLayerParserRegisterGetEventInfo(uint8_t ipproto, AppProto alproto,
    int (*StateGetEventInfo)(const char *event_name, int *event_id,
                             AppLayerEventType *event_type));
void AppLayerParserRegisterGetEventInfoById(uint8_t ipproto, AppProto alproto,
    int (*StateGetEventInfoById)(int event_id, const char **event_name,
                                 AppLayerEventType *event_type));
void AppLayerParserRegisterGetFrameFuncs(uint8_t ipproto, AppProto alproto,
        AppLayerParserGetFrameIdByNameFn GetFrameIdByName,
        AppLayerParserGetFrameNameByIdFn GetFrameNameById);
void AppLayerParserRegisterGetStreamDepth(uint8_t ipproto,
                                          AppProto alproto,
                                          uint32_t (*GetStreamDepth)(void));
void AppLayerParserRegisterSetStreamDepthFlag(uint8_t ipproto, AppProto alproto,
        void (*SetStreamDepthFlag)(void *tx, uint8_t flags));

void AppLayerParserRegisterTxDataFunc(uint8_t ipproto, AppProto alproto,
        AppLayerTxData *(*GetTxData)(void *tx));
void AppLayerParserRegisterApplyTxConfigFunc(uint8_t ipproto, AppProto alproto,
        bool (*ApplyTxConfig)(void *state, void *tx, int mode, AppLayerTxConfig));
void AppLayerParserRegisterStateDataFunc(
        uint8_t ipproto, AppProto alproto, AppLayerStateData *(*GetStateData)(void *state));

/***** Get and transaction functions *****/

uint32_t AppLayerParserGetOptionFlags(uint8_t protomap, AppProto alproto);
AppLayerGetTxIteratorFunc AppLayerGetTxIterator(const uint8_t ipproto,
         const AppProto alproto);

void *AppLayerParserGetProtocolParserLocalStorage(uint8_t ipproto, AppProto alproto);
void AppLayerParserDestroyProtocolParserLocalStorage(uint8_t ipproto, AppProto alproto,
                                          void *local_data);


uint64_t AppLayerParserGetTransactionLogId(AppLayerParserState *pstate);
void AppLayerParserSetTransactionLogId(AppLayerParserState *pstate, uint64_t tx_id);

uint64_t AppLayerParserGetTransactionInspectId(AppLayerParserState *pstate, uint8_t direction);
void AppLayerParserSetTransactionInspectId(const Flow *f, AppLayerParserState *pstate,
                                void *alstate, const uint8_t flags, bool tag_txs_as_inspected);

AppLayerDecoderEvents *AppLayerParserGetDecoderEvents(AppLayerParserState *pstate);
void AppLayerParserSetDecoderEvents(AppLayerParserState *pstate, AppLayerDecoderEvents *devents);
AppLayerDecoderEvents *AppLayerParserGetEventsByTx(uint8_t ipproto, AppProto alproto, void *tx);
FileContainer *AppLayerParserGetFiles(const Flow *f, const uint8_t direction);
int AppLayerParserGetStateProgress(uint8_t ipproto, AppProto alproto,
                        void *alstate, uint8_t direction);
uint64_t AppLayerParserGetTxCnt(const Flow *, void *alstate);
void *AppLayerParserGetTx(uint8_t ipproto, AppProto alproto, void *alstate, uint64_t tx_id);
int AppLayerParserGetStateProgressCompletionStatus(AppProto alproto, uint8_t direction);
int AppLayerParserGetEventInfo(uint8_t ipproto, AppProto alproto, const char *event_name,
                    int *event_id, AppLayerEventType *event_type);
int AppLayerParserGetEventInfoById(uint8_t ipproto, AppProto alproto, int event_id,
                    const char **event_name, AppLayerEventType *event_type);

uint64_t AppLayerParserGetTransactionActive(const Flow *f, AppLayerParserState *pstate, uint8_t direction);

uint8_t AppLayerParserGetFirstDataDir(uint8_t ipproto, AppProto alproto);

int AppLayerParserSupportsFiles(uint8_t ipproto, AppProto alproto);

AppLayerTxData *AppLayerParserGetTxData(uint8_t ipproto, AppProto alproto, void *tx);
AppLayerStateData *AppLayerParserGetStateData(uint8_t ipproto, AppProto alproto, void *state);
void AppLayerParserApplyTxConfig(uint8_t ipproto, AppProto alproto,
        void *state, void *tx, enum ConfigAction mode, AppLayerTxConfig);

/***** General *****/

int AppLayerParserParse(ThreadVars *tv, AppLayerParserThreadCtx *tctx, Flow *f, AppProto alproto,
                   uint8_t flags, const uint8_t *input, uint32_t input_len);
void AppLayerParserSetEOF(AppLayerParserState *pstate);
bool AppLayerParserHasDecoderEvents(AppLayerParserState *pstate);
int AppLayerParserProtocolHasLogger(uint8_t ipproto, AppProto alproto);
LoggerId AppLayerParserProtocolGetLoggerBits(uint8_t ipproto, AppProto alproto);
void AppLayerParserTriggerRawStreamReassembly(Flow *f, int direction);
void AppLayerParserSetStreamDepth(uint8_t ipproto, AppProto alproto, uint32_t stream_depth);
uint32_t AppLayerParserGetStreamDepth(const Flow *f);
void AppLayerParserSetStreamDepthFlag(uint8_t ipproto, AppProto alproto, void *state, uint64_t tx_id, uint8_t flags);
int AppLayerParserIsEnabled(AppProto alproto);
int AppLayerParserGetFrameIdByName(uint8_t ipproto, AppProto alproto, const char *name);
const char *AppLayerParserGetFrameNameById(uint8_t ipproto, AppProto alproto, const uint8_t id);

/***** Cleanup *****/

void AppLayerParserStateProtoCleanup(
        uint8_t protomap, AppProto alproto, void *alstate, AppLayerParserState *pstate);
void AppLayerParserStateCleanup(const Flow *f, void *alstate, AppLayerParserState *pstate);

void AppLayerParserRegisterProtocolParsers(void);

void AppLayerParserStateSetFlag(AppLayerParserState *pstate, uint16_t flag);
uint16_t AppLayerParserStateIssetFlag(AppLayerParserState *pstate, uint16_t flag);

void AppLayerParserStreamTruncated(uint8_t ipproto, AppProto alproto, void *alstate,
                        uint8_t direction);

AppLayerParserState *AppLayerParserStateAlloc(void);
void AppLayerParserStateFree(AppLayerParserState *pstate);

void AppLayerParserTransactionsCleanup(Flow *f, const uint8_t pkt_dir);

#ifdef DEBUG
void AppLayerParserStatePrintDetails(AppLayerParserState *pstate);
#endif


/***** Unittests *****/

#ifdef UNITTESTS
void AppLayerParserRegisterProtocolUnittests(uint8_t ipproto, AppProto alproto,
                                  void (*RegisterUnittests)(void));
void AppLayerParserRegisterUnittests(void);
void AppLayerParserBackupParserTable(void);
void AppLayerParserRestoreParserTable(void);
void UTHAppLayerParserStateGetIds(void *ptr, uint64_t *i1, uint64_t *i2, uint64_t *log, uint64_t *min);
#endif

void AppLayerFramesFreeContainer(Flow *f);

#endif /* __APP_LAYER_PARSER_H__ */
