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
 * \author Anoop Saldanha <anoopsaldanha@gmail.com>
 */

#ifndef __APP_LAYER_PARSER_H__
#define __APP_LAYER_PARSER_H__

#include "app-layer-events.h"
#include "detect-engine-state.h"
#include "util-file.h"
#include "stream-tcp-private.h"

/* Flags for AppLayerParserState. */
#define APP_LAYER_PARSER_EOF                    BIT_U8(0)
#define APP_LAYER_PARSER_NO_INSPECTION          BIT_U8(1)
#define APP_LAYER_PARSER_NO_REASSEMBLY          BIT_U8(2)
#define APP_LAYER_PARSER_NO_INSPECTION_PAYLOAD  BIT_U8(3)
#define APP_LAYER_PARSER_BYPASS_READY           BIT_U8(4)

/* Flags for AppLayerParserProtoCtx. */
#define APP_LAYER_PARSER_OPT_ACCEPT_GAPS        BIT_U32(0)

#define APP_LAYER_PARSER_INT_STREAM_DEPTH_SET   BIT_U32(0)

/* applies to DetectFlags uint64_t field */

/** is tx fully inspected? */
#define APP_LAYER_TX_INSPECTED_FLAG             BIT_U64(63)
/** other 63 bits are for tracking which prefilter engine is already
 *  completely inspected */
#define APP_LAYER_TX_PREFILTER_MASK             ~APP_LAYER_TX_INSPECTED_FLAG

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
typedef int (*AppLayerParserFPtr)(Flow *f, void *protocol_state,
        AppLayerParserState *pstate,
        uint8_t *buf, uint32_t buf_len,
        void *local_storage, const uint8_t flags);

typedef struct AppLayerGetTxIterTuple {
    void *tx_ptr;
    uint64_t tx_id;
    bool has_next;
} AppLayerGetTxIterTuple;

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
                           void *(*StateAlloc)(void),
                           void (*StateFree)(void *));
void AppLayerParserRegisterLocalStorageFunc(uint8_t ipproto, AppProto proto,
                                 void *(*LocalStorageAlloc)(void),
                                 void (*LocalStorageFree)(void *));
void AppLayerParserRegisterGetFilesFunc(uint8_t ipproto, AppProto alproto,
                             FileContainer *(*StateGetFiles)(void *, uint8_t));
void AppLayerParserRegisterGetEventsFunc(uint8_t ipproto, AppProto proto,
    AppLayerDecoderEvents *(*StateGetEvents)(void *) __attribute__((nonnull)));
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
void AppLayerParserRegisterGetStateProgressCompletionStatus(AppProto alproto,
    int (*StateGetStateProgressCompletionStatus)(uint8_t direction));
void AppLayerParserRegisterGetEventInfo(uint8_t ipproto, AppProto alproto,
    int (*StateGetEventInfo)(const char *event_name, int *event_id,
                             AppLayerEventType *event_type));
void AppLayerParserRegisterGetEventInfoById(uint8_t ipproto, AppProto alproto,
    int (*StateGetEventInfoById)(int event_id, const char **event_name,
                                 AppLayerEventType *event_type));
void AppLayerParserRegisterDetectStateFuncs(uint8_t ipproto, AppProto alproto,
        DetectEngineState *(*GetTxDetectState)(void *tx),
        int (*SetTxDetectState)(void *tx, DetectEngineState *));
void AppLayerParserRegisterGetStreamDepth(uint8_t ipproto,
                                          AppProto alproto,
                                          uint32_t (*GetStreamDepth)(void));
void AppLayerParserRegisterMpmIDsFuncs(uint8_t ipproto, AppProto alproto,
        uint64_t (*GetTxMpmIDs)(void *tx),
        int (*SetTxMpmIDs)(void *tx, uint64_t));
void AppLayerParserRegisterDetectFlagsFuncs(uint8_t ipproto, AppProto alproto,
        uint64_t(*GetTxDetectFlags)(void *tx, uint8_t dir),
        void (*SetTxDetectFlags)(void *tx, uint8_t dir, uint64_t));

/***** Get and transaction functions *****/

AppLayerGetTxIteratorFunc AppLayerGetTxIterator(const uint8_t ipproto,
         const AppProto alproto);

void *AppLayerParserGetProtocolParserLocalStorage(uint8_t ipproto, AppProto alproto);
void AppLayerParserDestroyProtocolParserLocalStorage(uint8_t ipproto, AppProto alproto,
                                          void *local_data);


uint64_t AppLayerParserGetTransactionLogId(AppLayerParserState *pstate);
void AppLayerParserSetTransactionLogId(AppLayerParserState *pstate, uint64_t tx_id);

void AppLayerParserSetTxLogged(uint8_t ipproto, AppProto alproto, void *alstate,
                               void *tx, LoggerId logged);
LoggerId AppLayerParserGetTxLogged(const Flow *f, void *alstate, void *tx);

uint64_t AppLayerParserGetTransactionInspectId(AppLayerParserState *pstate, uint8_t direction);
void AppLayerParserSetTransactionInspectId(const Flow *f, AppLayerParserState *pstate,
                                void *alstate, const uint8_t flags, bool tag_txs_as_inspected);

AppLayerDecoderEvents *AppLayerParserGetDecoderEvents(AppLayerParserState *pstate);
void AppLayerParserSetDecoderEvents(AppLayerParserState *pstate, AppLayerDecoderEvents *devents);
AppLayerDecoderEvents *AppLayerParserGetEventsByTx(uint8_t ipproto, AppProto alproto, void *tx);
FileContainer *AppLayerParserGetFiles(uint8_t ipproto, AppProto alproto,
                           void *alstate, uint8_t direction);
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
int AppLayerParserSupportsTxDetectState(uint8_t ipproto, AppProto alproto);
int AppLayerParserHasTxDetectState(uint8_t ipproto, AppProto alproto, void *alstate);
DetectEngineState *AppLayerParserGetTxDetectState(uint8_t ipproto, AppProto alproto, void *tx);
int AppLayerParserSetTxDetectState(const Flow *f, void *tx, DetectEngineState *s);

uint64_t AppLayerParserGetTxDetectFlags(uint8_t ipproto, AppProto alproto, void *tx, uint8_t dir);
void AppLayerParserSetTxDetectFlags(uint8_t ipproto, AppProto alproto, void *tx, uint8_t dir, uint64_t);

/***** General *****/

int AppLayerParserParse(ThreadVars *tv, AppLayerParserThreadCtx *tctx, Flow *f, AppProto alproto,
                   uint8_t flags, uint8_t *input, uint32_t input_len);
void AppLayerParserSetEOF(AppLayerParserState *pstate);
bool AppLayerParserHasDecoderEvents(AppLayerParserState *pstate);
int AppLayerParserIsTxAware(AppProto alproto);
int AppLayerParserProtocolIsTxEventAware(uint8_t ipproto, AppProto alproto);
int AppLayerParserProtocolHasLogger(uint8_t ipproto, AppProto alproto);
LoggerId AppLayerParserProtocolGetLoggerBits(uint8_t ipproto, AppProto alproto);
void AppLayerParserTriggerRawStreamReassembly(Flow *f, int direction);
void AppLayerParserSetStreamDepth(uint8_t ipproto, AppProto alproto, uint32_t stream_depth);
uint32_t AppLayerParserGetStreamDepth(const Flow *f);

/***** Cleanup *****/

void AppLayerParserStateCleanup(const Flow *f, void *alstate, AppLayerParserState *pstate);

void AppLayerParserRegisterProtocolParsers(void);


void AppLayerParserStateSetFlag(AppLayerParserState *pstate, uint8_t flag);
int AppLayerParserStateIssetFlag(AppLayerParserState *pstate, uint8_t flag);

void AppLayerParserStreamTruncated(uint8_t ipproto, AppProto alproto, void *alstate,
                        uint8_t direction);



AppLayerParserState *AppLayerParserStateAlloc(void);
void AppLayerParserStateFree(AppLayerParserState *pstate);

void AppLayerParserTransactionsCleanup(Flow *f);

#ifdef DEBUG
void AppLayerParserStatePrintDetails(AppLayerParserState *pstate);
#endif

#ifdef AFLFUZZ_APPLAYER
int AppLayerParserRequestFromFile(uint8_t ipproto, AppProto alproto, char *filename);
int AppLayerParserRequestFromFileSerie(uint8_t ipproto, AppProto alproto, char *prefix);
int AppLayerParserFromFile(uint8_t ipproto, AppProto alproto, char *filename);
int AppLayerParserFromFileSerie(uint8_t ipproto, AppProto alproto, char *prefix);
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

#endif /* __APP_LAYER_PARSER_H__ */
