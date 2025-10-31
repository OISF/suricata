/* Copyright (C) 2007-2025 Open Information Security Foundation
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

#ifndef SURICATA_APP_LAYER_PARSER_H
#define SURICATA_APP_LAYER_PARSER_H

#include "app-layer-protos.h"
// Forward declarations for bindgen
enum ConfigAction;
typedef struct Flow_ Flow;
typedef struct AppLayerParserState_ AppLayerParserState;
typedef struct AppLayerDecoderEvents_ AppLayerDecoderEvents;
typedef struct ThreadVars_ ThreadVars;
typedef struct File_ File;
typedef enum LoggerId LoggerId;
// Forward declarations from rust
typedef struct StreamSlice StreamSlice;
typedef struct AppLayerResult AppLayerResult;
typedef struct AppLayerGetTxIterTuple AppLayerGetTxIterTuple;
typedef struct AppLayerGetFileState AppLayerGetFileState;
typedef struct AppLayerTxData AppLayerTxData;
typedef enum AppLayerEventType AppLayerEventType;
typedef struct AppLayerStateData AppLayerStateData;
typedef struct AppLayerTxConfig AppLayerTxConfig;

/* Flags for AppLayerParserState. */
// flag available                               BIT_U16(0)
#define APP_LAYER_PARSER_NO_INSPECTION         BIT_U16(1)
#define APP_LAYER_PARSER_NO_REASSEMBLY         BIT_U16(2)
#define APP_LAYER_PARSER_NO_INSPECTION_PAYLOAD BIT_U16(3)
#define APP_LAYER_PARSER_BYPASS_READY          BIT_U16(4)
#define APP_LAYER_PARSER_EOF_TS                BIT_U16(5)
#define APP_LAYER_PARSER_EOF_TC                BIT_U16(6)
/* 2x vacancy */
#define APP_LAYER_PARSER_SFRAME_TS             BIT_U16(9)
#define APP_LAYER_PARSER_SFRAME_TC             BIT_U16(10)

/* Flags for AppLayerParserProtoCtx. */
#define APP_LAYER_PARSER_OPT_ACCEPT_GAPS BIT_U32(0)

#define APP_LAYER_PARSER_INT_STREAM_DEPTH_SET   BIT_U32(0)

/* for use with the detect_progress_ts|detect_progress_tc fields */

/** should inspection be skipped in that direction */
#define APP_LAYER_TX_SKIP_INSPECT_TS BIT_U8(0)
#define APP_LAYER_TX_SKIP_INSPECT_TC BIT_U8(1)
/** is tx fully inspected? */
#define APP_LAYER_TX_INSPECTED_TS BIT_U8(2)
#define APP_LAYER_TX_INSPECTED_TC BIT_U8(3)
/** accept is applied to entire tx */
#define APP_LAYER_TX_ACCEPT BIT_U8(4)

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
int SCAppLayerParserConfParserEnabled(const char *ipproto, const char *alproto_name);

enum ExceptionPolicy AppLayerErrorGetExceptionPolicy(void);

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

/**
 *  \param name progress name to get the id for
 *  \param direction STREAM_TOSERVER/STREAM_TOCLIENT
 */
typedef int (*AppLayerParserGetStateIdByNameFn)(const char *name, const uint8_t direction);
/**
 *  \param id progress value id to get the name for
 *  \param direction STREAM_TOSERVER/STREAM_TOCLIENT
 */
typedef const char *(*AppLayerParserGetStateNameByIdFn)(const int id, const uint8_t direction);

typedef int (*AppLayerParserGetFrameIdByNameFn)(const char *frame_name);
typedef const char *(*AppLayerParserGetFrameNameByIdFn)(const uint8_t id);

int SCAppLayerParserReallocCtx(AppProto alproto);
int AppLayerParserPreRegister(void (*Register)(void));
/**
 * \brief Register app layer parser for the protocol.
 *
 * \retval 0 On success.
 * \retval -1 On failure.
 */
int AppLayerParserRegisterParser(uint8_t ipproto, AppProto alproto,
                      uint8_t direction,
                      AppLayerParserFPtr Parser);
void SCAppLayerParserRegisterParserAcceptableDataDirection(
        uint8_t ipproto, AppProto alproto, uint8_t direction);
void AppLayerParserRegisterOptionFlags(uint8_t ipproto, AppProto alproto,
        uint32_t flags);
void AppLayerParserRegisterStateFuncs(uint8_t ipproto, AppProto alproto,
        void *(*StateAlloc)(void *, AppProto), void (*StateFree)(void *));
void AppLayerParserRegisterLocalStorageFunc(uint8_t ipproto, AppProto proto,
        void *(*LocalStorageAlloc)(void), void (*LocalStorageFree)(void *));
// void AppLayerParserRegisterGetEventsFunc(uint8_t ipproto, AppProto proto,
//     AppLayerDecoderEvents *(*StateGetEvents)(void *) __attribute__((nonnull)));
void AppLayerParserRegisterGetTxFilesFunc(
        uint8_t ipproto, AppProto alproto, AppLayerGetFileState (*GetTxFiles)(void *, uint8_t));
void SCAppLayerParserRegisterLogger(uint8_t ipproto, AppProto alproto);
void AppLayerParserRegisterLoggerBits(uint8_t ipproto, AppProto alproto, LoggerId bits);
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
        int (*StateGetEventInfo)(
                const char *event_name, uint8_t *event_id, AppLayerEventType *event_type));
void AppLayerParserRegisterGetEventInfoById(uint8_t ipproto, AppProto alproto,
        int (*StateGetEventInfoById)(
                uint8_t event_id, const char **event_name, AppLayerEventType *event_type));
void AppLayerParserRegisterGetFrameFuncs(uint8_t ipproto, AppProto alproto,
        AppLayerParserGetFrameIdByNameFn GetFrameIdByName,
        AppLayerParserGetFrameNameByIdFn GetFrameNameById);
void AppLayerParserRegisterSetStreamDepthFlag(uint8_t ipproto, AppProto alproto,
        void (*SetStreamDepthFlag)(void *tx, uint8_t flags));
void AppLayerParserRegisterGetStateFuncs(uint8_t ipproto, AppProto alproto,
        AppLayerParserGetStateIdByNameFn GetStateIdByName,
        AppLayerParserGetStateNameByIdFn GetStateNameById);

void AppLayerParserRegisterTxDataFunc(uint8_t ipproto, AppProto alproto,
        AppLayerTxData *(*GetTxData)(void *tx));
void AppLayerParserRegisterApplyTxConfigFunc(uint8_t ipproto, AppProto alproto,
        bool (*ApplyTxConfig)(void *state, void *tx, int mode, AppLayerTxConfig));
void AppLayerParserRegisterStateDataFunc(
        uint8_t ipproto, AppProto alproto, AppLayerStateData *(*GetStateData)(void *state));

/***** Get and transaction functions *****/

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
AppLayerDecoderEvents *AppLayerParserGetEventsByTx(uint8_t ipproto, AppProto alproto, void *tx);
AppLayerGetFileState AppLayerParserGetTxFiles(const Flow *f, void *tx, const uint8_t direction);
int AppLayerParserGetStateProgress(uint8_t ipproto, AppProto alproto,
                        void *alstate, uint8_t direction);
uint64_t AppLayerParserGetTxCnt(const Flow *, void *alstate);
void *AppLayerParserGetTx(uint8_t ipproto, AppProto alproto, void *alstate, uint64_t tx_id);
int AppLayerParserGetStateProgressCompletionStatus(AppProto alproto, uint8_t direction);
int AppLayerParserGetEventInfo(uint8_t ipproto, AppProto alproto, const char *event_name,
        uint8_t *event_id, AppLayerEventType *event_type);
int AppLayerParserGetEventInfoById(uint8_t ipproto, AppProto alproto, uint8_t event_id,
        const char **event_name, AppLayerEventType *event_type);

uint64_t AppLayerParserGetTransactionActive(const Flow *f, AppLayerParserState *pstate, uint8_t direction);

uint8_t AppLayerParserGetFirstDataDir(uint8_t ipproto, AppProto alproto);

bool AppLayerParserSupportsFiles(uint8_t ipproto, AppProto alproto);

AppLayerTxData *AppLayerParserGetTxData(uint8_t ipproto, AppProto alproto, void *tx);
uint8_t AppLayerParserGetTxDetectProgress(AppLayerTxData *txd, const uint8_t dir);
AppLayerStateData *AppLayerParserGetStateData(uint8_t ipproto, AppProto alproto, void *state);
void AppLayerParserApplyTxConfig(uint8_t ipproto, AppProto alproto,
        void *state, void *tx, enum ConfigAction mode, AppLayerTxConfig);

/** \brief check if tx (possibly) has files in this tx for the direction */
#define AppLayerParserHasFilesInDir(txd, direction)                                                \
    ((txd)->files_opened && ((txd)->file_tx & (direction)) != 0)

/***** General *****/

int AppLayerParserParse(ThreadVars *tv, AppLayerParserThreadCtx *tctx, Flow *f, AppProto alproto,
                   uint8_t flags, const uint8_t *input, uint32_t input_len);
void AppLayerParserSetEOF(AppLayerParserState *pstate);
bool AppLayerParserHasDecoderEvents(AppLayerParserState *pstate);
int AppLayerParserProtocolHasLogger(uint8_t ipproto, AppProto alproto);
LoggerId AppLayerParserProtocolGetLoggerBits(uint8_t ipproto, AppProto alproto);
void SCAppLayerParserTriggerRawStreamInspection(Flow *f, int direction);
void SCAppLayerParserSetStreamDepth(uint8_t ipproto, AppProto alproto, uint32_t stream_depth);
uint32_t AppLayerParserGetStreamDepth(const Flow *f);
void AppLayerParserSetStreamDepthFlag(uint8_t ipproto, AppProto alproto, void *state, uint64_t tx_id, uint8_t flags);
int AppLayerParserIsEnabled(AppProto alproto);
int AppLayerParserGetFrameIdByName(uint8_t ipproto, AppProto alproto, const char *name);
const char *AppLayerParserGetFrameNameById(uint8_t ipproto, AppProto alproto, const uint8_t id);
/**
 *  \param name progress name to get the id for
 *  \param direction STREAM_TOSERVER/STREAM_TOCLIENT
 */
int AppLayerParserGetStateIdByName(
        uint8_t ipproto, AppProto alproto, const char *name, uint8_t direction);
/**
 *  \param id progress value id to get the name for
 *  \param direction STREAM_TOSERVER/STREAM_TOCLIENT
 */
const char *AppLayerParserGetStateNameById(
        uint8_t ipproto, AppProto alproto, const int id, uint8_t direction);

/***** Cleanup *****/

void AppLayerParserStateProtoCleanup(
        uint8_t protomap, AppProto alproto, void *alstate, AppLayerParserState *pstate);
void AppLayerParserStateCleanup(const Flow *f, void *alstate, AppLayerParserState *pstate);

void AppLayerParserRegisterProtocolParsers(void);

void SCAppLayerParserStateSetFlag(AppLayerParserState *pstate, uint16_t flag);
uint16_t SCAppLayerParserStateIssetFlag(AppLayerParserState *pstate, uint16_t flag);

AppLayerParserState *AppLayerParserStateAlloc(void);
void AppLayerParserStateFree(AppLayerParserState *pstate);

void AppLayerParserTransactionsCleanup(Flow *f, const uint8_t pkt_dir);

/***** Unittests *****/

#ifdef UNITTESTS
void AppLayerParserRegisterProtocolUnittests(uint8_t ipproto, AppProto alproto,
                                  void (*RegisterUnittests)(void));
void AppLayerParserRegisterUnittests(void);
void UTHAppLayerParserStateGetIds(void *ptr, uint64_t *i1, uint64_t *i2, uint64_t *log, uint64_t *min);
#endif

void AppLayerFramesFreeContainer(Flow *f);
void FileApplyTxFlags(const AppLayerTxData *txd, const uint8_t direction, File *file);

#endif /* SURICATA_APP_LAYER_PARSER_H */
