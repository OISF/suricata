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

#include "decode-events.h"
#include "util-file.h"

#define APP_LAYER_PARSER_EOF            0x01
#define APP_LAYER_PARSER_NO_INSPECTION  0x02
#define APP_LAYER_PARSER_NO_REASSEMBLY  0x04

int AppLayerParserSetup(void);

int AppLayerParserDeSetup(void);

/**
 * \brief Gets a new app layer protocol's parser thread context.
 *
 * \retval Non-NULL pointer on success.
 *         NULL pointer on failure.
 */
void *AppLayerParserGetCtxThread(void);

/**
 * \brief Destroys the app layer parser thread context obtained
 *        using AppLayerParserGetCtxThread().
 *
 * \param tctx Pointer to the thread context to be destroyed.
 */
void AppLayerParserDestroyCtxThread(void *tctx);

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

/***** Parser related registration *****/

/**
 * \brief Register app layer parser for the protocol.
 *
 * \retval 0 On success.
 * \retval -1 On failure.
 */
int AppLayerParserRegisterParser(uint16_t ip_proto, AppProto alproto,
                      uint8_t direction,
                      int (*Parser)(Flow *f, void *protocol_state,
                                    void *pstate,
                                    uint8_t *buf, uint32_t buf_len,
                                    void *local_storage));
void AppLayerParserRegisterParserAcceptableDataDirection(uint16_t ipproto,
                                              AppProto alproto,
                                              uint8_t direction);
void AppLayerParserRegisterStateFuncs(uint16_t ipproto, AppProto alproto,
                           void *(*StateAlloc)(void),
                           void (*StateFree)(void *));
void AppLayerParserRegisterLocalStorageFunc(uint16_t ipproto, AppProto proto,
                                 void *(*LocalStorageAlloc)(void),
                                 void (*LocalStorageFree)(void *));
void AppLayerParserRegisterGetFilesFunc(uint16_t ipproto, AppProto alproto,
                             FileContainer *(*StateGetFiles)(void *, uint8_t));
void AppLayerParserRegisterGetEventsFunc(uint16_t ipproto, AppProto proto,
    AppLayerDecoderEvents *(*StateGetEvents)(void *, uint64_t));
void AppLayerParserRegisterHasEventsFunc(uint16_t ipproto, AppProto alproto,
                              int (*StateHasEvents)(void *));
void AppLayerParserRegisterLogger(uint16_t ipproto, AppProto alproto);
void AppLayerParserRegisterTruncateFunc(uint16_t ipproto, AppProto alproto,
                             void (*Truncate)(void *, uint8_t));
void AppLayerParserRegisterGetStateProgressFunc(uint16_t ipproto, AppProto alproto,
    int (*StateGetStateProgress)(void *alstate, uint8_t direction));
void AppLayerParserRegisterTxFreeFunc(uint16_t ipproto, AppProto alproto,
                           void (*StateTransactionFree)(void *, uint64_t));
void AppLayerParserRegisterGetTxCnt(uint16_t ipproto, AppProto alproto,
                         uint64_t (*StateGetTxCnt)(void *alstate));
void AppLayerParserRegisterGetTx(uint16_t ipproto, AppProto alproto,
                      void *(StateGetTx)(void *alstate, uint64_t tx_id));
void AppLayerParserRegisterGetStateProgressCompletionStatus(uint16_t ipproto,
                                                 uint16_t alproto,
    int (*StateGetStateProgressCompletionStatus)(uint8_t direction));
void AppLayerParserRegisterGetEventInfo(uint16_t ipproto, AppProto alproto,
    int (*StateGetEventInfo)(const char *event_name, int *event_id,
                             AppLayerEventType *event_type));

/***** Get and transaction functions *****/

void *AppLayerParserGetProtocolParserLocalStorage(uint16_t ipproto, AppProto alproto);
void AppLayerParserDestroyProtocolParserLocalStorage(uint16_t ipproto, AppProto alproto,
                                          void *local_data);


uint64_t AppLayerParserGetTransactionLogId(void *pstate);
void AppLayerParserSetTransactionLogId(void *pstate);
uint64_t AppLayerParserGetTransactionInspectId(void *pstate, uint8_t direction);
void AppLayerParserSetTransactionInspectId(void *pstate,
                                uint16_t ipproto, AppProto alproto, void *alstate,
                                uint8_t direction);
AppLayerDecoderEvents *AppLayerParserGetDecoderEvents(void *pstate);
void AppLayerParserSetDecoderEvents(void *pstate, AppLayerDecoderEvents *devents);
AppLayerDecoderEvents *AppLayerParserGetEventsByTx(uint16_t ipproto, AppProto alproto, void *alstate,
                                        uint64_t tx_id);
uint16_t AppLayerParserGetStateVersion(void *pstate);
FileContainer *AppLayerParserGetFiles(uint16_t ipproto, AppProto alproto,
                           void *alstate, uint8_t direction);
int AppLayerParserGetStateProgress(uint16_t ipproto, AppProto alproto,
                        void *alstate, uint8_t direction);
uint64_t AppLayerParserGetTxCnt(uint16_t ipproto, AppProto alproto, void *alstate);
void *AppLayerParserGetTx(uint16_t ipproto, AppProto alproto, void *alstate, uint64_t tx_id);
int AppLayerParserGetStateProgressCompletionStatus(uint16_t ipproto, AppProto alproto,
                                        uint8_t direction);
int AppLayerParserGetEventInfo(uint16_t ipproto, AppProto alproto, const char *event_name,
                    int *event_id, AppLayerEventType *event_type);

uint64_t AppLayerParserGetTransactionActive(uint16_t ipproto, AppProto alproto, void *pstate, uint8_t direction);

uint8_t AppLayerParserGetFirstDataDir(uint16_t ipproto, uint16_t alproto);

/***** General *****/

int AppLayerParserParse(void *tctx, Flow *f, AppProto alproto,
                   uint8_t flags, uint8_t *input, uint32_t input_len);
void AppLayerParserSetEOF(void *pstate);
int AppLayerParserHasDecoderEvents(uint16_t ipproto, AppProto alproto, void *alstate, void *pstate,
                        uint8_t flags);
int AppLayerParserProtocolIsTxEventAware(uint16_t ipproto, AppProto alproto);
int AppLayerParserProtocolSupportsTxs(uint16_t ipproto, AppProto alproto);
void AppLayerParserTriggerRawStreamReassembly(Flow *f);

/***** Cleanup *****/

void AppLayerParserStateCleanup(uint16_t ipproto, AppProto alproto, void *alstate, void *pstate);

void AppLayerParserRegisterProtocolParsers(void);


void AppLayerParserStateSetFlag(void *pstate, uint8_t flag);
int AppLayerParserStateIssetFlag(void *pstate, uint8_t flag);

void AppLayerParserStreamTruncated(uint16_t ipproto, AppProto alproto, void *alstate,
                        uint8_t direction);



void *AppLayerParserStateAlloc(void);
void AppLayerParserStateFree(void *pstate);



#ifdef DEBUG
void AppLayerParserStatePrintDetails(void *pstate);
#endif

/***** Unittests *****/

#ifdef UNITTESTS
void AppLayerParserRegisterProtocolUnittests(uint16_t ipproto, AppProto alproto,
                                  void (*RegisterUnittests)(void));
void AppLayerParserRegisterUnittests(void);
void AppLayerParserBackupParserTable(void);
void AppLayerParserRestoreParserTable(void);
#endif

#endif /* __APP_LAYER_PARSER_H__ */
