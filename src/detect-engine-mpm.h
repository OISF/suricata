/* Copyright (C) 2007-2010 Open Information Security Foundation
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
 */

#ifndef __DETECT_ENGINE_MPM_H__
#define __DETECT_ENGINE_MPM_H__

#include "tm-threads.h"

#include "detect.h"
#include "detect-content.h"
#include "detect-uricontent.h"

#include "stream.h"

uint16_t PatternMatchDefaultMatcher(void);

uint32_t PatternStrength(uint8_t *, uint16_t);
uint32_t PacketPatternSearchWithStreamCtx(DetectEngineThreadCtx *, Packet *);
uint32_t PacketPatternSearch(DetectEngineThreadCtx *, Packet *);
uint32_t UriPatternSearch(DetectEngineThreadCtx *, uint8_t *, uint16_t, uint8_t);
uint32_t StreamPatternSearch(DetectEngineThreadCtx *, Packet *, StreamMsg *, uint8_t);
uint32_t HttpClientBodyPatternSearch(DetectEngineThreadCtx *, uint8_t *, uint32_t, uint8_t);
uint32_t HttpServerBodyPatternSearch(DetectEngineThreadCtx *, uint8_t *, uint32_t, uint8_t);
uint32_t HttpHeaderPatternSearch(DetectEngineThreadCtx *, uint8_t *, uint32_t, uint8_t);
uint32_t HttpRawHeaderPatternSearch(DetectEngineThreadCtx *, uint8_t *, uint32_t, uint8_t);
uint32_t HttpMethodPatternSearch(DetectEngineThreadCtx *, uint8_t *, uint32_t, uint8_t);
uint32_t HttpCookiePatternSearch(DetectEngineThreadCtx *, uint8_t *, uint32_t, uint8_t);
uint32_t HttpRawUriPatternSearch(DetectEngineThreadCtx *, uint8_t *, uint32_t, uint8_t);
uint32_t HttpStatMsgPatternSearch(DetectEngineThreadCtx *, uint8_t *, uint32_t, uint8_t);
uint32_t HttpStatCodePatternSearch(DetectEngineThreadCtx *, uint8_t *, uint32_t, uint8_t);
uint32_t HttpUAPatternSearch(DetectEngineThreadCtx *, uint8_t *, uint32_t, uint8_t);
uint32_t HttpHHPatternSearch(DetectEngineThreadCtx *, uint8_t *, uint32_t, uint8_t);
uint32_t HttpHRHPatternSearch(DetectEngineThreadCtx *, uint8_t *, uint32_t, uint8_t);
uint32_t DnsQueryPatternSearch(DetectEngineThreadCtx *det_ctx, uint8_t *buffer, uint32_t buffer_len, uint8_t flags);
uint32_t SMTPFiledataPatternSearch(DetectEngineThreadCtx *det_ctx, uint8_t *buffer, uint32_t buffer_len, uint8_t flags);

void PacketPatternCleanup(ThreadVars *, DetectEngineThreadCtx *);
void StreamPatternCleanup(ThreadVars *t, DetectEngineThreadCtx *det_ctx, StreamMsg *smsg);

void PatternMatchPrepare(MpmCtx *, uint16_t);
void PatternMatchThreadPrepare(MpmThreadCtx *, uint16_t type, uint32_t max_id);

void PatternMatchDestroy(MpmCtx *, uint16_t);
void PatternMatchThreadDestroy(MpmThreadCtx *mpm_thread_ctx, uint16_t);
void PatternMatchThreadPrint(MpmThreadCtx *, uint16_t);

int PatternMatchPrepareGroup(DetectEngineCtx *, SigGroupHead *);
void DetectEngineThreadCtxInfo(ThreadVars *, DetectEngineThreadCtx *);
void PatternMatchDestroyGroup(SigGroupHead *);

TmEcode DetectEngineThreadCtxInit(ThreadVars *, void *, void **);
TmEcode DetectEngineThreadCtxDeinit(ThreadVars *, void *);

void DbgPrintSearchStats();

MpmPatternIdStore *MpmPatternIdTableInitHash(void);
void MpmPatternIdTableFreeHash(MpmPatternIdStore *);
uint32_t MpmPatternIdStoreGetMaxId(MpmPatternIdStore *);
uint32_t DetectContentGetId(MpmPatternIdStore *, DetectContentData *);

int SignatureHasPacketContent(Signature *);
int SignatureHasStreamContent(Signature *);

SigMatch *RetrieveFPForSig(Signature *s);
SigMatch *RetrieveFPForSigV2(Signature *s);

/**
 * \brief Figured out the FP and their respective content ids for all the
 *        sigs in the engine.
 *
 * \param de_ctx Detection engine context.
 *
 * \retval  0 On success.
 * \retval -1 On failure.
 */
int DetectSetFastPatternAndItsId(DetectEngineCtx *de_ctx);

#endif /* __DETECT_ENGINE_MPM_H__ */

