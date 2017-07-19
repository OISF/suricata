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

void DetectMpmInitializeAppMpms(DetectEngineCtx *de_ctx);
int DetectMpmPrepareAppMpms(DetectEngineCtx *de_ctx);
void DetectMpmInitializeBuiltinMpms(DetectEngineCtx *de_ctx);
int DetectMpmPrepareBuiltinMpms(DetectEngineCtx *de_ctx);

uint32_t PatternStrength(uint8_t *, uint16_t);

uint16_t PatternMatchDefaultMatcher(void);
uint32_t DnsQueryPatternSearch(DetectEngineThreadCtx *det_ctx, uint8_t *buffer, uint32_t buffer_len, uint8_t flags);

void PacketPatternCleanup(ThreadVars *, DetectEngineThreadCtx *);

void PatternMatchPrepare(MpmCtx *, uint16_t);
void PatternMatchThreadPrepare(MpmThreadCtx *, uint16_t type);

void PatternMatchDestroy(MpmCtx *, uint16_t);
void PatternMatchThreadDestroy(MpmThreadCtx *mpm_thread_ctx, uint16_t);
void PatternMatchThreadPrint(MpmThreadCtx *, uint16_t);

int PatternMatchPrepareGroup(DetectEngineCtx *, SigGroupHead *);
void DetectEngineThreadCtxInfo(ThreadVars *, DetectEngineThreadCtx *);

TmEcode DetectEngineThreadCtxInit(ThreadVars *, void *, void **);
TmEcode DetectEngineThreadCtxDeinit(ThreadVars *, void *);

int SignatureHasPacketContent(const Signature *);
int SignatureHasStreamContent(const Signature *);

void RetrieveFPForSig(Signature *s);

int MpmStoreInit(DetectEngineCtx *);
void MpmStoreFree(DetectEngineCtx *);
void MpmStoreReportStats(const DetectEngineCtx *de_ctx);
MpmStore *MpmStorePrepareBuffer(DetectEngineCtx *de_ctx, SigGroupHead *sgh, enum MpmBuiltinBuffers buf);

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

/** \brief register an app layer keyword for mpm
 *  \param name keyword name
 *  \param direction SIG_FLAG_TOSERVER or SIG_FLAG_TOCLIENT
 *  \param PrefilterRegister Prefilter api registration function
 *
 *  \note direction must be set to either toserver or toclient.
 *        If both are needed, register the keyword twice.
 */
void DetectAppLayerMpmRegister(const char *name,
        int direction, int priority,
        int (*PrefilterRegister)(SigGroupHead *sgh, MpmCtx *mpm_ctx));

#endif /* __DETECT_ENGINE_MPM_H__ */

