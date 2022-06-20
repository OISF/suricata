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

void DetectMpmInitializeFrameMpms(DetectEngineCtx *de_ctx);
int DetectMpmPrepareFrameMpms(DetectEngineCtx *de_ctx);
void DetectMpmInitializePktMpms(DetectEngineCtx *de_ctx);
int DetectMpmPreparePktMpms(DetectEngineCtx *de_ctx);
void DetectMpmInitializeAppMpms(DetectEngineCtx *de_ctx);
int DetectMpmPrepareAppMpms(DetectEngineCtx *de_ctx);
void DetectMpmInitializeBuiltinMpms(DetectEngineCtx *de_ctx);
int DetectMpmPrepareBuiltinMpms(DetectEngineCtx *de_ctx);

uint32_t PatternStrength(uint8_t *, uint16_t);

uint8_t PatternMatchDefaultMatcher(void);
uint32_t DnsQueryPatternSearch(DetectEngineThreadCtx *det_ctx, uint8_t *buffer, uint32_t buffer_len, uint8_t flags);

void PatternMatchPrepare(MpmCtx *, uint16_t);
void PatternMatchThreadPrepare(MpmThreadCtx *, uint8_t type);

void PatternMatchDestroy(MpmCtx *, uint8_t);
void PatternMatchThreadDestroy(MpmThreadCtx *mpm_thread_ctx, uint8_t);
void PatternMatchThreadPrint(MpmThreadCtx *, uint8_t);

int PatternMatchPrepareGroup(DetectEngineCtx *, SigGroupHead *);
void DetectEngineThreadCtxInfo(ThreadVars *, DetectEngineThreadCtx *);

TmEcode DetectEngineThreadCtxInit(ThreadVars *, void *, void **);
TmEcode DetectEngineThreadCtxDeinit(ThreadVars *, void *);

int SignatureHasPacketContent(const Signature *);
int SignatureHasStreamContent(const Signature *);

void RetrieveFPForSig(const DetectEngineCtx *de_ctx, Signature *s);

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
 *  \param name buffer name
 *  \param direction SIG_FLAG_TOSERVER or SIG_FLAG_TOCLIENT
 *  \param priority mpm keyword priority
 *  \param PrefilterRegister Prefilter api registration function
 *  \param GetData callback to setup a InspectBuffer. May be NULL.
 *  \param alproto AppProto this MPM engine inspects
 *  \param tx_min_progress min tx progress needed to invoke this engine.
 *
 *  \note direction must be set to either toserver or toclient.
 *        If both are needed, register the keyword twice.
 */
void DetectAppLayerMpmRegister2(const char *name,
        int direction, int priority,
        int (*PrefilterRegister)(DetectEngineCtx *de_ctx,
            SigGroupHead *sgh, MpmCtx *mpm_ctx,
            const DetectBufferMpmRegistery *mpm_reg, int list_id),
        InspectionBufferGetDataPtr GetData,
        AppProto alproto, int tx_min_progress);
void DetectAppLayerMpmRegisterByParentId(
        DetectEngineCtx *de_ctx,
        const int id, const int parent_id,
        DetectEngineTransforms *transforms);

void DetectPktMpmRegister(const char *name,
        int priority,
        int (*PrefilterRegister)(DetectEngineCtx *de_ctx,
            SigGroupHead *sgh, MpmCtx *mpm_ctx,
            const DetectBufferMpmRegistery *mpm_reg, int list_id),
        InspectionBufferGetPktDataPtr GetData);
void DetectPktMpmRegisterByParentId(DetectEngineCtx *de_ctx,
        const int id, const int parent_id,
        DetectEngineTransforms *transforms);

void DetectFrameMpmRegister(const char *name, int direction, int priority,
        int (*PrefilterRegister)(DetectEngineCtx *de_ctx, SigGroupHead *sgh, MpmCtx *mpm_ctx,
                const DetectBufferMpmRegistery *mpm_reg, int list_id),
        AppProto alproto, uint8_t type);
void DetectFrameMpmRegisterByParentId(DetectEngineCtx *de_ctx, const int id, const int parent_id,
        DetectEngineTransforms *transforms);
void DetectEngineFrameMpmRegister(DetectEngineCtx *de_ctx, const char *name, int direction,
        int priority,
        int (*PrefilterRegister)(DetectEngineCtx *de_ctx, SigGroupHead *sgh, MpmCtx *mpm_ctx,
                const DetectBufferMpmRegistery *mpm_reg, int list_id),
        AppProto alproto, uint8_t type);

int PrefilterGenericMpmPktRegister(DetectEngineCtx *de_ctx,
         SigGroupHead *sgh, MpmCtx *mpm_ctx,
         const DetectBufferMpmRegistery *mpm_reg, int list_id);

int PrefilterGenericMpmFrameRegister(DetectEngineCtx *de_ctx, SigGroupHead *sgh, MpmCtx *mpm_ctx,
        const DetectBufferMpmRegistery *mpm_reg, int list_id);

typedef struct PrefilterMpmListId {
    int list_id;
    const MpmCtx *mpm_ctx;
    const DetectEngineTransforms *transforms;
} PrefilterMpmListId;

struct MpmListIdDataArgs {
    uint32_t local_id; /**< used as index into thread inspect array */
    void *txv;
};

void EngineAnalysisAddAllRulePatterns(DetectEngineCtx *de_ctx, const Signature *s);

#endif /* __DETECT_ENGINE_MPM_H__ */

