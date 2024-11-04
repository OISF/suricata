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

#ifndef SURICATA_DETECT_ENGINE_MPM_H
#define SURICATA_DETECT_ENGINE_MPM_H

#include "detect.h"


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

void PatternMatchPrepare(MpmCtx *, uint16_t);
void PatternMatchThreadPrepare(MpmThreadCtx *, uint16_t type);

void PatternMatchDestroy(MpmCtx *, uint16_t);
void PatternMatchThreadDestroy(MpmThreadCtx *mpm_thread_ctx, uint16_t);

int PatternMatchPrepareGroup(DetectEngineCtx *, SigGroupHead *);

int SignatureHasPacketContent(const Signature *);
int SignatureHasStreamContent(const Signature *);

void RetrieveFPForSig(const DetectEngineCtx *de_ctx, Signature *s);

int MpmStoreInit(DetectEngineCtx *);
void MpmStoreFree(DetectEngineCtx *);
void MpmStoreReportStats(const DetectEngineCtx *de_ctx);
MpmStore *MpmStorePrepareBuffer(DetectEngineCtx *de_ctx, SigGroupHead *sgh, enum MpmBuiltinBuffers buf);

/**
 * \brief Figure out the FP and their respective content ids for all the
 *        sigs in the engine.
 *
 * \param de_ctx Detection engine context.
 *
 * \retval  0 On success.
 * \retval -1 On failure.
 */
int DetectSetFastPatternAndItsId(DetectEngineCtx *de_ctx);

typedef int (*PrefilterRegisterFunc)(DetectEngineCtx *de_ctx, SigGroupHead *sgh, MpmCtx *mpm_ctx,
        const DetectBufferMpmRegistry *mpm_reg, int list_id);

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
void DetectAppLayerMpmRegister(const char *name, int direction, int priority,
        PrefilterRegisterFunc PrefilterRegister, InspectionBufferGetDataPtr GetData,
        AppProto alproto, int tx_min_progress);
void DetectAppLayerMpmMultiRegister(const char *name, int direction, int priority,
        PrefilterRegisterFunc PrefilterRegister, InspectionMultiBufferGetDataPtr GetData,
        AppProto alproto, int tx_min_progress);
void DetectAppLayerMpmRegisterByParentId(
        DetectEngineCtx *de_ctx,
        const int id, const int parent_id,
        DetectEngineTransforms *transforms);

void DetectPktMpmRegister(const char *name, int priority, PrefilterRegisterFunc PrefilterRegister,
        InspectionBufferGetPktDataPtr GetData);
void DetectPktMpmRegisterByParentId(DetectEngineCtx *de_ctx,
        const int id, const int parent_id,
        DetectEngineTransforms *transforms);

void DetectFrameMpmRegister(const char *name, int direction, int priority,
        int (*PrefilterRegister)(DetectEngineCtx *de_ctx, SigGroupHead *sgh, MpmCtx *mpm_ctx,
                const DetectBufferMpmRegistry *mpm_reg, int list_id),
        AppProto alproto, uint8_t type);
void DetectFrameMpmRegisterByParentId(DetectEngineCtx *de_ctx, const int id, const int parent_id,
        DetectEngineTransforms *transforms);
void DetectEngineFrameMpmRegister(DetectEngineCtx *de_ctx, const char *name, int direction,
        int priority,
        int (*PrefilterRegister)(DetectEngineCtx *de_ctx, SigGroupHead *sgh, MpmCtx *mpm_ctx,
                const DetectBufferMpmRegistry *mpm_reg, int list_id),
        AppProto alproto, uint8_t type);

int PrefilterGenericMpmPktRegister(DetectEngineCtx *de_ctx, SigGroupHead *sgh, MpmCtx *mpm_ctx,
        const DetectBufferMpmRegistry *mpm_reg, int list_id);

int PrefilterGenericMpmFrameRegister(DetectEngineCtx *de_ctx, SigGroupHead *sgh, MpmCtx *mpm_ctx,
        const DetectBufferMpmRegistry *mpm_reg, int list_id);

typedef struct PrefilterMpmListId {
    int list_id;
    const MpmCtx *mpm_ctx;
    InspectionMultiBufferGetDataPtr GetData;
    const DetectEngineTransforms *transforms;
} PrefilterMpmListId;

struct MpmListIdDataArgs {
    uint32_t local_id; /**< used as index into thread inspect array */
    void *txv;
};

void EngineAnalysisAddAllRulePatterns(DetectEngineCtx *de_ctx, const Signature *s);

#endif /* SURICATA_DETECT_ENGINE_MPM_H */
