/* Copyright (C) 2016 Open Information Security Foundation
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

#ifndef __DETECT_ENGINE_PREFILTER_H__
#define __DETECT_ENGINE_PREFILTER_H__

#include "detect-engine-state.h"

typedef struct PrefilterStore_ {
    const char *name;
    void (*FreeFunc)(void *);
    uint32_t id;
} PrefilterStore;

void Prefilter(DetectEngineThreadCtx *, const SigGroupHead *, Packet *p,
        const uint8_t flags);

int PrefilterAppendEngine(DetectEngineCtx *de_ctx, SigGroupHead *sgh,
        void (*Prefilter)(DetectEngineThreadCtx *det_ctx, Packet *p, const void *pectx),
        void *pectx, void (*FreeFunc)(void *pectx),
        const char *name);
int PrefilterAppendPayloadEngine(DetectEngineCtx *de_ctx, SigGroupHead *sgh,
        void (*Prefilter)(DetectEngineThreadCtx *det_ctx, Packet *p, const void *pectx),
        void *pectx, void (*FreeFunc)(void *pectx),
        const char *name);
int PrefilterAppendTxEngine(DetectEngineCtx *de_ctx, SigGroupHead *sgh,
        PrefilterTxFn PrefilterTxFunc, const AppProto alproto, const int tx_min_progress,
        void *pectx, void (*FreeFunc)(void *pectx), const char *name);
int PrefilterAppendFrameEngine(DetectEngineCtx *de_ctx, SigGroupHead *sgh,
        PrefilterFrameFn PrefilterFrameFunc, AppProto alproto, uint8_t frame_type, void *pectx,
        void (*FreeFunc)(void *pectx), const char *name);

void DetectRunPrefilterTx(DetectEngineThreadCtx *det_ctx,
        const SigGroupHead *sgh,
        Packet *p,
        const uint8_t ipproto,
        const uint8_t flow_flags,
        const AppProto alproto,
        void *alstate,
        DetectTransaction *tx);

void PrefilterFreeEnginesList(PrefilterEngineList *list);

void PrefilterSetupRuleGroup(DetectEngineCtx *de_ctx, SigGroupHead *sgh);
void PrefilterCleanupRuleGroup(const DetectEngineCtx *de_ctx, SigGroupHead *sgh);

#ifdef PROFILING
const char *PrefilterStoreGetName(const uint32_t id);
#endif

void PrefilterInit(DetectEngineCtx *de_ctx);
void PrefilterDeinit(DetectEngineCtx *de_ctx);

int PrefilterGenericMpmRegister(DetectEngineCtx *de_ctx,
        SigGroupHead *sgh, MpmCtx *mpm_ctx,
        const DetectBufferMpmRegistery *mpm_reg, int list_id);

int PrefilterGenericMpmPktRegister(DetectEngineCtx *de_ctx,
        SigGroupHead *sgh, MpmCtx *mpm_ctx,
        const DetectBufferMpmRegistery *mpm_reg, int list_id);


#endif
