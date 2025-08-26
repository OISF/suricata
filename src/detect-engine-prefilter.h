/* Copyright (C) 2016-2025 Open Information Security Foundation
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

#ifndef SURICATA_DETECT_ENGINE_PREFILTER_H
#define SURICATA_DETECT_ENGINE_PREFILTER_H

#include "detect.h"
#include "detect-engine-state.h"

// TODO
typedef struct DetectTransaction_ {
    void *tx_ptr;
    const uint64_t tx_id;
    struct AppLayerTxData *tx_data_ptr;
    DetectEngineStateDirection *de_state;

    /* tracking detect progress. Holds the value of
     * the last completed "progress" + 1. */
    uint8_t detect_progress;
    /* original value to track changes. */
    const uint8_t detect_progress_orig;

    const int tx_progress;
    const int tx_end_state;
} DetectTransaction;

typedef struct PrefilterStore_ {
    const char *name;
    void (*FreeFunc)(void *);
    uint32_t id;
} PrefilterStore;

void Prefilter(DetectEngineThreadCtx *, const SigGroupHead *, Packet *p, const uint8_t flags,
        const SignatureMask mask);

int PrefilterAppendEngine(DetectEngineCtx *de_ctx, SigGroupHead *sgh, PrefilterPktFn PrefilterFunc,
        SignatureMask mask, enum SignatureHookPkt hook, void *pectx, void (*FreeFunc)(void *pectx),
        const char *name);

void PrefilterPostRuleMatch(
        DetectEngineThreadCtx *det_ctx, const SigGroupHead *sgh, Packet *p, Flow *f);

int PrefilterAppendPayloadEngine(DetectEngineCtx *de_ctx, SigGroupHead *sgh,
        PrefilterPktFn PrefilterFunc, void *pectx, void (*FreeFunc)(void *pectx), const char *name);
int PrefilterAppendTxEngine(DetectEngineCtx *de_ctx, SigGroupHead *sgh,
        PrefilterTxFn PrefilterTxFunc, const AppProto alproto, const int tx_min_progress,
        void *pectx, void (*FreeFunc)(void *pectx), const char *name);
int PrefilterAppendFrameEngine(DetectEngineCtx *de_ctx, SigGroupHead *sgh,
        PrefilterFrameFn PrefilterFrameFunc, AppProto alproto, uint8_t frame_type, void *pectx,
        void (*FreeFunc)(void *pectx), const char *name);
int PrefilterAppendPostRuleEngine(DetectEngineCtx *de_ctx, SigGroupHead *sgh,
        void (*PrefilterPostRuleFunc)(
                DetectEngineThreadCtx *det_ctx, const void *pectx, Packet *p, Flow *f),
        void *pectx, void (*FreeFunc)(void *pectx), const char *name);

void DetectRunPrefilterTx(DetectEngineThreadCtx *det_ctx,
        const SigGroupHead *sgh,
        Packet *p,
        const uint8_t ipproto,
        const uint8_t flow_flags,
        const AppProto alproto,
        void *alstate,
        DetectTransaction *tx);

void PrefilterFreeEnginesList(PrefilterEngineList *list);

int PrefilterSetupRuleGroup(DetectEngineCtx *de_ctx, SigGroupHead *sgh);
void PrefilterCleanupRuleGroup(const DetectEngineCtx *de_ctx, SigGroupHead *sgh);

void PrefilterInit(DetectEngineCtx *de_ctx);
void PrefilterDeinit(DetectEngineCtx *de_ctx);

int PrefilterGenericMpmRegister(DetectEngineCtx *de_ctx, SigGroupHead *sgh, MpmCtx *mpm_ctx,
        const DetectBufferMpmRegistry *mpm_reg, int list_id);

int PrefilterSingleMpmRegister(DetectEngineCtx *de_ctx, SigGroupHead *sgh, MpmCtx *mpm_ctx,
        const DetectBufferMpmRegistry *mpm_reg, int list_id);

int PrefilterMultiGenericMpmRegister(DetectEngineCtx *de_ctx, SigGroupHead *sgh, MpmCtx *mpm_ctx,
        const DetectBufferMpmRegistry *mpm_reg, int list_id);

int PrefilterGenericMpmPktRegister(DetectEngineCtx *de_ctx, SigGroupHead *sgh, MpmCtx *mpm_ctx,
        const DetectBufferMpmRegistry *mpm_reg, int list_id);

void PostRuleMatchWorkQueueAppend(
        DetectEngineThreadCtx *det_ctx, const Signature *s, const int type, const uint32_t value);

void PrefilterPktNonPFStatsDump(void);

#endif
