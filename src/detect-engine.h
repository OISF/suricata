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

#ifndef __DETECT_ENGINE_H__
#define __DETECT_ENGINE_H__

#include "detect.h"
#include "tm-threads.h"

typedef struct DetectEngineAppInspectionEngine_ {
    uint16_t alproto;
    uint16_t dir;

    int32_t sm_list;
    uint32_t inspect_flags;
    uint32_t match_flags;

    int (*Callback)(ThreadVars *tv,
                    DetectEngineCtx *de_ctx, DetectEngineThreadCtx *det_ctx,
                    Signature *sig, Flow *f, uint8_t flags, void *alstate,
                    int32_t tx_id);

    struct DetectEngineAppInspectionEngine_ *next;
} DetectEngineAppInspectionEngine;

extern DetectEngineAppInspectionEngine *app_inspection_engine[ALPROTO_MAX][2];

/* prototypes */
void DetectEngineRegisterAppInspectionEngines(void);
void DetectEngineSpawnLiveRuleSwapMgmtThread(void);
DetectEngineCtx *DetectEngineCtxInit(void);
DetectEngineCtx *DetectEngineGetGlobalDeCtx(void);
void DetectEngineCtxFree(DetectEngineCtx *);

TmEcode DetectEngineThreadCtxInit(ThreadVars *, void *, void **);
TmEcode DetectEngineThreadCtxDeinit(ThreadVars *, void *);
//inline uint32_t DetectEngineGetMaxSigId(DetectEngineCtx *);
/* faster as a macro than a inline function on my box -- VJ */
#define DetectEngineGetMaxSigId(de_ctx) ((de_ctx)->signum)
void DetectEngineResetMaxSigId(DetectEngineCtx *);
void DetectEngineRegisterTests(void);

/**
 * \brief Registers an app inspection engine.
 *
 * \param alproto App layer protocol for which we will register the engine.
 * \param direction The direction for the engine.  0 - toserver; 1- toclient.
 * \param sm_list The SigMatch list against which the engine works.
 * \param inspect_flags The inspection flags to be used by de_state
 *                      against the engine.
 * \param match_flags The match flags to be used by de_state in tandem with
 *                    the inpsect_flags.
 * \param Callback The engine callback.
 */
void DetectEngineRegisterAppInspectionEngine(uint16_t alproto,
                                             uint16_t direction,
                                             int32_t sm_list,
                                             uint32_t inspect_flags,
                                             uint32_t match_flags,
                                             int (*Callback)(ThreadVars *tv,
                                                             DetectEngineCtx *de_ctx,
                                                             DetectEngineThreadCtx *det_ctx,
                                                             Signature *sig, Flow *f,
                                                             uint8_t flags, void *alstate,
                                                             int32_t tx_id),
                                             DetectEngineAppInspectionEngine *list[][2]);
#endif /* __DETECT_ENGINE_H__ */
