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
#include "flow-private.h"

typedef struct DetectEngineAppInspectionEngine_ {
    uint8_t ipproto;
    AppProto alproto;
    uint16_t dir;

    int32_t sm_list;
    uint32_t inspect_flags;

    /* \retval 0 No match.  Don't discontinue matching yet.  We need more data.
     *         1 Match.
     *         2 Sig can't match.
     *         3 Special value used by filestore sigs to indicate disabling
     *           filestore for the tx.
     */
    int (*Callback)(ThreadVars *tv,
                    DetectEngineCtx *de_ctx, DetectEngineThreadCtx *det_ctx,
                    Signature *sig, Flow *f, uint8_t flags, void *alstate,
                    void *tx, uint64_t tx_id);

    struct DetectEngineAppInspectionEngine_ *next;
} DetectEngineAppInspectionEngine;

extern DetectEngineAppInspectionEngine *app_inspection_engine[FLOW_PROTO_DEFAULT][ALPROTO_MAX][2];

/* prototypes */
void DetectEngineRegisterAppInspectionEngines(void);
DetectEngineCtx *DetectEngineCtxInitWithPrefix(const char *prefix);
DetectEngineCtx *DetectEngineCtxInit(void);
DetectEngineCtx *DetectEngineCtxInitMinimal(void);
void DetectEngineCtxFree(DetectEngineCtx *);

TmEcode DetectEngineThreadCtxInit(ThreadVars *, void *, void **);
TmEcode DetectEngineThreadCtxDeinit(ThreadVars *, void *);
//inline uint32_t DetectEngineGetMaxSigId(DetectEngineCtx *);
/* faster as a macro than a inline function on my box -- VJ */
#define DetectEngineGetMaxSigId(de_ctx) ((de_ctx)->signum)
void DetectEngineResetMaxSigId(DetectEngineCtx *);
void DetectEngineRegisterTests(void);
const char *DetectSigmatchListEnumToString(enum DetectSigmatchListEnum type);

int DetectEngineAddToMaster(DetectEngineCtx *de_ctx);
DetectEngineCtx *DetectEngineGetCurrent(void);
DetectEngineCtx *DetectEngineGetByTenantId(int tenant_id);
void DetectEnginePruneFreeList(void);
int DetectEngineMoveToFreeList(DetectEngineCtx *de_ctx);
DetectEngineCtx *DetectEngineReference(DetectEngineCtx *);
void DetectEngineDeReference(DetectEngineCtx **de_ctx);
int DetectEngineReload(const char *filename, SCInstance *suri);
int DetectEngineEnabled(void);
int DetectEngineMTApply(void);
int DetectEngineMultiTenantEnabled(void);
int DetectEngineMultiTenantSetup(void);

int DetectEngineReloadStart(void);
int DetectEngineReloadIsStart(void);
void DetectEngineReloadSetDone(void);
int DetectEngineReloadIsDone(void);

int DetectEngineLoadTenantBlocking(uint32_t tenant_id, const char *yaml);
int DetectEngineReloadTenantBlocking(uint32_t tenant_id, const char *yaml, int reload_cnt);

int DetectEngineTentantRegisterVlanId(uint32_t tenant_id, uint16_t vlan_id);
int DetectEngineTentantUnregisterVlanId(uint32_t tenant_id, uint16_t vlan_id);
int DetectEngineTentantRegisterPcapFile(uint32_t tenant_id);
int DetectEngineTentantUnregisterPcapFile(uint32_t tenant_id);

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
void DetectEngineRegisterAppInspectionEngine(uint8_t ipproto,
                                             AppProto alproto,
                                             uint16_t direction,
                                             int32_t sm_list,
                                             uint32_t inspect_flags,
                                             int (*Callback)(ThreadVars *tv,
                                                             DetectEngineCtx *de_ctx,
                                                             DetectEngineThreadCtx *det_ctx,
                                                             Signature *sig, Flow *f,
                                                             uint8_t flags, void *alstate,
                                                             void *tx, uint64_t tx_id),
                                             DetectEngineAppInspectionEngine *list[][ALPROTO_MAX][2]);
#endif /* __DETECT_ENGINE_H__ */
