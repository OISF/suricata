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

int DetectBufferTypeRegister(const char *name);
int DetectBufferTypeGetByName(const char *name);
const char *DetectBufferTypeGetNameById(const int id);
void DetectBufferTypeSupportsMpm(const char *name);
void DetectBufferTypeSupportsPacket(const char *name);
_Bool DetectBufferTypeSupportsMpmGetById(const int id);
_Bool DetectBufferTypeSupportsPacketGetById(const int id);
int DetectBufferTypeMaxId(void);
void DetectBufferTypeFinalizeRegistration(void);
void DetectBufferTypeSetDescriptionByName(const char *name, const char *desc);
const char *DetectBufferTypeGetDescriptionById(const int id);
const char *DetectBufferTypeGetDescriptionByName(const char *name);
void DetectBufferTypeRegisterSetupCallback(const char *name,
        void (*Callback)(Signature *));
void DetectBufferRunSetupCallback(const int id, Signature *s);
void DetectBufferTypeRegisterValidateCallback(const char *name,
        _Bool (*ValidateCallback)(const Signature *));
_Bool DetectBufferRunValidateCallback(const int id, const Signature *s);

/* prototypes */
DetectEngineCtx *DetectEngineCtxInitWithPrefix(const char *prefix);
DetectEngineCtx *DetectEngineCtxInit(void);
DetectEngineCtx *DetectEngineCtxInitMinimal(void);
void DetectEngineCtxFree(DetectEngineCtx *);

int DetectRegisterThreadCtxGlobalFuncs(const char *name,
        void *(*InitFunc)(void *), void *data, void (*FreeFunc)(void *));
void *DetectThreadCtxGetGlobalKeywordThreadCtx(DetectEngineThreadCtx *det_ctx, int id);

TmEcode DetectEngineThreadCtxInit(ThreadVars *, void *, void **);
TmEcode DetectEngineThreadCtxDeinit(ThreadVars *, void *);
//inline uint32_t DetectEngineGetMaxSigId(DetectEngineCtx *);
/* faster as a macro than a inline function on my box -- VJ */
#define DetectEngineGetMaxSigId(de_ctx) ((de_ctx)->signum)
void DetectEngineResetMaxSigId(DetectEngineCtx *);
void DetectEngineRegisterTests(void);
const char *DetectSigmatchListEnumToString(enum DetectSigmatchListEnum type);

uint32_t DetectEngineGetVersion(void);
void DetectEngineBumpVersion(void);
int DetectEngineAddToMaster(DetectEngineCtx *de_ctx);
DetectEngineCtx *DetectEngineGetCurrent(void);
DetectEngineCtx *DetectEngineGetByTenantId(int tenant_id);
void DetectEnginePruneFreeList(void);
int DetectEngineMoveToFreeList(DetectEngineCtx *de_ctx);
DetectEngineCtx *DetectEngineReference(DetectEngineCtx *);
void DetectEngineDeReference(DetectEngineCtx **de_ctx);
int DetectEngineReload(SCInstance *suri);
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

int DetectEngineInspectGenericList(ThreadVars *, const DetectEngineCtx *,
                                   DetectEngineThreadCtx *,
                                   const Signature *, const SigMatchData *,
                                   Flow *, const uint8_t, void *, void *,
                                   uint64_t);

/**
 * \brief Registers an app inspection engine.
 *
 * \param name Name of the detection list
 * \param alproto App layer protocol for which we will register the engine.
 * \param direction The direction for the engine: SIG_FLAG_TOSERVER or
 *                  SIG_FLAG_TOCLIENT
 * \param progress Minimal progress value for inspect engine to run
 * \param Callback The engine callback.
 */
void DetectAppLayerInspectEngineRegister(const char *name,
        AppProto alproto, uint32_t dir,
        int progress, InspectEngineFuncPtr Callback);

int DetectEngineAppInspectionEngine2Signature(Signature *s);
void DetectEngineAppInspectionEngineSignatureFree(Signature *s);

#endif /* __DETECT_ENGINE_H__ */
