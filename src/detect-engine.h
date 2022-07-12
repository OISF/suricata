/* Copyright (C) 2007-2021 Open Information Security Foundation
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

#include "detect-engine-frame.h"

void InspectionBufferInit(InspectionBuffer *buffer, uint32_t initial_size);
void InspectionBufferSetup(DetectEngineThreadCtx *det_ctx, const int list_id,
        InspectionBuffer *buffer, const uint8_t *data, const uint32_t data_len);
void InspectionBufferFree(InspectionBuffer *buffer);
void InspectionBufferCheckAndExpand(InspectionBuffer *buffer, uint32_t min_size);
void InspectionBufferCopy(InspectionBuffer *buffer, uint8_t *buf, uint32_t buf_len);
void InspectionBufferApplyTransforms(InspectionBuffer *buffer,
        const DetectEngineTransforms *transforms);
void InspectionBufferClean(DetectEngineThreadCtx *det_ctx);
InspectionBuffer *InspectionBufferGet(DetectEngineThreadCtx *det_ctx, const int list_id);
void InspectionBufferSetupMulti(InspectionBuffer *buffer, const DetectEngineTransforms *transforms,
        const uint8_t *data, const uint32_t data_len);
InspectionBuffer *InspectionBufferMultipleForListGet(
        DetectEngineThreadCtx *det_ctx, const int list_id, uint32_t local_id);

/* start up registery funcs */

int DetectBufferTypeRegister(const char *name);
int DetectBufferTypeGetByName(const char *name);
void DetectBufferTypeSupportsMpm(const char *name);
void DetectBufferTypeSupportsPacket(const char *name);
void DetectBufferTypeSupportsFrames(const char *name);
void DetectBufferTypeSupportsTransformations(const char *name);
int DetectBufferTypeMaxId(void);
void DetectBufferTypeCloseRegistration(void);
void DetectBufferTypeSetDescriptionByName(const char *name, const char *desc);
const char *DetectBufferTypeGetDescriptionByName(const char *name);
void DetectBufferTypeRegisterSetupCallback(const char *name,
        void (*Callback)(const DetectEngineCtx *, Signature *));
void DetectBufferTypeRegisterValidateCallback(const char *name,
        bool (*ValidateCallback)(const Signature *, const char **sigerror));

/* detect engine related buffer funcs */

int DetectEngineBufferTypeRegisterWithFrameEngines(DetectEngineCtx *de_ctx, const char *name,
        const int direction, const AppProto alproto, const uint8_t frame_type);
int DetectEngineBufferTypeRegister(DetectEngineCtx *de_ctx, const char *name);
const char *DetectEngineBufferTypeGetNameById(const DetectEngineCtx *de_ctx, const int id);
const DetectBufferType *DetectEngineBufferTypeGetById(const DetectEngineCtx *de_ctx, const int id);
bool DetectEngineBufferTypeSupportsMpmGetById(const DetectEngineCtx *de_ctx, const int id);
bool DetectEngineBufferTypeSupportsPacketGetById(const DetectEngineCtx *de_ctx, const int id);
const char *DetectEngineBufferTypeGetDescriptionById(const DetectEngineCtx *de_ctx, const int id);
const DetectBufferType *DetectEngineBufferTypeGetById(const DetectEngineCtx *de_ctx, const int id);
int DetectEngineBufferTypeGetByIdTransforms(
        DetectEngineCtx *de_ctx, const int id, TransformData *transforms, int transform_cnt);
void DetectEngineBufferRunSetupCallback(const DetectEngineCtx *de_ctx, const int id, Signature *s);
bool DetectEngineBufferRunValidateCallback(
        const DetectEngineCtx *de_ctx, const int id, const Signature *s, const char **sigerror);
bool DetectEngineBufferTypeValidateTransform(DetectEngineCtx *de_ctx, int sm_list,
        const uint8_t *content, uint16_t content_len, const char **namestr);
void DetectEngineBufferTypeSupportsFrames(DetectEngineCtx *de_ctx, const char *name);
void DetectEngineBufferTypeSupportsPacket(DetectEngineCtx *de_ctx, const char *name);
void DetectEngineBufferTypeSupportsMpm(DetectEngineCtx *de_ctx, const char *name);
void DetectEngineBufferTypeSupportsTransformations(DetectEngineCtx *de_ctx, const char *name);

/* prototypes */
DetectEngineCtx *DetectEngineCtxInitWithPrefix(const char *prefix);
DetectEngineCtx *DetectEngineCtxInit(void);
DetectEngineCtx *DetectEngineCtxInitStubForDD(void);
DetectEngineCtx *DetectEngineCtxInitStubForMT(void);
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
int DetectEngineReload(const SCInstance *suri);
int DetectEngineEnabled(void);
int DetectEngineMTApply(void);
int DetectEngineMultiTenantEnabled(void);
int DetectEngineMultiTenantSetup(void);

int DetectEngineReloadStart(void);
int DetectEngineReloadIsStart(void);
void DetectEngineReloadSetIdle(void);
int DetectEngineReloadIsIdle(void);

int DetectEngineLoadTenantBlocking(uint32_t tenant_id, const char *yaml);
int DetectEngineReloadTenantBlocking(uint32_t tenant_id, const char *yaml, int reload_cnt);

int DetectEngineTentantRegisterLivedev(uint32_t tenant_id, int device_id);
int DetectEngineTentantRegisterVlanId(uint32_t tenant_id, uint16_t vlan_id);
int DetectEngineTentantUnregisterVlanId(uint32_t tenant_id, uint16_t vlan_id);
int DetectEngineTentantRegisterPcapFile(uint32_t tenant_id);
int DetectEngineTentantUnregisterPcapFile(uint32_t tenant_id);

uint8_t DetectEngineInspectGenericList(DetectEngineCtx *, DetectEngineThreadCtx *,
        const struct DetectEngineAppInspectionEngine_ *, const Signature *, Flow *, uint8_t, void *,
        void *, uint64_t);

uint8_t DetectEngineInspectBufferGeneric(DetectEngineCtx *de_ctx, DetectEngineThreadCtx *det_ctx,
        const DetectEngineAppInspectionEngine *engine, const Signature *s, Flow *f, uint8_t flags,
        void *alstate, void *txv, uint64_t tx_id);

int DetectEngineInspectPktBufferGeneric(
        DetectEngineThreadCtx *det_ctx,
        const DetectEnginePktInspectionEngine *engine,
        const Signature *s, Packet *p, uint8_t *alert_flags);

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
void DetectAppLayerInspectEngineRegister2(const char *name,
        AppProto alproto, uint32_t dir, int progress,
        InspectEngineFuncPtr2 Callback2,
        InspectionBufferGetDataPtr GetData);

void DetectPktInspectEngineRegister(const char *name,
        InspectionBufferGetPktDataPtr GetPktData,
        InspectionBufferPktInspectFunc Callback);

void DetectFrameInspectEngineRegister(const char *name, int dir,
        InspectionBufferFrameInspectFunc Callback, AppProto alproto, uint8_t type);
void DetectEngineFrameInspectEngineRegister(DetectEngineCtx *de_ctx, const char *name, int dir,
        InspectionBufferFrameInspectFunc Callback, AppProto alproto, uint8_t type);

int DetectEngineAppInspectionEngine2Signature(DetectEngineCtx *de_ctx, Signature *s);
void DetectEngineAppInspectionEngineSignatureFree(DetectEngineCtx *, Signature *s);

bool DetectEngineFrameInspectionRun(ThreadVars *tv, DetectEngineThreadCtx *det_ctx,
        const Signature *s, Flow *f, Packet *p, uint8_t *alert_flags);
bool DetectEnginePktInspectionRun(ThreadVars *tv,
        DetectEngineThreadCtx *det_ctx, const Signature *s,
        Flow *f, Packet *p,
        uint8_t *alert_flags);
int DetectEnginePktInspectionSetup(Signature *s);

void DetectEngineSetParseMetadata(void);
void DetectEngineUnsetParseMetadata(void);
int DetectEngineMustParseMetadata(void);

int WARN_UNUSED DetectBufferSetActiveList(Signature *s, const int list);
int DetectBufferGetActiveList(DetectEngineCtx *de_ctx, Signature *s);

DetectEngineThreadCtx *DetectEngineThreadCtxInitForReload(
        ThreadVars *tv, DetectEngineCtx *new_de_ctx, int mt);

#endif /* __DETECT_ENGINE_H__ */
