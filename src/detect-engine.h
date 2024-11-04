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

#ifndef SURICATA_DETECT_ENGINE_H
#define SURICATA_DETECT_ENGINE_H

#include "detect.h"
#include "suricata.h"

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
void InspectionBufferSetupMultiEmpty(InspectionBuffer *buffer);
void InspectionBufferSetupMulti(InspectionBuffer *buffer, const DetectEngineTransforms *transforms,
        const uint8_t *data, const uint32_t data_len);
InspectionBuffer *InspectionBufferMultipleForListGet(
        DetectEngineThreadCtx *det_ctx, const int list_id, uint32_t local_id);

/* start up registry funcs */

int DetectBufferTypeRegister(const char *name);
int DetectBufferTypeGetByName(const char *name);
void DetectBufferTypeSupportsMpm(const char *name);
void DetectBufferTypeSupportsPacket(const char *name);
void DetectBufferTypeSupportsFrames(const char *name);
void DetectBufferTypeSupportsTransformations(const char *name);
void DetectBufferTypeSupportsMultiInstance(const char *name);
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
bool DetectEngineBufferTypeSupportsMultiInstanceGetById(
        const DetectEngineCtx *de_ctx, const int id);
bool DetectEngineBufferTypeSupportsFramesGetById(const DetectEngineCtx *de_ctx, const int id);
const char *DetectEngineBufferTypeGetDescriptionById(const DetectEngineCtx *de_ctx, const int id);
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
DetectEngineCtx *DetectEngineCtxInitWithPrefix(const char *prefix, uint32_t tenant_id);
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
DetectEngineCtx *DetectEngineGetByTenantId(uint32_t tenant_id);
void DetectEnginePruneFreeList(void);
int DetectEngineMoveToFreeList(DetectEngineCtx *de_ctx);
void DetectEngineClearMaster(void);
DetectEngineCtx *DetectEngineReference(DetectEngineCtx *);
void DetectEngineDeReference(DetectEngineCtx **de_ctx);
int DetectEngineReload(const SCInstance *suri);
int DetectEngineEnabled(void);
int DetectEngineMTApply(void);
int DetectEngineMultiTenantEnabled(void);
int DetectEngineMultiTenantSetup(const bool unix_socket);

int DetectEngineReloadStart(void);
int DetectEngineReloadIsStart(void);
void DetectEngineReloadSetIdle(void);
int DetectEngineReloadIsIdle(void);

int DetectEngineLoadTenantBlocking(uint32_t tenant_id, const char *yaml);
int DetectEngineReloadTenantBlocking(uint32_t tenant_id, const char *yaml, int reload_cnt);
int DetectEngineReloadTenantsBlocking(const int reload_cnt);

int DetectEngineTenantRegisterLivedev(uint32_t tenant_id, int device_id);
int DetectEngineTenantRegisterVlanId(uint32_t tenant_id, uint16_t vlan_id);
int DetectEngineTenantUnregisterVlanId(uint32_t tenant_id, uint16_t vlan_id);
int DetectEngineTenantRegisterPcapFile(uint32_t tenant_id);
int DetectEngineTenantUnregisterPcapFile(uint32_t tenant_id);

uint8_t DetectEngineInspectGenericList(DetectEngineCtx *, DetectEngineThreadCtx *,
        const struct DetectEngineAppInspectionEngine_ *, const Signature *, Flow *, uint8_t, void *,
        void *, uint64_t);

uint8_t DetectEngineInspectBufferGeneric(DetectEngineCtx *de_ctx, DetectEngineThreadCtx *det_ctx,
        const DetectEngineAppInspectionEngine *engine, const Signature *s, Flow *f, uint8_t flags,
        void *alstate, void *txv, uint64_t tx_id);

uint8_t DetectEngineInspectMultiBufferGeneric(DetectEngineCtx *de_ctx,
        DetectEngineThreadCtx *det_ctx, const DetectEngineAppInspectionEngine *engine,
        const Signature *s, Flow *f, uint8_t flags, void *alstate, void *txv, uint64_t tx_id);

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
void DetectAppLayerInspectEngineRegister(const char *name, AppProto alproto, uint32_t dir,
        int progress, InspectEngineFuncPtr Callback2, InspectionBufferGetDataPtr GetData);

void DetectAppLayerMultiRegister(const char *name, AppProto alproto, uint32_t dir, int progress,
        InspectionMultiBufferGetDataPtr GetData, int priority, int tx_min_progress);

void DetectPktInspectEngineRegister(const char *name,
        InspectionBufferGetPktDataPtr GetPktData,
        InspectionBufferPktInspectFunc Callback);

void DetectEngineFrameInspectEngineRegister(DetectEngineCtx *de_ctx, const char *name, int dir,
        InspectionBufferFrameInspectFunc Callback, AppProto alproto, uint8_t type);

int DetectEngineAppInspectionEngine2Signature(DetectEngineCtx *de_ctx, Signature *s);
void DetectEngineAppInspectionEngineSignatureFree(DetectEngineCtx *, Signature *s);

bool DetectEnginePktInspectionRun(ThreadVars *tv,
        DetectEngineThreadCtx *det_ctx, const Signature *s,
        Flow *f, Packet *p,
        uint8_t *alert_flags);
int DetectEnginePktInspectionSetup(Signature *s);

void DetectEngineSetParseMetadata(void);
void DetectEngineUnsetParseMetadata(void);
int DetectEngineMustParseMetadata(void);

bool DetectBufferIsPresent(const Signature *s, const uint32_t buf_id);

int WARN_UNUSED DetectBufferSetActiveList(DetectEngineCtx *de_ctx, Signature *s, const int list);
int DetectBufferGetActiveList(DetectEngineCtx *de_ctx, Signature *s);
SigMatch *DetectBufferGetFirstSigMatch(const Signature *s, const uint32_t buf_id);
SigMatch *DetectBufferGetLastSigMatch(const Signature *s, const uint32_t buf_id);

DetectEngineThreadCtx *DetectEngineThreadCtxInitForReload(
        ThreadVars *tv, DetectEngineCtx *new_de_ctx, int mt);

void DetectRunStoreStateTx(const SigGroupHead *sgh, Flow *f, void *tx, uint64_t tx_id,
        const Signature *s, uint32_t inspect_flags, uint8_t flow_flags,
        const uint16_t file_no_match);

void DetectEngineStateResetTxs(Flow *f);

void DeStateRegisterTests(void);

#endif /* SURICATA_DETECT_ENGINE_H */
