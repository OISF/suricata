#ifndef __DETECT_ENGINE_MPM_H__
#define __DETECT_ENGINE_MPM_H__

#include "tm-modules.h"

uint16_t PatternMatchDefaultMatcher(void);
uint32_t PacketPatternScan(ThreadVars *, DetectEngineThreadCtx *, Packet *);
uint32_t PacketPatternMatch(ThreadVars *, DetectEngineThreadCtx *, Packet *);

void PacketPatternCleanup(ThreadVars *, DetectEngineThreadCtx *);

void PatternMatchPrepare(MpmCtx *, uint16_t);
void PatternMatchThreadPrepare(MpmThreadCtx *, uint16_t type, uint32_t max_id);

void PatternMatchDestroy(MpmCtx *, uint16_t);
void PatternMatchThreadDestroy(MpmThreadCtx *mpm_thread_ctx, uint16_t);
void PatternMatchThreadPrint(MpmThreadCtx *, uint16_t);

int PatternMatchPrepareGroup(DetectEngineCtx *, SigGroupHead *);
void DetectEngineThreadCtxInfo(ThreadVars *, DetectEngineThreadCtx *);
void PatternMatchDestroyGroup(SigGroupHead *);

TmEcode DetectEngineThreadCtxInit(ThreadVars *, void *, void **);
TmEcode DetectEngineThreadCtxDeinit(ThreadVars *, void *);

void DbgPrintScanSearchStats();

#endif /* __DETECT_ENGINE_MPM_H__ */

