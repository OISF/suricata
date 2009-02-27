#ifndef __DETECT_ENGINE_IPONLY_H__
#define __DETECT_ENGINE_IPONLY_H__

void IPOnlyMatchPacket(DetectEngineCtx *, DetectEngineIPOnlyCtx *, DetectEngineIPOnlyThreadCtx *, Packet *);
void IPOnlyInit(DetectEngineCtx *, DetectEngineIPOnlyCtx *);
void IPOnlyPrint(DetectEngineCtx *, DetectEngineIPOnlyCtx *);
void IPOnlyDeinit(DetectEngineCtx *, DetectEngineIPOnlyCtx *);
void IPOnlyPrepare(DetectEngineCtx *);
void DetectEngineIPOnlyThreadInit(DetectEngineCtx *, DetectEngineIPOnlyThreadCtx *);
void IPOnlyAddSignature(DetectEngineCtx *, DetectEngineIPOnlyCtx *, Signature *);

#endif /* __DETECT_ENGINE_IPONLY_H__ */

