#ifndef __DETECT_ENGINE_H__
#define __DETECT_ENGINE_H__

/* prototypes */
DetectEngineCtx *DetectEngineCtxInit(void);
void DetectEngineCtxFree(DetectEngineCtx *);

uint32_t DetectEngineGetMaxSigId(DetectEngineCtx *);
void DetectEngineResetMaxSigId(DetectEngineCtx *);

#endif /* __DETECT_ENGINE_H__ */

