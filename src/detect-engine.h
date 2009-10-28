#ifndef __DETECT_ENGINE_H__
#define __DETECT_ENGINE_H__

#include "detect.h"

/* prototypes */
DetectEngineCtx *DetectEngineCtxInit(void);
void DetectEngineCtxFree(DetectEngineCtx *);

inline uint32_t DetectEngineGetMaxSigId(DetectEngineCtx *);
void DetectEngineResetMaxSigId(DetectEngineCtx *);

#endif /* __DETECT_ENGINE_H__ */

