#ifndef __DETECT_ENGINE_H__
#define __DETECT_ENGINE_H__

#include "detect.h"

/* prototypes */
DetectEngineCtx *DetectEngineCtxInit(void);
void DetectEngineCtxFree(DetectEngineCtx *);

//inline uint32_t DetectEngineGetMaxSigId(DetectEngineCtx *);
/* faster as a macro than a inline function on my box -- VJ */
#define DetectEngineGetMaxSigId(de_ctx) ((de_ctx)->signum)
void DetectEngineResetMaxSigId(DetectEngineCtx *);

#endif /* __DETECT_ENGINE_H__ */

