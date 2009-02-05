/* Copyright (C) 2008 by Victor Julien <victor@inliniac.net> */

#include "vips.h"
#include "debug.h"
#include "detect.h"
#include "flow.h"

#include "detect-parse.h"

#include "detect-engine-siggroup.h"
#include "detect-engine-address.h"
#include "detect-engine-port.h"

#include "util-hash.h"

DetectEngineCtx *DetectEngineCtxInit(void) {
    DetectEngineCtx *de_ctx;

    de_ctx = malloc(sizeof(DetectEngineCtx));
    if (de_ctx == NULL) {
        goto error;
    }

    memset(de_ctx,0,sizeof(DetectEngineCtx));

    SigGroupHeadHashInit(de_ctx);
    SigGroupHeadMpmHashInit(de_ctx);
    SigGroupHeadMpmUriHashInit(de_ctx);
    SigGroupHeadSPortHashInit(de_ctx);
    SigGroupHeadDPortHashInit(de_ctx);
    DetectPortSpHashInit(de_ctx);
    DetectPortDpHashInit(de_ctx);
    return de_ctx;
error:
    return NULL;
}

void DetectEngineCtxFree(DetectEngineCtx *de_ctx) {

    /* Normally the hashes are freed elsewhere, but
     * to be sure look at them again here.
     */
    SigGroupHeadHashFree(de_ctx);
    SigGroupHeadMpmHashFree(de_ctx);
    SigGroupHeadMpmUriHashFree(de_ctx);
    SigGroupHeadSPortHashFree(de_ctx);
    SigGroupHeadDPortHashFree(de_ctx);
    DetectPortSpHashFree(de_ctx);
    DetectPortDpHashFree(de_ctx);

    free(de_ctx);
}

/*
 * getting & (re)setting the internal sig i
 */

u_int32_t DetectEngineGetMaxSigId(DetectEngineCtx *de_ctx) {
    return de_ctx->signum;
}

void DetectEngineResetMaxSigId(DetectEngineCtx *de_ctx) {
    de_ctx->signum = 0;
}

