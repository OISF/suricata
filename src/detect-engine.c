/* Copyright (C) 2008 by Victor Julien <victor@inliniac.net> */

#include "vips.h"
#include "debug.h"
#include "detect.h"
#include "flow.h"

#include "detect-parse.h"
#include "detect-siggroup.h"

#include "detect-address.h"

DetectEngineCtx *DetectEngineCtxInit(void) {
    DetectEngineCtx *de_ctx;

    de_ctx = malloc(sizeof(DetectEngineCtx));
    if (de_ctx == NULL) {
        goto error;
    }

    memset(de_ctx,0,sizeof(DetectEngineCtx));

    return de_ctx;
error:
    return NULL;
}

