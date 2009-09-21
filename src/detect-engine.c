/* Copyright (C) 2008 by Victor Julien <victor@inliniac.net> */

#include "eidps-common.h"
#include "debug.h"
#include "detect.h"
#include "flow.h"

#include "detect-parse.h"
#include "detect-engine-sigorder.h"

#include "detect-engine-siggroup.h"
#include "detect-engine-address.h"
#include "detect-engine-port.h"
#include "detect-engine-mpm.h"
#include "detect-engine-iponly.h"

#include "detect-content.h"
#include "detect-uricontent.h"

//#include "util-mpm.h"
#include "util-hash.h"

#include "util-var-name.h"

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

    VariableNameInitHash(de_ctx);
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
    SCSigSignatureOrderingModuleCleanup(de_ctx);
    DetectPortSpHashFree(de_ctx);
    DetectPortDpHashFree(de_ctx);

    VariableNameFreeHash(de_ctx);
    free(de_ctx);
}

/*
 * getting & (re)setting the internal sig i
 */

uint32_t DetectEngineGetMaxSigId(DetectEngineCtx *de_ctx) {
    return de_ctx->signum;
}

void DetectEngineResetMaxSigId(DetectEngineCtx *de_ctx) {
    de_ctx->signum = 0;
}

int DetectEngineThreadCtxInit(ThreadVars *tv, void *initdata, void **data) {
    DetectEngineCtx *de_ctx = (DetectEngineCtx *)initdata;
    if (de_ctx == NULL)
        return -1;

    DetectEngineThreadCtx *det_ctx = malloc(sizeof(DetectEngineThreadCtx));
    if (det_ctx == NULL) {
        return -1;
    }
    memset(det_ctx, 0, sizeof(DetectEngineThreadCtx));

    det_ctx->de_ctx = de_ctx;

    /** \todo we still depend on the global mpm_ctx here
     *
     * Initialize the thread pattern match ctx with the max size
     * of the content and uricontent id's so our match lookup
     * table is always big enough
     */
    mpm_ctx[0].InitThreadCtx(&mpm_ctx[0], &det_ctx->mtc, DetectContentMaxId(de_ctx));
    mpm_ctx[0].InitThreadCtx(&mpm_ctx[0], &det_ctx->mtcu, DetectUricontentMaxId(de_ctx));

    PmqSetup(&det_ctx->pmq, DetectEngineGetMaxSigId(de_ctx));

    /* IP-ONLY */
    DetectEngineIPOnlyThreadInit(de_ctx,&det_ctx->io_ctx);

    /** alert counter setup */
    det_ctx->counter_alerts = PerfTVRegisterCounter("detect.alert", tv, TYPE_UINT64, "NULL");
    tv->pca = PerfGetAllCountersArray(&tv->pctx);
    PerfAddToClubbedTMTable(tv->name, &tv->pctx);

    *data = (void *)det_ctx;
    //printf("DetectEngineThreadCtxInit: data %p det_ctx %p\n", *data, det_ctx);
    return 0;
}

int DetectEngineThreadCtxDeinit(ThreadVars *tv, void *data) {
    DetectEngineThreadCtx *det_ctx = (DetectEngineThreadCtx *)data;

    /** \todo get rid of this static */
    mpm_ctx[0].DestroyThreadCtx(&mpm_ctx[0], &det_ctx->mtc);
    mpm_ctx[0].DestroyThreadCtx(&mpm_ctx[0], &det_ctx->mtcu);

    return 0;
}

void DetectEngineThreadCtxInfo(ThreadVars *t, DetectEngineThreadCtx *det_ctx) {
    /* XXX */
    mpm_ctx[0].PrintThreadCtx(&det_ctx->mtc);
    mpm_ctx[0].PrintThreadCtx(&det_ctx->mtcu);
}

