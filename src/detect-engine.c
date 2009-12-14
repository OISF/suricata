/* Copyright (C) 2008 by Victor Julien <victor@inliniac.net> */

#include "suricata-common.h"
#include "debug.h"
#include "detect.h"
#include "flow.h"
#include "conf.h"

#include "detect-parse.h"
#include "detect-engine-sigorder.h"

#include "detect-engine-siggroup.h"
#include "detect-engine-address.h"
#include "detect-engine-port.h"
#include "detect-engine-mpm.h"
#include "detect-engine-iponly.h"

#include "detect-engine.h"

#include "detect-content.h"
#include "detect-uricontent.h"
#include "detect-engine-threshold.h"

//#include "util-mpm.h"
#include "util-hash.h"
#include "util-debug.h"

#include "util-var-name.h"
#include "tm-modules.h"

DetectEngineCtx *DetectEngineCtxInit(void) {
    DetectEngineCtx *de_ctx;

    de_ctx = malloc(sizeof(DetectEngineCtx));
    if (de_ctx == NULL) {
        goto error;
    }

    memset(de_ctx,0,sizeof(DetectEngineCtx));

    if (ConfGetBool("engine.init_failure_fatal", (int *)&(de_ctx->failure_fatal)) != 1) {
        SCLogDebug("ConfGetBool could not load the value.");
    }

    de_ctx->mpm_matcher = PatternMatchDefaultMatcher();

    SigGroupHeadHashInit(de_ctx);
    SigGroupHeadMpmHashInit(de_ctx);
    SigGroupHeadMpmUriHashInit(de_ctx);
    SigGroupHeadSPortHashInit(de_ctx);
    SigGroupHeadDPortHashInit(de_ctx);
    DetectPortSpHashInit(de_ctx);
    DetectPortDpHashInit(de_ctx);
    ThresholdHashInit(de_ctx);
    VariableNameInitHash(de_ctx);
    return de_ctx;
error:
    return NULL;
}

void DetectEngineCtxFree(DetectEngineCtx *de_ctx) {

    if (de_ctx == NULL)
        return;

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
    ThresholdContextDestroy(de_ctx);
    SigCleanSignatures(de_ctx);

    VariableNameFreeHash(de_ctx);
    if (de_ctx->sig_array)
        free(de_ctx->sig_array);

    if (de_ctx->class_conf_ht != NULL)
        free(de_ctx->class_conf_ht);
    free(de_ctx);
    //DetectAddressGroupPrintMemory();
    //DetectSigGroupPrintMemory();
    //DetectPortPrintMemory();
}

/*
 * getting & (re)setting the internal sig i
 */

//inline uint32_t DetectEngineGetMaxSigId(DetectEngineCtx *de_ctx) {
//    return de_ctx->signum;
//}

void DetectEngineResetMaxSigId(DetectEngineCtx *de_ctx) {
    de_ctx->signum = 0;
}

TmEcode DetectEngineThreadCtxInit(ThreadVars *tv, void *initdata, void **data) {
    DetectEngineCtx *de_ctx = (DetectEngineCtx *)initdata;
    if (de_ctx == NULL)
        return TM_ECODE_FAILED;

    DetectEngineThreadCtx *det_ctx = malloc(sizeof(DetectEngineThreadCtx));
    if (det_ctx == NULL) {
        return TM_ECODE_FAILED;
    }
    memset(det_ctx, 0, sizeof(DetectEngineThreadCtx));

    det_ctx->de_ctx = de_ctx;

    /** \todo we still depend on the global mpm_ctx here
     *
     * Initialize the thread pattern match ctx with the max size
     * of the content and uricontent id's so our match lookup
     * table is always big enough
     */
    PatternMatchThreadPrepare(&det_ctx->mtc, de_ctx->mpm_matcher, DetectContentMaxId(de_ctx));
    PatternMatchThreadPrepare(&det_ctx->mtcu, de_ctx->mpm_matcher, DetectUricontentMaxId(de_ctx));

    PmqSetup(&det_ctx->pmq, DetectEngineGetMaxSigId(de_ctx));

    /* IP-ONLY */
    DetectEngineIPOnlyThreadInit(de_ctx,&det_ctx->io_ctx);

    /** alert counter setup */
    det_ctx->counter_alerts = SCPerfTVRegisterCounter("detect.alert", tv,
                                                      SC_PERF_TYPE_UINT64, "NULL");
    tv->sc_perf_pca = SCPerfGetAllCountersArray(&tv->sc_perf_pctx);
    SCPerfAddToClubbedTMTable(tv->name, &tv->sc_perf_pctx);

    *data = (void *)det_ctx;
    //printf("DetectEngineThreadCtxInit: data %p det_ctx %p\n", *data, det_ctx);
    return TM_ECODE_OK;
}

TmEcode DetectEngineThreadCtxDeinit(ThreadVars *tv, void *data) {
    DetectEngineThreadCtx *det_ctx = (DetectEngineThreadCtx *)data;

    DetectEngineIPOnlyThreadDeinit(&det_ctx->io_ctx);

    /** \todo get rid of this static */
    PatternMatchThreadDestroy(&det_ctx->mtc, det_ctx->de_ctx->mpm_matcher);
    PatternMatchThreadDestroy(&det_ctx->mtcu, det_ctx->de_ctx->mpm_matcher);

    free(det_ctx);

    return TM_ECODE_OK;
}

void DetectEngineThreadCtxInfo(ThreadVars *t, DetectEngineThreadCtx *det_ctx) {
    /* XXX */
    PatternMatchThreadPrint(&det_ctx->mtc, det_ctx->de_ctx->mpm_matcher);
    PatternMatchThreadPrint(&det_ctx->mtcu, det_ctx->de_ctx->mpm_matcher);
}

