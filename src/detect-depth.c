/* DEPTH part of the detection engine. */

#include "suricata-common.h"
#include "decode.h"
#include "detect.h"
#include "flow-var.h"
#include "detect-content.h"
#include "detect-pcre.h"
#include "util-debug.h"

static int DetectDepthSetup (DetectEngineCtx *, Signature *, char *);

void DetectDepthRegister (void) {
    sigmatch_table[DETECT_DEPTH].name = "depth";
    sigmatch_table[DETECT_DEPTH].Match = NULL;
    sigmatch_table[DETECT_DEPTH].Setup = DetectDepthSetup;
    sigmatch_table[DETECT_DEPTH].Free  = NULL;
    sigmatch_table[DETECT_DEPTH].RegisterTests = NULL;

    sigmatch_table[DETECT_DEPTH].flags |= SIGMATCH_PAYLOAD;
}

static int DetectDepthSetup (DetectEngineCtx *de_ctx, Signature *s, char *depthstr)
{
    char *str = depthstr;
    char dubbed = 0;

    /* strip "'s */
    if (depthstr[0] == '\"' && depthstr[strlen(depthstr)-1] == '\"') {
        str = SCStrdup(depthstr+1);
        str[strlen(depthstr)-2] = '\0';
        dubbed = 1;
    }

    /** Search for the first previous DetectContent
     * SigMatch (it can be the same as this one) */
    SigMatch *pm = DetectContentFindPrevApplicableSM(s->pmatch_tail);
    if (pm == NULL) {
        SCLogError(SC_ERR_DEPTH_MISSING_CONTENT, "depth needs a preceeding content option");
        if (dubbed) SCFree(str);
        return -1;
    }

    DetectContentData *cd = (DetectContentData *)pm->ctx;
    if (cd == NULL) {
        SCLogError(SC_ERR_INVALID_ARGUMENT, "invalid argument");
        if (dubbed) SCFree(str);
        return -1;
    }

    cd->depth = (uint32_t)atoi(str);
    if (cd->content_len + cd->offset > cd->depth) {
        SCLogDebug("depth increased to %"PRIu32" to match pattern len and offset", cd->content_len + cd->offset);
        cd->depth = cd->content_len + cd->offset;
    }

    if (dubbed) SCFree(str);
    return 0;
}

