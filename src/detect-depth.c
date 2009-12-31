/* DEPTH part of the detection engine. */

#include "suricata-common.h"
#include "decode.h"
#include "detect.h"
#include "flow-var.h"
#include "detect-content.h"
#include "detect-pcre.h"
#include "util-debug.h"

int DetectDepthSetup (DetectEngineCtx *, Signature *s, SigMatch *m, char *depthstr);

void DetectDepthRegister (void) {
    sigmatch_table[DETECT_DEPTH].name = "depth";
    sigmatch_table[DETECT_DEPTH].Match = NULL;
    sigmatch_table[DETECT_DEPTH].Setup = DetectDepthSetup;
    sigmatch_table[DETECT_DEPTH].Free  = NULL;
    sigmatch_table[DETECT_DEPTH].RegisterTests = NULL;

    sigmatch_table[DETECT_DEPTH].flags |= SIGMATCH_PAYLOAD;
}

int DetectDepthSetup (DetectEngineCtx *de_ctx, Signature *s, SigMatch *m, char *depthstr)
{
    char *str = depthstr;
    char dubbed = 0;

    //printf("DetectDepthSetup: s->match:%p,m:%p,depthstr:\'%s\'\n", s->match, m, depthstr);

    /* strip "'s */
    if (depthstr[0] == '\"' && depthstr[strlen(depthstr)-1] == '\"') {
        str = strdup(depthstr+1);
        str[strlen(depthstr)-2] = '\0';
        dubbed = 1;
    }

    /** Search for the first previous DetectContent
     * SigMatch (it can be the same as this one) */
    SigMatch *pm = DetectContentFindPrevApplicableSM(m);
    if (pm == NULL) {
        SCLogError(SC_ERR_DEPTH_MISSING_CONTENT, "depth needs a preceeding content option");
        return -1;
    }

    DetectContentData *cd = (DetectContentData *)pm->ctx;
    if (cd == NULL) {
        SCLogError(SC_INVALID_ARGUMENT, "invalid argument");
        return -1;
    }

    cd->depth = (uint32_t)atoi(str);
    if (cd->content_len + cd->offset > cd->depth) {
        SCLogDebug("depth increased to %"PRIu32" to match pattern len and offset", cd->content_len + cd->offset);
        cd->depth = cd->content_len + cd->offset;
    }

    /** Propagate the modifiers through the first chunk
     * (SigMatch) if we're dealing with chunks */
    if (cd->flags & DETECT_CONTENT_IS_CHUNK)
        DetectContentPropagateDepth(pm);

    //DetectContentPrint(cd);
    //printf("DetectDepthSetup: set depth %" PRIu32 " for previous content\n", cd->depth);

    if (dubbed) free(str);
    return 0;
}

