/* DEPTH part of the detection engine. */

#include "suricata-common.h"

#include "decode.h"

#include "detect.h"
#include "detect-parse.h"
#include "detect-content.h"
#include "detect-uricontent.h"

#include "flow-var.h"

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

    /** Search for the first previous DetectContent or uricontent
     * SigMatch (it can be the same as this one) */
    SigMatch *pm = SigMatchGetLastPattern(s);
    if (pm == NULL) {
        SCLogError(SC_ERR_DEPTH_MISSING_CONTENT, "depth needs a preceeding content option");
        if (dubbed) SCFree(str);
        return -1;
    }

    DetectUricontentData *ud = NULL;
    DetectContentData *cd = NULL;
    switch (pm->type) {
        case DETECT_URICONTENT:
            ud = (DetectUricontentData *)pm->ctx;
            if (ud == NULL) {
                SCLogError(SC_ERR_INVALID_ARGUMENT, "invalid argpment");
                if (dubbed) SCFree(str);
                return -1;
            }
            ud->depth = (uint32_t)atoi(str);
            if (ud->uricontent_len + ud->offset > ud->depth) {
                SCLogDebug("depth increased to %"PRIu32" to match pattern len and offset", ud->uricontent_len + ud->offset);
                ud->depth = ud->uricontent_len + ud->offset;
            }
        break;

        case DETECT_CONTENT:
            cd = (DetectContentData *)pm->ctx;
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
        break;

        default:
            SCLogError(SC_ERR_DEPTH_MISSING_CONTENT, "depth needs a preceeding content (or uricontent) option");
            if (dubbed) SCFree(str);
                return -1;
        break;
    }

    if (dubbed) SCFree(str);
    return 0;
}

