/* DISTANCE part of the detection engine. */

#include "suricata-common.h"
#include "decode.h"
#include "detect.h"
#include "flow-var.h"
#include "detect-content.h"
#include "detect-uricontent.h"
#include "detect-pcre.h"
#include "util-debug.h"

static int DetectDistanceSetup(DetectEngineCtx *, Signature *, char *);

void DetectDistanceRegister (void) {
    sigmatch_table[DETECT_DISTANCE].name = "distance";
    sigmatch_table[DETECT_DISTANCE].Match = NULL;
    sigmatch_table[DETECT_DISTANCE].Setup = DetectDistanceSetup;
    sigmatch_table[DETECT_DISTANCE].Free  = NULL;
    sigmatch_table[DETECT_DISTANCE].RegisterTests = NULL;

    sigmatch_table[DETECT_DISTANCE].flags |= SIGMATCH_PAYLOAD;
}

static int DetectDistanceSetup (DetectEngineCtx *de_ctx, Signature *s, char *distancestr)
{
    char *str = distancestr;
    char dubbed = 0;

    /* strip "'s */
    if (distancestr[0] == '\"' && distancestr[strlen(distancestr)-1] == '\"') {
        str = SCStrdup(distancestr+1);
        str[strlen(distancestr)-2] = '\0';
        dubbed = 1;
    }

    if (s->pmatch == NULL) {
        SCLogError(SC_ERR_DISTANCE_MISSING_CONTENT, "distance needs two preceeding content options");
        goto error;
    }

    /** Search for the first previous DetectContent
     * SigMatch (it can be the same as this one) */
    SigMatch *pm = DetectContentFindPrevApplicableSM(s->pmatch_tail);
    if (pm == NULL) {
        SCLogError(SC_ERR_DISTANCE_MISSING_CONTENT, "distance needs two preceeding content options");
        if (dubbed) SCFree(str);
        return -1;
    }
    if (DetectContentHasPrevSMPattern(pm) == NULL) {
        SCLogError(SC_ERR_DISTANCE_MISSING_CONTENT, "distance needs two preceeding content options");
        if (dubbed) SCFree(str);
        return -1;
    }

    DetectContentData *cd = (DetectContentData *)pm->ctx;
    if (cd == NULL) {
        SCLogError(SC_ERR_RULE_KEYWORD_UNKNOWN, "Unknown previous keyword!");
        if (dubbed) SCFree(str);
        return -1;
    }

    cd->distance = strtol(str, NULL, 10);
    cd->flags |= DETECT_CONTENT_DISTANCE;

    if (cd->flags & DETECT_CONTENT_WITHIN) {
        if (cd->distance + cd->content_len > cd->within) {
            cd->within = cd->distance + cd->content_len;
        }
    }

    /** Propagate the modifiers through the first chunk
     * (SigMatch) if we're dealing with chunks */
    if (cd->flags & DETECT_CONTENT_IS_CHUNK)
        DetectContentPropagateDistance(pm);

    //DetectContentPrint(cd);
    //printf("DetectDistanceSetup: set distance %" PRId32 " for previous content\n", cd->distance);

    pm = DetectContentFindPrevApplicableSM(s->pmatch_tail->prev);
    if (pm == NULL) {
        SCLogError(SC_ERR_DISTANCE_MISSING_CONTENT, "distance needs two preceeding content options");
        goto error;
    }

    if (pm->type == DETECT_PCRE) {
        DetectPcreData *pe = (DetectPcreData *)pm->ctx;
        pe->flags |= DETECT_PCRE_DISTANCE_NEXT;
    } else if (pm->type == DETECT_CONTENT) {
        DetectContentData *cd = (DetectContentData *)pm->ctx;
        cd->flags |= DETECT_CONTENT_DISTANCE_NEXT;
    } else if (pm->type == DETECT_URICONTENT) {
        DetectUricontentData *cd = (DetectUricontentData *)pm->ctx;
        cd->flags |= DETECT_URICONTENT_DISTANCE_NEXT;
    } else {
        SCLogError(SC_ERR_RULE_KEYWORD_UNKNOWN, "Unknown previous-previous keyword!");
        goto error;
    }

    if (dubbed) SCFree(str);
    return 0;
error:
    if (dubbed) SCFree(str);
    return -1;
}

