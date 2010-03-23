/* WITHIN part of the detection engine. */

/** \file
 *  \author Victor Julien <victor@inliniac.net>
 */

#include "suricata-common.h"
#include "decode.h"
#include "detect.h"
#include "flow-var.h"
#include "detect-content.h"
#include "detect-uricontent.h"
#include "detect-pcre.h"
#include "util-debug.h"

static int DetectWithinSetup (DetectEngineCtx *, Signature *, char *);

void DetectWithinRegister (void) {
    sigmatch_table[DETECT_WITHIN].name = "within";
    sigmatch_table[DETECT_WITHIN].Match = NULL;
    sigmatch_table[DETECT_WITHIN].Setup = DetectWithinSetup;
    sigmatch_table[DETECT_WITHIN].Free  = NULL;
    sigmatch_table[DETECT_WITHIN].RegisterTests = NULL;

    sigmatch_table[DETECT_WITHIN].flags |= SIGMATCH_PAYLOAD;
}

static int DetectWithinSetup (DetectEngineCtx *de_ctx, Signature *s, char *withinstr)
{
    char *str = withinstr;
    char dubbed = 0;

    /* strip "'s */
    if (withinstr[0] == '\"' && withinstr[strlen(withinstr)-1] == '\"') {
        str = SCStrdup(withinstr+1);
        str[strlen(withinstr)-2] = '\0';
        dubbed = 1;
    }

    if (s->pmatch == NULL) {
        SCLogError(SC_ERR_WITHIN_MISSING_CONTENT, "within needs two preceeding content options");
        goto error;
    }

    /** Search for the first previous DetectContent
     * SigMatch (it can be the same as this one) */
    SigMatch *pm = DetectContentFindPrevApplicableSM(s->pmatch_tail);
    if (pm == NULL || DetectContentHasPrevSMPattern(pm) == NULL) {
        SCLogError(SC_ERR_WITHIN_MISSING_CONTENT, "within needs two preceeding content options");
        goto error;
    }

    DetectContentData *cd = (DetectContentData *)pm->ctx;
    if (cd == NULL) {
        printf("DetectWithinSetup: Unknown previous keyword!\n");
        goto error;
    }

    cd->within = strtol(str, NULL, 10);
    cd->flags |= DETECT_CONTENT_WITHIN;

    if (cd->flags & DETECT_CONTENT_DISTANCE) {
        if (cd->distance > (cd->content_len + cd->within)) {
            cd->within = cd->distance + cd->content_len;
        }
    }

    pm = DetectContentFindPrevApplicableSM(s->pmatch_tail->prev);
    if (pm == NULL) {
        SCLogError(SC_ERR_WITHIN_MISSING_CONTENT, "within needs two preceeding content options");
        goto error;
    }

    /* Set the relative next flag on the prev sigmatch */
    if (pm->type == DETECT_CONTENT) {
        DetectContentData *cd = (DetectContentData *)pm->ctx;
        cd->flags |= DETECT_CONTENT_RELATIVE_NEXT;
    } else {
        printf("DetectWithinSetup: Unknown previous-previous keyword!\n");
        goto error;
    }

    if (dubbed) SCFree(str);
    return 0;
error:
    if (dubbed) SCFree(str);
    return -1;
}

