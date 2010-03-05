/* WITHIN part of the detection engine. */

/** \file
 *  \author Victor Julien <victor@inliniac.net>
 *  \todo within logic is not Snort compat atm: it is applied to pcre and uricontent as well */

#include "suricata-common.h"
#include "decode.h"
#include "detect.h"
#include "flow-var.h"
#include "detect-content.h"
#include "detect-uricontent.h"
#include "detect-pcre.h"
#include "util-debug.h"

int DetectWithinSetup (DetectEngineCtx *, Signature *s, SigMatch *m, char *withinstr);

void DetectWithinRegister (void) {
    sigmatch_table[DETECT_WITHIN].name = "within";
    sigmatch_table[DETECT_WITHIN].Match = NULL;
    sigmatch_table[DETECT_WITHIN].Setup = DetectWithinSetup;
    sigmatch_table[DETECT_WITHIN].Free  = NULL;
    sigmatch_table[DETECT_WITHIN].RegisterTests = NULL;

    sigmatch_table[DETECT_WITHIN].flags |= SIGMATCH_PAYLOAD;
}

int DetectWithinSetup (DetectEngineCtx *de_ctx, Signature *s, SigMatch *notused, char *withinstr)
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

    /** Propagate the modifiers through the first chunk
     * (SigMatch) if we're dealing with chunks */
    if (cd->flags & DETECT_CONTENT_IS_CHUNK)
        DetectContentPropagateWithin(pm);

    //DetectContentPrint(cd);
    //printf("DetectWithinSetup: set within %" PRId32 " for previous content\n", cd->within);

    pm = DetectContentFindPrevApplicableSM(s->pmatch_tail->prev);
    if (pm == NULL) {
        SCLogError(SC_ERR_WITHIN_MISSING_CONTENT, "within needs two preceeding content options");
        goto error;
    }

    /* Set the within next flag on the prev sigmatch */
    if (pm->type == DETECT_PCRE) {
        DetectPcreData *pe = (DetectPcreData *)pm->ctx;
        pe->flags |= DETECT_PCRE_WITHIN_NEXT;
    } else if (pm->type == DETECT_CONTENT) {
        DetectContentData *cd = (DetectContentData *)pm->ctx;
        cd->flags |= DETECT_CONTENT_WITHIN_NEXT;
    } else if (pm->type == DETECT_URICONTENT) {
        DetectUricontentData *ud = (DetectUricontentData *)pm->ctx;
        ud->flags |= DETECT_URICONTENT_WITHIN_NEXT;
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

