/* WITHIN part of the detection engine. */

/** \file
 *  \author Victor Julien <victor@inliniac.net>
 *  \todo within logic is not Snort compat atm: it is applied to pcre and uricontent as well */

#include "eidps-common.h"
#include "decode.h"
#include "detect.h"
#include "flow-var.h"
#include "detect-content.h"
#include "detect-uricontent.h"
#include "detect-pcre.h"

int DetectWithinSetup (DetectEngineCtx *, Signature *s, SigMatch *m, char *withinstr);

void DetectWithinRegister (void) {
    sigmatch_table[DETECT_WITHIN].name = "within";
    sigmatch_table[DETECT_WITHIN].Match = NULL;
    sigmatch_table[DETECT_WITHIN].Setup = DetectWithinSetup;
    sigmatch_table[DETECT_WITHIN].Free  = NULL;
    sigmatch_table[DETECT_WITHIN].RegisterTests = NULL;

    sigmatch_table[DETECT_WITHIN].flags |= SIGMATCH_PAYLOAD;
}

int DetectWithinSetup (DetectEngineCtx *de_ctx, Signature *s, SigMatch *m, char *withinstr)
{
    char *str = withinstr;
    char dubbed = 0;

    //printf("DetectWithinSetup: s->match:%p,m:%p,withinstr:\'%s\'\n", s->match, m, withinstr);

    /* strip "'s */
    if (withinstr[0] == '\"' && withinstr[strlen(withinstr)-1] == '\"') {
        str = strdup(withinstr+1);
        str[strlen(withinstr)-2] = '\0';
        dubbed = 1;
    }

    SigMatch *pm = m;
    if (pm == NULL) {
        printf("DetectWithinSetup: No previous match!\n");
        goto error;
    }

    /* Set the within flag on the Sigmatch */
    if (pm->type == DETECT_PCRE) {
        DetectPcreData *pe = (DetectPcreData *)pm->ctx;

        pe->within = strtol(str, NULL, 10);
        pe->flags |= DETECT_PCRE_WITHIN;
        //printf("DetectWithinSetup: set within %" PRId32 " for previous pcre\n", pe->within);

    } else if (pm->type == DETECT_CONTENT) {
        /** Search for the first previous DetectContent
          * SigMatch (it can be the same as this one) */
        pm = DetectContentFindApplicableSM(m);
        if (pm == NULL) {
            printf("DetectWithinSetup: Unknown previous keyword!\n");
            return -1;
        }

        DetectContentData *cd = (DetectContentData *)pm->ctx;
        if (cd == NULL) {
            printf("DetectWithinSetup: Unknown previous keyword!\n");
            return -1;
        }

        cd->within = strtol(str, NULL, 10);
        cd->flags |= DETECT_CONTENT_WITHIN;

        /** Propagate the modifiers through the first chunk
          * (SigMatch) if we're dealing with chunks */
        if (cd->flags & DETECT_CONTENT_IS_CHUNK)
            DetectContentPropagateWithin(pm);

        //DetectContentPrint(cd);
        //printf("DetectWithinSetup: set within %" PRId32 " for previous content\n", cd->within);
    } else if (pm->type == DETECT_URICONTENT) {
        DetectUricontentData *ud = (DetectUricontentData *)pm->ctx;

        ud->within = strtol(str, NULL, 10);
        ud->flags |= DETECT_URICONTENT_WITHIN;

        //printf("DetectWithinSetup: set within %" PRId32 " for previous content\n", cd->within);
    } else {
        printf("DetectWithinSetup: Unknown previous keyword!\n");
        goto error;
    }

    pm = m->prev;
    if (pm == NULL) {
        printf("DetectWithinSetup: No previous-previous match!\n");
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

    if (dubbed) free(str);
    return 0;
error:
    if (dubbed) free(str);
    return -1;
}

