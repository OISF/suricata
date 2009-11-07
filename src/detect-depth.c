/* DEPTH part of the detection engine. */

#include "eidps-common.h"
#include "decode.h"
#include "detect.h"
#include "flow-var.h"
#include "detect-content.h"
#include "detect-pcre.h"

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

    SigMatch *pm = m;
    if (pm != NULL) {
        if (pm->type == DETECT_PCRE) {
            DetectPcreData *pe = (DetectPcreData *)pm->ctx;
            pe->depth = (uint32_t)atoi(str);
            //printf("DetectDepthSetup: set depth %" PRIu32 " for previous pcre\n", pe->depth);

        } else if (pm->type == DETECT_CONTENT) {
            /** Search for the first previous DetectContent
              * SigMatch (it can be the same as this one) */
            pm = DetectContentFindPrevApplicableSM(m);
            if (pm == NULL) {
                printf("DetectDepthSetup: Unknown previous keyword!\n");
                return -1;
            }

            DetectContentData *cd = (DetectContentData *)pm->ctx;
            if (cd == NULL) {
                printf("DetectDepthSetup: Unknown previous keyword!\n");
                return -1;
            }

            cd->depth = (uint32_t)atoi(str);

            /** Propagate the modifiers through the first chunk
              * (SigMatch) if we're dealing with chunks */
            if (cd->flags & DETECT_CONTENT_IS_CHUNK)
                DetectContentPropagateDepth(pm);

            //DetectContentPrint(cd);
            //printf("DetectDepthSetup: set depth %" PRIu32 " for previous content\n", cd->depth);

        } else {
            printf("DetectDepthSetup: Unknown previous keyword!\n");
        }
    } else {
        printf("DetectDepthSetup: No previous match!\n");
    }

    if (dubbed) free(str);
    return 0;
}

