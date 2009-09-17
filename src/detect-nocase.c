/* NOCASE part of the detection engine. */

#include "eidps-common.h"
#include "decode.h"
#include "detect.h"
#include "flow-var.h"

#include "detect-content.h"
#include "detect-uricontent.h"
#include "detect-pcre.h"

int DetectNocaseSetup (DetectEngineCtx *, Signature *s, SigMatch *m, char *depthstr);

void DetectNocaseRegister (void) {
    sigmatch_table[DETECT_NOCASE].name = "nocase";
    sigmatch_table[DETECT_NOCASE].Match = NULL;
    sigmatch_table[DETECT_NOCASE].Setup = DetectNocaseSetup;
    sigmatch_table[DETECT_NOCASE].Free  = NULL;
    sigmatch_table[DETECT_NOCASE].RegisterTests = NULL;

    sigmatch_table[DETECT_NOCASE].flags |= SIGMATCH_NOOPT;
}

int DetectNocaseSetup (DetectEngineCtx *de_ctx, Signature *s, SigMatch *m, char *nullstr)
{
    //printf("DetectNocaseSetup: s->match:%p,m:%p\n", s->match, m);

    if (nullstr != NULL) {
        printf("DetectNocaseSetup: nocase has no value\n");
        return -1;
    }

    SigMatch *pm = m;
    if (pm != NULL) {
#if 0
        if (pm->type == DETECT_PCRE) {
            DetectPcreData *pe = (DetectPcreData *)pm->ctx;
            printf("DetectNocaseSetup: set depth %" PRIu32 " for previous pcre\n", pe->depth);
        } else 
#endif
        if (pm->type == DETECT_CONTENT) {
            DetectContentData *cd = (DetectContentData *)pm->ctx;
            //printf("DetectNocaseSetup: set nocase for previous content\n");
            cd->flags |= DETECT_CONTENT_NOCASE;
        } else if (pm->type == DETECT_URICONTENT) {
            DetectUricontentData *cd = (DetectUricontentData *)pm->ctx;
            //printf("DetectNocaseSetup: set nocase for previous content\n");
            cd->flags |= DETECT_URICONTENT_NOCASE;
        } else {
            printf("DetectNocaseSetup: Unknown previous keyword! (type %" PRIu32 ")\n", pm->type);
            return -1;
        }
    } else {
        printf("DetectNocaseSetup: No previous match! (pm == NULL)\n");
        return -1;
    }

    return 0;
}

