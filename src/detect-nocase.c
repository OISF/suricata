/* NOCASE part of the detection engine. */

#include "suricata-common.h"
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
    sigmatch_table[DETECT_NOCASE].flags |= SIGMATCH_PAYLOAD;
}

int DetectNocaseSetup (DetectEngineCtx *de_ctx, Signature *s, SigMatch *m, char *nullstr)
{
    int ret = 0;

    if (nullstr != NULL) {
        printf("DetectNocaseSetup: nocase has no value\n");
        return -1;
    }

    SigMatch *pm = m;
    for (; pm != NULL; pm = pm->prev) {
        if (pm->type == DETECT_CONTENT) {
            DetectContentData *cd = (DetectContentData *)pm->ctx;
            //printf("DetectNocaseSetup: set nocase for previous content\n");
            cd->flags |= DETECT_CONTENT_NOCASE;
            goto end;
        } else if (pm->type == DETECT_URICONTENT) {
            DetectUricontentData *cd = (DetectUricontentData *)pm->ctx;
            //printf("DetectNocaseSetup: set nocase for previous content\n");
            cd->flags |= DETECT_URICONTENT_NOCASE;
            goto end;
        }
    }

    ret = -1;
end:
    return ret;
}

