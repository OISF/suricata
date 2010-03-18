/* NOCASE part of the detection engine. */

#include "suricata-common.h"
#include "decode.h"
#include "detect.h"
#include "flow-var.h"

#include "detect-content.h"
#include "detect-uricontent.h"
#include "detect-pcre.h"

#include "util-debug.h"

static int DetectNocaseSetup (DetectEngineCtx *, Signature *, char *);

void DetectNocaseRegister (void) {
    sigmatch_table[DETECT_NOCASE].name = "nocase";
    sigmatch_table[DETECT_NOCASE].Match = NULL;
    sigmatch_table[DETECT_NOCASE].Setup = DetectNocaseSetup;
    sigmatch_table[DETECT_NOCASE].Free  = NULL;
    sigmatch_table[DETECT_NOCASE].RegisterTests = NULL;

    sigmatch_table[DETECT_NOCASE].flags |= SIGMATCH_NOOPT;
    sigmatch_table[DETECT_NOCASE].flags |= SIGMATCH_PAYLOAD;
}

/** \todo uricontent needs fixing */
static int DetectNocaseSetup (DetectEngineCtx *de_ctx, Signature *s, char *nullstr)
{
    int ret = 0;

    if (nullstr != NULL) {
        SCLogError(SC_ERR_INVALID_VALUE, "nocase has no value");
        return -1;
    }

    if (s->pmatch_tail == NULL)
        return -1;

    SigMatch *pm = DetectContentFindPrevApplicableSM(s->pmatch_tail);
    if (pm != NULL) {
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

