/* NOCASE part of the detection engine. */

#include "suricata-common.h"
#include "decode.h"

#include "detect.h"
#include "detect-parse.h"

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
    SCEnter();

    int ret = 0;

    if (nullstr != NULL) {
        SCLogError(SC_ERR_INVALID_VALUE, "nocase has no value");
        SCReturnInt(-1);
    }

    SigMatch *co_sm = DetectContentFindPrevApplicableSM(s->pmatch_tail);
    SigMatch *ur_sm = SigMatchGetLastSM(s->match, DETECT_URICONTENT);
    char uri = 0;

    if (co_sm != NULL && ur_sm != NULL) {
        BUG_ON(co_sm->idx == ur_sm->idx);

        if (co_sm->idx > ur_sm->idx)
            uri = 0;
        else
            uri = 1;
    } else if (co_sm != NULL) {
        uri = 0;
    } else if (ur_sm != NULL) {
        uri = 1;
    } else {
        SCReturnInt(-1);
    }

    if (uri == 0) {
        DetectContentData *cd = (DetectContentData *)co_sm->ctx;
        cd->flags |= DETECT_CONTENT_NOCASE;
        goto end;
    } else {
        DetectUricontentData *cd = (DetectUricontentData *)ur_sm->ctx;
        cd->flags |= DETECT_URICONTENT_NOCASE;
        goto end;
    }

    ret = -1;
end:
    SCReturnInt(ret);
}

