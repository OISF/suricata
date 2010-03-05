/* RAWBYTES part of the detection engine. */

#include "suricata-common.h"

#include "decode.h"
#include "detect.h"
#include "flow-var.h"

#include "detect-content.h"
#include "detect-pcre.h"

#include "util-debug.h"

int DetectRawbytesSetup (DetectEngineCtx *, Signature *, SigMatch *, char *);

void DetectRawbytesRegister (void) {
    sigmatch_table[DETECT_RAWBYTES].name = "rawbytes";
    sigmatch_table[DETECT_RAWBYTES].Match = NULL;
    sigmatch_table[DETECT_RAWBYTES].Setup = DetectRawbytesSetup;
    sigmatch_table[DETECT_RAWBYTES].Free  = NULL;
    sigmatch_table[DETECT_RAWBYTES].RegisterTests = NULL;

    sigmatch_table[DETECT_RAWBYTES].flags |= SIGMATCH_NOOPT;
    sigmatch_table[DETECT_RAWBYTES].flags |= SIGMATCH_PAYLOAD;
}

int DetectRawbytesSetup (DetectEngineCtx *de_ctx, Signature *s, SigMatch *m, char *nullstr)
{
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
            cd->flags |= DETECT_CONTENT_RAWBYTES;
        }
    }

    return 0;
}

