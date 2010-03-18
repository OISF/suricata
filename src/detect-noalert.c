/* NOALERT part of the detection engine. */

#include "suricata-common.h"
#include "detect.h"
#include "util-debug.h"

static int DetectNoalertSetup (DetectEngineCtx *, Signature *, char *);

void DetectNoalertRegister (void) {
    sigmatch_table[DETECT_NOALERT].name = "noalert";
    sigmatch_table[DETECT_NOALERT].Match = NULL;
    sigmatch_table[DETECT_NOALERT].Setup = DetectNoalertSetup;
    sigmatch_table[DETECT_NOALERT].Free  = NULL;
    sigmatch_table[DETECT_NOALERT].RegisterTests = NULL;

    sigmatch_table[DETECT_NOALERT].flags |= SIGMATCH_NOOPT;
}

static int DetectNoalertSetup (DetectEngineCtx *de_ctx, Signature *s, char *nullstr)
{
    if (nullstr != NULL) {
        SCLogError(SC_ERR_INVALID_VALUE, "nocase has no value");
        return -1;
    }

    s->flags |= SIG_FLAG_NOALERT;
    return 0;
}

