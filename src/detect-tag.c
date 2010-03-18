/* TAG part of the detection engine. */

#include "suricata-common.h"
#include "detect.h"

static int DetectTagSetup(DetectEngineCtx *, Signature *, char *);

void DetectTagRegister (void) {
    sigmatch_table[DETECT_TAG].name = "tag";
    sigmatch_table[DETECT_TAG].Match = NULL;
    sigmatch_table[DETECT_TAG].Setup = DetectTagSetup;
    sigmatch_table[DETECT_TAG].Free  = NULL;
    sigmatch_table[DETECT_TAG].RegisterTests = NULL;
}

static int DetectTagSetup (DetectEngineCtx *de_ctx, Signature *s, char *rawstr)
{
    return 0;
}

