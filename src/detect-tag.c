/* TAG part of the detection engine. */

#include "suricata-common.h"
#include "detect.h"

int DetectTagSetup (DetectEngineCtx *, Signature *s, SigMatch *m, char *str);

void DetectTagRegister (void) {
    sigmatch_table[DETECT_TAG].name = "tag";
    sigmatch_table[DETECT_TAG].Match = NULL;
    sigmatch_table[DETECT_TAG].Setup = DetectTagSetup;
    sigmatch_table[DETECT_TAG].Free  = NULL;
    sigmatch_table[DETECT_TAG].RegisterTests = NULL;
}

int DetectTagSetup (DetectEngineCtx *de_ctx, Signature *s, SigMatch *m, char *rawstr)
{
    return 0;
}

