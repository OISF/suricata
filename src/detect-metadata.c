/* METADATA part of the detection engine. */

#include "suricata-common.h"
#include "detect.h"

static int DetectMetadataSetup (DetectEngineCtx *, Signature *, char *);

void DetectMetadataRegister (void) {
    sigmatch_table[DETECT_METADATA].name = "metadata";
    sigmatch_table[DETECT_METADATA].Match = NULL;
    sigmatch_table[DETECT_METADATA].Setup = DetectMetadataSetup;
    sigmatch_table[DETECT_METADATA].Free  = NULL;
    sigmatch_table[DETECT_METADATA].RegisterTests = NULL;
}

static int DetectMetadataSetup (DetectEngineCtx *de_ctx, Signature *s, char *rawstr)
{
    return 0;
}

