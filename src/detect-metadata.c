/* METADATA part of the detection engine. */

#include "suricata-common.h"
#include "detect.h"

int DetectMetadataSetup (DetectEngineCtx *, Signature *s, SigMatch *m, char *str);

void DetectMetadataRegister (void) {
    sigmatch_table[DETECT_METADATA].name = "metadata";
    sigmatch_table[DETECT_METADATA].Match = NULL;
    sigmatch_table[DETECT_METADATA].Setup = DetectMetadataSetup;
    sigmatch_table[DETECT_METADATA].Free  = NULL;
    sigmatch_table[DETECT_METADATA].RegisterTests = NULL;
}

int DetectMetadataSetup (DetectEngineCtx *de_ctx, Signature *s, SigMatch *m, char *rawstr)
{
    char *str = rawstr;
    char dubbed = 0;

    /* strip "'s */
    if (rawstr[0] == '\"' && rawstr[strlen(rawstr)-1] == '\"') {
        str = strdup(rawstr+1);
        str[strlen(rawstr)-2] = '\0';
        dubbed = 1;
    }

    /* XXX */

    if (dubbed) free(str);
    return 0;
}

