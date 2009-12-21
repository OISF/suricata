/* THRESHOLD part of the detection engine. */

#include "suricata-common.h"
#include "detect.h"

int DetectThresholdSetup (DetectEngineCtx *, Signature *s, SigMatch *m, char *str);

void DetectThresholdRegister (void) {
    sigmatch_table[DETECT_THRESHOLD].name = "threshold";
    sigmatch_table[DETECT_THRESHOLD].Match = NULL;
    sigmatch_table[DETECT_THRESHOLD].Setup = DetectThresholdSetup;
    sigmatch_table[DETECT_THRESHOLD].Free  = NULL;
    sigmatch_table[DETECT_THRESHOLD].RegisterTests  = NULL;
}

int DetectThresholdSetup (DetectEngineCtx *de_ctx, Signature *s, SigMatch *m, char *rawstr)
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

