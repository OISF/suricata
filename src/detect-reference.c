/* REFERENCE part of the detection engine. */

#include "suricata-common.h"
#include "detect.h"

int DetectReferenceSetup (DetectEngineCtx *, Signature *s, SigMatch *m, char *str);

void DetectReferenceRegister (void) {
    sigmatch_table[DETECT_REFERENCE].name = "reference";
    sigmatch_table[DETECT_REFERENCE].Match = NULL;
    sigmatch_table[DETECT_REFERENCE].Setup = DetectReferenceSetup;
    sigmatch_table[DETECT_REFERENCE].Free  = NULL;
    sigmatch_table[DETECT_REFERENCE].RegisterTests = NULL;
}

int DetectReferenceSetup (DetectEngineCtx *de_ctx, Signature *s, SigMatch *m, char *rawstr)
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

