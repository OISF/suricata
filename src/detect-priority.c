/* PRIORITY part of the detection engine. */

#include "decode.h"
#include "detect.h"
#include "flow-var.h"

int DetectPrioritySetup (DetectEngineCtx *, Signature *s, SigMatch *m, char *sidstr);

void DetectPriorityRegister (void) {
    sigmatch_table[DETECT_PRIORITY].name = "priority";
    sigmatch_table[DETECT_PRIORITY].Match = NULL;
    sigmatch_table[DETECT_PRIORITY].Setup = DetectPrioritySetup;
    sigmatch_table[DETECT_PRIORITY].Free = NULL;
    sigmatch_table[DETECT_PRIORITY].RegisterTests = NULL;
}

int DetectPrioritySetup (DetectEngineCtx *de_ctx, Signature *s, SigMatch *m, char *rawstr)
{
    char *str = rawstr;
    char dubbed = 0;

    /* strip "'s */
    if (rawstr[0] == '\"' && rawstr[strlen(rawstr)-1] == '\"') {
        str = strdup(rawstr+1);
        str[strlen(rawstr)-2] = '\0';
        dubbed = 1;
    }

    s->prio = (u_int32_t)atoi(str);

    if (dubbed) free(str);
    return 0;
}

