/* REV part of the detection engine. */

#include "suricata-common.h"
#include "detect.h"
#include "util-debug.h"
#include "util-error.h"

static int DetectRevSetup (DetectEngineCtx *, Signature *, char *);

void DetectRevRegister (void) {
    sigmatch_table[DETECT_REV].name = "rev";
    sigmatch_table[DETECT_REV].Match = NULL;
    sigmatch_table[DETECT_REV].Setup = DetectRevSetup;
    sigmatch_table[DETECT_REV].Free  = NULL;
    sigmatch_table[DETECT_REV].RegisterTests = NULL;
}

static int DetectRevSetup (DetectEngineCtx *de_ctx, Signature *s, char *rawstr)
{
    char *str = rawstr;
    char dubbed = 0;

    /* strip "'s */
    if (rawstr[0] == '\"' && rawstr[strlen(rawstr)-1] == '\"') {
        str = SCStrdup(rawstr+1);
        str[strlen(rawstr)-2] = '\0';
        dubbed = 1;
    }

    s->rev = (uint8_t)atoi(str);

    if (dubbed) SCFree(str);
    return 0;
}

