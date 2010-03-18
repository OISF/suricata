/* SID part of the detection engine. */

#include "suricata-common.h"
#include "detect.h"
#include "util-debug.h"
#include "util-error.h"

static int DetectSidSetup (DetectEngineCtx *, Signature *, char *);

void DetectSidRegister (void) {
    sigmatch_table[DETECT_SID].name = "sid";
    sigmatch_table[DETECT_SID].Match = NULL;
    sigmatch_table[DETECT_SID].Setup = DetectSidSetup;
    sigmatch_table[DETECT_SID].Free = NULL;
    sigmatch_table[DETECT_SID].RegisterTests = NULL;
}

static int DetectSidSetup (DetectEngineCtx *de_ctx, Signature *s, char *sidstr)
{
    char *str = sidstr;
    char dubbed = 0;

    /* strip "'s */
    if (sidstr[0] == '\"' && sidstr[strlen(sidstr)-1] == '\"') {
        str = SCStrdup(sidstr+1);
        str[strlen(sidstr)-2] = '\0';
        dubbed = 1;
    }

    s->id = (uint32_t)atoi(str);

    if (dubbed) SCFree(str);
    return 0;
}

