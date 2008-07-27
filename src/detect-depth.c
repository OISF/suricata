/* DEPTH part of the detection engine. */

#include "decode.h"
#include "detect.h"
#include "flow-var.h"

#include <pcre.h>
#include "detect-content.h"
#include "detect-pcre.h"

int DetectDepthSetup (Signature *s, SigMatch *m, char *depthstr);

void DetectDepthRegister (void) {
    sigmatch_table[DETECT_DEPTH].name = "depth";
    sigmatch_table[DETECT_DEPTH].Match = NULL;
    sigmatch_table[DETECT_DEPTH].Setup = DetectDepthSetup;
    sigmatch_table[DETECT_DEPTH].Free  = NULL;
    sigmatch_table[DETECT_DEPTH].RegisterTests = NULL;
}

int DetectDepthSetup (Signature *s, SigMatch *m, char *depthstr)
{
    char *str = depthstr;
    char dubbed = 0;

    //printf("DetectDepthSetup: s->match:%p,m:%p,depthstr:\'%s\'\n", s->match, m, depthstr);

    /* strip "'s */
    if (depthstr[0] == '\"' && depthstr[strlen(depthstr)-1] == '\"') {
        str = strdup(depthstr+1);
        str[strlen(depthstr)-2] = '\0';
        dubbed = 1;
    }

    SigMatch *pm = m;
    if (pm != NULL) {
        if (pm->type == DETECT_PCRE) {
            DetectPcreData *pe = (DetectPcreData *)pm->ctx;
            pe->depth = (u_int32_t)atoi(str);
            //printf("DetectDepthSetup: set depth %u for previous pcre\n", pe->depth);
        } else if (pm->type == DETECT_CONTENT) {
            DetectContentData *cd = (DetectContentData *)pm->ctx;
            cd->depth = (u_int32_t)atoi(str);
            //printf("DetectDepthSetup: set depth %u for previous content\n", cd->depth);
        } else {
            printf("DetectDepthSetup: Unknown previous keyword!\n");
        }
    } else {
        printf("DetectDepthSetup: No previous match!\n");
    }

    if (dubbed) free(str);
    return 0;
}

