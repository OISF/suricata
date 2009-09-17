/* OFFSET part of the detection engine. */

#include "eidps-common.h"

#include "decode.h"
#include "detect.h"
#include "flow-var.h"

#include "detect-content.h"
#include "detect-pcre.h"

int DetectOffsetSetup (DetectEngineCtx *, Signature *s, SigMatch *m, char *offsetstr);

void DetectOffsetRegister (void) {
    sigmatch_table[DETECT_OFFSET].name = "offset";
    sigmatch_table[DETECT_OFFSET].Match = NULL;
    sigmatch_table[DETECT_OFFSET].Setup = DetectOffsetSetup;
    sigmatch_table[DETECT_OFFSET].Free  = NULL;
    sigmatch_table[DETECT_OFFSET].RegisterTests = NULL;
}

int DetectOffsetSetup (DetectEngineCtx *de_ctx, Signature *s, SigMatch *m, char *offsetstr)
{
    char *str = offsetstr;
    char dubbed = 0;

    //printf("DetectOffsetSetup: s->match:%p,m:%p,offsetstr:\'%s\'\n", s->match, m, offsetstr);

    /* strip "'s */
    if (offsetstr[0] == '\"' && offsetstr[strlen(offsetstr)-1] == '\"') {
        str = strdup(offsetstr+1);
        str[strlen(offsetstr)-2] = '\0';
        dubbed = 1;
    }

    SigMatch *pm = m;
    if (pm != NULL) {
        if (pm->type == DETECT_PCRE) {
            //DetectPcreData *pe = (DetectPcreData *)pm->ctx;
            //pe->offset = (uint32_t)atoi(str); /* XXX */
            //printf("DetectOffsetSetup: set offset %" PRIu32 " for previous pcre\n", pe->offset);
        } else if (pm->type == DETECT_CONTENT) {
            DetectContentData *cd = (DetectContentData *)pm->ctx;
            cd->offset = (uint32_t)atoi(str); /* XXX */
            //printf("DetectOffsetSetup: set offset %" PRIu32 " for previous content\n", cd->offset);
        } else {
            printf("DetectOffsetSetup: Unknown previous keyword!\n");
        }
    } else {
        printf("DetectOffsetSetup: No previous match!\n");
    }

    if (dubbed) free(str);
    return 0;
}

