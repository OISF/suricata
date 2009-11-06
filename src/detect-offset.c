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

    sigmatch_table[DETECT_OFFSET].flags |= SIGMATCH_PAYLOAD;
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
            /** Search for the first previous DetectContent
              * SigMatch (it can be the same as this one) */
            pm = DetectContentFindApplicableSM(m);
            if (pm == NULL) {
                printf("DetectOffsetSetup: Unknown previous keyword!\n");
                return -1;
            }

            DetectContentData *cd = (DetectContentData *)pm->ctx;
            if (cd == NULL) {
                printf("DetectOffsetSetup: Unknown previous keyword!\n");
                return -1;
            }

            cd->offset = (uint32_t)atoi(str); /* XXX */

            /** Propagate the modifiers through the first chunk
              * (SigMatch) if we're dealing with chunks */
            if (cd->flags & DETECT_CONTENT_IS_CHUNK)
                DetectContentPropagateOffset(pm);

            //DetectContentPrint(cd);
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

