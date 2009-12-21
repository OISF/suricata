/* RAWBYTES part of the detection engine. */

#include "suricata-common.h"

#include "decode.h"
#include "detect.h"
#include "flow-var.h"

#include "detect-content.h"
#include "detect-pcre.h"

int DetectRawbytesSetup (DetectEngineCtx *, Signature *, SigMatch *, char *);

void DetectRawbytesRegister (void) {
    sigmatch_table[DETECT_RAWBYTES].name = "rawbytes";
    sigmatch_table[DETECT_RAWBYTES].Match = NULL;
    sigmatch_table[DETECT_RAWBYTES].Setup = DetectRawbytesSetup;
    sigmatch_table[DETECT_RAWBYTES].Free  = NULL;
    sigmatch_table[DETECT_RAWBYTES].RegisterTests = NULL;

    sigmatch_table[DETECT_RAWBYTES].flags |= SIGMATCH_NOOPT;
    sigmatch_table[DETECT_RAWBYTES].flags |= SIGMATCH_PAYLOAD;
}

int DetectRawbytesSetup (DetectEngineCtx *de_ctx, Signature *s, SigMatch *m, char *nullstr)
{
    //printf("DetectRawbytesSetup: s->match:%p,m:%p\n", s->match, m);

    if (nullstr != NULL) {
        printf("DetectRawbytesSetup: nocase has no value\n");
        return -1;
    }

    SigMatch *pm = m;
    if (pm != NULL) {
#if 0
        if (pm->type == DETECT_PCRE) {
            DetectPcreData *pe = (DetectPcreData *)pm->ctx;
            printf("DetectRawbytesSetup: set depth %" PRIu32 " for previous pcre\n", pe->depth);
        } else 
#endif
        if (pm->type == DETECT_CONTENT) {
            DetectContentData *cd = (DetectContentData *)pm->ctx;
            //printf("DetectRawbytesSetup: set nocase for previous content\n");
            cd->flags |= DETECT_CONTENT_RAWBYTES;
        } else {
            printf("DetectRawbytesSetup: Unknown previous keyword!\n");
        }
    } else {
        printf("DetectRawbytesSetup: No previous match!\n");
    }

    return 0;
}

