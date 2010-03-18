/* RECURSIVE part of the detection engine.
 *
 * Used to capture variables recursively in a payload,
 * used for example to extract http_uri for uricontent.
 *
 * Note: non Snort compatible. */

#include "suricata-common.h"
#include "decode.h"
#include "detect.h"
#include "flow-var.h"

static int DetectRecursiveSetup (DetectEngineCtx *, Signature *, char *);

void DetectRecursiveRegister (void) {
    sigmatch_table[DETECT_RECURSIVE].name = "recursive";
    sigmatch_table[DETECT_RECURSIVE].Match = NULL;
    sigmatch_table[DETECT_RECURSIVE].Setup = DetectRecursiveSetup;
    sigmatch_table[DETECT_RECURSIVE].Free  = NULL;
    sigmatch_table[DETECT_RECURSIVE].RegisterTests = NULL;

    sigmatch_table[DETECT_RECURSIVE].flags |= SIGMATCH_NOOPT;
}

static int DetectRecursiveSetup (DetectEngineCtx *de_ctx, Signature *s, char *nullstr)
{
    if (nullstr != NULL) {
        printf("DetectRecursiveSetup: recursive has no value\n");
        return -1;
    }

    s->flags |= SIG_FLAG_RECURSIVE;
    return 0;
}

