/* OFFSET part of the detection engine. */

#include "suricata-common.h"

#include "decode.h"

#include "detect.h"
#include "detect-parse.h"
#include "detect-content.h"
#include "detect-uricontent.h"

#include "flow-var.h"

#include "util-debug.h"

static int DetectOffsetSetup (DetectEngineCtx *, Signature *, char *);

void DetectOffsetRegister (void) {
    sigmatch_table[DETECT_OFFSET].name = "offset";
    sigmatch_table[DETECT_OFFSET].Match = NULL;
    sigmatch_table[DETECT_OFFSET].Setup = DetectOffsetSetup;
    sigmatch_table[DETECT_OFFSET].Free  = NULL;
    sigmatch_table[DETECT_OFFSET].RegisterTests = NULL;

    sigmatch_table[DETECT_OFFSET].flags |= SIGMATCH_PAYLOAD;
}

int DetectOffsetSetup (DetectEngineCtx *de_ctx, Signature *s, char *offsetstr)
{
    char *str = offsetstr;
    char dubbed = 0;

    /* strip "'s */
    if (offsetstr[0] == '\"' && offsetstr[strlen(offsetstr)-1] == '\"') {
        str = SCStrdup(offsetstr+1);
        str[strlen(offsetstr)-2] = '\0';
        dubbed = 1;
    }

    /** Search for the first previous DetectContent or uricontent
     * SigMatch (it can be the same as this one) */
    SigMatch *pm = SigMatchGetLastPattern(s);
    if (pm == NULL) {
        SCLogError(SC_ERR_OFFSET_MISSING_CONTENT, "offset needs a preceeding content option");
        if (dubbed) SCFree(str);
        return -1;
    }

    DetectUricontentData *ud = NULL;
    DetectContentData *cd = NULL;
    switch (pm->type) {
        case DETECT_URICONTENT:
            ud = (DetectUricontentData *)pm->ctx;
            if (ud == NULL) {
                SCLogError(SC_ERR_INVALID_ARGUMENT, "invalid argpment");
                if (dubbed) SCFree(str);
                return -1;
            }
            ud->offset = (uint32_t)atoi(str);
            if (ud->depth != 0) {
                SCLogDebug("depth increased to %"PRIu32" to match pattern len and offset", ud->uricontent_len + ud->offset);
                ud->depth = ud->uricontent_len + ud->offset;
            }
        break;

        case DETECT_CONTENT:
            cd = (DetectContentData *)pm->ctx;
            if (cd == NULL) {
                SCLogError(SC_ERR_INVALID_ARGUMENT, "invalid argument");
                if (dubbed) SCFree(str);
                return -1;
            }
            cd->offset = (uint32_t)atoi(str);
            if (cd->depth != 0) {
                SCLogDebug("depth increased to %"PRIu32" to match pattern len and offset", cd->content_len + cd->offset);
                cd->depth = cd->content_len + cd->offset;
            }
        break;

        default:
            SCLogError(SC_ERR_OFFSET_MISSING_CONTENT, "offset needs a preceeding content (or uricontent) option");
            if (dubbed) SCFree(str);
                return -1;
        break;
    }

    if (dubbed) SCFree(str);
    return 0;
}

