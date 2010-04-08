/* DISTANCE part of the detection engine. */

#include "suricata-common.h"

#include "decode.h"

#include "detect.h"
#include "detect-parse.h"
#include "detect-content.h"
#include "detect-uricontent.h"

#include "flow-var.h"

#include "util-debug.h"

static int DetectDistanceSetup(DetectEngineCtx *, Signature *, char *);

void DetectDistanceRegister (void) {
    sigmatch_table[DETECT_DISTANCE].name = "distance";
    sigmatch_table[DETECT_DISTANCE].Match = NULL;
    sigmatch_table[DETECT_DISTANCE].Setup = DetectDistanceSetup;
    sigmatch_table[DETECT_DISTANCE].Free  = NULL;
    sigmatch_table[DETECT_DISTANCE].RegisterTests = NULL;

    sigmatch_table[DETECT_DISTANCE].flags |= SIGMATCH_PAYLOAD;
}

static int DetectDistanceSetup (DetectEngineCtx *de_ctx, Signature *s, char *distancestr)
{
    char *str = distancestr;
    char dubbed = 0;

    /* strip "'s */
    if (distancestr[0] == '\"' && distancestr[strlen(distancestr)-1] == '\"') {
        str = SCStrdup(distancestr+1);
        str[strlen(distancestr)-2] = '\0';
        dubbed = 1;
    }

    /** Search for the first previous DetectContent
     * SigMatch (it can be the same as this one) */
    SigMatch *pm = SigMatchGetLastPattern(s);
    if (pm == NULL) {
        SCLogError(SC_ERR_DISTANCE_MISSING_CONTENT, "depth needs two preceeding content (or uricontent) options");
        if (dubbed) SCFree(str);
        return -1;
    }

    DetectUricontentData *ud = NULL;
    DetectContentData *cd = NULL;

    switch (pm->type) {
        case DETECT_URICONTENT:
            ud = (DetectUricontentData *)pm->ctx;
            if (ud == NULL) {
                SCLogError(SC_ERR_DISTANCE_MISSING_CONTENT, "Unknown previous keyword!\n");
                goto error;
            }

            ud->distance = strtol(str, NULL, 10);
            ud->flags |= DETECT_URICONTENT_DISTANCE;
            if (ud->flags & DETECT_URICONTENT_WITHIN) {
                if (ud->distance + ud->uricontent_len > ud->within) {
                    ud->within = ud->distance + ud->uricontent_len;
                }
            }

            pm = DetectUricontentGetLastPattern(s->umatch_tail->prev);
            if (pm == NULL) {
                SCLogError(SC_ERR_DISTANCE_MISSING_CONTENT, "distance needs two preceeding content options");
                goto error;
            }

            if (pm->type == DETECT_URICONTENT) {
                ud = (DetectUricontentData *)pm->ctx;
                ud->flags |= DETECT_URICONTENT_RELATIVE_NEXT;
            } else {
                SCLogError(SC_ERR_RULE_KEYWORD_UNKNOWN, "Unknown previous-previous keyword!");
                goto error;
            }
        break;

        case DETECT_CONTENT:
            cd = (DetectContentData *)pm->ctx;
            if (cd == NULL) {
                SCLogError(SC_ERR_DISTANCE_MISSING_CONTENT, "Unknown previous keyword!\n");
                goto error;
            }

            cd->distance = strtol(str, NULL, 10);
            cd->flags |= DETECT_CONTENT_DISTANCE;
            if (cd->flags & DETECT_CONTENT_WITHIN) {
                if (cd->distance + cd->content_len > cd->within) {
                    cd->within = cd->distance + cd->content_len;
                }
            }

            pm = DetectContentGetLastPattern(s->pmatch_tail->prev);
            if (pm == NULL) {
                SCLogError(SC_ERR_DISTANCE_MISSING_CONTENT, "distance needs two preceeding content options");
                goto error;
            }

            if (pm->type == DETECT_CONTENT) {
                cd = (DetectContentData *)pm->ctx;
                cd->flags |= DETECT_CONTENT_RELATIVE_NEXT;
            } else {
                SCLogError(SC_ERR_RULE_KEYWORD_UNKNOWN, "Unknown previous-previous keyword!");
                goto error;
            }
        break;

        default:
            SCLogError(SC_ERR_DISTANCE_MISSING_CONTENT, "distance needs two preceeding content (or uricontent) options");
            if (dubbed) SCFree(str);
                return -1;
        break;
    }

    if (dubbed) SCFree(str);
    return 0;
error:
    if (dubbed) SCFree(str);
    return -1;
}

