/* WITHIN part of the detection engine. */

/** \file
 *  \author Victor Julien <victor@inliniac.net>
 */

#include "suricata-common.h"

#include "decode.h"

#include "detect.h"
#include "detect-parse.h"
#include "detect-content.h"
#include "detect-uricontent.h"

#include "flow-var.h"

#include "util-debug.h"

static int DetectWithinSetup (DetectEngineCtx *, Signature *, char *);

void DetectWithinRegister (void) {
    sigmatch_table[DETECT_WITHIN].name = "within";
    sigmatch_table[DETECT_WITHIN].Match = NULL;
    sigmatch_table[DETECT_WITHIN].Setup = DetectWithinSetup;
    sigmatch_table[DETECT_WITHIN].Free  = NULL;
    sigmatch_table[DETECT_WITHIN].RegisterTests = NULL;

    sigmatch_table[DETECT_WITHIN].flags |= SIGMATCH_PAYLOAD;
}

/** \brief Setup within pattern (content/uricontent) modifier.
 *
 *  \todo apply to uricontent
 *
 *  \retval 0 ok
 *  \retval -1 error, sig needs to be invalidated
 */
static int DetectWithinSetup (DetectEngineCtx *de_ctx, Signature *s, char *withinstr)
{
    char *str = withinstr;
    char dubbed = 0;

    /* strip "'s */
    if (withinstr[0] == '\"' && withinstr[strlen(withinstr)-1] == '\"') {
        str = SCStrdup(withinstr+1);
        str[strlen(withinstr)-2] = '\0';
        dubbed = 1;
    }

    /** Search for the first previous DetectContent
     * SigMatch (it can be the same as this one) */
    SigMatch *pm = SigMatchGetLastPattern(s);
    if (pm == NULL) {
        SCLogError(SC_ERR_WITHIN_MISSING_CONTENT, "depth needs two preceeding content (or uricontent) options");
        if (dubbed) SCFree(str);
        return -1;
    }

    DetectUricontentData *ud = NULL;
    DetectContentData *cd = NULL;

    switch (pm->type) {
        case DETECT_URICONTENT:
            ud = (DetectUricontentData *)pm->ctx;
            if (ud == NULL) {
                SCLogError(SC_ERR_WITHIN_MISSING_CONTENT, "Unknown previous keyword!\n");
                goto error;
            }

            ud->within = strtol(str, NULL, 10);
            if (ud->within < (int32_t)ud->uricontent_len) {
                SCLogError(SC_ERR_WITHIN_INVALID, "within argument \"%"PRIi32"\" is "
                        "less than the content length \"%"PRIu32"\" which is invalid, since "
                        "this will never match.  Invalidating signature", ud->within,
                        ud->uricontent_len);
                goto error;
            }

            ud->flags |= DETECT_URICONTENT_WITHIN;

            if (ud->flags & DETECT_URICONTENT_DISTANCE) {
                if (ud->distance > (ud->uricontent_len + ud->within)) {
                    ud->within = ud->distance + ud->uricontent_len;
                }
            }

            pm = DetectUricontentGetLastPattern(s->umatch_tail->prev);
            if (pm == NULL) {
                SCLogError(SC_ERR_WITHIN_MISSING_CONTENT, "within needs two preceeding content options");
                goto error;
            }

            /* Set the relative next flag on the prev sigmatch */
            if (pm->type == DETECT_URICONTENT) {
                ud = (DetectUricontentData *)pm->ctx;
                ud->flags |= DETECT_URICONTENT_RELATIVE_NEXT;
            } else {
                SCLogError(SC_ERR_RULE_KEYWORD_UNKNOWN, "Unknown previous-previous keyword!\n");
                goto error;
            }
            DetectUricontentPrint(ud);

        break;

        case DETECT_CONTENT:
            cd = (DetectContentData *)pm->ctx;
            if (cd == NULL) {
                SCLogError(SC_ERR_RULE_KEYWORD_UNKNOWN, "Unknown previous keyword!\n");
                goto error;
            }

            cd->within = strtol(str, NULL, 10);
            if (cd->within < (int32_t)cd->content_len) {
                SCLogError(SC_ERR_WITHIN_INVALID, "within argument \"%"PRIi32"\" is "
                        "less than the content length \"%"PRIu32"\" which is invalid, since "
                        "this will never match.  Invalidating signature", cd->within,
                        cd->content_len);
                goto error;
            }

            cd->flags |= DETECT_CONTENT_WITHIN;

            if (cd->flags & DETECT_CONTENT_DISTANCE) {
                if (cd->distance > (cd->content_len + cd->within)) {
                    cd->within = cd->distance + cd->content_len;
                }
            }

            pm = DetectContentGetLastPattern(s->pmatch_tail->prev);
            if (pm == NULL) {
                SCLogError(SC_ERR_WITHIN_MISSING_CONTENT, "within needs two preceeding content options");
                goto error;
            }

            /* Set the relative next flag on the prev sigmatch */
            if (pm->type == DETECT_CONTENT) {
                cd = (DetectContentData *)pm->ctx;
                cd->flags |= DETECT_CONTENT_RELATIVE_NEXT;
            } else {
                SCLogError(SC_ERR_RULE_KEYWORD_UNKNOWN, "Unknown previous-previous keyword!\n");
                goto error;
            }
        break;

        default:
            SCLogError(SC_ERR_WITHIN_MISSING_CONTENT, "within needs two preceeding content (or uricontent) options");
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

