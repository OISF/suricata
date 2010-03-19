/* NOCASE part of the detection engine. */

#include "suricata-common.h"
#include "decode.h"

#include "detect.h"
#include "detect-parse.h"

#include "flow-var.h"

#include "detect-content.h"
#include "detect-uricontent.h"
#include "detect-pcre.h"

#include "util-debug.h"

static int DetectNocaseSetup (DetectEngineCtx *, Signature *, char *);

void DetectNocaseRegister (void) {
    sigmatch_table[DETECT_NOCASE].name = "nocase";
    sigmatch_table[DETECT_NOCASE].Match = NULL;
    sigmatch_table[DETECT_NOCASE].Setup = DetectNocaseSetup;
    sigmatch_table[DETECT_NOCASE].Free  = NULL;
    sigmatch_table[DETECT_NOCASE].RegisterTests = NULL;

    sigmatch_table[DETECT_NOCASE].flags |= SIGMATCH_NOOPT;
    sigmatch_table[DETECT_NOCASE].flags |= SIGMATCH_PAYLOAD;
}

/** \internal
 *  \brief Apply the nocase keyword to the last pattern match, either content or uricontent
 *  \param det_ctx detection engine ctx
 *  \param s signature
 *  \param nullstr should be null
 *  \retval 0 ok
 *  \retval -1 failure
 */
static int DetectNocaseSetup (DetectEngineCtx *de_ctx, Signature *s, char *nullstr)
{
    SCEnter();

    if (nullstr != NULL) {
        SCLogError(SC_ERR_INVALID_VALUE, "nocase has no value");
        SCReturnInt(-1);
    }

    SigMatch *pm = SigMatchGetLastPattern(s);
    if (pm == NULL) {
        SCLogError(SC_ERR_NOCASE_MISSING_PATTERN, "\"nocase\" needs a preceeding content or uricontent option.");
        SCReturnInt(-1);
    }

    switch (pm->type) {
        case DETECT_CONTENT:
        {
            DetectContentData *cd = (DetectContentData *)pm->ctx;
            cd->flags |= DETECT_CONTENT_NOCASE;
            break;
        }
        case DETECT_URICONTENT:
        {
            DetectUricontentData *cd = (DetectUricontentData *)pm->ctx;
            cd->flags |= DETECT_URICONTENT_NOCASE;
            break;
        }
        /* should never happen */
        default:
            BUG_ON(1);
            break;
    }

    SCReturnInt(0);
}

