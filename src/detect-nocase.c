/* NOCASE part of the detection engine. */

#include "suricata-common.h"
#include "decode.h"

#include "detect.h"
#include "detect-parse.h"

#include "flow-var.h"

#include "detect-content.h"
#include "detect-uricontent.h"
#include "detect-pcre.h"
#include "detect-http-client-body.h"

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
 *  \brief get the last pattern sigmatch that supports nocase:
 *         content, uricontent, http_client_body
 *
 *  \param s signature
 *
 *  \retval sm sigmatch of either content or uricontent that is the last
 *             or NULL if none was found
 */
static SigMatch *SigMatchGetLastNocasePattern(Signature *s) {
    SCEnter();

    BUG_ON(s == NULL);

    SigMatch *co_sm = DetectContentGetLastPattern(s->pmatch_tail);
    SigMatch *ur_sm = SigMatchGetLastSM(s->umatch_tail, DETECT_URICONTENT);
    /* http client body SigMatch */
    SigMatch *hcbd_sm = SigMatchGetLastSM(s->match_tail, DETECT_AL_HTTP_CLIENT_BODY);
    SigMatch *sm = NULL;

    if (co_sm != NULL && ur_sm != NULL && hcbd_sm != NULL) {
        BUG_ON(co_sm->idx == ur_sm->idx);

        if (co_sm->idx > ur_sm->idx && ur_sm > hcbd_sm)
            sm = co_sm;
        else if (ur_sm->idx > co_sm->idx && co_sm > hcbd_sm)
            sm = ur_sm;
        else
            sm = hcbd_sm;
    } else if (co_sm != NULL && ur_sm != NULL) {
        if (co_sm->idx > ur_sm->idx)
            sm = co_sm;
        else
            sm = ur_sm;
    } else if (co_sm != NULL && hcbd_sm != NULL) {
        if (co_sm->idx > hcbd_sm->idx)
            sm = co_sm;
        else
            sm = hcbd_sm;
    } else if (ur_sm != NULL && hcbd_sm != NULL) {
        if (ur_sm->idx > hcbd_sm->idx)
            sm = ur_sm;
        else
            sm = hcbd_sm;
    } else if (co_sm != NULL) {
        sm = co_sm;
    } else if (ur_sm != NULL) {
        sm = ur_sm;
    } else if (hcbd_sm != NULL) {
        sm = hcbd_sm;
    }

    SCReturnPtr(sm, "SigMatch");
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
    /** Search for the first previous DetectContent or uricontent
     * SigMatch (it can be the same as this one) */
    SigMatch *pm = SigMatchGetLastNocasePattern(s);
    if (pm == NULL) {
        SCLogError(SC_ERR_NOCASE_MISSING_PATTERN, "nocase needs a preceeding content option");
        SCReturnInt(-1);
    }

    DetectUricontentData *ud = NULL;
    DetectContentData *cd = NULL;
    switch (pm->type) {
        case DETECT_URICONTENT:
            ud = (DetectUricontentData *)pm->ctx;
            if (ud == NULL) {
                SCLogError(SC_ERR_INVALID_ARGUMENT, "invalid argpment");
                SCReturnInt(-1);
            }
            ud->flags |= DETECT_URICONTENT_NOCASE;
            break;

        case DETECT_CONTENT:
            cd = (DetectContentData *)pm->ctx;
            if (cd == NULL) {
                SCLogError(SC_ERR_INVALID_ARGUMENT, "invalid argument");
                SCReturnInt(-1);
            }
            cd->flags |= DETECT_CONTENT_NOCASE;
            break;
        case DETECT_AL_HTTP_CLIENT_BODY:
            {
                ((DetectHttpClientBodyData *)(pm->ctx))->flags |= DETECT_AL_HTTP_CLIENT_BODY_NOCASE;
                break;
            }

        /* should never happen */
        default:
            SCLogError(SC_ERR_NOCASE_MISSING_PATTERN, "nocase needs a preceeding content (or uricontent) option");
            SCReturnInt(-1);
            break;
    }

    SCReturnInt(0);
}

