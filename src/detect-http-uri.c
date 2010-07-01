/* Copyright (C) 2007-2010 Open Information Security Foundation
 *
 * You can copy, redistribute or modify this Program under the terms of
 * the GNU General Public License version 2 as published by the Free
 * Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 */

/**
 * \file
 *
 * \author Gerardo Iglesias  <iglesiasg@gmail.com>
 */

#include "suricata-common.h"
#include "threads.h"
#include "debug.h"
#include "decode.h"
#include "detect.h"

#include "detect-parse.h"
#include "detect-engine.h"
#include "detect-engine-mpm.h"
#include "detect-content.h"

#include "flow.h"
#include "flow-var.h"

#include "util-debug.h"
#include "util-unittest.h"
#include "util-spm.h"
#include "util-print.h"

#include "app-layer.h"

#include <htp/htp.h>
#include "app-layer-htp.h"
#include "detect-http-uri.h"
#include "detect-uricontent.h"
#include "stream-tcp.h"

int DetectHttpUriMatch (ThreadVars *t, DetectEngineThreadCtx *det_ctx,
                           Flow *f, uint8_t flags, void *state, Signature *s,
                           SigMatch *m);
static int DetectHttpUriSetup (DetectEngineCtx *, Signature *, char *);
void DetectHttpUriRegisterTests(void);

/**
 * \brief Registration function for keyword: http_uri
 */
void DetectHttpUriRegister (void) {
    sigmatch_table[DETECT_AL_HTTP_URI].name = "http_uri";
    sigmatch_table[DETECT_AL_HTTP_URI].Match = NULL;
    sigmatch_table[DETECT_AL_HTTP_URI].AppLayerMatch = NULL;
    sigmatch_table[DETECT_AL_HTTP_URI].alproto = ALPROTO_HTTP;
    sigmatch_table[DETECT_AL_HTTP_URI].Setup = DetectHttpUriSetup;
    sigmatch_table[DETECT_AL_HTTP_URI].Free  = NULL;
    sigmatch_table[DETECT_AL_HTTP_URI].RegisterTests = DetectHttpUriRegisterTests;

    sigmatch_table[DETECT_AL_HTTP_URI].flags |= SIGMATCH_PAYLOAD;
}


/**
 * \brief this function setups the http_uri modifier keyword used in the rule
 *
 * \param de_ctx   Pointer to the Detection Engine Context
 * \param s        Pointer to the Signature to which the current keyword belongs
 * \param str      Should hold an empty string always
 *
 * \retval  0 On success
 * \retval -1 On failure
 */

static int DetectHttpUriSetup (DetectEngineCtx *de_ctx, Signature *s, char *str)
{
    DetectUricontentData *duc = NULL;
    SigMatch *sm = NULL;

    /** new sig match to replace previous content */
    SigMatch *nm = NULL;

    if (str != NULL && strcmp(str, "") != 0) {
        SCLogError(SC_ERR_INVALID_ARGUMENT, "http_uri shouldn't be supplied with"
                                        " an argument");
        return -1;
    }

    if (s->pmatch_tail == NULL) {
        SCLogError(SC_ERR_INVALID_SIGNATURE, "http_uri found inside the "
                     "rule, without any preceding content keywords");
        return -1;
    }

    SigMatch *pm = DetectContentGetLastPattern(s->pmatch_tail);
    if (pm == NULL) {
        SCLogWarning(SC_ERR_INVALID_SIGNATURE, "http_uri modifies \"content\""
                "but none was found");
        return -1;
    }

    if (((DetectContentData *)pm->ctx)->flags & DETECT_CONTENT_FAST_PATTERN)
    {
        SCLogWarning(SC_WARN_COMPATIBILITY,
                   "http_uri cannot be used with \"fast_pattern\" currently."
                   "Unsetting fast_pattern on this modifier. Signature ==> %s", s->sig_str);
        ((DetectContentData *)pm->ctx)->flags &= ~DETECT_CONTENT_FAST_PATTERN;
    }

    /* http_uri should not be used with the rawbytes rule */
    if (((DetectContentData *)pm->ctx)->flags & DETECT_CONTENT_RAWBYTES) {

        SCLogError(SC_ERR_INVALID_SIGNATURE, "http_uri rule can not "
                "be used with the rawbytes rule keyword");
        return -1;
    }

    nm = SigMatchAlloc();
    if (nm == NULL)
        goto error;

    /* Setup the uricontent data from content data structure */
    duc = SCMalloc(sizeof(DetectUricontentData));
    if (duc == NULL)
        goto error;
    memset(duc, 0, sizeof(DetectUricontentData));

    duc->uricontent_len = ((DetectContentData *)pm->ctx)->content_len;
    if ((duc->uricontent = SCMalloc(duc->uricontent_len)) == NULL)
        goto error;
    memcpy(duc->uricontent, ((DetectContentData *)pm->ctx)->content, duc->uricontent_len);

    duc->flags |= (((DetectContentData *)pm->ctx)->flags & DETECT_CONTENT_NOCASE) ?
        DETECT_URICONTENT_NOCASE : 0;
    duc->flags |= (((DetectContentData *)pm->ctx)->flags & DETECT_CONTENT_NEGATED) ?
        DETECT_URICONTENT_NEGATED : 0;
    duc->bm_ctx = BoyerMooreCtxInit(duc->uricontent, duc->uricontent_len);

    nm->type = DETECT_URICONTENT;
    nm->ctx = (void *)duc;

    /* pull the previous content from the pmatch list, append
     * the new match to the match list */
    SigMatchReplaceContentToUricontent(s, pm, nm);

    /* free the old content sigmatch, the content pattern memory
     * is taken over by the new sigmatch */
    SCFree(pm->ctx);
    SCFree(pm);

    /* Flagged the signature as to inspect the app layer data */
    s->flags |= SIG_FLAG_APPLAYER;

    if (s->alproto != ALPROTO_UNKNOWN && s->alproto != ALPROTO_HTTP) {
        SCLogError(SC_ERR_CONFLICTING_RULE_KEYWORDS, "rule contains conflicting keywords.");
        goto error;
    }

    s->alproto = ALPROTO_HTTP;

    return 0;
error:
    if (duc != NULL) {
        if (duc->uricontent != NULL)
            SCFree(duc->uricontent);
        SCFree(duc);
    }
    if(sm !=NULL) SCFree(sm);
    return -1;
}


/******************************** UNITESTS **********************************/

#ifdef UNITTESTS

#include "stream-tcp-reassemble.h"

/**
 * \test Checks if a http_uri is registered in a Signature, if content is not
 *       specified in the signature
 */
int DetectHttpUriTest01(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(msg:\"Testing http_uri\"; http_uri;sid:1;)");
    if (de_ctx->sig_list == NULL)
        result = 1;

end:
    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);
    return result;
}

/**
 * \test Checks if a http_uri is registered in a Signature, if some parameter
 *       is specified with http_uri in the signature
 */
int DetectHttpUriTest02(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(msg:\"Testing http_uri\"; content:\"one\"; "
                               "http_cookie:wrong; sid:1;)");
    if (de_ctx->sig_list == NULL)
        result = 1;

end:
    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);
    return result;
}

/**
 * \test Checks if a http_uri is registered in a Signature
 */
int DetectHttpUriTest03(void)
{
    SigMatch *sm = NULL;
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(msg:\"Testing http_uri\"; content:\"one\"; "
                               "http_uri; content:\"two\"; http_uri; "
                               "content:\"three\"; http_uri; "
                               "sid:1;)");

    if (de_ctx->sig_list == NULL) {
        printf("sig parse failed: ");
        goto end;
    }

    sm = de_ctx->sig_list->umatch;
    if (sm == NULL) {
        printf("no sigmatch(es): ");
        goto end;
    }

    while (sm != NULL) {
        if (sm->type == DETECT_URICONTENT) {
            result = 1;
        } else {
            printf("expected DETECT_AL_HTTP_URI, got %d: ", sm->type);
            goto end;
        }
        sm = sm->next;
    }

end:
    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);
    return result;
}

/**
 * \test Checks if a http_uri is registered in a Signature, when rawbytes is
 *       also specified in the signature
 */
int DetectHttpUriTest04(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(msg:\"Testing http_uri\"; content:\"one\"; "
                               "rawbytes; http_uri; sid:1;)");
    if (de_ctx->sig_list == NULL)
        result = 1;

 end:
    if (de_ctx != NULL) SigCleanSignatures(de_ctx);
    if (de_ctx != NULL) DetectEngineCtxFree(de_ctx);
    return result;
}

/**
 * \test Checks if a http_uri is successfully converted to a uricontent
 *
 */
int DetectHttpUriTest05(void)
{
    DetectEngineCtx *de_ctx = NULL;
    Signature *s = NULL;
    int result = 0;

    if ((de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    s = SigInit(de_ctx, "alert tcp any any -> any any "
                    "(msg:\"Testing http_uri\"; "
                    "content:\"we are testing http_uri keyword\"; "
                    "http_uri; sid:1;)");
    if (s == NULL) {
        printf("sig failed to parse\n");
        goto end;
    }
    if (s->umatch == NULL)
        goto end;
    if (s->umatch->type != DETECT_URICONTENT) {
        printf("wrong type\n");
        goto end;
    }

    char *str = "we are testing http_uri keyword";
    int uricomp = memcmp((const char *)((DetectUricontentData*) s->umatch->ctx)->uricontent, str, strlen(str)-1);
    int urilen = ((DetectUricontentData*) s->umatch_tail->ctx)->uricontent_len;
    if (uricomp != 0 ||
        urilen != strlen("we are testing http_uri keyword")) {
        printf("sig failed to parse, content not setup properly\n");
        goto end;
    }
    result = 1;

end:
    if (de_ctx != NULL) SigCleanSignatures(de_ctx);
    if (de_ctx != NULL) SigGroupCleanup(de_ctx);
    return result;
}

#endif /* UNITTESTS */

/**
 * \brief   Register the UNITTESTS for the http_uri keyword
 */
void DetectHttpUriRegisterTests (void)
{
#ifdef UNITTESTS /* UNITTESTS */
    UtRegisterTest("DetectHttpUriTest01", DetectHttpUriTest01, 1);
    UtRegisterTest("DetectHttpUriTest02", DetectHttpUriTest02, 1);
    UtRegisterTest("DetectHttpUriTest03", DetectHttpUriTest03, 1);
    UtRegisterTest("DetectHttpUriTest04", DetectHttpUriTest04, 1);
    UtRegisterTest("DetectHttpUriTest05", DetectHttpUriTest05, 1);
#endif /* UNITTESTS */

}

