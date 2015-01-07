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
 * \ingroup httplayer
 *
 * @{
 */


/**
 * \file
 *
 * \author Anoop Saldanha <anoopsaldanha@gmail.com>
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
#include "detect-pcre.h"

#include "flow.h"
#include "flow-var.h"

#include "util-debug.h"
#include "util-unittest.h"
#include "util-spm.h"
#include "util-print.h"

#include "app-layer.h"

#include "app-layer-htp.h"
#include "detect-http-raw-uri.h"
#include "stream-tcp.h"

static int DetectHttpRawUriSetup(DetectEngineCtx *, Signature *, char *);
static void DetectHttpRawUriRegisterTests(void);

/**
 * \brief Registration function for keyword http_raw_uri.
 */
void DetectHttpRawUriRegister(void)
{
    sigmatch_table[DETECT_AL_HTTP_RAW_URI].name = "http_raw_uri";
    sigmatch_table[DETECT_AL_HTTP_RAW_URI].desc = "content modifier to match on HTTP uri";
    sigmatch_table[DETECT_AL_HTTP_RAW_URI].url = "https://redmine.openinfosecfoundation.org/projects/suricata/wiki/HTTP-keywords#http_uri-and-http_raw_uri";
    sigmatch_table[DETECT_AL_HTTP_RAW_URI].Match = NULL;
    sigmatch_table[DETECT_AL_HTTP_RAW_URI].AppLayerMatch = NULL;
    sigmatch_table[DETECT_AL_HTTP_RAW_URI].alproto = ALPROTO_HTTP;
    sigmatch_table[DETECT_AL_HTTP_RAW_URI].Setup = DetectHttpRawUriSetup;
    sigmatch_table[DETECT_AL_HTTP_RAW_URI].Free = NULL;
    sigmatch_table[DETECT_AL_HTTP_RAW_URI].RegisterTests = DetectHttpRawUriRegisterTests;
    sigmatch_table[DETECT_AL_HTTP_RAW_URI].flags |= SIGMATCH_NOOPT;
    sigmatch_table[DETECT_AL_HTTP_RAW_URI].flags |= SIGMATCH_PAYLOAD;

    return;
}

/**
 * \brief Sets up the http_raw_uri modifier keyword.
 *
 * \param de_ctx Pointer to the Detection Engine Context.
 * \param s      Pointer to the Signature to which the current keyword belongs.
 * \param arg    Should hold an empty string always.
 *
 * \retval  0 On success.
 * \retval -1 On failure.
 */
static int DetectHttpRawUriSetup(DetectEngineCtx *de_ctx, Signature *s, char *arg)
{
    return DetectEngineContentModifierBufferSetup(de_ctx, s, arg,
                                                  DETECT_AL_HTTP_RAW_URI,
                                                  DETECT_SM_LIST_HRUDMATCH,
                                                  ALPROTO_HTTP,
                                                  NULL);
}


/******************************** UNITESTS **********************************/

#ifdef UNITTESTS

#include "stream-tcp-reassemble.h"

/**
 * \test Checks if a http_raw_uri is registered in a Signature, if content is not
 *       specified in the signature.
 */
int DetectHttpRawUriTest01(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(msg:\"Testing http_raw_uri\"; http_raw_uri; sid:1;)");
    if (de_ctx->sig_list == NULL)
        result = 1;

end:
    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);
    return result;
}

/**
 * \test Checks if a http_raw_uri is registered in a Signature, if some parameter
 *       is specified with http_raw_uri in the signature.
 */
int DetectHttpRawUriTest02(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(msg:\"Testing http_raw_uri\"; content:\"one\"; "
                               "http_raw_uri:wrong; sid:1;)");
    if (de_ctx->sig_list == NULL)
        result = 1;

end:
    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);
    return result;
}

/**
 * \test Checks if a http_raw_uri is registered in a Signature.
 */
int DetectHttpRawUriTest03(void)
{
    SigMatch *sm = NULL;
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(msg:\"Testing http_raw_uri\"; "
                               "content:\"one\"; http_raw_uri; "
                               "content:\"two\"; http_raw_uri; "
                               "content:\"three\"; http_raw_uri; "
                               "sid:1;)");
    if (de_ctx->sig_list == NULL) {
        printf("sig parse failed: ");
        goto end;
    }

    sm = de_ctx->sig_list->sm_lists[DETECT_SM_LIST_HRUDMATCH];
    if (sm == NULL) {
        printf("no sigmatch(es): ");
        goto end;
    }

    while (sm != NULL) {
        if (sm->type == DETECT_CONTENT) {
            result = 1;
        } else {
            printf("expected DETECT_CONTENT for http_raw_uri(%d), got %d: ",
                   DETECT_CONTENT, sm->type);
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
 * \test Checks if a http_raw_uri is registered in a Signature, when rawbytes is
 *       also specified in the signature.
 */
int DetectHttpRawUriTest04(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(msg:\"Testing http_raw_uri\"; "
                               "content:\"one\"; rawbytes; http_raw_uri; "
                               "sid:1;)");
    if (de_ctx->sig_list == NULL)
        result = 1;

 end:
    if (de_ctx != NULL)
        SigCleanSignatures(de_ctx);
    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);
    return result;
}

/**
 * \test Checks if a http_raw_uri is successfully converted to a rawuricontent.
 *
 */
int DetectHttpRawUriTest05(void)
{
    DetectEngineCtx *de_ctx = NULL;
    Signature *s = NULL;
    int result = 0;

    if ((de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    s = SigInit(de_ctx, "alert tcp any any -> any any "
                "(msg:\"Testing http_raw_uri\"; "
                "content:\"we are testing http_raw_uri keyword\"; http_raw_uri; "
                "sid:1;)");
    if (s == NULL) {
        printf("sig failed to parse\n");
        goto end;
    }
    if (s->sm_lists[DETECT_SM_LIST_HRUDMATCH] == NULL)
        goto end;
    if (s->sm_lists[DETECT_SM_LIST_HRUDMATCH]->type != DETECT_CONTENT) {
        printf("wrong type\n");
        goto end;
    }

    char *str = "we are testing http_raw_uri keyword";
    int uricomp = memcmp((const char *)
                         ((DetectContentData*)s->sm_lists[DETECT_SM_LIST_HRUDMATCH]->ctx)->content,
                         str,
                         strlen(str) - 1);
    int urilen = ((DetectContentData*)s->sm_lists_tail[DETECT_SM_LIST_HRUDMATCH]->ctx)->content_len;
    if (uricomp != 0 ||
        urilen != strlen("we are testing http_raw_uri keyword")) {
        printf("sig failed to parse, content not setup properly\n");
        goto end;
    }
    result = 1;

end:
    if (de_ctx != NULL)
        SigCleanSignatures(de_ctx);
    if (de_ctx != NULL)
        SigGroupCleanup(de_ctx);
    return result;
}

int DetectHttpRawUriTest12(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert icmp any any -> any any "
                               "(content:\"one\"; http_raw_uri; "
                               "content:\"two\"; distance:0; http_raw_uri; sid:1;)");
    if (de_ctx->sig_list == NULL) {
        printf("de_ctx->sig_list == NULL\n");
        goto end;
    }

    if (de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH] != NULL) {
        printf("de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH] != NULL\n");
        goto end;
    }

    if (de_ctx->sig_list->sm_lists[DETECT_SM_LIST_HRUDMATCH] == NULL) {
        printf("de_ctx->sig_list->sm_lists[DETECT_SM_LIST_HRUDMATCH] == NULL\n");
        goto end;
    }

    DetectContentData *ud1 =
        (DetectContentData *)de_ctx->sig_list->sm_lists_tail[DETECT_SM_LIST_HRUDMATCH]->prev->ctx;
    DetectContentData *ud2 =
        (DetectContentData *)de_ctx->sig_list->sm_lists_tail[DETECT_SM_LIST_HRUDMATCH]->ctx;
    if (ud1->flags != DETECT_CONTENT_RELATIVE_NEXT ||
        memcmp(ud1->content, "one", ud1->content_len) != 0 ||
        ud2->flags != DETECT_CONTENT_DISTANCE ||
        memcmp(ud2->content, "two", ud1->content_len) != 0) {
        /* inside body */
        goto end;
    }

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

int DetectHttpRawUriTest13(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert icmp any any -> any any "
                               "(content:\"one\"; http_raw_uri; "
                               "content:\"two\"; within:5; http_raw_uri; sid:1;)");
    if (de_ctx->sig_list == NULL) {
        printf("de_ctx->sig_list == NULL\n");
        goto end;
    }

    if (de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH] != NULL) {
        printf("de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH] != NULL\n");
        goto end;
    }

    if (de_ctx->sig_list->sm_lists[DETECT_SM_LIST_HRUDMATCH] == NULL) {
        printf("de_ctx->sig_list->sm_lists[DETECT_SM_LIST_HRUDMATCH] == NULL\n");
        goto end;
    }

    DetectContentData *ud1 =
        (DetectContentData *)de_ctx->sig_list->sm_lists_tail[DETECT_SM_LIST_HRUDMATCH]->prev->ctx;
    DetectContentData *ud2 =
        (DetectContentData *)de_ctx->sig_list->sm_lists_tail[DETECT_SM_LIST_HRUDMATCH]->ctx;
    if (ud1->flags != DETECT_CONTENT_RELATIVE_NEXT ||
        memcmp(ud1->content, "one", ud1->content_len) != 0 ||
        ud2->flags != DETECT_CONTENT_WITHIN ||
        memcmp(ud2->content, "two", ud1->content_len) != 0) {
        /* inside the body */
        goto end;
    }

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

int DetectHttpRawUriTest14(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert icmp any any -> any any "
                               "(content:\"one\"; within:5; http_raw_uri; sid:1;)");
    if (de_ctx->sig_list == NULL) {
        printf("de_ctx->sig_list == NULL\n");
        goto end;
    }

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

int DetectHttpRawUriTest15(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert icmp any any -> any any "
                               "(content:\"one\"; http_raw_uri; within:5; sid:1;)");
    if (de_ctx->sig_list == NULL) {
        printf("de_ctx->sig_list == NULL\n");
        goto end;
    }

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

int DetectHttpRawUriTest16(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert icmp any any -> any any "
                               "(content:\"one\"; within:5; sid:1;)");
    if (de_ctx->sig_list == NULL) {
        printf("de_ctx->sig_list == NULL\n");
        goto end;
    }

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

int DetectHttpRawUriTest17(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert icmp any any -> any any "
                               "(content:\"one\"; http_raw_uri; "
                               "content:\"two\"; distance:0; http_raw_uri; sid:1;)");
    if (de_ctx->sig_list == NULL) {
        printf("de_ctx->sig_list == NULL\n");
        goto end;
    }

    if (de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH] != NULL) {
        printf("de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH] != NULL\n");
        goto end;
    }

    if (de_ctx->sig_list->sm_lists[DETECT_SM_LIST_HRUDMATCH] == NULL) {
        printf("de_ctx->sig_list->sm_lists[DETECT_SM_LIST_HRUDMATCH] == NULL\n");
        goto end;
    }

    DetectContentData *ud1 =
      (DetectContentData *)de_ctx->sig_list->sm_lists_tail[DETECT_SM_LIST_HRUDMATCH]->prev->ctx;
    DetectContentData *ud2 =
      (DetectContentData *)de_ctx->sig_list->sm_lists_tail[DETECT_SM_LIST_HRUDMATCH]->ctx;
    if (ud1->flags != DETECT_CONTENT_RELATIVE_NEXT ||
        memcmp(ud1->content, "one", ud1->content_len) != 0 ||
        ud2->flags != DETECT_CONTENT_DISTANCE ||
        memcmp(ud2->content, "two", ud1->content_len) != 0) {
        /* inside body */
        goto end;
    }

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

int DetectHttpRawUriTest18(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert icmp any any -> any any "
                               "(content:\"one\"; http_raw_uri; "
                               "content:\"two\"; within:5; http_raw_uri; "
                               "sid:1;)");
    if (de_ctx->sig_list == NULL) {
        printf("de_ctx->sig_list == NULL\n");
        goto end;
    }

    if (de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH] != NULL) {
        printf("de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH] != NULL\n");
        goto end;
    }

    if (de_ctx->sig_list->sm_lists[DETECT_SM_LIST_HRUDMATCH] == NULL) {
        printf("de_ctx->sig_list->sm_lists[DETECT_SM_LIST_HRUDMATCH] == NULL\n");
        goto end;
    }

    DetectContentData *ud1 =
        (DetectContentData *)de_ctx->sig_list->sm_lists_tail[DETECT_SM_LIST_HRUDMATCH]->prev->ctx;
    DetectContentData *ud2 =
        (DetectContentData *)de_ctx->sig_list->sm_lists_tail[DETECT_SM_LIST_HRUDMATCH]->ctx;
    if (ud1->flags != DETECT_CONTENT_RELATIVE_NEXT ||
        memcmp(ud1->content, "one", ud1->content_len) != 0 ||
        ud2->flags != DETECT_CONTENT_WITHIN ||
        memcmp(ud2->content, "two", ud1->content_len) != 0) {
        /* inside body */
        goto end;
    }

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

#endif /* UNITTESTS */

/**
 * \brief   Register the UNITTESTS for the http_uri keyword
 */
static void DetectHttpRawUriRegisterTests (void)
{
#ifdef UNITTESTS /* UNITTESTS */
    UtRegisterTest("DetectHttpRawUriTest01", DetectHttpRawUriTest01, 1);
    UtRegisterTest("DetectHttpRawUriTest02", DetectHttpRawUriTest02, 1);
    UtRegisterTest("DetectHttpRawUriTest03", DetectHttpRawUriTest03, 1);
    UtRegisterTest("DetectHttpRawUriTest04", DetectHttpRawUriTest04, 1);
    UtRegisterTest("DetectHttpRawUriTest05", DetectHttpRawUriTest05, 1);
    UtRegisterTest("DetectHttpRawUriTest12", DetectHttpRawUriTest12, 1);
    UtRegisterTest("DetectHttpRawUriTest13", DetectHttpRawUriTest13, 1);
    UtRegisterTest("DetectHttpRawUriTest14", DetectHttpRawUriTest14, 1);
    UtRegisterTest("DetectHttpRawUriTest15", DetectHttpRawUriTest15, 1);
    UtRegisterTest("DetectHttpRawUriTest16", DetectHttpRawUriTest16, 1);
    UtRegisterTest("DetectHttpRawUriTest17", DetectHttpRawUriTest17, 1);
    UtRegisterTest("DetectHttpRawUriTest18", DetectHttpRawUriTest18, 1);
#endif /* UNITTESTS */

    return;
}
/**
 * @}
 */
