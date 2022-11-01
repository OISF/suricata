/* Copyright (C) 2007-2022 Open Information Security Foundation
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
 * \author  Victor Julien <victor@inliniac.net>
 * \author Gurvinder Singh <gurvindersinghdahiya@gmail.com>
 *
 * Simple uricontent match part of the detection engine.
 */

#include "suricata-common.h"
#include "decode.h"
#include "detect.h"
#include "detect-content.h"
#include "detect-http-uri.h"
#include "detect-uricontent.h"
#include "detect-engine-mpm.h"
#include "detect-parse.h"
#include "detect-engine.h"
#include "detect-engine-state.h"
#include "flow.h"
#include "detect-flow.h"
#include "flow-var.h"
#include "flow-util.h"
#include "threads.h"

#include "stream-tcp.h"
#include "stream.h"
#include "app-layer.h"
#include "app-layer-parser.h"
#include "app-layer-protos.h"
#include "app-layer-htp.h"

#include "util-mpm.h"
#include "util-print.h"
#include "util-debug.h"
#include "util-unittest.h"
#include "util-unittest-helper.h"
#include "util-spm.h"
#include "conf.h"

/* prototypes */
static int DetectUricontentSetup (DetectEngineCtx *, Signature *, const char *);
#ifdef UNITTESTS
static void DetectUricontentRegisterTests(void);
#endif
static void DetectUricontentFree(DetectEngineCtx *de_ctx, void *);

static int g_http_uri_buffer_id = 0;

/**
 * \brief Registration function for uricontent: keyword
 */
void DetectUricontentRegister (void)
{
    sigmatch_table[DETECT_URICONTENT].name = "uricontent";
    sigmatch_table[DETECT_URICONTENT].desc = "legacy keyword to match on the request URI buffer";
    sigmatch_table[DETECT_URICONTENT].url = "/rules/http-keywords.html#uricontent";
    sigmatch_table[DETECT_URICONTENT].Match = NULL;
    sigmatch_table[DETECT_URICONTENT].Setup = DetectUricontentSetup;
    sigmatch_table[DETECT_URICONTENT].Free  = DetectUricontentFree;
#ifdef UNITTESTS
    sigmatch_table[DETECT_URICONTENT].RegisterTests = DetectUricontentRegisterTests;
#endif
    sigmatch_table[DETECT_URICONTENT].flags = (SIGMATCH_QUOTES_MANDATORY|SIGMATCH_HANDLE_NEGATION);
    sigmatch_table[DETECT_URICONTENT].alternative = DETECT_HTTP_URI;

    g_http_uri_buffer_id = DetectBufferTypeRegister("http_uri");
}

/**
 * \brief this function will Free memory associated with DetectContentData
 *
 * \param cd pointer to DetectUricotentData
 */
void DetectUricontentFree(DetectEngineCtx *de_ctx, void *ptr)
{
    SCEnter();
    DetectContentData *cd = (DetectContentData *)ptr;

    if (cd == NULL)
        SCReturn;

    SpmDestroyCtx(cd->spm_ctx);
    SCFree(cd);

    SCReturn;
}

/**
 * \brief Creates a SigMatch for the uricontent keyword being sent as argument,
 *        and appends it to the Signature(s).
 *
 * \param de_ctx    Pointer to the detection engine context
 * \param s         Pointer to signature for the current Signature being parsed
 *                  from the rules
 * \param contentstr  Pointer to the string holding the keyword value
 *
 * \retval 0 on success, -1 on failure
 */
int DetectUricontentSetup(DetectEngineCtx *de_ctx, Signature *s, const char *contentstr)
{
    SCEnter();

    const char *legacy = NULL;
    if (ConfGet("legacy.uricontent", &legacy) == 1) {
        if (strcasecmp("disabled", legacy) == 0) {
            SCLogError(SC_ERR_INVALID_SIGNATURE, "uriconent deprecated.  To "
                       "use a rule with \"uricontent\", either set the "
                       "option - \"legacy.uricontent\" in the conf to "
                       "\"enabled\" OR replace uricontent with "
                       "\'content:%s; http_uri;\'.", contentstr);
            goto error;
        } else if (strcasecmp("enabled", legacy) == 0) {
            ;
        } else {
            SCLogError(SC_ERR_INVALID_YAML_CONF_ENTRY, "Invalid value found "
                       "for legacy.uriconent - \"%s\".  Valid values are "
                       "\"enabled\" OR \"disabled\".", legacy);
            goto error;
        }
    }

    if (DetectContentSetup(de_ctx, s, contentstr) < 0)
        goto error;

    if (DetectHttpUriSetup(de_ctx, s, NULL) < 0)
        goto error;

    SCReturnInt(0);
error:
    SCReturnInt(-1);
}

/*
 * UNITTTESTS
 */

#ifdef UNITTESTS

#include "detect-isdataat.h"

/**
 * \test Checks if a uricontent is registered in a Signature
 */
static int DetectUriSigTest01(void)
{
    ThreadVars th_v;
    Signature *s = NULL;

    memset(&th_v, 0, sizeof(th_v));

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    de_ctx->flags |= DE_QUIET;

    s = DetectEngineAppendSig(de_ctx,"alert http any any -> any any (msg:"
            "\" Test uricontent\"; content:\"me\"; uricontent:\"me\"; sid:1;)");
    FAIL_IF_NULL(s);

    BUG_ON(s->sm_lists[g_http_uri_buffer_id] == NULL);
    FAIL_IF_NOT(de_ctx->sig_list->sm_lists[g_http_uri_buffer_id]->type == DETECT_CONTENT);

    DetectEngineCtxFree(de_ctx);
    PASS;
}

/**
 * \test Check that modifiers of content apply only to content keywords
 *       and the same for uricontent modifiers
 */
static int DetectUriSigTest02(void)
{
    Signature *s = NULL;

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);

    s = SigInit(de_ctx, "alert tcp any any -> any any (msg:"
                        "\" Test uricontent\"; "
                        "uricontent:\"foo\"; sid:1;)");
    FAIL_IF_NULL(s);
    FAIL_IF_NULL(s->sm_lists[g_http_uri_buffer_id]);
    FAIL_IF_NOT_NULL(s->sm_lists[DETECT_SM_LIST_PMATCH]);
    FAIL_IF_NOT_NULL(s->sm_lists[DETECT_SM_LIST_MATCH]);

    s = SigInit(de_ctx, "alert tcp any any -> any any (msg:"
                        "\" Test uricontent and content\"; "
                        "uricontent:\"foo\"; content:\"bar\";sid:1;)");

    FAIL_IF_NULL(s);
    FAIL_IF_NULL(s->sm_lists[g_http_uri_buffer_id]);
    FAIL_IF_NULL(s->sm_lists[DETECT_SM_LIST_PMATCH]);
    FAIL_IF_NOT_NULL(s->sm_lists[DETECT_SM_LIST_MATCH]);

    s = SigInit(de_ctx, "alert tcp any any -> any any (msg:"
                        "\" Test uricontent and content\"; "
                        "uricontent:\"foo\"; content:\"bar\";"
                        " depth:10; offset: 5; sid:1;)");

    FAIL_IF_NULL(s);
    FAIL_IF_NULL(s->sm_lists[g_http_uri_buffer_id]);
    FAIL_IF_NULL(s->sm_lists[DETECT_SM_LIST_PMATCH]);
    FAIL_IF_NOT(((DetectContentData *)s->sm_lists[DETECT_SM_LIST_PMATCH]->ctx)->depth = 15);
    FAIL_IF_NOT(((DetectContentData *)s->sm_lists[DETECT_SM_LIST_PMATCH]->ctx)->offset = 5);
    FAIL_IF_NOT_NULL(s->sm_lists[DETECT_SM_LIST_MATCH]);

    s = SigInit(de_ctx, "alert tcp any any -> any any (msg:"
                        "\" Test uricontent and content\"; "
                        "content:\"foo\"; uricontent:\"bar\";"
                        " depth:10; offset: 5; sid:1;)");

    FAIL_IF_NULL(s);
    FAIL_IF_NULL(s->sm_lists[g_http_uri_buffer_id]);
    FAIL_IF_NULL(s->sm_lists[DETECT_SM_LIST_PMATCH]);
    FAIL_IF_NOT(((DetectContentData *)s->sm_lists[g_http_uri_buffer_id]->ctx)->depth = 15);
    FAIL_IF_NOT(((DetectContentData *)s->sm_lists[g_http_uri_buffer_id]->ctx)->offset = 5);
    FAIL_IF_NOT_NULL(s->sm_lists[DETECT_SM_LIST_MATCH]);

    s = SigInit(de_ctx, "alert tcp any any -> any any (msg:"
                        "\" Test uricontent and content\"; "
                        "uricontent:\"foo\"; content:\"bar\";"
                        " depth:10; offset: 5; within:3; sid:1;)");

    FAIL_IF_NOT_NULL(s);

    s = SigInit(de_ctx, "alert tcp any any -> any any (msg:"
                        "\" Test uricontent and content\"; "
                        "uricontent:\"foo\"; content:\"bar\";"
                        " depth:10; offset: 5; distance:3; sid:1;)");
    FAIL_IF_NOT_NULL(s);

    s = SigInit(de_ctx, "alert tcp any any -> any any (msg:"
                        "\" Test uricontent and content\"; "
                        "uricontent:\"foo\"; content:\"bar\";"
                        " depth:10; offset: 5; content:"
                        "\"two_contents\"; within:30; sid:1;)");

    FAIL_IF_NULL(s);
    FAIL_IF_NULL(s->sm_lists[g_http_uri_buffer_id]);
    FAIL_IF_NULL(s->sm_lists[DETECT_SM_LIST_PMATCH]);
    FAIL_IF_NOT(((DetectContentData *)s->sm_lists[DETECT_SM_LIST_PMATCH]->ctx)->depth = 15);
    FAIL_IF_NOT(((DetectContentData *)s->sm_lists[DETECT_SM_LIST_PMATCH]->ctx)->offset = 5);
    FAIL_IF_NOT(((DetectContentData *)s->sm_lists_tail[DETECT_SM_LIST_PMATCH]->ctx)->within = 30);
    FAIL_IF_NOT_NULL(s->sm_lists[DETECT_SM_LIST_MATCH]);

    s = SigInit(de_ctx, "alert tcp any any -> any any (msg:"
                        "\" Test uricontent and content\"; "
                        "uricontent:\"foo\"; content:\"bar\";"
                        " depth:10; offset: 5; uricontent:"
                        "\"two_uricontents\"; within:30; sid:1;)");

    FAIL_IF_NULL(s);
    FAIL_IF_NULL(s->sm_lists[g_http_uri_buffer_id]);
    FAIL_IF_NULL(s->sm_lists[DETECT_SM_LIST_PMATCH]);
    FAIL_IF_NOT(((DetectContentData *)s->sm_lists[DETECT_SM_LIST_PMATCH]->ctx)->depth = 15);
    FAIL_IF_NOT(((DetectContentData *)s->sm_lists[DETECT_SM_LIST_PMATCH]->ctx)->offset = 5);
    FAIL_IF_NOT(((DetectContentData *)s->sm_lists_tail[g_http_uri_buffer_id]->ctx)->within = 30);
    FAIL_IF_NOT_NULL(s->sm_lists[DETECT_SM_LIST_MATCH]);

    s = SigInit(de_ctx, "alert tcp any any -> any any (msg:"
                        "\" Test uricontent and content\"; "
                        "uricontent:\"foo\"; content:\"bar\";"
                        " depth:10; offset: 5; content:"
                        "\"two_contents\"; distance:30; sid:1;)");

    FAIL_IF_NULL(s);
    FAIL_IF_NULL(s->sm_lists[g_http_uri_buffer_id]);
    FAIL_IF_NULL(s->sm_lists[DETECT_SM_LIST_PMATCH]);
    FAIL_IF_NOT(((DetectContentData *)s->sm_lists[DETECT_SM_LIST_PMATCH]->ctx)->depth = 15);
    FAIL_IF_NOT(((DetectContentData *)s->sm_lists[DETECT_SM_LIST_PMATCH]->ctx)->offset = 5);
    FAIL_IF_NOT(((DetectContentData *)s->sm_lists_tail[DETECT_SM_LIST_PMATCH]->ctx)->distance = 30);
    FAIL_IF_NOT_NULL(s->sm_lists[DETECT_SM_LIST_MATCH]);

    s = SigInit(de_ctx, "alert tcp any any -> any any (msg:"
                        "\" Test uricontent and content\"; "
                        "uricontent:\"foo\"; content:\"bar\";"
                        " depth:10; offset: 5; uricontent:"
                        "\"two_uricontents\"; distance:30; sid:1;)");

    FAIL_IF_NULL(s);
    FAIL_IF_NULL(s->sm_lists[g_http_uri_buffer_id]);
    FAIL_IF_NULL(s->sm_lists[DETECT_SM_LIST_PMATCH]);
    FAIL_IF_NOT(((DetectContentData *)s->sm_lists[DETECT_SM_LIST_PMATCH]->ctx)->depth = 15);
    FAIL_IF_NOT(((DetectContentData *)s->sm_lists[DETECT_SM_LIST_PMATCH]->ctx)->offset = 5);
    FAIL_IF_NOT(((DetectContentData *)s->sm_lists_tail[g_http_uri_buffer_id]->ctx)->distance = 30);
    FAIL_IF_NOT_NULL(s->sm_lists[DETECT_SM_LIST_MATCH]);

    s = SigInit(de_ctx, "alert tcp any any -> any any (msg:"
                        "\" Test uricontent and content\"; "
                        "uricontent:\"foo\"; content:\"bar\";"
                        " depth:10; offset: 5; uricontent:"
                        "\"two_uricontents\"; distance:30; "
                        "within:60; content:\"two_contents\";"
                        " within:70; distance:45; sid:1;)");
    FAIL_IF_NULL(s);

    FAIL_IF_NULL(s->sm_lists[g_http_uri_buffer_id]);
    FAIL_IF_NULL(s->sm_lists[DETECT_SM_LIST_PMATCH]);
    FAIL_IF_NOT(((DetectContentData *)s->sm_lists[DETECT_SM_LIST_PMATCH]->ctx)->depth = 15);
    FAIL_IF_NOT(((DetectContentData *)s->sm_lists[DETECT_SM_LIST_PMATCH]->ctx)->offset = 5);
    FAIL_IF_NOT(((DetectContentData *)s->sm_lists_tail[g_http_uri_buffer_id]->ctx)->distance = 30);
    FAIL_IF_NOT(((DetectContentData *)s->sm_lists_tail[g_http_uri_buffer_id]->ctx)->within = 60);
    FAIL_IF_NOT(((DetectContentData *)s->sm_lists_tail[DETECT_SM_LIST_PMATCH]->ctx)->distance = 45);
    FAIL_IF_NOT(((DetectContentData *)s->sm_lists_tail[DETECT_SM_LIST_PMATCH]->ctx)->within = 70);
    FAIL_IF_NOT_NULL(s->sm_lists[DETECT_SM_LIST_MATCH]);

    DetectEngineCtxFree(de_ctx);
    PASS;
}

/**
 * \test Test content for dce sig.
 */
static int DetectUriSigTest03(void)
{
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    de_ctx->flags |= DE_QUIET;

    Signature *s = DetectEngineAppendSig(de_ctx, "alert udp any any -> any any "
                                                 "(msg:\"test\"; uricontent:\"\"; sid:238012;)");
    FAIL_IF_NOT_NULL(s);

    DetectEngineCtxFree(de_ctx);
    PASS;
}

/**
 * \test Test content for dce sig.
 */
static int DetectUriSigTest04(void)
{
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    de_ctx->flags |= DE_QUIET;

    Signature *s = DetectEngineAppendSig(de_ctx, "alert udp any any -> any any "
                                                 "(msg:\"test\"; uricontent:\"; sid:238012;)");
    FAIL_IF_NOT_NULL(s);

    DetectEngineCtxFree(de_ctx);
    PASS;
}

/**
 * \test Test content for dce sig.
 */
static int DetectUriSigTest05(void)
{
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    de_ctx->flags |= DE_QUIET;

    Signature *s = DetectEngineAppendSig(de_ctx, "alert udp any any -> any any "
                                                 "(msg:\"test\"; uricontent:\"boo; sid:238012;)");
    FAIL_IF_NOT_NULL(s);

    DetectEngineCtxFree(de_ctx);
    PASS;
}

/**
 * \test Test content for dce sig.
 */
static int DetectUriSigTest06(void)
{
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    de_ctx->flags |= DE_QUIET;

    Signature *s = DetectEngineAppendSig(de_ctx, "alert udp any any -> any any "
                                                 "(msg:\"test\"; uricontent:boo\"; sid:238012;)");
    FAIL_IF_NOT_NULL(s);

    DetectEngineCtxFree(de_ctx);
    PASS;
}

/**
 * \test Parsing test
 */
static int DetectUriSigTest07(void)
{
    DetectContentData *ud = 0;
    Signature *s = NULL;

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);

    de_ctx->flags |= DE_QUIET;
    s = DetectEngineAppendSig(de_ctx, "alert udp any any -> any any "
                                      "(msg:\"test\"; uricontent:    !\"boo\"; sid:238012;)");
    FAIL_IF_NULL(s);

    FAIL_IF_NULL(s->sm_lists_tail[g_http_uri_buffer_id]);
    FAIL_IF_NULL(s->sm_lists_tail[g_http_uri_buffer_id]->ctx);

    ud = (DetectContentData *)s->sm_lists_tail[g_http_uri_buffer_id]->ctx;
    FAIL_IF_NOT(strncmp("boo", (char *)ud->content, ud->content_len) == 0);

    DetectEngineCtxFree(de_ctx);
    PASS;
}


/**
 * \test Parsing test
 */
static int DetectUriContentParseTest08(void)
{
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    de_ctx->flags |= DE_QUIET;

    Signature *s = DetectEngineAppendSig(de_ctx, "alert udp any any -> any any "
                                                 "(msg:\"test\"; uricontent:\"|\"; sid:1;)");
    FAIL_IF_NOT_NULL(s);

    DetectEngineCtxFree(de_ctx);
    PASS;
}

/**
 * \test Parsing test
 */
static int DetectUriContentParseTest09(void)
{
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    de_ctx->flags |= DE_QUIET;

    Signature *s = DetectEngineAppendSig(de_ctx, "alert udp any any -> any any "
                                                 "(msg:\"test\"; uricontent:\"|af\"; sid:1;)");
    FAIL_IF_NOT_NULL(s);

    DetectEngineCtxFree(de_ctx);
    PASS;
}

/**
 * \test Parsing test
 */
static int DetectUriContentParseTest10(void)
{
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    de_ctx->flags |= DE_QUIET;

    Signature *s = DetectEngineAppendSig(de_ctx, "alert udp any any -> any any "
                                                 "(msg:\"test\"; uricontent:\"af|\"; sid:1;)");
    FAIL_IF_NOT_NULL(s);

    DetectEngineCtxFree(de_ctx);
    PASS;
}

/**
 * \test Parsing test
 */
static int DetectUriContentParseTest11(void)
{
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    de_ctx->flags |= DE_QUIET;

    Signature *s = DetectEngineAppendSig(de_ctx, "alert udp any any -> any any "
                                                 "(msg:\"test\"; uricontent:\"|af|\"; sid:1;)");
    FAIL_IF_NULL(s);

    DetectEngineCtxFree(de_ctx);
    PASS;
}

/**
 * \test Parsing test
 */
static int DetectUriContentParseTest12(void)
{
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    de_ctx->flags |= DE_QUIET;

    Signature *s = DetectEngineAppendSig(de_ctx, "alert udp any any -> any any "
                                                 "(msg:\"test\"; uricontent:\"aast|\"; sid:1;)");
    FAIL_IF_NOT_NULL(s);

    DetectEngineCtxFree(de_ctx);
    PASS;
}

/**
 * \test Parsing test
 */
static int DetectUriContentParseTest13(void)
{
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    de_ctx->flags |= DE_QUIET;

    Signature *s = DetectEngineAppendSig(de_ctx, "alert udp any any -> any any "
                                                 "(msg:\"test\"; uricontent:\"aast|af\"; sid:1;)");
    FAIL_IF_NOT_NULL(s);

    DetectEngineCtxFree(de_ctx);
    PASS;
}

/**
 * \test Parsing test
 */
static int DetectUriContentParseTest14(void)
{
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    de_ctx->flags |= DE_QUIET;

    Signature *s = DetectEngineAppendSig(de_ctx, "alert udp any any -> any any "
                                                 "(msg:\"test\"; uricontent:\"aast|af|\"; sid:1;)");
    FAIL_IF_NULL(s);

    DetectEngineCtxFree(de_ctx);
    PASS;
}

/**
 * \test Parsing test
 */
static int DetectUriContentParseTest15(void)
{
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    de_ctx->flags |= DE_QUIET;

    Signature *s = DetectEngineAppendSig(de_ctx, "alert udp any any -> any any "
                                                 "(msg:\"test\"; uricontent:\"|af|asdf\"; sid:1;)");
    FAIL_IF_NULL(s);

    DetectEngineCtxFree(de_ctx);
    PASS;
}

/**
 * \test Parsing test
 */
static int DetectUriContentParseTest16(void)
{
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    de_ctx->flags |= DE_QUIET;

    Signature *s = DetectEngineAppendSig(de_ctx, "alert udp any any -> any any "
                                                 "(msg:\"test\"; uricontent:\"|af|af|\"; sid:1;)");
    FAIL_IF_NOT_NULL(s);

    DetectEngineCtxFree(de_ctx);
    PASS;
}

/**
 * \test Parsing test
 */
static int DetectUriContentParseTest17(void)
{
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    de_ctx->flags |= DE_QUIET;

    Signature *s =
            DetectEngineAppendSig(de_ctx, "alert udp any any -> any any "
                                          "(msg:\"test\"; uricontent:\"|af|af|af\"; sid:1;)");
    FAIL_IF_NOT_NULL(s);

    DetectEngineCtxFree(de_ctx);
    PASS;
}

/**
 * \test Parsing test
 */
static int DetectUriContentParseTest18(void)
{
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    de_ctx->flags |= DE_QUIET;

    Signature *s =
            DetectEngineAppendSig(de_ctx, "alert udp any any -> any any "
                                          "(msg:\"test\"; uricontent:\"|af|af|af|\"; sid:1;)");
    FAIL_IF_NULL(s);

    DetectEngineCtxFree(de_ctx);
    PASS;
}

/**
 * \test Parsing test
 */
static int DetectUriContentParseTest19(void)
{
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    de_ctx->flags |= DE_QUIET;

    Signature *s = DetectEngineAppendSig(de_ctx, "alert tcp any any -> any any "
                                                 "(msg:\"test\"; uricontent:\"\"; sid:1;)");
    FAIL_IF_NOT_NULL(s);

    DetectEngineCtxFree(de_ctx);
    PASS;
}

static int DetectUricontentIsdataatParseTest(void)
{
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    de_ctx->flags |= DE_QUIET;

    Signature *s = DetectEngineAppendSig(de_ctx,
            "alert tcp any any -> any any ("
            "uricontent:\"one\"; "
            "isdataat:!4,relative; sid:1;)");
    FAIL_IF_NULL(s);

    SigMatch *sm = s->init_data->smlists_tail[g_http_uri_buffer_id];
    FAIL_IF_NULL(sm);
    FAIL_IF_NOT(sm->type == DETECT_ISDATAAT);

    DetectIsdataatData *data = (DetectIsdataatData *)sm->ctx;
    FAIL_IF_NOT(data->flags & ISDATAAT_RELATIVE);
    FAIL_IF_NOT(data->flags & ISDATAAT_NEGATED);
    FAIL_IF(data->flags & ISDATAAT_RAWBYTES);

    DetectEngineCtxFree(de_ctx);
    PASS;
}

static void DetectUricontentRegisterTests(void)
{
    UtRegisterTest("DetectUriSigTest01", DetectUriSigTest01);
    UtRegisterTest("DetectUriSigTest02 - Modifiers", DetectUriSigTest02);
    UtRegisterTest("DetectUriSigTest03", DetectUriSigTest03);
    UtRegisterTest("DetectUriSigTest04", DetectUriSigTest04);
    UtRegisterTest("DetectUriSigTest05", DetectUriSigTest05);
    UtRegisterTest("DetectUriSigTest06", DetectUriSigTest06);
    UtRegisterTest("DetectUriSigTest07", DetectUriSigTest07);

    UtRegisterTest("DetectUriContentParseTest08", DetectUriContentParseTest08);
    UtRegisterTest("DetectUriContentParseTest09", DetectUriContentParseTest09);
    UtRegisterTest("DetectUriContentParseTest10", DetectUriContentParseTest10);
    UtRegisterTest("DetectUriContentParseTest11", DetectUriContentParseTest11);
    UtRegisterTest("DetectUriContentParseTest12", DetectUriContentParseTest12);
    UtRegisterTest("DetectUriContentParseTest13", DetectUriContentParseTest13);
    UtRegisterTest("DetectUriContentParseTest14", DetectUriContentParseTest14);
    UtRegisterTest("DetectUriContentParseTest15", DetectUriContentParseTest15);
    UtRegisterTest("DetectUriContentParseTest16", DetectUriContentParseTest16);
    UtRegisterTest("DetectUriContentParseTest17", DetectUriContentParseTest17);
    UtRegisterTest("DetectUriContentParseTest18", DetectUriContentParseTest18);
    UtRegisterTest("DetectUriContentParseTest19", DetectUriContentParseTest19);

    UtRegisterTest("DetectUricontentIsdataatParseTest",
            DetectUricontentIsdataatParseTest);
}
#endif /* UNITTESTS */
