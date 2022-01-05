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
#include "stream-tcp-reassemble.h"

/**
 * \brief Helper function to print a DetectContentData
 */
static void DetectUricontentPrint(DetectContentData *cd)
{
    int i = 0;
    if (cd == NULL) {
        SCLogDebug("Detect UricontentData \"cd\" is NULL");
        return;
    }
    char *tmpstr = SCMalloc(sizeof(char) * cd->content_len + 1);
    if (unlikely(tmpstr == NULL))
        return;

    if (tmpstr != NULL) {
        for (i = 0; i < cd->content_len; i++) {
            if (isprint(cd->content[i]))
                tmpstr[i] = cd->content[i];
            else
                tmpstr[i] = '.';
        }
        tmpstr[i] = '\0';
        SCLogDebug("Uricontent: \"%s\"", tmpstr);
        SCFree(tmpstr);
    } else {
        SCLogDebug("Uricontent: ");
        for (i = 0; i < cd->content_len; i++)
            SCLogDebug("%c", cd->content[i]);
    }

    SCLogDebug("Uricontent_id: %"PRIu32, cd->id);
    SCLogDebug("Uricontent_len: %"PRIu16, cd->content_len);
    SCLogDebug("Depth: %"PRIu16, cd->depth);
    SCLogDebug("Offset: %"PRIu16, cd->offset);
    SCLogDebug("Within: %"PRIi32, cd->within);
    SCLogDebug("Distance: %"PRIi32, cd->distance);
    SCLogDebug("flags: %u ", cd->flags);
    SCLogDebug("negated: %s ",
            cd->flags & DETECT_CONTENT_NEGATED ? "true" : "false");
    SCLogDebug("relative match next: %s ",
            cd->flags & DETECT_CONTENT_RELATIVE_NEXT ? "true" : "false");
    SCLogDebug("-----------");
}

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

    UtRegisterTest("DetectUricontentIsdataatParseTest",
            DetectUricontentIsdataatParseTest);
}
#endif /* UNITTESTS */
