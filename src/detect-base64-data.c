/* Copyright (C) 2015 Open Information Security Foundation
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

#include "suricata-common.h"
#include "detect.h"
#include "detect-engine.h"
#include "detect-engine-content-inspection.h"
#include "detect-parse.h"
#include "detect-base64-data.h"
#include "detect-engine-build.h"

#include "util-unittest.h"

static int DetectBase64DataSetup(DetectEngineCtx *, Signature *, const char *);
#ifdef UNITTESTS
static void DetectBase64DataRegisterTests(void);
#endif

void DetectBase64DataRegister(void)
{
    sigmatch_table[DETECT_BASE64_DATA].name = "base64_data";
    sigmatch_table[DETECT_BASE64_DATA].desc =
        "Content match base64 decoded data.";
    sigmatch_table[DETECT_BASE64_DATA].url =
        "/rules/base64-keywords.html#base64-data";
    sigmatch_table[DETECT_BASE64_DATA].Setup = DetectBase64DataSetup;
#ifdef UNITTESTS
    sigmatch_table[DETECT_BASE64_DATA].RegisterTests =
        DetectBase64DataRegisterTests;
#endif
    sigmatch_table[DETECT_BASE64_DATA].flags |= SIGMATCH_NOOPT;
}

static int DetectBase64DataSetup(DetectEngineCtx *de_ctx, Signature *s,
    const char *str)
{
    SigMatch *pm = NULL;

    /* Check for a preceding base64_decode. */
    pm = DetectGetLastSMFromLists(s, DETECT_BASE64_DECODE, -1);
    if (pm == NULL) {
        SCLogError("\"base64_data\" keyword seen without preceding base64_decode.");
        return -1;
    }

    s->init_data->list = DETECT_SM_LIST_BASE64_DATA;
    return 0;
}

#ifdef UNITTESTS

static int g_file_data_buffer_id = 0;

static int DetectBase64DataSetupTest01(void)
{
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);

    de_ctx->flags |= DE_QUIET;
    Signature *s = DetectEngineAppendSig(de_ctx,
            "alert smtp any any -> any any (msg:\"DetectBase64DataSetupTest\"; "
            "base64_decode; base64_data; content:\"content\"; sid:1; rev:1;)");
    FAIL_IF_NULL(s);

    SigMatch *sm = s->init_data->smlists[DETECT_SM_LIST_PMATCH];
    FAIL_IF_NULL(sm);
    FAIL_IF_NOT(sm->type == DETECT_BASE64_DECODE);
    FAIL_IF_NULL(s->init_data->smlists[DETECT_SM_LIST_BASE64_DATA]);

    DetectEngineCtxFree(de_ctx);
    PASS;
}

/**
 * \test Test that the list can be changed to post-detection lists
 *     after the base64 keyword.
 */
static int DetectBase64DataSetupTest04(void)
{
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);

    de_ctx->flags |= DE_QUIET;
    Signature *s = DetectEngineAppendSig(de_ctx,
            "alert tcp any any -> any any (msg:\"some b64thing\"; flow:established,from_server; "
            "file_data; content:\"sometext\"; fast_pattern; base64_decode:relative; base64_data; "
            "content:\"foobar\"; nocase; tag:session,120,seconds; sid:1111111; rev:1;)");
    FAIL_IF_NULL(s);

    DetectEngineCtxFree(de_ctx);
    PASS;
}

static void DetectBase64DataRegisterTests(void)
{
    g_file_data_buffer_id = DetectBufferTypeGetByName("file_data");

    UtRegisterTest("DetectBase64DataSetupTest01", DetectBase64DataSetupTest01);
    UtRegisterTest("DetectBase64DataSetupTest04", DetectBase64DataSetupTest04);
}
#endif /* UNITTESTS */