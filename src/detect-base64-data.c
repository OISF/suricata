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
#include "detect-engine-content-inspection.h"
#include "detect-parse.h"

#include "util-unittest.h"

static int DetectBase64DataSetup(DetectEngineCtx *, Signature *, char *);
static void DetectBase64DataRegisterTests(void);

void DetectBase64DataRegister(void)
{
    sigmatch_table[DETECT_BASE64_DATA].name = "base64_data";
    sigmatch_table[DETECT_BASE64_DATA].desc =
        "Content match base64 decoded data.";
    sigmatch_table[DETECT_BASE64_DATA].url =
        "https://redmine.openinfosecfoundation.org/projects/suricata/wiki/Payload_keywords#base64_data";
    sigmatch_table[DETECT_BASE64_DATA].Setup = DetectBase64DataSetup;
    sigmatch_table[DETECT_BASE64_DATA].RegisterTests =
        DetectBase64DataRegisterTests;

    sigmatch_table[DETECT_BASE64_DATA].flags |= SIGMATCH_NOOPT;
}

static int DetectBase64DataSetup(DetectEngineCtx *de_ctx, Signature *s,
    char *str)
{
    SigMatch *pm = NULL;

    /* Check for a preceding base64_decode. */
    pm = SigMatchGetLastSMFromLists(s, 28,
        DETECT_BASE64_DECODE, s->sm_lists_tail[DETECT_SM_LIST_PMATCH],
        DETECT_BASE64_DECODE, s->sm_lists_tail[DETECT_SM_LIST_UMATCH],
        DETECT_BASE64_DECODE, s->sm_lists_tail[DETECT_SM_LIST_HCBDMATCH],
        DETECT_BASE64_DECODE, s->sm_lists_tail[DETECT_SM_LIST_FILEDATA],
        DETECT_BASE64_DECODE, s->sm_lists_tail[DETECT_SM_LIST_HHDMATCH],
        DETECT_BASE64_DECODE, s->sm_lists_tail[DETECT_SM_LIST_HRHDMATCH],
        DETECT_BASE64_DECODE, s->sm_lists_tail[DETECT_SM_LIST_HMDMATCH],
        DETECT_BASE64_DECODE, s->sm_lists_tail[DETECT_SM_LIST_HCDMATCH],
        DETECT_BASE64_DECODE, s->sm_lists_tail[DETECT_SM_LIST_HRUDMATCH],
        DETECT_BASE64_DECODE, s->sm_lists_tail[DETECT_SM_LIST_HSMDMATCH],
        DETECT_BASE64_DECODE, s->sm_lists_tail[DETECT_SM_LIST_HSCDMATCH],
        DETECT_BASE64_DECODE, s->sm_lists_tail[DETECT_SM_LIST_HUADMATCH],
        DETECT_BASE64_DECODE, s->sm_lists_tail[DETECT_SM_LIST_HHHDMATCH],
        DETECT_BASE64_DECODE, s->sm_lists_tail[DETECT_SM_LIST_HRHHDMATCH]);
    if (pm == NULL) {
        SCLogError(SC_ERR_INVALID_SIGNATURE,
            "\"base64_data\" keyword seen without preceding base64_decode.");
        return -1;
    }

    s->list = DETECT_SM_LIST_BASE64_DATA;
    return 0;
}

int DetectBase64DataDoMatch(DetectEngineCtx *de_ctx,
    DetectEngineThreadCtx *det_ctx, Signature *s, Flow *f)
{
    if (det_ctx->base64_decoded_len) {
        return DetectEngineContentInspection(de_ctx, det_ctx, s,
            s->sm_lists[DETECT_SM_LIST_BASE64_DATA], f, det_ctx->base64_decoded,
            det_ctx->base64_decoded_len, 0,
            DETECT_ENGINE_CONTENT_INSPECTION_MODE_BASE64, NULL);
    }

    return 0;
}

#ifdef UNITTESTS

#include "detect-engine.h"

static int DetectBase64DataSetupTest01(void)
{
    DetectEngineCtx *de_ctx = NULL;
    SigMatch *sm;
    int retval = 0;

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx,
        "alert smtp any any -> any any (msg:\"DetectBase64DataSetupTest\"; "
        "base64_decode; base64_data; content:\"content\"; sid:1; rev:1;)");
    if (de_ctx->sig_list == NULL) {
        printf("SigInit failed: ");
        goto end;
    }

    sm = de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH];
    if (sm == NULL) {
        printf("DETECT_SM_LIST_PMATCH should not be NULL: ");
        goto end;
    }
    if (sm->type != DETECT_BASE64_DECODE) {
        printf("sm->type should be DETECT_BASE64_DECODE: ");
        goto end;
    }

    if (de_ctx->sig_list->sm_lists[DETECT_SM_LIST_BASE64_DATA] == NULL) {
        printf("DETECT_SM_LIST_BASE64_DATA should not be NULL: ");
       goto end;
    }

    retval = 1;
end:
    if (de_ctx != NULL) {
        SigGroupCleanup(de_ctx);
        SigCleanSignatures(de_ctx);
        DetectEngineCtxFree(de_ctx);
    }
    return retval;
}

static int DetectBase64DataSetupTest02(void)
{
    DetectEngineCtx *de_ctx = NULL;
    SigMatch *sm;
    int retval = 0;

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx,
        "alert smtp any any -> any any ( "
        "msg:\"DetectBase64DataSetupTest\"; "
        "file_data; "
        "content:\"SGV\"; "
        "base64_decode: bytes 16; "
        "base64_data; "
        "content:\"content\"; "
        "sid:1; rev:1;)");
    if (de_ctx->sig_list == NULL) {
        printf("SigInit failed: ");
        goto end;
    }

    sm = de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH];
    if (sm != NULL) {
        printf("DETECT_SM_LIST_PMATCH is not NULL: ");
        goto end;
    }

    sm = de_ctx->sig_list->sm_lists[DETECT_SM_LIST_FILEDATA];
    if (sm == NULL) {
        printf("DETECT_SM_LIST_FILEDATA is NULL: ");
        goto end;
    }

    sm = de_ctx->sig_list->sm_lists[DETECT_SM_LIST_BASE64_DATA];
    if (sm == NULL) {
        printf("DETECT_SM_LIST_BASE64_DATA is NULL: ");
        goto end;
    }

    retval = 1;
end:
    if (de_ctx != NULL) {
        SigGroupCleanup(de_ctx);
        SigCleanSignatures(de_ctx);
        DetectEngineCtxFree(de_ctx);
    }
    return retval;
}

static int DetectBase64DataSetupTest03(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int retval = 0;

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx,
        "alert smtp any any -> any any ( "
        "msg:\"DetectBase64DataSetupTest\"; "
        "base64_decode: bytes 16; "
        "base64_data; "
        "content:\"content\"; "
        "file_data; "
        "content:\"SGV\"; "
        "sid:1; rev:1;)");
    if (de_ctx->sig_list != NULL) {
        printf("SigInit should have failed: ");
        goto end;
    }

    retval = 1;
end:
    if (de_ctx != NULL) {
        SigGroupCleanup(de_ctx);
        SigCleanSignatures(de_ctx);
        DetectEngineCtxFree(de_ctx);
    }
    return retval;
}

#endif

static void DetectBase64DataRegisterTests(void)
{
#ifdef UNITTESTS
    UtRegisterTest("DetectBase64DataSetupTest01", DetectBase64DataSetupTest01,
        1);
    UtRegisterTest("DetectBase64DataSetupTest02", DetectBase64DataSetupTest02,
        1);
    UtRegisterTest("DetectBase64DataSetupTest03", DetectBase64DataSetupTest03,
        1);
#endif /* UNITTESTS */
}
