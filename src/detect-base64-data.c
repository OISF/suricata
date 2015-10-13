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
    sigmatch_table[DETECT_BASE64_DATA].Setup = DetectBase64DataSetup;
    sigmatch_table[DETECT_BASE64_DATA].RegisterTests =
        DetectBase64DataRegisterTests;

    /* sigmatch_table[DETECT_BASE64_DATA].flags |= SIGMATCH_PAYLOAD; */
    sigmatch_table[DETECT_BASE64_DATA].flags |= SIGMATCH_NOOPT;
}

static int DetectBase64DataSetup(DetectEngineCtx *de_ctx, Signature *s,
    char *str)
{
    s->list = DETECT_SM_LIST_BASE64_DATA;
    return 0;
}

int DetectBase64DataDoMatch(DetectEngineCtx *de_ctx,
    DetectEngineThreadCtx *det_ctx, Signature *s, Flow *f)
{
    if (det_ctx->base64_decoded_len) {
        return DetectEngineContentInspection(de_ctx, det_ctx, s,
            s->sm_lists[DETECT_SM_LIST_BASE64_DATA], f, det_ctx->base64_decoded,
            det_ctx->base64_decoded_len, 0, 0, NULL);
    }

    return 0;
}

#ifdef UNITTESTS

#include "detect-engine.h"

static int DetectBase64DataSetupTest01(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int retval = 0;

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx,
        "alert smtp any any -> any any (msg:\"DetectBase64DataSetupTest\"; "
        "base64_data; content:\"content\"; sid:1; rev:1;)");
    if (de_ctx->sig_list == NULL) {
        printf("SigInit failed: ");
        goto end;
    }

    if (de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH] != NULL) {
        printf("Content is still in PMATCH list: ");
        goto end;
    }

    if (de_ctx->sig_list->sm_lists[DETECT_SM_LIST_BASE64_DATA] == NULL) {
       printf("Content not in BASE64_DATA list: ");
       goto end;
    }

    retval = 1;
end:
    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
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
        printf("Content is still in PMATCH list: ");
        goto end;
    }

    sm = de_ctx->sig_list->sm_lists[DETECT_SM_LIST_FILEDATA];
    if (sm == NULL) {
        printf("sm not in DETECT_SM_LIST_FILEDATA: ");
        goto end;
    }

    sm = de_ctx->sig_list->sm_lists[DETECT_SM_LIST_BASE64_DATA];
    if (sm == NULL) {
       printf("sm not in DETECT_SM_LIST_BASE64_DATA: ");
       goto end;
    }

    retval = 1;
end:
    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
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
#endif /* UNITTESTS */
}
