/* Copyright (C) 2007-2011 Open Information Security Foundation
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
 * \author Victor Julien <victor@inliniac.net>
 *
 */

#include "suricata-common.h"
#include "threads.h"
#include "debug.h"
#include "decode.h"

#include "detect.h"
#include "detect-parse.h"

#include "detect-engine.h"
#include "detect-engine-mpm.h"
#include "detect-engine-state.h"

#include "detect-engine-filedata-smtp.h"
#include "detect-engine-hsbd.h"
#include "detect-file-data.h"

#include "flow.h"
#include "flow-var.h"
#include "flow-util.h"

#include "util-debug.h"
#include "util-spm-bm.h"
#include "util-unittest.h"
#include "util-unittest-helper.h"

static int DetectFiledataSetup (DetectEngineCtx *, Signature *, const char *);
static void DetectFiledataRegisterTests(void);
static void DetectFiledataSetupCallback(Signature *s);
static int g_file_data_buffer_id = 0;

/**
 * \brief Registration function for keyword: file_data
 */
void DetectFiledataRegister(void)
{
    sigmatch_table[DETECT_FILE_DATA].name = "file_data";
    sigmatch_table[DETECT_FILE_DATA].desc = "make content keywords match on HTTP response body";
    sigmatch_table[DETECT_FILE_DATA].url = DOC_URL DOC_VERSION "/rules/http-keywords.html#file-data";
    sigmatch_table[DETECT_FILE_DATA].Match = NULL;
    sigmatch_table[DETECT_FILE_DATA].Setup = DetectFiledataSetup;
    sigmatch_table[DETECT_FILE_DATA].Free  = NULL;
    sigmatch_table[DETECT_FILE_DATA].RegisterTests = DetectFiledataRegisterTests;
    sigmatch_table[DETECT_FILE_DATA].flags = SIGMATCH_NOOPT;

    DetectAppLayerMpmRegister("file_data", SIG_FLAG_TOSERVER, 2,
            PrefilterTxSmtpFiledataRegister);
    DetectAppLayerMpmRegister("file_data", SIG_FLAG_TOCLIENT, 2,
            PrefilterTxHttpResponseBodyRegister);

    DetectAppLayerInspectEngineRegister("file_data",
            ALPROTO_HTTP, SIG_FLAG_TOCLIENT, HTP_RESPONSE_BODY,
            DetectEngineInspectHttpServerBody);
    DetectAppLayerInspectEngineRegister("file_data",
            ALPROTO_SMTP, SIG_FLAG_TOSERVER, 0,
            DetectEngineInspectSMTPFiledata);

    DetectBufferTypeRegisterSetupCallback("file_data",
            DetectFiledataSetupCallback);

    DetectBufferTypeSetDescriptionByName("file_data",
            "http response body or smtp attachments data");

    g_file_data_buffer_id = DetectBufferTypeGetByName("file_data");
}

/**
 * \brief this function is used to parse filedata options
 * \brief into the current signature
 *
 * \param de_ctx pointer to the Detection Engine Context
 * \param s pointer to the Current Signature
 * \param str pointer to the user provided "filestore" option
 *
 * \retval 0 on Success
 * \retval -1 on Failure
 */
static int DetectFiledataSetup (DetectEngineCtx *de_ctx, Signature *s, const char *str)
{
    SCEnter();

    if (!DetectProtoContainsProto(&s->proto, IPPROTO_TCP) ||
        (s->alproto != ALPROTO_UNKNOWN && s->alproto != ALPROTO_HTTP &&
        s->alproto != ALPROTO_SMTP)) {
        SCLogError(SC_ERR_CONFLICTING_RULE_KEYWORDS, "rule contains conflicting keywords.");
        return -1;
    }

    if (s->alproto == ALPROTO_HTTP && (s->init_data->init_flags & SIG_FLAG_INIT_FLOW) &&
        (s->flags & SIG_FLAG_TOSERVER) && !(s->flags & SIG_FLAG_TOCLIENT)) {
        SCLogError(SC_ERR_INVALID_SIGNATURE, "Can't use file_data with "
                "flow:to_server or flow:from_client with http.");
        return -1;
    }

    if (s->alproto == ALPROTO_SMTP && (s->init_data->init_flags & SIG_FLAG_INIT_FLOW) &&
        !(s->flags & SIG_FLAG_TOSERVER) && (s->flags & SIG_FLAG_TOCLIENT)) {
        SCLogError(SC_ERR_INVALID_SIGNATURE, "Can't use file_data with "
                "flow:to_client or flow:from_server with smtp.");
        return -1;
    }

    s->init_data->list = DetectBufferTypeGetByName("file_data");
    return 0;
}

static void DetectFiledataSetupCallback(Signature *s)
{
    if (s->alproto == ALPROTO_HTTP || s->alproto == ALPROTO_UNKNOWN) {
        AppLayerHtpEnableRequestBodyCallback();
    }
    if (s->alproto == ALPROTO_HTTP) {
        s->mask |= SIG_MASK_REQUIRE_HTTP_STATE;
    } else if (s->alproto == ALPROTO_SMTP) {
        s->mask |= SIG_MASK_REQUIRE_SMTP_STATE;
    }

    SCLogDebug("callback invoked by %u", s->id);
}

#ifdef UNITTESTS
#include "detect-isdataat.h"

static int DetectFiledataParseTest01(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx,
                               "alert smtp any any -> any any "
                               "(msg:\"test\"; file_data; content:\"abc\"; sid:1;)");
    if (de_ctx->sig_list == NULL) {
        printf("sig parse failed: ");
        goto end;
    }

    if (de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH] != NULL) {
        printf("content is still in FILEDATA list: ");
        goto end;
    }

    if (de_ctx->sig_list->sm_lists[g_file_data_buffer_id] == NULL) {
       printf("content not in FILEDATA list: ");
       goto end;
    }

    result = 1;
end:
    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);

    return result;
}

static int DetectFiledataParseTest02(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx,
                               "alert tcp any any -> any any "
                               "(msg:\"test\"; file_data; content:\"abc\"; sid:1;)");
    if (de_ctx->sig_list == NULL) {
        printf("sig parse failed: ");
        goto end;
    }

    if (de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH] != NULL) {
        printf("content is still in PMATCH list: ");
        goto end;
    }

    if (de_ctx->sig_list->sm_lists[g_file_data_buffer_id] == NULL) {
       printf("content not in FILEDATA list: ");
       goto end;
    }

    result = 1;
end:
    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);

    return result;
}

static int DetectFiledataParseTest03(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx,
                               "alert tcp any any -> any 25 "
                               "(msg:\"test\"; flow:to_server,established; file_data; content:\"abc\"; sid:1;)");
    if (de_ctx->sig_list == NULL) {
        printf("sig parse failed: ");
        goto end;
    }

    if (de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH] != NULL) {
        printf("content is still in PMATCH list: ");
        goto end;
    }

    if (de_ctx->sig_list->sm_lists[g_file_data_buffer_id] == NULL) {
       printf("content not in FILEDATA list: ");
       goto end;
    }

    result = 1;
end:
    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);

    return result;
}

/**
 * \test Test the file_data fails with flow:to_server.
 */
static int DetectFiledataParseTest04(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx,
                               "alert smtp any any -> any any "
                               "(msg:\"test\"; flow:to_client,established; file_data; content:\"abc\"; sid:1;)");
    if (de_ctx->sig_list == NULL) {
        result = 1;
    }

end:
    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);

    return result;
}

/**
 * \test Test the file_data fails with flow:to_server.
 */
static int DetectFiledataParseTest05(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx,
                               "alert http any any -> any any "
                               "(msg:\"test\"; flow:to_server,established; file_data; content:\"abc\"; sid:1;)");
    if (de_ctx->sig_list == NULL) {
        result = 1;
    }

end:
    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);

    return result;
}

static int DetectFiledataIsdataatParseTest1(void)
{
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    de_ctx->flags |= DE_QUIET;

    Signature *s = DetectEngineAppendSig(de_ctx,
            "alert tcp any any -> any any ("
            "file_data; content:\"one\"; "
            "isdataat:!4,relative; sid:1;)");
    FAIL_IF_NULL(s);

    SigMatch *sm = s->init_data->smlists[g_file_data_buffer_id];
    FAIL_IF_NULL(sm);
    FAIL_IF_NOT(sm->type == DETECT_CONTENT);
    sm = sm->next;
    FAIL_IF_NULL(sm);
    FAIL_IF_NOT(sm->type == DETECT_ISDATAAT);

    DetectIsdataatData *data = (DetectIsdataatData *)sm->ctx;
    FAIL_IF_NOT(data->flags & ISDATAAT_RELATIVE);
    FAIL_IF_NOT(data->flags & ISDATAAT_NEGATED);
    FAIL_IF(data->flags & ISDATAAT_RAWBYTES);

    DetectEngineCtxFree(de_ctx);
    PASS;
}

static int DetectFiledataIsdataatParseTest2(void)
{
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    de_ctx->flags |= DE_QUIET;

    Signature *s = DetectEngineAppendSig(de_ctx,
            "alert tcp any any -> any any ("
            "file_data; "
            "isdataat:!4,relative; sid:1;)");
    FAIL_IF_NULL(s);

    SigMatch *sm = s->init_data->smlists_tail[g_file_data_buffer_id];
    FAIL_IF_NULL(sm);
    FAIL_IF_NOT(sm->type == DETECT_ISDATAAT);

    DetectIsdataatData *data = (DetectIsdataatData *)sm->ctx;
    FAIL_IF_NOT(data->flags & ISDATAAT_RELATIVE);
    FAIL_IF_NOT(data->flags & ISDATAAT_NEGATED);
    FAIL_IF(data->flags & ISDATAAT_RAWBYTES);

    DetectEngineCtxFree(de_ctx);
    PASS;
}

#endif

void DetectFiledataRegisterTests(void)
{
#ifdef UNITTESTS
    UtRegisterTest("DetectFiledataParseTest01", DetectFiledataParseTest01);
    UtRegisterTest("DetectFiledataParseTest02", DetectFiledataParseTest02);
    UtRegisterTest("DetectFiledataParseTest03", DetectFiledataParseTest03);
    UtRegisterTest("DetectFiledataParseTest04", DetectFiledataParseTest04);
    UtRegisterTest("DetectFiledataParseTest05", DetectFiledataParseTest05);

    UtRegisterTest("DetectFiledataIsdataatParseTest1",
            DetectFiledataIsdataatParseTest1);
    UtRegisterTest("DetectFiledataIsdataatParseTest2",
            DetectFiledataIsdataatParseTest2);
#endif
}
