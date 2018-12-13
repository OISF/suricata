/* Copyright (C) 2007-2018 Open Information Security Foundation
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
 * \author Giuseppe Longo <giuseppelng@gmail.com>
 * \author Victor Julien <victor@inliniac.net>
 *
 */

#ifdef UNITTESTS

#include "../stream-tcp.h"
#include "../detect.h"
#include "../detect-isdataat.h"

static int DetectEngineSMTPFiledataTest01(void)
{
    uint8_t mimemsg[] = {0x4D, 0x49, 0x4D, 0x45, 0x2D, 0x56, 0x65, 0x72,
                0x73, 0x69, 0x6F, 0x6E, 0x3A, 0x20, 0x31, 0x2E,
                0x30, 0x0D, 0x0A, 0x43, 0x6F, 0x6E, 0x74, 0x65,
                0x6E, 0x74, 0x2D, 0x54, 0x79, 0x70, 0x65, 0x3A,
                0x20, 0x74, 0x65, 0x78, 0x74, 0x2F, 0x70, 0x6C,
                0x61, 0x69, 0x6E, 0x3B, 0x20, 0x63, 0x68, 0x61,
                0x72, 0x73, 0x65, 0x74, 0x3D, 0x55, 0x54, 0x46,
                0x2D, 0x38, 0x3B, 0x0D, 0x0A, 0x43, 0x6F, 0x6E,
                0x74, 0x65, 0x6E, 0x74, 0x2D, 0x54, 0x72, 0x61,
                0x6E, 0x73, 0x66, 0x65, 0x72, 0x2D, 0x45, 0x6E,
                0x63, 0x6F, 0x64, 0x69, 0x6E, 0x67, 0x3A, 0x20,
                0x37, 0x62, 0x69, 0x74, 0x0D, 0x0A, 0x43, 0x6F,
                0x6E, 0x74, 0x65, 0x6E, 0x74, 0x2D, 0x44, 0x69,
                0x73, 0x70, 0x6F, 0x73, 0x69, 0x74, 0x69, 0x6F,
                0x6E, 0x3A, 0x20, 0x61, 0x74, 0x74, 0x61, 0x63,
                0x68, 0x6D, 0x65, 0x6E, 0x74, 0x3B, 0x20, 0x66,
                0x69, 0x6C, 0x65, 0x6E, 0x61, 0x6D, 0x65, 0x3D,
                0x22, 0x74, 0x65, 0x73, 0x74, 0x2E, 0x74, 0x78,
                0x74, 0x22, 0x0D, 0x0A, 0x0D, 0x0A, 0x6d, 0x65,
                0x73, 0x73, 0x61, 0x67, 0x65,};
    uint32_t mimemsg_len = sizeof(mimemsg) - 1;
    TcpSession ssn;
    Packet *p;
    ThreadVars th_v;
    DetectEngineCtx *de_ctx = NULL;
    DetectEngineThreadCtx *det_ctx = NULL;
    SMTPState *smtp_state = NULL;
    Flow f;
    int result = 0;

    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&th_v, 0, sizeof(th_v));
    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    p = UTHBuildPacket(NULL, 0, IPPROTO_TCP);

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;
    f.flags |= FLOW_IPV4;
    f.alstate = SMTPStateAlloc();

    MimeDecParseState *state = MimeDecInitParser(&f, NULL);
    ((MimeDecEntity *)state->stack->top->data)->ctnt_flags = CTNT_IS_ATTACHMENT;
    state->body_begin = 1;

    if (SMTPProcessDataChunk((uint8_t *)mimemsg, sizeof(mimemsg), state) != 0)
        goto end;

    p->flow = &f;
    p->flowflags |= FLOW_PKT_TOSERVER;
    p->flowflags |= FLOW_PKT_ESTABLISHED;
    p->flags |= PKT_HAS_FLOW|PKT_STREAM_EST|PKT_STREAM_EOF;
    f.alproto = ALPROTO_SMTP;

    StreamTcpInitConfig(TRUE);

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx, "alert smtp any any -> any any "
                               "(msg:\"file_data smtp test\"; "
                               "file_data; content:\"message\"; sid:1;)");
    if (de_ctx->sig_list == NULL) {
        goto end;
    }

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    FLOWLOCK_WRLOCK(&f);
    int r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_SMTP,
                                STREAM_TOSERVER | STREAM_START | STREAM_EOF,
                                mimemsg,
                                mimemsg_len);
    if (r != 0) {
        printf("AppLayerParse for smtp failed. Returned %d", r);
        FLOWLOCK_UNLOCK(&f);
        goto end;
    }
    FLOWLOCK_UNLOCK(&f);

    smtp_state = f.alstate;
    if (smtp_state == NULL) {
        printf("no smtp state: ");
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);

    if (!(PacketAlertCheck(p, 1))) {
        printf("sid 1 didn't match but should have\n");
        goto end;
    }

    result = 1;

end:
    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
    if (de_ctx != NULL)
        SigGroupCleanup(de_ctx);
    if (de_ctx != NULL)
        SigCleanSignatures(de_ctx);

    StreamTcpFreeConfig(TRUE);
    FLOW_DESTROY(&f);
    UTHFreePackets(&p, 1);
    return result;
}

static int DetectEngineSMTPFiledataTest02(void)
{
    Signature *s = NULL;
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;

    s = DetectEngineAppendSig(de_ctx, "alert smtp any any -> any any "
                              "(msg:\"file_data smtp test\"; "
                              "file_data; content:\"message\"; sid:1;)");
    if (s == NULL)
        goto end;

    if (s->flags & SIG_FLAG_TOSERVER)
        result = 1;
    else if (s->flags & SIG_FLAG_TOCLIENT)
        printf("s->flags & SIG_FLAG_TOCLIENT");

end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;

}

static int DetectEngineSMTPFiledataTest03(void)
{
    uint8_t mimemsg1[] = {0x65, 0x76,};
    uint8_t mimemsg2[] = {0x69, 0x6C,};
    uint32_t mimemsg1_len = sizeof(mimemsg1) - 1;
    uint32_t mimemsg2_len = sizeof(mimemsg2) - 1;
    TcpSession ssn;
    Packet *p;
    ThreadVars th_v;
    DetectEngineCtx *de_ctx = NULL;
    DetectEngineThreadCtx *det_ctx = NULL;
    SMTPState *smtp_state = NULL;
    Flow f;
    int result = 1;

    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&th_v, 0, sizeof(th_v));
    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    p = UTHBuildPacket(NULL, 0, IPPROTO_TCP);

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;
    f.flags |= FLOW_IPV4;
    f.alstate = SMTPStateAlloc();

    MimeDecParseState *state = MimeDecInitParser(&f, NULL);
    ((MimeDecEntity *)state->stack->top->data)->ctnt_flags = CTNT_IS_ATTACHMENT;
    state->body_begin = 1;

    if (SMTPProcessDataChunk((uint8_t *)mimemsg1, sizeof(mimemsg1), state) != 0)
        goto end;

    if (SMTPProcessDataChunk((uint8_t *)mimemsg2, sizeof(mimemsg2), state) != 0)
        goto end;

    p->flow = &f;
    p->flowflags |= FLOW_PKT_TOSERVER;
    p->flowflags |= FLOW_PKT_ESTABLISHED;
    p->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    f.alproto = ALPROTO_SMTP;

    StreamTcpInitConfig(TRUE);

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx, "alert smtp any any -> any any "
                               "(msg:\"file_data smtp test\"; "
                               "file_data; content:\"evil\"; sid:1;)");
    if (de_ctx->sig_list == NULL) {
        goto end;
    }

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    FLOWLOCK_WRLOCK(&f);
    int r = 0;
    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_SMTP,
                            STREAM_TOSERVER, mimemsg1, mimemsg1_len);
    if (r != 0) {
        printf("AppLayerParse for smtp failed. Returned %d", r);
        FLOWLOCK_UNLOCK(&f);
        goto end;
    }
    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_SMTP,
                            STREAM_TOSERVER, mimemsg2, mimemsg2_len);
    if (r != 0) {
        printf("AppLayerParse for smtp failed. Returned %d", r);
        FLOWLOCK_UNLOCK(&f);
        goto end;
    }
    FLOWLOCK_UNLOCK(&f);

    smtp_state = f.alstate;
    if (smtp_state == NULL) {
        printf("no smtp state: ");
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);

    if (PacketAlertCheck(p, 1)) {
        printf("sid 1 matched but shouldn't have\n");
        goto end;
    }

    result = 0;

end:
    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
    if (de_ctx != NULL)
        SigGroupCleanup(de_ctx);
    if (de_ctx != NULL)
        SigCleanSignatures(de_ctx);

    StreamTcpFreeConfig(TRUE);
    FLOW_DESTROY(&f);
    UTHFreePackets(&p, 1);
    return result == 0;
}

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

void DetectFiledataRegisterTests(void)
{
    UtRegisterTest("DetectEngineSMTPFiledataTest01",
                   DetectEngineSMTPFiledataTest01);
    UtRegisterTest("DetectEngineSMTPFiledataTest02",
                   DetectEngineSMTPFiledataTest02);
    UtRegisterTest("DetectEngineSMTPFiledataTest03",
                   DetectEngineSMTPFiledataTest03);

    UtRegisterTest("DetectFiledataParseTest01", DetectFiledataParseTest01);
    UtRegisterTest("DetectFiledataParseTest02", DetectFiledataParseTest02);
    UtRegisterTest("DetectFiledataParseTest03", DetectFiledataParseTest03);
    UtRegisterTest("DetectFiledataParseTest04", DetectFiledataParseTest04);
    UtRegisterTest("DetectFiledataParseTest05", DetectFiledataParseTest05);

    UtRegisterTest("DetectFiledataIsdataatParseTest1",
            DetectFiledataIsdataatParseTest1);
    UtRegisterTest("DetectFiledataIsdataatParseTest2",
            DetectFiledataIsdataatParseTest2);
}

#endif
