/* Copyright (C) 2017-2022 Open Information Security Foundation
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
 * \author Giuseppe Longo <giuseppe@glongo.it>
 *
 * Tests for the hsbd with swf files
 */

#include "../suricata-common.h"
#include "../conf-yaml-loader.h"
#include "../decode.h"
#include "../flow.h"
#include "../detect.h"
#include "../detect-engine-build.h"

/**
 * \test Test parser accepting valid rules and rejecting invalid rules
 */
static int DetectHttpServerBodyParserTest01(void)
{
    FAIL_IF_NOT(UTHParseSignature("alert http any any -> any any (flow:to_client; content:\"abc\"; http_server_body; sid:1;)", true));
    FAIL_IF_NOT(UTHParseSignature("alert http any any -> any any (flow:to_client; content:\"abc\"; nocase; http_server_body; sid:1;)", true));
    FAIL_IF_NOT(UTHParseSignature("alert http any any -> any any (flow:to_client; content:\"abc\"; endswith; http_server_body; sid:1;)", true));
    FAIL_IF_NOT(UTHParseSignature("alert http any any -> any any (flow:to_client; content:\"abc\"; startswith; http_server_body; sid:1;)", true));
    FAIL_IF_NOT(UTHParseSignature("alert http any any -> any any (flow:to_client; content:\"abc\"; startswith; endswith; http_server_body; sid:1;)", true));

    FAIL_IF_NOT(UTHParseSignature("alert http any any -> any any (flow:to_client; content:\"abc\"; rawbytes; http_server_body; sid:1;)", false));
    FAIL_IF_NOT(UTHParseSignature("alert tcp any any -> any any (flow:to_client; http_server_body; sid:1;)", false));
    FAIL_IF_NOT(UTHParseSignature("alert tls any any -> any any (flow:to_client; content:\"abc\"; http_server_body; sid:1;)", false));
    PASS;
}

/**
 * \test Test parser accepting valid rules and rejecting invalid rules
 */
static int DetectHttpServerBodyParserTest02(void)
{
    FAIL_IF_NOT(UTHParseSignature("alert http any any -> any any (flow:to_client; http.response_body; content:\"abc\"; sid:1;)", true));
    FAIL_IF_NOT(UTHParseSignature("alert http any any -> any any (flow:to_client; http.response_body; content:\"abc\"; nocase; sid:1;)", true));
    FAIL_IF_NOT(UTHParseSignature("alert http any any -> any any (flow:to_client; http.response_body; content:\"abc\"; endswith; sid:1;)", true));
    FAIL_IF_NOT(UTHParseSignature("alert http any any -> any any (flow:to_client; http.response_body; content:\"abc\"; startswith; sid:1;)", true));
    FAIL_IF_NOT(UTHParseSignature("alert http any any -> any any (flow:to_client; http.response_body; content:\"abc\"; startswith; endswith; sid:1;)", true));
    FAIL_IF_NOT(UTHParseSignature("alert http any any -> any any (flow:to_client; http.response_body; bsize:10; sid:1;)", true));

    FAIL_IF_NOT(UTHParseSignature("alert http any any -> any any (flow:to_client; http.response_body; content:\"abc\"; rawbytes; sid:1;)", false));
    FAIL_IF_NOT(UTHParseSignature("alert tcp any any -> any any (flow:to_client; http.response_body; sid:1;)", false));
    FAIL_IF_NOT(UTHParseSignature("alert tls any any -> any any (flow:to_client; http.response_body; content:\"abc\"; sid:1;)", false));
    PASS;
}
struct TestSteps {
    const uint8_t *input;
    size_t input_size;      /**< if 0 strlen will be used */
    int direction;          /**< STREAM_TOSERVER, STREAM_TOCLIENT */
    int expect;
};

static int RunTest(struct TestSteps *steps, const char *sig, const char *yaml)
{
    TcpSession ssn;
    Flow f;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx = NULL;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();
    FAIL_IF_NULL(alp_tctx);

    memset(&th_v, 0, sizeof(th_v));
    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    if (yaml) {
        ConfCreateContextBackup();
        ConfInit();
        HtpConfigCreateBackup();

        ConfYamlLoadString(yaml, strlen(yaml));
        HTPConfigure();
        EngineModeSetIPS();
    }

    StreamTcpInitConfig(true);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    de_ctx->flags |= DE_QUIET;

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;
    f.flags |= FLOW_IPV4;
    f.alproto = ALPROTO_HTTP1;

    SCLogDebug("sig %s", sig);
    Signature *s = DetectEngineAppendSig(de_ctx, (char *)sig);
    FAIL_IF_NULL(s);

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);
    FAIL_IF_NULL(det_ctx);

    struct TestSteps *b = steps;
    int i = 0;
    while (b->input != NULL) {
        SCLogDebug("chunk %p %d", b, i);
        Packet *p = UTHBuildPacket(NULL, 0, IPPROTO_TCP);
        FAIL_IF_NULL(p);
        p->flow = &f;
        p->flowflags = (b->direction == STREAM_TOSERVER) ? FLOW_PKT_TOSERVER : FLOW_PKT_TOCLIENT;
        p->flowflags |= FLOW_PKT_ESTABLISHED;
        p->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;

        int r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_HTTP1, b->direction,
                (uint8_t *)b->input,
                b->input_size ? b->input_size : strlen((const char *)b->input));
        FAIL_IF_NOT(r == 0);

        /* do detect */
        SigMatchSignatures(&th_v, de_ctx, det_ctx, p);

        int match = PacketAlertCheck(p, 1);
        FAIL_IF_NOT(b->expect == match);

        UTHFreePackets(&p, 1);
        b++;
        i++;
    }

    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    AppLayerParserThreadCtxFree(alp_tctx);
    DetectEngineCtxFree(de_ctx);

    StreamTcpFreeConfig(true);
    FLOW_DESTROY(&f);

    if (yaml) {
        HtpConfigRestoreBackup();
        ConfRestoreContextBackup();
        EngineModeSetIDS();
    }
    PASS;
}

static int DetectEngineHttpServerBodyTest01(void)
{
    TcpSession ssn;
    Packet *p1 = NULL;
    Packet *p2 = NULL;
    ThreadVars th_v;
    DetectEngineCtx *de_ctx = NULL;
    DetectEngineThreadCtx *det_ctx = NULL;
    HtpState *http_state = NULL;
    Flow f;
    uint8_t http_buf1[] =
        "GET /index.html HTTP/1.0\r\n"
        "Host: www.openinfosecfoundation.org\r\n"
        "User-Agent: Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.1.7) Gecko/20091221 Firefox/3.5.7\r\n"
        "\r\n";
    uint32_t http_len1 = sizeof(http_buf1) - 1;
    uint8_t http_buf2[] =
        "HTTP/1.0 200 ok\r\n"
        "Content-Type: text/html\r\n"
        "Content-Length: 7\r\n"
        "\r\n"
        "message";
    uint32_t http_len2 = sizeof(http_buf2) - 1;
    int result = 0;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&th_v, 0, sizeof(th_v));
    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    p1 = UTHBuildPacket(NULL, 0, IPPROTO_TCP);
    p2 = UTHBuildPacket(NULL, 0, IPPROTO_TCP);

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;
    f.flags |= FLOW_IPV4;

    p1->flow = &f;
    p1->flowflags |= FLOW_PKT_TOSERVER;
    p1->flowflags |= FLOW_PKT_ESTABLISHED;
    p1->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    p2->flow = &f;
    p2->flowflags |= FLOW_PKT_TOCLIENT;
    p2->flowflags |= FLOW_PKT_ESTABLISHED;
    p2->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    f.alproto = ALPROTO_HTTP1;

    StreamTcpInitConfig(true);

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert http any any -> any any "
                               "(msg:\"http server body test\"; "
                               "content:\"message\"; http_server_body; "
                               "sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParserParse(
            NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER, http_buf1, http_len1);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        goto end;
    }

    http_state = f.alstate;
    if (http_state == NULL) {
        printf("no http state: \n");
        result = 0;
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p1);

    if ((PacketAlertCheck(p1, 1))) {
        printf("sid 1 matched but shouldn't have\n");
        goto end;
    }

    r = AppLayerParserParse(
            NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOCLIENT, http_buf2, http_len2);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: \n", r);
        result = 0;
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p2);

    if (!(PacketAlertCheck(p2, 1))) {
        printf("sid 1 didn't match but should have");
        goto end;
    }

    result = 1;

end:
    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);

    StreamTcpFreeConfig(true);
    FLOW_DESTROY(&f);
    UTHFreePackets(&p1, 1);
    UTHFreePackets(&p2, 1);
    return result;
}

static int DetectEngineHttpServerBodyTest02(void)
{
    TcpSession ssn;
    Packet *p1 = NULL;
    ThreadVars th_v;
    DetectEngineCtx *de_ctx = NULL;
    DetectEngineThreadCtx *det_ctx = NULL;
    HtpState *http_state = NULL;
    Flow f;
    uint8_t http_buf1[] =
        "GET /index.html HTTP/1.0\r\n"
        "Host: www.openinfosecfoundation.org\r\n"
        "User-Agent: Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.1.7) Gecko/20091221 Firefox/3.5.7\r\n"
        "\r\n";
    uint32_t http_len1 = sizeof(http_buf1) - 1;
    uint8_t http_buf2[] =
        "HTTP/1.0 200 ok\r\n"
        "Content-Type: text/html\r\n"
        "Content-Length: 7\r\n"
        "\r\n"
        "xxxxABC";
    uint32_t http_len2 = sizeof(http_buf2) - 1;
    int result = 0;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&th_v, 0, sizeof(th_v));
    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    p1 = UTHBuildPacket(NULL, 0, IPPROTO_TCP);

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;
    f.flags |= FLOW_IPV4;

    p1->flow = &f;
    p1->flowflags |= FLOW_PKT_TOCLIENT;
    p1->flowflags |= FLOW_PKT_ESTABLISHED;
    p1->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    f.alproto = ALPROTO_HTTP1;

    StreamTcpInitConfig(true);

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert http any any -> any any "
                               "(msg:\"http server body test\"; "
                               "content:\"ABC\"; http_server_body; offset:4; "
                               "sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParserParse(
            NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER, http_buf1, http_len1);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        goto end;
    }

    r = AppLayerParserParse(
            NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOCLIENT, http_buf2, http_len2);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        goto end;
    }

    http_state = f.alstate;
    if (http_state == NULL) {
        printf("no http state: \n");
        result = 0;
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p1);

    if (!(PacketAlertCheck(p1, 1))) {
        printf("sid 1 didn't match but should have\n");
        goto end;
    }

    result = 1;

end:
    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);

    StreamTcpFreeConfig(true);
    FLOW_DESTROY(&f);
    UTHFreePackets(&p1, 1);
    return result;
}

static int DetectEngineHttpServerBodyTest03(void)
{
    TcpSession ssn;
    Packet *p1 = NULL;
    Packet *p2 = NULL;
    ThreadVars th_v;
    DetectEngineCtx *de_ctx = NULL;
    DetectEngineThreadCtx *det_ctx = NULL;
    HtpState *http_state = NULL;
    Flow f;
    int result = 0;
    uint8_t http_buf1[] =
        "GET /index.html HTTP/1.0\r\n"
        "Host: www.openinfosecfoundation.org\r\n"
        "User-Agent: Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.1.7) Gecko/20091221 Firefox/3.5.7\r\n"
        "\r\n";
    uint32_t http_len1 = sizeof(http_buf1) - 1;
    uint8_t http_buf2[] =
        "HTTP/1.0 200 ok\r\n"
        "Content-Type: text/html\r\n"
        "Content-Length: 17\r\n"
        "\r\n"
        "1234567";
    uint32_t http_len2 = sizeof(http_buf2) - 1;
    uint8_t http_buf3[] =
        "8901234ABC";
    uint32_t http_len3 = sizeof(http_buf3) - 1;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&th_v, 0, sizeof(th_v));
    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    p1 = UTHBuildPacket(NULL, 0, IPPROTO_TCP);
    p2 = UTHBuildPacket(NULL, 0, IPPROTO_TCP);

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;
    f.flags |= FLOW_IPV4;

    p1->flow = &f;
    p1->flowflags |= FLOW_PKT_TOSERVER;
    p1->flowflags |= FLOW_PKT_ESTABLISHED;
    p1->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    p2->flow = &f;
    p2->flowflags |= FLOW_PKT_TOCLIENT;
    p2->flowflags |= FLOW_PKT_ESTABLISHED;
    p2->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    f.alproto = ALPROTO_HTTP1;

    StreamTcpInitConfig(true);

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert http any any -> any any "
                               "(msg:\"http server body test\"; "
                               "content:\"ABC\"; http_server_body; offset:14; "
                               "sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParserParse(
            NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER, http_buf1, http_len1);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        goto end;
    }

    http_state = f.alstate;
    if (http_state == NULL) {
        printf("no http state: \n");
        result = 0;
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p1);

    if (PacketAlertCheck(p1, 1)) {
        printf("sid 1 matched but shouldn't have\n");
        goto end;
    }

    r = AppLayerParserParse(
            NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOCLIENT, http_buf2, http_len2);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: \n", r);
        result = 0;
        goto end;
    }

    r = AppLayerParserParse(
            NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOCLIENT, http_buf3, http_len3);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: \n", r);
        result = 0;
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p2);

    if (!(PacketAlertCheck(p2, 1))) {
        printf("sid 1 didn't match but should have");
        goto end;
    }

    result = 1;

end:
    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);

    StreamTcpFreeConfig(true);
    FLOW_DESTROY(&f);
    UTHFreePackets(&p1, 1);
    UTHFreePackets(&p2, 1);
    return result;
}

static int DetectEngineHttpServerBodyTest04(void)
{
    TcpSession ssn;
    Packet *p1 = NULL;
    Packet *p2 = NULL;
    ThreadVars th_v;
    DetectEngineCtx *de_ctx = NULL;
    DetectEngineThreadCtx *det_ctx = NULL;
    HtpState *http_state = NULL;
    Flow f;
    uint8_t http_buf1[] =
        "GET /index.html HTTP/1.0\r\n"
        "Host: www.openinfosecfoundation.org\r\n"
        "User-Agent: Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.1.7) Gecko/20091221 Firefox/3.5.7\r\n"
        "\r\n";
    uint32_t http_len1 = sizeof(http_buf1) - 1;
    uint8_t http_buf2[] =
        "HTTP/1.0 200 ok\r\n"
        "Content-Type: text/html\r\n"
        "Content-Length: 6\r\n"
        "\r\n"
        "abcdef";
    uint32_t http_len2 = sizeof(http_buf2) - 1;
    int result = 0;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&th_v, 0, sizeof(th_v));
    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    p1 = UTHBuildPacket(NULL, 0, IPPROTO_TCP);
    p2 = UTHBuildPacket(NULL, 0, IPPROTO_TCP);

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;
    f.flags |= FLOW_IPV4;

    p1->flow = &f;
    p1->flowflags |= FLOW_PKT_TOSERVER;
    p1->flowflags |= FLOW_PKT_ESTABLISHED;
    p1->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    p2->flow = &f;
    p2->flowflags |= FLOW_PKT_TOCLIENT;
    p2->flowflags |= FLOW_PKT_ESTABLISHED;
    p2->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    f.alproto = ALPROTO_HTTP1;

    StreamTcpInitConfig(true);

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert http any any -> any any "
                               "(msg:\"http server body test\"; "
                               "content:!\"abc\"; http_server_body; offset:3; "
                               "sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParserParse(
            NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER, http_buf1, http_len1);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        goto end;
    }

    http_state = f.alstate;
    if (http_state == NULL) {
        printf("no http state: \n");
        result = 0;
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p1);

    if (PacketAlertCheck(p1, 1)) {
        printf("sid 1 matched but shouldn't have: ");
        goto end;
    }

    r = AppLayerParserParse(
            NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOCLIENT, http_buf2, http_len2);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: \n", r);
        result = 0;
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p2);

    if (!PacketAlertCheck(p2, 1)) {
        printf("sid 1 didn't match but should have: ");
        goto end;
    }

    result = 1;

end:
    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);

    StreamTcpFreeConfig(true);
    FLOW_DESTROY(&f);
    UTHFreePackets(&p1, 1);
    UTHFreePackets(&p2, 1);
    return result;
}

static int DetectEngineHttpServerBodyTest05(void)
{
    TcpSession ssn;
    Packet *p1 = NULL;
    Packet *p2 = NULL;
    ThreadVars th_v;
    DetectEngineCtx *de_ctx = NULL;
    DetectEngineThreadCtx *det_ctx = NULL;
    HtpState *http_state = NULL;
    Flow f;
    uint8_t http_buf1[] =
        "GET /index.html HTTP/1.0\r\n"
        "Host: www.openinfosecfoundation.org\r\n"
        "User-Agent: Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.1.7) Gecko/20091221 Firefox/3.5.7\r\n"
        "\r\n";
    uint32_t http_len1 = sizeof(http_buf1) - 1;
    uint8_t http_buf2[] =
        "HTTP/1.0 200 ok\r\n"
        "Content-Type: text/html\r\n"
        "Content-Length: 6\r\n"
        "\r\n"
        "abcdef";
    uint32_t http_len2 = sizeof(http_buf2) - 1;
    int result = 0;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&th_v, 0, sizeof(th_v));
    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    p1 = UTHBuildPacket(NULL, 0, IPPROTO_TCP);
    p2 = UTHBuildPacket(NULL, 0, IPPROTO_TCP);

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;
    f.flags |= FLOW_IPV4;

    p1->flow = &f;
    p1->flowflags |= FLOW_PKT_TOSERVER;
    p1->flowflags |= FLOW_PKT_ESTABLISHED;
    p1->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    p2->flow = &f;
    p2->flowflags |= FLOW_PKT_TOCLIENT;
    p2->flowflags |= FLOW_PKT_ESTABLISHED;
    p2->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    f.alproto = ALPROTO_HTTP1;

    StreamTcpInitConfig(true);

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert http any any -> any any "
                               "(msg:\"http server body test\"; "
                               "content:\"abc\"; http_server_body; depth:3; "
                               "sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParserParse(
            NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER, http_buf1, http_len1);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        goto end;
    }

    http_state = f.alstate;
    if (http_state == NULL) {
        printf("no http state: \n");
        result = 0;
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p1);

    if (PacketAlertCheck(p1, 1)) {
        printf("sid 1 matched but shouldn't have: ");
        goto end;
    }

    r = AppLayerParserParse(
            NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOCLIENT, http_buf2, http_len2);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: \n", r);
        result = 0;
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p2);

    if (!PacketAlertCheck(p2, 1)) {
        printf("sid 1 didn't match but should have: ");
        goto end;
    }

    result = 1;

end:
    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);

    StreamTcpFreeConfig(true);
    FLOW_DESTROY(&f);
    UTHFreePackets(&p1, 1);
    UTHFreePackets(&p2, 1);
    return result;
}

static int DetectEngineHttpServerBodyTest06(void)
{
    TcpSession ssn;
    Packet *p1 = NULL;
    Packet *p2 = NULL;
    ThreadVars th_v;
    DetectEngineCtx *de_ctx = NULL;
    DetectEngineThreadCtx *det_ctx = NULL;
    HtpState *http_state = NULL;
    Flow f;
    uint8_t http_buf1[] =
        "GET /index.html HTTP/1.0\r\n"
        "Host: www.openinfosecfoundation.org\r\n"
        "User-Agent: Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.1.7) Gecko/20091221 Firefox/3.5.7\r\n"
        "\r\n";
    uint32_t http_len1 = sizeof(http_buf1) - 1;
    uint8_t http_buf2[] =
        "HTTP/1.0 200 ok\r\n"
        "Content-Type: text/html\r\n"
        "Content-Length: 6\r\n"
        "\r\n"
        "abcdef";
    uint32_t http_len2 = sizeof(http_buf2) - 1;
    int result = 0;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&th_v, 0, sizeof(th_v));
    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    p1 = UTHBuildPacket(NULL, 0, IPPROTO_TCP);
    p2 = UTHBuildPacket(NULL, 0, IPPROTO_TCP);

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;
    f.flags |= FLOW_IPV4;

    p1->flow = &f;
    p1->flowflags |= FLOW_PKT_TOSERVER;
    p1->flowflags |= FLOW_PKT_ESTABLISHED;
    p1->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    p2->flow = &f;
    p2->flowflags |= FLOW_PKT_TOCLIENT;
    p2->flowflags |= FLOW_PKT_ESTABLISHED;
    p2->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    f.alproto = ALPROTO_HTTP1;

    StreamTcpInitConfig(true);

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert http any any -> any any "
                               "(msg:\"http server body test\"; "
                               "content:!\"def\"; http_server_body; depth:3; "
                               "sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParserParse(
            NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER, http_buf1, http_len1);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        goto end;
    }

    http_state = f.alstate;
    if (http_state == NULL) {
        printf("no http state: \n");
        result = 0;
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p1);

    if (PacketAlertCheck(p1, 1)) {
        printf("sid 1 matched but shouldn't have: ");
        goto end;
    }

    r = AppLayerParserParse(
            NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOCLIENT, http_buf2, http_len2);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: \n", r);
        result = 0;
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p2);

    if (!PacketAlertCheck(p2, 1)) {
        printf("sid 1 didn't match but should have: ");
        goto end;
    }

    result = 1;

end:
    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);

    StreamTcpFreeConfig(true);
    FLOW_DESTROY(&f);
    UTHFreePackets(&p1, 1);
    UTHFreePackets(&p2, 1);
    return result;
}

static int DetectEngineHttpServerBodyTest07(void)
{
    TcpSession ssn;
    Packet *p1 = NULL;
    Packet *p2 = NULL;
    ThreadVars th_v;
    DetectEngineCtx *de_ctx = NULL;
    DetectEngineThreadCtx *det_ctx = NULL;
    HtpState *http_state = NULL;
    Flow f;
    uint8_t http_buf1[] =
        "GET /index.html HTTP/1.0\r\n"
        "Host: www.openinfosecfoundation.org\r\n"
        "User-Agent: Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.1.7) Gecko/20091221 Firefox/3.5.7\r\n"
        "\r\n";
    uint32_t http_len1 = sizeof(http_buf1) - 1;
    uint8_t http_buf2[] =
        "HTTP/1.0 200 ok\r\n"
        "Content-Type: text/html\r\n"
        "Content-Length: 6\r\n"
        "\r\n"
        "abcdef";
    uint32_t http_len2 = sizeof(http_buf2) - 1;
    int result = 0;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&th_v, 0, sizeof(th_v));
    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    p1 = UTHBuildPacket(NULL, 0, IPPROTO_TCP);
    p2 = UTHBuildPacket(NULL, 0, IPPROTO_TCP);

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;
    f.flags |= FLOW_IPV4;

    p1->flow = &f;
    p1->flowflags |= FLOW_PKT_TOSERVER;
    p1->flowflags |= FLOW_PKT_ESTABLISHED;
    p1->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    p2->flow = &f;
    p2->flowflags |= FLOW_PKT_TOCLIENT;
    p2->flowflags |= FLOW_PKT_ESTABLISHED;
    p2->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    f.alproto = ALPROTO_HTTP1;

    StreamTcpInitConfig(true);

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert http any any -> any any "
                               "(msg:\"http server body test\"; "
                               "content:!\"def\"; http_server_body; offset:3; "
                               "sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParserParse(
            NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER, http_buf1, http_len1);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        goto end;
    }

    http_state = f.alstate;
    if (http_state == NULL) {
        printf("no http state: \n");
        result = 0;
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p1);

    if (PacketAlertCheck(p1, 1)) {
        printf("sid 1 matched but shouldn't have: ");
        goto end;
    }

    r = AppLayerParserParse(
            NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOCLIENT, http_buf2, http_len2);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: \n", r);
        result = 0;
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p2);

    if (PacketAlertCheck(p2, 1)) {
        printf("sid 1 matched but shouldn't have: ");
        goto end;
    }

    result = 1;

end:
    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);

    StreamTcpFreeConfig(true);
    FLOW_DESTROY(&f);
    UTHFreePackets(&p1, 1);
    UTHFreePackets(&p2, 1);
    return result;
}

static int DetectEngineHttpServerBodyTest08(void)
{
    TcpSession ssn;
    Packet *p1 = NULL;
    Packet *p2 = NULL;
    ThreadVars th_v;
    DetectEngineCtx *de_ctx = NULL;
    DetectEngineThreadCtx *det_ctx = NULL;
    HtpState *http_state = NULL;
    Flow f;
    uint8_t http_buf1[] =
        "GET /index.html HTTP/1.0\r\n"
        "Host: www.openinfosecfoundation.org\r\n"
        "User-Agent: Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.1.7) Gecko/20091221 Firefox/3.5.7\r\n"
        "\r\n";
    uint32_t http_len1 = sizeof(http_buf1) - 1;
    uint8_t http_buf2[] =
        "HTTP/1.0 200 ok\r\n"
        "Content-Type: text/html\r\n"
        "Content-Length: 6\r\n"
        "\r\n"
        "abcdef";
    uint32_t http_len2 = sizeof(http_buf2) - 1;
    int result = 0;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&th_v, 0, sizeof(th_v));
    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    p1 = UTHBuildPacket(NULL, 0, IPPROTO_TCP);
    p2 = UTHBuildPacket(NULL, 0, IPPROTO_TCP);

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;
    f.flags |= FLOW_IPV4;

    p1->flow = &f;
    p1->flowflags |= FLOW_PKT_TOSERVER;
    p1->flowflags |= FLOW_PKT_ESTABLISHED;
    p1->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    p2->flow = &f;
    p2->flowflags |= FLOW_PKT_TOCLIENT;
    p2->flowflags |= FLOW_PKT_ESTABLISHED;
    p2->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    f.alproto = ALPROTO_HTTP1;

    StreamTcpInitConfig(true);

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert http any any -> any any "
                               "(msg:\"http server body test\"; "
                               "content:!\"abc\"; http_server_body; depth:3; "
                               "sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParserParse(
            NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER, http_buf1, http_len1);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        goto end;
    }

    http_state = f.alstate;
    if (http_state == NULL) {
        printf("no http state: \n");
        result = 0;
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p1);

    if (PacketAlertCheck(p1, 1)) {
        printf("sid 1 matched but shouldn't have: ");
        goto end;
    }

    r = AppLayerParserParse(
            NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOCLIENT, http_buf2, http_len2);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: \n", r);
        result = 0;
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p2);

    if (PacketAlertCheck(p2, 1)) {
        printf("sid 1 matched but shouldn't have: ");
        goto end;
    }

    result = 1;

end:
    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);

    StreamTcpFreeConfig(true);
    FLOW_DESTROY(&f);
    UTHFreePackets(&p1, 1);
    UTHFreePackets(&p2, 1);
    return result;
}

static int DetectEngineHttpServerBodyTest09(void)
{
    TcpSession ssn;
    Packet *p1 = NULL;
    Packet *p2 = NULL;
    ThreadVars th_v;
    DetectEngineCtx *de_ctx = NULL;
    DetectEngineThreadCtx *det_ctx = NULL;
    HtpState *http_state = NULL;
    Flow f;
    uint8_t http_buf1[] =
        "GET /index.html HTTP/1.0\r\n"
        "Host: www.openinfosecfoundation.org\r\n"
        "User-Agent: Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.1.7) Gecko/20091221 Firefox/3.5.7\r\n"
        "\r\n";
    uint32_t http_len1 = sizeof(http_buf1) - 1;
    uint8_t http_buf2[] =
        "HTTP/1.0 200 ok\r\n"
        "Content-Type: text/html\r\n"
        "Content-Length: 6\r\n"
        "\r\n"
        "abcdef";
    uint32_t http_len2 = sizeof(http_buf2) - 1;
    int result = 0;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&th_v, 0, sizeof(th_v));
    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    p1 = UTHBuildPacket(NULL, 0, IPPROTO_TCP);
    p2 = UTHBuildPacket(NULL, 0, IPPROTO_TCP);

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;
    f.flags |= FLOW_IPV4;

    p1->flow = &f;
    p1->flowflags |= FLOW_PKT_TOSERVER;
    p1->flowflags |= FLOW_PKT_ESTABLISHED;
    p1->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    p2->flow = &f;
    p2->flowflags |= FLOW_PKT_TOCLIENT;
    p2->flowflags |= FLOW_PKT_ESTABLISHED;
    p2->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    f.alproto = ALPROTO_HTTP1;

    StreamTcpInitConfig(true);

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert http any any -> any any "
                               "(msg:\"http server body test\"; "
                               "content:\"abc\"; http_server_body; depth:3; "
                               "content:\"def\"; http_server_body; within:3; "
                               "sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParserParse(
            NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER, http_buf1, http_len1);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        goto end;
    }

    http_state = f.alstate;
    if (http_state == NULL) {
        printf("no http state: \n");
        result = 0;
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p1);

    if (PacketAlertCheck(p1, 1)) {
        printf("sid 1 matched but shouldn't have: ");
        goto end;
    }

    r = AppLayerParserParse(
            NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOCLIENT, http_buf2, http_len2);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: \n", r);
        result = 0;
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p2);

    if (!PacketAlertCheck(p2, 1)) {
        printf("sid 1 didn't match but should have: ");
        goto end;
    }

    result = 1;

end:
    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);

    StreamTcpFreeConfig(true);
    FLOW_DESTROY(&f);
    UTHFreePackets(&p1, 1);
    UTHFreePackets(&p2, 1);
    return result;
}

static int DetectEngineHttpServerBodyTest10(void)
{
    TcpSession ssn;
    Packet *p1 = NULL;
    Packet *p2 = NULL;
    ThreadVars th_v;
    DetectEngineCtx *de_ctx = NULL;
    DetectEngineThreadCtx *det_ctx = NULL;
    HtpState *http_state = NULL;
    Flow f;
    uint8_t http_buf1[] =
        "GET /index.html HTTP/1.0\r\n"
        "Host: www.openinfosecfoundation.org\r\n"
        "User-Agent: Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.1.7) Gecko/20091221 Firefox/3.5.7\r\n"
        "\r\n";
    uint32_t http_len1 = sizeof(http_buf1) - 1;
    uint8_t http_buf2[] =
        "HTTP/1.0 200 ok\r\n"
        "Content-Type: text/html\r\n"
        "Content-Length: 6\r\n"
        "\r\n"
        "abcdef";
    uint32_t http_len2 = sizeof(http_buf2) - 1;
    int result = 0;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&th_v, 0, sizeof(th_v));
    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    p1 = UTHBuildPacket(NULL, 0, IPPROTO_TCP);
    p2 = UTHBuildPacket(NULL, 0, IPPROTO_TCP);

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;
    f.flags |= FLOW_IPV4;

    p1->flow = &f;
    p1->flowflags |= FLOW_PKT_TOSERVER;
    p1->flowflags |= FLOW_PKT_ESTABLISHED;
    p1->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    p2->flow = &f;
    p2->flowflags |= FLOW_PKT_TOCLIENT;
    p2->flowflags |= FLOW_PKT_ESTABLISHED;
    p2->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    f.alproto = ALPROTO_HTTP1;

    StreamTcpInitConfig(true);

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert http any any -> any any "
                               "(msg:\"http server body test\"; "
                               "content:\"abc\"; http_server_body; depth:3; "
                               "content:!\"xyz\"; http_server_body; within:3; "
                               "sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParserParse(
            NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER, http_buf1, http_len1);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        goto end;
    }

    http_state = f.alstate;
    if (http_state == NULL) {
        printf("no http state: \n");
        result = 0;
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p1);

    if (PacketAlertCheck(p1, 1)) {
        printf("sid 1 matched but shouldn't have: ");
        goto end;
    }

    r = AppLayerParserParse(
            NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOCLIENT, http_buf2, http_len2);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: \n", r);
        result = 0;
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p2);

    if (!PacketAlertCheck(p2, 1)) {
        printf("sid 1 didn't match but should have: ");
        goto end;
    }

    result = 1;

end:
    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);

    StreamTcpFreeConfig(true);
    FLOW_DESTROY(&f);
    UTHFreePackets(&p1, 1);
    UTHFreePackets(&p2, 1);
    return result;
}

static int DetectEngineHttpServerBodyTest11(void)
{
    TcpSession ssn;
    Packet *p1 = NULL;
    Packet *p2 = NULL;
    ThreadVars th_v;
    DetectEngineCtx *de_ctx = NULL;
    DetectEngineThreadCtx *det_ctx = NULL;
    HtpState *http_state = NULL;
    Flow f;
    uint8_t http_buf1[] =
        "GET /index.html HTTP/1.0\r\n"
        "Host: www.openinfosecfoundation.org\r\n"
        "User-Agent: Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.1.7) Gecko/20091221 Firefox/3.5.7\r\n"
        "\r\n";
    uint32_t http_len1 = sizeof(http_buf1) - 1;
    uint8_t http_buf2[] =
        "HTTP/1.0 200 ok\r\n"
        "Content-Type: text/html\r\n"
        "Content-Length: 6\r\n"
        "\r\n"
        "abcdef";
    uint32_t http_len2 = sizeof(http_buf2) - 1;
    int result = 0;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&th_v, 0, sizeof(th_v));
    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    p1 = UTHBuildPacket(NULL, 0, IPPROTO_TCP);
    p2 = UTHBuildPacket(NULL, 0, IPPROTO_TCP);

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;
    f.flags |= FLOW_IPV4;

    p1->flow = &f;
    p1->flowflags |= FLOW_PKT_TOSERVER;
    p1->flowflags |= FLOW_PKT_ESTABLISHED;
    p1->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    p2->flow = &f;
    p2->flowflags |= FLOW_PKT_TOCLIENT;
    p2->flowflags |= FLOW_PKT_ESTABLISHED;
    p2->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    f.alproto = ALPROTO_HTTP1;

    StreamTcpInitConfig(true);

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert http any any -> any any "
                               "(msg:\"http server body test\"; "
                               "content:\"abc\"; http_server_body; depth:3; "
                               "content:\"xyz\"; http_server_body; within:3; "
                               "sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParserParse(
            NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER, http_buf1, http_len1);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        goto end;
    }

    http_state = f.alstate;
    if (http_state == NULL) {
        printf("no http state: \n");
        result = 0;
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p1);

    if (PacketAlertCheck(p1, 1)) {
        printf("sid 1 matched but shouldn't have: ");
        goto end;
    }

    r = AppLayerParserParse(
            NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOCLIENT, http_buf2, http_len2);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: \n", r);
        result = 0;
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p2);

    if (PacketAlertCheck(p2, 1)) {
        printf("sid 1 did match but should not have: ");
        goto end;
    }

    result = 1;

end:
    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);

    StreamTcpFreeConfig(true);
    FLOW_DESTROY(&f);
    UTHFreePackets(&p1, 1);
    UTHFreePackets(&p2, 1);
    return result;
}

static int DetectEngineHttpServerBodyTest12(void)
{
    TcpSession ssn;
    Packet *p1 = NULL;
    Packet *p2 = NULL;
    ThreadVars th_v;
    DetectEngineCtx *de_ctx = NULL;
    DetectEngineThreadCtx *det_ctx = NULL;
    HtpState *http_state = NULL;
    Flow f;
    uint8_t http_buf1[] =
        "GET /index.html HTTP/1.0\r\n"
        "Host: www.openinfosecfoundation.org\r\n"
        "User-Agent: Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.1.7) Gecko/20091221 Firefox/3.5.7\r\n"
        "\r\n";
    uint32_t http_len1 = sizeof(http_buf1) - 1;
    uint8_t http_buf2[] =
        "HTTP/1.0 200 ok\r\n"
        "Content-Type: text/html\r\n"
        "Content-Length: 6\r\n"
        "\r\n"
        "abcdef";
    uint32_t http_len2 = sizeof(http_buf2) - 1;
    int result = 0;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&th_v, 0, sizeof(th_v));
    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    p1 = UTHBuildPacket(NULL, 0, IPPROTO_TCP);
    p2 = UTHBuildPacket(NULL, 0, IPPROTO_TCP);

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;
    f.flags |= FLOW_IPV4;

    p1->flow = &f;
    p1->flowflags |= FLOW_PKT_TOSERVER;
    p1->flowflags |= FLOW_PKT_ESTABLISHED;
    p1->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    p2->flow = &f;
    p2->flowflags |= FLOW_PKT_TOCLIENT;
    p2->flowflags |= FLOW_PKT_ESTABLISHED;
    p2->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    f.alproto = ALPROTO_HTTP1;

    StreamTcpInitConfig(true);

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert http any any -> any any "
                               "(msg:\"http server body test\"; "
                               "content:\"ab\"; http_server_body; depth:2; "
                               "content:\"ef\"; http_server_body; distance:2; "
                               "sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParserParse(
            NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER, http_buf1, http_len1);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        goto end;
    }

    http_state = f.alstate;
    if (http_state == NULL) {
        printf("no http state: \n");
        result = 0;
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p1);

    if (PacketAlertCheck(p1, 1)) {
        printf("sid 1 matched but shouldn't have: ");
        goto end;
    }

    r = AppLayerParserParse(
            NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOCLIENT, http_buf2, http_len2);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: \n", r);
        result = 0;
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p2);

    if (!PacketAlertCheck(p2, 1)) {
        printf("sid 1 did not match but should have: ");
        goto end;
    }

    result = 1;

end:
    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);

    StreamTcpFreeConfig(true);
    FLOW_DESTROY(&f);
    UTHFreePackets(&p1, 1);
    UTHFreePackets(&p2, 1);
    return result;
}

static int DetectEngineHttpServerBodyTest13(void)
{
    TcpSession ssn;
    Packet *p1 = NULL;
    Packet *p2 = NULL;
    ThreadVars th_v;
    DetectEngineCtx *de_ctx = NULL;
    DetectEngineThreadCtx *det_ctx = NULL;
    HtpState *http_state = NULL;
    Flow f;
    uint8_t http_buf1[] =
        "GET /index.html HTTP/1.0\r\n"
        "Host: www.openinfosecfoundation.org\r\n"
        "User-Agent: Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.1.7) Gecko/20091221 Firefox/3.5.7\r\n"
        "\r\n";
    uint32_t http_len1 = sizeof(http_buf1) - 1;
    uint8_t http_buf2[] =
        "HTTP/1.0 200 ok\r\n"
        "Content-Type: text/html\r\n"
        "Content-Length: 6\r\n"
        "\r\n"
        "abcdef";
    uint32_t http_len2 = sizeof(http_buf2) - 1;
    int result = 0;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&th_v, 0, sizeof(th_v));
    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    p1 = UTHBuildPacket(NULL, 0, IPPROTO_TCP);
    p2 = UTHBuildPacket(NULL, 0, IPPROTO_TCP);

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;
    f.flags |= FLOW_IPV4;

    p1->flow = &f;
    p1->flowflags |= FLOW_PKT_TOSERVER;
    p1->flowflags |= FLOW_PKT_ESTABLISHED;
    p1->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    p2->flow = &f;
    p2->flowflags |= FLOW_PKT_TOCLIENT;
    p2->flowflags |= FLOW_PKT_ESTABLISHED;
    p2->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    f.alproto = ALPROTO_HTTP1;

    StreamTcpInitConfig(true);

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert http any any -> any any "
                               "(msg:\"http server body test\"; "
                               "content:\"ab\"; http_server_body; depth:3; "
                               "content:!\"yz\"; http_server_body; distance:2; "
                               "sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParserParse(
            NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER, http_buf1, http_len1);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        goto end;
    }

    http_state = f.alstate;
    if (http_state == NULL) {
        printf("no http state: \n");
        result = 0;
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p1);

    if (PacketAlertCheck(p1, 1)) {
        printf("sid 1 matched but shouldn't have: ");
        goto end;
    }

    r = AppLayerParserParse(
            NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOCLIENT, http_buf2, http_len2);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: \n", r);
        result = 0;
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p2);

    if (!PacketAlertCheck(p2, 1)) {
        printf("sid 1 did not match but should have: ");
        goto end;
    }

    result = 1;

end:
    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);

    StreamTcpFreeConfig(true);
    FLOW_DESTROY(&f);
    UTHFreePackets(&p1, 1);
    UTHFreePackets(&p2, 1);
    return result;
}

static int DetectEngineHttpServerBodyTest14(void)
{
    TcpSession ssn;
    Packet *p1 = NULL;
    Packet *p2 = NULL;
    ThreadVars th_v;
    DetectEngineCtx *de_ctx = NULL;
    DetectEngineThreadCtx *det_ctx = NULL;
    HtpState *http_state = NULL;
    Flow f;
    uint8_t http_buf1[] =
        "GET /index.html HTTP/1.0\r\n"
        "Host: www.openinfosecfoundation.org\r\n"
        "User-Agent: Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.1.7) Gecko/20091221 Firefox/3.5.7\r\n"
        "\r\n";
    uint32_t http_len1 = sizeof(http_buf1) - 1;
    uint8_t http_buf2[] =
        "HTTP/1.0 200 ok\r\n"
        "Content-Type: text/html\r\n"
        "Content-Length: 6\r\n"
        "\r\n"
        "abcdef";
    uint32_t http_len2 = sizeof(http_buf2) - 1;
    int result = 0;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&th_v, 0, sizeof(th_v));
    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    p1 = UTHBuildPacket(NULL, 0, IPPROTO_TCP);
    p2 = UTHBuildPacket(NULL, 0, IPPROTO_TCP);

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;
    f.flags |= FLOW_IPV4;

    p1->flow = &f;
    p1->flowflags |= FLOW_PKT_TOSERVER;
    p1->flowflags |= FLOW_PKT_ESTABLISHED;
    p1->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    p2->flow = &f;
    p2->flowflags |= FLOW_PKT_TOCLIENT;
    p2->flowflags |= FLOW_PKT_ESTABLISHED;
    p2->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    f.alproto = ALPROTO_HTTP1;

    StreamTcpInitConfig(true);

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert http any any -> any any "
                               "(msg:\"http server body test\"; "
                               "pcre:/ab/Q; "
                               "content:\"ef\"; http_server_body; distance:2; "
                               "sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParserParse(
            NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER, http_buf1, http_len1);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        goto end;
    }

    http_state = f.alstate;
    if (http_state == NULL) {
        printf("no http state: \n");
        result = 0;
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p1);

    if (PacketAlertCheck(p1, 1)) {
        printf("sid 1 matched but shouldn't have: ");
        goto end;
    }

    r = AppLayerParserParse(
            NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOCLIENT, http_buf2, http_len2);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: \n", r);
        result = 0;
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p2);

    if (!PacketAlertCheck(p2, 1)) {
        printf("sid 1 did not match but should have: ");
        goto end;
    }

    result = 1;

end:
    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);

    StreamTcpFreeConfig(true);
    FLOW_DESTROY(&f);
    UTHFreePackets(&p1, 1);
    UTHFreePackets(&p2, 1);
    return result;
}

static int DetectEngineHttpServerBodyTest15(void)
{
    TcpSession ssn;
    Packet *p1 = NULL;
    Packet *p2 = NULL;
    ThreadVars th_v;
    DetectEngineCtx *de_ctx = NULL;
    DetectEngineThreadCtx *det_ctx = NULL;
    HtpState *http_state = NULL;
    Flow f;
    uint8_t http_buf1[] =
        "GET /index.html HTTP/1.0\r\n"
        "Host: www.openinfosecfoundation.org\r\n"
        "User-Agent: Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.1.7) Gecko/20091221 Firefox/3.5.7\r\n"
        "\r\n";
    uint32_t http_len1 = sizeof(http_buf1) - 1;
    uint8_t http_buf2[] =
        "HTTP/1.0 200 ok\r\n"
        "Content-Type: text/html\r\n"
        "Content-Length: 6\r\n"
        "\r\n"
        "abcdef";
    uint32_t http_len2 = sizeof(http_buf2) - 1;
    int result = 0;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&th_v, 0, sizeof(th_v));
    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    p1 = UTHBuildPacket(NULL, 0, IPPROTO_TCP);
    p2 = UTHBuildPacket(NULL, 0, IPPROTO_TCP);

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;
    f.flags |= FLOW_IPV4;

    p1->flow = &f;
    p1->flowflags |= FLOW_PKT_TOSERVER;
    p1->flowflags |= FLOW_PKT_ESTABLISHED;
    p1->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    p2->flow = &f;
    p2->flowflags |= FLOW_PKT_TOCLIENT;
    p2->flowflags |= FLOW_PKT_ESTABLISHED;
    p2->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    f.alproto = ALPROTO_HTTP1;

    StreamTcpInitConfig(true);

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert http any any -> any any "
                               "(msg:\"http server body test\"; "
                               "pcre:/abc/Q; "
                               "content:!\"xyz\"; http_server_body; distance:0; within:3; "
                               "sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParserParse(
            NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER, http_buf1, http_len1);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        goto end;
    }

    http_state = f.alstate;
    if (http_state == NULL) {
        printf("no http state: \n");
        result = 0;
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p1);

    if (PacketAlertCheck(p1, 1)) {
        printf("sid 1 matched but shouldn't have: ");
        goto end;
    }

    r = AppLayerParserParse(
            NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOCLIENT, http_buf2, http_len2);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: \n", r);
        result = 0;
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p2);

    if (!PacketAlertCheck(p2, 1)) {
        printf("sid 1 did not match but should have: ");
        goto end;
    }

    result = 1;

end:
    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);

    StreamTcpFreeConfig(true);
    FLOW_DESTROY(&f);
    UTHFreePackets(&p1, 1);
    UTHFreePackets(&p2, 1);
    return result;
}

static int DetectEngineHttpServerBodyTest16(void)
{
    char input[] = "\
%YAML 1.1\n\
---\n\
libhtp:\n\
\n\
  default-config:\n\
    personality: IDS\n\
    request-body-limit: 0\n\
    response-body-limit: 0\n\
\n\
    request-body-inspect-window: 0\n\
    response-body-inspect-window: 0\n\
    request-body-minimal-inspect-size: 0\n\
    response-body-minimal-inspect-size: 0\n\
";

    ConfCreateContextBackup();
    ConfInit();
    HtpConfigCreateBackup();

    ConfYamlLoadString(input, strlen(input));
    HTPConfigure();

    TcpSession ssn;
    Packet *p1 = NULL;
    Packet *p2 = NULL;
    ThreadVars th_v;
    DetectEngineCtx *de_ctx = NULL;
    DetectEngineThreadCtx *det_ctx = NULL;
    HtpState *http_state = NULL;
    Flow f;
    int result = 0;
    uint8_t http_buf1[] =
        "GET /index.html HTTP/1.0\r\n"
        "Host: www.openinfosecfoundation.org\r\n"
        "User-Agent: Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.1.7) Gecko/20091221 Firefox/3.5.7\r\n"
        "\r\n";
    uint32_t http_len1 = sizeof(http_buf1) - 1;
    uint8_t http_buf2[] =
        "HTTP/1.0 200 ok\r\n"
        "Content-Type: text/html\r\n"
        "Content-Length: 17\r\n"
        "\r\n"
        "1234567";
    uint32_t http_len2 = sizeof(http_buf2) - 1;
    uint8_t http_buf3[] =
        "8901234ABC";
    uint32_t http_len3 = sizeof(http_buf3) - 1;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&th_v, 0, sizeof(th_v));
    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    p1 = UTHBuildPacket(NULL, 0, IPPROTO_TCP);
    p2 = UTHBuildPacket(NULL, 0, IPPROTO_TCP);

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;
    f.flags |= FLOW_IPV4;

    p1->flow = &f;
    p1->flowflags |= FLOW_PKT_TOSERVER;
    p1->flowflags |= FLOW_PKT_ESTABLISHED;
    p1->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    p2->flow = &f;
    p2->flowflags |= FLOW_PKT_TOCLIENT;
    p2->flowflags |= FLOW_PKT_ESTABLISHED;
    p2->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    f.alproto = ALPROTO_HTTP1;

    StreamTcpInitConfig(true);

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert http any any -> any any "
                               "(msg:\"http server body test\"; "
                               "content:\"890\"; within:3; http_server_body; "
                               "sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParserParse(
            NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER, http_buf1, http_len1);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        goto end;
    }

    http_state = f.alstate;
    if (http_state == NULL) {
        printf("no http state: \n");
        result = 0;
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p1);

    if (PacketAlertCheck(p1, 1)) {
        printf("sid 1 matched but shouldn't have\n");
        goto end;
    }

    r = AppLayerParserParse(
            NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOCLIENT, http_buf2, http_len2);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: \n", r);
        result = 0;
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p2);

    if (PacketAlertCheck(p2, 1)) {
        printf("sid 1 matched but shouldn't have\n");
        goto end;
    }

    r = AppLayerParserParse(
            NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOCLIENT, http_buf3, http_len3);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: \n", r);
        result = 0;
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p2);

    if (PacketAlertCheck(p2, 1)) {
        printf("sid 1 matched but shouldn't have\n");
        goto end;
    }

    result = 1;

end:
    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
    HTPFreeConfig();
    HtpConfigRestoreBackup();
    ConfRestoreContextBackup();

    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);

    StreamTcpFreeConfig(true);
    FLOW_DESTROY(&f);
    UTHFreePackets(&p1, 1);
    UTHFreePackets(&p2, 1);
    return result;
}

static int DetectEngineHttpServerBodyTest17(void)
{
    char input[] = "\
%YAML 1.1\n\
---\n\
libhtp:\n\
\n\
  default-config:\n\
    personality: IDS\n\
    request-body-limit: 0\n\
    response-body-limit: 0\n\
\n\
    request-body-inspect-window: 0\n\
    response-body-inspect-window: 0\n\
    request-body-minimal-inspect-size: 0\n\
    response-body-minimal-inspect-size: 0\n\
";

    ConfCreateContextBackup();
    ConfInit();
    HtpConfigCreateBackup();

    ConfYamlLoadString(input, strlen(input));
    HTPConfigure();

    TcpSession ssn;
    Packet *p1 = NULL;
    Packet *p2 = NULL;
    ThreadVars th_v;
    DetectEngineCtx *de_ctx = NULL;
    DetectEngineThreadCtx *det_ctx = NULL;
    HtpState *http_state = NULL;
    Flow f;
    uint8_t http_buf1[] =
        "GET /index.html HTTP/1.0\r\n"
        "Host: www.openinfosecfoundation.org\r\n"
        "User-Agent: Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.1.7) Gecko/20091221 Firefox/3.5.7\r\n"
        "\r\n";
    uint32_t http_len1 = sizeof(http_buf1) - 1;
    uint8_t http_buf2[] =
        "HTTP/1.0 200 ok\r\n"
        "Content-Type: text/html\r\n"
        "Content-Length: 17\r\n"
        "\r\n"
        "1234567";
    uint32_t http_len2 = sizeof(http_buf2) - 1;
    uint8_t http_buf3[] =
        "8901234ABC";
    uint32_t http_len3 = sizeof(http_buf3) - 1;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&th_v, 0, sizeof(th_v));
    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    p1 = UTHBuildPacket(NULL, 0, IPPROTO_TCP);
    p2 = UTHBuildPacket(NULL, 0, IPPROTO_TCP);

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;
    f.flags |= FLOW_IPV4;

    p1->flow = &f;
    p1->flowflags |= FLOW_PKT_TOSERVER;
    p1->flowflags |= FLOW_PKT_ESTABLISHED;
    p1->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    p2->flow = &f;
    p2->flowflags |= FLOW_PKT_TOCLIENT;
    p2->flowflags |= FLOW_PKT_ESTABLISHED;
    p2->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    f.alproto = ALPROTO_HTTP1;

    StreamTcpInitConfig(true);

    de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    de_ctx->flags |= DE_QUIET;

    Signature *s = DetectEngineAppendSig(de_ctx, "alert http any any -> any any ("
                                                 "content:\"890\"; depth:3; http_server_body; "
                                                 "sid:1;)");
    FAIL_IF_NULL(s);

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParserParse(
            NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER, http_buf1, http_len1);
    FAIL_IF_NOT(r == 0);

    http_state = f.alstate;
    FAIL_IF_NULL(http_state);

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p1);
    FAIL_IF(PacketAlertCheck(p1, 1));

    SCLogDebug("chunk http_buf2");
    r = AppLayerParserParse(
            NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOCLIENT, http_buf2, http_len2);
    FAIL_IF_NOT(r == 0);

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p2);
    FAIL_IF(PacketAlertCheck(p2, 1));

    SCLogDebug("chunk http_buf3");
    r = AppLayerParserParse(
            NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOCLIENT, http_buf3, http_len3);
    FAIL_IF_NOT(r == 0);

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p2);
    FAIL_IF(PacketAlertCheck(p2, 1));

    AppLayerParserThreadCtxFree(alp_tctx);
    HTPFreeConfig();
    HtpConfigRestoreBackup();
    ConfRestoreContextBackup();

    DetectEngineCtxFree(de_ctx);

    StreamTcpFreeConfig(true);
    FLOW_DESTROY(&f);
    UTHFreePackets(&p1, 1);
    UTHFreePackets(&p2, 1);
    PASS;
}

/*
 * gzip stream
 */
static int DetectEngineHttpServerBodyTest18(void)
{
    TcpSession ssn;
    Packet *p1 = NULL;
    Packet *p2 = NULL;
    ThreadVars th_v;
    DetectEngineCtx *de_ctx = NULL;
    DetectEngineThreadCtx *det_ctx = NULL;
    HtpState *http_state = NULL;
    Flow f;
    uint8_t http_buf1[] =
        "GET /index.html HTTP/1.0\r\n"
        "Host: www.openinfosecfoundation.org\r\n"
        "User-Agent: Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.1.7) Gecko/20091221 Firefox/3.5.7\r\n"
        "\r\n";
    uint32_t http_len1 = sizeof(http_buf1) - 1;
    uint8_t http_buf2[] = {
        'H', 'T', 'T', 'P', '/', '1', '.', '1', ' ', '2', '0', '0', 'o', 'k', 0x0d, 0x0a,
        'C', 'o', 'n', 't', 'e', 'n', 't', '-', 'L', 'e', 'n', 'g', 't', 'h', ':', ' ', '5', '1', 0x0d, 0x0a,
        'C', 'o', 'n', 't', 'e', 'n', 't', '-', 'E', 'n', 'c', 'o', 'd', 'i', 'n', 'g', ':', ' ', 'g', 'z', 'i', 'p', 0x0d, 0x0a,
        0x0d, 0x0a,
        0x1f, 0x8b, 0x08, 0x08, 0x27, 0x1e, 0xe5, 0x51,
        0x00, 0x03, 0x74, 0x65, 0x73, 0x74, 0x2e, 0x74,
        0x78, 0x74, 0x00, 0x2b, 0xc9, 0xc8, 0x2c, 0x56,
        0x00, 0xa2, 0x44, 0x85, 0xb4, 0xcc, 0x9c, 0x54,
        0x85, 0xcc, 0x3c, 0x20, 0x2b, 0x29, 0xbf, 0x42,
        0x8f, 0x0b, 0x00, 0xb2, 0x7d, 0xac, 0x9b, 0x19,
        0x00, 0x00, 0x00,
    };
    uint32_t http_len2 = sizeof(http_buf2);
    int result = 0;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&th_v, 0, sizeof(th_v));
    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    p1 = UTHBuildPacket(NULL, 0, IPPROTO_TCP);
    p2 = UTHBuildPacket(NULL, 0, IPPROTO_TCP);

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;
    f.flags |= FLOW_IPV4;

    p1->flow = &f;
    p1->flowflags |= FLOW_PKT_TOSERVER;
    p1->flowflags |= FLOW_PKT_ESTABLISHED;
    p1->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    p2->flow = &f;
    p2->flowflags |= FLOW_PKT_TOCLIENT;
    p2->flowflags |= FLOW_PKT_ESTABLISHED;
    p2->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    f.alproto = ALPROTO_HTTP1;

    StreamTcpInitConfig(true);

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert http any any -> any any "
                               "(msg:\"http server body test\"; "
                               "content:\"file\"; http_server_body; "
                               "sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParserParse(
            NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER, http_buf1, http_len1);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        goto end;
    }

    http_state = f.alstate;
    if (http_state == NULL) {
        printf("no http state: \n");
        result = 0;
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p1);

    if ((PacketAlertCheck(p1, 1))) {
        printf("sid 1 matched but shouldn't have\n");
        goto end;
    }

    r = AppLayerParserParse(
            NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOCLIENT, http_buf2, http_len2);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: \n", r);
        result = 0;
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p2);

    if (!(PacketAlertCheck(p2, 1))) {
        printf("sid 1 didn't match but should have");
        goto end;
    }

    result = 1;

end:
    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);

    StreamTcpFreeConfig(true);
    FLOW_DESTROY(&f);
    UTHFreePackets(&p1, 1);
    UTHFreePackets(&p2, 1);
    return result;
}

/*
 * deflate stream
 */
static int DetectEngineHttpServerBodyTest19(void)
{
    TcpSession ssn;
    Packet *p1 = NULL;
    Packet *p2 = NULL;
    ThreadVars th_v;
    DetectEngineCtx *de_ctx = NULL;
    DetectEngineThreadCtx *det_ctx = NULL;
    HtpState *http_state = NULL;
    Flow f;
    uint8_t http_buf1[] =
        "GET /index.html HTTP/1.0\r\n"
        "Host: www.openinfosecfoundation.org\r\n"
        "User-Agent: Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.1.7) Gecko/20091221 Firefox/3.5.7\r\n"
        "\r\n";
    uint32_t http_len1 = sizeof(http_buf1) - 1;
    uint8_t http_buf2[] = {
        'H', 'T', 'T', 'P', '/', '1', '.', '1', ' ', '2', '0', '0', 'o', 'k', 0x0d, 0x0a,
        'C', 'o', 'n', 't', 'e', 'n', 't', '-', 'L', 'e', 'n', 'g', 't', 'h', ':', ' ', '2', '4', 0x0d, 0x0a,
        'C', 'o', 'n', 't', 'e', 'n', 't', '-', 'E', 'n', 'c', 'o', 'd', 'i', 'n', 'g', ':', ' ', 'd', 'e', 'f', 'l', 'a', 't', 'e', 0x0d, 0x0a,
        0x0d, 0x0a,
        0x2b, 0xc9, 0xc8, 0x2c, 0x56,
        0x00, 0xa2, 0x44, 0x85, 0xb4, 0xcc, 0x9c, 0x54,
        0x85, 0xcc, 0x3c, 0x20, 0x2b, 0x29, 0xbf, 0x42,
        0x8f, 0x0b, 0x00,
    };
    // 0xb2, 0x7d, 0xac, 0x9b, 0x19, 0x00, 0x00, 0x00,
    uint32_t http_len2 = sizeof(http_buf2);
    int result = 0;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&th_v, 0, sizeof(th_v));
    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    p1 = UTHBuildPacket(NULL, 0, IPPROTO_TCP);
    p2 = UTHBuildPacket(NULL, 0, IPPROTO_TCP);

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;
    f.flags |= FLOW_IPV4;

    p1->flow = &f;
    p1->flowflags |= FLOW_PKT_TOSERVER;
    p1->flowflags |= FLOW_PKT_ESTABLISHED;
    p1->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    p2->flow = &f;
    p2->flowflags |= FLOW_PKT_TOCLIENT;
    p2->flowflags |= FLOW_PKT_ESTABLISHED;
    p2->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    f.alproto = ALPROTO_HTTP1;

    StreamTcpInitConfig(true);

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert http any any -> any any "
                               "(msg:\"http server body test\"; "
                               "content:\"file\"; http_server_body; "
                               "sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParserParse(
            NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER, http_buf1, http_len1);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        goto end;
    }

    http_state = f.alstate;
    if (http_state == NULL) {
        printf("no http state: \n");
        result = 0;
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p1);

    if ((PacketAlertCheck(p1, 1))) {
        printf("sid 1 matched but shouldn't have\n");
        goto end;
    }

    r = AppLayerParserParse(
            NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOCLIENT, http_buf2, http_len2);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: \n", r);
        result = 0;
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p2);

    if (!(PacketAlertCheck(p2, 1))) {
        printf("sid 1 didn't match but should have");
        goto end;
    }

    result = 1;

end:
    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);

    StreamTcpFreeConfig(true);
    FLOW_DESTROY(&f);
    UTHFreePackets(&p1, 1);
    UTHFreePackets(&p2, 1);
    return result;
}

/*
 * deflate stream with gzip set as content-encoding
 */
static int DetectEngineHttpServerBodyTest20(void)
{
    TcpSession ssn;
    Packet *p1 = NULL;
    Packet *p2 = NULL;
    ThreadVars th_v;
    DetectEngineCtx *de_ctx = NULL;
    DetectEngineThreadCtx *det_ctx = NULL;
    HtpState *http_state = NULL;
    Flow f;
    uint8_t http_buf1[] =
        "GET /index.html HTTP/1.0\r\n"
        "Host: www.openinfosecfoundation.org\r\n"
        "User-Agent: Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.1.7) Gecko/20091221 Firefox/3.5.7\r\n"
        "\r\n";
    uint32_t http_len1 = sizeof(http_buf1) - 1;
    uint8_t http_buf2[] = {
        'H', 'T', 'T', 'P', '/', '1', '.', '1', ' ', '2', '0', '0', 'o', 'k', 0x0d, 0x0a,
        'C', 'o', 'n', 't', 'e', 'n', 't', '-', 'L', 'e', 'n', 'g', 't', 'h', ':', ' ', '2', '4', 0x0d, 0x0a,
        'C', 'o', 'n', 't', 'e', 'n', 't', '-', 'E', 'n', 'c', 'o', 'd', 'i', 'n', 'g', ':', ' ', 'g', 'z', 'i', 'p', 0x0d, 0x0a,
        0x0d, 0x0a,
        0x2b, 0xc9, 0xc8, 0x2c, 0x56,
        0x00, 0xa2, 0x44, 0x85, 0xb4, 0xcc, 0x9c, 0x54,
        0x85, 0xcc, 0x3c, 0x20, 0x2b, 0x29, 0xbf, 0x42,
        0x8f, 0x0b, 0x00,
    };
    // 0xb2, 0x7d, 0xac, 0x9b, 0x19, 0x00, 0x00, 0x00,
    uint32_t http_len2 = sizeof(http_buf2);
    int result = 0;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&th_v, 0, sizeof(th_v));
    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    p1 = UTHBuildPacket(NULL, 0, IPPROTO_TCP);
    p2 = UTHBuildPacket(NULL, 0, IPPROTO_TCP);

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;
    f.flags |= FLOW_IPV4;

    p1->flow = &f;
    p1->flowflags |= FLOW_PKT_TOSERVER;
    p1->flowflags |= FLOW_PKT_ESTABLISHED;
    p1->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    p2->flow = &f;
    p2->flowflags |= FLOW_PKT_TOCLIENT;
    p2->flowflags |= FLOW_PKT_ESTABLISHED;
    p2->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    f.alproto = ALPROTO_HTTP1;

    StreamTcpInitConfig(true);

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert http any any -> any any "
                               "(msg:\"http server body test\"; "
                               "content:\"file\"; http_server_body; "
                               "sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParserParse(
            NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER, http_buf1, http_len1);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        goto end;
    }

    http_state = f.alstate;
    if (http_state == NULL) {
        printf("no http state: \n");
        result = 0;
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p1);

    if ((PacketAlertCheck(p1, 1))) {
        printf("sid 1 matched but shouldn't have\n");
        goto end;
    }

    r = AppLayerParserParse(
            NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOCLIENT, http_buf2, http_len2);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: \n", r);
        result = 0;
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p2);

#ifdef HAVE_HTP_CONFIG_SET_RESPONSE_DECOMPRESSION_LAYER_LIMIT
    FAIL_IF(!(PacketAlertCheck(p2, 1)));
#endif

    result = 1;

end:
    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);

    StreamTcpFreeConfig(true);
    FLOW_DESTROY(&f);
    UTHFreePackets(&p1, 1);
    UTHFreePackets(&p2, 1);
    return result;
}

/*
 * gzip stream with deflate set as content-encoding.
 */
static int DetectEngineHttpServerBodyTest21(void)
{
    TcpSession ssn;
    Packet *p1 = NULL;
    Packet *p2 = NULL;
    ThreadVars th_v;
    DetectEngineCtx *de_ctx = NULL;
    DetectEngineThreadCtx *det_ctx = NULL;
    HtpState *http_state = NULL;
    Flow f;
    uint8_t http_buf1[] =
        "GET /index.html HTTP/1.0\r\n"
        "Host: www.openinfosecfoundation.org\r\n"
        "User-Agent: Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.1.7) Gecko/20091221 Firefox/3.5.7\r\n"
        "\r\n";
    uint32_t http_len1 = sizeof(http_buf1) - 1;
    uint8_t http_buf2[] = {
        'H', 'T', 'T', 'P', '/', '1', '.', '1', ' ', '2', '0', '0', 'o', 'k', 0x0d, 0x0a,
        'C', 'o', 'n', 't', 'e', 'n', 't', '-', 'L', 'e', 'n', 'g', 't', 'h', ':', ' ', '5', '1', 0x0d, 0x0a,
        'C', 'o', 'n', 't', 'e', 'n', 't', '-', 'E', 'n', 'c', 'o', 'd', 'i', 'n', 'g', ':', ' ', 'd', 'e', 'f', 'l', 'a', 't', 'e', 0x0d, 0x0a,
        0x0d, 0x0a,
        0x1f, 0x8b, 0x08, 0x08, 0x27, 0x1e, 0xe5, 0x51,
        0x00, 0x03, 0x74, 0x65, 0x73, 0x74, 0x2e, 0x74,
        0x78, 0x74, 0x00, 0x2b, 0xc9, 0xc8, 0x2c, 0x56,
        0x00, 0xa2, 0x44, 0x85, 0xb4, 0xcc, 0x9c, 0x54,
        0x85, 0xcc, 0x3c, 0x20, 0x2b, 0x29, 0xbf, 0x42,
        0x8f, 0x0b, 0x00, 0xb2, 0x7d, 0xac, 0x9b, 0x19,
        0x00, 0x00, 0x00,
    };
    uint32_t http_len2 = sizeof(http_buf2);
    int result = 0;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&th_v, 0, sizeof(th_v));
    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    p1 = UTHBuildPacket(NULL, 0, IPPROTO_TCP);
    p2 = UTHBuildPacket(NULL, 0, IPPROTO_TCP);

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;
    f.flags |= FLOW_IPV4;

    p1->flow = &f;
    p1->flowflags |= FLOW_PKT_TOSERVER;
    p1->flowflags |= FLOW_PKT_ESTABLISHED;
    p1->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    p2->flow = &f;
    p2->flowflags |= FLOW_PKT_TOCLIENT;
    p2->flowflags |= FLOW_PKT_ESTABLISHED;
    p2->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    f.alproto = ALPROTO_HTTP1;

    StreamTcpInitConfig(true);

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert http any any -> any any "
                               "(msg:\"http server body test\"; "
                               "content:\"file\"; http_server_body; "
                               "sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParserParse(
            NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER, http_buf1, http_len1);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        goto end;
    }

    http_state = f.alstate;
    if (http_state == NULL) {
        printf("no http state: \n");
        result = 0;
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p1);

    if ((PacketAlertCheck(p1, 1))) {
        printf("sid 1 matched but shouldn't have\n");
        goto end;
    }

    r = AppLayerParserParse(
            NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOCLIENT, http_buf2, http_len2);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: \n", r);
        result = 0;
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p2);

#ifdef HAVE_HTP_CONFIG_SET_RESPONSE_DECOMPRESSION_LAYER_LIMIT
    FAIL_IF(!(PacketAlertCheck(p2, 1)));
#endif

    result = 1;

end:
    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);

    StreamTcpFreeConfig(true);
    FLOW_DESTROY(&f);
    UTHFreePackets(&p1, 1);
    UTHFreePackets(&p2, 1);
    return result;
}

/*
 * gzip stream.
 * We have 2 content-encoding headers.  First gzip and second deflate.
 */
static int DetectEngineHttpServerBodyTest22(void)
{
    TcpSession ssn;
    Packet *p1 = NULL;
    Packet *p2 = NULL;
    ThreadVars th_v;
    DetectEngineCtx *de_ctx = NULL;
    DetectEngineThreadCtx *det_ctx = NULL;
    HtpState *http_state = NULL;
    Flow f;
    uint8_t http_buf1[] =
        "GET /index.html HTTP/1.0\r\n"
        "Host: www.openinfosecfoundation.org\r\n"
        "User-Agent: Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.1.7) Gecko/20091221 Firefox/3.5.7\r\n"
        "\r\n";
    uint32_t http_len1 = sizeof(http_buf1) - 1;
    uint8_t http_buf2[] = {
        'H', 'T', 'T', 'P', '/', '1', '.', '1', ' ', '2', '0', '0', 'o', 'k', 0x0d, 0x0a,
        'C', 'o', 'n', 't', 'e', 'n', 't', '-', 'L', 'e', 'n', 'g', 't', 'h', ':', ' ', '5', '1', 0x0d, 0x0a,
        'C', 'o', 'n', 't', 'e', 'n', 't', '-', 'E', 'n', 'c', 'o', 'd', 'i', 'n', 'g', ':', ' ', 'g', 'z', 'i', 'p', 0x0d, 0x0a,
        'C', 'o', 'n', 't', 'e', 'n', 't', '-', 'E', 'n', 'c', 'o', 'd', 'i', 'n', 'g', ':', ' ', 'd', 'e', 'f', 'l', 'a', 't', 'e', 0x0d, 0x0a,
        0x0d, 0x0a,
        0x1f, 0x8b, 0x08, 0x08, 0x27, 0x1e, 0xe5, 0x51,
        0x00, 0x03, 0x74, 0x65, 0x73, 0x74, 0x2e, 0x74,
        0x78, 0x74, 0x00, 0x2b, 0xc9, 0xc8, 0x2c, 0x56,
        0x00, 0xa2, 0x44, 0x85, 0xb4, 0xcc, 0x9c, 0x54,
        0x85, 0xcc, 0x3c, 0x20, 0x2b, 0x29, 0xbf, 0x42,
        0x8f, 0x0b, 0x00, 0xb2, 0x7d, 0xac, 0x9b, 0x19,
        0x00, 0x00, 0x00,
    };
    uint32_t http_len2 = sizeof(http_buf2);
    int result = 0;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&th_v, 0, sizeof(th_v));
    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    p1 = UTHBuildPacket(NULL, 0, IPPROTO_TCP);
    p2 = UTHBuildPacket(NULL, 0, IPPROTO_TCP);

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;
    f.flags |= FLOW_IPV4;

    p1->flow = &f;
    p1->flowflags |= FLOW_PKT_TOSERVER;
    p1->flowflags |= FLOW_PKT_ESTABLISHED;
    p1->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    p2->flow = &f;
    p2->flowflags |= FLOW_PKT_TOCLIENT;
    p2->flowflags |= FLOW_PKT_ESTABLISHED;
    p2->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    f.alproto = ALPROTO_HTTP1;

    StreamTcpInitConfig(true);

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert http any any -> any any "
                               "(msg:\"http server body test\"; "
                               "content:\"file\"; http_server_body; "
                               "sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParserParse(
            NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER, http_buf1, http_len1);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        goto end;
    }

    http_state = f.alstate;
    if (http_state == NULL) {
        printf("no http state: \n");
        result = 0;
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p1);

    if ((PacketAlertCheck(p1, 1))) {
        printf("sid 1 matched but shouldn't have: ");
        goto end;
    }

    r = AppLayerParserParse(
            NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOCLIENT, http_buf2, http_len2);
    if (r != 0) {
        printf("toserver chunk 2 returned %" PRId32 ", expected 0: \n", r);
        result = 0;
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p2);

#ifdef HAVE_HTP_CONFIG_SET_RESPONSE_DECOMPRESSION_LAYER_LIMIT
    FAIL_IF(!(PacketAlertCheck(p2, 1)));
#endif

    result = 1;

end:
    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);

    StreamTcpFreeConfig(true);
    FLOW_DESTROY(&f);
    UTHFreePackets(&p1, 1);
    UTHFreePackets(&p2, 1);
    return result;
}

static int DetectEngineHttpServerBodyFileDataTest01(void)
{
    TcpSession ssn;
    Packet *p1 = NULL;
    Packet *p2 = NULL;
    ThreadVars th_v;
    DetectEngineCtx *de_ctx = NULL;
    DetectEngineThreadCtx *det_ctx = NULL;
    HtpState *http_state = NULL;
    Flow f;
    uint8_t http_buf1[] =
        "GET /index.html HTTP/1.0\r\n"
        "Host: www.openinfosecfoundation.org\r\n"
        "User-Agent: Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.1.7) Gecko/20091221 Firefox/3.5.7\r\n"
        "\r\n";
    uint32_t http_len1 = sizeof(http_buf1) - 1;
    uint8_t http_buf2[] =
        "HTTP/1.0 200 ok\r\n"
        "Content-Type: text/html\r\n"
        "Content-Length: 6\r\n"
        "\r\n"
        "abcdef";
    uint32_t http_len2 = sizeof(http_buf2) - 1;
    int result = 0;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&th_v, 0, sizeof(th_v));
    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    p1 = UTHBuildPacket(NULL, 0, IPPROTO_TCP);
    p2 = UTHBuildPacket(NULL, 0, IPPROTO_TCP);

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;
    f.flags |= FLOW_IPV4;

    p1->flow = &f;
    p1->flowflags |= FLOW_PKT_TOSERVER;
    p1->flowflags |= FLOW_PKT_ESTABLISHED;
    p1->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    p2->flow = &f;
    p2->flowflags |= FLOW_PKT_TOCLIENT;
    p2->flowflags |= FLOW_PKT_ESTABLISHED;
    p2->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    f.alproto = ALPROTO_HTTP1;

    StreamTcpInitConfig(true);

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert http any any -> any any "
                               "(msg:\"http server body test\"; "
                               "file_data; pcre:/ab/; "
                               "content:\"ef\"; distance:2; "
                               "sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParserParse(
            NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER, http_buf1, http_len1);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        goto end;
    }

    http_state = f.alstate;
    if (http_state == NULL) {
        printf("no http state: \n");
        result = 0;
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p1);

    if (PacketAlertCheck(p1, 1)) {
        printf("sid 1 matched but shouldn't have: ");
        goto end;
    }

    r = AppLayerParserParse(
            NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOCLIENT, http_buf2, http_len2);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: \n", r);
        result = 0;
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p2);

    if (!PacketAlertCheck(p2, 1)) {
        printf("sid 1 did not match but should have: ");
        goto end;
    }

    result = 1;

end:
    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);

    StreamTcpFreeConfig(true);
    FLOW_DESTROY(&f);
    UTHFreePackets(&p1, 1);
    UTHFreePackets(&p2, 1);
    return result;
}

static int DetectEngineHttpServerBodyFileDataTest02(void)
{
    TcpSession ssn;
    Packet *p1 = NULL;
    Packet *p2 = NULL;
    ThreadVars th_v;
    DetectEngineCtx *de_ctx = NULL;
    DetectEngineThreadCtx *det_ctx = NULL;
    HtpState *http_state = NULL;
    Flow f;
    uint8_t http_buf1[] =
        "GET /index.html HTTP/1.0\r\n"
        "Host: www.openinfosecfoundation.org\r\n"
        "User-Agent: Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.1.7) Gecko/20091221 Firefox/3.5.7\r\n"
        "\r\n";
    uint32_t http_len1 = sizeof(http_buf1) - 1;
    uint8_t http_buf2[] =
        "HTTP/1.0 200 ok\r\n"
        "Content-Type: text/html\r\n"
        "Content-Length: 6\r\n"
        "\r\n"
        "abcdef";
    uint32_t http_len2 = sizeof(http_buf2) - 1;
    int result = 0;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&th_v, 0, sizeof(th_v));
    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    p1 = UTHBuildPacket(NULL, 0, IPPROTO_TCP);
    p2 = UTHBuildPacket(NULL, 0, IPPROTO_TCP);

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;
    f.flags |= FLOW_IPV4;

    p1->flow = &f;
    p1->flowflags |= FLOW_PKT_TOSERVER;
    p1->flowflags |= FLOW_PKT_ESTABLISHED;
    p1->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    p2->flow = &f;
    p2->flowflags |= FLOW_PKT_TOCLIENT;
    p2->flowflags |= FLOW_PKT_ESTABLISHED;
    p2->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    f.alproto = ALPROTO_HTTP1;

    StreamTcpInitConfig(true);

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert http any any -> any any "
                               "(msg:\"http server body test\"; "
                               "file_data; pcre:/abc/; "
                               "content:!\"xyz\"; distance:0; within:3; "
                               "sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParserParse(
            NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER, http_buf1, http_len1);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        goto end;
    }

    http_state = f.alstate;
    if (http_state == NULL) {
        printf("no http state: \n");
        result = 0;
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p1);

    if (PacketAlertCheck(p1, 1)) {
        printf("sid 1 matched but shouldn't have: ");
        goto end;
    }

    r = AppLayerParserParse(
            NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOCLIENT, http_buf2, http_len2);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: \n", r);
        result = 0;
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p2);

    if (!PacketAlertCheck(p2, 1)) {
        printf("sid 1 did not match but should have: ");
        goto end;
    }

    result = 1;

end:
    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);

    StreamTcpFreeConfig(true);
    FLOW_DESTROY(&f);
    UTHFreePackets(&p1, 1);
    UTHFreePackets(&p2, 1);
    return result;
}

/* \test recursive relative byte test */
static int DetectEngineHttpServerBodyFileDataTest03(void)
{
    TcpSession ssn;
    Packet *p1 = NULL;
    Packet *p2 = NULL;
    ThreadVars th_v;
    DetectEngineCtx *de_ctx = NULL;
    DetectEngineThreadCtx *det_ctx = NULL;
    HtpState *http_state = NULL;
    Flow f;
    uint8_t http_buf1[] =
        "GET /index.html HTTP/1.0\r\n"
        "Host: www.openinfosecfoundation.org\r\n"
        "User-Agent: Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.1.7) Gecko/20091221 Firefox/3.5.7\r\n"
        "\r\n";
    uint32_t http_len1 = sizeof(http_buf1) - 1;
    uint8_t http_buf2[] =
        "HTTP/1.0 200 ok\r\n"
        "Content-Type: text/html\r\n"
        "Content-Length: 33\r\n"
        "\r\n"
        "XYZ_klm_1234abcd_XYZ_klm_5678abcd";
    uint32_t http_len2 = sizeof(http_buf2) - 1;
    int result = 0;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&th_v, 0, sizeof(th_v));
    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    p1 = UTHBuildPacket(NULL, 0, IPPROTO_TCP);
    p2 = UTHBuildPacket(NULL, 0, IPPROTO_TCP);

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;
    f.flags |= FLOW_IPV4;

    p1->flow = &f;
    p1->flowflags |= FLOW_PKT_TOSERVER;
    p1->flowflags |= FLOW_PKT_ESTABLISHED;
    p1->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    p2->flow = &f;
    p2->flowflags |= FLOW_PKT_TOCLIENT;
    p2->flowflags |= FLOW_PKT_ESTABLISHED;
    p2->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    f.alproto = ALPROTO_HTTP1;

    StreamTcpInitConfig(true);

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;

    if (!(DetectEngineAppendSig(de_ctx, "alert http any any -> any any "
                               "(msg:\"match on 1st\"; "
                               "file_data; content:\"XYZ\"; content:\"_klm_\"; distance:0; content:\"abcd\"; distance:4; byte_test:4,=,1234,-8,relative,string;"
                               "sid:1;)")))
        goto end;
    if (!(DetectEngineAppendSig(de_ctx, "alert http any any -> any any "
                               "(msg:\"match on 2nd\"; "
                               "file_data; content:\"XYZ\"; content:\"_klm_\"; distance:0; content:\"abcd\"; distance:4; byte_test:4,=,5678,-8,relative,string;"
                               "sid:2;)")))
        goto end;

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParserParse(
            NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER, http_buf1, http_len1);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        goto end;
    }

    http_state = f.alstate;
    if (http_state == NULL) {
        printf("no http state: \n");
        result = 0;
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p1);

    if (PacketAlertCheck(p1, 1)) {
        printf("sid 1 matched but shouldn't have: ");
        goto end;
    }

    r = AppLayerParserParse(
            NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOCLIENT, http_buf2, http_len2);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: \n", r);
        result = 0;
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p2);

    if (!PacketAlertCheck(p2, 1)) {
        printf("sid 1 did not match but should have: ");
        goto end;
    }
    if (!PacketAlertCheck(p2, 2)) {
        printf("sid 2 did not match but should have: ");
        goto end;
    }

    result = 1;

end:
    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);

    StreamTcpFreeConfig(true);
    FLOW_DESTROY(&f);
    UTHFreePackets(&p1, 1);
    UTHFreePackets(&p2, 1);
    return result;
}

static int DetectEngineHttpServerBodyFileDataTest04(void)
{

    const char yaml[] = "\
%YAML 1.1\n\
---\n\
libhtp:\n\
\n\
  default-config:\n\
\n\
    http-body-inline: yes\n\
    response-body-minimal-inspect-size: 6\n\
    response-body-inspect-window: 3\n\
";

    struct TestSteps steps[] = {
        {   (const uint8_t *)"GET /index.html HTTP/1.0\r\n"
            "Host: www.openinfosecfoundation.org\r\n"
            "User-Agent: Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.1.7) Gecko/20091221 Firefox/3.5.7\r\n"
            "\r\n",
            0, STREAM_TOSERVER, 0 },
        {   (const uint8_t *)"HTTP/1.0 200 ok\r\n"
            "Content-Type: text/html\r\n"
            "Content-Length: 6\r\n"
            "\r\n"
            "ab",
            0, STREAM_TOCLIENT, 0 },
        {   (const uint8_t *)"cd",
            0, STREAM_TOCLIENT, 1 },
        {   (const uint8_t *)"ef",
            0, STREAM_TOCLIENT, 0 },
        {   NULL, 0, 0, 0 },
    };

    const char *sig = "alert http any any -> any any (file_data; content:\"abcd\"; sid:1;)";
    return RunTest(steps, sig, yaml);
}

static int DetectEngineHttpServerBodyFileDataTest05(void)
{

    const char yaml[] = "\
%YAML 1.1\n\
---\n\
libhtp:\n\
\n\
  default-config:\n\
\n\
    http-body-inline: yes\n\
    response-body-minimal-inspect-size: 6\n\
    response-body-inspect-window: 3\n\
";

    struct TestSteps steps[] = {
        {   (const uint8_t *)"GET /index.html HTTP/1.0\r\n"
            "Host: www.openinfosecfoundation.org\r\n"
            "User-Agent: Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.1.7) Gecko/20091221 Firefox/3.5.7\r\n"
            "\r\n",
            0, STREAM_TOSERVER, 0 },
        {   (const uint8_t *)"HTTP/1.0 200 ok\r\n"
            "Content-Type: text/html\r\n"
            "Content-Length: 6\r\n"
            "\r\n"
            "ab",
            0, STREAM_TOCLIENT, 0 },
        {   (const uint8_t *)"cd",
            0, STREAM_TOCLIENT, 0 },
        {   (const uint8_t *)"ef",
            0, STREAM_TOCLIENT, 1 },
        {   NULL, 0, 0, 0 },
    };

    const char *sig = "alert http any any -> any any (file_data; content:\"abcdef\"; sid:1;)";
    return RunTest(steps, sig, yaml);
}

static int DetectEngineHttpServerBodyFileDataTest06(void)
{

    const char yaml[] = "\
%YAML 1.1\n\
---\n\
libhtp:\n\
\n\
  default-config:\n\
\n\
    http-body-inline: yes\n\
    response-body-minimal-inspect-size: 6\n\
    response-body-inspect-window: 3\n\
";

    struct TestSteps steps[] = {
        {   (const uint8_t *)"GET /index.html HTTP/1.0\r\n"
            "Host: www.openinfosecfoundation.org\r\n"
            "User-Agent: Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.1.7) Gecko/20091221 Firefox/3.5.7\r\n"
            "\r\n",
            0, STREAM_TOSERVER, 0 },
        {   (const uint8_t *)"HTTP/1.0 200 ok\r\n"
            "Content-Type: text/html\r\n"
            "Content-Length: 6\r\n"
            "\r\n"
            "ab",
            0, STREAM_TOCLIENT, 0 },
        {   (const uint8_t *)"cd",
            0, STREAM_TOCLIENT, 0 },
        {   (const uint8_t *)"ef",
            0, STREAM_TOCLIENT, 1 },
        {   NULL, 0, 0, 0 },
    };

    const char *sig = "alert http any any -> any any (file_data; content:\"bcdef\"; offset:1; sid:1;)";
    return RunTest(steps, sig, yaml);
}

static int DetectEngineHttpServerBodyFileDataTest07(void)
{

    const char yaml[] = "\
%YAML 1.1\n\
---\n\
libhtp:\n\
\n\
  default-config:\n\
\n\
    http-body-inline: yes\n\
    response-body-minimal-inspect-size: 6\n\
    response-body-inspect-window: 3\n\
";

    struct TestSteps steps[] = {
        {   (const uint8_t *)"GET /index.html HTTP/1.0\r\n"
            "Host: www.openinfosecfoundation.org\r\n"
            "User-Agent: Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.1.7) Gecko/20091221 Firefox/3.5.7\r\n"
            "\r\n",
            0, STREAM_TOSERVER, 0 },
        {   (const uint8_t *)"HTTP/1.0 200 ok\r\n"
            "Content-Type: text/html\r\n"
            "Content-Length: 13\r\n"
            "\r\n"
            "ab",
            0, STREAM_TOCLIENT, 0 },
        {   (const uint8_t *)"cd",
            0, STREAM_TOCLIENT, 1 },
        {   (const uint8_t *)"123456789",
            0, STREAM_TOCLIENT, 0 },
        {   NULL, 0, 0, 0 },
    };

    const char *sig = "alert http any any -> any any (file_data; content:\"bc\"; offset:1; depth:2; sid:1;)";
    return RunTest(steps, sig, yaml);
}

static int DetectEngineHttpServerBodyFileDataTest08(void)
{

    const char yaml[] = "\
%YAML 1.1\n\
---\n\
libhtp:\n\
\n\
  default-config:\n\
\n\
    http-body-inline: yes\n\
    response-body-minimal-inspect-size: 6\n\
    response-body-inspect-window: 3\n\
";

    struct TestSteps steps[] = {
        {   (const uint8_t *)"GET /index.html HTTP/1.0\r\n"
            "Host: www.openinfosecfoundation.org\r\n"
            "User-Agent: Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.1.7) Gecko/20091221 Firefox/3.5.7\r\n"
            "\r\n",
            0, STREAM_TOSERVER, 0 },
        {   (const uint8_t *)"HTTP/1.0 200 ok\r\n"
            "Content-Type: text/html\r\n"
            "Content-Length: 14\r\n"
            "\r\n"
            "ab",
            0, STREAM_TOCLIENT, 0 },
        {   (const uint8_t *)"cd",
            0, STREAM_TOCLIENT, 0 },
        {   (const uint8_t *)"1234567890",
            0, STREAM_TOCLIENT, 1 },
        {   NULL, 0, 0, 0 },
    };

    const char *sig = "alert http any any -> any any (file_data; content:\"d123456789\"; offset:3; sid:1;)";
    return RunTest(steps, sig, yaml);
}

static int DetectEngineHttpServerBodyFileDataTest09(void)
{

    const char yaml[] = "\
%YAML 1.1\n\
---\n\
libhtp:\n\
\n\
  default-config:\n\
\n\
    http-body-inline: yes\n\
    response-body-minimal-inspect-size: 6\n\
    response-body-inspect-window: 3\n\
";

    struct TestSteps steps[] = {
        {   (const uint8_t *)"GET /index.html HTTP/1.0\r\n"
            "Host: www.openinfosecfoundation.org\r\n"
            "User-Agent: Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.1.7) Gecko/20091221 Firefox/3.5.7\r\n"
            "\r\n",
            0, STREAM_TOSERVER, 0 },
        {   (const uint8_t *)"HTTP/1.0 200 ok\r\n"
            "Content-Type: text/html\r\n"
            "Content-Length: 13\r\n"
            "\r\n"
            "ab",
            0, STREAM_TOCLIENT, 0 },
        {   (const uint8_t *)"cd",
            0, STREAM_TOCLIENT, 0 },
        {   (const uint8_t *)"123456789",
            0, STREAM_TOCLIENT, 1 },
        {   NULL, 0, 0, 0 },
    };

    const char *sig = "alert http any any -> any any (file_data; content:\"abcd12\"; depth:6; sid:1;)";
    return RunTest(steps, sig, yaml);
}

static int DetectEngineHttpServerBodyFileDataTest10(void)
{

    const char yaml[] = "\
%YAML 1.1\n\
---\n\
libhtp:\n\
\n\
  default-config:\n\
\n\
    http-body-inline: yes\n\
    response-body-minimal-inspect-size: 6\n\
    response-body-inspect-window: 3\n\
";

    struct TestSteps steps[] = {
        {   (const uint8_t *)"GET /index.html HTTP/1.0\r\n"
            "Host: www.openinfosecfoundation.org\r\n"
            "User-Agent: Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.1.7) Gecko/20091221 Firefox/3.5.7\r\n"
            "\r\n",
            0, STREAM_TOSERVER, 0 },
        {   (const uint8_t *)"HTTP/1.0 200 ok\r\n"
            "Content-Type: text/html\r\n"
            "Content-Length: 5\r\n"
            "\r\n"
            "ab",
            0, STREAM_TOCLIENT, 0 },
        {   (const uint8_t *)"c",
            0, STREAM_TOCLIENT, 1 },
        {   (const uint8_t *)"de",
            0, STREAM_TOCLIENT, 0 },
        {   NULL, 0, 0, 0 },
    };

    const char *sig = "alert http any any -> any any (file_data; content:\"abc\"; depth:3; sid:1;)";
    return RunTest(steps, sig, yaml);
}

static int DetectEngineHttpServerBodyFileDataTest11(void)
{

    const char yaml[] = "\
%YAML 1.1\n\
---\n\
libhtp:\n\
\n\
  default-config:\n\
\n\
    http-body-inline: yes\n\
    response-body-minimal-inspect-size: 6\n\
    response-body-inspect-window: 3\n\
";

    struct TestSteps steps[] = {
        {   (const uint8_t *)"GET /index.html HTTP/1.0\r\n"
            "Host: www.openinfosecfoundation.org\r\n"
            "User-Agent: Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.1.7) Gecko/20091221 Firefox/3.5.7\r\n"
            "\r\n",
            0, STREAM_TOSERVER, 0 },
        {   (const uint8_t *)"HTTP/1.0 200 ok\r\n"
            "Content-Type: text/html\r\n"
            "Content-Length: 5\r\n"
            "\r\n"
            "ab",
            0, STREAM_TOCLIENT, 0 },
        {   (const uint8_t *)"c",
            0, STREAM_TOCLIENT, 0 },
        {   (const uint8_t *)"de",
            0, STREAM_TOCLIENT, 1 },
        {   NULL, 0, 0, 0 },
    };

    const char *sig = "alert http any any -> any any (file_data; content:\"bcde\"; offset:1; depth:4; sid:1;)";
    return RunTest(steps, sig, yaml);
}

static int DetectEngineHttpServerBodyFileDataTest12(void)
{

    const char yaml[] = "\
%YAML 1.1\n\
---\n\
libhtp:\n\
\n\
  default-config:\n\
\n\
    http-body-inline: yes\n\
    response-body-minimal-inspect-size: 6\n\
    response-body-inspect-window: 3\n\
";

    struct TestSteps steps[] = {
        {   (const uint8_t *)"GET /index.html HTTP/1.0\r\n"
            "Host: www.openinfosecfoundation.org\r\n"
            "User-Agent: Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.1.7) Gecko/20091221 Firefox/3.5.7\r\n"
            "\r\n",
            0, STREAM_TOSERVER, 0 },
        {   (const uint8_t *)"HTTP/1.0 200 ok\r\n"
            "Content-Type: text/html\r\n"
            "Content-Length: 13\r\n"
            "\r\n"
            "a",
            0, STREAM_TOCLIENT, 0 },
        {   (const uint8_t *)"b",
            0, STREAM_TOCLIENT, 0 },
        {   (const uint8_t *)"c",
            0, STREAM_TOCLIENT, 0 },
        {   (const uint8_t *)"d",
            0, STREAM_TOCLIENT, 1 },
        {   (const uint8_t *)"efghijklm",
            0, STREAM_TOCLIENT, 0 },
        {   NULL, 0, 0, 0 },
    };

    const char *sig = "alert http any any -> any any (file_data; content:\"abcd\"; sid:1;)";
    return RunTest(steps, sig, yaml);
}

static int DetectEngineHttpServerBodyFileDataTest13(void)
{

    const char yaml[] = "\
%YAML 1.1\n\
---\n\
libhtp:\n\
\n\
  default-config:\n\
\n\
    http-body-inline: yes\n\
    response-body-minimal-inspect-size: 9\n\
    response-body-inspect-window: 12\n\
";

    struct TestSteps steps[] = {
        {   (const uint8_t *)"GET /index.html HTTP/1.0\r\n"
            "Host: www.openinfosecfoundation.org\r\n"
            "User-Agent: Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.1.7) Gecko/20091221 Firefox/3.5.7\r\n"
            "\r\n",
            0, STREAM_TOSERVER, 0 },
        {   (const uint8_t *)"HTTP/1.0 200 ok\r\n"
            "Content-Type: text/html\r\n"
            "Content-Length: 13\r\n"
            "\r\n"
            "a",
            0, STREAM_TOCLIENT, 0 },
        {   (const uint8_t *)"b",
            0, STREAM_TOCLIENT, 0 },
        {   (const uint8_t *)"c",
            0, STREAM_TOCLIENT, 0 },
        {   (const uint8_t *)"d",
            0, STREAM_TOCLIENT, 0 },
        {   (const uint8_t *)"efghijklm",
            0, STREAM_TOCLIENT, 1 },
        {   NULL, 0, 0, 0 },
    };

    const char *sig = "alert http any any -> any any (file_data; content:\"abcdefghijklm\"; sid:1;)";
    return RunTest(steps, sig, yaml);
}

static int DetectEngineHttpServerBodyFileDataTest14(void)
{

    const char yaml[] = "\
%YAML 1.1\n\
---\n\
libhtp:\n\
\n\
  default-config:\n\
\n\
    http-body-inline: yes\n\
    response-body-minimal-inspect-size: 9\n\
    response-body-inspect-window: 12\n\
";

    struct TestSteps steps[] = {
        {   (const uint8_t *)"GET /index.html HTTP/1.0\r\n"
            "Host: www.openinfosecfoundation.org\r\n"
            "User-Agent: Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.1.7) Gecko/20091221 Firefox/3.5.7\r\n"
            "\r\n",
            0, STREAM_TOSERVER, 0 },
        {   (const uint8_t *)"HTTP/1.0 200 ok\r\n"
            "Content-Type: text/html\r\n"
            "Content-Length: 20\r\n"
            "\r\n"
            "1234567890",
            0, STREAM_TOCLIENT, 0 },
        {   (const uint8_t *)"abcdefghi",
            0, STREAM_TOCLIENT, 1 },
        {   NULL, 0, 0, 0 },
    };

    const char *sig = "alert http any any -> any any (file_data; content:\"890abcdefghi\"; sid:1;)";
    return RunTest(steps, sig, yaml);
}

static int DetectEngineHttpServerBodyFileDataTest15(void)
{

    const char yaml[] = "\
%YAML 1.1\n\
---\n\
libhtp:\n\
\n\
  default-config:\n\
\n\
    http-body-inline: yes\n\
    response-body-minimal-inspect-size: 9\n\
    response-body-inspect-window: 12\n\
";

    struct TestSteps steps[] = {
        {   (const uint8_t *)"GET /index.html HTTP/1.0\r\n"
            "Host: www.openinfosecfoundation.org\r\n"
            "User-Agent: Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.1.7) Gecko/20091221 Firefox/3.5.7\r\n"
            "\r\n",
            0, STREAM_TOSERVER, 0 },
        {   (const uint8_t *)"HTTP/1.0 200 ok\r\n"
            "Content-Type: text/html\r\n"
            "Content-Length: 20\r\n"
            "\r\n"
            "1234567890",
            0, STREAM_TOCLIENT, 0 },
        {   (const uint8_t *)"abcdefghi",
            0, STREAM_TOCLIENT, 0 },
        {   NULL, 0, 0, 0 },
    };

    const char *sig = "alert http any any -> any any (file_data; content:\"7890ab\"; depth:6; sid:1;)";
    return RunTest(steps, sig, yaml);
}

static int DetectEngineHttpServerBodyFileDataTest16(void)
{

    const char yaml[] = "\
%YAML 1.1\n\
---\n\
libhtp:\n\
\n\
  default-config:\n\
\n\
    http-body-inline: yes\n\
    response-body-minimal-inspect-size: 9\n\
    response-body-inspect-window: 12\n\
";

    struct TestSteps steps[] = {
        {   (const uint8_t *)"GET /index.html HTTP/1.0\r\n"
            "Host: www.openinfosecfoundation.org\r\n"
            "User-Agent: Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.1.7) Gecko/20091221 Firefox/3.5.7\r\n"
            "\r\n",
            0, STREAM_TOSERVER, 0 },
        {   (const uint8_t *)"HTTP/1.0 200 ok\r\n"
            "Content-Type: text/html\r\n"
            "Content-Length: 20\r\n"
            "\r\n"
            "aaaab",
            0, STREAM_TOCLIENT, 0 },
        {   (const uint8_t *)"bbbbc",
            0, STREAM_TOCLIENT, 0 },
        {   (const uint8_t *)"ccccd",
            0, STREAM_TOCLIENT, 0 },
        {   (const uint8_t *)"dddde",
            0, STREAM_TOCLIENT, 0 },
        {   NULL, 0, 0, 0 },
    };

    const char *sig = "alert http any any -> any any (file_data; content:\"aabb\"; depth:4; sid:1;)";
    return RunTest(steps, sig, yaml);
}

static int DetectEngineHttpServerBodyFileDataTest17(void)
{

    const char yaml[] = "\
%YAML 1.1\n\
---\n\
libhtp:\n\
\n\
  default-config:\n\
\n\
    http-body-inline: yes\n\
    response-body-minimal-inspect-size: 8\n\
    response-body-inspect-window: 4\n\
";

    struct TestSteps steps[] = {
        {   (const uint8_t *)"GET /index.html HTTP/1.0\r\n"
            "Host: www.openinfosecfoundation.org\r\n"
            "User-Agent: Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.1.7) Gecko/20091221 Firefox/3.5.7\r\n"
            "\r\n",
            0, STREAM_TOSERVER, 0 },
        {   (const uint8_t *)"HTTP/1.0 200 ok\r\n"
            "Content-Type: text/html\r\n"
            "Content-Length: 20\r\n"
            "\r\n"
            "aaaab",
            0, STREAM_TOCLIENT, 0 },
        {   (const uint8_t *)"bbbbc",
            0, STREAM_TOCLIENT, 0 },
        {   (const uint8_t *)"ccccd",
            0, STREAM_TOCLIENT, 0 },
        {   (const uint8_t *)"dddde",
            0, STREAM_TOCLIENT, 0 },
        {   NULL, 0, 0, 0 },
    };

    const char *sig = "alert http any any -> any any (file_data; content:\"bbbc\"; depth:4; sid:1;)";
    return RunTest(steps, sig, yaml);
}

static int DetectEngineHttpServerBodyFileDataTest18(void)
{

    const char yaml[] = "\
%YAML 1.1\n\
---\n\
libhtp:\n\
\n\
  default-config:\n\
\n\
    http-body-inline: yes\n\
    response-body-minimal-inspect-size: 8\n\
    response-body-inspect-window: 4\n\
";

    struct TestSteps steps[] = {
        {   (const uint8_t *)"GET /index.html HTTP/1.0\r\n"
            "Host: www.openinfosecfoundation.org\r\n"
            "User-Agent: Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.1.7) Gecko/20091221 Firefox/3.5.7\r\n"
            "\r\n",
            0, STREAM_TOSERVER, 0 },
        {   (const uint8_t *)"HTTP/1.0 200 ok\r\n"
            "Content-Type: text/html\r\n"
            "Content-Length: 20\r\n"
            "\r\n"
            "aaaab",
            0, STREAM_TOCLIENT, 0 },
        {   (const uint8_t *)"bbbbc",
            0, STREAM_TOCLIENT, 0 },
        {   (const uint8_t *)"ccccd",
            0, STREAM_TOCLIENT, 0 },
        {   (const uint8_t *)"dddde",
            0, STREAM_TOCLIENT, 0 },
        {   NULL, 0, 0, 0 },
    };

    const char *sig = "alert http any any -> any any (file_data; content:\"bccd\"; depth:4; sid:1;)";
    return RunTest(steps, sig, yaml);
}
static int DetectEngineHttpServerBodyFileDataTest19(void)
{
    char input[] = "\
%YAML 1.1\n\
---\n\
libhtp:\n\
\n\
  default-config:\n\
\n\
    swf-decompression:\n\
      enabled: yes\n\
      type: both\n\
      compress-depth: 0\n\
      decompress-depth: 0\n\
";
    ConfCreateContextBackup();
    ConfInit();
    HtpConfigCreateBackup();
    ConfYamlLoadString(input, strlen(input));
    HTPConfigure();
    TcpSession ssn;
    Packet *p1 = NULL;
    Packet *p2 = NULL;
    ThreadVars th_v;
    DetectEngineCtx *de_ctx = NULL;
    DetectEngineThreadCtx *det_ctx = NULL;
    HtpState *http_state = NULL;
    Flow f;
    uint8_t http_buf1[] =
        "GET /file.swf HTTP/1.0\r\n"
        "Host: www.openinfosecfoundation.org\r\n"
        "User-Agent: Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.1.7) Gecko/20091221 Firefox/3.5.7\r\n"
        "\r\n";
    uint32_t http_len1 = sizeof(http_buf1) - 1;
    uint8_t http_buf2[] = {
        'H', 'T', 'T', 'P', '/', '1', '.', '1', ' ', '2', '0', '0', 'o', 'k', 0x0d, 0x0a,
        'C', 'o', 'n', 't', 'e', 'n', 't', '-', 'L', 'e', 'n', 'g', 't', 'h', ':', ' ', '8', '0', 0x0d, 0x0a,
        'C', 'o', 'n', 't', 'e', 'n', 't', '-', 'T', 'y', 'p', 'e', ':', ' ',
        'a','p','p','l','i','c','a','t','i','o','n','/','x','-','s','h','o','c','k','w','a','v','e','-','f','l','a','s','h', 0x0d, 0x0a,
        0x0d, 0x0a,
        0x43, 0x57, 0x53, 0x0a, 0xcb, 0x6c, 0x00, 0x00, 0x78, 0xda, 0xad, 0xbd, 0x07, 0x98, 0x55, 0x55,
        0x9e, 0xee, 0xbd, 0x4f, 0xd8, 0xb5, 0x4e, 0x15, 0xc1, 0xc2, 0x80, 0x28, 0x86, 0xd2, 0x2e, 0x5a,
        0xdb, 0x46, 0xd9, 0x39, 0x38, 0xdd, 0x4e, 0x1b, 0xa8, 0x56, 0x5b, 0xc5, 0x6b, 0xe8, 0x76, 0xfa,
        0x0e, 0xc2, 0x8e, 0x50, 0x76, 0x51, 0xc5, 0x54, 0x15, 0x88, 0x73, 0xc3, 0xd0, 0x88, 0x39, 0x81,
        0x98, 0x63, 0x91, 0x93, 0x8a, 0x82, 0x89, 0x60, 0x00, 0xcc, 0xb1, 0x00, 0x01, 0x73, 0xce, 0x39,
    };
    uint32_t http_len2 = sizeof(http_buf2);
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();
    FAIL_IF_NULL(alp_tctx);

    memset(&th_v, 0, sizeof(th_v));
    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    p1 = UTHBuildPacket(NULL, 0, IPPROTO_TCP);
    p2 = UTHBuildPacket(NULL, 0, IPPROTO_TCP);

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;
    f.flags |= FLOW_IPV4;

    p1->flow = &f;
    p1->flowflags |= FLOW_PKT_TOSERVER;
    p1->flowflags |= FLOW_PKT_ESTABLISHED;
    p1->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    p2->flow = &f;
    p2->flowflags |= FLOW_PKT_TOCLIENT;
    p2->flowflags |= FLOW_PKT_ESTABLISHED;
    p2->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    f.alproto = ALPROTO_HTTP1;

    StreamTcpInitConfig(true);

    de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert tcp any any -> any any "
                               "(flow:established,from_server; "
                               "file_data; content:\"FWS\"; "
                               "sid:1;)");
    FAIL_IF_NULL(de_ctx->sig_list);

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParserParse(
            &th_v, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER, http_buf1, http_len1);
    FAIL_IF(r != 0);

    http_state = f.alstate;
    FAIL_IF_NULL(http_state);

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p1);

    FAIL_IF((PacketAlertCheck(p1, 1)));

    r = AppLayerParserParse(
            &th_v, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOCLIENT, http_buf2, http_len2);
    FAIL_IF(r != 0);

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p2);

    FAIL_IF(!(PacketAlertCheck(p2, 1)));

    AppLayerParserThreadCtxFree(alp_tctx);
    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);

    HTPFreeConfig();
    HtpConfigRestoreBackup();
    ConfRestoreContextBackup();

    StreamTcpFreeConfig(true);
    FLOW_DESTROY(&f);
    UTHFreePackets(&p1, 1);
    UTHFreePackets(&p2, 1);
    PASS;
}

static int DetectEngineHttpServerBodyFileDataTest20(void)
{
    char input[] = "\
%YAML 1.1\n\
---\n\
libhtp:\n\
\n\
  default-config:\n\
\n\
    swf-decompression:\n\
      enabled: no\n\
      type: both\n\
      compress-depth: 0\n\
      decompress-depth: 0\n\
";

    ConfCreateContextBackup();
    ConfInit();
    HtpConfigCreateBackup();

    ConfYamlLoadString(input, strlen(input));
    HTPConfigure();

    TcpSession ssn;
    Packet *p1 = NULL;
    Packet *p2 = NULL;
    ThreadVars th_v;
    DetectEngineCtx *de_ctx = NULL;
    DetectEngineThreadCtx *det_ctx = NULL;
    HtpState *http_state = NULL;
    Flow f;
    uint8_t http_buf1[] =
        "GET /file.swf HTTP/1.0\r\n"
        "Host: www.openinfosecfoundation.org\r\n"
        "User-Agent: Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.1.7) Gecko/20091221 Firefox/3.5.7\r\n"
        "\r\n";
    uint32_t http_len1 = sizeof(http_buf1) - 1;
    uint8_t http_buf2[] = {
        'H', 'T', 'T', 'P', '/', '1', '.', '1', ' ', '2', '0', '0', 'o', 'k', 0x0d, 0x0a,
        'C', 'o', 'n', 't', 'e', 'n', 't', '-', 'L', 'e', 'n', 'g', 't', 'h', ':', ' ', '8', '0', 0x0d, 0x0a,
        'C', 'o', 'n', 't', 'e', 'n', 't', '-', 'T', 'y', 'p', 'e', ':', ' ',
        'a','p','p','l','i','c','a','t','i','o','n','/','x','-','s','h','o','c','k','w','a','v','e','-','f','l','a','s','h', 0x0d, 0x0a,
        0x0d, 0x0a,
        0x43, 0x57, 0x53, 0x0a, 0xcb, 0x6c, 0x00, 0x00, 0x78, 0xda, 0xad, 0xbd, 0x07, 0x98, 0x55, 0x55,
        0x9e, 0xee, 0xbd, 0x4f, 0xd8, 0xb5, 0x4e, 0x15, 0xc1, 0xc2, 0x80, 0x28, 0x86, 0xd2, 0x2e, 0x5a,
        0xdb, 0x46, 0xd9, 0x39, 0x38, 0xdd, 0x4e, 0x1b, 0xa8, 0x56, 0x5b, 0xc5, 0x6b, 0xe8, 0x76, 0xfa,
        0x0e, 0xc2, 0x8e, 0x50, 0x76, 0x51, 0xc5, 0x54, 0x15, 0x88, 0x73, 0xc3, 0xd0, 0x88, 0x39, 0x81,
        0x98, 0x63, 0x91, 0x93, 0x8a, 0x82, 0x89, 0x60, 0x00, 0xcc, 0xb1, 0x00, 0x01, 0x73, 0xce, 0x39,
    };
    uint32_t http_len2 = sizeof(http_buf2);
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();
    FAIL_IF_NULL(alp_tctx);

    memset(&th_v, 0, sizeof(th_v));
    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    p1 = UTHBuildPacket(NULL, 0, IPPROTO_TCP);
    p2 = UTHBuildPacket(NULL, 0, IPPROTO_TCP);

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;
    f.flags |= FLOW_IPV4;

    p1->flow = &f;
    p1->flowflags |= FLOW_PKT_TOSERVER;
    p1->flowflags |= FLOW_PKT_ESTABLISHED;
    p1->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    p2->flow = &f;
    p2->flowflags |= FLOW_PKT_TOCLIENT;
    p2->flowflags |= FLOW_PKT_ESTABLISHED;
    p2->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    f.alproto = ALPROTO_HTTP1;

    StreamTcpInitConfig(true);

    de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert tcp any any -> any any "
                               "(flow:established,from_server; "
                               "file_data; content:\"CWS\"; "
                               "sid:1;)");
    FAIL_IF_NULL(de_ctx->sig_list);

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParserParse(
            &th_v, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER, http_buf1, http_len1);
    FAIL_IF(r != 0);

    http_state = f.alstate;
    FAIL_IF_NULL(http_state);

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p1);

    FAIL_IF((PacketAlertCheck(p1, 1)));

    r = AppLayerParserParse(
            &th_v, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOCLIENT, http_buf2, http_len2);
    FAIL_IF(r != 0);

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p2);

    FAIL_IF(!(PacketAlertCheck(p2, 1)));

    AppLayerParserThreadCtxFree(alp_tctx);
    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);

    HTPFreeConfig();
    HtpConfigRestoreBackup();
    ConfRestoreContextBackup();

    StreamTcpFreeConfig(true);
    FLOW_DESTROY(&f);
    UTHFreePackets(&p1, 1);
    UTHFreePackets(&p2, 1);
    PASS;
}

static int DetectEngineHttpServerBodyFileDataTest21(void)
{
    char input[] = "\
%YAML 1.1\n\
---\n\
libhtp:\n\
\n\
  default-config:\n\
\n\
    swf-decompression:\n\
      enabled: yes\n\
      type: deflate\n\
      compress-depth: 0\n\
      decompress-depth: 0\n\
";

    ConfCreateContextBackup();
    ConfInit();
    HtpConfigCreateBackup();

    ConfYamlLoadString(input, strlen(input));
    HTPConfigure();

    TcpSession ssn;
    Packet *p1 = NULL;
    Packet *p2 = NULL;
    ThreadVars th_v;
    DetectEngineCtx *de_ctx = NULL;
    DetectEngineThreadCtx *det_ctx = NULL;
    HtpState *http_state = NULL;
    Flow f;
    uint8_t http_buf1[] =
        "GET /file.swf HTTP/1.0\r\n"
        "Host: www.openinfosecfoundation.org\r\n"
        "User-Agent: Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.1.7) Gecko/20091221 Firefox/3.5.7\r\n"
        "\r\n";
    uint32_t http_len1 = sizeof(http_buf1) - 1;
    uint8_t http_buf2[] = {
        'H', 'T', 'T', 'P', '/', '1', '.', '1', ' ', '2', '0', '0', 'o', 'k', 0x0d, 0x0a,
        'C', 'o', 'n', 't', 'e', 'n', 't', '-', 'L', 'e', 'n', 'g', 't', 'h', ':', ' ', '8', '0', 0x0d, 0x0a,
        'C', 'o', 'n', 't', 'e', 'n', 't', '-', 'T', 'y', 'p', 'e', ':', ' ',
        'a','p','p','l','i','c','a','t','i','o','n','/','x','-','s','h','o','c','k','w','a','v','e','-','f','l','a','s','h', 0x0d, 0x0a,
        0x0d, 0x0a,
        0x43, 0x57, 0x53, 0x0a, 0xcb, 0x6c, 0x00, 0x00, 0x78, 0xda, 0xad, 0xbd, 0x07, 0x98, 0x55, 0x55,
        0x9e, 0xee, 0xbd, 0x4f, 0xd8, 0xb5, 0x4e, 0x15, 0xc1, 0xc2, 0x80, 0x28, 0x86, 0xd2, 0x2e, 0x5a,
        0xdb, 0x46, 0xd9, 0x39, 0x38, 0xdd, 0x4e, 0x1b, 0xa8, 0x56, 0x5b, 0xc5, 0x6b, 0xe8, 0x76, 0xfa,
        0x0e, 0xc2, 0x8e, 0x50, 0x76, 0x51, 0xc5, 0x54, 0x15, 0x88, 0x73, 0xc3, 0xd0, 0x88, 0x39, 0x81,
        0x98, 0x63, 0x91, 0x93, 0x8a, 0x82, 0x89, 0x60, 0x00, 0xcc, 0xb1, 0x00, 0x01, 0x73, 0xce, 0x39,
    };
    uint32_t http_len2 = sizeof(http_buf2);
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();
    FAIL_IF_NULL(alp_tctx);

    memset(&th_v, 0, sizeof(th_v));
    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    p1 = UTHBuildPacket(NULL, 0, IPPROTO_TCP);
    p2 = UTHBuildPacket(NULL, 0, IPPROTO_TCP);

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;
    f.flags |= FLOW_IPV4;

    p1->flow = &f;
    p1->flowflags |= FLOW_PKT_TOSERVER;
    p1->flowflags |= FLOW_PKT_ESTABLISHED;
    p1->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    p2->flow = &f;
    p2->flowflags |= FLOW_PKT_TOCLIENT;
    p2->flowflags |= FLOW_PKT_ESTABLISHED;
    p2->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    f.alproto = ALPROTO_HTTP1;

    StreamTcpInitConfig(true);

    de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert tcp any any -> any any "
                               "(flow:established,from_server; "
                               "file_data; content:\"FWS\"; "
                               "sid:1;)");
    FAIL_IF_NULL(de_ctx->sig_list);

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParserParse(
            &th_v, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER, http_buf1, http_len1);
    FAIL_IF(r != 0);

    http_state = f.alstate;
    FAIL_IF_NULL(http_state);

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p1);

    FAIL_IF((PacketAlertCheck(p1, 1)));

    r = AppLayerParserParse(
            &th_v, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOCLIENT, http_buf2, http_len2);
    FAIL_IF(r != 0);

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p2);

    FAIL_IF(!(PacketAlertCheck(p2, 1)));

    AppLayerParserThreadCtxFree(alp_tctx);
    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);

    HTPFreeConfig();
    HtpConfigRestoreBackup();
    ConfRestoreContextBackup();

    StreamTcpFreeConfig(true);
    FLOW_DESTROY(&f);
    UTHFreePackets(&p1, 1);
    UTHFreePackets(&p2, 1);
    PASS;
}

static int DetectEngineHttpServerBodyFileDataTest22(void)
{
    char input[] = "\
%YAML 1.1\n\
---\n\
libhtp:\n\
\n\
  default-config:\n\
\n\
    swf-decompression:\n\
      enabled: yes\n\
      type: lzma\n\
      compress-depth: 0\n\
      decompress-depth: 0\n\
";

    ConfCreateContextBackup();
    ConfInit();
    HtpConfigCreateBackup();

    ConfYamlLoadString(input, strlen(input));
    HTPConfigure();

    TcpSession ssn;
    Packet *p1 = NULL;
    Packet *p2 = NULL;
    ThreadVars th_v;
    DetectEngineCtx *de_ctx = NULL;
    DetectEngineThreadCtx *det_ctx = NULL;
    HtpState *http_state = NULL;
    Flow f;
    uint8_t http_buf1[] =
        "GET /file.swf HTTP/1.0\r\n"
        "Host: www.openinfosecfoundation.org\r\n"
        "User-Agent: Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.1.7) Gecko/20091221 Firefox/3.5.7\r\n"
        "\r\n";
    uint32_t http_len1 = sizeof(http_buf1) - 1;
    uint8_t http_buf2[] = {
        'H', 'T', 'T', 'P', '/', '1', '.', '1', ' ', '2', '0', '0', 'o', 'k', 0x0d, 0x0a,
        'C', 'o', 'n', 't', 'e', 'n', 't', '-', 'L', 'e', 'n', 'g', 't', 'h', ':', ' ', '8', '0', 0x0d, 0x0a,
        'C', 'o', 'n', 't', 'e', 'n', 't', '-', 'T', 'y', 'p', 'e', ':', ' ',
        'a','p','p','l','i','c','a','t','i','o','n','/','x','-','s','h','o','c','k','w','a','v','e','-','f','l','a','s','h', 0x0d, 0x0a,
        0x0d, 0x0a,
        0x43, 0x57, 0x53, 0x0a, 0xcb, 0x6c, 0x00, 0x00, 0x78, 0xda, 0xad, 0xbd, 0x07, 0x98, 0x55, 0x55,
        0x9e, 0xee, 0xbd, 0x4f, 0xd8, 0xb5, 0x4e, 0x15, 0xc1, 0xc2, 0x80, 0x28, 0x86, 0xd2, 0x2e, 0x5a,
        0xdb, 0x46, 0xd9, 0x39, 0x38, 0xdd, 0x4e, 0x1b, 0xa8, 0x56, 0x5b, 0xc5, 0x6b, 0xe8, 0x76, 0xfa,
        0x0e, 0xc2, 0x8e, 0x50, 0x76, 0x51, 0xc5, 0x54, 0x15, 0x88, 0x73, 0xc3, 0xd0, 0x88, 0x39, 0x81,
        0x98, 0x63, 0x91, 0x93, 0x8a, 0x82, 0x89, 0x60, 0x00, 0xcc, 0xb1, 0x00, 0x01, 0x73, 0xce, 0x39,
    };
    uint32_t http_len2 = sizeof(http_buf2);
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();
    FAIL_IF_NULL(alp_tctx);

    memset(&th_v, 0, sizeof(th_v));
    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    p1 = UTHBuildPacket(NULL, 0, IPPROTO_TCP);
    p2 = UTHBuildPacket(NULL, 0, IPPROTO_TCP);

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;
    f.flags |= FLOW_IPV4;

    p1->flow = &f;
    p1->flowflags |= FLOW_PKT_TOSERVER;
    p1->flowflags |= FLOW_PKT_ESTABLISHED;
    p1->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    p2->flow = &f;
    p2->flowflags |= FLOW_PKT_TOCLIENT;
    p2->flowflags |= FLOW_PKT_ESTABLISHED;
    p2->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    f.alproto = ALPROTO_HTTP1;

    StreamTcpInitConfig(true);

    de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert tcp any any -> any any "
                               "(flow:established,from_server; "
                               "file_data; content:\"CWS\"; "
                               "sid:1;)");
    FAIL_IF_NULL(de_ctx->sig_list);

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParserParse(
            &th_v, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER, http_buf1, http_len1);
    FAIL_IF(r != 0);

    http_state = f.alstate;
    FAIL_IF_NULL(http_state);

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p1);

    FAIL_IF((PacketAlertCheck(p1, 1)));

    r = AppLayerParserParse(
            &th_v, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOCLIENT, http_buf2, http_len2);
    FAIL_IF(r != 0);

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p2);

    FAIL_IF(!(PacketAlertCheck(p2, 1)));

    AppLayerParserThreadCtxFree(alp_tctx);
    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);

    HTPFreeConfig();
    HtpConfigRestoreBackup();
    ConfRestoreContextBackup();

    StreamTcpFreeConfig(true);
    FLOW_DESTROY(&f);
    UTHFreePackets(&p1, 1);
    UTHFreePackets(&p2, 1);
    PASS;
}

static int DetectEngineHttpServerBodyFileDataTest23(void)
{
    char input[] = "\
%YAML 1.1\n\
---\n\
libhtp:\n\
\n\
  default-config:\n\
\n\
    swf-decompression:\n\
      enabled: yes\n\
      type: both\n\
      compress-depth: 0\n\
      decompress-depth: 0\n\
";

    ConfCreateContextBackup();
    ConfInit();
    HtpConfigCreateBackup();

    ConfYamlLoadString(input, strlen(input));
    HTPConfigure();

    TcpSession ssn;
    Packet *p1 = NULL;
    Packet *p2 = NULL;
    ThreadVars th_v;
    DetectEngineCtx *de_ctx = NULL;
    DetectEngineThreadCtx *det_ctx = NULL;
    HtpState *http_state = NULL;
    Flow f;
    uint8_t http_buf1[] =
        "GET /file.swf HTTP/1.0\r\n"
        "Host: www.openinfosecfoundation.org\r\n"
        "User-Agent: Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.1.7) Gecko/20091221 Firefox/3.5.7\r\n"
        "\r\n";
    uint32_t http_len1 = sizeof(http_buf1) - 1;
    uint8_t http_buf2[] = {
        'H', 'T', 'T', 'P', '/', '1', '.', '1', ' ', '2', '0', '0', 'o', 'k', 0x0d, 0x0a,
        'C', 'o', 'n', 't', 'e', 'n', 't', '-', 'L', 'e', 'n', 'g', 't', 'h', ':', ' ', '8', '0', 0x0d, 0x0a,
        'C', 'o', 'n', 't', 'e', 'n', 't', '-', 'T', 'y', 'p', 'e', ':', ' ',
        'a','p','p','l','i','c','a','t','i','o','n','/','x','-','s','h','o','c','k','w','a','v','e','-','f','l','a','s','h', 0x0d, 0x0a,
        0x0d, 0x0a,
        0x43, 0x57, 0x53, 0x01, 0xcb, 0x6c, 0x00, 0x00, 0x78, 0xda, 0xad, 0xbd, 0x07, 0x98, 0x55, 0x55,
        0x9e, 0xee, 0xbd, 0x4f, 0xd8, 0xb5, 0x4e, 0x15, 0xc1, 0xc2, 0x80, 0x28, 0x86, 0xd2, 0x2e, 0x5a,
        0xdb, 0x46, 0xd9, 0x39, 0x38, 0xdd, 0x4e, 0x1b, 0xa8, 0x56, 0x5b, 0xc5, 0x6b, 0xe8, 0x76, 0xfa,
        0x0e, 0xc2, 0x8e, 0x50, 0x76, 0x51, 0xc5, 0x54, 0x15, 0x88, 0x73, 0xc3, 0xd0, 0x88, 0x39, 0x81,
        0x98, 0x63, 0x91, 0x93, 0x8a, 0x82, 0x89, 0x60, 0x00, 0xcc, 0xb1, 0x00, 0x01, 0x73, 0xce, 0x39,
    };
    uint32_t http_len2 = sizeof(http_buf2);
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();
    FAIL_IF_NULL(alp_tctx);

    memset(&th_v, 0, sizeof(th_v));
    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    p1 = UTHBuildPacket(NULL, 0, IPPROTO_TCP);
    p2 = UTHBuildPacket(NULL, 0, IPPROTO_TCP);

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;
    f.flags |= FLOW_IPV4;

    p1->flow = &f;
    p1->flowflags |= FLOW_PKT_TOSERVER;
    p1->flowflags |= FLOW_PKT_ESTABLISHED;
    p1->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    p2->flow = &f;
    p2->flowflags |= FLOW_PKT_TOCLIENT;
    p2->flowflags |= FLOW_PKT_ESTABLISHED;
    p2->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    f.alproto = ALPROTO_HTTP1;

    StreamTcpInitConfig(true);

    de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert tcp any any -> any any "
                               "(flow:established,from_server; "
                               "file_data; content:\"CWS\"; "
                               "sid:1;)");
    FAIL_IF_NULL(de_ctx->sig_list);

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParserParse(
            &th_v, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER, http_buf1, http_len1);
    FAIL_IF(r != 0);

    http_state = f.alstate;
    FAIL_IF_NULL(http_state);

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p1);

    FAIL_IF((PacketAlertCheck(p1, 1)));

    r = AppLayerParserParse(
            &th_v, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOCLIENT, http_buf2, http_len2);
    FAIL_IF(r != 0);

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p2);

    FAIL_IF(!(PacketAlertCheck(p2, 1)));

    AppLayerParserThreadCtxFree(alp_tctx);
    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);

    HTPFreeConfig();
    HtpConfigRestoreBackup();
    ConfRestoreContextBackup();

    StreamTcpFreeConfig(true);
    FLOW_DESTROY(&f);
    UTHFreePackets(&p1, 1);
    UTHFreePackets(&p2, 1);
    PASS;
}

static int DetectEngineHttpServerBodyFileDataTest24(void)
{
    char input[] = "\
%YAML 1.1\n\
---\n\
libhtp:\n\
\n\
  default-config:\n\
\n\
    swf-decompression:\n\
      enabled: yes\n\
      type: both\n\
      compress-depth: 0\n\
      decompress-depth: 0\n\
";

    ConfCreateContextBackup();
    ConfInit();
    HtpConfigCreateBackup();

    ConfYamlLoadString(input, strlen(input));
    HTPConfigure();

    TcpSession ssn;
    Packet *p1 = NULL;
    Packet *p2 = NULL;
    ThreadVars th_v;
    DetectEngineCtx *de_ctx = NULL;
    DetectEngineThreadCtx *det_ctx = NULL;
    HtpState *http_state = NULL;
    Flow f;
    uint8_t http_buf1[] =
        "GET /file.swf HTTP/1.0\r\n"
        "Host: www.openinfosecfoundation.org\r\n"
        "User-Agent: Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.1.7) Gecko/20091221 Firefox/3.5.7\r\n"
        "\r\n";
    uint32_t http_len1 = sizeof(http_buf1) - 1;
    uint8_t http_buf2[] = {
        'H', 'T', 'T', 'P', '/', '1', '.', '1', ' ', '2', '0', '0', 'o', 'k', 0x0d, 0x0a,
        'C', 'o', 'n', 't', 'e', 'n', 't', '-', 'L', 'e', 'n', 'g', 't', 'h', ':', ' ', '1', '0', '3', 0x0d, 0x0a,
        'C', 'o', 'n', 't', 'e', 'n', 't', '-', 'T', 'y', 'p', 'e', ':', ' ',
        'a','p','p','l','i','c','a','t','i','o','n','/','o','c','t','e','t','-','s','t','r','e','a','m', 0x0d, 0x0a,
        0x0d, 0x0a,
        0x5a, 0x57, 0x53, 0x17, 0x5c, 0x24, 0x00, 0x00, 0xb7, 0x21, 0x00, 0x00, 0x5d, 0x00, 0x00, 0x20,
        0x00, 0x00, 0x3b, 0xff, 0xfc, 0x8e, 0x19, 0xfa, 0xdf, 0xe7, 0x66, 0x08, 0xa0, 0x3d, 0x3e, 0x85,
        0xf5, 0x75, 0x6f, 0xd0, 0x7e, 0x61, 0x35, 0x1b, 0x1a, 0x8b, 0x16, 0x4d, 0xdf, 0x05, 0x32, 0xfe,
        0xa4, 0x4c, 0x46, 0x49, 0xb7, 0x7b, 0x6b, 0x75, 0xf9, 0x2b, 0x5c, 0x37, 0x29, 0x0b, 0x91, 0x37,
        0x01, 0x37, 0x0e, 0xe9, 0xf2, 0xe1, 0xfc, 0x9e, 0x64, 0xda, 0x6c, 0x11, 0x21, 0x33, 0xed, 0xa0,
        0x0e, 0x76, 0x70, 0xa0, 0xcd, 0x98, 0x2e, 0x76, 0x80, 0xf0, 0xe0, 0x59, 0x56, 0x06, 0x08, 0xe9,
        0xca, 0xeb, 0xa2, 0xc6, 0xdb, 0x5a, 0x86
    };
    uint32_t http_len2 = sizeof(http_buf2);
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();
    FAIL_IF_NULL(alp_tctx);

    memset(&th_v, 0, sizeof(th_v));
    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    p1 = UTHBuildPacket(NULL, 0, IPPROTO_TCP);
    p2 = UTHBuildPacket(NULL, 0, IPPROTO_TCP);

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;
    f.flags |= FLOW_IPV4;

    p1->flow = &f;
    p1->flowflags |= FLOW_PKT_TOSERVER;
    p1->flowflags |= FLOW_PKT_ESTABLISHED;
    p1->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    p2->flow = &f;
    p2->flowflags |= FLOW_PKT_TOCLIENT;
    p2->flowflags |= FLOW_PKT_ESTABLISHED;
    p2->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    f.alproto = ALPROTO_HTTP1;

    StreamTcpInitConfig(true);

    de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);


    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert tcp any any -> any any "
                               "(flow:established,from_server; "
                               "file_data; content:\"FWS\"; "
                               "sid:1;)");
    FAIL_IF_NULL(de_ctx->sig_list);

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParserParse(
            &th_v, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER, http_buf1, http_len1);
    FAIL_IF(r != 0);

    http_state = f.alstate;
    FAIL_IF_NULL(http_state);

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p1);

    FAIL_IF((PacketAlertCheck(p1, 1)));

    r = AppLayerParserParse(
            &th_v, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOCLIENT, http_buf2, http_len2);
    FAIL_IF(r != 0);

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p2);

    FAIL_IF(!(PacketAlertCheck(p2, 1)));

    AppLayerParserThreadCtxFree(alp_tctx);
    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);

    HTPFreeConfig();
    HtpConfigRestoreBackup();
    ConfRestoreContextBackup();

    StreamTcpFreeConfig(true);
    FLOW_DESTROY(&f);
    UTHFreePackets(&p1, 1);
    UTHFreePackets(&p2, 1);
    PASS;
}

static int DetectEngineHttpServerBodyFileDataTest25(void)
{
    char input[] = "\
%YAML 1.1\n\
---\n\
libhtp:\n\
\n\
  default-config:\n\
\n\
    swf-decompression:\n\
      enabled: no\n\
      type: both\n\
      compress-depth: 0\n\
      decompress-depth: 0\n\
";

    ConfCreateContextBackup();
    ConfInit();
    HtpConfigCreateBackup();

    ConfYamlLoadString(input, strlen(input));
    HTPConfigure();

    TcpSession ssn;
    Packet *p1 = NULL;
    Packet *p2 = NULL;
    ThreadVars th_v;
    DetectEngineCtx *de_ctx = NULL;
    DetectEngineThreadCtx *det_ctx = NULL;
    HtpState *http_state = NULL;
    Flow f;
    uint8_t http_buf1[] =
        "GET /file.swf HTTP/1.0\r\n"
        "Host: www.openinfosecfoundation.org\r\n"
        "User-Agent: Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.1.7) Gecko/20091221 Firefox/3.5.7\r\n"
        "\r\n";
    uint32_t http_len1 = sizeof(http_buf1) - 1;
    uint8_t http_buf2[] = {
        'H', 'T', 'T', 'P', '/', '1', '.', '1', ' ', '2', '0', '0', 'o', 'k', 0x0d, 0x0a,
        'C', 'o', 'n', 't', 'e', 'n', 't', '-', 'L', 'e', 'n', 'g', 't', 'h', ':', ' ', '1', '0', '3', 0x0d, 0x0a,
        'C', 'o', 'n', 't', 'e', 'n', 't', '-', 'T', 'y', 'p', 'e', ':', ' ',
        'a','p','p','l','i','c','a','t','i','o','n','/','o','c','t','e','t','-','s','t','r','e','a','m', 0x0d, 0x0a,
        0x0d, 0x0a,
        0x5a, 0x57, 0x53, 0x17, 0x5c, 0x24, 0x00, 0x00, 0xb7, 0x21, 0x00, 0x00, 0x5d, 0x00, 0x00, 0x20, 0x00, 0x00, 0x3b, 0xff, 0xfc, 0x8e, 0x19,
        0xfa, 0xdf, 0xe7, 0x66, 0x08, 0xa0, 0x3d, 0x3e, 0x85, 0xf5, 0x75, 0x6f, 0xd0, 0x7e, 0x61, 0x35, 0x1b, 0x1a, 0x8b, 0x16, 0x4d, 0xdf, 0x05,
        0x32, 0xfe, 0xa4, 0x4c, 0x46, 0x49, 0xb7, 0x7b, 0x6b, 0x75, 0xf9, 0x2b, 0x5c, 0x37, 0x29, 0x0b, 0x91, 0x37, 0x01, 0x37, 0x0e, 0xe9, 0xf2,
        0xe1, 0xfc, 0x9e, 0x64, 0xda, 0x6c, 0x11, 0x21, 0x33, 0xed, 0xa0, 0x0e, 0x76, 0x70, 0xa0, 0xcd, 0x98, 0x2e, 0x76, 0x80, 0xf0, 0xe0, 0x59,
        0x56, 0x06, 0x08, 0xe9, 0xca, 0xeb, 0xa2, 0xc6, 0xdb, 0x5a, 0x86
    };
    uint32_t http_len2 = sizeof(http_buf2);
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();
    FAIL_IF_NULL(alp_tctx);

    memset(&th_v, 0, sizeof(th_v));
    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    p1 = UTHBuildPacket(NULL, 0, IPPROTO_TCP);
    p2 = UTHBuildPacket(NULL, 0, IPPROTO_TCP);

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;
    f.flags |= FLOW_IPV4;

    p1->flow = &f;
    p1->flowflags |= FLOW_PKT_TOSERVER;
    p1->flowflags |= FLOW_PKT_ESTABLISHED;
    p1->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    p2->flow = &f;
    p2->flowflags |= FLOW_PKT_TOCLIENT;
    p2->flowflags |= FLOW_PKT_ESTABLISHED;
    p2->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    f.alproto = ALPROTO_HTTP1;

    StreamTcpInitConfig(true);

    de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert tcp any any -> any any "
                               "(flow:established,from_server; "
                               "file_data; content:\"ZWS\"; "
                               "sid:1;)");
    FAIL_IF_NULL(de_ctx->sig_list);

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParserParse(
            &th_v, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER, http_buf1, http_len1);
    FAIL_IF(r != 0);

    http_state = f.alstate;
    FAIL_IF_NULL(http_state);

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p1);

    FAIL_IF((PacketAlertCheck(p1, 1)));

    r = AppLayerParserParse(
            &th_v, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOCLIENT, http_buf2, http_len2);
    FAIL_IF(r != 0);

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p2);

    FAIL_IF(!(PacketAlertCheck(p2, 1)));

    AppLayerParserThreadCtxFree(alp_tctx);
    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);

    HTPFreeConfig();
    HtpConfigRestoreBackup();
    ConfRestoreContextBackup();

    StreamTcpFreeConfig(true);
    FLOW_DESTROY(&f);
    UTHFreePackets(&p1, 1);
    UTHFreePackets(&p2, 1);
    PASS;
}

static int DetectEngineHttpServerBodyFileDataTest26(void)
{
    char input[] = "\
%YAML 1.1\n\
---\n\
libhtp:\n\
\n\
  default-config:\n\
\n\
    swf-decompression:\n\
      enabled: yes\n\
      type: lzma\n\
      compress-depth: 0\n\
      decompress-depth: 0\n\
";

    ConfCreateContextBackup();
    ConfInit();
    HtpConfigCreateBackup();

    ConfYamlLoadString(input, strlen(input));
    HTPConfigure();

    TcpSession ssn;
    Packet *p1 = NULL;
    Packet *p2 = NULL;
    ThreadVars th_v;
    DetectEngineCtx *de_ctx = NULL;
    DetectEngineThreadCtx *det_ctx = NULL;
    HtpState *http_state = NULL;
    Flow f;
    uint8_t http_buf1[] =
        "GET /file.swf HTTP/1.0\r\n"
        "Host: www.openinfosecfoundation.org\r\n"
        "User-Agent: Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.1.7) Gecko/20091221 Firefox/3.5.7\r\n"
        "\r\n";
    uint32_t http_len1 = sizeof(http_buf1) - 1;
    uint8_t http_buf2[] = {
        'H', 'T', 'T', 'P', '/', '1', '.', '1', ' ', '2', '0', '0', 'o', 'k', 0x0d, 0x0a,
        'C', 'o', 'n', 't', 'e', 'n', 't', '-', 'L', 'e', 'n', 'g', 't', 'h', ':', ' ', '1', '0', '3', 0x0d, 0x0a,
        'C', 'o', 'n', 't', 'e', 'n', 't', '-', 'T', 'y', 'p', 'e', ':', ' ',
        'a','p','p','l','i','c','a','t','i','o','n','/','o','c','t','e','t','-','s','t','r','e','a','m', 0x0d, 0x0a,
        0x0d, 0x0a,
        0x5a, 0x57, 0x53, 0x17, 0x5c, 0x24, 0x00, 0x00, 0xb7, 0x21, 0x00, 0x00, 0x5d, 0x00, 0x00, 0x20,
        0x00, 0x00, 0x3b, 0xff, 0xfc, 0x8e, 0x19, 0xfa, 0xdf, 0xe7, 0x66, 0x08, 0xa0, 0x3d, 0x3e, 0x85,
        0xf5, 0x75, 0x6f, 0xd0, 0x7e, 0x61, 0x35, 0x1b, 0x1a, 0x8b, 0x16, 0x4d, 0xdf, 0x05, 0x32, 0xfe,
        0xa4, 0x4c, 0x46, 0x49, 0xb7, 0x7b, 0x6b, 0x75, 0xf9, 0x2b, 0x5c, 0x37, 0x29, 0x0b, 0x91, 0x37,
        0x01, 0x37, 0x0e, 0xe9, 0xf2, 0xe1, 0xfc, 0x9e, 0x64, 0xda, 0x6c, 0x11, 0x21, 0x33, 0xed, 0xa0,
        0x0e, 0x76, 0x70, 0xa0, 0xcd, 0x98, 0x2e, 0x76, 0x80, 0xf0, 0xe0, 0x59, 0x56, 0x06, 0x08, 0xe9,
        0xca, 0xeb, 0xa2, 0xc6, 0xdb, 0x5a, 0x86
    };
    uint32_t http_len2 = sizeof(http_buf2);
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();
    FAIL_IF_NULL(alp_tctx);

    memset(&th_v, 0, sizeof(th_v));
    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    p1 = UTHBuildPacket(NULL, 0, IPPROTO_TCP);
    p2 = UTHBuildPacket(NULL, 0, IPPROTO_TCP);

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;
    f.flags |= FLOW_IPV4;

    p1->flow = &f;
    p1->flowflags |= FLOW_PKT_TOSERVER;
    p1->flowflags |= FLOW_PKT_ESTABLISHED;
    p1->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    p2->flow = &f;
    p2->flowflags |= FLOW_PKT_TOCLIENT;
    p2->flowflags |= FLOW_PKT_ESTABLISHED;
    p2->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    f.alproto = ALPROTO_HTTP1;

    StreamTcpInitConfig(true);

    de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert tcp any any -> any any "
                               "(flow:established,from_server; "
                               "file_data; content:\"FWS\"; "
                               "sid:1;)");
    FAIL_IF_NULL(de_ctx->sig_list);

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParserParse(
            &th_v, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER, http_buf1, http_len1);
    FAIL_IF(r != 0);

    http_state = f.alstate;
    FAIL_IF_NULL(http_state);

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p1);

    FAIL_IF((PacketAlertCheck(p1, 1)));

    r = AppLayerParserParse(
            &th_v, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOCLIENT, http_buf2, http_len2);
    FAIL_IF(r != 0);

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p2);

    FAIL_IF(!(PacketAlertCheck(p2, 1)));

    AppLayerParserThreadCtxFree(alp_tctx);
    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);

    HTPFreeConfig();
    HtpConfigRestoreBackup();
    ConfRestoreContextBackup();

    StreamTcpFreeConfig(true);
    FLOW_DESTROY(&f);
    UTHFreePackets(&p1, 1);
    UTHFreePackets(&p2, 1);
    PASS;
}

static int DetectEngineHttpServerBodyFileDataTest27(void)
{
    char input[] = "\
%YAML 1.1\n\
---\n\
libhtp:\n\
\n\
  default-config:\n\
\n\
    swf-decompression:\n\
      enabled: yes\n\
      type: deflate\n\
      compress-depth: 0\n\
      decompress-depth: 0\n\
";

    ConfCreateContextBackup();
    ConfInit();
    HtpConfigCreateBackup();

    ConfYamlLoadString(input, strlen(input));
    HTPConfigure();

    TcpSession ssn;
    Packet *p1 = NULL;
    Packet *p2 = NULL;
    ThreadVars th_v;
    DetectEngineCtx *de_ctx = NULL;
    DetectEngineThreadCtx *det_ctx = NULL;
    HtpState *http_state = NULL;
    Flow f;
    uint8_t http_buf1[] =
        "GET /file.swf HTTP/1.0\r\n"
        "Host: www.openinfosecfoundation.org\r\n"
        "User-Agent: Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.1.7) Gecko/20091221 Firefox/3.5.7\r\n"
        "\r\n";
    uint32_t http_len1 = sizeof(http_buf1) - 1;
    uint8_t http_buf2[] = {
        'H', 'T', 'T', 'P', '/', '1', '.', '1', ' ', '2', '0', '0', 'o', 'k', 0x0d, 0x0a,
        'C', 'o', 'n', 't', 'e', 'n', 't', '-', 'L', 'e', 'n', 'g', 't', 'h', ':', ' ', '8', '0', 0x0d, 0x0a,
        'C', 'o', 'n', 't', 'e', 'n', 't', '-', 'T', 'y', 'p', 'e', ':', ' ',
        'a','p','p','l','i','c','a','t','i','o','n','/','o','c','t','e','t','-','s','t','r','e','a','m', 0x0d, 0x0a,
        0x0d, 0x0a,
        0x5a, 0x57, 0x53, 0x17, 0x5c, 0x24, 0x00, 0x00, 0xb7, 0x21, 0x00, 0x00, 0x5d, 0x00, 0x00, 0x20,
        0x00, 0x00, 0x3b, 0xff, 0xfc, 0x8e, 0x19, 0xfa, 0xdf, 0xe7, 0x66, 0x08, 0xa0, 0x3d, 0x3e, 0x85,
        0x19, 0xfa, 0xdf, 0xe7, 0x66, 0x08, 0xa0, 0x3d, 0x3e, 0x85, 0xf5, 0x75, 0x6f, 0xd0, 0x7e, 0x61,
        0x35, 0x1b, 0x1a, 0x8b, 0x16, 0x4d, 0xdf, 0x05, 0x32, 0xfe, 0xa4, 0x4c, 0x46, 0x49, 0xb7, 0x7b,
        0x6b, 0x75, 0xf9, 0x2b, 0x5c, 0x37, 0x29, 0x0b, 0x91, 0x37, 0x01, 0x37, 0x0e, 0xe9, 0xf2, 0xe1,
    };
    uint32_t http_len2 = sizeof(http_buf2);
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();
    FAIL_IF_NULL(alp_tctx);

    memset(&th_v, 0, sizeof(th_v));
    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    p1 = UTHBuildPacket(NULL, 0, IPPROTO_TCP);
    p2 = UTHBuildPacket(NULL, 0, IPPROTO_TCP);

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;
    f.flags |= FLOW_IPV4;

    p1->flow = &f;
    p1->flowflags |= FLOW_PKT_TOSERVER;
    p1->flowflags |= FLOW_PKT_ESTABLISHED;
    p1->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    p2->flow = &f;
    p2->flowflags |= FLOW_PKT_TOCLIENT;
    p2->flowflags |= FLOW_PKT_ESTABLISHED;
    p2->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    f.alproto = ALPROTO_HTTP1;

    StreamTcpInitConfig(true);

    de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert tcp any any -> any any "
                               "(flow:established,from_server; "
                               "file_data; content:\"ZWS\"; "
                               "sid:1;)");
    FAIL_IF_NULL(de_ctx->sig_list);

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParserParse(
            &th_v, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER, http_buf1, http_len1);
    FAIL_IF(r != 0);

    http_state = f.alstate;
    FAIL_IF_NULL(http_state);

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p1);

    FAIL_IF((PacketAlertCheck(p1, 1)));

    r = AppLayerParserParse(
            &th_v, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOCLIENT, http_buf2, http_len2);
    FAIL_IF(r != 0);

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p2);

    FAIL_IF(!(PacketAlertCheck(p2, 1)));

    AppLayerParserThreadCtxFree(alp_tctx);
    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);

    HTPFreeConfig();
    HtpConfigRestoreBackup();
    ConfRestoreContextBackup();

    StreamTcpFreeConfig(true);
    FLOW_DESTROY(&f);
    UTHFreePackets(&p1, 1);
    UTHFreePackets(&p2, 1);
    PASS;
}

static int DetectEngineHttpServerBodyFileDataTest28(void)
{
    char input[] = "\
%YAML 1.1\n\
---\n\
libhtp:\n\
\n\
  default-config:\n\
\n\
    swf-decompression:\n\
      enabled: yes\n\
      type: both\n\
      compress-depth: 0\n\
      decompress-depth: 0\n\
";

    ConfCreateContextBackup();
    ConfInit();
    HtpConfigCreateBackup();

    ConfYamlLoadString(input, strlen(input));
    HTPConfigure();

    TcpSession ssn;
    Packet *p1 = NULL;
    Packet *p2 = NULL;
    ThreadVars th_v;
    DetectEngineCtx *de_ctx = NULL;
    DetectEngineThreadCtx *det_ctx = NULL;
    HtpState *http_state = NULL;
    Flow f;
    uint8_t http_buf1[] =
        "GET /file.swf HTTP/1.0\r\n"
        "Host: www.openinfosecfoundation.org\r\n"
        "User-Agent: Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.1.7) Gecko/20091221 Firefox/3.5.7\r\n"
        "\r\n";
    uint32_t http_len1 = sizeof(http_buf1) - 1;
    uint8_t http_buf2[] = {
        'H', 'T', 'T', 'P', '/', '1', '.', '1', ' ', '2', '0', '0', 'o', 'k', 0x0d, 0x0a,
        'C', 'o', 'n', 't', 'e', 'n', 't', '-', 'L', 'e', 'n', 'g', 't', 'h', ':', ' ', '8', '0', 0x0d, 0x0a,
        'C', 'o', 'n', 't', 'e', 'n', 't', '-', 'T', 'y', 'p', 'e', ':', ' ',
        'a','p','p','l','i','c','a','t','i','o','n','/','o','c','t','e','t','-','s','t','r','e','a','m', 0x0d, 0x0a,
        0x0d, 0x0a,
        0x5a, 0x57, 0x53, 0x01, 0x5c, 0x24, 0x00, 0x00, 0xb7, 0x21, 0x00, 0x00, 0x5d, 0x00, 0x00, 0x20,
        0x00, 0x00, 0x3b, 0xff, 0xfc, 0x8e, 0x19, 0xfa, 0xdf, 0xe7, 0x66, 0x08, 0xa0, 0x3d, 0x3e, 0x85,
        0x19, 0xfa, 0xdf, 0xe7, 0x66, 0x08, 0xa0, 0x3d, 0x3e, 0x85, 0xf5, 0x75, 0x6f, 0xd0, 0x7e, 0x61,
        0x35, 0x1b, 0x1a, 0x8b, 0x16, 0x4d, 0xdf, 0x05, 0x32, 0xfe, 0xa4, 0x4c, 0x46, 0x49, 0xb7, 0x7b,
        0x6b, 0x75, 0xf9, 0x2b, 0x5c, 0x37, 0x29, 0x0b, 0x91, 0x37, 0x01, 0x37, 0x0e, 0xe9, 0xf2, 0xe1,
    };
    uint32_t http_len2 = sizeof(http_buf2);
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();
    FAIL_IF_NULL(alp_tctx);

    memset(&th_v, 0, sizeof(th_v));
    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    p1 = UTHBuildPacket(NULL, 0, IPPROTO_TCP);
    p2 = UTHBuildPacket(NULL, 0, IPPROTO_TCP);

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;
    f.flags |= FLOW_IPV4;

    p1->flow = &f;
    p1->flowflags |= FLOW_PKT_TOSERVER;
    p1->flowflags |= FLOW_PKT_ESTABLISHED;
    p1->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    p2->flow = &f;
    p2->flowflags |= FLOW_PKT_TOCLIENT;
    p2->flowflags |= FLOW_PKT_ESTABLISHED;
    p2->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    f.alproto = ALPROTO_HTTP1;

    StreamTcpInitConfig(true);

    de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert tcp any any -> any any "
                               "(flow:established,from_server; "
                               "file_data; content:\"ZWS\"; "
                               "sid:1;)");
    FAIL_IF_NULL(de_ctx->sig_list);

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParserParse(
            &th_v, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER, http_buf1, http_len1);
    FAIL_IF(r != 0);

    http_state = f.alstate;
    FAIL_IF_NULL(http_state);

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p1);

    FAIL_IF((PacketAlertCheck(p1, 1)));

    r = AppLayerParserParse(
            &th_v, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOCLIENT, http_buf2, http_len2);
    FAIL_IF(r != 0);

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p2);

    FAIL_IF(!(PacketAlertCheck(p2, 1)));

    AppLayerParserThreadCtxFree(alp_tctx);
    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);

    HTPFreeConfig();
    HtpConfigRestoreBackup();
    ConfRestoreContextBackup();

    StreamTcpFreeConfig(true);
    FLOW_DESTROY(&f);
    UTHFreePackets(&p1, 1);
    UTHFreePackets(&p2, 1);
    PASS;
}

static int DetectEngineHttpServerBodyFileDataTest29(void)
{
    char input[] = "\
%YAML 1.1\n\
---\n\
libhtp:\n\
\n\
  default-config:\n\
\n\
    swf-decompression:\n\
      enabled: yes\n\
      type: both\n\
      compress-depth: 1000\n\
      decompress-depth: 0\n\
";

    ConfCreateContextBackup();
    ConfInit();
    HtpConfigCreateBackup();
    ConfYamlLoadString(input, strlen(input));
    HTPConfigure();

    TcpSession ssn;
    Packet *p1 = NULL;
    Packet *p2 = NULL;
    ThreadVars th_v;
    DetectEngineCtx *de_ctx = NULL;
    DetectEngineThreadCtx *det_ctx = NULL;
    HtpState *http_state = NULL;
    Flow f;
    uint8_t http_buf1[] =
        "GET /file.swf HTTP/1.0\r\n"
        "Host: www.openinfosecfoundation.org\r\n"
        "User-Agent: Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.1.7) Gecko/20091221 Firefox/3.5.7\r\n"
        "\r\n";
    uint32_t http_len1 = sizeof(http_buf1) - 1;
    uint8_t http_buf2[] = {
        'H', 'T', 'T', 'P', '/', '1', '.', '1', ' ', '2', '0', '0', 'o', 'k', 0x0d, 0x0a,
        'C', 'o', 'n', 't', 'e', 'n', 't', '-', 'L', 'e', 'n', 'g', 't', 'h', ':', ' ', '8', '0', 0x0d, 0x0a,
        'C', 'o', 'n', 't', 'e', 'n', 't', '-', 'T', 'y', 'p', 'e', ':', ' ',
        'a','p','p','l','i','c','a','t','i','o','n','/','x','-','s','h','o','c','k','w','a','v','e','-','f','l','a','s','h', 0x0d, 0x0a,
        0x0d, 0x0a,
        0x43, 0x57, 0x53, 0x0a, 0xcb, 0x6c, 0x00, 0x00, 0x78, 0xda, 0xad, 0xbd, 0x07, 0x98, 0x55, 0x55,
        0x9e, 0xee, 0xbd, 0x4f, 0xd8, 0xb5, 0x4e, 0x15, 0xc1, 0xc2, 0x80, 0x28, 0x86, 0xd2, 0x2e, 0x5a,
        0xdb, 0x46, 0xd9, 0x39, 0x38, 0xdd, 0x4e, 0x1b, 0xa8, 0x56, 0x5b, 0xc5, 0x6b, 0xe8, 0x76, 0xfa,
        0x0e, 0xc2, 0x8e, 0x50, 0x76, 0x51, 0xc5, 0x54, 0x15, 0x88, 0x73, 0xc3, 0xd0, 0x88, 0x39, 0x81,
        0x98, 0x63, 0x91, 0x93, 0x8a, 0x82, 0x89, 0x60, 0x00, 0xcc, 0xb1, 0x00, 0x01, 0x73, 0xce, 0x39,
    };
    uint32_t http_len2 = sizeof(http_buf2);
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();
    FAIL_IF_NULL(alp_tctx);

    memset(&th_v, 0, sizeof(th_v));
    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    p1 = UTHBuildPacket(NULL, 0, IPPROTO_TCP);
    p2 = UTHBuildPacket(NULL, 0, IPPROTO_TCP);

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;
    f.flags |= FLOW_IPV4;

    p1->flow = &f;
    p1->flowflags |= FLOW_PKT_TOSERVER;
    p1->flowflags |= FLOW_PKT_ESTABLISHED;
    p1->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    p2->flow = &f;
    p2->flowflags |= FLOW_PKT_TOCLIENT;
    p2->flowflags |= FLOW_PKT_ESTABLISHED;
    p2->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    f.alproto = ALPROTO_HTTP1;

    StreamTcpInitConfig(true);

    de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert tcp any any -> any any "
                               "(flow:established,from_server; "
                               "file_data; content:\"FWS\"; "
                               "sid:1;)");
    FAIL_IF_NULL(de_ctx->sig_list);

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParserParse(
            &th_v, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER, http_buf1, http_len1);
    FAIL_IF(r != 0);

    http_state = f.alstate;
    FAIL_IF_NULL(http_state);

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p1);

    FAIL_IF((PacketAlertCheck(p1, 1)));

    r = AppLayerParserParse(
            &th_v, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOCLIENT, http_buf2, http_len2);
    FAIL_IF(r != 0);

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p2);

    FAIL_IF(!(PacketAlertCheck(p2, 1)));

    AppLayerParserThreadCtxFree(alp_tctx);
    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);

    HTPFreeConfig();
    HtpConfigRestoreBackup();
    ConfRestoreContextBackup();

    StreamTcpFreeConfig(true);
    FLOW_DESTROY(&f);
    UTHFreePackets(&p1, 1);
    UTHFreePackets(&p2, 1);
    PASS;
}

/**
 * \test Test that a signature containting a http_server_body is correctly parsed
 *       and the keyword is registered.
 */
static int DetectHttpServerBodyTest01(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;
    SigMatch *sm = NULL;

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(msg:\"Testing http_server_body\"; "
                               "content:\"one\"; http_server_body; sid:1;)");
    if (de_ctx->sig_list == NULL) {
        goto end;
    }

    /* sm should not be in the MATCH list */
    sm = de_ctx->sig_list->sm_lists[DETECT_SM_LIST_MATCH];
    if (sm != NULL) {
        goto end;
    }

    sm = de_ctx->sig_list->sm_lists[g_file_data_buffer_id];
    if (sm == NULL) {
        goto end;
    }

    if (sm->type != DETECT_CONTENT) {
        printf("sm type not DETECT_AL_HTTP_SERVER_BODY: ");
        goto end;
    }

    if (sm->next != NULL) {
        goto end;
    }

    result = 1;
end:
    DetectEngineCtxFree(de_ctx);

    return result;
}

/**
 * \test Test that a signature containing an valid http_server_body entry is
 *       parsed.
 */
static int DetectHttpServerBodyTest02(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(msg:\"Testing http_server_body\"; "
                               "content:\"one\"; http_server_body:; sid:1;)");
    if (de_ctx->sig_list != NULL)
        result = 1;

 end:
    DetectEngineCtxFree(de_ctx);

    return result;
}

/**
 * \test Test that an invalid signature containing no content but a http_server_body
 *       is invalidated.
 */
static int DetectHttpServerBodyTest03(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(msg:\"Testing http_server_body\"; "
                               "http_server_body; sid:1;)");
    if (de_ctx->sig_list == NULL)
        result = 1;

 end:
    DetectEngineCtxFree(de_ctx);

    return result;
}

/**
 * \test Test that an invalid signature containing a rawbytes along with a
 *       http_server_body is invalidated.
 */
static int DetectHttpServerBodyTest04(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(msg:\"Testing http_server_body\"; "
                               "content:\"one\"; rawbytes; http_server_body; sid:1;)");
    if (de_ctx->sig_list == NULL)
        result = 1;

 end:
    DetectEngineCtxFree(de_ctx);

    return result;
}

/**
 * \test Test that an invalid signature containing a rawbytes along with a
 *       http_server_body is invalidated.
 */
static int DetectHttpServerBodyTest05(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(msg:\"Testing http_server_body\"; "
                               "content:\"one\"; http_server_body; nocase; sid:1;)");
    if (de_ctx->sig_list != NULL)
        result = 1;

 end:
    DetectEngineCtxFree(de_ctx);

    return result;
}

/**
 *\test Test that the http_server_body content matches against a http request
 *      which holds the content.
 */
static int DetectHttpServerBodyTest06(void)
{
    TcpSession ssn;
    Packet *p = NULL;
    ThreadVars th_v;
    DetectEngineCtx *de_ctx = NULL;
    DetectEngineThreadCtx *det_ctx = NULL;
    HtpState *http_state = NULL;
    Flow f;
    uint8_t http_buf[] =
        "GET /index.html HTTP/1.0\r\n"
        "Host: www.openinfosecfoundation.org\r\n"
        "User-Agent: Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.1.7) Gecko/20091221 Firefox/3.5.7\r\n"
        "\r\n";
    uint32_t http_len = sizeof(http_buf) - 1;
    uint8_t http_buf2[] =
        "HTTP/1.0 200 ok\r\n"
        "Content-Type: text/html\r\n"
        "Content-Length: 7\r\n"
        "\r\n"
        "message";
    uint32_t http_len2 = sizeof(http_buf2) - 1;
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

    p->flow = &f;
    p->flowflags |= FLOW_PKT_TOCLIENT;
    p->flowflags |= FLOW_PKT_ESTABLISHED;
    p->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    f.alproto = ALPROTO_HTTP1;

    StreamTcpInitConfig(true);

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert http any any -> any any "
                               "(msg:\"http server body test\"; "
                               "content:\"message\"; http_server_body; "
                               "sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_HTTP1,
            STREAM_TOSERVER | STREAM_START | STREAM_EOF, http_buf, http_len);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        goto end;
    }
    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_HTTP1,
            STREAM_TOCLIENT | STREAM_START | STREAM_EOF, http_buf2, http_len2);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        goto end;
    }

    http_state = f.alstate;
    if (http_state == NULL) {
        printf("no http state: \n");
        result = 0;
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);

    if (!(PacketAlertCheck(p, 1))) {
        printf("sid 1 didn't match but should have: ");
        goto end;
    }

    result = 1;
end:
    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);

    StreamTcpFreeConfig(true);
    FLOW_DESTROY(&f);
    UTHFreePackets(&p, 1);
    return result;
}

/**
 *\test Test that the http_server_body content matches against a http request
 *      which holds the content.
 */
static int DetectHttpServerBodyTest07(void)
{
    TcpSession ssn;
    Packet *p1 = NULL;
    Packet *p2 = NULL;
    ThreadVars th_v;
    DetectEngineCtx *de_ctx = NULL;
    DetectEngineThreadCtx *det_ctx = NULL;
    HtpState *http_state = NULL;
    Flow f;
    uint8_t http_buf1[] =
        "GET /index.html HTTP/1.0\r\n"
        "Host: www.openinfosecfoundation.org\r\n"
        "User-Agent: Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.1.7) Gecko/20091221 Firefox/3.5.7\r\n"
        "\r\n";
    uint32_t http_len1 = sizeof(http_buf1) - 1;
    uint8_t http_buf2[] =
        "HTTP/1.0 200 ok\r\n"
        "Content-Type: text/html\r\n"
        "Content-Length: 14\r\n"
        "\r\n";
    uint32_t http_len2 = sizeof(http_buf2) - 1;
    uint8_t http_buf3[] =
        "message";
    uint32_t http_len3 = sizeof(http_buf3) - 1;
    int result = 0;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&th_v, 0, sizeof(th_v));
    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    p1 = UTHBuildPacket(NULL, 0, IPPROTO_TCP);
    p2 = UTHBuildPacket(NULL, 0, IPPROTO_TCP);

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;
    f.flags |= FLOW_IPV4;

    p1->flow = &f;
    p1->flowflags |= FLOW_PKT_TOCLIENT;
    p1->flowflags |= FLOW_PKT_ESTABLISHED;
    p1->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;

    p2->flow = &f;
    p2->flowflags |= FLOW_PKT_TOCLIENT;
    p2->flowflags |= FLOW_PKT_ESTABLISHED;
    p2->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    f.alproto = ALPROTO_HTTP1;

    StreamTcpInitConfig(true);

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert http any any -> any any "
                               "(msg:\"http server body test\"; "
                               "content:\"message\"; http_server_body; "
                               "sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER | STREAM_START,
            http_buf1, http_len1);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        goto end;
    }

    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOCLIENT | STREAM_START,
            http_buf2, http_len2);
    if (r != 0) {
        printf("toserver chunk 2 returned %" PRId32 ", expected 0: ", r);
        goto end;
    }

    http_state = f.alstate;
    if (http_state == NULL) {
        printf("no http state: ");
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p1);

    if ((PacketAlertCheck(p1, 1))) {
        printf("sid 1 matched on chunk2 but shouldn't have: ");
        goto end;
    }

    r = AppLayerParserParse(
            NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOCLIENT | STREAM_EOF, http_buf3, http_len3);
    if (r != 0) {
        printf("toserver chunk 3 returned %" PRId32 ", expected 0: ", r);
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p2);
    if (!(PacketAlertCheck(p2, 1))) {
        printf("sid 1 didn't match on p2 (chunk3) but should have: ");
        goto end;
    }

    result = 1;
end:
    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);

    StreamTcpFreeConfig(true);
    FLOW_DESTROY(&f);
    UTHFreePackets(&p1, 1);
    UTHFreePackets(&p2, 1);
    return result;
}

/**
 *\test Test that the http_server_body content matches against a http request
 *      which holds the content.
 */
static int DetectHttpServerBodyTest08(void)
{
    TcpSession ssn;
    Packet *p1 = NULL;
    Packet *p2 = NULL;
    ThreadVars th_v;
    DetectEngineCtx *de_ctx = NULL;
    DetectEngineThreadCtx *det_ctx = NULL;
    HtpState *http_state = NULL;
    Flow f;
    uint8_t http_buf1[] =
        "GET /index.html HTTP/1.0\r\n"
        "Host: www.openinfosecfoundation.org\r\n"
        "User-Agent: Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.1.7) Gecko/20091221 Firefox/3.5.7\r\n"
        "\r\n";
    uint32_t http_len1 = sizeof(http_buf1) - 1;
    uint8_t http_buf2[] =
        "HTTP/1.0 200 ok\r\n"
        "Content-Type: text/html\r\n"
        "Content-Length: 14\r\n"
        "\r\n"
        "bigmes";
    uint32_t http_len2 = sizeof(http_buf2) - 1;
    uint8_t http_buf3[] =
        "sage4u!!";
    uint32_t http_len3 = sizeof(http_buf3) - 1;
    int result = 0;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&th_v, 0, sizeof(th_v));
    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    p1 = UTHBuildPacket(NULL, 0, IPPROTO_TCP);
    p2 = UTHBuildPacket(NULL, 0, IPPROTO_TCP);

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;
    f.flags |= FLOW_IPV4;

    p1->flow = &f;
    p1->flowflags |= FLOW_PKT_TOCLIENT;
    p1->flowflags |= FLOW_PKT_ESTABLISHED;
    p1->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    p2->flow = &f;
    p2->flowflags |= FLOW_PKT_TOCLIENT;
    p2->flowflags |= FLOW_PKT_ESTABLISHED;
    p2->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    f.alproto = ALPROTO_HTTP1;

    StreamTcpInitConfig(true);

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert http any any -> any any "
                               "(msg:\"http client body test\"; "
                               "content:\"message\"; http_server_body; "
                               "sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER | STREAM_START,
            http_buf1, http_len1);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        goto end;
    }

    http_state = f.alstate;
    if (http_state == NULL) {
        printf("no http state: ");
        result = 0;
        goto end;
    }

    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOCLIENT | STREAM_START,
            http_buf2, http_len2);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p1);

    if ((PacketAlertCheck(p1, 1))) {
        printf("sid 1 matched but shouldn't have: ");
        goto end;
    }

    r = AppLayerParserParse(
            NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOCLIENT | STREAM_EOF, http_buf3, http_len3);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p2);

    if (!(PacketAlertCheck(p2, 1))) {
        printf("sid 1 didn't match but should have: ");
        goto end;
    }

    result = 1;
end:
    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);

    StreamTcpFreeConfig(true);
    FLOW_DESTROY(&f);
    UTHFreePackets(&p1, 1);
    UTHFreePackets(&p2, 1);
    return result;
}

/**
 *\test Test that the http_server_body content matches against a http request
 *      which holds the content.
 */
static int DetectHttpServerBodyTest09(void)
{
    TcpSession ssn;
    Packet *p1 = NULL;
    Packet *p2 = NULL;
    ThreadVars th_v;
    DetectEngineCtx *de_ctx = NULL;
    DetectEngineThreadCtx *det_ctx = NULL;
    HtpState *http_state = NULL;
    Flow f;
    uint8_t http_buf1[] =
        "GET /index.html HTTP/1.0\r\n"
        "Host: www.openinfosecfoundation.org\r\n"
        "User-Agent: Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.1.7) Gecko/20091221 Firefox/3.5.7\r\n"
        "\r\n";
    uint32_t http_len1 = sizeof(http_buf1) - 1;
    uint8_t http_buf2[] =
        "HTTP/1.0 200 ok\r\n"
        "Content-Type: text/html\r\n"
        "Content-Length: 14\r\n"
        "\r\n"
        "bigmes";
    uint32_t http_len2 = sizeof(http_buf2) - 1;
    uint8_t http_buf3[] =
        "sag";
    uint32_t http_len3 = sizeof(http_buf3) - 1;
    uint8_t http_buf4[] =
        "e4u!!";
    uint32_t http_len4 = sizeof(http_buf4) - 1;
    int result = 0;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&th_v, 0, sizeof(th_v));
    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    p1 = UTHBuildPacket(NULL, 0, IPPROTO_TCP);
    p2 = UTHBuildPacket(NULL, 0, IPPROTO_TCP);

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;
    f.flags |= FLOW_IPV4;

    p1->flow = &f;
    p1->flowflags |= FLOW_PKT_TOCLIENT;
    p1->flowflags |= FLOW_PKT_ESTABLISHED;
    p1->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    p2->flow = &f;
    p2->flowflags |= FLOW_PKT_TOCLIENT;
    p2->flowflags |= FLOW_PKT_ESTABLISHED;
    p2->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    f.alproto = ALPROTO_HTTP1;

    StreamTcpInitConfig(true);

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert http any any -> any any "
                               "(msg:\"http client body test\"; "
                               "content:\"message\"; http_server_body; "
                               "sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER | STREAM_START,
            http_buf1, http_len1);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        goto end;
    }

    http_state = f.alstate;
    if (http_state == NULL) {
        printf("no http state: ");
        result = 0;
        goto end;
    }

    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOCLIENT | STREAM_START,
            http_buf2, http_len2);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p1);

    if ((PacketAlertCheck(p1, 1))) {
        printf("sid 1 matched but shouldn't have: ");
        goto end;
    }

    r = AppLayerParserParse(
            NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOCLIENT, http_buf3, http_len3);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        goto end;
    }

    r = AppLayerParserParse(
            NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOCLIENT | STREAM_EOF, http_buf4, http_len4);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p2);

    if (!(PacketAlertCheck(p2, 1))) {
        printf("sid 1 didn't match but should have: ");
        goto end;
    }

    result = 1;
end:
    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);

    StreamTcpFreeConfig(true);
    FLOW_DESTROY(&f);
    UTHFreePackets(&p1, 1);
    UTHFreePackets(&p2, 1);
    return result;
}

/**
 *\test Test that the http_server_body content matches against a http request
 *      which holds the content. Case insensitve.
 */
static int DetectHttpServerBodyTest10(void)
{
    TcpSession ssn;
    Packet *p1 = NULL;
    Packet *p2 = NULL;
    ThreadVars th_v;
    DetectEngineCtx *de_ctx = NULL;
    DetectEngineThreadCtx *det_ctx = NULL;
    HtpState *http_state = NULL;
    Flow f;
    uint8_t http_buf1[] =
        "GET /index.html HTTP/1.0\r\n"
        "Host: www.openinfosecfoundation.org\r\n"
        "User-Agent: Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.1.7) Gecko/20091221 Firefox/3.5.7\r\n"
        "\r\n";
    uint32_t http_len1 = sizeof(http_buf1) - 1;
    uint8_t http_buf2[] =
        "HTTP/1.0 200 ok\r\n"
        "Content-Type: text/html\r\n"
        "Content-Length: 14\r\n"
        "\r\n"
        "bigmes";
    uint32_t http_len2 = sizeof(http_buf2) - 1;
    uint8_t http_buf3[] =
        "sag";
    uint32_t http_len3 = sizeof(http_buf3) - 1;
    uint8_t http_buf4[] =
        "e4u!!";
    uint32_t http_len4 = sizeof(http_buf4) - 1;
    int result = 0;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&th_v, 0, sizeof(th_v));
    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    p1 = UTHBuildPacket(NULL, 0, IPPROTO_TCP);
    p2 = UTHBuildPacket(NULL, 0, IPPROTO_TCP);

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;
    f.flags |= FLOW_IPV4;

    p1->flow = &f;
    p1->flowflags |= FLOW_PKT_TOCLIENT;
    p1->flowflags |= FLOW_PKT_ESTABLISHED;
    p1->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    p2->flow = &f;
    p2->flowflags |= FLOW_PKT_TOCLIENT;
    p2->flowflags |= FLOW_PKT_ESTABLISHED;
    p2->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    f.alproto = ALPROTO_HTTP1;

    StreamTcpInitConfig(true);

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert http any any -> any any "
                               "(msg:\"http client body test\"; "
                               "content:\"MeSSaGE\"; http_server_body; nocase; "
                               "sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER | STREAM_START,
            http_buf1, http_len1);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        goto end;
    }

    http_state = f.alstate;
    if (http_state == NULL) {
        printf("no http state: ");
        result = 0;
        goto end;
    }

    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOCLIENT | STREAM_START,
            http_buf2, http_len2);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p1);

    if ((PacketAlertCheck(p1, 1))) {
        printf("sid 1 matched but shouldn't have: ");
        goto end;
    }

    r = AppLayerParserParse(
            NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOCLIENT, http_buf3, http_len3);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        goto end;
    }

    r = AppLayerParserParse(
            NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOCLIENT | STREAM_EOF, http_buf4, http_len4);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p2);

    if (!(PacketAlertCheck(p2, 1))) {
        printf("sid 1 didn't match but should have: ");
        goto end;
    }

    result = 1;
end:
    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);

    StreamTcpFreeConfig(true);
    FLOW_DESTROY(&f);
    UTHFreePackets(&p1, 1);
    UTHFreePackets(&p2, 1);
    return result;
}

/**
 *\test Test that the http_server_body content matches against a http request
 *      which holds the content. Negated match.
 */
static int DetectHttpServerBodyTest11(void)
{
    TcpSession ssn;
    Packet *p1 = NULL;
    Packet *p2 = NULL;
    ThreadVars th_v;
    DetectEngineCtx *de_ctx = NULL;
    DetectEngineThreadCtx *det_ctx = NULL;
    HtpState *http_state = NULL;
    Flow f;
    uint8_t http_buf1[] =
        "GET /index.html HTTP/1.0\r\n"
        "Host: www.openinfosecfoundation.org\r\n"
        "User-Agent: Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.1.7) Gecko/20091221 Firefox/3.5.7\r\n"
        "\r\n";
    uint32_t http_len1 = sizeof(http_buf1) - 1;
    uint8_t http_buf2[] =
        "HTTP/1.0 200 ok\r\n"
        "Content-Type: text/html\r\n"
        "Content-Length: 14\r\n"
        "\r\n";
    uint32_t http_len2 = sizeof(http_buf2) - 1;
    uint8_t http_buf3[] =
        "bigmessage4u!!";
    uint32_t http_len3 = sizeof(http_buf3) - 1;
    int result = 0;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&th_v, 0, sizeof(th_v));
    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    p1 = UTHBuildPacket(NULL, 0, IPPROTO_TCP);
    p2 = UTHBuildPacket(NULL, 0, IPPROTO_TCP);

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;
    f.flags |= FLOW_IPV4;

    p1->flow = &f;
    p1->flowflags |= FLOW_PKT_TOCLIENT;
    p1->flowflags |= FLOW_PKT_ESTABLISHED;
    p1->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    p2->flow = &f;
    p2->flowflags |= FLOW_PKT_TOCLIENT;
    p2->flowflags |= FLOW_PKT_ESTABLISHED;
    p2->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    f.alproto = ALPROTO_HTTP1;

    StreamTcpInitConfig(true);

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert http any any -> any any "
                               "(msg:\"http client body test\"; "
                               "content:!\"MaSSaGE\"; http_server_body; nocase; "
                               "sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER | STREAM_START,
            http_buf1, http_len1);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        goto end;
    }

    http_state = f.alstate;
    if (http_state == NULL) {
        printf("no http state: ");
        result = 0;
        goto end;
    }

    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOCLIENT | STREAM_START,
            http_buf2, http_len2);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p1);

    if (PacketAlertCheck(p1, 1)) {
        printf("sid 1 matched but shouldn't have (p1): ");
        goto end;
    }

    r = AppLayerParserParse(
            NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOCLIENT | STREAM_EOF, http_buf3, http_len3);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p2);

    if (!(PacketAlertCheck(p2, 1))) {
        printf("sid 1 didn't match but should have (p2): ");
        goto end;
    }

    result = 1;
end:
    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);

    StreamTcpFreeConfig(true);
    FLOW_DESTROY(&f);
    UTHFreePackets(&p1, 1);
    UTHFreePackets(&p2, 1);
    return result;
}

/**
 *\test Test that the http_server_body content matches against a http request
 *      which holds the content. Negated match.
 */
static int DetectHttpServerBodyTest12(void)
{
    TcpSession ssn;
    Packet *p1 = NULL;
    Packet *p2 = NULL;
    ThreadVars th_v;
    DetectEngineCtx *de_ctx = NULL;
    DetectEngineThreadCtx *det_ctx = NULL;
    HtpState *http_state = NULL;
    Flow f;
    uint8_t http_buf1[] =
        "GET /index.html HTTP/1.0\r\n"
        "Host: www.openinfosecfoundation.org\r\n"
        "User-Agent: Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.1.7) Gecko/20091221 Firefox/3.5.7\r\n"
        "\r\n";
    uint32_t http_len1 = sizeof(http_buf1) - 1;
    uint8_t http_buf2[] =
        "HTTP/1.0 200 ok\r\n"
        "Content-Type: text/html\r\n"
        "Content-Length: 14\r\n"
        "\r\n";
    uint32_t http_len2 = sizeof(http_buf2) - 1;
    uint8_t http_buf3[] =
        "bigmessage4u!!";
    uint32_t http_len3 = sizeof(http_buf3) - 1;
    int result = 0;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&th_v, 0, sizeof(th_v));
    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    p1 = UTHBuildPacket(NULL, 0, IPPROTO_TCP);
    p2 = UTHBuildPacket(NULL, 0, IPPROTO_TCP);

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;
    f.flags |= FLOW_IPV4;

    p1->flow = &f;
    p1->flowflags |= FLOW_PKT_TOCLIENT;
    p1->flowflags |= FLOW_PKT_ESTABLISHED;
    p1->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    p2->flow = &f;
    p2->flowflags |= FLOW_PKT_TOCLIENT;
    p2->flowflags |= FLOW_PKT_ESTABLISHED;
    p2->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    f.alproto = ALPROTO_HTTP1;

    StreamTcpInitConfig(true);

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert http any any -> any any "
                               "(msg:\"http client body test\"; "
                               "content:!\"MeSSaGE\"; http_server_body; nocase; "
                               "sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER | STREAM_START,
            http_buf1, http_len1);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        goto end;
    }

    http_state = f.alstate;
    if (http_state == NULL) {
        printf("no http state: ");
        result = 0;
        goto end;
    }

    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOCLIENT | STREAM_START,
            http_buf2, http_len2);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p1);

    if (PacketAlertCheck(p1, 1)) {
        printf("sid 1 matched but shouldn't have (p1): ");
        goto end;
    }

    r = AppLayerParserParse(
            NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOCLIENT | STREAM_EOF, http_buf3, http_len3);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p2);

    if (PacketAlertCheck(p2, 1)) {
        printf("sid 1 matched but shouldn't have (p2): ");
        goto end;
    }

    result = 1;
end:
    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);

    StreamTcpFreeConfig(true);
    FLOW_DESTROY(&f);
    UTHFreePackets(&p1, 1);
    UTHFreePackets(&p2, 1);
    return result;
}

static int DetectHttpServerBodyTest13(void)
{
    TcpSession ssn;
    Packet *p = NULL;
    ThreadVars th_v;
    DetectEngineCtx *de_ctx = NULL;
    DetectEngineThreadCtx *det_ctx = NULL;
    HtpState *http_state = NULL;
    Flow f;
    uint8_t http_buf[] =
        "GET /index.html HTTP/1.0\r\n"
        "Host: www.openinfosecfoundation.org\r\n"
        "User-Agent: Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.1.7) Gecko/20091221 Firefox/3.5.7\r\n"
        "\r\n";
    uint32_t http_len = sizeof(http_buf) - 1;
    uint8_t http_buf2[] =
        "HTTP/1.0 200 ok\r\n"
        "Content-Type: text/html\r\n"
        "Content-Length: 55\r\n"
        "\r\n"
        "longbufferabcdefghijklmnopqrstuvwxyz0123456789bufferend";
    uint32_t http_len2 = sizeof(http_buf2) - 1;
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

    p->flow = &f;
    p->flowflags |= FLOW_PKT_TOCLIENT;
    p->flowflags |= FLOW_PKT_ESTABLISHED;
    p->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    f.alproto = ALPROTO_HTTP1;

    StreamTcpInitConfig(true);

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert http any any -> any any "
                               "(msg:\"http server body test\"; "
                               "content:\"longbufferabcdefghijklmnopqrstuvwxyz0123456789bufferend\"; http_server_body; "
                               "sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_HTTP1,
            STREAM_TOSERVER | STREAM_START | STREAM_EOF, http_buf, http_len);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        goto end;
    }
    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_HTTP1,
            STREAM_TOCLIENT | STREAM_START | STREAM_EOF, http_buf2, http_len2);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        goto end;
    }

    http_state = f.alstate;
    if (http_state == NULL) {
        printf("no http state: \n");
        result = 0;
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);

    if (!(PacketAlertCheck(p, 1))) {
        printf("sid 1 didn't match but should have: ");
        goto end;
    }

    result = 1;
end:
    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);

    StreamTcpFreeConfig(true);
    FLOW_DESTROY(&f);
    UTHFreePackets(&p, 1);
    return result;
}

/** \test multiple http transactions and body chunks of request handling */
static int DetectHttpServerBodyTest14(void)
{
    int result = 0;
    Signature *s = NULL;
    DetectEngineThreadCtx *det_ctx = NULL;
    ThreadVars th_v;
    Flow f;
    TcpSession ssn;
    Packet *p = NULL;
    uint8_t httpbuf1[] = "GET /index1.html HTTP/1.1\r\n"
        "User-Agent: Mozilla/1.0\r\n"
        "Host: www.openinfosecfoundation.org\r\n"
        "Connection: keep-alive\r\n"
        "Cookie: dummy1\r\n\r\n";
    uint32_t httplen1 = sizeof(httpbuf1) - 1; /* minus the \0 */
    uint8_t httpbuf2[] = "HTTP/1.1 200 ok\r\n"
        "Content-Type: text/html\r\n"
        "Content-Length: 3\r\n"
        "\r\n"
        "one";
    uint32_t httplen2 = sizeof(httpbuf2) - 1; /* minus the \0 */
    uint8_t httpbuf3[] = "GET /index2.html HTTP/1.1\r\n"
        "User-Agent: Firefox/1.0\r\n"
        "Host: www.openinfosecfoundation.org\r\n"
        "Connection: keep-alive\r\n"
        "Cookie: dummy2\r\n\r\n";
    uint32_t httplen3 = sizeof(httpbuf3) - 1; /* minus the \0 */
    uint8_t httpbuf4[] = "HTTP/1.1 200 ok\r\n"
        "Content-Type: text/html\r\n"
        "Content-Length: 3\r\n"
        "\r\n"
        "two";
    uint32_t httplen4 = sizeof(httpbuf4) - 1; /* minus the \0 */
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&th_v, 0, sizeof(th_v));
    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    p = UTHBuildPacket(NULL, 0, IPPROTO_TCP);

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;
    f.flags |= FLOW_IPV4;

    p->flow = &f;
    p->flowflags |= FLOW_PKT_TOCLIENT;
    p->flowflags |= FLOW_PKT_ESTABLISHED;
    p->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    f.alproto = ALPROTO_HTTP1;

    StreamTcpInitConfig(true);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }

    de_ctx->flags |= DE_QUIET;

    s = DetectEngineAppendSig(de_ctx, "alert tcp any any -> any any (flow:established,to_client; content:\"one\"; http_server_body; sid:1; rev:1;)");
    if (s == NULL) {
        printf("sig parse failed: ");
        goto end;
    }
    s = DetectEngineAppendSig(de_ctx, "alert tcp any any -> any any (flow:established,to_client; content:\"two\"; http_server_body; sid:2; rev:1;)");
    if (s == NULL) {
        printf("sig2 parse failed: ");
        goto end;
    }

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    SCLogDebug("add chunk 1");

    int r = AppLayerParserParse(
            NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER | STREAM_START, httpbuf1, httplen1);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        goto end;
    }

    SCLogDebug("add chunk 2");

    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOCLIENT, httpbuf2, httplen2);
    if (r != 0) {
        printf("toserver chunk 2 returned %" PRId32 ", expected 0: ", r);
        goto end;
    }

    SCLogDebug("inspect chunk 1");

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    if (!(PacketAlertCheck(p, 1))) {
        printf("sig 1 didn't alert (tx 1): ");
        goto end;
    }
    p->alerts.cnt = 0;

    SCLogDebug("add chunk 3");

    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER, httpbuf3, httplen3);
    if (r != 0) {
        printf("toserver chunk 3 returned %" PRId32 ", expected 0: ", r);
        goto end;
    }

    SCLogDebug("add chunk 4");

    r = AppLayerParserParse(
            NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOCLIENT | STREAM_EOF, httpbuf4, httplen4);
    if (r != 0) {
        printf("toserver chunk 4 returned %" PRId32 ", expected 0: ", r);
        goto end;
    }

    SCLogDebug("inspect chunk 4");

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    if ((PacketAlertCheck(p, 1))) {
        printf("sig 1 alerted (tx 2): ");
        goto end;
    }
    if (!(PacketAlertCheck(p, 2))) {
        printf("sig 2 didn't alert (tx 2): ");
        goto end;
    }
    p->alerts.cnt = 0;

    HtpState *htp_state = f.alstate;
    if (htp_state == NULL) {
        printf("no http state: ");
        goto end;
    }

    if (AppLayerParserGetTxCnt(&f, htp_state) != 2) {
        printf("The http app layer doesn't have 2 transactions, but it should: ");
        goto end;
    }

    result = 1;
end:
    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
    if (det_ctx != NULL) {
        DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    }
    if (de_ctx != NULL) {
        DetectEngineCtxFree(de_ctx);
    }

    StreamTcpFreeConfig(true);
    FLOW_DESTROY(&f);
    UTHFreePacket(p);
    return result;
}

static int DetectHttpServerBodyTest15(void)
{
    int result = 0;
    Signature *s = NULL;
    DetectEngineThreadCtx *det_ctx = NULL;
    ThreadVars th_v;
    Flow f;
    TcpSession ssn;
    Packet *p = NULL;
    uint8_t httpbuf1[] = "GET /index1.html HTTP/1.1\r\n"
        "User-Agent: Mozilla/1.0\r\n"
        "Host: www.openinfosecfoundation.org\r\n"
        "Connection: keep-alive\r\n"
        "Cookie: dummy1\r\n\r\n";
    uint32_t httplen1 = sizeof(httpbuf1) - 1; /* minus the \0 */
    uint8_t httpbuf2[] = "HTTP/1.1 200 ok\r\n"
        "Content-Type: text/html\r\n"
        "Content-Length: 3\r\n"
        "\r\n"
        "one";
    uint32_t httplen2 = sizeof(httpbuf2) - 1; /* minus the \0 */
    uint8_t httpbuf3[] = "GET /index2.html HTTP/1.1\r\n"
        "User-Agent: Firefox/1.0\r\n"
        "Host: www.openinfosecfoundation.org\r\n"
        "Connection: keep-alive\r\n"
        "Cookie: dummy2\r\n\r\n";
    uint32_t httplen3 = sizeof(httpbuf3) - 1; /* minus the \0 */
    uint8_t httpbuf4[] = "HTTP/1.1 200 ok\r\n"
        "Content-Type: text/html\r\n"
        "Content-Length: 3\r\n"
        "\r\n"
        "two";
    uint32_t httplen4 = sizeof(httpbuf4) - 1; /* minus the \0 */
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&th_v, 0, sizeof(th_v));
    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    p = UTHBuildPacket(NULL, 0, IPPROTO_TCP);

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;
    f.flags |= FLOW_IPV4;

    p->flow = &f;
    p->flowflags |= FLOW_PKT_TOCLIENT;
    p->flowflags |= FLOW_PKT_ESTABLISHED;
    p->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    f.alproto = ALPROTO_HTTP1;

    StreamTcpInitConfig(true);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }

    de_ctx->flags |= DE_QUIET;

    s = DetectEngineAppendSig(de_ctx, "alert tcp any any -> any any (flow:established,to_client; content:\"one\"; http_server_body; sid:1; rev:1;)");
    if (s == NULL) {
        printf("sig parse failed: ");
        goto end;
    }
    s = DetectEngineAppendSig(de_ctx, "alert tcp any any -> any any (flow:established,to_client; content:\"two\"; http_server_body; sid:2; rev:1;)");
    if (s == NULL) {
        printf("sig2 parse failed: ");
        goto end;
    }

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParserParse(
            NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER | STREAM_START, httpbuf1, httplen1);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        goto end;
    }

    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOCLIENT, httpbuf2, httplen2);
    if (r != 0) {
        printf("toserver chunk 2 returned %" PRId32 ", expected 0: ", r);
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    if (!(PacketAlertCheck(p, 1))) {
        printf("sig 1 didn't alert (tx 1): ");
        goto end;
    }
    if (PacketAlertCheck(p, 2)) {
        printf("sig 2 alerted (tx 1): ");
        goto end;
    }
    p->alerts.cnt = 0;

    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER, httpbuf3, httplen3);
    if (r != 0) {
        printf("toserver chunk 3 returned %" PRId32 ", expected 0: ", r);
        goto end;
    }

    r = AppLayerParserParse(
            NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOCLIENT | STREAM_EOF, httpbuf4, httplen4);
    if (r != 0) {
        printf("toserver chunk 4 returned %" PRId32 ", expected 0: ", r);
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    if ((PacketAlertCheck(p, 1))) {
        printf("sig 1 alerted (tx 2): ");
        goto end;
    }
    if (!(PacketAlertCheck(p, 2))) {
        printf("sig 2 didn't alert (tx 2): ");
        goto end;
    }
    p->alerts.cnt = 0;

    HtpState *htp_state = f.alstate;
    if (htp_state == NULL) {
        printf("no http state: ");
        goto end;
    }

    if (AppLayerParserGetTxCnt(&f, htp_state) != 2) {
        printf("The http app layer doesn't have 2 transactions, but it should: ");
        goto end;
    }

    result = 1;
end:
    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
    if (det_ctx != NULL) {
        DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    }
    if (de_ctx != NULL) {
        DetectEngineCtxFree(de_ctx);
    }

    StreamTcpFreeConfig(true);
    FLOW_DESTROY(&f);
    UTHFreePacket(p);
    return result;
}

static int DetectHttpServerBodyTest22(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; content:\"two\"; http_server_body; "
                               "content:\"three\"; distance:10; http_server_body; content:\"four\"; sid:1;)");
    if (de_ctx->sig_list == NULL) {
        printf("de_ctx->sig_list == NULL\n");
        goto end;
    }

    if (de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH] == NULL) {
        printf("de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH] == NULL\n");
        goto end;
    }

    if (de_ctx->sig_list->sm_lists[g_file_data_buffer_id] == NULL) {
        printf("de_ctx->sig_list->sm_lists[g_file_data_buffer_id] == NULL\n");
        goto end;
    }

    DetectContentData *cd1 = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[DETECT_SM_LIST_PMATCH]->prev->ctx;
    DetectContentData *cd2 = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[DETECT_SM_LIST_PMATCH]->ctx;
    DetectContentData *hsbd1 = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_file_data_buffer_id]->prev->ctx;
    DetectContentData *hsbd2 = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_file_data_buffer_id]->ctx;
    if (cd1->flags != 0 || memcmp(cd1->content, "one", cd1->content_len) != 0 ||
        cd2->flags != 0 || memcmp(cd2->content, "four", cd2->content_len) != 0 ||
        hsbd1->flags != DETECT_CONTENT_RELATIVE_NEXT ||
        memcmp(hsbd1->content, "two", hsbd1->content_len) != 0 ||
        hsbd2->flags != DETECT_CONTENT_DISTANCE ||
        memcmp(hsbd2->content, "three", hsbd1->content_len) != 0) {
        goto end;
    }

    if (!DETECT_CONTENT_IS_SINGLE(cd1) ||
        !DETECT_CONTENT_IS_SINGLE(cd2) ||
        DETECT_CONTENT_IS_SINGLE(hsbd1) ||
        DETECT_CONTENT_IS_SINGLE(hsbd2)) {
        goto end;
    }

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectHttpServerBodyTest23(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_server_body; pcre:/two/; "
                               "content:\"three\"; distance:10; http_server_body; content:\"four\"; sid:1;)");
    if (de_ctx->sig_list == NULL) {
        printf("de_ctx->sig_list == NULL\n");
        goto end;
    }

    if (de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH] == NULL) {
        printf("de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH] == NULL\n");
        goto end;
    }

    if (de_ctx->sig_list->sm_lists[g_file_data_buffer_id] == NULL) {
        printf("de_ctx->sig_list->sm_lists[g_file_data_buffer_id] == NULL\n");
        goto end;
    }

    DetectPcreData *pd1 = (DetectPcreData *)de_ctx->sig_list->sm_lists_tail[DETECT_SM_LIST_PMATCH]->prev->ctx;
    DetectContentData *cd2 = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[DETECT_SM_LIST_PMATCH]->ctx;
    DetectContentData *hsbd1 = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_file_data_buffer_id]->prev->ctx;
    DetectContentData *hsbd2 = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_file_data_buffer_id]->ctx;
    if (pd1->flags != 0 ||
        cd2->flags != 0 || memcmp(cd2->content, "four", cd2->content_len) != 0 ||
        hsbd1->flags != DETECT_CONTENT_RELATIVE_NEXT ||
        memcmp(hsbd1->content, "one", hsbd1->content_len) != 0 ||
        hsbd2->flags != DETECT_CONTENT_DISTANCE ||
        memcmp(hsbd2->content, "three", hsbd1->content_len) != 0) {
        goto end;
    }

    if (!DETECT_CONTENT_IS_SINGLE(cd2) ||
        DETECT_CONTENT_IS_SINGLE(hsbd1) ||
        DETECT_CONTENT_IS_SINGLE(hsbd2)) {
        goto end;
    }

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectHttpServerBodyTest24(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_server_body; pcre:/two/; "
                               "content:\"three\"; distance:10; within:15; http_server_body; content:\"four\"; sid:1;)");
    if (de_ctx->sig_list == NULL) {
        printf("de_ctx->sig_list == NULL\n");
        goto end;
    }

    if (de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH] == NULL) {
        printf("de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH] == NULL\n");
        goto end;
    }

    if (de_ctx->sig_list->sm_lists[g_file_data_buffer_id] == NULL) {
        printf("de_ctx->sig_list->sm_lists[g_file_data_buffer_id] == NULL\n");
        goto end;
    }

    DetectPcreData *pd1 = (DetectPcreData *)de_ctx->sig_list->sm_lists_tail[DETECT_SM_LIST_PMATCH]->prev->ctx;
    DetectContentData *cd2 = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[DETECT_SM_LIST_PMATCH]->ctx;
    DetectContentData *hsbd1 = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_file_data_buffer_id]->prev->ctx;
    DetectContentData *hsbd2 = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_file_data_buffer_id]->ctx;
    if (pd1->flags != 0 ||
        cd2->flags != 0 || memcmp(cd2->content, "four", cd2->content_len) != 0 ||
        hsbd1->flags != DETECT_CONTENT_RELATIVE_NEXT ||
        memcmp(hsbd1->content, "one", hsbd1->content_len) != 0 ||
        hsbd2->flags != (DETECT_CONTENT_DISTANCE | DETECT_CONTENT_WITHIN) ||
        memcmp(hsbd2->content, "three", hsbd1->content_len) != 0) {
        goto end;
    }

    if (!DETECT_CONTENT_IS_SINGLE(cd2) ||
        DETECT_CONTENT_IS_SINGLE(hsbd1) ||
        DETECT_CONTENT_IS_SINGLE(hsbd2)) {
        goto end;
    }

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectHttpServerBodyTest25(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_server_body; pcre:/two/; "
                               "content:\"three\"; distance:10; http_server_body; "
                               "content:\"four\"; distance:10; sid:1;)");
    if (de_ctx->sig_list == NULL) {
        printf("de_ctx->sig_list == NULL\n");
        goto end;
    }

    if (de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH] == NULL) {
        printf("de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH] == NULL\n");
        goto end;
    }

    if (de_ctx->sig_list->sm_lists[g_file_data_buffer_id] == NULL) {
        printf("de_ctx->sig_list->sm_lists[g_file_data_buffer_id] == NULL\n");
        goto end;
    }

    DetectPcreData *pd1 = (DetectPcreData *)de_ctx->sig_list->sm_lists_tail[DETECT_SM_LIST_PMATCH]->prev->ctx;
    DetectContentData *cd2 = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[DETECT_SM_LIST_PMATCH]->ctx;
    DetectContentData *hsbd1 = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_file_data_buffer_id]->prev->ctx;
    DetectContentData *hsbd2 = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_file_data_buffer_id]->ctx;
    if (pd1->flags != DETECT_PCRE_RELATIVE_NEXT ||
        cd2->flags != DETECT_CONTENT_DISTANCE ||
        memcmp(cd2->content, "four", cd2->content_len) != 0 ||
        hsbd1->flags != DETECT_CONTENT_RELATIVE_NEXT ||
        memcmp(hsbd1->content, "one", hsbd1->content_len) != 0 ||
        hsbd2->flags != DETECT_CONTENT_DISTANCE ||
        memcmp(hsbd2->content, "three", hsbd1->content_len) != 0) {
        goto end;
    }

    if (DETECT_CONTENT_IS_SINGLE(cd2) ||
        DETECT_CONTENT_IS_SINGLE(hsbd1) ||
        DETECT_CONTENT_IS_SINGLE(hsbd2)) {
        goto end;
    }

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectHttpServerBodyTest26(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; offset:10; http_server_body; pcre:/two/; "
                               "content:\"three\"; distance:10; http_server_body; within:10; "
                               "content:\"four\"; distance:10; sid:1;)");
    if (de_ctx->sig_list == NULL) {
        printf("de_ctx->sig_list == NULL\n");
        goto end;
    }

    if (de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH] == NULL) {
        printf("de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH] == NULL\n");
        goto end;
    }

    if (de_ctx->sig_list->sm_lists[g_file_data_buffer_id] == NULL) {
        printf("de_ctx->sig_list->sm_lists[g_file_data_buffer_id] == NULL\n");
        goto end;
    }

    DetectPcreData *pd1 = (DetectPcreData *)de_ctx->sig_list->sm_lists_tail[DETECT_SM_LIST_PMATCH]->prev->ctx;
    DetectContentData *cd2 = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[DETECT_SM_LIST_PMATCH]->ctx;
    DetectContentData *hsbd1 = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_file_data_buffer_id]->prev->ctx;
    DetectContentData *hsbd2 = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_file_data_buffer_id]->ctx;
    if (pd1->flags != (DETECT_PCRE_RELATIVE_NEXT) ||
        cd2->flags != DETECT_CONTENT_DISTANCE ||
        memcmp(cd2->content, "four", cd2->content_len) != 0 ||
        hsbd1->flags != (DETECT_CONTENT_RELATIVE_NEXT | DETECT_CONTENT_OFFSET) ||
        memcmp(hsbd1->content, "one", hsbd1->content_len) != 0 ||
        hsbd2->flags != (DETECT_CONTENT_DISTANCE | DETECT_CONTENT_WITHIN) ||
        memcmp(hsbd2->content, "three", hsbd1->content_len) != 0) {
        goto end;
    }

    if (DETECT_CONTENT_IS_SINGLE(cd2) ||
        DETECT_CONTENT_IS_SINGLE(hsbd1) ||
        DETECT_CONTENT_IS_SINGLE(hsbd2)) {
        goto end;
    }

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

/** \test invalid combination for content: distance, depth, http_server_body */
static int DetectHttpServerBodyTest27(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; offset:10; http_server_body; pcre:/two/; distance:10; "
                               "content:\"three\"; distance:10; http_server_body; depth:10; "
                               "content:\"four\"; distance:10; sid:1;)");
    if (de_ctx->sig_list != NULL) {
        printf("de_ctx->sig_list != NULL: ");
        goto end;
    }

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectHttpServerBodyTest28(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_server_body; pcre:/two/; "
                               "content:\"three\"; http_server_body; depth:10; "
                               "content:\"four\"; distance:10; sid:1;)");
    if (de_ctx->sig_list == NULL) {
        printf("de_ctx->sig_list == NULL\n");
        goto end;
    }

    if (de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH] == NULL) {
        printf("de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH] == NULL\n");
        goto end;
    }

    if (de_ctx->sig_list->sm_lists[g_file_data_buffer_id] == NULL) {
        printf("de_ctx->sig_list->sm_lists[g_file_data_buffer_id] == NULL\n");
        goto end;
    }

    DetectPcreData *pd1 = (DetectPcreData *)de_ctx->sig_list->sm_lists_tail[DETECT_SM_LIST_PMATCH]->prev->ctx;
    DetectContentData *cd2 = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[DETECT_SM_LIST_PMATCH]->ctx;
    DetectContentData *hsbd1 = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_file_data_buffer_id]->prev->ctx;
    DetectContentData *hsbd2 = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_file_data_buffer_id]->ctx;
    if (pd1->flags != (DETECT_PCRE_RELATIVE_NEXT) ||
        cd2->flags != DETECT_CONTENT_DISTANCE ||
        memcmp(cd2->content, "four", cd2->content_len) != 0 ||
        hsbd1->flags != 0 ||
        memcmp(hsbd1->content, "one", hsbd1->content_len) != 0 ||
        hsbd2->flags != DETECT_CONTENT_DEPTH ||
        memcmp(hsbd2->content, "three", hsbd1->content_len) != 0) {
        goto end;
    }

    if (DETECT_CONTENT_IS_SINGLE(cd2) ||
        !DETECT_CONTENT_IS_SINGLE(hsbd1) ||
        DETECT_CONTENT_IS_SINGLE(hsbd2)) {
        goto end;
    }

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectHttpServerBodyTest29(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_server_body; "
                               "content:\"two\"; distance:0; http_server_body; sid:1;)");
    if (de_ctx->sig_list == NULL) {
        printf("de_ctx->sig_list == NULL\n");
        goto end;
    }

    if (de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH] != NULL) {
        printf("de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH] != NULL\n");
        goto end;
    }

    if (de_ctx->sig_list->sm_lists[g_file_data_buffer_id] == NULL) {
        printf("de_ctx->sig_list->sm_lists[g_file_data_buffer_id] == NULL\n");
        goto end;
    }

    DetectContentData *hsbd1 = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_file_data_buffer_id]->prev->ctx;
    DetectContentData *hsbd2 = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_file_data_buffer_id]->ctx;
    if (hsbd1->flags != DETECT_CONTENT_RELATIVE_NEXT ||
        memcmp(hsbd1->content, "one", hsbd1->content_len) != 0 ||
        hsbd2->flags != DETECT_CONTENT_DISTANCE ||
        memcmp(hsbd2->content, "two", hsbd1->content_len) != 0) {
        goto end;
    }

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectHttpServerBodyTest30(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_server_body; "
                               "content:\"two\"; within:5; http_server_body; sid:1;)");
    if (de_ctx->sig_list == NULL) {
        printf("de_ctx->sig_list == NULL\n");
        goto end;
    }

    if (de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH] != NULL) {
        printf("de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH] != NULL\n");
        goto end;
    }

    if (de_ctx->sig_list->sm_lists[g_file_data_buffer_id] == NULL) {
        printf("de_ctx->sig_list->sm_lists[g_file_data_buffer_id] == NULL\n");
        goto end;
    }

    DetectContentData *hsbd1 = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_file_data_buffer_id]->prev->ctx;
    DetectContentData *hsbd2 = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_file_data_buffer_id]->ctx;
    if (hsbd1->flags != DETECT_CONTENT_RELATIVE_NEXT ||
        memcmp(hsbd1->content, "one", hsbd1->content_len) != 0 ||
        hsbd2->flags != DETECT_CONTENT_WITHIN ||
        memcmp(hsbd2->content, "two", hsbd1->content_len) != 0) {
        goto end;
    }

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectHttpServerBodyTest31(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; within:5; http_server_body; sid:1;)");
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

static int DetectHttpServerBodyTest32(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_server_body; within:5; sid:1;)");
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

static int DetectHttpServerBodyTest33(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
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

static int DetectHttpServerBodyTest34(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(pcre:/one/Q; "
                               "content:\"two\"; within:5; http_server_body; sid:1;)");
    FAIL_IF_NULL(de_ctx->sig_list);

    FAIL_IF_NOT_NULL(de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH]);

    if (de_ctx->sig_list->sm_lists[g_file_data_buffer_id] == NULL) {
        printf("de_ctx->sig_list->sm_lists[g_file_data_buffer_id] == NULL\n");
        goto end;
    }

    if (de_ctx->sig_list->sm_lists_tail[g_file_data_buffer_id] == NULL ||
        de_ctx->sig_list->sm_lists_tail[g_file_data_buffer_id]->type != DETECT_CONTENT ||
        de_ctx->sig_list->sm_lists_tail[g_file_data_buffer_id]->prev == NULL ||
        de_ctx->sig_list->sm_lists_tail[g_file_data_buffer_id]->prev->type != DETECT_PCRE) {

        goto end;
    }

    DetectPcreData *pd1 = (DetectPcreData *)de_ctx->sig_list->sm_lists_tail[g_file_data_buffer_id]->prev->ctx;
    DetectContentData *hsbd2 = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_file_data_buffer_id]->ctx;
    if (pd1->flags != (DETECT_PCRE_RELATIVE_NEXT) ||
        hsbd2->flags != DETECT_CONTENT_WITHIN ||
        memcmp(hsbd2->content, "two", hsbd2->content_len) != 0) {
        goto end;
    }

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectHttpServerBodyTest35(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"two\"; http_server_body; "
                               "pcre:/one/QR; sid:1;)");
    if (de_ctx->sig_list == NULL) {
        printf("de_ctx->sig_list == NULL\n");
        goto end;
    }

    if (de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH] != NULL) {
        printf("de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH] != NULL\n");
        goto end;
    }

    if (de_ctx->sig_list->sm_lists[g_file_data_buffer_id] == NULL) {
        printf("de_ctx->sig_list->sm_lists[g_file_data_buffer_id] == NULL\n");
        goto end;
    }

    if (de_ctx->sig_list->sm_lists_tail[g_file_data_buffer_id] == NULL ||
        de_ctx->sig_list->sm_lists_tail[g_file_data_buffer_id]->type != DETECT_PCRE ||
        de_ctx->sig_list->sm_lists_tail[g_file_data_buffer_id]->prev == NULL ||
        de_ctx->sig_list->sm_lists_tail[g_file_data_buffer_id]->prev->type != DETECT_CONTENT) {

        goto end;
    }

    DetectContentData *hsbd1 = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_file_data_buffer_id]->prev->ctx;
    DetectPcreData *pd2 = (DetectPcreData *)de_ctx->sig_list->sm_lists_tail[g_file_data_buffer_id]->ctx;
    if (pd2->flags != (DETECT_PCRE_RELATIVE) ||
        hsbd1->flags != DETECT_CONTENT_RELATIVE_NEXT ||
        memcmp(hsbd1->content, "two", hsbd1->content_len) != 0) {
        goto end;
    }

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectHttpServerBodyTest36(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(pcre:/one/Q; "
                               "content:\"two\"; distance:5; http_server_body; sid:1;)");
    if (de_ctx->sig_list == NULL) {
        printf("de_ctx->sig_list == NULL\n");
        goto end;
    }

    if (de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH] != NULL) {
        printf("de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH] != NULL\n");
        goto end;
    }

    if (de_ctx->sig_list->sm_lists[g_file_data_buffer_id] == NULL) {
        printf("de_ctx->sig_list->sm_lists[g_file_data_buffer_id] == NULL\n");
        goto end;
    }

    if (de_ctx->sig_list->sm_lists_tail[g_file_data_buffer_id] == NULL ||
        de_ctx->sig_list->sm_lists_tail[g_file_data_buffer_id]->type != DETECT_CONTENT ||
        de_ctx->sig_list->sm_lists_tail[g_file_data_buffer_id]->prev == NULL ||
        de_ctx->sig_list->sm_lists_tail[g_file_data_buffer_id]->prev->type != DETECT_PCRE) {

        goto end;
    }

    DetectPcreData *pd1 = (DetectPcreData *)de_ctx->sig_list->sm_lists_tail[g_file_data_buffer_id]->prev->ctx;
    DetectContentData *hsbd2 = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_file_data_buffer_id]->ctx;
    if (pd1->flags != (DETECT_PCRE_RELATIVE_NEXT) ||
        hsbd2->flags != DETECT_CONTENT_DISTANCE ||
        memcmp(hsbd2->content, "two", hsbd2->content_len) != 0) {
        goto end;
    }

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

/**
 *\test Test that the http_server_body content matches against a http request
 *      which holds the content.
 */
static int DetectHttpServerBodyFileDataTest01(void)
{
    TcpSession ssn;
    Packet *p = NULL;
    ThreadVars th_v;
    DetectEngineCtx *de_ctx = NULL;
    DetectEngineThreadCtx *det_ctx = NULL;
    HtpState *http_state = NULL;
    Flow f;
    uint8_t http_buf[] =
        "GET /index.html HTTP/1.0\r\n"
        "Host: www.openinfosecfoundation.org\r\n"
        "User-Agent: Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.1.7) Gecko/20091221 Firefox/3.5.7\r\n"
        "\r\n";
    uint32_t http_len = sizeof(http_buf) - 1;
    uint8_t http_buf2[] =
        "HTTP/1.0 200 ok\r\n"
        "Content-Type: text/html\r\n"
        "Content-Length: 7\r\n"
        "\r\n"
        "message";
    uint32_t http_len2 = sizeof(http_buf2) - 1;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&th_v, 0, sizeof(th_v));
    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    p = UTHBuildPacket(NULL, 0, IPPROTO_TCP);

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;
    f.flags |= FLOW_IPV4;

    p->flow = &f;
    p->flowflags |= FLOW_PKT_TOCLIENT;
    p->flowflags |= FLOW_PKT_ESTABLISHED;
    p->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    f.alproto = ALPROTO_HTTP1;

    StreamTcpInitConfig(true);

    de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert http any any -> any any "
                               "(msg:\"http server body test\"; "
                               "file_data; content:\"message\"; "
                               "sid:1;)");
    FAIL_IF_NULL(de_ctx->sig_list);

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_HTTP1,
            STREAM_TOSERVER | STREAM_START | STREAM_EOF, http_buf, http_len);
    FAIL_IF(r != 0);
    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_HTTP1,
            STREAM_TOCLIENT | STREAM_START | STREAM_EOF, http_buf2, http_len2);
    FAIL_IF(r != 0);
    http_state = f.alstate;
    FAIL_IF_NULL(http_state);

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);

    FAIL_IF(!(PacketAlertCheck(p, 1)));

    AppLayerParserThreadCtxFree(alp_tctx);
    DetectEngineCtxFree(de_ctx);

    StreamTcpFreeConfig(true);
    FLOW_DESTROY(&f);
    UTHFreePackets(&p, 1);
    PASS;
}

/**
 *\test Test that the http_server_body content matches against a http request
 *      which holds the content.
 */
static int DetectHttpServerBodyFileDataTest02(void)
{
    TcpSession ssn;
    Packet *p1 = NULL;
    Packet *p2 = NULL;
    ThreadVars th_v;
    DetectEngineCtx *de_ctx = NULL;
    DetectEngineThreadCtx *det_ctx = NULL;
    HtpState *http_state = NULL;
    Flow f;
    uint8_t http_buf1[] =
        "GET /index.html HTTP/1.0\r\n"
        "Host: www.openinfosecfoundation.org\r\n"
        "User-Agent: Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.1.7) Gecko/20091221 Firefox/3.5.7\r\n"
        "\r\n";
    uint32_t http_len1 = sizeof(http_buf1) - 1;
    uint8_t http_buf2[] =
        "HTTP/1.0 200 ok\r\n"
        "Content-Type: text/html\r\n"
        "Content-Length: 14\r\n"
        "\r\n";
    uint32_t http_len2 = sizeof(http_buf2) - 1;
    uint8_t http_buf3[] =
        "message";
    uint32_t http_len3 = sizeof(http_buf3) - 1;
    int result = 0;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&th_v, 0, sizeof(th_v));
    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    p1 = UTHBuildPacket(NULL, 0, IPPROTO_TCP);
    p2 = UTHBuildPacket(NULL, 0, IPPROTO_TCP);

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;
    f.flags |= FLOW_IPV4;

    p1->flow = &f;
    p1->flowflags |= FLOW_PKT_TOCLIENT;
    p1->flowflags |= FLOW_PKT_ESTABLISHED;
    p1->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;

    p2->flow = &f;
    p2->flowflags |= FLOW_PKT_TOCLIENT;
    p2->flowflags |= FLOW_PKT_ESTABLISHED;
    p2->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    f.alproto = ALPROTO_HTTP1;

    StreamTcpInitConfig(true);

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert http any any -> any any "
                               "(msg:\"http server body test\"; "
                               "file_data; content:\"message\"; "
                               "sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER | STREAM_START,
            http_buf1, http_len1);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        goto end;
    }

    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOCLIENT | STREAM_START,
            http_buf2, http_len2);
    if (r != 0) {
        printf("toserver chunk 2 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        goto end;
    }

    http_state = f.alstate;
    if (http_state == NULL) {
        printf("no http state: ");
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p1);

    if (PacketAlertCheck(p1, 1)) {
        printf("sid 1 matched on p1 but should have: ");
        goto end;
    }

    r = AppLayerParserParse(
            NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOCLIENT | STREAM_EOF, http_buf3, http_len3);
    if (r != 0) {
        printf("toserver chunk 3 returned %" PRId32 ", expected 0: ", r);
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p2);
    if (!(PacketAlertCheck(p2, 1))) {
        printf("sid 1 didn't match on p2 but should have: ");
        goto end;
    }

    result = 1;
end:
    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);

    StreamTcpFreeConfig(true);
    FLOW_DESTROY(&f);
    UTHFreePackets(&p1, 1);
    UTHFreePackets(&p2, 1);
    return result;
}

/**
 *\test Test that the http_server_body content matches against a http request
 *      which holds the content.
 */
static int DetectHttpServerBodyFileDataTest03(void)
{
    TcpSession ssn;
    Packet *p1 = NULL;
    Packet *p2 = NULL;
    ThreadVars th_v;
    DetectEngineCtx *de_ctx = NULL;
    DetectEngineThreadCtx *det_ctx = NULL;
    HtpState *http_state = NULL;
    Flow f;
    uint8_t http_buf1[] =
        "GET /index.html HTTP/1.0\r\n"
        "Host: www.openinfosecfoundation.org\r\n"
        "User-Agent: Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.1.7) Gecko/20091221 Firefox/3.5.7\r\n"
        "\r\n";
    uint32_t http_len1 = sizeof(http_buf1) - 1;
    uint8_t http_buf2[] =
        "HTTP/1.0 200 ok\r\n"
        "Content-Type: text/html\r\n"
        "Content-Length: 14\r\n"
        "\r\n"
        "bigmes";
    uint32_t http_len2 = sizeof(http_buf2) - 1;
    uint8_t http_buf3[] =
        "sage4u!!";
    uint32_t http_len3 = sizeof(http_buf3) - 1;
    int result = 0;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&th_v, 0, sizeof(th_v));
    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    p1 = UTHBuildPacket(NULL, 0, IPPROTO_TCP);
    p2 = UTHBuildPacket(NULL, 0, IPPROTO_TCP);

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;
    f.flags |= FLOW_IPV4;

    p1->flow = &f;
    p1->flowflags |= FLOW_PKT_TOCLIENT;
    p1->flowflags |= FLOW_PKT_ESTABLISHED;
    p1->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    p2->flow = &f;
    p2->flowflags |= FLOW_PKT_TOCLIENT;
    p2->flowflags |= FLOW_PKT_ESTABLISHED;
    p2->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    f.alproto = ALPROTO_HTTP1;

    StreamTcpInitConfig(true);

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert http any any -> any any "
                               "(msg:\"http client body test\"; "
                               "file_data; content:\"message\"; "
                               "sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER | STREAM_START,
            http_buf1, http_len1);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        goto end;
    }

    http_state = f.alstate;
    if (http_state == NULL) {
        printf("no http state: ");
        result = 0;
        goto end;
    }

    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOCLIENT | STREAM_START,
            http_buf2, http_len2);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p1);

    if ((PacketAlertCheck(p1, 1))) {
        printf("sid 1 matched but shouldn't have: ");
        goto end;
    }

    r = AppLayerParserParse(
            NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOCLIENT | STREAM_EOF, http_buf3, http_len3);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        goto end;
    }


    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p2);

    if (!(PacketAlertCheck(p2, 1))) {
        printf("sid 1 didn't match but should have: ");
        goto end;
    }

    result = 1;
end:
    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);

    StreamTcpFreeConfig(true);
    FLOW_DESTROY(&f);
    UTHFreePackets(&p1, 1);
    UTHFreePackets(&p2, 1);
    return result;
}

/**
 *\test Test that the http_server_body content matches against a http request
 *      which holds the content.
 */
static int DetectHttpServerBodyFileDataTest04(void)
{
    TcpSession ssn;
    Packet *p1 = NULL;
    Packet *p2 = NULL;
    ThreadVars th_v;
    DetectEngineCtx *de_ctx = NULL;
    DetectEngineThreadCtx *det_ctx = NULL;
    HtpState *http_state = NULL;
    Flow f;
    uint8_t http_buf1[] =
        "GET /index.html HTTP/1.0\r\n"
        "Host: www.openinfosecfoundation.org\r\n"
        "User-Agent: Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.1.7) Gecko/20091221 Firefox/3.5.7\r\n"
        "\r\n";
    uint32_t http_len1 = sizeof(http_buf1) - 1;
    uint8_t http_buf2[] =
        "HTTP/1.0 200 ok\r\n"
        "Content-Type: text/html\r\n"
        "Content-Length: 14\r\n"
        "\r\n"
        "bigmes";
    uint32_t http_len2 = sizeof(http_buf2) - 1;
    uint8_t http_buf3[] =
        "sag";
    uint32_t http_len3 = sizeof(http_buf3) - 1;
    uint8_t http_buf4[] =
        "e4u!!";
    uint32_t http_len4 = sizeof(http_buf4) - 1;
    int result = 0;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&th_v, 0, sizeof(th_v));
    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    p1 = UTHBuildPacket(NULL, 0, IPPROTO_TCP);
    p2 = UTHBuildPacket(NULL, 0, IPPROTO_TCP);

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;
    f.flags |= FLOW_IPV4;

    p1->flow = &f;
    p1->flowflags |= FLOW_PKT_TOCLIENT;
    p1->flowflags |= FLOW_PKT_ESTABLISHED;
    p1->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    p2->flow = &f;
    p2->flowflags |= FLOW_PKT_TOCLIENT;
    p2->flowflags |= FLOW_PKT_ESTABLISHED;
    p2->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    f.alproto = ALPROTO_HTTP1;

    StreamTcpInitConfig(true);

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert http any any -> any any "
                               "(msg:\"http client body test\"; "
                               "file_data; content:\"message\"; "
                               "sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER | STREAM_START,
            http_buf1, http_len1);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        goto end;
    }

    http_state = f.alstate;
    if (http_state == NULL) {
        printf("no http state: ");
        result = 0;
        goto end;
    }

    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOCLIENT | STREAM_START,
            http_buf2, http_len2);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p1);

    if ((PacketAlertCheck(p1, 1))) {
        printf("sid 1 matched but shouldn't have: ");
        goto end;
    }

    r = AppLayerParserParse(
            NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOCLIENT, http_buf3, http_len3);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        goto end;
    }

    r = AppLayerParserParse(
            NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOCLIENT | STREAM_EOF, http_buf4, http_len4);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p2);

    if (!(PacketAlertCheck(p2, 1))) {
        printf("sid 1 didn't match but should have: ");
        goto end;
    }

    result = 1;
end:
    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);

    StreamTcpFreeConfig(true);
    FLOW_DESTROY(&f);
    UTHFreePackets(&p1, 1);
    UTHFreePackets(&p2, 1);
    return result;
}

/**
 *\test Test that the http_server_body content matches against a http request
 *      which holds the content. Case insensitve.
 */
static int DetectHttpServerBodyFileDataTest05(void)
{
    TcpSession ssn;
    Packet *p1 = NULL;
    Packet *p2 = NULL;
    ThreadVars th_v;
    DetectEngineCtx *de_ctx = NULL;
    DetectEngineThreadCtx *det_ctx = NULL;
    HtpState *http_state = NULL;
    Flow f;
    uint8_t http_buf1[] =
        "GET /index.html HTTP/1.0\r\n"
        "Host: www.openinfosecfoundation.org\r\n"
        "User-Agent: Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.1.7) Gecko/20091221 Firefox/3.5.7\r\n"
        "\r\n";
    uint32_t http_len1 = sizeof(http_buf1) - 1;
    uint8_t http_buf2[] =
        "HTTP/1.0 200 ok\r\n"
        "Content-Type: text/html\r\n"
        "Content-Length: 14\r\n"
        "\r\n"
        "bigmes";
    uint32_t http_len2 = sizeof(http_buf2) - 1;
    uint8_t http_buf3[] =
        "sag";
    uint32_t http_len3 = sizeof(http_buf3) - 1;
    uint8_t http_buf4[] =
        "e4u!!";
    uint32_t http_len4 = sizeof(http_buf4) - 1;
    int result = 0;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&th_v, 0, sizeof(th_v));
    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    p1 = UTHBuildPacket(NULL, 0, IPPROTO_TCP);
    p2 = UTHBuildPacket(NULL, 0, IPPROTO_TCP);

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;
    f.flags |= FLOW_IPV4;

    p1->flow = &f;
    p1->flowflags |= FLOW_PKT_TOCLIENT;
    p1->flowflags |= FLOW_PKT_ESTABLISHED;
    p1->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    p2->flow = &f;
    p2->flowflags |= FLOW_PKT_TOCLIENT;
    p2->flowflags |= FLOW_PKT_ESTABLISHED;
    p2->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    f.alproto = ALPROTO_HTTP1;

    StreamTcpInitConfig(true);

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert http any any -> any any "
                               "(msg:\"http client body test\"; "
                               "file_data; content:\"MeSSaGE\"; nocase; "
                               "sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER | STREAM_START,
            http_buf1, http_len1);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        goto end;
    }

    http_state = f.alstate;
    if (http_state == NULL) {
        printf("no http state: ");
        result = 0;
        goto end;
    }

    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOCLIENT | STREAM_START,
            http_buf2, http_len2);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p1);

    if ((PacketAlertCheck(p1, 1))) {
        printf("sid 1 matched but shouldn't have: ");
        goto end;
    }

    r = AppLayerParserParse(
            NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOCLIENT, http_buf3, http_len3);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        goto end;
    }

    r = AppLayerParserParse(
            NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOCLIENT | STREAM_EOF, http_buf4, http_len4);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p2);

    if (!(PacketAlertCheck(p2, 1))) {
        printf("sid 1 didn't match but should have: ");
        goto end;
    }

    result = 1;
end:
    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);

    StreamTcpFreeConfig(true);
    FLOW_DESTROY(&f);
    UTHFreePackets(&p1, 1);
    UTHFreePackets(&p2, 1);
    return result;
}

/**
 *\test Test that the http_server_body content matches against a http request
 *      which holds the content. Negated match.
 */
static int DetectHttpServerBodyFileDataTest06(void)
{
    TcpSession ssn;
    Packet *p1 = NULL;
    Packet *p2 = NULL;
    ThreadVars th_v;
    DetectEngineCtx *de_ctx = NULL;
    DetectEngineThreadCtx *det_ctx = NULL;
    HtpState *http_state = NULL;
    Flow f;
    uint8_t http_buf1[] =
        "GET /index.html HTTP/1.0\r\n"
        "Host: www.openinfosecfoundation.org\r\n"
        "User-Agent: Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.1.7) Gecko/20091221 Firefox/3.5.7\r\n"
        "\r\n";
    uint32_t http_len1 = sizeof(http_buf1) - 1;
    uint8_t http_buf2[] =
        "HTTP/1.0 200 ok\r\n"
        "Content-Type: text/html\r\n"
        "Content-Length: 14\r\n"
        "\r\n";
    uint32_t http_len2 = sizeof(http_buf2) - 1;
    uint8_t http_buf3[] =
        "bigmessage4u!!";
    uint32_t http_len3 = sizeof(http_buf3) - 1;
    int result = 0;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&th_v, 0, sizeof(th_v));
    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    p1 = UTHBuildPacket(NULL, 0, IPPROTO_TCP);
    p2 = UTHBuildPacket(NULL, 0, IPPROTO_TCP);

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;
    f.flags |= FLOW_IPV4;

    p1->flow = &f;
    p1->flowflags |= FLOW_PKT_TOCLIENT;
    p1->flowflags |= FLOW_PKT_ESTABLISHED;
    p1->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    p2->flow = &f;
    p2->flowflags |= FLOW_PKT_TOCLIENT;
    p2->flowflags |= FLOW_PKT_ESTABLISHED;
    p2->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    f.alproto = ALPROTO_HTTP1;

    StreamTcpInitConfig(true);

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert http any any -> any any "
                               "(msg:\"http file_data test\"; "
                               "file_data; content:!\"MaSSaGE\"; nocase; "
                               "sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER | STREAM_START,
            http_buf1, http_len1);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        goto end;
    }

    http_state = f.alstate;
    if (http_state == NULL) {
        printf("no http state: ");
        result = 0;
        goto end;
    }

    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOCLIENT | STREAM_START,
            http_buf2, http_len2);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p1);

    if (PacketAlertCheck(p1, 1)) {
        printf("sid 1 matched but shouldn't have (p1): ");
        goto end;
    }

    r = AppLayerParserParse(
            NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOCLIENT | STREAM_EOF, http_buf3, http_len3);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p2);

    if (!(PacketAlertCheck(p2, 1))) {
        printf("sid 1 didn't match but should have (p2): ");
        goto end;
    }

    result = 1;
end:
    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);

    StreamTcpFreeConfig(true);
    FLOW_DESTROY(&f);
    UTHFreePackets(&p1, 1);
    UTHFreePackets(&p2, 1);
    return result;
}

/**
 *\test Test that the http_server_body content matches against a http request
 *      which holds the content. Negated match.
 */
static int DetectHttpServerBodyFileDataTest07(void)
{
    TcpSession ssn;
    Packet *p1 = NULL;
    Packet *p2 = NULL;
    ThreadVars th_v;
    DetectEngineCtx *de_ctx = NULL;
    DetectEngineThreadCtx *det_ctx = NULL;
    HtpState *http_state = NULL;
    Flow f;
    uint8_t http_buf1[] =
        "GET /index.html HTTP/1.0\r\n"
        "Host: www.openinfosecfoundation.org\r\n"
        "User-Agent: Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.1.7) Gecko/20091221 Firefox/3.5.7\r\n"
        "\r\n";
    uint32_t http_len1 = sizeof(http_buf1) - 1;
    uint8_t http_buf2[] =
        "HTTP/1.0 200 ok\r\n"
        "Content-Type: text/html\r\n"
        "Content-Length: 14\r\n"
        "\r\n";
    uint32_t http_len2 = sizeof(http_buf2) - 1;
    uint8_t http_buf3[] =
        "bigmessage4u!!";
    uint32_t http_len3 = sizeof(http_buf3) - 1;
    int result = 0;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&th_v, 0, sizeof(th_v));
    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    p1 = UTHBuildPacket(NULL, 0, IPPROTO_TCP);
    p2 = UTHBuildPacket(NULL, 0, IPPROTO_TCP);

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;
    f.flags |= FLOW_IPV4;

    p1->flow = &f;
    p1->flowflags |= FLOW_PKT_TOCLIENT;
    p1->flowflags |= FLOW_PKT_ESTABLISHED;
    p1->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    p2->flow = &f;
    p2->flowflags |= FLOW_PKT_TOCLIENT;
    p2->flowflags |= FLOW_PKT_ESTABLISHED;
    p2->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    f.alproto = ALPROTO_HTTP1;

    StreamTcpInitConfig(true);

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert http any any -> any any "
                               "(msg:\"http file_data test\"; "
                               "file_data; content:!\"MeSSaGE\"; nocase; "
                               "sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER | STREAM_START,
            http_buf1, http_len1);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        goto end;
    }

    http_state = f.alstate;
    if (http_state == NULL) {
        printf("no http state: ");
        result = 0;
        goto end;
    }

    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOCLIENT | STREAM_START,
            http_buf2, http_len2);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p1);

    if (PacketAlertCheck(p1, 1)) {
        printf("sid 1 matched but shouldn't have (p1): ");
        goto end;
    }

    r = AppLayerParserParse(
            NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOCLIENT | STREAM_EOF, http_buf3, http_len3);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p2);

    if (PacketAlertCheck(p2, 1)) {
        printf("sid 1 matched but shouldn't have (p2): ");
        goto end;
    }

    result = 1;
end:
    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);

    StreamTcpFreeConfig(true);
    FLOW_DESTROY(&f);
    UTHFreePackets(&p1, 1);
    UTHFreePackets(&p2, 1);
    return result;
}

static int DetectHttpServerBodyFileDataTest08(void)
{
    TcpSession ssn;
    Packet *p = NULL;
    ThreadVars th_v;
    DetectEngineCtx *de_ctx = NULL;
    DetectEngineThreadCtx *det_ctx = NULL;
    HtpState *http_state = NULL;
    Flow f;
    uint8_t http_buf[] =
        "GET /index.html HTTP/1.0\r\n"
        "Host: www.openinfosecfoundation.org\r\n"
        "User-Agent: Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.1.7) Gecko/20091221 Firefox/3.5.7\r\n"
        "\r\n";
    uint32_t http_len = sizeof(http_buf) - 1;
    uint8_t http_buf2[] =
        "HTTP/1.0 200 ok\r\n"
        "Content-Type: text/html\r\n"
        "Content-Length: 55\r\n"
        "\r\n"
        "longbufferabcdefghijklmnopqrstuvwxyz0123456789bufferend";
    uint32_t http_len2 = sizeof(http_buf2) - 1;
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

    p->flow = &f;
    p->flowflags |= FLOW_PKT_TOCLIENT;
    p->flowflags |= FLOW_PKT_ESTABLISHED;
    p->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    f.alproto = ALPROTO_HTTP1;

    StreamTcpInitConfig(true);

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert http any any -> any any "
                               "(msg:\"http server body test\"; "
                               "file_data; content:\"longbufferabcdefghijklmnopqrstuvwxyz0123456789bufferend\"; "
                               "sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_HTTP1,
            STREAM_TOSERVER | STREAM_START | STREAM_EOF, http_buf, http_len);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        goto end;
    }
    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_HTTP1,
            STREAM_TOCLIENT | STREAM_START | STREAM_EOF, http_buf2, http_len2);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        goto end;
    }

    http_state = f.alstate;
    if (http_state == NULL) {
        printf("no http state: \n");
        result = 0;
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);

    if (!(PacketAlertCheck(p, 1))) {
        printf("sid 1 didn't match but should have: ");
        goto end;
    }

    result = 1;
end:
    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);

    StreamTcpFreeConfig(true);
    FLOW_DESTROY(&f);
    UTHFreePackets(&p, 1);
    return result;
}

/** \test multiple http transactions and body chunks of request handling */
static int DetectHttpServerBodyFileDataTest09(void)
{
    int result = 0;
    Signature *s = NULL;
    DetectEngineThreadCtx *det_ctx = NULL;
    ThreadVars th_v;
    Flow f;
    TcpSession ssn;
    Packet *p = NULL;
    uint8_t httpbuf1[] = "GET /index1.html HTTP/1.1\r\n"
        "User-Agent: Mozilla/1.0\r\n"
        "Host: www.openinfosecfoundation.org\r\n"
        "Connection: keep-alive\r\n"
        "Cookie: dummy1\r\n\r\n";
    uint32_t httplen1 = sizeof(httpbuf1) - 1; /* minus the \0 */
    uint8_t httpbuf2[] = "HTTP/1.1 200 ok\r\n"
        "Content-Type: text/html\r\n"
        "Content-Length: 3\r\n"
        "\r\n"
        "one";
    uint32_t httplen2 = sizeof(httpbuf2) - 1; /* minus the \0 */
    uint8_t httpbuf3[] = "GET /index2.html HTTP/1.1\r\n"
        "User-Agent: Firefox/1.0\r\n"
        "Host: www.openinfosecfoundation.org\r\n"
        "Connection: keep-alive\r\n"
        "Cookie: dummy2\r\n\r\n";
    uint32_t httplen3 = sizeof(httpbuf3) - 1; /* minus the \0 */
    uint8_t httpbuf4[] = "HTTP/1.1 200 ok\r\n"
        "Content-Type: text/html\r\n"
        "Content-Length: 3\r\n"
        "\r\n"
        "two";
    uint32_t httplen4 = sizeof(httpbuf4) - 1; /* minus the \0 */
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&th_v, 0, sizeof(th_v));
    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    p = UTHBuildPacket(NULL, 0, IPPROTO_TCP);

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;
    f.flags |= FLOW_IPV4;

    p->flow = &f;
    p->flowflags |= FLOW_PKT_TOCLIENT;
    p->flowflags |= FLOW_PKT_ESTABLISHED;
    p->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    f.alproto = ALPROTO_HTTP1;

    StreamTcpInitConfig(true);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }

    de_ctx->flags |= DE_QUIET;

    s = DetectEngineAppendSig(de_ctx, "alert tcp any any -> any any (flow:established,to_client; file_data; content:\"one\"; sid:1; rev:1;)");
    if (s == NULL) {
        printf("sig parse failed: ");
        goto end;
    }
    s = DetectEngineAppendSig(de_ctx, "alert tcp any any -> any any (flow:established,to_client; file_data; content:\"two\"; sid:2; rev:1;)");
    if (s == NULL) {
        printf("sig2 parse failed: ");
        goto end;
    }

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParserParse(
            NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER | STREAM_START, httpbuf1, httplen1);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        goto end;
    }

    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOCLIENT, httpbuf2, httplen2);
    if (r != 0) {
        printf("toserver chunk 2 returned %" PRId32 ", expected 0: ", r);
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    if (!(PacketAlertCheck(p, 1))) {
        printf("sig 1 didn't alert (tx 1): ");
        goto end;
    }
    p->alerts.cnt = 0;

    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER, httpbuf3, httplen3);
    if (r != 0) {
        printf("toserver chunk 3 returned %" PRId32 ", expected 0: ", r);
        goto end;
    }

    r = AppLayerParserParse(
            NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOCLIENT | STREAM_EOF, httpbuf4, httplen4);
    if (r != 0) {
        printf("toserver chunk 4 returned %" PRId32 ", expected 0: ", r);
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    if ((PacketAlertCheck(p, 1))) {
        printf("sig 1 alerted (tx 2): ");
        goto end;
    }
    if (!(PacketAlertCheck(p, 2))) {
        printf("sig 2 didn't alert (tx 2): ");
        goto end;
    }
    p->alerts.cnt = 0;

    HtpState *htp_state = f.alstate;
    if (htp_state == NULL) {
        printf("no http state: ");
        goto end;
    }

    if (AppLayerParserGetTxCnt(&f, htp_state) != 2) {
        printf("The http app layer doesn't have 2 transactions, but it should: ");
        goto end;
    }

    result = 1;
end:
    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
    if (det_ctx != NULL) {
        DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    }
    if (de_ctx != NULL) {
        DetectEngineCtxFree(de_ctx);
    }

    StreamTcpFreeConfig(true);
    FLOW_DESTROY(&f);
    UTHFreePacket(p);
    return result;
}

static int DetectHttpServerBodyFileDataTest10(void)
{
    int result = 0;
    Signature *s = NULL;
    DetectEngineThreadCtx *det_ctx = NULL;
    ThreadVars th_v;
    Flow f;
    TcpSession ssn;
    Packet *p = NULL;
    uint8_t httpbuf1[] = "GET /index1.html HTTP/1.1\r\n"
        "User-Agent: Mozilla/1.0\r\n"
        "Host: www.openinfosecfoundation.org\r\n"
        "Connection: keep-alive\r\n"
        "Cookie: dummy1\r\n\r\n";
    uint32_t httplen1 = sizeof(httpbuf1) - 1; /* minus the \0 */
    uint8_t httpbuf2[] = "HTTP/1.1 200 ok\r\n"
        "Content-Type: text/html\r\n"
        "Content-Length: 3\r\n"
        "\r\n"
        "one";
    uint32_t httplen2 = sizeof(httpbuf2) - 1; /* minus the \0 */
    uint8_t httpbuf3[] = "GET /index2.html HTTP/1.1\r\n"
        "User-Agent: Firefox/1.0\r\n"
        "Host: www.openinfosecfoundation.org\r\n"
        "Connection: keep-alive\r\n"
        "Cookie: dummy2\r\n\r\n";
    uint32_t httplen3 = sizeof(httpbuf3) - 1; /* minus the \0 */
    uint8_t httpbuf4[] = "HTTP/1.1 200 ok\r\n"
        "Content-Type: text/html\r\n"
        "Content-Length: 3\r\n"
        "\r\n"
        "two";
    uint32_t httplen4 = sizeof(httpbuf4) - 1; /* minus the \0 */
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&th_v, 0, sizeof(th_v));
    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    p = UTHBuildPacket(NULL, 0, IPPROTO_TCP);

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;
    f.flags |= FLOW_IPV4;

    p->flow = &f;
    p->flowflags |= FLOW_PKT_TOCLIENT;
    p->flowflags |= FLOW_PKT_ESTABLISHED;
    p->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    f.alproto = ALPROTO_HTTP1;

    StreamTcpInitConfig(true);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }

    de_ctx->flags |= DE_QUIET;

    s = DetectEngineAppendSig(de_ctx, "alert tcp any any -> any any (flow:established,to_client; file_data; content:\"one\";  sid:1; rev:1;)");
    if (s == NULL) {
        printf("sig parse failed: ");
        goto end;
    }
    s = DetectEngineAppendSig(de_ctx, "alert tcp any any -> any any (flow:established,to_client; file_data; content:\"two\"; sid:2; rev:1;)");
    if (s == NULL) {
        printf("sig2 parse failed: ");
        goto end;
    }

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParserParse(
            NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER | STREAM_START, httpbuf1, httplen1);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        goto end;
    }

    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOCLIENT, httpbuf2, httplen2);
    if (r != 0) {
        printf("toserver chunk 2 returned %" PRId32 ", expected 0: ", r);
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    if (!(PacketAlertCheck(p, 1))) {
        printf("sig 1 didn't alert (tx 1): ");
        goto end;
    }
    p->alerts.cnt = 0;

    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER, httpbuf3, httplen3);
    if (r != 0) {
        printf("toserver chunk 3 returned %" PRId32 ", expected 0: ", r);
        goto end;
    }

    r = AppLayerParserParse(
            NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOCLIENT | STREAM_EOF, httpbuf4, httplen4);
    if (r != 0) {
        printf("toserver chunk 4 returned %" PRId32 ", expected 0: ", r);
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    if ((PacketAlertCheck(p, 1))) {
        printf("sig 1 alerted (tx 2): ");
        goto end;
    }
    if (!(PacketAlertCheck(p, 2))) {
        printf("sig 2 didn't alert (tx 2): ");
        goto end;
    }
    p->alerts.cnt = 0;

    HtpState *htp_state = f.alstate;
    if (htp_state == NULL) {
        printf("no http state: ");
        goto end;
    }

    if (AppLayerParserGetTxCnt(&f, htp_state) != 2) {
        printf("The http app layer doesn't have 2 transactions, but it should: ");
        goto end;
    }

    result = 1;
end:
    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
    if (det_ctx != NULL) {
        DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    }
    if (de_ctx != NULL) {
        DetectEngineCtxFree(de_ctx);
    }

    StreamTcpFreeConfig(true);
    FLOW_DESTROY(&f);
    UTHFreePacket(p);
    return result;
}

void DetectHttpServerBodyRegisterTests(void)
{
    UtRegisterTest("DetectHttpServerBodyParserTest01", DetectHttpServerBodyParserTest01);
    UtRegisterTest("DetectHttpServerBodyParserTest02", DetectHttpServerBodyParserTest02);

    UtRegisterTest("DetectHttpServerBodyTest01", DetectHttpServerBodyTest01);
    UtRegisterTest("DetectHttpServerBodyTest02", DetectHttpServerBodyTest02);
    UtRegisterTest("DetectHttpServerBodyTest03", DetectHttpServerBodyTest03);
    UtRegisterTest("DetectHttpServerBodyTest04", DetectHttpServerBodyTest04);
    UtRegisterTest("DetectHttpServerBodyTest05", DetectHttpServerBodyTest05);
    UtRegisterTest("DetectHttpServerBodyTest06", DetectHttpServerBodyTest06);
    UtRegisterTest("DetectHttpServerBodyTest07", DetectHttpServerBodyTest07);
    UtRegisterTest("DetectHttpServerBodyTest08", DetectHttpServerBodyTest08);
    UtRegisterTest("DetectHttpServerBodyTest09", DetectHttpServerBodyTest09);
    UtRegisterTest("DetectHttpServerBodyTest10", DetectHttpServerBodyTest10);
    UtRegisterTest("DetectHttpServerBodyTest11", DetectHttpServerBodyTest11);
    UtRegisterTest("DetectHttpServerBodyTest12", DetectHttpServerBodyTest12);
    UtRegisterTest("DetectHttpServerBodyTest13", DetectHttpServerBodyTest13);
    UtRegisterTest("DetectHttpServerBodyTest14", DetectHttpServerBodyTest14);
    UtRegisterTest("DetectHttpServerBodyTest15", DetectHttpServerBodyTest15);
    UtRegisterTest("DetectHttpServerBodyTest22", DetectHttpServerBodyTest22);
    UtRegisterTest("DetectHttpServerBodyTest23", DetectHttpServerBodyTest23);
    UtRegisterTest("DetectHttpServerBodyTest24", DetectHttpServerBodyTest24);
    UtRegisterTest("DetectHttpServerBodyTest25", DetectHttpServerBodyTest25);
    UtRegisterTest("DetectHttpServerBodyTest26", DetectHttpServerBodyTest26);
    UtRegisterTest("DetectHttpServerBodyTest27", DetectHttpServerBodyTest27);
    UtRegisterTest("DetectHttpServerBodyTest28", DetectHttpServerBodyTest28);
    UtRegisterTest("DetectHttpServerBodyTest29", DetectHttpServerBodyTest29);
    UtRegisterTest("DetectHttpServerBodyTest30", DetectHttpServerBodyTest30);
    UtRegisterTest("DetectHttpServerBodyTest31", DetectHttpServerBodyTest31);
    UtRegisterTest("DetectHttpServerBodyTest32", DetectHttpServerBodyTest32);
    UtRegisterTest("DetectHttpServerBodyTest33", DetectHttpServerBodyTest33);
    UtRegisterTest("DetectHttpServerBodyTest34", DetectHttpServerBodyTest34);
    UtRegisterTest("DetectHttpServerBodyTest35", DetectHttpServerBodyTest35);
    UtRegisterTest("DetectHttpServerBodyTest36", DetectHttpServerBodyTest36);

    UtRegisterTest("DetectHttpServerBodyFileDataTest01",
                   DetectHttpServerBodyFileDataTest01);
    UtRegisterTest("DetectHttpServerBodyFileDataTest02",
                   DetectHttpServerBodyFileDataTest02);
    UtRegisterTest("DetectHttpServerBodyFileDataTest03",
                   DetectHttpServerBodyFileDataTest03);
    UtRegisterTest("DetectHttpServerBodyFileDataTest04",
                   DetectHttpServerBodyFileDataTest04);
    UtRegisterTest("DetectHttpServerBodyFileDataTest05",
                   DetectHttpServerBodyFileDataTest05);
    UtRegisterTest("DetectHttpServerBodyFileDataTest06",
                   DetectHttpServerBodyFileDataTest06);
    UtRegisterTest("DetectHttpServerBodyFileDataTest07",
                   DetectHttpServerBodyFileDataTest07);
    UtRegisterTest("DetectHttpServerBodyFileDataTest08",
                   DetectHttpServerBodyFileDataTest08);
    UtRegisterTest("DetectHttpServerBodyFileDataTest09",
                   DetectHttpServerBodyFileDataTest09);
    UtRegisterTest("DetectHttpServerBodyFileDataTest10",
                   DetectHttpServerBodyFileDataTest10);

    UtRegisterTest("DetectEngineHttpServerBodyTest01",
                   DetectEngineHttpServerBodyTest01);
    UtRegisterTest("DetectEngineHttpServerBodyTest02",
                   DetectEngineHttpServerBodyTest02);
    UtRegisterTest("DetectEngineHttpServerBodyTest03",
                   DetectEngineHttpServerBodyTest03);
    UtRegisterTest("DetectEngineHttpServerBodyTest04",
                   DetectEngineHttpServerBodyTest04);
    UtRegisterTest("DetectEngineHttpServerBodyTest05",
                   DetectEngineHttpServerBodyTest05);
    UtRegisterTest("DetectEngineHttpServerBodyTest06",
                   DetectEngineHttpServerBodyTest06);
    UtRegisterTest("DetectEngineHttpServerBodyTest07",
                   DetectEngineHttpServerBodyTest07);
    UtRegisterTest("DetectEngineHttpServerBodyTest08",
                   DetectEngineHttpServerBodyTest08);
    UtRegisterTest("DetectEngineHttpServerBodyTest09",
                   DetectEngineHttpServerBodyTest09);
    UtRegisterTest("DetectEngineHttpServerBodyTest10",
                   DetectEngineHttpServerBodyTest10);
    UtRegisterTest("DetectEngineHttpServerBodyTest11",
                   DetectEngineHttpServerBodyTest11);
    UtRegisterTest("DetectEngineHttpServerBodyTest12",
                   DetectEngineHttpServerBodyTest12);
    UtRegisterTest("DetectEngineHttpServerBodyTest13",
                   DetectEngineHttpServerBodyTest13);
    UtRegisterTest("DetectEngineHttpServerBodyTest14",
                   DetectEngineHttpServerBodyTest14);
    UtRegisterTest("DetectEngineHttpServerBodyTest15",
                   DetectEngineHttpServerBodyTest15);
    UtRegisterTest("DetectEngineHttpServerBodyTest16",
                   DetectEngineHttpServerBodyTest16);
    UtRegisterTest("DetectEngineHttpServerBodyTest17",
                   DetectEngineHttpServerBodyTest17);
    UtRegisterTest("DetectEngineHttpServerBodyTest18",
                   DetectEngineHttpServerBodyTest18);
    UtRegisterTest("DetectEngineHttpServerBodyTest19",
                   DetectEngineHttpServerBodyTest19);
    UtRegisterTest("DetectEngineHttpServerBodyTest20",
                   DetectEngineHttpServerBodyTest20);
    UtRegisterTest("DetectEngineHttpServerBodyTest21",
                   DetectEngineHttpServerBodyTest21);
    UtRegisterTest("DetectEngineHttpServerBodyTest22",
                   DetectEngineHttpServerBodyTest22);

    UtRegisterTest("DetectEngineHttpServerBodyFileDataTest01",
                   DetectEngineHttpServerBodyFileDataTest01);
    UtRegisterTest("DetectEngineHttpServerBodyFileDataTest02",
                   DetectEngineHttpServerBodyFileDataTest02);
    UtRegisterTest("DetectEngineHttpServerBodyFileDataTest03",
                   DetectEngineHttpServerBodyFileDataTest03);
    UtRegisterTest("DetectEngineHttpServerBodyFileDataTest04",
                   DetectEngineHttpServerBodyFileDataTest04);
    UtRegisterTest("DetectEngineHttpServerBodyFileDataTest05",
                   DetectEngineHttpServerBodyFileDataTest05);
    UtRegisterTest("DetectEngineHttpServerBodyFileDataTest06",
                   DetectEngineHttpServerBodyFileDataTest06);
    UtRegisterTest("DetectEngineHttpServerBodyFileDataTest07",
                   DetectEngineHttpServerBodyFileDataTest07);
    UtRegisterTest("DetectEngineHttpServerBodyFileDataTest08",
                   DetectEngineHttpServerBodyFileDataTest08);
    UtRegisterTest("DetectEngineHttpServerBodyFileDataTest09",
                   DetectEngineHttpServerBodyFileDataTest09);
    UtRegisterTest("DetectEngineHttpServerBodyFileDataTest10",
                   DetectEngineHttpServerBodyFileDataTest10);
    UtRegisterTest("DetectEngineHttpServerBodyFileDataTest11",
                   DetectEngineHttpServerBodyFileDataTest11);
    UtRegisterTest("DetectEngineHttpServerBodyFileDataTest12",
                   DetectEngineHttpServerBodyFileDataTest12);
    UtRegisterTest("DetectEngineHttpServerBodyFileDataTest13",
                   DetectEngineHttpServerBodyFileDataTest13);
    UtRegisterTest("DetectEngineHttpServerBodyFileDataTest14",
                   DetectEngineHttpServerBodyFileDataTest14);
    UtRegisterTest("DetectEngineHttpServerBodyFileDataTest15",
                   DetectEngineHttpServerBodyFileDataTest15);
    UtRegisterTest("DetectEngineHttpServerBodyFileDataTest16",
                   DetectEngineHttpServerBodyFileDataTest16);
    UtRegisterTest("DetectEngineHttpServerBodyFileDataTest17",
                   DetectEngineHttpServerBodyFileDataTest17);
    UtRegisterTest("DetectEngineHttpServerBodyFileDataTest18",
                   DetectEngineHttpServerBodyFileDataTest18);

    UtRegisterTest("DetectEngineHttpServerBodyFileDataTest19",
                  DetectEngineHttpServerBodyFileDataTest19);
    UtRegisterTest("DetectEngineHttpServerBodyFileDataTest20",
                  DetectEngineHttpServerBodyFileDataTest20);
    UtRegisterTest("DetectEngineHttpServerBodyFileDataTest21",
                  DetectEngineHttpServerBodyFileDataTest21);
    UtRegisterTest("DetectEngineHttpServerBodyFileDataTest22",
                  DetectEngineHttpServerBodyFileDataTest22);
    UtRegisterTest("DetectEngineHttpServerBodyFileDataTest23",
                  DetectEngineHttpServerBodyFileDataTest23);
    UtRegisterTest("DetectEngineHttpServerBodyFileDataTest24",
                  DetectEngineHttpServerBodyFileDataTest24);
    UtRegisterTest("DetectEngineHttpServerBodyFileDataTest25",
                  DetectEngineHttpServerBodyFileDataTest25);
    UtRegisterTest("DetectEngineHttpServerBodyFileDataTest26",
                  DetectEngineHttpServerBodyFileDataTest26);
    UtRegisterTest("DetectEngineHttpServerBodyFileDataTest27",
                  DetectEngineHttpServerBodyFileDataTest27);
    UtRegisterTest("DetectEngineHttpServerBodyFileDataTest28",
                  DetectEngineHttpServerBodyFileDataTest28);
    UtRegisterTest("DetectEngineHttpServerBodyFileDataTest29",
                  DetectEngineHttpServerBodyFileDataTest29);
}
