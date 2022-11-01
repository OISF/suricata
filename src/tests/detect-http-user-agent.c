/* Copyright (C) 2007-2021 Open Information Security Foundation
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


/** \file
 *
 * \author Anoop Saldanha <anoopsaldanha@gmail.com>
 * \author Victor Julien <victor@inliniac.net>
 *
 * \brief Handle HTTP user agent match
 *
 */

#include "suricata-common.h"
#include "suricata.h"
#include "flow-util.h"
#include "flow.h"
#include "app-layer-parser.h"
#include "util-unittest.h"
#include "util-unittest-helper.h"
#include "app-layer.h"
#include "app-layer-htp.h"
#include "app-layer-protos.h"
#include "detect-engine-build.h"
#include "detect-engine-alert.h"

static int DetectEngineHttpUATest(
        const uint8_t *buf, const uint32_t buf_len, const char *sig, const bool expect)
{
    TcpSession ssn;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx = NULL;
    Flow f;

    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();
    FAIL_IF_NULL(alp_tctx);

    memset(&th_v, 0, sizeof(th_v));
    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    Packet *p = UTHBuildPacket(NULL, 0, IPPROTO_TCP);
    FAIL_IF_NULL(p);

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;
    f.flags |= FLOW_IPV4;
    p->flow = &f;
    p->flowflags |= FLOW_PKT_TOSERVER;
    p->flowflags |= FLOW_PKT_ESTABLISHED;
    p->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    f.alproto = ALPROTO_HTTP1;

    StreamTcpInitConfig(true);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    de_ctx->flags |= DE_QUIET;

    Signature *s = DetectEngineAppendSig(de_ctx, sig);
    FAIL_IF_NULL(s);

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);
    FAIL_IF_NULL(det_ctx);

    int r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER, buf, buf_len);
    FAIL_IF_NOT(r == 0);
    FAIL_IF_NULL(f.alstate);

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);

    bool match = PacketAlertCheck(p, 1);
    FAIL_IF_NOT(match == expect);

    AppLayerParserThreadCtxFree(alp_tctx);

    DetectEngineCtxFree(de_ctx);
    StreamTcpFreeConfig(true);
    FLOW_DESTROY(&f);
    UTHFreePackets(&p, 1);
    PASS;
}

static int DetectEngineHttpUATest01(void)
{
    uint8_t http_buf[] = "GET /index.html HTTP/1.0\r\n"
                         "User-Agent: CONNECT\r\n"
                         "Host: www.onetwothreefourfivesixseven.org\r\n\r\n";
    uint32_t http_len = sizeof(http_buf) - 1;
    return DetectEngineHttpUATest(http_buf, http_len,
            "alert http any any -> any any "
            "(msg:\"http user agent test\"; "
            "content:\"CONNECT\"; http_user_agent; "
            "sid:1;)",
            true);
}

static int DetectEngineHttpUATest02(void)
{
    uint8_t http_buf[] = "GET /index.html HTTP/1.0\r\n"
                         "User-Agent: CONNECT\r\n"
                         "Host: www.onetwothreefourfivesixseven.org\r\n\r\n";
    uint32_t http_len = sizeof(http_buf) - 1;
    return DetectEngineHttpUATest(http_buf, http_len,
            "alert http any any -> any any "
            "(msg:\"http user agent test\"; "
            "content:\"CO\"; depth:4; http_user_agent; "
            "sid:1;)",
            true);
}

static int DetectEngineHttpUATest03(void)
{
    uint8_t http_buf[] = "CONNECT /index.html HTTP/1.0\r\n"
                         "User-Agent: CONNECT\r\n"
                         "Host: www.onetwothreefourfivesixseven.org\r\n\r\n";
    uint32_t http_len = sizeof(http_buf) - 1;
    return DetectEngineHttpUATest(http_buf, http_len,
            "alert http any any -> any any "
            "(msg:\"http_user_agent test\"; "
            "content:!\"ECT\"; depth:4; http_user_agent; "
            "sid:1;)",
            true);
}

static int DetectEngineHttpUATest04(void)
{
    uint8_t http_buf[] = "CONNECT /index.html HTTP/1.0\r\n"
                         "User-Agent: CONNECT\r\n"
                         "Host: www.onetwothreefourfivesixseven.org\r\n\r\n";
    uint32_t http_len = sizeof(http_buf) - 1;
    return DetectEngineHttpUATest(http_buf, http_len,
            "alert http any any -> any any "
            "(msg:\"http user agent test\"; "
            "content:\"ECT\"; depth:4; http_user_agent; "
            "sid:1;)",
            false);
}

static int DetectEngineHttpUATest05(void)
{
    uint8_t http_buf[] = "CONNECT /index.html HTTP/1.0\r\n"
                         "User-Agent: CONNECT\r\n"
                         "Host: www.onetwothreefourfivesixseven.org\r\n\r\n";
    uint32_t http_len = sizeof(http_buf) - 1;
    return DetectEngineHttpUATest(http_buf, http_len,
            "alert http any any -> any any "
            "(msg:\"http user agent test\"; "
            "content:!\"CON\"; depth:4; http_user_agent; "
            "sid:1;)",
            false);
}

static int DetectEngineHttpUATest06(void)
{
    uint8_t http_buf[] = "CONNECT /index.html HTTP/1.0\r\n"
                         "User-Agent: CONNECT\r\n"
                         "Host: www.onetwothreefourfivesixseven.org\r\n\r\n";
    uint32_t http_len = sizeof(http_buf) - 1;
    return DetectEngineHttpUATest(http_buf, http_len,
            "alert http any any -> any any "
            "(msg:\"http user agent test\"; "
            "content:\"ECT\"; offset:3; http_user_agent; "
            "sid:1;)",
            true);
}

static int DetectEngineHttpUATest07(void)
{
    uint8_t http_buf[] = "CONNECT /index.html HTTP/1.0\r\n"
                         "User-Agent: CONNECT\r\n"
                         "Host: www.onetwothreefourfivesixseven.org\r\n\r\n";
    uint32_t http_len = sizeof(http_buf) - 1;
    return DetectEngineHttpUATest(http_buf, http_len,
            "alert http any any -> any any "
            "(msg:\"http user agent test\"; "
            "content:!\"CO\"; offset:3; http_user_agent; "
            "sid:1;)",
            true);
}

static int DetectEngineHttpUATest08(void)
{
    uint8_t http_buf[] = "CONNECT /index.html HTTP/1.0\r\n"
                         "User-Agent: CONNECT\r\n"
                         "Host: www.onetwothreefourfivesixseven.org\r\n\r\n";
    uint32_t http_len = sizeof(http_buf) - 1;
    return DetectEngineHttpUATest(http_buf, http_len,
            "alert http any any -> any any "
            "(msg:\"http user agent test\"; "
            "content:!\"ECT\"; offset:3; http_user_agent; "
            "sid:1;)",
            false);
}

static int DetectEngineHttpUATest09(void)
{
    uint8_t http_buf[] = "CONNECT /index.html HTTP/1.0\r\n"
                         "User-Agent: CONNECT\r\n"
                         "Host: www.onetwothreefourfivesixseven.org\r\n\r\n";
    uint32_t http_len = sizeof(http_buf) - 1;
    return DetectEngineHttpUATest(http_buf, http_len,
            "alert http any any -> any any "
            "(msg:\"http user agent test\"; "
            "content:\"CON\"; offset:3; http_user_agent; "
            "sid:1;)",
            false);
}

static int DetectEngineHttpUATest10(void)
{
    uint8_t http_buf[] = "CONNECT /index.html HTTP/1.0\r\n"
                         "User-Agent: CONNECT\r\n"
                         "Host: www.onetwothreefourfivesixseven.org\r\n\r\n";
    uint32_t http_len = sizeof(http_buf) - 1;
    return DetectEngineHttpUATest(http_buf, http_len,
            "alert http any any -> any any "
            "(msg:\"http_user_agent test\"; "
            "content:\"CO\"; http_user_agent; "
            "content:\"EC\"; within:4; http_user_agent; "
            "sid:1;)",
            true);
}

static int DetectEngineHttpUATest11(void)
{
    uint8_t http_buf[] = "CONNECT /index.html HTTP/1.0\r\n"
                         "User-Agent: CONNECT\r\n"
                         "Host: www.onetwothreefourfivesixseven.org\r\n\r\n";
    uint32_t http_len = sizeof(http_buf) - 1;
    return DetectEngineHttpUATest(http_buf, http_len,
            "alert http any any -> any any "
            "(msg:\"http user agent test\"; "
            "content:\"CO\"; http_user_agent; "
            "content:!\"EC\"; within:3; http_user_agent; "
            "sid:1;)",
            true);
}

static int DetectEngineHttpUATest12(void)
{
    uint8_t http_buf[] = "CONNECT /index.html HTTP/1.0\r\n"
                         "User-Agent: CONNECT\r\n"
                         "Host: www.onetwothreefourfivesixseven.org\r\n\r\n";
    uint32_t http_len = sizeof(http_buf) - 1;
    return DetectEngineHttpUATest(http_buf, http_len,
            "alert http any any -> any any "
            "(msg:\"http_user_agent test\"; "
            "content:\"CO\"; http_user_agent; "
            "content:\"EC\"; within:3; http_user_agent; "
            "sid:1;)",
            false);
}

static int DetectEngineHttpUATest13(void)
{
    uint8_t http_buf[] = "CONNECT /index.html HTTP/1.0\r\n"
                         "User-Agent: CONNECT\r\n"
                         "Host: www.onetwothreefourfivesixseven.org\r\n\r\n";
    uint32_t http_len = sizeof(http_buf) - 1;
    return DetectEngineHttpUATest(http_buf, http_len,
            "alert http any any -> any any "
            "(msg:\"http user agent test\"; "
            "content:\"CO\"; http_user_agent; "
            "content:!\"EC\"; within:4; http_user_agent; "
            "sid:1;)",
            false);
}

static int DetectEngineHttpUATest14(void)
{
    uint8_t http_buf[] = "CONNECT /index.html HTTP/1.0\r\n"
                         "User-Agent: CONNECT\r\n"
                         "Host: www.onetwothreefourfivesixseven.org\r\n\r\n";
    uint32_t http_len = sizeof(http_buf) - 1;
    return DetectEngineHttpUATest(http_buf, http_len,
            "alert http any any -> any any "
            "(msg:\"http_user_agent test\"; "
            "content:\"CO\"; http_user_agent; "
            "content:\"EC\"; distance:2; http_user_agent; "
            "sid:1;)",
            true);
}

static int DetectEngineHttpUATest15(void)
{
    uint8_t http_buf[] = "CONNECT /index.html HTTP/1.0\r\n"
                         "User-Agent: CONNECT\r\n"
                         "Host: www.onetwothreefourfivesixseven.org\r\n\r\n";
    uint32_t http_len = sizeof(http_buf) - 1;
    return DetectEngineHttpUATest(http_buf, http_len,
            "alert http any any -> any any "
            "(msg:\"http user agent test\"; "
            "content:\"CO\"; http_user_agent; "
            "content:!\"EC\"; distance:3; http_user_agent; "
            "sid:1;)",
            true);
}

static int DetectEngineHttpUATest16(void)
{
    uint8_t http_buf[] = "CONNECT /index.html HTTP/1.0\r\n"
                         "User-Agent: CONNECT\r\n"
                         "Host: www.onetwothreefourfivesixseven.org\r\n\r\n";
    uint32_t http_len = sizeof(http_buf) - 1;
    return DetectEngineHttpUATest(http_buf, http_len,
            "alert http any any -> any any "
            "(msg:\"http user agent test\"; "
            "content:\"CO\"; http_user_agent; "
            "content:\"EC\"; distance:3; http_user_agent; "
            "sid:1;)",
            false);
}

static int DetectEngineHttpUATest17(void)
{
    uint8_t http_buf[] = "CONNECT /index.html HTTP/1.0\r\n"
                         "User-Agent: CONNECT\r\n"
                         "Host: www.onetwothreefourfivesixseven.org\r\n\r\n";
    uint32_t http_len = sizeof(http_buf) - 1;
    return DetectEngineHttpUATest(http_buf, http_len,
            "alert http any any -> any any "
            "(msg:\"http_user_agent test\"; "
            "content:\"CO\"; http_user_agent; "
            "content:!\"EC\"; distance:2; http_user_agent; "
            "sid:1;)",
            false);
}

static int DetectHttpUATestSigParse(const char *sig, const bool expect)
{
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    de_ctx->flags |= DE_QUIET;

    Signature *s = DetectEngineAppendSig(de_ctx, sig);
    bool parsed = (s != NULL);
    FAIL_IF_NOT(parsed == expect);
    DetectEngineCtxFree(de_ctx);
    PASS;
}

/**
 * \test Test that a signature containting a http_user_agent is correctly parsed
 *       and the keyword is registered.
 */
static int DetectHttpUATest01(void)
{
    return DetectHttpUATestSigParse("alert tcp any any -> any any "
                                    "(msg:\"Testing http_user_agent\"; "
                                    "content:\"one\"; http_user_agent; sid:1;)",
            true);
}

/**
 * \test Test that a signature containing an valid http_user_agent entry is
 *       parsed.
 */
static int DetectHttpUATest02(void)
{
    return DetectHttpUATestSigParse("alert tcp any any -> any any "
                                    "(msg:\"Testing http_user_agent\"; "
                                    "content:\"one\"; http_user_agent:; sid:1;)",
            true);
}

/**
 * \test Test that an invalid signature containing no content but a
 *       http_user_agent is invalidated.
 */
static int DetectHttpUATest03(void)
{
    return DetectHttpUATestSigParse("alert tcp any any -> any any "
                                    "(msg:\"Testing http_user_agent\"; "
                                    "http_user_agent; sid:1;)",
            false);
}

/**
 * \test Test that an invalid signature containing a rawbytes along with a
 *       http_user_agent is invalidated.
 */
static int DetectHttpUATest04(void)
{
    return DetectHttpUATestSigParse("alert tcp any any -> any any "
                                    "(msg:\"Testing http_user_agent\"; "
                                    "content:\"one\"; rawbytes; http_user_agent; sid:1;)",
            false);
}

/**
 * \test Test that a http_user_agent with nocase is parsed.
 */
static int DetectHttpUATest05(void)
{
    return DetectHttpUATestSigParse("alert tcp any any -> any any "
                                    "(msg:\"Testing http_user_agent\"; "
                                    "content:\"one\"; http_user_agent; nocase; sid:1;)",
            true);
}

/**
 *\test Test that the http_user_agent content matches against a http request
 *      which holds the content.
 */
static int DetectHttpUATest06(void)
{
    TcpSession ssn;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx = NULL;
    Flow f;
    uint8_t http_buf[] =
        "GET /index.html HTTP/1.0\r\n"
        "Host: www.openinfosecfoundation.org\r\n"
        "User-Agent: This is dummy message body\r\n"
        "Content-Type: text/html\r\n"
        "\r\n";
    uint32_t http_len = sizeof(http_buf) - 1;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&th_v, 0, sizeof(th_v));
    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    Packet *p = UTHBuildPacket(NULL, 0, IPPROTO_TCP);
    FAIL_IF_NULL(p);

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;
    f.flags |= FLOW_IPV4;

    p->flow = &f;
    p->flowflags |= FLOW_PKT_TOSERVER;
    p->flowflags |= FLOW_PKT_ESTABLISHED;
    p->flags |= PKT_HAS_FLOW | PKT_STREAM_EST;
    f.alproto = ALPROTO_HTTP1;

    StreamTcpInitConfig(true);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    de_ctx->flags |= DE_QUIET;

    Signature *s = DetectEngineAppendSig(de_ctx, "alert http any any -> any any "
                                                 "(msg:\"http user agent test\"; "
                                                 "content:\"message\"; http_user_agent; "
                                                 "sid:1;)");
    FAIL_IF_NULL(s);

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParserParse(
            NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER, http_buf, http_len);
    FAIL_IF_NOT(r == 0);
    FAIL_IF_NULL(f.alstate);

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);

    FAIL_IF_NOT(PacketAlertCheck(p, 1));

    AppLayerParserThreadCtxFree(alp_tctx);
    DetectEngineCtxFree(de_ctx);

    StreamTcpFreeConfig(true);
    FLOW_DESTROY(&f);
    UTHFreePackets(&p, 1);
    PASS;
}

/**
 *\test Test that the http_user_agent content matches against a http request
 *      which holds the content.
 */
static int DetectHttpUATest07(void)
{
    TcpSession ssn;
    Packet *p1 = NULL;
    Packet *p2 = NULL;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx = NULL;
    Flow f;
    uint8_t http1_buf[] =
        "GET /index.html HTTP/1.0\r\n"
        "Host: www.openinfosecfoundation.org\r\n"
        "User-Agent: This is dummy message";
    uint8_t http2_buf[] =
        "body1\r\n\r\n";
    uint32_t http1_len = sizeof(http1_buf) - 1;
    uint32_t http2_len = sizeof(http2_buf) - 1;
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
    p2->flowflags |= FLOW_PKT_TOSERVER;
    p2->flowflags |= FLOW_PKT_ESTABLISHED;
    p2->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    f.alproto = ALPROTO_HTTP1;

    StreamTcpInitConfig(true);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    de_ctx->flags |= DE_QUIET;

    Signature *s = DetectEngineAppendSig(de_ctx, "alert http any any -> any any "
                                                 "(msg:\"http user agent test\"; "
                                                 "content:\"message\"; http_user_agent; "
                                                 "sid:1;)");
    FAIL_IF_NULL(s);

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParserParse(
            NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER, http1_buf, http1_len);
    FAIL_IF_NOT(r == 0);
    FAIL_IF_NULL(f.alstate);

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p1);

    FAIL_IF(PacketAlertCheck(p1, 1));

    r = AppLayerParserParse(
            NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER, http2_buf, http2_len);
    FAIL_IF_NOT(r == 0);
    FAIL_IF_NULL(f.alstate);

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p2);
    FAIL_IF_NOT(PacketAlertCheck(p2, 1));

    AppLayerParserThreadCtxFree(alp_tctx);
    DetectEngineCtxFree(de_ctx);

    StreamTcpFreeConfig(true);
    FLOW_DESTROY(&f);
    UTHFreePackets(&p1, 1);
    UTHFreePackets(&p2, 1);
    PASS;
}

/**
 *\test Test that the http_user_agent content matches against a http request
 *      which holds the content.
 */
static int DetectHttpUATest08(void)
{
    TcpSession ssn;
    Packet *p1 = NULL;
    Packet *p2 = NULL;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx = NULL;
    Flow f;
    uint8_t http1_buf[] =
        "GET /index.html HTTP/1.0\r\n"
        "Host: www.openinfosecfoundation.org\r\n"
        "User-Agent: This is dummy mess";
    uint8_t http2_buf[] =
        "age body\r\n\r\n";
    uint32_t http1_len = sizeof(http1_buf) - 1;
    uint32_t http2_len = sizeof(http2_buf) - 1;
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
    p2->flowflags |= FLOW_PKT_TOSERVER;
    p2->flowflags |= FLOW_PKT_ESTABLISHED;
    p2->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    f.alproto = ALPROTO_HTTP1;

    StreamTcpInitConfig(true);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    de_ctx->flags |= DE_QUIET;

    Signature *s = DetectEngineAppendSig(de_ctx, "alert http any any -> any any "
                                                 "(msg:\"http user agent test\"; "
                                                 "content:\"message\"; http_user_agent; "
                                                 "sid:1;)");
    FAIL_IF_NULL(s);

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParserParse(
            NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER, http1_buf, http1_len);
    FAIL_IF_NOT(r == 0);
    FAIL_IF_NULL(f.alstate);

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p1);
    FAIL_IF(PacketAlertCheck(p1, 1));

    r = AppLayerParserParse(
            NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER, http2_buf, http2_len);
    FAIL_IF_NOT(r == 0);
    FAIL_IF_NULL(f.alstate);

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p2);

    FAIL_IF_NOT(PacketAlertCheck(p2, 1));

    AppLayerParserThreadCtxFree(alp_tctx);
    DetectEngineCtxFree(de_ctx);

    StreamTcpFreeConfig(true);
    FLOW_DESTROY(&f);
    UTHFreePackets(&p1, 1);
    UTHFreePackets(&p2, 1);
    PASS;
}

/**
 *\test Test that the http_user_agent content matches against a http request
 *      which holds the content, against a cross boundary present pattern.
 */
static int DetectHttpUATest09(void)
{
    TcpSession ssn;
    Packet *p1 = NULL;
    Packet *p2 = NULL;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx = NULL;
    Flow f;
    uint8_t http1_buf[] =
        "GET /index.html HTTP/1.0\r\n"
        "Host: www.openinfosecfoundation.org\r\n"
        "User-Agent: This is dummy body1";
    uint8_t http2_buf[] =
        "This is dummy message body2\r\n"
        "Content-Type: text/html\r\n"
        "Content-Length: 46\r\n"
        "\r\n"
        "This is dummy body1";
    uint32_t http1_len = sizeof(http1_buf) - 1;
    uint32_t http2_len = sizeof(http2_buf) - 1;
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
    p2->flowflags |= FLOW_PKT_TOSERVER;
    p2->flowflags |= FLOW_PKT_ESTABLISHED;
    p2->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    f.alproto = ALPROTO_HTTP1;

    StreamTcpInitConfig(true);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    de_ctx->flags |= DE_QUIET;

    Signature *s = DetectEngineAppendSig(de_ctx, "alert http any any -> any any "
                                                 "(msg:\"http user agent test\"; "
                                                 "content:\"body1This\"; http_user_agent; "
                                                 "sid:1;)");
    FAIL_IF_NULL(s);

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParserParse(
            NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER, http1_buf, http1_len);
    FAIL_IF_NOT(r == 0);
    FAIL_IF_NULL(f.alstate);

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p1);
    FAIL_IF(PacketAlertCheck(p1, 1));

    r = AppLayerParserParse(
            NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER, http2_buf, http2_len);
    FAIL_IF_NOT(r == 0);
    FAIL_IF_NULL(f.alstate);

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p2);

    FAIL_IF_NOT(PacketAlertCheck(p2, 1));

    AppLayerParserThreadCtxFree(alp_tctx);
    DetectEngineCtxFree(de_ctx);
    StreamTcpFreeConfig(true);
    FLOW_DESTROY(&f);
    UTHFreePackets(&p1, 1);
    UTHFreePackets(&p2, 1);
    PASS;
}

/**
 *\test Test that the http_user_agent content matches against a http request
 *      against a case insensitive pattern.
 */
static int DetectHttpUATest10(void)
{
    TcpSession ssn;
    Packet *p1 = NULL;
    Packet *p2 = NULL;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx = NULL;
    Flow f;
    uint8_t http1_buf[] =
        "GET /index.html HTTP/1.0\r\n"
        "Host: www.openinfosecfoundation.org\r\n"
        "User-Agent: This is dummy bodY1";
    uint8_t http2_buf[] =
        "This is dummy message body2\r\n"
        "Content-Type: text/html\r\n"
        "Content-Length: 46\r\n"
        "\r\n"
        "This is dummy bodY1";
    uint32_t http1_len = sizeof(http1_buf) - 1;
    uint32_t http2_len = sizeof(http2_buf) - 1;
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
    p2->flowflags |= FLOW_PKT_TOSERVER;
    p2->flowflags |= FLOW_PKT_ESTABLISHED;
    p2->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    f.alproto = ALPROTO_HTTP1;

    StreamTcpInitConfig(true);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    de_ctx->flags |= DE_QUIET;

    Signature *s = DetectEngineAppendSig(de_ctx, "alert http any any -> any any "
                                                 "(msg:\"http user agent test\"; "
                                                 "content:\"body1this\"; http_user_agent; nocase;"
                                                 "sid:1;)");
    FAIL_IF_NULL(s);

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParserParse(
            NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER, http1_buf, http1_len);
    FAIL_IF_NOT(r == 0);
    FAIL_IF_NULL(f.alstate);

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p1);
    FAIL_IF(PacketAlertCheck(p1, 1));

    r = AppLayerParserParse(
            NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER, http2_buf, http2_len);
    FAIL_IF_NOT(r == 0);
    FAIL_IF_NULL(f.alstate);

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p2);
    FAIL_IF_NOT(PacketAlertCheck(p2, 1));

    AppLayerParserThreadCtxFree(alp_tctx);
    DetectEngineCtxFree(de_ctx);
    StreamTcpFreeConfig(true);
    FLOW_DESTROY(&f);
    UTHFreePackets(&p1, 1);
    UTHFreePackets(&p2, 1);
    PASS;
}

/**
 *\test Test that the negated http_user_agent content matches against a
 *      http request which doesn't hold the content.
 */
static int DetectHttpUATest11(void)
{
    TcpSession ssn;
    Packet *p = NULL;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx = NULL;
    Flow f;
    uint8_t http_buf[] =
        "GET /index.html HTTP/1.0\r\n"
        "Host: www.openinfosecfoundation.org\r\n"
        "User-Agent: This is dummy message body\r\n"
        "Content-Type: text/html\r\n"
        "\r\n";
    uint32_t http_len = sizeof(http_buf) - 1;
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
    p->flowflags |= FLOW_PKT_TOSERVER;
    p->flowflags |= FLOW_PKT_ESTABLISHED;
    p->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    f.alproto = ALPROTO_HTTP1;

    StreamTcpInitConfig(true);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    de_ctx->flags |= DE_QUIET;

    Signature *s = DetectEngineAppendSig(de_ctx, "alert http any any -> any any "
                                                 "(msg:\"http user agent test\"; "
                                                 "content:!\"message\"; http_user_agent; "
                                                 "sid:1;)");
    FAIL_IF_NULL(s);

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParserParse(
            NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER, http_buf, http_len);
    FAIL_IF_NOT(r == 0);
    FAIL_IF_NULL(f.alstate);

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);

    FAIL_IF(PacketAlertCheck(p, 1));

    AppLayerParserThreadCtxFree(alp_tctx);
    DetectEngineCtxFree(de_ctx);
    StreamTcpFreeConfig(true);
    FLOW_DESTROY(&f);
    UTHFreePackets(&p, 1);
    PASS;
}

/**
 *\test Negative test that the negated http_user_agent content matches against a
 *      http request which holds hold the content.
 */
static int DetectHttpUATest12(void)
{
    TcpSession ssn;
    Packet *p = NULL;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx = NULL;
    Flow f;
    uint8_t http_buf[] =
        "GET /index.html HTTP/1.0\r\n"
        "Host: www.openinfosecfoundation.org\r\n"
        "User-Agent: This is dummy body\r\n"
        "\r\n";
    uint32_t http_len = sizeof(http_buf) - 1;
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
    p->flowflags |= FLOW_PKT_TOSERVER;
    p->flowflags |= FLOW_PKT_ESTABLISHED;
    p->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    f.alproto = ALPROTO_HTTP1;

    StreamTcpInitConfig(true);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    de_ctx->flags |= DE_QUIET;

    Signature *s = DetectEngineAppendSig(de_ctx, "alert http any any -> any any "
                                                 "(msg:\"http user agent test\"; "
                                                 "content:!\"message\"; http_user_agent; "
                                                 "sid:1;)");
    FAIL_IF_NULL(s);

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParserParse(
            NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER, http_buf, http_len);
    FAIL_IF_NOT(r == 0);
    FAIL_IF_NULL(f.alstate);

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    FAIL_IF_NOT(PacketAlertCheck(p, 1));

    AppLayerParserThreadCtxFree(alp_tctx);
    DetectEngineCtxFree(de_ctx);

    StreamTcpFreeConfig(true);
    FLOW_DESTROY(&f);
    UTHFreePackets(&p, 1);
    PASS;
}

/**
 * \test Test that the http_user_agent content matches against a http request
 *       which holds the content.
 */
static int DetectHttpUATest13(void)
{
    TcpSession ssn;
    Packet *p = NULL;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx = NULL;
    Flow f;
    uint8_t http_buf[] =
        "GET /index.html HTTP/1.0\r\n"
        "Host: www.openinfosecfoundation.org\r\n"
        "User-Agent: longbufferabcdefghijklmnopqrstuvwxyz0123456789bufferend\r\n"
        "Content-Type: text/html\r\n"
        "\r\n";
    uint32_t http_len = sizeof(http_buf) - 1;
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
    p->flowflags |= FLOW_PKT_TOSERVER;
    p->flowflags |= FLOW_PKT_ESTABLISHED;
    p->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    f.alproto = ALPROTO_HTTP1;

    StreamTcpInitConfig(true);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    de_ctx->flags |= DE_QUIET;

    Signature *s = DetectEngineAppendSig(de_ctx,
            "alert http any any -> any any "
            "(msg:\"http user agent test\"; "
            "content:\"abcdefghijklmnopqrstuvwxyz0123456789\"; http_user_agent; "
            "sid:1;)");
    FAIL_IF_NULL(s);

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParserParse(
            NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER, http_buf, http_len);
    FAIL_IF_NOT(r == 0);
    FAIL_IF_NULL(f.alstate);

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);

    FAIL_IF_NOT(PacketAlertCheck(p, 1));

    AppLayerParserThreadCtxFree(alp_tctx);
    DetectEngineCtxFree(de_ctx);
    StreamTcpFreeConfig(true);
    FLOW_DESTROY(&f);
    UTHFreePackets(&p, 1);
    PASS;
}

/**
 * \test multiple http transactions and body chunks of request handling
 */
static int DetectHttpUATest14(void)
{
    Signature *s = NULL;
    DetectEngineThreadCtx *det_ctx = NULL;
    ThreadVars th_v;
    Flow f;
    TcpSession ssn;
    Packet *p = NULL;
    uint8_t httpbuf1[] = "POST / HTTP/1.1\r\n";
    uint8_t httpbuf2[] = "Cookie: dummy1\r\n";
    uint8_t httpbuf3[] = "User-Agent: Body one!!\r\n\r\n";
    uint32_t httplen1 = sizeof(httpbuf1) - 1; /* minus the \0 */
    uint32_t httplen2 = sizeof(httpbuf2) - 1; /* minus the \0 */
    uint32_t httplen3 = sizeof(httpbuf3) - 1; /* minus the \0 */
    uint8_t httpbuf4[] = "GET /?var=val HTTP/1.1\r\n";
    uint8_t httpbuf5[] = "Cookie: dummy2\r\n";
    uint8_t httpbuf6[] = "User-Agent: Body two\r\n\r\n";
    uint32_t httplen4 = sizeof(httpbuf4) - 1; /* minus the \0 */
    uint32_t httplen5 = sizeof(httpbuf5) - 1; /* minus the \0 */
    uint32_t httplen6 = sizeof(httpbuf6) - 1; /* minus the \0 */
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
    p->flowflags |= FLOW_PKT_TOSERVER;
    p->flowflags |= FLOW_PKT_ESTABLISHED;
    p->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    f.alproto = ALPROTO_HTTP1;

    StreamTcpInitConfig(true);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    de_ctx->flags |= DE_QUIET;

    s = DetectEngineAppendSig(de_ctx, "alert tcp any any -> any any (content:\"POST\"; http_method; content:\"dummy1\"; http_cookie; content:\"Body one\"; http_user_agent; sid:1; rev:1;)");
    FAIL_IF_NULL(s);
    s = DetectEngineAppendSig(de_ctx, "alert tcp any any -> any any (content:\"GET\"; http_method; content:\"dummy2\"; http_cookie; content:\"Body two\"; http_user_agent; sid:2; rev:1;)");
    FAIL_IF_NULL(s);

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParserParse(
            NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER, httpbuf1, httplen1);
    FAIL_IF_NOT(r == 0);

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    FAIL_IF(PacketAlertCheck(p, 1));

    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER, httpbuf2, httplen2);
    FAIL_IF_NOT(r == 0);

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    FAIL_IF(PacketAlertCheck(p, 1));

    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER, httpbuf3, httplen3);
    FAIL_IF_NOT(r == 0);

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    FAIL_IF_NOT(PacketAlertCheck(p, 1));
    p->alerts.cnt = 0;

    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER, httpbuf4, httplen4);
    FAIL_IF_NOT(r == 0);

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    FAIL_IF(PacketAlertCheck(p, 1));
    FAIL_IF(PacketAlertCheck(p, 2));

    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER, httpbuf5, httplen5);
    FAIL_IF_NOT(r == 0);

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    FAIL_IF(PacketAlertCheck(p, 1));
    FAIL_IF(PacketAlertCheck(p, 2));

    SCLogDebug("sending data chunk 7");

    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER, httpbuf6, httplen6);
    FAIL_IF_NOT(r == 0);

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    FAIL_IF(PacketAlertCheck(p, 1));
    FAIL_IF_NOT(PacketAlertCheck(p, 2));
    p->alerts.cnt = 0;

    HtpState *htp_state = f.alstate;
    FAIL_IF_NULL(htp_state);
    FAIL_IF_NOT(AppLayerParserGetTxCnt(&f, htp_state) == 2);

    AppLayerParserThreadCtxFree(alp_tctx);
    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);

    StreamTcpFreeConfig(true);
    FLOW_DESTROY(&f);
    UTHFreePacket(p);
    PASS;
}

static int DetectHttpUATest22(void)
{
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    de_ctx->flags |= DE_QUIET;

    Signature *s = DetectEngineAppendSig(de_ctx,
            "alert tcp any any -> any any "
            "(content:\"one\"; content:\"two\"; http_user_agent; "
            "content:\"three\"; distance:10; http_user_agent; content:\"four\"; sid:1;)");
    FAIL_IF_NULL(s);
    FAIL_IF_NULL(s->sm_lists[DETECT_SM_LIST_PMATCH]);
    FAIL_IF_NULL(s->sm_lists[g_http_ua_buffer_id]);

    DetectContentData *cd1 =
            (DetectContentData *)s->sm_lists_tail[DETECT_SM_LIST_PMATCH]->prev->ctx;
    DetectContentData *cd2 = (DetectContentData *)s->sm_lists_tail[DETECT_SM_LIST_PMATCH]->ctx;
    DetectContentData *huad1 =
            (DetectContentData *)s->sm_lists_tail[g_http_ua_buffer_id]->prev->ctx;
    DetectContentData *huad2 = (DetectContentData *)s->sm_lists_tail[g_http_ua_buffer_id]->ctx;

    FAIL_IF_NULL(cd1);
    FAIL_IF_NULL(cd2);
    FAIL_IF_NULL(huad1);
    FAIL_IF_NULL(huad2);

    FAIL_IF_NOT(cd1->flags == 0);
    FAIL_IF_NOT(memcmp(cd1->content, "one", cd1->content_len) == 0);
    FAIL_IF_NOT(cd2->flags == 0);
    FAIL_IF_NOT(memcmp(cd2->content, "four", cd2->content_len) == 0);
    FAIL_IF_NOT(huad1->flags == DETECT_CONTENT_RELATIVE_NEXT);
    FAIL_IF_NOT(memcmp(huad1->content, "two", huad1->content_len) == 0);
    FAIL_IF_NOT(huad2->flags == DETECT_CONTENT_DISTANCE);
    FAIL_IF_NOT(memcmp(huad2->content, "three", huad1->content_len) == 0);

    FAIL_IF(!DETECT_CONTENT_IS_SINGLE(cd1));
    FAIL_IF(!DETECT_CONTENT_IS_SINGLE(cd2));
    FAIL_IF(DETECT_CONTENT_IS_SINGLE(huad1));
    FAIL_IF(DETECT_CONTENT_IS_SINGLE(huad2));

    DetectEngineCtxFree(de_ctx);
    PASS;
}

static int DetectHttpUATest23(void)
{
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    de_ctx->flags |= DE_QUIET;

    Signature *s = DetectEngineAppendSig(de_ctx,
            "alert tcp any any -> any any "
            "(content:\"one\"; http_user_agent; pcre:/two/; "
            "content:\"three\"; distance:10; http_user_agent; content:\"four\"; sid:1;)");
    FAIL_IF_NULL(s);
    FAIL_IF_NULL(s->sm_lists[DETECT_SM_LIST_PMATCH]);
    FAIL_IF_NULL(s->sm_lists[g_http_ua_buffer_id]);

    DetectPcreData *pd1 = (DetectPcreData *)s->sm_lists_tail[DETECT_SM_LIST_PMATCH]->prev->ctx;
    DetectContentData *cd2 = (DetectContentData *)s->sm_lists_tail[DETECT_SM_LIST_PMATCH]->ctx;
    DetectContentData *huad1 =
            (DetectContentData *)s->sm_lists_tail[g_http_ua_buffer_id]->prev->ctx;
    DetectContentData *huad2 = (DetectContentData *)s->sm_lists_tail[g_http_ua_buffer_id]->ctx;
    FAIL_IF_NOT(pd1->flags == 0);
    FAIL_IF_NOT(cd2->flags == 0);
    FAIL_IF_NOT(memcmp(cd2->content, "four", cd2->content_len) == 0);
    FAIL_IF_NOT(huad1->flags == DETECT_CONTENT_RELATIVE_NEXT);
    FAIL_IF_NOT(memcmp(huad1->content, "one", huad1->content_len) == 0);
    FAIL_IF_NOT(huad2->flags == DETECT_CONTENT_DISTANCE);
    FAIL_IF_NOT(memcmp(huad2->content, "three", huad1->content_len) == 0);

    FAIL_IF(!DETECT_CONTENT_IS_SINGLE(cd2));
    FAIL_IF(DETECT_CONTENT_IS_SINGLE(huad1));
    FAIL_IF(DETECT_CONTENT_IS_SINGLE(huad2));

    DetectEngineCtxFree(de_ctx);
    PASS;
}

static int DetectHttpUATest24(void)
{
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    de_ctx->flags |= DE_QUIET;

    Signature *s = DetectEngineAppendSig(de_ctx, "alert tcp any any -> any any "
                                                 "(content:\"one\"; http_user_agent; pcre:/two/; "
                                                 "content:\"three\"; distance:10; within:15; "
                                                 "http_user_agent; content:\"four\"; sid:1;)");
    FAIL_IF_NULL(s);
    FAIL_IF_NULL(s->sm_lists[DETECT_SM_LIST_PMATCH]);
    FAIL_IF_NULL(s->sm_lists[g_http_ua_buffer_id]);

    DetectPcreData *pd1 = (DetectPcreData *)s->sm_lists_tail[DETECT_SM_LIST_PMATCH]->prev->ctx;
    DetectContentData *cd2 = (DetectContentData *)s->sm_lists_tail[DETECT_SM_LIST_PMATCH]->ctx;
    DetectContentData *huad1 =
            (DetectContentData *)s->sm_lists_tail[g_http_ua_buffer_id]->prev->ctx;
    DetectContentData *huad2 = (DetectContentData *)s->sm_lists_tail[g_http_ua_buffer_id]->ctx;
    FAIL_IF_NOT(pd1->flags == 0);
    FAIL_IF_NOT(cd2->flags == 0);
    FAIL_IF_NOT(memcmp(cd2->content, "four", cd2->content_len) == 0);
    FAIL_IF_NOT(huad1->flags == DETECT_CONTENT_RELATIVE_NEXT);
    FAIL_IF_NOT(memcmp(huad1->content, "one", huad1->content_len) == 0);
    FAIL_IF_NOT(huad2->flags == (DETECT_CONTENT_DISTANCE | DETECT_CONTENT_WITHIN));
    FAIL_IF_NOT(memcmp(huad2->content, "three", huad1->content_len) == 0);

    FAIL_IF(!DETECT_CONTENT_IS_SINGLE(cd2));
    FAIL_IF(DETECT_CONTENT_IS_SINGLE(huad1));
    FAIL_IF(DETECT_CONTENT_IS_SINGLE(huad2));

    DetectEngineCtxFree(de_ctx);
    PASS;
}

static int DetectHttpUATest25(void)
{
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    de_ctx->flags |= DE_QUIET;

    Signature *s = DetectEngineAppendSig(de_ctx, "alert tcp any any -> any any "
                                                 "(content:\"one\"; http_user_agent; pcre:/two/; "
                                                 "content:\"three\"; distance:10; http_user_agent; "
                                                 "content:\"four\"; distance:10; sid:1;)");
    FAIL_IF_NULL(s);
    FAIL_IF_NULL(s->sm_lists[DETECT_SM_LIST_PMATCH]);
    FAIL_IF_NULL(s->sm_lists[g_http_ua_buffer_id]);

    DetectPcreData *pd1 = (DetectPcreData *)s->sm_lists_tail[DETECT_SM_LIST_PMATCH]->prev->ctx;
    DetectContentData *cd2 = (DetectContentData *)s->sm_lists_tail[DETECT_SM_LIST_PMATCH]->ctx;
    DetectContentData *huad1 =
            (DetectContentData *)s->sm_lists_tail[g_http_ua_buffer_id]->prev->ctx;
    DetectContentData *huad2 = (DetectContentData *)s->sm_lists_tail[g_http_ua_buffer_id]->ctx;

    FAIL_IF_NOT(pd1->flags == DETECT_PCRE_RELATIVE_NEXT);
    FAIL_IF_NOT(cd2->flags == DETECT_CONTENT_DISTANCE);
    FAIL_IF_NOT(memcmp(cd2->content, "four", cd2->content_len) == 0);
    FAIL_IF_NOT(huad1->flags == DETECT_CONTENT_RELATIVE_NEXT);
    FAIL_IF_NOT(memcmp(huad1->content, "one", huad1->content_len) == 0);
    FAIL_IF_NOT(huad2->flags == DETECT_CONTENT_DISTANCE);
    FAIL_IF_NOT(memcmp(huad2->content, "three", huad1->content_len) == 0);

    FAIL_IF(DETECT_CONTENT_IS_SINGLE(cd2));
    FAIL_IF(DETECT_CONTENT_IS_SINGLE(huad1));
    FAIL_IF(DETECT_CONTENT_IS_SINGLE(huad2));

    DetectEngineCtxFree(de_ctx);
    PASS;
}

static int DetectHttpUATest26(void)
{
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    de_ctx->flags |= DE_QUIET;

    Signature *s = DetectEngineAppendSig(de_ctx,
            "alert tcp any any -> any any "
            "(content:\"one\"; offset:10; http_user_agent; pcre:/two/; "
            "content:\"three\"; distance:10; http_user_agent; within:10; "
            "content:\"four\"; distance:10; sid:1;)");
    FAIL_IF_NULL(s);
    FAIL_IF_NULL(s->sm_lists[DETECT_SM_LIST_PMATCH]);
    FAIL_IF_NULL(s->sm_lists[g_http_ua_buffer_id]);

    DetectPcreData *pd1 = (DetectPcreData *)s->sm_lists_tail[DETECT_SM_LIST_PMATCH]->prev->ctx;
    DetectContentData *cd2 = (DetectContentData *)s->sm_lists_tail[DETECT_SM_LIST_PMATCH]->ctx;
    DetectContentData *huad1 =
            (DetectContentData *)s->sm_lists_tail[g_http_ua_buffer_id]->prev->ctx;
    DetectContentData *huad2 = (DetectContentData *)s->sm_lists_tail[g_http_ua_buffer_id]->ctx;

    FAIL_IF_NOT(pd1->flags == DETECT_PCRE_RELATIVE_NEXT);
    FAIL_IF_NOT(cd2->flags == DETECT_CONTENT_DISTANCE);
    FAIL_IF_NOT(memcmp(cd2->content, "four", cd2->content_len) == 0);
    FAIL_IF_NOT(huad1->flags == (DETECT_CONTENT_RELATIVE_NEXT | DETECT_CONTENT_OFFSET));
    FAIL_IF_NOT(memcmp(huad1->content, "one", huad1->content_len) == 0);
    FAIL_IF_NOT(huad2->flags == (DETECT_CONTENT_DISTANCE | DETECT_CONTENT_WITHIN));
    FAIL_IF_NOT(memcmp(huad2->content, "three", huad1->content_len) == 0);

    FAIL_IF(DETECT_CONTENT_IS_SINGLE(cd2));
    FAIL_IF(DETECT_CONTENT_IS_SINGLE(huad1));
    FAIL_IF(DETECT_CONTENT_IS_SINGLE(huad2));

    DetectEngineCtxFree(de_ctx);
    PASS;
}

static int DetectHttpUATest27(void)
{
    return DetectHttpUATestSigParse("alert tcp any any -> any any "
                                    "(content:\"one\"; offset:10; http_user_agent; pcre:/two/; "
                                    "content:\"three\"; distance:10; http_user_agent; within:10; "
                                    "content:\"four\"; distance:10; sid:1;)",
            true);
}

static int DetectHttpUATest28(void)
{
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    de_ctx->flags |= DE_QUIET;

    Signature *s = DetectEngineAppendSig(de_ctx, "alert tcp any any -> any any "
                                                 "(content:\"one\"; http_user_agent; pcre:/two/; "
                                                 "content:\"three\"; http_user_agent; depth:10; "
                                                 "content:\"four\"; distance:10; sid:1;)");
    FAIL_IF_NULL(s);
    FAIL_IF_NULL(s->sm_lists[DETECT_SM_LIST_PMATCH]);
    FAIL_IF_NULL(s->sm_lists[g_http_ua_buffer_id]);

    DetectPcreData *pd1 = (DetectPcreData *)s->sm_lists_tail[DETECT_SM_LIST_PMATCH]->prev->ctx;
    DetectContentData *cd2 = (DetectContentData *)s->sm_lists_tail[DETECT_SM_LIST_PMATCH]->ctx;
    DetectContentData *huad1 =
            (DetectContentData *)s->sm_lists_tail[g_http_ua_buffer_id]->prev->ctx;
    DetectContentData *huad2 = (DetectContentData *)s->sm_lists_tail[g_http_ua_buffer_id]->ctx;

    FAIL_IF_NOT(pd1->flags == DETECT_PCRE_RELATIVE_NEXT);
    FAIL_IF_NOT(cd2->flags == DETECT_CONTENT_DISTANCE);
    FAIL_IF_NOT(memcmp(cd2->content, "four", cd2->content_len) == 0);
    FAIL_IF_NOT(huad1->flags == 0);
    FAIL_IF_NOT(memcmp(huad1->content, "one", huad1->content_len) == 0);
    FAIL_IF_NOT(huad2->flags == (DETECT_CONTENT_DEPTH));
    FAIL_IF_NOT(memcmp(huad2->content, "three", huad1->content_len) == 0);

    FAIL_IF(DETECT_CONTENT_IS_SINGLE(cd2));
    FAIL_IF_NOT(DETECT_CONTENT_IS_SINGLE(huad1));
    FAIL_IF(DETECT_CONTENT_IS_SINGLE(huad2));

    DetectEngineCtxFree(de_ctx);
    PASS;
}

static int DetectHttpUATest29(void)
{
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    de_ctx->flags |= DE_QUIET;

    Signature *s =
            DetectEngineAppendSig(de_ctx, "alert tcp any any -> any any "
                                          "(content:\"one\"; http_user_agent; "
                                          "content:\"two\"; distance:0; http_user_agent; sid:1;)");
    FAIL_IF_NULL(s);
    FAIL_IF_NOT_NULL(s->sm_lists[DETECT_SM_LIST_PMATCH]);
    FAIL_IF_NULL(s->sm_lists[g_http_ua_buffer_id]);

    DetectContentData *huad1 =
            (DetectContentData *)s->sm_lists_tail[g_http_ua_buffer_id]->prev->ctx;
    DetectContentData *huad2 = (DetectContentData *)s->sm_lists_tail[g_http_ua_buffer_id]->ctx;
    FAIL_IF_NOT(huad1->flags == DETECT_CONTENT_RELATIVE_NEXT);
    FAIL_IF_NOT(memcmp(huad1->content, "one", huad1->content_len) == 0);
    FAIL_IF_NOT(huad2->flags == DETECT_CONTENT_DISTANCE);
    FAIL_IF_NOT(memcmp(huad2->content, "two", huad1->content_len) == 0);

    DetectEngineCtxFree(de_ctx);
    PASS;
}

static int DetectHttpUATest30(void)
{
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    de_ctx->flags |= DE_QUIET;

    Signature *s =
            DetectEngineAppendSig(de_ctx, "alert tcp any any -> any any "
                                          "(content:\"one\"; http_user_agent; "
                                          "content:\"two\"; within:5; http_user_agent; sid:1;)");
    FAIL_IF_NULL(s);
    FAIL_IF_NOT_NULL(s->sm_lists[DETECT_SM_LIST_PMATCH]);
    FAIL_IF_NULL(s->sm_lists[g_http_ua_buffer_id]);

    DetectContentData *huad1 =
            (DetectContentData *)s->sm_lists_tail[g_http_ua_buffer_id]->prev->ctx;
    DetectContentData *huad2 = (DetectContentData *)s->sm_lists_tail[g_http_ua_buffer_id]->ctx;
    FAIL_IF_NOT(huad1->flags == DETECT_CONTENT_RELATIVE_NEXT);
    FAIL_IF_NOT(memcmp(huad1->content, "one", huad1->content_len) == 0);
    FAIL_IF_NOT(huad2->flags == DETECT_CONTENT_WITHIN);
    FAIL_IF_NOT(memcmp(huad2->content, "two", huad1->content_len) == 0);

    DetectEngineCtxFree(de_ctx);
    PASS;
}

static int DetectHttpUATest31(void)
{
    return DetectHttpUATestSigParse("alert tcp any any -> any any "
                                    "(content:\"one\"; within:5; http_user_agent; sid:1;)",
            true);
}

static int DetectHttpUATest32(void)
{
    return DetectHttpUATestSigParse("alert tcp any any -> any any "
                                    "(content:\"one\"; http_user_agent; within:5; sid:1;)",
            true);
}

static int DetectHttpUATest33(void)
{
    return DetectHttpUATestSigParse("alert tcp any any -> any any "
                                    "(content:\"one\"; within:5; sid:1;)",
            true);
}

static int DetectHttpUATest34(void)
{
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    de_ctx->flags |= DE_QUIET;

    Signature *s =
            DetectEngineAppendSig(de_ctx, "alert tcp any any -> any any "
                                          "(pcre:/one/V; "
                                          "content:\"two\"; within:5; http_user_agent; sid:1;)");
    FAIL_IF_NULL(s);
    FAIL_IF_NOT_NULL(s->sm_lists[DETECT_SM_LIST_PMATCH]);
    FAIL_IF_NULL(s->sm_lists[g_http_ua_buffer_id]);

    SigMatch *sm = de_ctx->sig_list->sm_lists_tail[g_http_ua_buffer_id];
    FAIL_IF_NULL(sm);
    FAIL_IF_NOT(sm->type == DETECT_CONTENT);
    FAIL_IF_NULL(sm->prev);
    FAIL_IF_NOT(sm->prev->type == DETECT_PCRE);

    DetectPcreData *pd1 = (DetectPcreData *)sm->prev->ctx;
    DetectContentData *huad2 = (DetectContentData *)sm->ctx;
    FAIL_IF_NOT(pd1->flags == (DETECT_PCRE_RELATIVE_NEXT));
    FAIL_IF_NOT(huad2->flags == DETECT_CONTENT_WITHIN);
    FAIL_IF_NOT(memcmp(huad2->content, "two", huad2->content_len) == 0);

    DetectEngineCtxFree(de_ctx);
    PASS;
}

static int DetectHttpUATest35(void)
{
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    de_ctx->flags |= DE_QUIET;

    Signature *s = DetectEngineAppendSig(de_ctx, "alert tcp any any -> any any "
                                                 "(content:\"two\"; http_user_agent; "
                                                 "pcre:/one/VR; sid:1;)");
    FAIL_IF_NULL(s);

    FAIL_IF_NOT_NULL(s->sm_lists[DETECT_SM_LIST_PMATCH]);
    SigMatch *sm = s->sm_lists_tail[g_http_ua_buffer_id];
    FAIL_IF_NULL(sm);

    FAIL_IF_NOT(sm->type == DETECT_PCRE);
    FAIL_IF_NULL(sm->prev);
    FAIL_IF_NOT(sm->prev->type == DETECT_CONTENT);

    DetectContentData *huad1 = (DetectContentData *)sm->prev->ctx;
    DetectPcreData *pd2 = (DetectPcreData *)sm->ctx;
    FAIL_IF_NOT(pd2->flags == (DETECT_PCRE_RELATIVE));
    FAIL_IF_NOT(huad1->flags == DETECT_CONTENT_RELATIVE_NEXT);
    FAIL_IF_NOT(memcmp(huad1->content, "two", huad1->content_len) == 0);

    DetectEngineCtxFree(de_ctx);
    PASS;
}

static int DetectHttpUATest36(void)
{
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    de_ctx->flags |= DE_QUIET;

    Signature *s =
            DetectEngineAppendSig(de_ctx, "alert tcp any any -> any any "
                                          "(pcre:/one/V; "
                                          "content:\"two\"; distance:5; http_user_agent; sid:1;)");
    FAIL_IF_NULL(s);
    FAIL_IF_NOT_NULL(s->sm_lists[DETECT_SM_LIST_PMATCH]);
    SigMatch *sm = s->sm_lists_tail[g_http_ua_buffer_id];
    FAIL_IF_NULL(sm);

    FAIL_IF(sm->type != DETECT_CONTENT);
    FAIL_IF_NULL(sm->prev);
    FAIL_IF_NOT(sm->prev->type == DETECT_PCRE);

    DetectPcreData *pd1 = (DetectPcreData *)sm->prev->ctx;
    DetectContentData *huad2 = (DetectContentData *)sm->ctx;
    FAIL_IF_NOT(pd1->flags == (DETECT_PCRE_RELATIVE_NEXT));
    FAIL_IF_NOT(huad2->flags == DETECT_CONTENT_DISTANCE);
    FAIL_IF_NOT(memcmp(huad2->content, "two", huad2->content_len) == 0);

    DetectEngineCtxFree(de_ctx);
    PASS;
}

static void DetectHttpUARegisterTests(void)
{
    UtRegisterTest("DetectEngineHttpUATest01", DetectEngineHttpUATest01);
    UtRegisterTest("DetectEngineHttpUATest02", DetectEngineHttpUATest02);
    UtRegisterTest("DetectEngineHttpUATest03", DetectEngineHttpUATest03);
    UtRegisterTest("DetectEngineHttpUATest04", DetectEngineHttpUATest04);
    UtRegisterTest("DetectEngineHttpUATest05", DetectEngineHttpUATest05);
    UtRegisterTest("DetectEngineHttpUATest06", DetectEngineHttpUATest06);
    UtRegisterTest("DetectEngineHttpUATest07", DetectEngineHttpUATest07);
    UtRegisterTest("DetectEngineHttpUATest08", DetectEngineHttpUATest08);
    UtRegisterTest("DetectEngineHttpUATest09", DetectEngineHttpUATest09);
    UtRegisterTest("DetectEngineHttpUATest10", DetectEngineHttpUATest10);
    UtRegisterTest("DetectEngineHttpUATest11", DetectEngineHttpUATest11);
    UtRegisterTest("DetectEngineHttpUATest12", DetectEngineHttpUATest12);
    UtRegisterTest("DetectEngineHttpUATest13", DetectEngineHttpUATest13);
    UtRegisterTest("DetectEngineHttpUATest14", DetectEngineHttpUATest14);
    UtRegisterTest("DetectEngineHttpUATest15", DetectEngineHttpUATest15);
    UtRegisterTest("DetectEngineHttpUATest16", DetectEngineHttpUATest16);
    UtRegisterTest("DetectEngineHttpUATest17", DetectEngineHttpUATest17);

    UtRegisterTest("DetectHttpUATest01", DetectHttpUATest01);
    UtRegisterTest("DetectHttpUATest02", DetectHttpUATest02);
    UtRegisterTest("DetectHttpUATest03", DetectHttpUATest03);
    UtRegisterTest("DetectHttpUATest04", DetectHttpUATest04);
    UtRegisterTest("DetectHttpUATest05", DetectHttpUATest05);
    UtRegisterTest("DetectHttpUATest06", DetectHttpUATest06);
    UtRegisterTest("DetectHttpUATest07", DetectHttpUATest07);
    UtRegisterTest("DetectHttpUATest08", DetectHttpUATest08);
    UtRegisterTest("DetectHttpUATest09", DetectHttpUATest09);
    UtRegisterTest("DetectHttpUATest10", DetectHttpUATest10);
    UtRegisterTest("DetectHttpUATest11", DetectHttpUATest11);
    UtRegisterTest("DetectHttpUATest12", DetectHttpUATest12);
    UtRegisterTest("DetectHttpUATest13", DetectHttpUATest13);
    UtRegisterTest("DetectHttpUATest14", DetectHttpUATest14);

    UtRegisterTest("DetectHttpUATest22", DetectHttpUATest22);
    UtRegisterTest("DetectHttpUATest23", DetectHttpUATest23);
    UtRegisterTest("DetectHttpUATest24", DetectHttpUATest24);
    UtRegisterTest("DetectHttpUATest25", DetectHttpUATest25);
    UtRegisterTest("DetectHttpUATest26", DetectHttpUATest26);
    UtRegisterTest("DetectHttpUATest27", DetectHttpUATest27);
    UtRegisterTest("DetectHttpUATest28", DetectHttpUATest28);
    UtRegisterTest("DetectHttpUATest29", DetectHttpUATest29);
    UtRegisterTest("DetectHttpUATest30", DetectHttpUATest30);
    UtRegisterTest("DetectHttpUATest31", DetectHttpUATest31);
    UtRegisterTest("DetectHttpUATest32", DetectHttpUATest32);
    UtRegisterTest("DetectHttpUATest33", DetectHttpUATest33);
    UtRegisterTest("DetectHttpUATest34", DetectHttpUATest34);
    UtRegisterTest("DetectHttpUATest35", DetectHttpUATest35);
    UtRegisterTest("DetectHttpUATest36", DetectHttpUATest36);
}

/**
 * @}
 */
