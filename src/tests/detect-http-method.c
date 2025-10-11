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


/** \file
 *
 * \author Anoop Saldanha <anoopsaldanha@gmail.com>
 *
 * \brief Handle HTTP method match
 *
 */

#include "../suricata-common.h"
#include "../suricata.h"
#include "../flow-util.h"
#include "../flow.h"
#include "../app-layer-parser.h"
#include "../conf.h"
#include "../conf-yaml-loader.h"
#include "../util-unittest.h"
#include "../util-unittest-helper.h"
#include "../app-layer.h"
#include "../app-layer-htp.h"
#include "../app-layer-protos.h"
#include "../detect-isdataat.h"
#include "../detect-engine-build.h"
#include "../detect-engine-alert.h"

struct TestSteps {
    const uint8_t *input;
    size_t input_size; /**< if 0 strlen will be used */
    int direction;     /**< STREAM_TOSERVER, STREAM_TOCLIENT */
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
        SCConfCreateContextBackup();
        SCConfInit();
        HtpConfigCreateBackup();

        SCConfYamlLoadString(yaml, strlen(yaml));
        HTPConfigure();
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
        (void)i;
        Packet *p = UTHBuildPacket(NULL, 0, IPPROTO_TCP);
        FAIL_IF_NULL(p);
        p->flow = &f;
        p->flowflags = (b->direction == STREAM_TOSERVER) ? FLOW_PKT_TOSERVER : FLOW_PKT_TOCLIENT;
        p->flowflags |= FLOW_PKT_ESTABLISHED;
        p->flags |= PKT_HAS_FLOW | PKT_STREAM_EST;

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
        HTPFreeConfig();
        SCConfDeInit();
        HtpConfigRestoreBackup();
        SCConfRestoreContextBackup();
    }
    StatsThreadCleanup(&th_v);
    PASS;
}

static int DetectEngineHttpMethodTest01(void)
{
    struct TestSteps steps[] = {
        { (const uint8_t *)"GET /index.html HTTP/1.1\r\n"
                           "Host: www.openinfosecfoundation.org\r\n"
                           "\r\n",
                0, STREAM_TOSERVER, 1 },
        { NULL, 0, 0, 0 },
    };

    const char *sig = "alert http any any -> any any (content:\"GET\"; http_method; sid:1;)";
    return RunTest(steps, sig, NULL);
}

static int DetectEngineHttpMethodTest02(void)
{
    struct TestSteps steps[] = {
        { (const uint8_t *)"CONNECT /index.html HTTP/1.0\r\n"
                           "Host: www.onetwothreefourfivesixseven.org\r\n\r\n",
                0, STREAM_TOSERVER, 1 },
        { NULL, 0, 0, 0 },
    };

    const char *sig =
            "alert http any any -> any any (content:\"CO\"; depth:4; http_method; sid:1;)";
    return RunTest(steps, sig, NULL);
}

static int DetectEngineHttpMethodTest03(void)
{
    struct TestSteps steps[] = {
        { (const uint8_t *)"CONNECT /index.html HTTP/1.0\r\n"
                           "Host: www.onetwothreefourfivesixseven.org\r\n\r\n",
                0, STREAM_TOSERVER, 1 },
        { NULL, 0, 0, 0 },
    };

    const char *sig =
            "alert http any any -> any any (content:!\"ECT\";  depth:4; http_method; sid:1;)";
    return RunTest(steps, sig, NULL);
}

static int DetectEngineHttpMethodTest04(void)
{
    struct TestSteps steps[] = {
        { (const uint8_t *)"CONNECT /index.html HTTP/1.0\r\n"
                           "Host: www.onetwothreefourfivesixseven.org\r\n\r\n",
                0, STREAM_TOSERVER, 0 },
        { NULL, 0, 0, 0 },
    };

    const char *sig =
            "alert http any any -> any any (content:\"ECT\";  depth:4; http_method; sid:1;)";
    return RunTest(steps, sig, NULL);
}

static int DetectEngineHttpMethodTest05(void)
{
    struct TestSteps steps[] = {
        { (const uint8_t *)"CONNECT /index.html HTTP/1.0\r\n"
                           "Host: www.onetwothreefourfivesixseven.org\r\n\r\n",
                0, STREAM_TOSERVER, 0 },
        { NULL, 0, 0, 0 },
    };

    const char *sig =
            "alert http any any -> any any (content:!\"CON\";  depth:4; http_method; sid:1;)";
    return RunTest(steps, sig, NULL);
}

static int DetectEngineHttpMethodTest06(void)
{
    struct TestSteps steps[] = {
        { (const uint8_t *)"CONNECT /index.html HTTP/1.0\r\n"
                           "Host: www.onetwothreefourfivesixseven.org\r\n\r\n",
                0, STREAM_TOSERVER, 1 },
        { NULL, 0, 0, 0 },
    };

    const char *sig =
            "alert http any any -> any any (content:\"ECT\"; offset:3; http_method; sid:1;)";
    return RunTest(steps, sig, NULL);
}

static int DetectEngineHttpMethodTest07(void)
{
    struct TestSteps steps[] = {
        { (const uint8_t *)"CONNECT /index.html HTTP/1.0\r\n"
                           "Host: www.onetwothreefourfivesixseven.org\r\n\r\n",
                0, STREAM_TOSERVER, 1 },
        { NULL, 0, 0, 0 },
    };

    const char *sig =
            "alert http any any -> any any (content:!\"CO\"; offset:3; http_method; sid:1;)";
    return RunTest(steps, sig, NULL);
}

static int DetectEngineHttpMethodTest08(void)
{
    struct TestSteps steps[] = {
        { (const uint8_t *)"CONNECT /index.html HTTP/1.0\r\n"
                           "Host: www.onetwothreefourfivesixseven.org\r\n\r\n",
                0, STREAM_TOSERVER, 0 },
        { NULL, 0, 0, 0 },
    };

    const char *sig =
            "alert http any any -> any any (content:!\"ECT\"; offset:3; http_method; sid:1;)";
    return RunTest(steps, sig, NULL);
}

static int DetectEngineHttpMethodTest09(void)
{
    struct TestSteps steps[] = {
        { (const uint8_t *)"CONNECT /index.html HTTP/1.0\r\n"
                           "Host: www.onetwothreefourfivesixseven.org\r\n\r\n",
                0, STREAM_TOSERVER, 0 },
        { NULL, 0, 0, 0 },
    };

    const char *sig =
            "alert http any any -> any any (content:\"CON\"; offset:3; http_method; sid:1;)";
    return RunTest(steps, sig, NULL);
}

static int DetectEngineHttpMethodTest10(void)
{
    struct TestSteps steps[] = {
        { (const uint8_t *)"CONNECT /index.html HTTP/1.0\r\n"
                           "Host: www.onetwothreefourfivesixseven.org\r\n\r\n",
                0, STREAM_TOSERVER, 1 },
        { NULL, 0, 0, 0 },
    };

    const char *sig = "alert http any any -> any any (content:\"CO\"; http_method; content:\"EC\"; "
                      "within:4; http_method;  sid:1;)";
    return RunTest(steps, sig, NULL);
}

static int DetectEngineHttpMethodTest11(void)
{
    struct TestSteps steps[] = {
        { (const uint8_t *)"CONNECT /index.html HTTP/1.0\r\n"
                           "Host: www.onetwothreefourfivesixseven.org\r\n\r\n",
                0, STREAM_TOSERVER, 1 },
        { NULL, 0, 0, 0 },
    };

    const char *sig = "alert http any any -> any any (content:\"CO\"; http_method; "
                      "content:!\"EC\"; within:3; http_method;  sid:1;)";
    return RunTest(steps, sig, NULL);
}

static int DetectEngineHttpMethodTest12(void)
{
    struct TestSteps steps[] = {
        { (const uint8_t *)"CONNECT /index.html HTTP/1.0\r\n"
                           "Host: www.onetwothreefourfivesixseven.org\r\n\r\n",
                0, STREAM_TOSERVER, 0 },
        { NULL, 0, 0, 0 },
    };

    const char *sig = "alert http any any -> any any (content:\"CO\"; http_method; content:\"EC\"; "
                      "within:3; http_method;  sid:1;)";
    return RunTest(steps, sig, NULL);
}

static int DetectEngineHttpMethodTest13(void)
{
    struct TestSteps steps[] = {
        { (const uint8_t *)"CONNECT /index.html HTTP/1.0\r\n"
                           "Host: www.onetwothreefourfivesixseven.org\r\n\r\n",
                0, STREAM_TOSERVER, 0 },
        { NULL, 0, 0, 0 },
    };

    const char *sig = "alert http any any -> any any (content:\"CO\"; http_method; "
                      "content:!\"EC\"; within:4; http_method;  sid:1;)";
    return RunTest(steps, sig, NULL);
}

static int DetectEngineHttpMethodTest14(void)
{
    struct TestSteps steps[] = {
        { (const uint8_t *)"CONNECT /index.html HTTP/1.0\r\n"
                           "Host: www.onetwothreefourfivesixseven.org\r\n\r\n",
                0, STREAM_TOSERVER, 1 },
        { NULL, 0, 0, 0 },
    };

    const char *sig = "alert http any any -> any any (content:\"CO\"; http_method; content:\"EC\"; "
                      "distance:2; http_method;  sid:1;)";
    return RunTest(steps, sig, NULL);
}

static int DetectEngineHttpMethodTest15(void)
{
    struct TestSteps steps[] = {
        { (const uint8_t *)"CONNECT /index.html HTTP/1.0\r\n"
                           "Host: www.onetwothreefourfivesixseven.org\r\n\r\n",
                0, STREAM_TOSERVER, 1 },
        { NULL, 0, 0, 0 },
    };

    const char *sig = "alert http any any -> any any (content:\"CO\"; http_method; "
                      "content:!\"EC\"; distance:3; http_method;  sid:1;)";
    return RunTest(steps, sig, NULL);
}

static int DetectEngineHttpMethodTest16(void)
{
    struct TestSteps steps[] = {
        { (const uint8_t *)"CONNECT /index.html HTTP/1.0\r\n"
                           "Host: www.onetwothreefourfivesixseven.org\r\n\r\n",
                0, STREAM_TOSERVER, 0 },
        { NULL, 0, 0, 0 },
    };

    const char *sig = "alert http any any -> any any (content:\"CO\"; http_method; content:\"EC\"; "
                      "distance:3; http_method; sid:1;)";
    return RunTest(steps, sig, NULL);
}

static int DetectEngineHttpMethodTest17(void)
{
    struct TestSteps steps[] = {
        { (const uint8_t *)"CONNECT /index.html HTTP/1.0\r\n"
                           "Host: www.onetwothreefourfivesixseven.org\r\n\r\n",
                0, STREAM_TOSERVER, 0 },
        { NULL, 0, 0, 0 },
    };

    const char *sig = "alert http any any -> any any (content:\"CO\"; http_method; "
                      "content:!\"EC\"; distance:2; http_method;  sid:1;)";
    return RunTest(steps, sig, NULL);
}

/** \test Check a signature with content */
static int DetectHttpMethodTest01(void)
{
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    de_ctx->flags |= DE_QUIET;
    Signature *s = DetectEngineAppendSig(de_ctx, "alert tcp any any -> any any "
                                                 "(msg:\"Testing http_method\"; "
                                                 "content:\"GET\"; "
                                                 "http_method; sid:1;)");
    FAIL_IF_NULL(s);
    DetectEngineCtxFree(de_ctx);
    PASS;
}

/** \test Check a signature without content (fail) */
static int DetectHttpMethodTest02(void)
{
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    de_ctx->flags |= DE_QUIET;
    Signature *s = DetectEngineAppendSig(de_ctx, "alert tcp any any -> any any "
                                                 "(msg:\"Testing http_method\"; "
                                                 "http_method; sid:1;)");
    FAIL_IF_NOT_NULL(s);
    DetectEngineCtxFree(de_ctx);
    PASS;
}

/** \test Check a signature with parameter (fail) */
static int DetectHttpMethodTest03(void)
{
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    de_ctx->flags |= DE_QUIET;
    Signature *s = DetectEngineAppendSig(de_ctx, "alert tcp any any -> any any "
                                                 "(msg:\"Testing http_method\"; "
                                                 "content:\"foobar\"; "
                                                 "http_method:\"GET\"; sid:1;)");
    FAIL_IF_NOT_NULL(s);
    DetectEngineCtxFree(de_ctx);
    PASS;
}

/** \test Check a signature with fast_pattern (should work) */
static int DetectHttpMethodTest04(void)
{
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    de_ctx->flags |= DE_QUIET;
    Signature *s = DetectEngineAppendSig(de_ctx, "alert tcp any any -> any any "
                                                 "(msg:\"Testing http_method\"; "
                                                 "content:\"GET\"; "
                                                 "fast_pattern; "
                                                 "http_method; sid:1;)");
    FAIL_IF_NULL(s);
    DetectEngineCtxFree(de_ctx);
    PASS;
}

/** \test Check a signature with rawbytes (fail) */
static int DetectHttpMethodTest05(void)
{
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    de_ctx->flags |= DE_QUIET;
    Signature *s = DetectEngineAppendSig(de_ctx, "alert tcp any any -> any any "
                                                 "(msg:\"Testing http_method\"; "
                                                 "content:\"GET\"; "
                                                 "rawbytes; "
                                                 "http_method; sid:1;)");
    FAIL_IF_NOT_NULL(s);
    DetectEngineCtxFree(de_ctx);
    PASS;
}

/** \test Check a signature with an known request method */
static int DetectHttpMethodSigTest01(void)
{
    Flow f;
    uint8_t httpbuf1[] = "GET / HTTP/1.0\r\n"
                         "Host: foo.bar.tld\r\n"
                         "\r\n";
    uint32_t httplen1 = sizeof(httpbuf1) - 1; /* minus the \0 */
    TcpSession ssn;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx;
    HtpState *http_state = NULL;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&th_v, 0, sizeof(th_v));
    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    Packet *p = UTHBuildPacket(NULL, 0, IPPROTO_TCP);

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

    Signature *s = DetectEngineAppendSig(de_ctx, "alert tcp any any -> any any "
                                                 "(msg:\"Testing http_method\"; "
                                                 "content:\"GET\"; "
                                                 "http_method; sid:1;)");
    FAIL_IF_NULL(s);
    s = DetectEngineAppendSig(de_ctx, "alert tcp any any -> any any "
                                      "(msg:\"Testing http_method\"; "
                                      "content:\"POST\"; "
                                      "http_method; sid:2;)");
    FAIL_IF_NULL(s);

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParserParse(
            NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER, httpbuf1, httplen1);
    FAIL_IF(r != 0);

    http_state = f.alstate;
    FAIL_IF_NULL(http_state);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);

    FAIL_IF(!(PacketAlertCheck(p, 1)));
    FAIL_IF(PacketAlertCheck(p, 2));

    UTHFreePackets(&p, 1);
    FLOW_DESTROY(&f);

    AppLayerParserThreadCtxFree(alp_tctx);
    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);
    StreamTcpFreeConfig(true);
    StatsThreadCleanup(&th_v);
    PASS;
}

/** \test Check a signature with an unknown request method */
static int DetectHttpMethodSigTest02(void)
{
    Flow f;
    uint8_t httpbuf1[] = "FOO / HTTP/1.0\r\n"
                         "Host: foo.bar.tld\r\n"
                         "\r\n";
    uint32_t httplen1 = sizeof(httpbuf1) - 1; /* minus the \0 */
    TcpSession ssn;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx = NULL;
    HtpState *http_state = NULL;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&th_v, 0, sizeof(th_v));
    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    Packet *p = UTHBuildPacket(NULL, 0, IPPROTO_TCP);

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

    Signature *s = DetectEngineAppendSig(de_ctx, "alert tcp any any -> any any "
                                                 "(msg:\"Testing http_method\"; "
                                                 "content:\"FOO\"; "
                                                 "http_method; sid:1;)");
    FAIL_IF_NULL(s);
    s = DetectEngineAppendSig(de_ctx, "alert tcp any any -> any any "
                                      "(msg:\"Testing http_method\"; "
                                      "content:\"BAR\"; "
                                      "http_method; sid:2;)");
    FAIL_IF_NULL(s);

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParserParse(
            NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER, httpbuf1, httplen1);
    FAIL_IF(r != 0);
    http_state = f.alstate;
    FAIL_IF_NULL(http_state);
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);

    FAIL_IF(!(PacketAlertCheck(p, 1)));
    FAIL_IF(PacketAlertCheck(p, 2));

    UTHFreePackets(&p, 1);
    FLOW_DESTROY(&f);

    AppLayerParserThreadCtxFree(alp_tctx);
    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);
    StreamTcpFreeConfig(true);
    StatsThreadCleanup(&th_v);
    PASS;
}

/** \test Check a signature against an unparsable request */
static int DetectHttpMethodSigTest03(void)
{
    Flow f;
    uint8_t httpbuf1[] = " ";
    uint32_t httplen1 = sizeof(httpbuf1) - 1; /* minus the \0 */
    TcpSession ssn;
    Packet *p = NULL;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx;
    HtpState *http_state = NULL;
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

    Signature *s = DetectEngineAppendSig(de_ctx, "alert tcp any any -> any any "
                                                 "(msg:\"Testing http_method\"; "
                                                 "content:\"GET\"; "
                                                 "http_method; sid:1;)");
    FAIL_IF_NULL(s);

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParserParse(
            NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER, httpbuf1, httplen1);
    FAIL_IF(r != 0);
    http_state = f.alstate;
    FAIL_IF_NULL(http_state);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    FAIL_IF(PacketAlertCheck(p, 1));

    UTHFreePackets(&p, 1);
    FLOW_DESTROY(&f);
    AppLayerParserThreadCtxFree(alp_tctx);
    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);
    StreamTcpFreeConfig(true);
    StatsThreadCleanup(&th_v);
    PASS;
}

/** \test Check a signature with an request method and negation of the same */
static int DetectHttpMethodSigTest04(void)
{
    Flow f;
    uint8_t httpbuf1[] = "GET / HTTP/1.0\r\n"
                         "Host: foo.bar.tld\r\n"
                         "\r\n";
    uint32_t httplen1 = sizeof(httpbuf1) - 1; /* minus the \0 */
    TcpSession ssn;
    Packet *p = NULL;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx = NULL;
    HtpState *http_state = NULL;
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
            "alert tcp any any -> any any (msg:\"Testing http_method\"; "
            "content:\"GET\"; http_method; sid:1;)");
    FAIL_IF_NULL(s);

    s = DetectEngineAppendSig(de_ctx, "alert tcp any any -> any any (msg:\"Testing http_method\"; "
                                      "content:!\"GET\"; http_method; sid:2;)");
    FAIL_IF_NULL(s);

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParserParse(
            NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER, httpbuf1, httplen1);
    FAIL_IF(r != 0);

    http_state = f.alstate;
    FAIL_IF_NULL(http_state);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);

    FAIL_IF(!(PacketAlertCheck(p, 1)));
    FAIL_IF(PacketAlertCheck(p, 2));

    UTHFreePackets(&p, 1);
    FLOW_DESTROY(&f);
    AppLayerParserThreadCtxFree(alp_tctx);
    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);
    StreamTcpFreeConfig(true);
    StatsThreadCleanup(&th_v);
    PASS;
}

static int DetectHttpMethodIsdataatParseTest(void)
{
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    de_ctx->flags |= DE_QUIET;

    Signature *s = DetectEngineAppendSig(de_ctx,
            "alert tcp any any -> any any ("
            "content:\"one\"; http_method; "
            "isdataat:!4,relative; sid:1;)");
    FAIL_IF_NULL(s);

    SigMatch *sm = DetectBufferGetLastSigMatch(s, g_http_method_buffer_id);
    FAIL_IF_NULL(sm);
    FAIL_IF_NOT(sm->type == DETECT_ISDATAAT);

    DetectIsdataatData *data = (DetectIsdataatData *)sm->ctx;
    FAIL_IF_NOT(data->flags & ISDATAAT_RELATIVE);
    FAIL_IF_NOT(data->flags & ISDATAAT_NEGATED);
    FAIL_IF(data->flags & ISDATAAT_RAWBYTES);

    DetectEngineCtxFree(de_ctx);
    PASS;
}

/**
 * \brief this function registers unit tests for DetectHttpMethod
 */
void DetectHttpMethodRegisterTests(void)
{
    UtRegisterTest("DetectHttpMethodTest01", DetectHttpMethodTest01);
    UtRegisterTest("DetectHttpMethodTest02", DetectHttpMethodTest02);
    UtRegisterTest("DetectHttpMethodTest03", DetectHttpMethodTest03);
    UtRegisterTest("DetectHttpMethodTest04", DetectHttpMethodTest04);
    UtRegisterTest("DetectHttpMethodTest05", DetectHttpMethodTest05);
    UtRegisterTest("DetectHttpMethodSigTest01", DetectHttpMethodSigTest01);
    UtRegisterTest("DetectHttpMethodSigTest02", DetectHttpMethodSigTest02);
    UtRegisterTest("DetectHttpMethodSigTest03", DetectHttpMethodSigTest03);
    UtRegisterTest("DetectHttpMethodSigTest04", DetectHttpMethodSigTest04);

    UtRegisterTest("DetectHttpMethodIsdataatParseTest",
            DetectHttpMethodIsdataatParseTest);
    UtRegisterTest("DetectEngineHttpMethodTest01",
                   DetectEngineHttpMethodTest01);
    UtRegisterTest("DetectEngineHttpMethodTest02",
                   DetectEngineHttpMethodTest02);
    UtRegisterTest("DetectEngineHttpMethodTest03",
                   DetectEngineHttpMethodTest03);
    UtRegisterTest("DetectEngineHttpMethodTest04",
                   DetectEngineHttpMethodTest04);
    UtRegisterTest("DetectEngineHttpMethodTest05",
                   DetectEngineHttpMethodTest05);
    UtRegisterTest("DetectEngineHttpMethodTest06",
                   DetectEngineHttpMethodTest06);
    UtRegisterTest("DetectEngineHttpMethodTest07",
                   DetectEngineHttpMethodTest07);
    UtRegisterTest("DetectEngineHttpMethodTest08",
                   DetectEngineHttpMethodTest08);
    UtRegisterTest("DetectEngineHttpMethodTest09",
                   DetectEngineHttpMethodTest09);
    UtRegisterTest("DetectEngineHttpMethodTest10",
                   DetectEngineHttpMethodTest10);
    UtRegisterTest("DetectEngineHttpMethodTest11",
                   DetectEngineHttpMethodTest11);
    UtRegisterTest("DetectEngineHttpMethodTest12",
                   DetectEngineHttpMethodTest12);
    UtRegisterTest("DetectEngineHttpMethodTest13",
                   DetectEngineHttpMethodTest13);
    UtRegisterTest("DetectEngineHttpMethodTest14",
                   DetectEngineHttpMethodTest14);
    UtRegisterTest("DetectEngineHttpMethodTest15",
                   DetectEngineHttpMethodTest15);
    UtRegisterTest("DetectEngineHttpMethodTest16",
                   DetectEngineHttpMethodTest16);
    UtRegisterTest("DetectEngineHttpMethodTest17",
                   DetectEngineHttpMethodTest17);
}

/**
 * @}
 */
