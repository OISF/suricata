/* Copyright (C) 2007-2016 Open Information Security Foundation
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
 * \brief Handle HTTP cookie match
 *
 */

#include "../suricata-common.h"
#include "../suricata.h"
#include "../flow-util.h"
#include "../flow.h"
#include "../app-layer-parser.h"
#include "../util-unittest.h"
#include "../util-unittest-helper.h"
#include "../app-layer.h"
#include "../app-layer-htp.h"
#include "../app-layer-protos.h"
#include "../detect-isdataat.h"
#include "../detect-engine-build.h"
#include "../detect-engine-alert.h"

/***********************************Unittests**********************************/

/**
 * \test Test that the http_cookie content matches against a http request
 *       which holds the content.
 */
static int DetectEngineHttpCookieTest01(void)
{
    TcpSession ssn;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx = NULL;
    Flow f;
    uint8_t http_buf[] = "GET /index.html HTTP/1.0\r\n"
                         "Cookie: CONNECT\r\n"
                         "Host: www.onetwothreefourfivesixseven.org\r\n\r\n";
    uint32_t http_len = sizeof(http_buf) - 1;
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
    p->flags |= PKT_HAS_FLOW | PKT_STREAM_EST;
    f.alproto = ALPROTO_HTTP1;

    StreamTcpInitConfig(true);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    de_ctx->flags |= DE_QUIET;

    Signature *s = DetectEngineAppendSig(de_ctx, "alert http any any -> any any "
                                                 "(msg:\"http header test\"; "
                                                 "content:\"CONNECT\"; http_cookie; "
                                                 "sid:1;)");
    FAIL_IF_NULL(s);

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParserParse(
            NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER, http_buf, http_len);
    FAIL_IF_NOT(r == 0);

    HtpState *http_state = f.alstate;
    FAIL_IF_NULL(http_state);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    FAIL_IF(!(PacketAlertCheck(p, 1)));

    FLOW_DESTROY(&f);
    UTHFreePackets(&p, 1);
    AppLayerParserThreadCtxFree(alp_tctx);
    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);
    StreamTcpFreeConfig(true);
    StatsThreadCleanup(&th_v);
    PASS;
}

/**
 * \test Test that the http_cookie content matches against a http request
 *       which holds the content.
 */
static int DetectEngineHttpCookieTest02(void)
{
    TcpSession ssn;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx = NULL;
    Flow f;
    uint8_t http_buf[] = "CONNECT /index.html HTTP/1.0\r\n"
                         "Cookie: CONNECT\r\n"
                         "Host: www.onetwothreefourfivesixseven.org\r\n\r\n";
    uint32_t http_len = sizeof(http_buf) - 1;
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
    p->flags |= PKT_HAS_FLOW | PKT_STREAM_EST;
    f.alproto = ALPROTO_HTTP1;

    StreamTcpInitConfig(true);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    de_ctx->flags |= DE_QUIET;

    Signature *s = DetectEngineAppendSig(de_ctx, "alert http any any -> any any "
                                                 "(msg:\"http header test\"; "
                                                 "content:\"CO\"; depth:4; http_cookie; "
                                                 "sid:1;)");
    FAIL_IF_NULL(s);

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParserParse(
            NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER, http_buf, http_len);
    FAIL_IF_NOT(r == 0);

    HtpState *http_state = f.alstate;
    FAIL_IF_NULL(http_state);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    FAIL_IF(!(PacketAlertCheck(p, 1)));

    FLOW_DESTROY(&f);
    UTHFreePackets(&p, 1);
    AppLayerParserThreadCtxFree(alp_tctx);
    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);
    StreamTcpFreeConfig(true);
    StatsThreadCleanup(&th_v);
    PASS;
}

/**
 * \test Test that the http_cookie content matches against a http request
 *       which holds the content.
 */
static int DetectEngineHttpCookieTest03(void)
{
    TcpSession ssn;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx = NULL;
    Flow f;
    uint8_t http_buf[] = "CONNECT /index.html HTTP/1.0\r\n"
                         "Cookie: CONNECT\r\n"
                         "Host: www.onetwothreefourfivesixseven.org\r\n\r\n";
    uint32_t http_len = sizeof(http_buf) - 1;
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
    p->flags |= PKT_HAS_FLOW | PKT_STREAM_EST;
    f.alproto = ALPROTO_HTTP1;

    StreamTcpInitConfig(true);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    de_ctx->flags |= DE_QUIET;

    Signature *s = DetectEngineAppendSig(de_ctx, "alert http any any -> any any "
                                                 "(msg:\"http header test\"; "
                                                 "content:!\"ECT\"; depth:4; http_cookie; "
                                                 "sid:1;)");
    FAIL_IF_NULL(s);

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParserParse(
            NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER, http_buf, http_len);
    FAIL_IF_NOT(r == 0);

    HtpState *http_state = f.alstate;
    FAIL_IF_NULL(http_state);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    FAIL_IF(!(PacketAlertCheck(p, 1)));

    FLOW_DESTROY(&f);
    UTHFreePackets(&p, 1);
    AppLayerParserThreadCtxFree(alp_tctx);
    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);
    StreamTcpFreeConfig(true);
    StatsThreadCleanup(&th_v);
    PASS;
}

/**
 * \test Test that the http_cookie content matches against a http request
 *       which holds the content.
 */
static int DetectEngineHttpCookieTest04(void)
{
    TcpSession ssn;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx = NULL;
    Flow f;
    uint8_t http_buf[] = "CONNECT /index.html HTTP/1.0\r\n"
                         "Cookie: CONNECT\r\n"
                         "Host: www.onetwothreefourfivesixseven.org\r\n\r\n";
    uint32_t http_len = sizeof(http_buf) - 1;
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
    p->flags |= PKT_HAS_FLOW | PKT_STREAM_EST;
    f.alproto = ALPROTO_HTTP1;

    StreamTcpInitConfig(true);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    de_ctx->flags |= DE_QUIET;

    Signature *s = DetectEngineAppendSig(de_ctx, "alert http any any -> any any "
                                                 "(msg:\"http header test\"; "
                                                 "content:\"ECT\"; depth:4; http_cookie; "
                                                 "sid:1;)");
    FAIL_IF_NULL(s);

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParserParse(
            NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER, http_buf, http_len);
    FAIL_IF_NOT(r == 0);

    HtpState *http_state = f.alstate;
    FAIL_IF_NULL(http_state);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    FAIL_IF(PacketAlertCheck(p, 1));

    FLOW_DESTROY(&f);
    UTHFreePackets(&p, 1);
    AppLayerParserThreadCtxFree(alp_tctx);
    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);
    StreamTcpFreeConfig(true);
    StatsThreadCleanup(&th_v);
    PASS;
}

/**
 * \test Test that the http_cookie content matches against a http request
 *       which holds the content.
 */
static int DetectEngineHttpCookieTest05(void)
{
    TcpSession ssn;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx = NULL;
    Flow f;
    uint8_t http_buf[] = "CONNECT /index.html HTTP/1.0\r\n"
                         "Cookie: CONNECT\r\n"
                         "Host: www.onetwothreefourfivesixseven.org\r\n\r\n";
    uint32_t http_len = sizeof(http_buf) - 1;
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
    p->flags |= PKT_HAS_FLOW | PKT_STREAM_EST;
    f.alproto = ALPROTO_HTTP1;

    StreamTcpInitConfig(true);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    de_ctx->flags |= DE_QUIET;

    Signature *s = DetectEngineAppendSig(de_ctx, "alert http any any -> any any "
                                                 "(msg:\"http header test\"; "
                                                 "content:!\"CON\"; depth:4; http_cookie; "
                                                 "sid:1;)");
    FAIL_IF_NULL(s);

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParserParse(
            NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER, http_buf, http_len);
    FAIL_IF_NOT(r == 0);

    HtpState *http_state = f.alstate;
    FAIL_IF_NULL(http_state);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    FAIL_IF(PacketAlertCheck(p, 1));

    FLOW_DESTROY(&f);
    UTHFreePackets(&p, 1);
    AppLayerParserThreadCtxFree(alp_tctx);
    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);
    StreamTcpFreeConfig(true);
    StatsThreadCleanup(&th_v);
    PASS;
}

/**
 * \test Test that the http_cookie content matches against a http request
 *       which holds the content.
 */
static int DetectEngineHttpCookieTest06(void)
{
    TcpSession ssn;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx = NULL;
    Flow f;
    uint8_t http_buf[] = "CONNECT /index.html HTTP/1.0\r\n"
                         "Cookie: CONNECT\r\n"
                         "Host: www.onetwothreefourfivesixseven.org\r\n\r\n";
    uint32_t http_len = sizeof(http_buf) - 1;
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
    p->flags |= PKT_HAS_FLOW | PKT_STREAM_EST;
    f.alproto = ALPROTO_HTTP1;

    StreamTcpInitConfig(true);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    de_ctx->flags |= DE_QUIET;

    Signature *s = DetectEngineAppendSig(de_ctx, "alert http any any -> any any "
                                                 "(msg:\"http header test\"; "
                                                 "content:\"ECT\"; offset:3; http_cookie; "
                                                 "sid:1;)");
    FAIL_IF_NULL(s);

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParserParse(
            NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER, http_buf, http_len);
    FAIL_IF_NOT(r == 0);

    HtpState *http_state = f.alstate;
    FAIL_IF_NULL(http_state);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    FAIL_IF(!(PacketAlertCheck(p, 1)));

    UTHFreePackets(&p, 1);
    FLOW_DESTROY(&f);
    AppLayerParserThreadCtxFree(alp_tctx);
    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);
    StreamTcpFreeConfig(true);
    StatsThreadCleanup(&th_v);
    PASS;
}

/**
 * \test Test that the http_cookie content matches against a http request
 *       which holds the content.
 */
static int DetectEngineHttpCookieTest07(void)
{
    TcpSession ssn;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx = NULL;
    Flow f;
    uint8_t http_buf[] = "CONNECT /index.html HTTP/1.0\r\n"
                         "Cookie: CONNECT\r\n"
                         "Host: www.onetwothreefourfivesixseven.org\r\n\r\n";
    uint32_t http_len = sizeof(http_buf) - 1;
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
    p->flags |= PKT_HAS_FLOW | PKT_STREAM_EST;
    f.alproto = ALPROTO_HTTP1;

    StreamTcpInitConfig(true);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    de_ctx->flags |= DE_QUIET;

    Signature *s = DetectEngineAppendSig(de_ctx, "alert http any any -> any any "
                                                 "(msg:\"http header test\"; "
                                                 "content:!\"CO\"; offset:3; http_cookie; "
                                                 "sid:1;)");
    FAIL_IF_NULL(s);

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParserParse(
            NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER, http_buf, http_len);
    FAIL_IF_NOT(r == 0);

    HtpState *http_state = f.alstate;
    FAIL_IF_NULL(http_state);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    FAIL_IF(!(PacketAlertCheck(p, 1)));

    AppLayerParserThreadCtxFree(alp_tctx);
    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);
    StreamTcpFreeConfig(true);
    UTHFreePackets(&p, 1);
    FLOW_DESTROY(&f);
    StatsThreadCleanup(&th_v);
    PASS;
}

/**
 * \test Test that the http_cookie content matches against a http request
 *       which holds the content.
 */
static int DetectEngineHttpCookieTest08(void)
{
    TcpSession ssn;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx = NULL;
    Flow f;
    uint8_t http_buf[] = "CONNECT /index.html HTTP/1.0\r\n"
                         "Cookie: CONNECT\r\n"
                         "Host: www.onetwothreefourfivesixseven.org\r\n\r\n";
    uint32_t http_len = sizeof(http_buf) - 1;
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
    p->flags |= PKT_HAS_FLOW | PKT_STREAM_EST;
    f.alproto = ALPROTO_HTTP1;

    StreamTcpInitConfig(true);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    de_ctx->flags |= DE_QUIET;

    Signature *s = DetectEngineAppendSig(de_ctx, "alert http any any -> any any "
                                                 "(msg:\"http header test\"; "
                                                 "content:!\"ECT\"; offset:3; http_cookie; "
                                                 "sid:1;)");
    FAIL_IF_NULL(s);

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParserParse(
            NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER, http_buf, http_len);
    FAIL_IF_NOT(r == 0);

    HtpState *http_state = f.alstate;
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

/**
 * \test Test that the http_cookie content matches against a http request
 *       which holds the content.
 */
static int DetectEngineHttpCookieTest09(void)
{
    TcpSession ssn;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx = NULL;
    Flow f;
    uint8_t http_buf[] = "CONNECT /index.html HTTP/1.0\r\n"
                         "Cookie: CONNECT\r\n"
                         "Host: www.onetwothreefourfivesixseven.org\r\n\r\n";
    uint32_t http_len = sizeof(http_buf) - 1;
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
    p->flags |= PKT_HAS_FLOW | PKT_STREAM_EST;
    f.alproto = ALPROTO_HTTP1;

    StreamTcpInitConfig(true);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    de_ctx->flags |= DE_QUIET;

    Signature *s = DetectEngineAppendSig(de_ctx, "alert http any any -> any any "
                                                 "(msg:\"http header test\"; "
                                                 "content:\"CON\"; offset:3; http_cookie; "
                                                 "sid:1;)");
    FAIL_IF_NULL(s);

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParserParse(
            NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER, http_buf, http_len);
    FAIL_IF_NOT(r == 0);

    HtpState *http_state = f.alstate;
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

/**
 * \test Test that the http_cookie content matches against a http request
 *       which holds the content.
 */
static int DetectEngineHttpCookieTest10(void)
{
    TcpSession ssn;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx = NULL;
    Flow f;
    uint8_t http_buf[] = "CONNECT /index.html HTTP/1.0\r\n"
                         "Cookie: CONNECT\r\n"
                         "Host: www.onetwothreefourfivesixseven.org\r\n\r\n";
    uint32_t http_len = sizeof(http_buf) - 1;
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
    p->flags |= PKT_HAS_FLOW | PKT_STREAM_EST;
    f.alproto = ALPROTO_HTTP1;

    StreamTcpInitConfig(true);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    de_ctx->flags |= DE_QUIET;

    Signature *s = DetectEngineAppendSig(de_ctx, "alert http any any -> any any "
                                                 "(msg:\"http header test\"; "
                                                 "content:\"CO\"; http_cookie; "
                                                 "content:\"EC\"; within:4; http_cookie; "
                                                 "sid:1;)");
    FAIL_IF_NULL(s);

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParserParse(
            NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER, http_buf, http_len);
    FAIL_IF_NOT(r == 0);

    HtpState *http_state = f.alstate;
    FAIL_IF_NULL(http_state);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    FAIL_IF(!PacketAlertCheck(p, 1));

    UTHFreePackets(&p, 1);
    FLOW_DESTROY(&f);
    AppLayerParserThreadCtxFree(alp_tctx);
    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);
    StreamTcpFreeConfig(true);
    StatsThreadCleanup(&th_v);
    PASS;
}

/**
 * \test Test that the http_cookie content matches against a http request
 *       which holds the content.
 */
static int DetectEngineHttpCookieTest11(void)
{
    TcpSession ssn;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx = NULL;
    Flow f;
    uint8_t http_buf[] = "CONNECT /index.html HTTP/1.0\r\n"
                         "Cookie: CONNECT\r\n"
                         "Host: www.onetwothreefourfivesixseven.org\r\n\r\n";
    uint32_t http_len = sizeof(http_buf) - 1;
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
    p->flags |= PKT_HAS_FLOW | PKT_STREAM_EST;
    f.alproto = ALPROTO_HTTP1;

    StreamTcpInitConfig(true);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    de_ctx->flags |= DE_QUIET;

    Signature *s = DetectEngineAppendSig(de_ctx, "alert http any any -> any any "
                                                 "(msg:\"http header test\"; "
                                                 "content:\"CO\"; http_cookie; "
                                                 "content:!\"EC\"; within:3; http_cookie; "
                                                 "sid:1;)");
    FAIL_IF_NULL(s);

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParserParse(
            NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER, http_buf, http_len);
    FAIL_IF_NOT(r == 0);

    HtpState *http_state = f.alstate;
    FAIL_IF_NULL(http_state);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    FAIL_IF(!PacketAlertCheck(p, 1));

    UTHFreePackets(&p, 1);
    FLOW_DESTROY(&f);
    AppLayerParserThreadCtxFree(alp_tctx);
    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);
    StreamTcpFreeConfig(true);
    StatsThreadCleanup(&th_v);
    PASS;
}

/**
 * \test Test that the http_cookie content matches against a http request
 *       which holds the content.
 */
static int DetectEngineHttpCookieTest12(void)
{
    TcpSession ssn;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx = NULL;
    Flow f;
    uint8_t http_buf[] = "CONNECT /index.html HTTP/1.0\r\n"
                         "Cookie: CONNECT\r\n"
                         "Host: www.onetwothreefourfivesixseven.org\r\n\r\n";
    uint32_t http_len = sizeof(http_buf) - 1;
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
    p->flags |= PKT_HAS_FLOW | PKT_STREAM_EST;
    f.alproto = ALPROTO_HTTP1;

    StreamTcpInitConfig(true);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    de_ctx->flags |= DE_QUIET;

    Signature *s = DetectEngineAppendSig(de_ctx, "alert http any any -> any any "
                                                 "(msg:\"http header test\"; "
                                                 "content:\"CO\"; http_cookie; "
                                                 "content:\"EC\"; within:3; http_cookie; "
                                                 "sid:1;)");
    FAIL_IF_NULL(s);

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParserParse(
            NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER, http_buf, http_len);
    FAIL_IF_NOT(r == 0);

    HtpState *http_state = f.alstate;
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

/**
 * \test Test that the http_cookie content matches against a http request
 *       which holds the content.
 */
static int DetectEngineHttpCookieTest13(void)
{
    TcpSession ssn;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx = NULL;
    Flow f;
    uint8_t http_buf[] = "CONNECT /index.html HTTP/1.0\r\n"
                         "Cookie: CONNECT\r\n"
                         "Host: www.onetwothreefourfivesixseven.org\r\n\r\n";
    uint32_t http_len = sizeof(http_buf) - 1;
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
    p->flags |= PKT_HAS_FLOW | PKT_STREAM_EST;
    f.alproto = ALPROTO_HTTP1;

    StreamTcpInitConfig(true);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    de_ctx->flags |= DE_QUIET;

    Signature *s = DetectEngineAppendSig(de_ctx, "alert http any any -> any any "
                                                 "(msg:\"http header test\"; "
                                                 "content:\"CO\"; http_cookie; "
                                                 "content:!\"EC\"; within:4; http_cookie; "
                                                 "sid:1;)");
    FAIL_IF_NULL(s);

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParserParse(
            NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER, http_buf, http_len);
    FAIL_IF_NOT(r == 0);

    HtpState *http_state = f.alstate;
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

/**
 * \test Test that the http_cookie content matches against a http request
 *       which holds the content.
 */
static int DetectEngineHttpCookieTest14(void)
{
    TcpSession ssn;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx = NULL;
    Flow f;
    uint8_t http_buf[] = "CONNECT /index.html HTTP/1.0\r\n"
                         "Cookie: CONNECT\r\n"
                         "Host: www.onetwothreefourfivesixseven.org\r\n\r\n";
    uint32_t http_len = sizeof(http_buf) - 1;
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
    p->flags |= PKT_HAS_FLOW | PKT_STREAM_EST;
    f.alproto = ALPROTO_HTTP1;

    StreamTcpInitConfig(true);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    de_ctx->flags |= DE_QUIET;

    Signature *s = DetectEngineAppendSig(de_ctx, "alert http any any -> any any "
                                                 "(msg:\"http header test\"; "
                                                 "content:\"CO\"; http_cookie; "
                                                 "content:\"EC\"; distance:2; http_cookie; "
                                                 "sid:1;)");
    FAIL_IF_NULL(s);

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParserParse(
            NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER, http_buf, http_len);
    FAIL_IF_NOT(r == 0);

    HtpState *http_state = f.alstate;
    FAIL_IF_NULL(http_state);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    FAIL_IF(!PacketAlertCheck(p, 1));

    UTHFreePackets(&p, 1);
    FLOW_DESTROY(&f);
    AppLayerParserThreadCtxFree(alp_tctx);
    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);
    StreamTcpFreeConfig(true);
    StatsThreadCleanup(&th_v);
    PASS;
}

/**
 * \test Test that the http_cookie content matches against a http request
 *       which holds the content.
 */
static int DetectEngineHttpCookieTest15(void)
{
    TcpSession ssn;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx = NULL;
    Flow f;
    uint8_t http_buf[] = "CONNECT /index.html HTTP/1.0\r\n"
                         "Cookie: CONNECT\r\n"
                         "Host: www.onetwothreefourfivesixseven.org\r\n\r\n";
    uint32_t http_len = sizeof(http_buf) - 1;
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
    p->flags |= PKT_HAS_FLOW | PKT_STREAM_EST;
    f.alproto = ALPROTO_HTTP1;

    StreamTcpInitConfig(true);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    de_ctx->flags |= DE_QUIET;

    Signature *s = DetectEngineAppendSig(de_ctx, "alert http any any -> any any "
                                                 "(msg:\"http header test\"; "
                                                 "content:\"CO\"; http_cookie; "
                                                 "content:!\"EC\"; distance:3; http_cookie; "
                                                 "sid:1;)");
    FAIL_IF_NULL(s);

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParserParse(
            NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER, http_buf, http_len);
    FAIL_IF_NOT(r == 0);

    HtpState *http_state = f.alstate;
    FAIL_IF_NULL(http_state);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    FAIL_IF(!PacketAlertCheck(p, 1));

    UTHFreePackets(&p, 1);
    FLOW_DESTROY(&f);
    AppLayerParserThreadCtxFree(alp_tctx);
    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);
    StreamTcpFreeConfig(true);
    StatsThreadCleanup(&th_v);
    PASS;
}

/**
 * \test Test that the http_cookie content matches against a http request
 *       which holds the content.
 */
static int DetectEngineHttpCookieTest16(void)
{
    TcpSession ssn;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx = NULL;
    Flow f;
    uint8_t http_buf[] = "CONNECT /index.html HTTP/1.0\r\n"
                         "Cookie: CONNECT\r\n"
                         "Host: www.onetwothreefourfivesixseven.org\r\n\r\n";
    uint32_t http_len = sizeof(http_buf) - 1;
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
    p->flags |= PKT_HAS_FLOW | PKT_STREAM_EST;
    f.alproto = ALPROTO_HTTP1;

    StreamTcpInitConfig(true);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    de_ctx->flags |= DE_QUIET;

    Signature *s = DetectEngineAppendSig(de_ctx, "alert http any any -> any any "
                                                 "(msg:\"http header test\"; "
                                                 "content:\"CO\"; http_cookie; "
                                                 "content:\"EC\"; distance:3; http_cookie; "
                                                 "sid:1;)");
    FAIL_IF_NULL(s);

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParserParse(
            NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER, http_buf, http_len);
    FAIL_IF_NOT(r == 0);

    HtpState *http_state = f.alstate;
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

/**
 * \test Test that the http_cookie content matches against a http request
 *       which holds the content.
 */
static int DetectEngineHttpCookieTest17(void)
{
    TcpSession ssn;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx = NULL;
    Flow f;
    uint8_t http_buf[] = "CONNECT /index.html HTTP/1.0\r\n"
                         "Cookie: CONNECT\r\n"
                         "Host: www.onetwothreefourfivesixseven.org\r\n\r\n";
    uint32_t http_len = sizeof(http_buf) - 1;
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
    p->flags |= PKT_HAS_FLOW | PKT_STREAM_EST;
    f.alproto = ALPROTO_HTTP1;

    StreamTcpInitConfig(true);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    de_ctx->flags |= DE_QUIET;

    Signature *s = DetectEngineAppendSig(de_ctx, "alert http any any -> any any "
                                                 "(msg:\"http header test\"; "
                                                 "content:\"CO\"; http_cookie; "
                                                 "content:!\"EC\"; distance:2; http_cookie; "
                                                 "sid:1;)");
    FAIL_IF_NULL(s);

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParserParse(
            NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER, http_buf, http_len);
    FAIL_IF_NOT(r == 0);

    HtpState *http_state = f.alstate;
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

/**
 * \test Checks if a http_cookie is registered in a Signature, if content is not
 *       specified in the signature
 */
static int DetectHttpCookieTest01(void)
{
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    de_ctx->flags |= DE_QUIET;
    Signature *s =
            DetectEngineAppendSig(de_ctx, "alert tcp any any -> any any "
                                          "(msg:\"Testing http_cookie\"; http_cookie;sid:1;)");
    FAIL_IF_NOT_NULL(s);
    DetectEngineCtxFree(de_ctx);
    PASS;
}

/**
 * \test Checks if a http_cookie is registered in a Signature, if some parameter
 *       is specified with http_cookie in the signature
 */
static int DetectHttpCookieTest02(void)
{
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    de_ctx->flags |= DE_QUIET;
    Signature *s = DetectEngineAppendSig(de_ctx, "alert tcp any any -> any any "
                                                 "(msg:\"Testing http_cookie\"; content:\"me\"; "
                                                 "http_cookie:woo; sid:1;)");
    FAIL_IF_NOT_NULL(s);
    DetectEngineCtxFree(de_ctx);
    PASS;
}

/** \test Check the signature working to alert when http_cookie is matched . */
static int DetectHttpCookieSigTest01(void)
{
    Flow f;
    uint8_t httpbuf1[] = "POST / HTTP/1.0\r\nUser-Agent: Mozilla/1.0\r\nCookie:"
                         " hellocatchme\r\n\r\n";
    uint32_t httplen1 = sizeof(httpbuf1) - 1; /* minus the \0 */
    TcpSession ssn;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx = NULL;
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
    p->flags |= PKT_HAS_FLOW | PKT_STREAM_EST;
    f.alproto = ALPROTO_HTTP1;

    StreamTcpInitConfig(true);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    de_ctx->flags |= DE_QUIET;

    Signature *s = DetectEngineAppendSig(de_ctx, "alert http any any -> any any (msg:"
                                                 "\"HTTP cookie\"; content:\"me\"; "
                                                 "http_cookie; sid:1;)");
    FAIL_IF_NULL(s);

    s = DetectEngineAppendSig(de_ctx, "alert http any any -> any any (msg:\"HTTP "
                                      "cookie\"; content:\"go\"; http_cookie; sid:2;)");
    FAIL_IF_NULL(s);

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParserParse(
            NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER, httpbuf1, httplen1);
    FAIL_IF_NOT(r == 0);

    HtpState *http_state = f.alstate;
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

/** \test Check the signature working to alert when http_cookie is not present */
static int DetectHttpCookieSigTest02(void)
{
    Flow f;
    uint8_t httpbuf1[] = "POST / HTTP/1.0\r\nUser-Agent: Mozilla/1.0\r\n\r\n";
    uint32_t httplen1 = sizeof(httpbuf1) - 1; /* minus the \0 */
    TcpSession ssn;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx = NULL;
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
    p->flags |= PKT_HAS_FLOW | PKT_STREAM_EST;
    f.alproto = ALPROTO_HTTP1;

    StreamTcpInitConfig(true);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    de_ctx->flags |= DE_QUIET;

    Signature *s = DetectEngineAppendSig(de_ctx, "alert http any any -> any any (msg:"
                                                 "\"HTTP cookie\"; content:\"me\"; "
                                                 "http_cookie; sid:1;)");
    FAIL_IF_NULL(s);

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParserParse(
            NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER, httpbuf1, httplen1);
    FAIL_IF_NOT(r == 0);

    HtpState *http_state = f.alstate;
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

/** \test Check the signature working to alert when http_cookie is not present */
static int DetectHttpCookieSigTest03(void)
{
    Flow f;
    uint8_t httpbuf1[] = "POST / HTTP/1.0\r\nUser-Agent: Mozilla/1.0\r\n"
                         "Cookie: dummy\r\n\r\n";
    uint32_t httplen1 = sizeof(httpbuf1) - 1; /* minus the \0 */
    TcpSession ssn;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx = NULL;
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
    p->flags |= PKT_HAS_FLOW | PKT_STREAM_EST;
    f.alproto = ALPROTO_HTTP1;

    StreamTcpInitConfig(true);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    de_ctx->flags |= DE_QUIET;

    Signature *s = DetectEngineAppendSig(de_ctx, "alert http any any -> any any (msg:"
                                                 "\"HTTP cookie\"; content:\"boo\"; "
                                                 "http_cookie; sid:1;)");
    FAIL_IF_NULL(s);

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParserParse(
            NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER, httpbuf1, httplen1);
    FAIL_IF_NOT(r == 0);

    HtpState *http_state = f.alstate;
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

/** \test Check the signature working to alert when http_cookie is not present */
static int DetectHttpCookieSigTest04(void)
{
    Flow f;
    uint8_t httpbuf1[] = "POST / HTTP/1.0\r\nUser-Agent: Mozilla/1.0\r\n"
                         "Cookie: dummy\r\n\r\n";
    uint32_t httplen1 = sizeof(httpbuf1) - 1; /* minus the \0 */
    TcpSession ssn;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx = NULL;
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
    p->flags |= PKT_HAS_FLOW | PKT_STREAM_EST;
    f.alproto = ALPROTO_HTTP1;

    StreamTcpInitConfig(true);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    de_ctx->flags |= DE_QUIET;

    Signature *s = DetectEngineAppendSig(de_ctx, "alert http any any -> any any (msg:"
                                                 "\"HTTP cookie\"; content:!\"boo\"; "
                                                 "http_cookie; sid:1;)");
    FAIL_IF_NULL(s);

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParserParse(
            NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER, httpbuf1, httplen1);
    FAIL_IF_NOT(r == 0);

    HtpState *http_state = f.alstate;
    FAIL_IF_NULL(http_state);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    FAIL_IF(!PacketAlertCheck(p, 1));

    UTHFreePackets(&p, 1);
    FLOW_DESTROY(&f);
    AppLayerParserThreadCtxFree(alp_tctx);
    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);
    StreamTcpFreeConfig(true);
    StatsThreadCleanup(&th_v);
    PASS;
}

/** \test Check the signature working to alert when http_cookie is not present */
static int DetectHttpCookieSigTest05(void)
{
    Flow f;
    uint8_t httpbuf1[] = "POST / HTTP/1.0\r\nUser-Agent: Mozilla/1.0\r\n"
                         "Cookie: DuMmY\r\n\r\n";
    uint32_t httplen1 = sizeof(httpbuf1) - 1; /* minus the \0 */
    TcpSession ssn;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx = NULL;
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
    p->flags |= PKT_HAS_FLOW | PKT_STREAM_EST;
    f.alproto = ALPROTO_HTTP1;

    StreamTcpInitConfig(true);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    de_ctx->flags |= DE_QUIET;

    Signature *s = DetectEngineAppendSig(de_ctx, "alert http any any -> any any (msg:"
                                                 "\"HTTP cookie\"; content:\"dummy\"; nocase; "
                                                 "http_cookie; sid:1;)");
    FAIL_IF_NULL(s);

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParserParse(
            NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER, httpbuf1, httplen1);
    FAIL_IF_NOT(r == 0);

    HtpState *http_state = f.alstate;
    FAIL_IF_NULL(http_state);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    FAIL_IF(!PacketAlertCheck(p, 1));

    UTHFreePackets(&p, 1);
    FLOW_DESTROY(&f);
    AppLayerParserThreadCtxFree(alp_tctx);
    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);
    StreamTcpFreeConfig(true);
    StatsThreadCleanup(&th_v);
    PASS;
}

/** \test Check the signature working to alert when http_cookie is not present */
static int DetectHttpCookieSigTest06(void)
{
    Flow f;
    uint8_t httpbuf1[] = "POST / HTTP/1.0\r\nUser-Agent: Mozilla/1.0\r\n"
                         "Cookie: DuMmY\r\n\r\n";
    uint32_t httplen1 = sizeof(httpbuf1) - 1; /* minus the \0 */
    TcpSession ssn;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx = NULL;
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
    p->flags |= PKT_HAS_FLOW | PKT_STREAM_EST;
    f.alproto = ALPROTO_HTTP1;

    StreamTcpInitConfig(true);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    de_ctx->flags |= DE_QUIET;

    Signature *s = DetectEngineAppendSig(de_ctx, "alert http any any -> any any (msg:"
                                                 "\"HTTP cookie\"; content:\"dummy\"; "
                                                 "http_cookie; nocase; sid:1;)");
    FAIL_IF_NULL(s);

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParserParse(
            NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER, httpbuf1, httplen1);
    FAIL_IF_NOT(r == 0);

    HtpState *http_state = f.alstate;
    FAIL_IF_NULL(http_state);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    FAIL_IF(!PacketAlertCheck(p, 1));

    UTHFreePackets(&p, 1);
    FLOW_DESTROY(&f);
    AppLayerParserThreadCtxFree(alp_tctx);
    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);
    StreamTcpFreeConfig(true);
    StatsThreadCleanup(&th_v);
    PASS;
}

/** \test Check the signature working to alert when http_cookie is not present */
static int DetectHttpCookieSigTest07(void)
{
    Flow f;
    uint8_t httpbuf1[] = "POST / HTTP/1.0\r\nUser-Agent: Mozilla/1.0\r\n"
                         "Cookie: dummy\r\n\r\n";
    uint32_t httplen1 = sizeof(httpbuf1) - 1; /* minus the \0 */
    TcpSession ssn;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx = NULL;
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
    p->flags |= PKT_HAS_FLOW | PKT_STREAM_EST;
    f.alproto = ALPROTO_HTTP1;

    StreamTcpInitConfig(true);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    de_ctx->flags |= DE_QUIET;

    Signature *s = DetectEngineAppendSig(de_ctx, "alert http any any -> any any (msg:"
                                                 "\"HTTP cookie\"; content:!\"dummy\"; "
                                                 "http_cookie; sid:1;)");
    FAIL_IF_NULL(s);

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParserParse(
            NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER, httpbuf1, httplen1);
    FAIL_IF_NOT(r == 0);

    HtpState *http_state = f.alstate;
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

/**
 * \test Check the signature working to alert against set-cookie
 */
static int DetectHttpCookieSigTest08(void)
{
    uint8_t httpbuf_request[] = "GET / HTTP/1.1\r\n"
                                "User-Agent: Mozilla/1.0\r\n"
                                "\r\n";
    uint32_t httpbuf_request_len = sizeof(httpbuf_request) - 1; /* minus the \0 */

    uint8_t httpbuf_response[] = "HTTP/1.1 200 OK\r\n"
                                 "Set-Cookie: response_user_agent\r\n"
                                 "\r\n";
    uint32_t httpbuf_response_len = sizeof(httpbuf_response) - 1; /* minus the \0 */

    Flow f;
    TcpSession ssn;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx = NULL;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&th_v, 0, sizeof(th_v));
    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;
    f.flags |= FLOW_IPV4;
    f.alproto = ALPROTO_HTTP1;

    Packet *p1 = UTHBuildPacket(NULL, 0, IPPROTO_TCP);
    p1->flow = &f;
    p1->flowflags |= FLOW_PKT_TOSERVER;
    p1->flowflags |= FLOW_PKT_ESTABLISHED;
    p1->flags |= PKT_HAS_FLOW | PKT_STREAM_EST;

    Packet *p2 = UTHBuildPacket(NULL, 0, IPPROTO_TCP);
    p2->flow = &f;
    p2->flowflags |= FLOW_PKT_TOCLIENT;
    p2->flowflags |= FLOW_PKT_ESTABLISHED;
    p2->flags |= PKT_HAS_FLOW | PKT_STREAM_EST;

    StreamTcpInitConfig(true);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    de_ctx->flags |= DE_QUIET;

    Signature *s =
            DetectEngineAppendSig(de_ctx, "alert http any any -> any any "
                                          "(flow:to_client; content:\"response_user_agent\"; "
                                          "http_cookie; sid:1;)");
    FAIL_IF_NULL(s);

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    /* request */
    int r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER, httpbuf_request,
            httpbuf_request_len);
    FAIL_IF(r != 0);

    HtpState *http_state = f.alstate;
    FAIL_IF_NULL(http_state);

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p1);
    FAIL_IF(PacketAlertCheck(p1, 1));

    /* response */
    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOCLIENT, httpbuf_response,
            httpbuf_response_len);
    FAIL_IF(r != 0);

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p2);
    FAIL_IF(!PacketAlertCheck(p2, 1));

    UTHFreePackets(&p1, 1);
    UTHFreePackets(&p2, 1);
    FLOW_DESTROY(&f);

    AppLayerParserThreadCtxFree(alp_tctx);
    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);
    StreamTcpFreeConfig(true);
    StatsThreadCleanup(&th_v);
    PASS;
}

/**
 * \test Check the signature working to alert against cookie/set-cookie
 */
static int DetectHttpCookieSigTest09(void)
{
    uint8_t httpbuf_request[] = "GET / HTTP/1.1\r\n"
                                "Cookie: request_user_agent\r\n"
                                "User-Agent: Mozilla/1.0\r\n"
                                "\r\n";
    uint32_t httpbuf_request_len = sizeof(httpbuf_request) - 1; /* minus the \0 */

    uint8_t httpbuf_response[] = "HTTP/1.1 200 OK\r\n"
                                 "Set-Cookie: response_user_agent\r\n"
                                 "\r\n";
    uint32_t httpbuf_response_len = sizeof(httpbuf_response) - 1; /* minus the \0 */
    Flow f;
    TcpSession ssn;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx = NULL;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&th_v, 0, sizeof(th_v));
    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;
    f.flags |= FLOW_IPV4;
    f.alproto = ALPROTO_HTTP1;

    Packet *p1 = UTHBuildPacket(NULL, 0, IPPROTO_TCP);
    p1->flow = &f;
    p1->flowflags |= FLOW_PKT_TOSERVER;
    p1->flowflags |= FLOW_PKT_ESTABLISHED;
    p1->flags |= PKT_HAS_FLOW | PKT_STREAM_EST;

    Packet *p2 = UTHBuildPacket(NULL, 0, IPPROTO_TCP);
    p2->flow = &f;
    p2->flowflags |= FLOW_PKT_TOCLIENT;
    p2->flowflags |= FLOW_PKT_ESTABLISHED;
    p2->flags |= PKT_HAS_FLOW | PKT_STREAM_EST;

    StreamTcpInitConfig(true);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    de_ctx->flags |= DE_QUIET;

    Signature *s = DetectEngineAppendSig(de_ctx, "alert http any any -> any any "
                                                 "(flow:to_server; content:\"request_user_agent\"; "
                                                 "http_cookie; sid:1;)");
    FAIL_IF_NULL(s);
    s = DetectEngineAppendSig(de_ctx, "alert http any any -> any any "
                                      "(flow:to_client; content:\"response_user_agent\"; "
                                      "http_cookie; sid:2;)");
    FAIL_IF_NULL(s);

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    /* request */
    int r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER, httpbuf_request,
            httpbuf_request_len);
    FAIL_IF_NOT(r == 0);

    HtpState *http_state = f.alstate;
    FAIL_IF_NULL(http_state);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p1);
    FAIL_IF(!PacketAlertCheck(p1, 1));
    FAIL_IF(PacketAlertCheck(p1, 2));

    /* response */
    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOCLIENT, httpbuf_response,
            httpbuf_response_len);
    FAIL_IF_NOT(r == 0);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p2);
    FAIL_IF(PacketAlertCheck(p2, 1));
    FAIL_IF(!PacketAlertCheck(p2, 2));

    UTHFreePackets(&p1, 1);
    UTHFreePackets(&p2, 1);
    FLOW_DESTROY(&f);
    AppLayerParserThreadCtxFree(alp_tctx);
    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);
    StreamTcpFreeConfig(true);
    StatsThreadCleanup(&th_v);
    PASS;
}

/**
 * \brief   Register the UNITTESTS for the http_cookie keyword
 */
void DetectHttpCookieRegisterTests(void)
{
    UtRegisterTest("DetectHttpCookieTest01", DetectHttpCookieTest01);
    UtRegisterTest("DetectHttpCookieTest02", DetectHttpCookieTest02);
    UtRegisterTest("DetectHttpCookieSigTest01", DetectHttpCookieSigTest01);
    UtRegisterTest("DetectHttpCookieSigTest02", DetectHttpCookieSigTest02);
    UtRegisterTest("DetectHttpCookieSigTest03", DetectHttpCookieSigTest03);
    UtRegisterTest("DetectHttpCookieSigTest04", DetectHttpCookieSigTest04);
    UtRegisterTest("DetectHttpCookieSigTest05", DetectHttpCookieSigTest05);
    UtRegisterTest("DetectHttpCookieSigTest06", DetectHttpCookieSigTest06);
    UtRegisterTest("DetectHttpCookieSigTest07", DetectHttpCookieSigTest07);
    UtRegisterTest("DetectHttpCookieSigTest08", DetectHttpCookieSigTest08);
    UtRegisterTest("DetectHttpCookieSigTest09", DetectHttpCookieSigTest09);
    UtRegisterTest("DetectEngineHttpCookieTest01", DetectEngineHttpCookieTest01);
    UtRegisterTest("DetectEngineHttpCookieTest02", DetectEngineHttpCookieTest02);
    UtRegisterTest("DetectEngineHttpCookieTest03", DetectEngineHttpCookieTest03);
    UtRegisterTest("DetectEngineHttpCookieTest04", DetectEngineHttpCookieTest04);
    UtRegisterTest("DetectEngineHttpCookieTest05", DetectEngineHttpCookieTest05);
    UtRegisterTest("DetectEngineHttpCookieTest06", DetectEngineHttpCookieTest06);
    UtRegisterTest("DetectEngineHttpCookieTest07", DetectEngineHttpCookieTest07);
    UtRegisterTest("DetectEngineHttpCookieTest08", DetectEngineHttpCookieTest08);
    UtRegisterTest("DetectEngineHttpCookieTest09", DetectEngineHttpCookieTest09);
    UtRegisterTest("DetectEngineHttpCookieTest10", DetectEngineHttpCookieTest10);
    UtRegisterTest("DetectEngineHttpCookieTest11", DetectEngineHttpCookieTest11);
    UtRegisterTest("DetectEngineHttpCookieTest12", DetectEngineHttpCookieTest12);
    UtRegisterTest("DetectEngineHttpCookieTest13", DetectEngineHttpCookieTest13);
    UtRegisterTest("DetectEngineHttpCookieTest14", DetectEngineHttpCookieTest14);
    UtRegisterTest("DetectEngineHttpCookieTest15", DetectEngineHttpCookieTest15);
    UtRegisterTest("DetectEngineHttpCookieTest16", DetectEngineHttpCookieTest16);
    UtRegisterTest("DetectEngineHttpCookieTest17", DetectEngineHttpCookieTest17);
}
/**
 * @}
 */
