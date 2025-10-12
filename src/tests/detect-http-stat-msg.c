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

/**
 * \file
 *
 * \author Anoop Saldanha <anoopsaldanha@gmail.com>
 * \author Victor Julien <victor@inliniac.net>
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
#include "../detect-engine-build.h"
#include "../detect-engine-alert.h"

static int DetectEngineHttpStatMsgTest01(void)
{
    TcpSession ssn;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx = NULL;
    Flow f;
    uint8_t http_buf1[] = "GET /index.html HTTP/1.0\r\n"
                          "Host: www.openinfosecfoundation.org\r\n"
                          "User-Agent: Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.1.7) "
                          "Gecko/20091221 Firefox/3.5.7\r\n"
                          "\r\n";
    uint32_t http_len1 = sizeof(http_buf1) - 1;
    uint8_t http_buf2[] = "HTTP/1.0 200 message\r\n"
                          "Content-Type: text/html\r\n"
                          "Content-Length: 7\r\n"
                          "\r\n"
                          "message";
    uint32_t http_len2 = sizeof(http_buf2) - 1;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&th_v, 0, sizeof(th_v));
    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    Packet *p1 = UTHBuildPacket(NULL, 0, IPPROTO_TCP);
    Packet *p2 = UTHBuildPacket(NULL, 0, IPPROTO_TCP);

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;
    f.flags |= FLOW_IPV4;

    p1->flow = &f;
    p1->flowflags |= FLOW_PKT_TOSERVER;
    p1->flowflags |= FLOW_PKT_ESTABLISHED;
    p1->flags |= PKT_HAS_FLOW | PKT_STREAM_EST;
    p2->flow = &f;
    p2->flowflags |= FLOW_PKT_TOCLIENT;
    p2->flowflags |= FLOW_PKT_ESTABLISHED;
    p2->flags |= PKT_HAS_FLOW | PKT_STREAM_EST;
    f.alproto = ALPROTO_HTTP1;

    StreamTcpInitConfig(true);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    de_ctx->flags |= DE_QUIET;

    Signature *s = DetectEngineAppendSig(de_ctx, "alert http any any -> any any "
                                                 "(msg:\"http stat msg test\"; "
                                                 "content:\"message\"; http_stat_msg; "
                                                 "sid:1;)");
    FAIL_IF_NULL(s);

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParserParse(
            NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER, http_buf1, http_len1);
    FAIL_IF(r != 0);

    HtpState *http_state = f.alstate;
    FAIL_IF_NULL(http_state);

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p1);
    FAIL_IF(PacketAlertCheck(p1, 1));

    r = AppLayerParserParse(
            NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOCLIENT, http_buf2, http_len2);
    FAIL_IF(r != 0);

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p2);
    FAIL_IF(!(PacketAlertCheck(p2, 1)));

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

static int DetectEngineHttpStatMsgTest02(void)
{
    TcpSession ssn;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx = NULL;
    Flow f;
    uint8_t http_buf1[] = "GET /index.html HTTP/1.0\r\n"
                          "Host: www.openinfosecfoundation.org\r\n"
                          "User-Agent: Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.1.7) "
                          "Gecko/20091221 Firefox/3.5.7\r\n"
                          "\r\n";
    uint32_t http_len1 = sizeof(http_buf1) - 1;
    uint8_t http_buf2[] = "HTTP/1.0 200 xxxxABC\r\n"
                          "Content-Type: text/html\r\n"
                          "Content-Length: 7\r\n"
                          "\r\n"
                          "xxxxABC";
    uint32_t http_len2 = sizeof(http_buf2) - 1;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&th_v, 0, sizeof(th_v));
    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    Packet *p1 = UTHBuildPacket(NULL, 0, IPPROTO_TCP);

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;
    f.flags |= FLOW_IPV4;

    p1->flow = &f;
    p1->flowflags |= FLOW_PKT_TOCLIENT;
    p1->flowflags |= FLOW_PKT_ESTABLISHED;
    p1->flags |= PKT_HAS_FLOW | PKT_STREAM_EST;
    f.alproto = ALPROTO_HTTP1;

    StreamTcpInitConfig(true);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    de_ctx->flags |= DE_QUIET;

    Signature *s = DetectEngineAppendSig(de_ctx, "alert http any any -> any any "
                                                 "(msg:\"http stat msg test\"; "
                                                 "content:\"ABC\"; http_stat_msg; offset:4; "
                                                 "sid:1;)");
    FAIL_IF_NULL(s);

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParserParse(
            NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER, http_buf1, http_len1);
    FAIL_IF(r != 0);

    r = AppLayerParserParse(
            NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOCLIENT, http_buf2, http_len2);
    FAIL_IF(r != 0);

    HtpState *http_state = f.alstate;
    FAIL_IF_NULL(http_state);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p1);
    FAIL_IF(!(PacketAlertCheck(p1, 1)));

    UTHFreePackets(&p1, 1);
    FLOW_DESTROY(&f);

    AppLayerParserThreadCtxFree(alp_tctx);
    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);
    StreamTcpFreeConfig(true);
    StatsThreadCleanup(&th_v);
    PASS;
}

static int DetectEngineHttpStatMsgTest03(void)
{
    TcpSession ssn;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx = NULL;
    Flow f;
    uint8_t http_buf1[] = "GET /index.html HTTP/1.0\r\n"
                          "Host: www.openinfosecfoundation.org\r\n"
                          "User-Agent: Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.1.7) "
                          "Gecko/20091221 Firefox/3.5.7\r\n"
                          "\r\n";
    uint32_t http_len1 = sizeof(http_buf1) - 1;
    uint8_t http_buf2[] = "HTTP/1.0 200 1234567";
    uint32_t http_len2 = sizeof(http_buf2) - 1;
    uint8_t http_buf3[] = "8901234ABC\r\n"
                          "Content-Type: text/html\r\n"
                          "Content-Length: 17\r\n"
                          "\r\n"
                          "12345678901234ABC";
    uint32_t http_len3 = sizeof(http_buf3) - 1;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&th_v, 0, sizeof(th_v));
    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    Packet *p1 = UTHBuildPacket(NULL, 0, IPPROTO_TCP);
    Packet *p2 = UTHBuildPacket(NULL, 0, IPPROTO_TCP);

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;
    f.flags |= FLOW_IPV4;

    p1->flow = &f;
    p1->flowflags |= FLOW_PKT_TOSERVER;
    p1->flowflags |= FLOW_PKT_ESTABLISHED;
    p1->flags |= PKT_HAS_FLOW | PKT_STREAM_EST;
    p2->flow = &f;
    p2->flowflags |= FLOW_PKT_TOCLIENT;
    p2->flowflags |= FLOW_PKT_ESTABLISHED;
    p2->flags |= PKT_HAS_FLOW | PKT_STREAM_EST;
    f.alproto = ALPROTO_HTTP1;

    StreamTcpInitConfig(true);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    de_ctx->flags |= DE_QUIET;

    Signature *s = DetectEngineAppendSig(de_ctx, "alert http any any -> any any "
                                                 "(msg:\"http stat msg test\"; "
                                                 "content:\"ABC\"; http_stat_msg; offset:14; "
                                                 "sid:1;)");
    FAIL_IF_NULL(s);

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParserParse(
            NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER, http_buf1, http_len1);
    FAIL_IF_NOT(r == 0);

    HtpState *http_state = f.alstate;
    FAIL_IF_NULL(http_state);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p1);
    FAIL_IF(PacketAlertCheck(p1, 1));

    r = AppLayerParserParse(
            NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOCLIENT, http_buf2, http_len2);
    FAIL_IF_NOT(r == 0);

    r = AppLayerParserParse(
            NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOCLIENT, http_buf3, http_len3);
    FAIL_IF_NOT(r == 0);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p2);
    FAIL_IF(!(PacketAlertCheck(p2, 1)));

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

static int DetectEngineHttpStatMsgTest04(void)
{
    TcpSession ssn;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx = NULL;
    Flow f;
    uint8_t http_buf1[] = "GET /index.html HTTP/1.0\r\n"
                          "Host: www.openinfosecfoundation.org\r\n"
                          "User-Agent: Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.1.7) "
                          "Gecko/20091221 Firefox/3.5.7\r\n"
                          "\r\n";
    uint32_t http_len1 = sizeof(http_buf1) - 1;
    uint8_t http_buf2[] = "HTTP/1.0 200 abcdef\r\n"
                          "Content-Type: text/html\r\n"
                          "Content-Length: 6\r\n"
                          "\r\n"
                          "abcdef";
    uint32_t http_len2 = sizeof(http_buf2) - 1;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&th_v, 0, sizeof(th_v));
    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    Packet *p1 = UTHBuildPacket(NULL, 0, IPPROTO_TCP);
    Packet *p2 = UTHBuildPacket(NULL, 0, IPPROTO_TCP);

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;
    f.flags |= FLOW_IPV4;

    p1->flow = &f;
    p1->flowflags |= FLOW_PKT_TOSERVER;
    p1->flowflags |= FLOW_PKT_ESTABLISHED;
    p1->flags |= PKT_HAS_FLOW | PKT_STREAM_EST;
    p2->flow = &f;
    p2->flowflags |= FLOW_PKT_TOCLIENT;
    p2->flowflags |= FLOW_PKT_ESTABLISHED;
    p2->flags |= PKT_HAS_FLOW | PKT_STREAM_EST;
    f.alproto = ALPROTO_HTTP1;

    StreamTcpInitConfig(true);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    de_ctx->flags |= DE_QUIET;

    Signature *s = DetectEngineAppendSig(de_ctx, "alert http any any -> any any "
                                                 "(msg:\"http stat msg test\"; "
                                                 "content:!\"abc\"; http_stat_msg; offset:3; "
                                                 "sid:1;)");
    FAIL_IF_NULL(s);

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParserParse(
            NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER, http_buf1, http_len1);
    FAIL_IF_NOT(r == 0);

    HtpState *http_state = f.alstate;
    FAIL_IF_NULL(http_state);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p1);
    FAIL_IF(PacketAlertCheck(p1, 1));

    r = AppLayerParserParse(
            NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOCLIENT, http_buf2, http_len2);
    FAIL_IF_NOT(r == 0);

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

static int DetectEngineHttpStatMsgTest05(void)
{
    TcpSession ssn;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx = NULL;
    Flow f;
    uint8_t http_buf1[] = "GET /index.html HTTP/1.0\r\n"
                          "Host: www.openinfosecfoundation.org\r\n"
                          "User-Agent: Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.1.7) "
                          "Gecko/20091221 Firefox/3.5.7\r\n"
                          "\r\n";
    uint32_t http_len1 = sizeof(http_buf1) - 1;
    uint8_t http_buf2[] = "HTTP/1.0 200 abcdef\r\n"
                          "Content-Type: text/html\r\n"
                          "Content-Length: 6\r\n"
                          "\r\n"
                          "abcdef";
    uint32_t http_len2 = sizeof(http_buf2) - 1;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&th_v, 0, sizeof(th_v));
    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    Packet *p1 = UTHBuildPacket(NULL, 0, IPPROTO_TCP);
    Packet *p2 = UTHBuildPacket(NULL, 0, IPPROTO_TCP);

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;
    f.flags |= FLOW_IPV4;

    p1->flow = &f;
    p1->flowflags |= FLOW_PKT_TOSERVER;
    p1->flowflags |= FLOW_PKT_ESTABLISHED;
    p1->flags |= PKT_HAS_FLOW | PKT_STREAM_EST;
    p2->flow = &f;
    p2->flowflags |= FLOW_PKT_TOCLIENT;
    p2->flowflags |= FLOW_PKT_ESTABLISHED;
    p2->flags |= PKT_HAS_FLOW | PKT_STREAM_EST;
    f.alproto = ALPROTO_HTTP1;

    StreamTcpInitConfig(true);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    de_ctx->flags |= DE_QUIET;

    Signature *s = DetectEngineAppendSig(de_ctx, "alert http any any -> any any "
                                                 "(msg:\"http stat msg test\"; "
                                                 "content:\"abc\"; http_stat_msg; depth:3; "
                                                 "sid:1;)");
    FAIL_IF_NULL(s);

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParserParse(
            NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER, http_buf1, http_len1);
    FAIL_IF_NOT(r == 0);

    HtpState *http_state = f.alstate;
    FAIL_IF_NULL(http_state);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p1);
    FAIL_IF(PacketAlertCheck(p1, 1));

    r = AppLayerParserParse(
            NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOCLIENT, http_buf2, http_len2);
    FAIL_IF_NOT(r == 0);

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

static int DetectEngineHttpStatMsgTest06(void)
{
    TcpSession ssn;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx = NULL;
    Flow f;
    uint8_t http_buf1[] = "GET /index.html HTTP/1.0\r\n"
                          "Host: www.openinfosecfoundation.org\r\n"
                          "User-Agent: Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.1.7) "
                          "Gecko/20091221 Firefox/3.5.7\r\n"
                          "\r\n";
    uint32_t http_len1 = sizeof(http_buf1) - 1;
    uint8_t http_buf2[] = "HTTP/1.0 200 abcdef\r\n"
                          "Content-Type: text/html\r\n"
                          "Content-Length: 6\r\n"
                          "\r\n"
                          "abcdef";
    uint32_t http_len2 = sizeof(http_buf2) - 1;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&th_v, 0, sizeof(th_v));
    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    Packet *p1 = UTHBuildPacket(NULL, 0, IPPROTO_TCP);
    Packet *p2 = UTHBuildPacket(NULL, 0, IPPROTO_TCP);

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;
    f.flags |= FLOW_IPV4;

    p1->flow = &f;
    p1->flowflags |= FLOW_PKT_TOSERVER;
    p1->flowflags |= FLOW_PKT_ESTABLISHED;
    p1->flags |= PKT_HAS_FLOW | PKT_STREAM_EST;
    p2->flow = &f;
    p2->flowflags |= FLOW_PKT_TOCLIENT;
    p2->flowflags |= FLOW_PKT_ESTABLISHED;
    p2->flags |= PKT_HAS_FLOW | PKT_STREAM_EST;
    f.alproto = ALPROTO_HTTP1;

    StreamTcpInitConfig(true);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    de_ctx->flags |= DE_QUIET;

    Signature *s = DetectEngineAppendSig(de_ctx, "alert http any any -> any any "
                                                 "(msg:\"http stat msg test\"; "
                                                 "content:!\"def\"; http_stat_msg; depth:3; "
                                                 "sid:1;)");
    FAIL_IF_NULL(s);

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParserParse(
            NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER, http_buf1, http_len1);
    FAIL_IF_NOT(r == 0);

    HtpState *http_state = f.alstate;
    FAIL_IF_NULL(http_state);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p1);
    FAIL_IF(PacketAlertCheck(p1, 1));

    r = AppLayerParserParse(
            NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOCLIENT, http_buf2, http_len2);
    FAIL_IF_NOT(r == 0);

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

static int DetectEngineHttpStatMsgTest07(void)
{
    TcpSession ssn;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx = NULL;
    Flow f;
    uint8_t http_buf1[] = "GET /index.html HTTP/1.0\r\n"
                          "Host: www.openinfosecfoundation.org\r\n"
                          "User-Agent: Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.1.7) "
                          "Gecko/20091221 Firefox/3.5.7\r\n"
                          "\r\n";
    uint32_t http_len1 = sizeof(http_buf1) - 1;
    uint8_t http_buf2[] = "HTTP/1.0 200 abcdef\r\n"
                          "Content-Type: text/html\r\n"
                          "Content-Length: 6\r\n"
                          "\r\n"
                          "abcdef";
    uint32_t http_len2 = sizeof(http_buf2) - 1;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&th_v, 0, sizeof(th_v));
    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    Packet *p1 = UTHBuildPacket(NULL, 0, IPPROTO_TCP);
    Packet *p2 = UTHBuildPacket(NULL, 0, IPPROTO_TCP);

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;
    f.flags |= FLOW_IPV4;

    p1->flow = &f;
    p1->flowflags |= FLOW_PKT_TOSERVER;
    p1->flowflags |= FLOW_PKT_ESTABLISHED;
    p1->flags |= PKT_HAS_FLOW | PKT_STREAM_EST;
    p2->flow = &f;
    p2->flowflags |= FLOW_PKT_TOCLIENT;
    p2->flowflags |= FLOW_PKT_ESTABLISHED;
    p2->flags |= PKT_HAS_FLOW | PKT_STREAM_EST;
    f.alproto = ALPROTO_HTTP1;

    StreamTcpInitConfig(true);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    de_ctx->flags |= DE_QUIET;

    Signature *s = DetectEngineAppendSig(de_ctx, "alert http any any -> any any "
                                                 "(msg:\"http stat msg test\"; "
                                                 "content:!\"def\"; http_stat_msg; offset:3; "
                                                 "sid:1;)");
    FAIL_IF_NULL(s);

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParserParse(
            NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER, http_buf1, http_len1);
    FAIL_IF_NOT(r == 0);

    HtpState *http_state = f.alstate;
    FAIL_IF_NULL(http_state);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p1);
    FAIL_IF(PacketAlertCheck(p1, 1));

    r = AppLayerParserParse(
            NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOCLIENT, http_buf2, http_len2);
    FAIL_IF_NOT(r == 0);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p2);
    FAIL_IF(PacketAlertCheck(p2, 1));

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

static int DetectEngineHttpStatMsgTest08(void)
{
    TcpSession ssn;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx = NULL;
    Flow f;
    uint8_t http_buf1[] = "GET /index.html HTTP/1.0\r\n"
                          "Host: www.openinfosecfoundation.org\r\n"
                          "User-Agent: Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.1.7) "
                          "Gecko/20091221 Firefox/3.5.7\r\n"
                          "\r\n";
    uint32_t http_len1 = sizeof(http_buf1) - 1;
    uint8_t http_buf2[] = "HTTP/1.0 200 abcdef\r\n"
                          "Content-Type: text/html\r\n"
                          "Content-Length: 6\r\n"
                          "\r\n"
                          "abcdef";
    uint32_t http_len2 = sizeof(http_buf2) - 1;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&th_v, 0, sizeof(th_v));
    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    Packet *p1 = UTHBuildPacket(NULL, 0, IPPROTO_TCP);
    Packet *p2 = UTHBuildPacket(NULL, 0, IPPROTO_TCP);

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;
    f.flags |= FLOW_IPV4;

    p1->flow = &f;
    p1->flowflags |= FLOW_PKT_TOSERVER;
    p1->flowflags |= FLOW_PKT_ESTABLISHED;
    p1->flags |= PKT_HAS_FLOW | PKT_STREAM_EST;
    p2->flow = &f;
    p2->flowflags |= FLOW_PKT_TOCLIENT;
    p2->flowflags |= FLOW_PKT_ESTABLISHED;
    p2->flags |= PKT_HAS_FLOW | PKT_STREAM_EST;
    f.alproto = ALPROTO_HTTP1;

    StreamTcpInitConfig(true);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    de_ctx->flags |= DE_QUIET;

    Signature *s = DetectEngineAppendSig(de_ctx, "alert http any any -> any any "
                                                 "(msg:\"http stat msg test\"; "
                                                 "content:!\"abc\"; http_stat_msg; depth:3; "
                                                 "sid:1;)");
    FAIL_IF_NULL(s);

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParserParse(
            NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER, http_buf1, http_len1);
    FAIL_IF_NOT(r == 0);

    HtpState *http_state = f.alstate;
    FAIL_IF_NULL(http_state);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p1);
    FAIL_IF(PacketAlertCheck(p1, 1));

    r = AppLayerParserParse(
            NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOCLIENT, http_buf2, http_len2);
    FAIL_IF_NOT(r == 0);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p2);
    FAIL_IF(PacketAlertCheck(p2, 1));

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

static int DetectEngineHttpStatMsgTest09(void)
{
    TcpSession ssn;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx = NULL;
    Flow f;
    uint8_t http_buf1[] = "GET /index.html HTTP/1.0\r\n"
                          "Host: www.openinfosecfoundation.org\r\n"
                          "User-Agent: Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.1.7) "
                          "Gecko/20091221 Firefox/3.5.7\r\n"
                          "\r\n";
    uint32_t http_len1 = sizeof(http_buf1) - 1;
    uint8_t http_buf2[] = "HTTP/1.0 200 abcdef\r\n"
                          "Content-Type: text/html\r\n"
                          "Content-Length: 6\r\n"
                          "\r\n"
                          "abcdef";
    uint32_t http_len2 = sizeof(http_buf2) - 1;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&th_v, 0, sizeof(th_v));
    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    Packet *p1 = UTHBuildPacket(NULL, 0, IPPROTO_TCP);
    Packet *p2 = UTHBuildPacket(NULL, 0, IPPROTO_TCP);

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;
    f.flags |= FLOW_IPV4;

    p1->flow = &f;
    p1->flowflags |= FLOW_PKT_TOSERVER;
    p1->flowflags |= FLOW_PKT_ESTABLISHED;
    p1->flags |= PKT_HAS_FLOW | PKT_STREAM_EST;
    p2->flow = &f;
    p2->flowflags |= FLOW_PKT_TOCLIENT;
    p2->flowflags |= FLOW_PKT_ESTABLISHED;
    p2->flags |= PKT_HAS_FLOW | PKT_STREAM_EST;
    f.alproto = ALPROTO_HTTP1;

    StreamTcpInitConfig(true);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    de_ctx->flags |= DE_QUIET;

    Signature *s = DetectEngineAppendSig(de_ctx, "alert http any any -> any any "
                                                 "(msg:\"http stat msg test\"; "
                                                 "content:\"abc\"; http_stat_msg; depth:3; "
                                                 "content:\"def\"; http_stat_msg; within:3; "
                                                 "sid:1;)");
    FAIL_IF_NULL(s);

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParserParse(
            NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER, http_buf1, http_len1);
    FAIL_IF_NOT(r == 0);

    HtpState *http_state = f.alstate;
    FAIL_IF_NULL(http_state);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p1);
    FAIL_IF(PacketAlertCheck(p1, 1));

    r = AppLayerParserParse(
            NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOCLIENT, http_buf2, http_len2);
    FAIL_IF_NOT(r == 0);

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

static int DetectEngineHttpStatMsgTest10(void)
{
    TcpSession ssn;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx = NULL;
    Flow f;
    uint8_t http_buf1[] = "GET /index.html HTTP/1.0\r\n"
                          "Host: www.openinfosecfoundation.org\r\n"
                          "User-Agent: Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.1.7) "
                          "Gecko/20091221 Firefox/3.5.7\r\n"
                          "\r\n";
    uint32_t http_len1 = sizeof(http_buf1) - 1;
    uint8_t http_buf2[] = "HTTP/1.0 200 abcdef\r\n"
                          "Content-Type: text/html\r\n"
                          "Content-Length: 6\r\n"
                          "\r\n"
                          "abcdef";
    uint32_t http_len2 = sizeof(http_buf2) - 1;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&th_v, 0, sizeof(th_v));
    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    Packet *p1 = UTHBuildPacket(NULL, 0, IPPROTO_TCP);
    Packet *p2 = UTHBuildPacket(NULL, 0, IPPROTO_TCP);

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;
    f.flags |= FLOW_IPV4;

    p1->flow = &f;
    p1->flowflags |= FLOW_PKT_TOSERVER;
    p1->flowflags |= FLOW_PKT_ESTABLISHED;
    p1->flags |= PKT_HAS_FLOW | PKT_STREAM_EST;
    p2->flow = &f;
    p2->flowflags |= FLOW_PKT_TOCLIENT;
    p2->flowflags |= FLOW_PKT_ESTABLISHED;
    p2->flags |= PKT_HAS_FLOW | PKT_STREAM_EST;
    f.alproto = ALPROTO_HTTP1;

    StreamTcpInitConfig(true);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    de_ctx->flags |= DE_QUIET;

    Signature *s = DetectEngineAppendSig(de_ctx, "alert http any any -> any any "
                                                 "(msg:\"http stat msg test\"; "
                                                 "content:\"abc\"; http_stat_msg; depth:3; "
                                                 "content:!\"xyz\"; http_stat_msg; within:3; "
                                                 "sid:1;)");
    FAIL_IF_NULL(s);

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParserParse(
            NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER, http_buf1, http_len1);
    FAIL_IF_NOT(r == 0);

    HtpState *http_state = f.alstate;
    FAIL_IF_NULL(http_state);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p1);
    FAIL_IF(PacketAlertCheck(p1, 1));

    r = AppLayerParserParse(
            NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOCLIENT, http_buf2, http_len2);
    FAIL_IF_NOT(r == 0);

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

static int DetectEngineHttpStatMsgTest11(void)
{
    TcpSession ssn;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx = NULL;
    Flow f;
    uint8_t http_buf1[] = "GET /index.html HTTP/1.0\r\n"
                          "Host: www.openinfosecfoundation.org\r\n"
                          "User-Agent: Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.1.7) "
                          "Gecko/20091221 Firefox/3.5.7\r\n"
                          "\r\n";
    uint32_t http_len1 = sizeof(http_buf1) - 1;
    uint8_t http_buf2[] = "HTTP/1.0 200 abcdef\r\n"
                          "Content-Type: text/html\r\n"
                          "Content-Length: 6\r\n"
                          "\r\n"
                          "abcdef";
    uint32_t http_len2 = sizeof(http_buf2) - 1;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&th_v, 0, sizeof(th_v));
    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    Packet *p1 = UTHBuildPacket(NULL, 0, IPPROTO_TCP);
    Packet *p2 = UTHBuildPacket(NULL, 0, IPPROTO_TCP);

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;
    f.flags |= FLOW_IPV4;

    p1->flow = &f;
    p1->flowflags |= FLOW_PKT_TOSERVER;
    p1->flowflags |= FLOW_PKT_ESTABLISHED;
    p1->flags |= PKT_HAS_FLOW | PKT_STREAM_EST;
    p2->flow = &f;
    p2->flowflags |= FLOW_PKT_TOCLIENT;
    p2->flowflags |= FLOW_PKT_ESTABLISHED;
    p2->flags |= PKT_HAS_FLOW | PKT_STREAM_EST;
    f.alproto = ALPROTO_HTTP1;

    StreamTcpInitConfig(true);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    de_ctx->flags |= DE_QUIET;

    Signature *s = DetectEngineAppendSig(de_ctx, "alert http any any -> any any "
                                                 "(msg:\"http stat msg test\"; "
                                                 "content:\"abc\"; http_stat_msg; depth:3; "
                                                 "content:\"xyz\"; http_stat_msg; within:3; "
                                                 "sid:1;)");
    FAIL_IF_NULL(s);

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParserParse(
            NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER, http_buf1, http_len1);
    FAIL_IF_NOT(r == 0);

    HtpState *http_state = f.alstate;
    FAIL_IF_NULL(http_state);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p1);
    FAIL_IF(PacketAlertCheck(p1, 1));

    r = AppLayerParserParse(
            NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOCLIENT, http_buf2, http_len2);
    FAIL_IF_NOT(r == 0);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p2);
    FAIL_IF(PacketAlertCheck(p2, 1));

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

static int DetectEngineHttpStatMsgTest12(void)
{
    TcpSession ssn;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx = NULL;
    Flow f;
    uint8_t http_buf1[] = "GET /index.html HTTP/1.0\r\n"
                          "Host: www.openinfosecfoundation.org\r\n"
                          "User-Agent: Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.1.7) "
                          "Gecko/20091221 Firefox/3.5.7\r\n"
                          "\r\n";
    uint32_t http_len1 = sizeof(http_buf1) - 1;
    uint8_t http_buf2[] = "HTTP/1.0 200 abcdef\r\n"
                          "Content-Type: text/html\r\n"
                          "Content-Length: 6\r\n"
                          "\r\n"
                          "abcdef";
    uint32_t http_len2 = sizeof(http_buf2) - 1;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&th_v, 0, sizeof(th_v));
    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    Packet *p1 = UTHBuildPacket(NULL, 0, IPPROTO_TCP);
    Packet *p2 = UTHBuildPacket(NULL, 0, IPPROTO_TCP);

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;
    f.flags |= FLOW_IPV4;

    p1->flow = &f;
    p1->flowflags |= FLOW_PKT_TOSERVER;
    p1->flowflags |= FLOW_PKT_ESTABLISHED;
    p1->flags |= PKT_HAS_FLOW | PKT_STREAM_EST;
    p2->flow = &f;
    p2->flowflags |= FLOW_PKT_TOCLIENT;
    p2->flowflags |= FLOW_PKT_ESTABLISHED;
    p2->flags |= PKT_HAS_FLOW | PKT_STREAM_EST;
    f.alproto = ALPROTO_HTTP1;

    StreamTcpInitConfig(true);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    de_ctx->flags |= DE_QUIET;

    Signature *s = DetectEngineAppendSig(de_ctx, "alert http any any -> any any "
                                                 "(msg:\"http stat msg test\"; "
                                                 "content:\"ab\"; http_stat_msg; depth:2; "
                                                 "content:\"ef\"; http_stat_msg; distance:2; "
                                                 "sid:1;)");
    FAIL_IF_NULL(s);

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParserParse(
            NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER, http_buf1, http_len1);
    FAIL_IF_NOT(r == 0);

    HtpState *http_state = f.alstate;
    FAIL_IF_NULL(http_state);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p1);
    FAIL_IF(PacketAlertCheck(p1, 1));

    r = AppLayerParserParse(
            NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOCLIENT, http_buf2, http_len2);
    FAIL_IF_NOT(r == 0);

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

static int DetectEngineHttpStatMsgTest13(void)
{
    TcpSession ssn;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx = NULL;
    Flow f;
    uint8_t http_buf1[] = "GET /index.html HTTP/1.0\r\n"
                          "Host: www.openinfosecfoundation.org\r\n"
                          "User-Agent: Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.1.7) "
                          "Gecko/20091221 Firefox/3.5.7\r\n"
                          "\r\n";
    uint32_t http_len1 = sizeof(http_buf1) - 1;
    uint8_t http_buf2[] = "HTTP/1.0 200 abcdef\r\n"
                          "Content-Type: text/html\r\n"
                          "Content-Length: 6\r\n"
                          "\r\n"
                          "abcdef";
    uint32_t http_len2 = sizeof(http_buf2) - 1;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&th_v, 0, sizeof(th_v));
    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    Packet *p1 = UTHBuildPacket(NULL, 0, IPPROTO_TCP);
    Packet *p2 = UTHBuildPacket(NULL, 0, IPPROTO_TCP);

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;
    f.flags |= FLOW_IPV4;

    p1->flow = &f;
    p1->flowflags |= FLOW_PKT_TOSERVER;
    p1->flowflags |= FLOW_PKT_ESTABLISHED;
    p1->flags |= PKT_HAS_FLOW | PKT_STREAM_EST;
    p2->flow = &f;
    p2->flowflags |= FLOW_PKT_TOCLIENT;
    p2->flowflags |= FLOW_PKT_ESTABLISHED;
    p2->flags |= PKT_HAS_FLOW | PKT_STREAM_EST;
    f.alproto = ALPROTO_HTTP1;

    StreamTcpInitConfig(true);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    de_ctx->flags |= DE_QUIET;

    Signature *s = DetectEngineAppendSig(de_ctx, "alert http any any -> any any "
                                                 "(msg:\"http stat msg test\"; "
                                                 "content:\"ab\"; http_stat_msg; depth:3; "
                                                 "content:!\"yz\"; http_stat_msg; distance:2; "
                                                 "sid:1;)");
    FAIL_IF_NULL(s);

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParserParse(
            NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER, http_buf1, http_len1);
    FAIL_IF_NOT(r == 0);

    HtpState *http_state = f.alstate;
    FAIL_IF_NULL(http_state);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p1);
    FAIL_IF(PacketAlertCheck(p1, 1));

    r = AppLayerParserParse(
            NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOCLIENT, http_buf2, http_len2);
    FAIL_IF_NOT(r == 0);

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

static int DetectEngineHttpStatMsgTest14(void)
{
    TcpSession ssn;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx = NULL;
    Flow f;
    uint8_t http_buf1[] = "GET /index.html HTTP/1.0\r\n"
                          "Host: www.openinfosecfoundation.org\r\n"
                          "User-Agent: Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.1.7) "
                          "Gecko/20091221 Firefox/3.5.7\r\n"
                          "\r\n";
    uint32_t http_len1 = sizeof(http_buf1) - 1;
    uint8_t http_buf2[] = "HTTP/1.0 200 abcdef\r\n"
                          "Content-Type: text/html\r\n"
                          "Content-Length: 6\r\n"
                          "\r\n"
                          "abcdef";
    uint32_t http_len2 = sizeof(http_buf2) - 1;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&th_v, 0, sizeof(th_v));
    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    Packet *p1 = UTHBuildPacket(NULL, 0, IPPROTO_TCP);
    Packet *p2 = UTHBuildPacket(NULL, 0, IPPROTO_TCP);

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;
    f.flags |= FLOW_IPV4;

    p1->flow = &f;
    p1->flowflags |= FLOW_PKT_TOSERVER;
    p1->flowflags |= FLOW_PKT_ESTABLISHED;
    p1->flags |= PKT_HAS_FLOW | PKT_STREAM_EST;
    p2->flow = &f;
    p2->flowflags |= FLOW_PKT_TOCLIENT;
    p2->flowflags |= FLOW_PKT_ESTABLISHED;
    p2->flags |= PKT_HAS_FLOW | PKT_STREAM_EST;
    f.alproto = ALPROTO_HTTP1;

    StreamTcpInitConfig(true);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    de_ctx->flags |= DE_QUIET;

    Signature *s = DetectEngineAppendSig(de_ctx, "alert http any any -> any any "
                                                 "(msg:\"http stat msg test\"; "
                                                 "pcre:/ab/Y; "
                                                 "content:\"ef\"; http_stat_msg; distance:2; "
                                                 "sid:1;)");
    FAIL_IF_NULL(s);

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParserParse(
            NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER, http_buf1, http_len1);
    FAIL_IF_NOT(r == 0);

    HtpState *http_state = f.alstate;
    FAIL_IF_NULL(http_state);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p1);
    FAIL_IF(PacketAlertCheck(p1, 1));

    r = AppLayerParserParse(
            NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOCLIENT, http_buf2, http_len2);
    FAIL_IF_NOT(r == 0);

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

static int DetectEngineHttpStatMsgTest15(void)
{
    TcpSession ssn;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx = NULL;
    Flow f;
    uint8_t http_buf1[] = "GET /index.html HTTP/1.0\r\n"
                          "Host: www.openinfosecfoundation.org\r\n"
                          "User-Agent: Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.1.7) "
                          "Gecko/20091221 Firefox/3.5.7\r\n"
                          "\r\n";
    uint32_t http_len1 = sizeof(http_buf1) - 1;
    uint8_t http_buf2[] = "HTTP/1.0 200 abcdef\r\n"
                          "Content-Type: text/html\r\n"
                          "Content-Length: 6\r\n"
                          "\r\n"
                          "abcdef";
    uint32_t http_len2 = sizeof(http_buf2) - 1;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&th_v, 0, sizeof(th_v));
    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    Packet *p1 = UTHBuildPacket(NULL, 0, IPPROTO_TCP);
    Packet *p2 = UTHBuildPacket(NULL, 0, IPPROTO_TCP);

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;
    f.flags |= FLOW_IPV4;

    p1->flow = &f;
    p1->flowflags |= FLOW_PKT_TOSERVER;
    p1->flowflags |= FLOW_PKT_ESTABLISHED;
    p1->flags |= PKT_HAS_FLOW | PKT_STREAM_EST;
    p2->flow = &f;
    p2->flowflags |= FLOW_PKT_TOCLIENT;
    p2->flowflags |= FLOW_PKT_ESTABLISHED;
    p2->flags |= PKT_HAS_FLOW | PKT_STREAM_EST;
    f.alproto = ALPROTO_HTTP1;

    StreamTcpInitConfig(true);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    de_ctx->flags |= DE_QUIET;

    Signature *s =
            DetectEngineAppendSig(de_ctx, "alert http any any -> any any "
                                          "(msg:\"http stat msg test\"; "
                                          "pcre:/abc/Y; "
                                          "content:!\"xyz\"; http_stat_msg; distance:0; within:3; "
                                          "sid:1;)");
    FAIL_IF_NULL(s);

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParserParse(
            NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER, http_buf1, http_len1);
    FAIL_IF_NOT(r == 0);

    HtpState *http_state = f.alstate;
    FAIL_IF_NULL(http_state);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p1);
    FAIL_IF(PacketAlertCheck(p1, 1));

    r = AppLayerParserParse(
            NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOCLIENT, http_buf2, http_len2);
    FAIL_IF_NOT(r == 0);

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

/** \test Check the signature working to alert when http_stat_msg is matched . */
static int DetectHttpStatMsgSigTest01(void)
{
    Flow f;
    uint8_t httpbuf1[] = "POST / HTTP/1.0\r\nUser-Agent: Mozilla/1.0\r\n\r\n";
    uint32_t httplen1 = sizeof(httpbuf1) - 1; /* minus the \0 */
    uint8_t httpbuf2[] = "HTTP/1.0 200 OK\r\n\r\n";
    uint32_t httplen2 = sizeof(httpbuf2) - 1; /* minus the \0 */
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
    p->flowflags |= FLOW_PKT_TOCLIENT;
    p->flowflags |= FLOW_PKT_ESTABLISHED;
    p->flags |= PKT_HAS_FLOW | PKT_STREAM_EST;
    f.alproto = ALPROTO_HTTP1;

    StreamTcpInitConfig(true);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    de_ctx->flags |= DE_QUIET;

    Signature *s = DetectEngineAppendSig(de_ctx, "alert http any any -> any any (msg:"
                                                 "\"HTTP status message\"; content:\"OK\"; "
                                                 "http_stat_msg; sid:1;)");
    FAIL_IF_NULL(s);

    s = DetectEngineAppendSig(de_ctx, "alert http any any -> any any (msg:\"HTTP "
                                      "Status message nocase\"; content:\"ok\"; nocase; "
                                      "http_stat_msg; sid:2;)");
    FAIL_IF_NULL(s);

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParserParse(
            NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER, httpbuf1, httplen1);
    FAIL_IF_NOT(r == 0);

    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOCLIENT, httpbuf2, httplen2);
    FAIL_IF_NOT(r == 0);

    HtpState *http_state = f.alstate;
    FAIL_IF_NULL(http_state);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    FAIL_IF(!(PacketAlertCheck(p, 1)));
    FAIL_IF(!(PacketAlertCheck(p, 2)));

    UTHFreePackets(&p, 1);
    FLOW_DESTROY(&f);
    AppLayerParserThreadCtxFree(alp_tctx);
    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);
    StreamTcpFreeConfig(true);
    StatsThreadCleanup(&th_v);
    PASS;
}

/** \test Check the signature working to alert when http_stat_msg is not matched . */
static int DetectHttpStatMsgSigTest02(void)
{
    Flow f;
    uint8_t httpbuf1[] = "POST / HTTP/1.0\r\nUser-Agent: Mozilla/1.0\r\n\r\n";
    uint32_t httplen1 = sizeof(httpbuf1) - 1; /* minus the \0 */
    uint8_t httpbuf2[] = "HTTP/1.0 200 OK\r\n\r\n";
    uint32_t httplen2 = sizeof(httpbuf2) - 1; /* minus the \0 */
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
    p->flowflags |= FLOW_PKT_TOCLIENT;
    p->flowflags |= FLOW_PKT_ESTABLISHED;
    p->flags |= PKT_HAS_FLOW | PKT_STREAM_EST;
    f.alproto = ALPROTO_HTTP1;

    StreamTcpInitConfig(true);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    de_ctx->flags |= DE_QUIET;

    Signature *s = DetectEngineAppendSig(de_ctx, "alert http any any -> any any (msg:"
                                                 "\"HTTP status message\"; content:\"no\"; "
                                                 "http_stat_msg; sid:1;)");
    FAIL_IF_NULL(s);

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParserParse(
            NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER, httpbuf1, httplen1);
    FAIL_IF_NOT(r == 0);

    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOCLIENT, httpbuf2, httplen2);
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

/** \test Check the signature working to alert when http_stat_msg is used with
 *        negated content . */
static int DetectHttpStatMsgSigTest03(void)
{
    Flow f;
    uint8_t httpbuf1[] = "POST / HTTP/1.0\r\nUser-Agent: Mozilla/1.0\r\n\r\n";
    uint32_t httplen1 = sizeof(httpbuf1) - 1; /* minus the \0 */
    uint8_t httpbuf2[] = "HTTP/1.0 200 OK\r\n\r\n";
    uint32_t httplen2 = sizeof(httpbuf2) - 1; /* minus the \0 */
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
    p->flowflags |= FLOW_PKT_TOCLIENT;
    p->flowflags |= FLOW_PKT_ESTABLISHED;
    p->flags |= PKT_HAS_FLOW | PKT_STREAM_EST;
    f.alproto = ALPROTO_HTTP1;

    StreamTcpInitConfig(true);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    de_ctx->flags |= DE_QUIET;

    Signature *s = DetectEngineAppendSig(de_ctx, "alert http any any -> any any (msg:"
                                                 "\"HTTP status message\"; content:\"ok\"; "
                                                 "nocase; http_stat_msg; sid:1;)");
    FAIL_IF_NULL(s);

    s = DetectEngineAppendSig(de_ctx, "alert http any any -> any any (msg:\"HTTP "
                                      "Status message nocase\"; content:!\"Not\"; "
                                      "http_stat_msg; sid:2;)");
    FAIL_IF_NULL(s);

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParserParse(
            NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER, httpbuf1, httplen1);
    FAIL_IF_NOT(r == 0);

    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOCLIENT, httpbuf2, httplen2);
    FAIL_IF_NOT(r == 0);

    HtpState *http_state = f.alstate;
    FAIL_IF_NULL(http_state);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);

    FAIL_IF(!PacketAlertCheck(p, 1));
    FAIL_IF(!PacketAlertCheck(p, 2));

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
 * \brief   Register the UNITTESTS for the http_stat_msg keyword
 */
void DetectHttpStatMsgRegisterTests(void)
{
    UtRegisterTest("DetectHttpStatMsgSigTest01", DetectHttpStatMsgSigTest01);
    UtRegisterTest("DetectHttpStatMsgSigTest02", DetectHttpStatMsgSigTest02);
    UtRegisterTest("DetectHttpStatMsgSigTest03", DetectHttpStatMsgSigTest03);

    UtRegisterTest("DetectEngineHttpStatMsgTest01", DetectEngineHttpStatMsgTest01);
    UtRegisterTest("DetectEngineHttpStatMsgTest02", DetectEngineHttpStatMsgTest02);
    UtRegisterTest("DetectEngineHttpStatMsgTest03", DetectEngineHttpStatMsgTest03);
    UtRegisterTest("DetectEngineHttpStatMsgTest04", DetectEngineHttpStatMsgTest04);
    UtRegisterTest("DetectEngineHttpStatMsgTest05", DetectEngineHttpStatMsgTest05);
    UtRegisterTest("DetectEngineHttpStatMsgTest06", DetectEngineHttpStatMsgTest06);
    UtRegisterTest("DetectEngineHttpStatMsgTest07", DetectEngineHttpStatMsgTest07);
    UtRegisterTest("DetectEngineHttpStatMsgTest08", DetectEngineHttpStatMsgTest08);
    UtRegisterTest("DetectEngineHttpStatMsgTest09", DetectEngineHttpStatMsgTest09);
    UtRegisterTest("DetectEngineHttpStatMsgTest10", DetectEngineHttpStatMsgTest10);
    UtRegisterTest("DetectEngineHttpStatMsgTest11", DetectEngineHttpStatMsgTest11);
    UtRegisterTest("DetectEngineHttpStatMsgTest12", DetectEngineHttpStatMsgTest12);
    UtRegisterTest("DetectEngineHttpStatMsgTest13", DetectEngineHttpStatMsgTest13);
    UtRegisterTest("DetectEngineHttpStatMsgTest14", DetectEngineHttpStatMsgTest14);
    UtRegisterTest("DetectEngineHttpStatMsgTest15", DetectEngineHttpStatMsgTest15);
}

/**
 * @}
 */
