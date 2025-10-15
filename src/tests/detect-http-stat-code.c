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

static int DetectEngineHttpStatCodeTest01(void)
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
                                                 "(msg:\"http stat code test\"; "
                                                 "content:\"200\"; http_stat_code; "
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
    FAIL_IF((PacketAlertCheck(p1, 1)));

    r = AppLayerParserParse(
            NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOCLIENT, http_buf2, http_len2);
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

static int DetectEngineHttpStatCodeTest02(void)
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
    uint8_t http_buf2[] = "HTTP/1.0 2000123 xxxxABC\r\n"
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
                                                 "(msg:\"http stat code test\"; "
                                                 "content:\"123\"; http_stat_code; offset:4; "
                                                 "sid:1;)");
    FAIL_IF_NULL(s);

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParserParse(
            NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER, http_buf1, http_len1);
    FAIL_IF_NOT(r == 0);

    r = AppLayerParserParse(
            NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOCLIENT, http_buf2, http_len2);
    FAIL_IF_NOT(r == 0);

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

static int DetectEngineHttpStatCodeTest03(void)
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
    uint8_t http_buf2[] = "HTTP/1.0 123";
    uint32_t http_len2 = sizeof(http_buf2) - 1;
    uint8_t http_buf3[] = "456789\r\n"
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
                                                 "(msg:\"http stat code test\"; "
                                                 "content:\"789\"; http_stat_code; offset:5; "
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

static int DetectEngineHttpStatCodeTest04(void)
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
    uint8_t http_buf2[] = "HTTP/1.0 200123 abcdef\r\n"
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
                                                 "(msg:\"http stat code test\"; "
                                                 "content:!\"200\"; http_stat_code; offset:3; "
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

static int DetectEngineHttpStatCodeTest05(void)
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
    uint8_t http_buf2[] = "HTTP/1.0 200123 abcdef\r\n"
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
                                                 "(msg:\"http stat code test\"; "
                                                 "content:\"200\"; http_stat_code; depth:3; "
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

static int DetectEngineHttpStatCodeTest06(void)
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
    uint8_t http_buf2[] = "HTTP/1.0 200123 abcdef\r\n"
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
                                                 "(msg:\"http stat code test\"; "
                                                 "content:!\"123\"; http_stat_code; depth:3; "
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

static int DetectEngineHttpStatCodeTest07(void)
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
    uint8_t http_buf2[] = "HTTP/1.0 200123 abcdef\r\n"
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
                                                 "(msg:\"http stat code test\"; "
                                                 "content:!\"123\"; http_stat_code; offset:3; "
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

static int DetectEngineHttpStatCodeTest08(void)
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
    uint8_t http_buf2[] = "HTTP/1.0 200123 abcdef\r\n"
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
                                                 "(msg:\"http stat code test\"; "
                                                 "content:!\"200\"; http_stat_code; depth:3; "
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

static int DetectEngineHttpStatCodeTest09(void)
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
    uint8_t http_buf2[] = "HTTP/1.0 200123 abcdef\r\n"
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
                                                 "(msg:\"http stat code test\"; "
                                                 "content:\"200\"; http_stat_code; depth:3; "
                                                 "content:\"123\"; http_stat_code; within:3; "
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

static int DetectEngineHttpStatCodeTest10(void)
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
    uint8_t http_buf2[] = "HTTP/1.0 200123 abcdef\r\n"
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
                                                 "(msg:\"http stat code test\"; "
                                                 "content:\"200\"; http_stat_code; depth:3; "
                                                 "content:!\"124\"; http_stat_code; within:3; "
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

static int DetectEngineHttpStatCodeTest11(void)
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
    uint8_t http_buf2[] = "HTTP/1.0 200123 abcdef\r\n"
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
                                                 "(msg:\"http stat code test\"; "
                                                 "content:\"200\"; http_stat_code; depth:3; "
                                                 "content:\"124\"; http_stat_code; within:3; "
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

static int DetectEngineHttpStatCodeTest12(void)
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
    uint8_t http_buf2[] = "HTTP/1.0 200123 abcdef\r\n"
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
                                                 "(msg:\"http stat code test\"; "
                                                 "content:\"20\"; http_stat_code; depth:2; "
                                                 "content:\"23\"; http_stat_code; distance:2; "
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

static int DetectEngineHttpStatCodeTest13(void)
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
    uint8_t http_buf2[] = "HTTP/1.0 200123 abcdef\r\n"
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
                                                 "(msg:\"http stat code test\"; "
                                                 "content:\"20\"; http_stat_code; depth:3; "
                                                 "content:!\"25\"; http_stat_code; distance:2; "
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

static int DetectEngineHttpStatCodeTest14(void)
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
    uint8_t http_buf2[] = "HTTP/1.0 200123 abcdef\r\n"
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
                                                 "(msg:\"http stat code test\"; "
                                                 "pcre:/20/S; "
                                                 "content:\"23\"; http_stat_code; distance:2; "
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

static int DetectEngineHttpStatCodeTest15(void)
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
    uint8_t http_buf2[] = "HTTP/1.0 200123 abcdef\r\n"
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
                                          "(msg:\"http stat code test\"; "
                                          "pcre:/200/S; "
                                          "content:!\"124\"; http_stat_code; distance:0; within:3; "
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

/** \test Check the signature working to alert when http_stat_code is matched . */
static int DetectHttpStatCodeSigTest01(void)
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

    Signature *s = DetectEngineAppendSig(de_ctx,
            "alert http any any -> any any (msg:"
            "\"HTTP status code\"; content:\"200\"; http_stat_code; sid:1;)");
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

    UTHFreePackets(&p, 1);
    FLOW_DESTROY(&f);
    AppLayerParserThreadCtxFree(alp_tctx);
    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);
    StreamTcpFreeConfig(true);
    StatsThreadCleanup(&th_v);
    PASS;
}

/** \test Check the signature working to alert when http_stat_code is not matched . */
static int DetectHttpStatCodeSigTest02(void)
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
                                                 "\"HTTP status code\"; content:\"no\"; "
                                                 "http_stat_code; sid:1;)");
    FAIL_IF_NULL(s);

    s = DetectEngineAppendSig(de_ctx, "alert http any any -> any any (msg:\"HTTP "
                                      "Status code\"; content:\"100\";"
                                      "http_stat_code; sid:2;)");
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
    FAIL_IF((PacketAlertCheck(p, 2)));

    UTHFreePackets(&p, 1);
    FLOW_DESTROY(&f);
    AppLayerParserThreadCtxFree(alp_tctx);
    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);
    StreamTcpFreeConfig(true);
    StatsThreadCleanup(&th_v);
    PASS;
}

/** \test Check the signature working to alert when http_stat_code is matched for
 *        for nocase or not */
static int DetectHttpStatCodeSigTest03(void)
{
    Flow f;
    uint8_t httpbuf1[] = "POST / HTTP/1.0\r\nUser-Agent: Mozilla/1.0\r\n\r\n";
    uint32_t httplen1 = sizeof(httpbuf1) - 1; /* minus the \0 */
    uint8_t httpbuf2[] = "HTTP/1.0 FAIL OK\r\n\r\n";
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
                                                 "\"HTTP status code\"; content:\"FAIL\"; "
                                                 "http_stat_code; sid:1;)");
    FAIL_IF_NULL(s);

    s = DetectEngineAppendSig(de_ctx, "alert http any any -> any any (msg:\"HTTP "
                                      "Status code nocase\"; content:\"fail\"; nocase; "
                                      "http_stat_code; sid:2;)");
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

/** \test Check the signature working to alert when http_stat_code is matched for
 *        for negation or not */
static int DetectHttpStatCodeSigTest04(void)
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
                                                 "\"HTTP status code\"; content:\"200\"; "
                                                 "http_stat_code; sid:1;)");
    FAIL_IF_NULL(s);

    s = DetectEngineAppendSig(de_ctx, "alert http any any -> any any (msg:\"HTTP "
                                      "Status code negation\"; content:!\"100\"; nocase; "
                                      "http_stat_code; sid:2;)");
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

/**
 * \brief   Register the UNITTESTS for the http_stat_code keyword
 */
void DetectHttpStatCodeRegisterTests(void)
{
    UtRegisterTest("DetectEngineHttpStatCodeTest01", DetectEngineHttpStatCodeTest01);
    UtRegisterTest("DetectEngineHttpStatCodeTest02", DetectEngineHttpStatCodeTest02);
    UtRegisterTest("DetectEngineHttpStatCodeTest03", DetectEngineHttpStatCodeTest03);
    UtRegisterTest("DetectEngineHttpStatCodeTest04", DetectEngineHttpStatCodeTest04);
    UtRegisterTest("DetectEngineHttpStatCodeTest05", DetectEngineHttpStatCodeTest05);
    UtRegisterTest("DetectEngineHttpStatCodeTest06", DetectEngineHttpStatCodeTest06);
    UtRegisterTest("DetectEngineHttpStatCodeTest07", DetectEngineHttpStatCodeTest07);
    UtRegisterTest("DetectEngineHttpStatCodeTest08", DetectEngineHttpStatCodeTest08);
    UtRegisterTest("DetectEngineHttpStatCodeTest09", DetectEngineHttpStatCodeTest09);
    UtRegisterTest("DetectEngineHttpStatCodeTest10", DetectEngineHttpStatCodeTest10);
    UtRegisterTest("DetectEngineHttpStatCodeTest11", DetectEngineHttpStatCodeTest11);
    UtRegisterTest("DetectEngineHttpStatCodeTest12", DetectEngineHttpStatCodeTest12);
    UtRegisterTest("DetectEngineHttpStatCodeTest13", DetectEngineHttpStatCodeTest13);
    UtRegisterTest("DetectEngineHttpStatCodeTest14", DetectEngineHttpStatCodeTest14);
    UtRegisterTest("DetectEngineHttpStatCodeTest15", DetectEngineHttpStatCodeTest15);

    UtRegisterTest("DetectHttpStatCodeSigTest01", DetectHttpStatCodeSigTest01);
    UtRegisterTest("DetectHttpStatCodeSigTest02", DetectHttpStatCodeSigTest02);
    UtRegisterTest("DetectHttpStatCodeSigTest03", DetectHttpStatCodeSigTest03);
    UtRegisterTest("DetectHttpStatCodeSigTest04", DetectHttpStatCodeSigTest04);
}

/**
 * @}
 */
