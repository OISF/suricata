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
        "HTTP/1.0 200 message\r\n"
        "Content-Type: text/html\r\n"
        "Content-Length: 7\r\n"
        "\r\n"
        "message";
    uint32_t http_len2 = sizeof(http_buf2) - 1;
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
        FAIL;

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert http any any -> any any "
                               "(msg:\"http stat msg test\"; "
                               "content:\"message\"; http_stat_msg; "
                               "sid:1;)");
    if (de_ctx->sig_list == NULL)
        FAIL;

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParserParse(
            NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER, http_buf1, http_len1);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        FAIL;
    }

    http_state = f.alstate;
    if (http_state == NULL) {
        printf("no http state: \n");
        FAIL;
    }

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p1);

    if ((PacketAlertCheck(p1, 1))) {
        printf("sid 1 matched but shouldn't have\n");
        FAIL;
    }

    r = AppLayerParserParse(
            NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOCLIENT, http_buf2, http_len2);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: \n", r);
        FAIL;
    }

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p2);

    if (!(PacketAlertCheck(p2, 1))) {
        printf("sid 1 didn't match but should have");
        FAIL;
    }

        AppLayerParserThreadCtxFree(alp_tctx);
        DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
        DetectEngineCtxFree(de_ctx);

    UTHFreePackets(&p1, 1);
    UTHFreePackets(&p2, 1);
    FLOW_DESTROY(&f);
    StreamTcpFreeConfig(true);
    StatsThreadCleanup(&th_v);
    PASS;
}

static int DetectEngineHttpStatMsgTest02(void)
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
        "HTTP/1.0 200 xxxxABC\r\n"
        "Content-Type: text/html\r\n"
        "Content-Length: 7\r\n"
        "\r\n"
        "xxxxABC";
    uint32_t http_len2 = sizeof(http_buf2) - 1;
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
        FAIL;

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert http any any -> any any "
                               "(msg:\"http stat msg test\"; "
                               "content:\"ABC\"; http_stat_msg; offset:4; "
                               "sid:1;)");
    if (de_ctx->sig_list == NULL)
        FAIL;

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParserParse(
            NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER, http_buf1, http_len1);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        FAIL;
    }

    r = AppLayerParserParse(
            NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOCLIENT, http_buf2, http_len2);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        FAIL;
    }

    http_state = f.alstate;
    if (http_state == NULL) {
        printf("no http state: \n");
        FAIL;
    }

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p1);

    if (!(PacketAlertCheck(p1, 1))) {
        printf("sid 1 didn't match but should have\n");
        FAIL;
    }

        AppLayerParserThreadCtxFree(alp_tctx);
        DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
        DetectEngineCtxFree(de_ctx);

    UTHFreePackets(&p1, 1);
    FLOW_DESTROY(&f);
    StreamTcpFreeConfig(true);
    StatsThreadCleanup(&th_v);
    PASS;
}

static int DetectEngineHttpStatMsgTest03(void)
{
    TcpSession ssn;
    Packet *p1 = NULL;
    Packet *p2 = NULL;
    ThreadVars th_v;
    DetectEngineCtx *de_ctx = NULL;
    DetectEngineThreadCtx *det_ctx = NULL;
    HtpState *http_state = NULL;
    Flow f;
    uint8_t http_buf1[] = "GET /index.html HTTP/1.0\r\n"
                          "Host: www.openinfosecfoundation.org\r\n"
                          "User-Agent: Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.1.7) "
                          "Gecko/20091221 Firefox/3.5.7\r\n"
                          "\r\n";
    uint32_t http_len1 = sizeof(http_buf1) - 1;
    uint8_t http_buf2[] =
        "HTTP/1.0 200 1234567";
    uint32_t http_len2 = sizeof(http_buf2) - 1;
    uint8_t http_buf3[] =
        "8901234ABC\r\n"
        "Content-Type: text/html\r\n"
        "Content-Length: 17\r\n"
        "\r\n"
        "12345678901234ABC";
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
        FAIL;

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert http any any -> any any "
                               "(msg:\"http stat msg test\"; "
                               "content:\"ABC\"; http_stat_msg; offset:14; "
                               "sid:1;)");
    if (de_ctx->sig_list == NULL)
        FAIL;

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParserParse(
            NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER, http_buf1, http_len1);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        FAIL;
    }

    http_state = f.alstate;
    if (http_state == NULL) {
        printf("no http state: \n");
        FAIL;
    }

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p1);

    if (PacketAlertCheck(p1, 1)) {
        printf("sid 1 matched but shouldn't have\n");
        FAIL;
    }

    r = AppLayerParserParse(
            NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOCLIENT, http_buf2, http_len2);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: \n", r);
        FAIL;
    }

    r = AppLayerParserParse(
            NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOCLIENT, http_buf3, http_len3);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: \n", r);
        FAIL;
    }

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p2);

    if (!(PacketAlertCheck(p2, 1))) {
        printf("sid 1 didn't match but should have");
        FAIL;
    }

    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    if (de_ctx != NULL)
        if (de_ctx != NULL)
            DetectEngineCtxFree(de_ctx);

    UTHFreePackets(&p1, 1);
    UTHFreePackets(&p2, 1);
    FLOW_DESTROY(&f);
    StreamTcpFreeConfig(true);
    StatsThreadCleanup(&th_v);
    PASS;
}

static int DetectEngineHttpStatMsgTest04(void)
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
        "HTTP/1.0 200 abcdef\r\n"
        "Content-Type: text/html\r\n"
        "Content-Length: 6\r\n"
        "\r\n"
        "abcdef";
    uint32_t http_len2 = sizeof(http_buf2) - 1;
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
        FAIL;

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert http any any -> any any "
                               "(msg:\"http stat msg test\"; "
                               "content:!\"abc\"; http_stat_msg; offset:3; "
                               "sid:1;)");
    if (de_ctx->sig_list == NULL)
        FAIL;

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParserParse(
            NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER, http_buf1, http_len1);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        FAIL;
    }

    http_state = f.alstate;
    if (http_state == NULL) {
        printf("no http state: \n");
        FAIL;
    }

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p1);

    if (PacketAlertCheck(p1, 1)) {
        printf("sid 1 matched but shouldn't have: ");
        FAIL;
    }

    r = AppLayerParserParse(
            NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOCLIENT, http_buf2, http_len2);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: \n", r);
        FAIL;
    }

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p2);

    if (!PacketAlertCheck(p2, 1)) {
        printf("sid 1 didn't match but should have: ");
        FAIL;
    }

    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);

    UTHFreePackets(&p1, 1);
    UTHFreePackets(&p2, 1);
    FLOW_DESTROY(&f);
    StreamTcpFreeConfig(true);
    StatsThreadCleanup(&th_v);
    PASS;
}

static int DetectEngineHttpStatMsgTest05(void)
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
        "HTTP/1.0 200 abcdef\r\n"
        "Content-Type: text/html\r\n"
        "Content-Length: 6\r\n"
        "\r\n"
        "abcdef";
    uint32_t http_len2 = sizeof(http_buf2) - 1;
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
        FAIL;

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert http any any -> any any "
                               "(msg:\"http stat msg test\"; "
                               "content:\"abc\"; http_stat_msg; depth:3; "
                               "sid:1;)");
    if (de_ctx->sig_list == NULL)
        FAIL;

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParserParse(
            NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER, http_buf1, http_len1);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        FAIL;
    }

    http_state = f.alstate;
    if (http_state == NULL) {
        printf("no http state: \n");
        FAIL;
    }

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p1);

    if (PacketAlertCheck(p1, 1)) {
        printf("sid 1 matched but shouldn't have: ");
        FAIL;
    }

    r = AppLayerParserParse(
            NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOCLIENT, http_buf2, http_len2);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: \n", r);
        FAIL;
    }

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p2);

    if (!PacketAlertCheck(p2, 1)) {
        printf("sid 1 didn't match but should have: ");
        FAIL;
    }

    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);

    UTHFreePackets(&p1, 1);
    UTHFreePackets(&p2, 1);
    FLOW_DESTROY(&f);
    StreamTcpFreeConfig(true);
    StatsThreadCleanup(&th_v);
    PASS;
}

static int DetectEngineHttpStatMsgTest06(void)
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
        "HTTP/1.0 200 abcdef\r\n"
        "Content-Type: text/html\r\n"
        "Content-Length: 6\r\n"
        "\r\n"
        "abcdef";
    uint32_t http_len2 = sizeof(http_buf2) - 1;
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
        FAIL;

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert http any any -> any any "
                               "(msg:\"http stat msg test\"; "
                               "content:!\"def\"; http_stat_msg; depth:3; "
                               "sid:1;)");
    if (de_ctx->sig_list == NULL)
        FAIL;

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParserParse(
            NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER, http_buf1, http_len1);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        FAIL;
    }

    http_state = f.alstate;
    if (http_state == NULL) {
        printf("no http state: \n");
        FAIL;
    }

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p1);

    if (PacketAlertCheck(p1, 1)) {
        printf("sid 1 matched but shouldn't have: ");
        FAIL;
    }

    r = AppLayerParserParse(
            NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOCLIENT, http_buf2, http_len2);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: \n", r);
        FAIL;
    }

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p2);

    if (!PacketAlertCheck(p2, 1)) {
        printf("sid 1 didn't match but should have: ");
        FAIL;
    }

    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);

    UTHFreePackets(&p1, 1);
    UTHFreePackets(&p2, 1);
    FLOW_DESTROY(&f);
    StreamTcpFreeConfig(true);
    StatsThreadCleanup(&th_v);
    PASS;
}

static int DetectEngineHttpStatMsgTest07(void)
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
        "HTTP/1.0 200 abcdef\r\n"
        "Content-Type: text/html\r\n"
        "Content-Length: 6\r\n"
        "\r\n"
        "abcdef";
    uint32_t http_len2 = sizeof(http_buf2) - 1;
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
        FAIL;

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert http any any -> any any "
                               "(msg:\"http stat msg test\"; "
                               "content:!\"def\"; http_stat_msg; offset:3; "
                               "sid:1;)");
    if (de_ctx->sig_list == NULL)
        FAIL;

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParserParse(
            NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER, http_buf1, http_len1);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        FAIL;
    }

    http_state = f.alstate;
    if (http_state == NULL) {
        printf("no http state: \n");
        FAIL;
    }

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p1);

    if (PacketAlertCheck(p1, 1)) {
        printf("sid 1 matched but shouldn't have: ");
        FAIL;
    }

    r = AppLayerParserParse(
            NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOCLIENT, http_buf2, http_len2);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: \n", r);
        FAIL;
    }

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p2);

    if (PacketAlertCheck(p2, 1)) {
        printf("sid 1 matched but shouldn't have: ");
        FAIL;
    }

    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);

    UTHFreePackets(&p1, 1);
    UTHFreePackets(&p2, 1);
    FLOW_DESTROY(&f);
    StreamTcpFreeConfig(true);
    StatsThreadCleanup(&th_v);
    PASS;
}

static int DetectEngineHttpStatMsgTest08(void)
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
        "HTTP/1.0 200 abcdef\r\n"
        "Content-Type: text/html\r\n"
        "Content-Length: 6\r\n"
        "\r\n"
        "abcdef";
    uint32_t http_len2 = sizeof(http_buf2) - 1;
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
        FAIL;

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert http any any -> any any "
                               "(msg:\"http stat msg test\"; "
                               "content:!\"abc\"; http_stat_msg; depth:3; "
                               "sid:1;)");
    if (de_ctx->sig_list == NULL)
        FAIL;

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParserParse(
            NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER, http_buf1, http_len1);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        FAIL;
    }

    http_state = f.alstate;
    if (http_state == NULL) {
        printf("no http state: \n");
        FAIL;
    }

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p1);

    if (PacketAlertCheck(p1, 1)) {
        printf("sid 1 matched but shouldn't have: ");
        FAIL;
    }

    r = AppLayerParserParse(
            NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOCLIENT, http_buf2, http_len2);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: \n", r);
        FAIL;
    }

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p2);

    if (PacketAlertCheck(p2, 1)) {
        printf("sid 1 matched but shouldn't have: ");
        FAIL;
    }

    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);

    UTHFreePackets(&p1, 1);
    UTHFreePackets(&p2, 1);
    FLOW_DESTROY(&f);
    StreamTcpFreeConfig(true);
    StatsThreadCleanup(&th_v);
    PASS;
}

static int DetectEngineHttpStatMsgTest09(void)
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
        "HTTP/1.0 200 abcdef\r\n"
        "Content-Type: text/html\r\n"
        "Content-Length: 6\r\n"
        "\r\n"
        "abcdef";
    uint32_t http_len2 = sizeof(http_buf2) - 1;
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
        FAIL;

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert http any any -> any any "
                               "(msg:\"http stat msg test\"; "
                               "content:\"abc\"; http_stat_msg; depth:3; "
                               "content:\"def\"; http_stat_msg; within:3; "
                               "sid:1;)");
    if (de_ctx->sig_list == NULL)
        FAIL;

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParserParse(
            NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER, http_buf1, http_len1);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        FAIL;
    }

    http_state = f.alstate;
    if (http_state == NULL) {
        printf("no http state: \n");
        FAIL;
    }

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p1);

    if (PacketAlertCheck(p1, 1)) {
        printf("sid 1 matched but shouldn't have: ");
        FAIL;
    }

    r = AppLayerParserParse(
            NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOCLIENT, http_buf2, http_len2);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: \n", r);
        FAIL;
    }

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p2);

    if (!PacketAlertCheck(p2, 1)) {
        printf("sid 1 didn't match but should have: ");
        FAIL;
    }

    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);

    UTHFreePackets(&p1, 1);
    UTHFreePackets(&p2, 1);
    FLOW_DESTROY(&f);
    StreamTcpFreeConfig(true);
    StatsThreadCleanup(&th_v);
    PASS;
}

static int DetectEngineHttpStatMsgTest10(void)
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
        "HTTP/1.0 200 abcdef\r\n"
        "Content-Type: text/html\r\n"
        "Content-Length: 6\r\n"
        "\r\n"
        "abcdef";
    uint32_t http_len2 = sizeof(http_buf2) - 1;
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
        FAIL;

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert http any any -> any any "
                               "(msg:\"http stat msg test\"; "
                               "content:\"abc\"; http_stat_msg; depth:3; "
                               "content:!\"xyz\"; http_stat_msg; within:3; "
                               "sid:1;)");
    if (de_ctx->sig_list == NULL)
        FAIL;

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParserParse(
            NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER, http_buf1, http_len1);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        FAIL;
    }

    http_state = f.alstate;
    if (http_state == NULL) {
        printf("no http state: \n");
        FAIL;
    }

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p1);

    if (PacketAlertCheck(p1, 1)) {
        printf("sid 1 matched but shouldn't have: ");
        FAIL;
    }

    r = AppLayerParserParse(
            NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOCLIENT, http_buf2, http_len2);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: \n", r);
        FAIL;
    }

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p2);

    if (!PacketAlertCheck(p2, 1)) {
        printf("sid 1 didn't match but should have: ");
        FAIL;
    }

    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);

    UTHFreePackets(&p1, 1);
    UTHFreePackets(&p2, 1);
    FLOW_DESTROY(&f);
    StreamTcpFreeConfig(true);
    StatsThreadCleanup(&th_v);
    PASS;
}

static int DetectEngineHttpStatMsgTest11(void)
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
        "HTTP/1.0 200 abcdef\r\n"
        "Content-Type: text/html\r\n"
        "Content-Length: 6\r\n"
        "\r\n"
        "abcdef";
    uint32_t http_len2 = sizeof(http_buf2) - 1;
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
        FAIL;

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert http any any -> any any "
                               "(msg:\"http stat msg test\"; "
                               "content:\"abc\"; http_stat_msg; depth:3; "
                               "content:\"xyz\"; http_stat_msg; within:3; "
                               "sid:1;)");
    if (de_ctx->sig_list == NULL)
        FAIL;

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParserParse(
            NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER, http_buf1, http_len1);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        FAIL;
    }

    http_state = f.alstate;
    if (http_state == NULL) {
        printf("no http state: \n");
        FAIL;
    }

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p1);

    if (PacketAlertCheck(p1, 1)) {
        printf("sid 1 matched but shouldn't have: ");
        FAIL;
    }

    r = AppLayerParserParse(
            NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOCLIENT, http_buf2, http_len2);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: \n", r);
        FAIL;
    }

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p2);

    if (PacketAlertCheck(p2, 1)) {
        printf("sid 1 did match but should not have: ");
        FAIL;
    }

    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);

    UTHFreePackets(&p1, 1);
    UTHFreePackets(&p2, 1);
    FLOW_DESTROY(&f);
    StreamTcpFreeConfig(true);
    StatsThreadCleanup(&th_v);
    PASS;
}

static int DetectEngineHttpStatMsgTest12(void)
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
        "HTTP/1.0 200 abcdef\r\n"
        "Content-Type: text/html\r\n"
        "Content-Length: 6\r\n"
        "\r\n"
        "abcdef";
    uint32_t http_len2 = sizeof(http_buf2) - 1;
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
        FAIL;

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert http any any -> any any "
                               "(msg:\"http stat msg test\"; "
                               "content:\"ab\"; http_stat_msg; depth:2; "
                               "content:\"ef\"; http_stat_msg; distance:2; "
                               "sid:1;)");
    if (de_ctx->sig_list == NULL)
        FAIL;

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParserParse(
            NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER, http_buf1, http_len1);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        FAIL;
    }

    http_state = f.alstate;
    if (http_state == NULL) {
        printf("no http state: \n");
        FAIL;
    }

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p1);

    if (PacketAlertCheck(p1, 1)) {
        printf("sid 1 matched but shouldn't have: ");
        FAIL;
    }

    r = AppLayerParserParse(
            NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOCLIENT, http_buf2, http_len2);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: \n", r);
        FAIL;
    }

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p2);

    if (!PacketAlertCheck(p2, 1)) {
        printf("sid 1 did not match but should have: ");
        FAIL;
    }

    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);

    UTHFreePackets(&p1, 1);
    UTHFreePackets(&p2, 1);
    FLOW_DESTROY(&f);
    StreamTcpFreeConfig(true);
    StatsThreadCleanup(&th_v);
    PASS;
}

static int DetectEngineHttpStatMsgTest13(void)
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
        "HTTP/1.0 200 abcdef\r\n"
        "Content-Type: text/html\r\n"
        "Content-Length: 6\r\n"
        "\r\n"
        "abcdef";
    uint32_t http_len2 = sizeof(http_buf2) - 1;
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
        FAIL;

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert http any any -> any any "
                               "(msg:\"http stat msg test\"; "
                               "content:\"ab\"; http_stat_msg; depth:3; "
                               "content:!\"yz\"; http_stat_msg; distance:2; "
                               "sid:1;)");
    if (de_ctx->sig_list == NULL)
        FAIL;

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParserParse(
            NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER, http_buf1, http_len1);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        FAIL;
    }

    http_state = f.alstate;
    if (http_state == NULL) {
        printf("no http state: \n");
        FAIL;
    }

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p1);

    if (PacketAlertCheck(p1, 1)) {
        printf("sid 1 matched but shouldn't have: ");
        FAIL;
    }

    r = AppLayerParserParse(
            NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOCLIENT, http_buf2, http_len2);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: \n", r);
        FAIL;
    }

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p2);

    if (!PacketAlertCheck(p2, 1)) {
        printf("sid 1 did not match but should have: ");
        FAIL;
    }

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
        "HTTP/1.0 200 abcdef\r\n"
        "Content-Type: text/html\r\n"
        "Content-Length: 6\r\n"
        "\r\n"
        "abcdef";
    uint32_t http_len2 = sizeof(http_buf2) - 1;
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
        FAIL;

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert http any any -> any any "
                               "(msg:\"http stat msg test\"; "
                               "pcre:/ab/Y; "
                               "content:\"ef\"; http_stat_msg; distance:2; "
                               "sid:1;)");
    if (de_ctx->sig_list == NULL)
        FAIL;

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParserParse(
            NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER, http_buf1, http_len1);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        FAIL;
    }

    http_state = f.alstate;
    if (http_state == NULL) {
        printf("no http state: \n");
        FAIL;
    }

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p1);

    if (PacketAlertCheck(p1, 1)) {
        printf("sid 1 matched but shouldn't have: ");
        FAIL;
    }

    r = AppLayerParserParse(
            NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOCLIENT, http_buf2, http_len2);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: \n", r);
        FAIL;
    }

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p2);

    if (!PacketAlertCheck(p2, 1)) {
        printf("sid 1 did not match but should have: ");
        FAIL;
    }

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
        "HTTP/1.0 200 abcdef\r\n"
        "Content-Type: text/html\r\n"
        "Content-Length: 6\r\n"
        "\r\n"
        "abcdef";
    uint32_t http_len2 = sizeof(http_buf2) - 1;
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
        FAIL;

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert http any any -> any any "
                               "(msg:\"http stat msg test\"; "
                               "pcre:/abc/Y; "
                               "content:!\"xyz\"; http_stat_msg; distance:0; within:3; "
                               "sid:1;)");
    if (de_ctx->sig_list == NULL)
        FAIL;

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParserParse(
            NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER, http_buf1, http_len1);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        FAIL;
    }

    http_state = f.alstate;
    if (http_state == NULL) {
        printf("no http state: \n");
        FAIL;
    }

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p1);

    if (PacketAlertCheck(p1, 1)) {
        printf("sid 1 matched but shouldn't have: ");
        FAIL;
    }

    r = AppLayerParserParse(
            NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOCLIENT, http_buf2, http_len2);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: \n", r);
        FAIL;
    }

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p2);

    if (!PacketAlertCheck(p2, 1)) {
        printf("sid 1 did not match but should have: ");
        FAIL;
    }

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
    Packet *p = NULL;
    Signature *s = NULL;
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
    p->flowflags |= FLOW_PKT_TOCLIENT;
    p->flowflags |= FLOW_PKT_ESTABLISHED;
    p->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    f.alproto = ALPROTO_HTTP1;

    StreamTcpInitConfig(true);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        FAIL;
    }

    de_ctx->flags |= DE_QUIET;

    s = de_ctx->sig_list = SigInit(de_ctx,"alert http any any -> any any (msg:"
                                   "\"HTTP status message\"; content:\"OK\"; "
                                   "http_stat_msg; sid:1;)");
    if (s == NULL) {
        FAIL;
    }

    s->next = SigInit(de_ctx,"alert http any any -> any any (msg:\"HTTP "
                      "Status message nocase\"; content:\"ok\"; nocase; "
                      "http_stat_msg; sid:2;)");
    if (s->next == NULL) {
        FAIL;
    }

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParserParse(
            NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER, httpbuf1, httplen1);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        FAIL;
    }

    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOCLIENT, httpbuf2, httplen2);
    if (r != 0) {
        printf("toclient chunk 1 returned %" PRId32 ", expected 0: ", r);
        FAIL;
    }

    http_state = f.alstate;
    if (http_state == NULL) {
        printf("no http state: ");
        FAIL;
    }

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);

    if (!(PacketAlertCheck(p, 1))) {
        printf("sid 1 didn't match but should have: ");
        FAIL;
    }
    if (!(PacketAlertCheck(p, 2))) {
        printf("sid 2 didn't match but should have: ");
        FAIL;
    }

    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    if (de_ctx != NULL) {
        DetectEngineCtxFree(de_ctx);
    }

    UTHFreePackets(&p, 1);
    FLOW_DESTROY(&f);
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
    Packet *p = NULL;
    Signature *s = NULL;
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
    p->flowflags |= FLOW_PKT_TOCLIENT;
    p->flowflags |= FLOW_PKT_ESTABLISHED;
    p->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    f.alproto = ALPROTO_HTTP1;

    StreamTcpInitConfig(true);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        FAIL;
    }

    de_ctx->flags |= DE_QUIET;

    s = de_ctx->sig_list = SigInit(de_ctx,"alert http any any -> any any (msg:"
                                   "\"HTTP status message\"; content:\"no\"; "
                                   "http_stat_msg; sid:1;)");
    if (s == NULL) {
        FAIL;
    }

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParserParse(
            NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER, httpbuf1, httplen1);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        FAIL;
    }

    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOCLIENT, httpbuf2, httplen2);
    if (r != 0) {
        printf("toclient chunk 1 returned %" PRId32 ", expected 0: ", r);
        FAIL;
    }

    http_state = f.alstate;
    if (http_state == NULL) {
        printf("no http state: ");
        FAIL;
    }

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);

    if (PacketAlertCheck(p, 1)) {
        printf("sid 1 matched but shouldn't: ");
        FAIL;
    }

    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
    if (det_ctx != NULL) {
        DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    }
    if (de_ctx != NULL) {
        DetectEngineCtxFree(de_ctx);
    }

    UTHFreePackets(&p, 1);
    FLOW_DESTROY(&f);
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
    Packet *p = NULL;
    Signature *s = NULL;
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
    p->flowflags |= FLOW_PKT_TOCLIENT;
    p->flowflags |= FLOW_PKT_ESTABLISHED;
    p->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    f.alproto = ALPROTO_HTTP1;

    StreamTcpInitConfig(true);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        FAIL;
    }

    de_ctx->flags |= DE_QUIET;

    s = de_ctx->sig_list = SigInit(de_ctx,"alert http any any -> any any (msg:"
                                   "\"HTTP status message\"; content:\"ok\"; "
                                   "nocase; http_stat_msg; sid:1;)");
    if (s == NULL) {
        FAIL;
    }

    s->next = SigInit(de_ctx,"alert http any any -> any any (msg:\"HTTP "
                        "Status message nocase\"; content:!\"Not\"; "
                        "http_stat_msg; sid:2;)");
    if (s->next == NULL) {
        FAIL;
    }

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParserParse(
            NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER, httpbuf1, httplen1);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        FAIL;
    }

    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOCLIENT, httpbuf2, httplen2);
    if (r != 0) {
        printf("toclient chunk 1 returned %" PRId32 ", expected 0: ", r);
        FAIL;
    }

    http_state = f.alstate;
    if (http_state == NULL) {
        printf("no http state: ");
        FAIL;
    }

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);

    if (! PacketAlertCheck(p, 1)) {
        printf("sid 1 didn't matched but should have: ");
        FAIL;
    }
    if (! PacketAlertCheck(p, 2)) {
        printf("sid 2 didn't matched but should have: ");
        FAIL;
    }

    AppLayerParserThreadCtxFree(alp_tctx);
    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);

    UTHFreePackets(&p, 1);
    FLOW_DESTROY(&f);
    StreamTcpFreeConfig(true);
    StatsThreadCleanup(&th_v);
    PASS;
}

/**
 * \brief   Register the UNITTESTS for the http_stat_msg keyword
 */
void DetectHttpStatMsgRegisterTests (void)
{
    UtRegisterTest("DetectHttpStatMsgSigTest01", DetectHttpStatMsgSigTest01);
    UtRegisterTest("DetectHttpStatMsgSigTest02", DetectHttpStatMsgSigTest02);
    UtRegisterTest("DetectHttpStatMsgSigTest03", DetectHttpStatMsgSigTest03);

    UtRegisterTest("DetectEngineHttpStatMsgTest01",
                   DetectEngineHttpStatMsgTest01);
    UtRegisterTest("DetectEngineHttpStatMsgTest02",
                   DetectEngineHttpStatMsgTest02);
    UtRegisterTest("DetectEngineHttpStatMsgTest03",
                   DetectEngineHttpStatMsgTest03);
    UtRegisterTest("DetectEngineHttpStatMsgTest04",
                   DetectEngineHttpStatMsgTest04);
    UtRegisterTest("DetectEngineHttpStatMsgTest05",
                   DetectEngineHttpStatMsgTest05);
    UtRegisterTest("DetectEngineHttpStatMsgTest06",
                   DetectEngineHttpStatMsgTest06);
    UtRegisterTest("DetectEngineHttpStatMsgTest07",
                   DetectEngineHttpStatMsgTest07);
    UtRegisterTest("DetectEngineHttpStatMsgTest08",
                   DetectEngineHttpStatMsgTest08);
    UtRegisterTest("DetectEngineHttpStatMsgTest09",
                   DetectEngineHttpStatMsgTest09);
    UtRegisterTest("DetectEngineHttpStatMsgTest10",
                   DetectEngineHttpStatMsgTest10);
    UtRegisterTest("DetectEngineHttpStatMsgTest11",
                   DetectEngineHttpStatMsgTest11);
    UtRegisterTest("DetectEngineHttpStatMsgTest12",
                   DetectEngineHttpStatMsgTest12);
    UtRegisterTest("DetectEngineHttpStatMsgTest13",
                   DetectEngineHttpStatMsgTest13);
    UtRegisterTest("DetectEngineHttpStatMsgTest14",
                   DetectEngineHttpStatMsgTest14);
    UtRegisterTest("DetectEngineHttpStatMsgTest15",
                   DetectEngineHttpStatMsgTest15);
}

/**
 * @}
 */
