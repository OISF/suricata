/* Copyright (C) 2007-2022 Open Information Security Foundation
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
 * \brief Handle HTTP host header.
 *        HHHD - Http Host Header Data
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

/**
 * \test Test that the http_host content matches against a http request
 *       which holds the content.
 */
static int DetectEngineHttpHHTest01(void)
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
        "Host: CONNECT\r\n"
        "User-Agent: www.onetwothreefourfivesixseven.org\r\n\r\n";
    uint32_t http_len = sizeof(http_buf) - 1;
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
    p->flowflags |= FLOW_PKT_TOSERVER;
    p->flowflags |= FLOW_PKT_ESTABLISHED;
    p->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    f.alproto = ALPROTO_HTTP1;

    StreamTcpInitConfig(true);

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert http any any -> any any "
                               "(msg:\"http host header test\"; "
                               "content:\"connect\"; http_host;  "
                               "sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParserParse(
            NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER, http_buf, http_len);
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
        SigGroupCleanup(de_ctx);
    if (de_ctx != NULL)
        SigCleanSignatures(de_ctx);
    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);

    StreamTcpFreeConfig(true);
    FLOW_DESTROY(&f);
    UTHFreePackets(&p, 1);
    return result;
}

/**
 * \test Test that the http_host content matches against a http request
 *       which holds the content.
 */
static int DetectEngineHttpHHTest02(void)
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
        "Host: CONNECT\r\n"
        "User-Agent: www.onetwothreefourfivesixseven.org\r\n\r\n";
    uint32_t http_len = sizeof(http_buf) - 1;
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
    p->flowflags |= FLOW_PKT_TOSERVER;
    p->flowflags |= FLOW_PKT_ESTABLISHED;
    p->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    f.alproto = ALPROTO_HTTP1;

    StreamTcpInitConfig(true);

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert http any any -> any any "
                               "(msg:\"http host header test\"; "
                               "content:\"co\"; depth:4; http_host;  "
                               "sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParserParse(
            NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER, http_buf, http_len);
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
        SigGroupCleanup(de_ctx);
    if (de_ctx != NULL)
        SigCleanSignatures(de_ctx);
    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);

    StreamTcpFreeConfig(true);
    FLOW_DESTROY(&f);
    UTHFreePackets(&p, 1);
    return result;
}

/**
 * \test Test that the http_host content matches against a http request
 *       which holds the content.
 */
static int DetectEngineHttpHHTest03(void)
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
        "Host: CONNECT\r\n"
        "User-Agent: www.onetwothreefourfivesixseven.org\r\n\r\n";
    uint32_t http_len = sizeof(http_buf) - 1;
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
    p->flowflags |= FLOW_PKT_TOSERVER;
    p->flowflags |= FLOW_PKT_ESTABLISHED;
    p->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    f.alproto = ALPROTO_HTTP1;

    StreamTcpInitConfig(true);

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert http any any -> any any "
                               "(msg:\"http_host header test\"; "
                               "content:!\"ect\"; depth:4; http_host;  "
                               "sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParserParse(
            NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER, http_buf, http_len);
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
        SigGroupCleanup(de_ctx);
    if (de_ctx != NULL)
        SigCleanSignatures(de_ctx);
    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);

    StreamTcpFreeConfig(true);
    FLOW_DESTROY(&f);
    UTHFreePackets(&p, 1);
    return result;
}

/**
 * \test Test that the http_host content matches against a http request
 *       which holds the content.
 */
static int DetectEngineHttpHHTest04(void)
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
        "Host: CONNECT\r\n"
        "User-Agent: www.onetwothreefourfivesixseven.org\r\n\r\n";
    uint32_t http_len = sizeof(http_buf) - 1;
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
    p->flowflags |= FLOW_PKT_TOSERVER;
    p->flowflags |= FLOW_PKT_ESTABLISHED;
    p->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    f.alproto = ALPROTO_HTTP1;

    StreamTcpInitConfig(true);

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert http any any -> any any "
                               "(msg:\"http host header test\"; "
                               "content:\"ect\"; depth:4; http_host;  "
                               "sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParserParse(
            NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER, http_buf, http_len);
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

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);

    if (PacketAlertCheck(p, 1)) {
        printf("sid 1 matched but shouldn't have: ");
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
    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);

    StreamTcpFreeConfig(true);
    FLOW_DESTROY(&f);
    UTHFreePackets(&p, 1);
    return result;
}

/**
 * \test Test that the http_host content matches against a http request
 *       which holds the content.
 */
static int DetectEngineHttpHHTest05(void)
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
        "Host: CONNECT\r\n"
        "User-Agent: www.onetwothreefourfivesixseven.org\r\n\r\n";
    uint32_t http_len = sizeof(http_buf) - 1;
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
    p->flowflags |= FLOW_PKT_TOSERVER;
    p->flowflags |= FLOW_PKT_ESTABLISHED;
    p->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    f.alproto = ALPROTO_HTTP1;

    StreamTcpInitConfig(true);

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert http any any -> any any "
                               "(msg:\"http host header test\"; "
                               "content:!\"con\"; depth:4; http_host;  "
                               "sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParserParse(
            NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER, http_buf, http_len);
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

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);

    if (PacketAlertCheck(p, 1)) {
        printf("sid 1 matched but shouldn't have: ");
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
    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);

    StreamTcpFreeConfig(true);
    FLOW_DESTROY(&f);
    UTHFreePackets(&p, 1);
    return result;
}

/**
 * \test Test that the http_host header content matches against a http request
 *       which holds the content.
 */
static int DetectEngineHttpHHTest06(void)
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
        "Host: CONNECT\r\n"
        "User-Agent: www.onetwothreefourfivesixseven.org\r\n\r\n";
    uint32_t http_len = sizeof(http_buf) - 1;
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
    p->flowflags |= FLOW_PKT_TOSERVER;
    p->flowflags |= FLOW_PKT_ESTABLISHED;
    p->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    f.alproto = ALPROTO_HTTP1;

    StreamTcpInitConfig(true);

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert http any any -> any any "
                               "(msg:\"http host header test\"; "
                               "content:\"ect\"; offset:3; http_host;  "
                               "sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParserParse(
            NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER, http_buf, http_len);
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
        SigGroupCleanup(de_ctx);
    if (de_ctx != NULL)
        SigCleanSignatures(de_ctx);
    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);

    StreamTcpFreeConfig(true);
    FLOW_DESTROY(&f);
    UTHFreePackets(&p, 1);
    return result;
}

/**
 * \test Test that the http_host content matches against a http request
 *       which holds the content.
 */
static int DetectEngineHttpHHTest07(void)
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
        "Host: CONNECT\r\n"
        "User-Agent: www.onetwothreefourfivesixseven.org\r\n\r\n";
    uint32_t http_len = sizeof(http_buf) - 1;
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
    p->flowflags |= FLOW_PKT_TOSERVER;
    p->flowflags |= FLOW_PKT_ESTABLISHED;
    p->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    f.alproto = ALPROTO_HTTP1;

    StreamTcpInitConfig(true);

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert http any any -> any any "
                               "(msg:\"http host header test\"; "
                               "content:!\"co\"; offset:3; http_host;  "
                               "sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParserParse(
            NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER, http_buf, http_len);
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
        SigGroupCleanup(de_ctx);
    if (de_ctx != NULL)
        SigCleanSignatures(de_ctx);
    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);

    StreamTcpFreeConfig(true);
    FLOW_DESTROY(&f);
    UTHFreePackets(&p, 1);
    return result;
}

/**
 * \test Test that the http_host header content matches against a http request
 *       which holds the content.
 */
static int DetectEngineHttpHHTest08(void)
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
        "Host: CONNECT\r\n"
        "User-Agent: www.onetwothreefourfivesixseven.org\r\n\r\n";
    uint32_t http_len = sizeof(http_buf) - 1;
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
    p->flowflags |= FLOW_PKT_TOSERVER;
    p->flowflags |= FLOW_PKT_ESTABLISHED;
    p->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    f.alproto = ALPROTO_HTTP1;

    StreamTcpInitConfig(true);

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert http any any -> any any "
                               "(msg:\"http host header test\"; "
                               "content:!\"ect\"; offset:3; http_host;  "
                               "sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParserParse(
            NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER, http_buf, http_len);
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

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);

    if (PacketAlertCheck(p, 1)) {
        printf("sid 1 matched but shouldn't have: ");
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
    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);

    StreamTcpFreeConfig(true);
    FLOW_DESTROY(&f);
    UTHFreePackets(&p, 1);
    return result;
}

/**
 * \test Test that the http_host header content matches against a http request
 *       which holds the content.
 */
static int DetectEngineHttpHHTest09(void)
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
        "Host: CONNECT\r\n"
        "User-Agent: www.onetwothreefourfivesixseven.org\r\n\r\n";
    uint32_t http_len = sizeof(http_buf) - 1;
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
    p->flowflags |= FLOW_PKT_TOSERVER;
    p->flowflags |= FLOW_PKT_ESTABLISHED;
    p->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    f.alproto = ALPROTO_HTTP1;

    StreamTcpInitConfig(true);

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert http any any -> any any "
                               "(msg:\"http host header test\"; "
                               "content:\"con\"; offset:3; http_host;  "
                               "sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParserParse(
            NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER, http_buf, http_len);
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

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);

    if (PacketAlertCheck(p, 1)) {
        printf("sid 1 matched but shouldn't have: ");
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
    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);

    StreamTcpFreeConfig(true);
    FLOW_DESTROY(&f);
    UTHFreePackets(&p, 1);
    return result;
}

/**
 * \test Test that the http_host header content matches against a http request
 *       which holds the content.
 */
static int DetectEngineHttpHHTest10(void)
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
        "Host: CONNECT\r\n"
        "User-Agent: www.onetwothreefourfivesixseven.org\r\n\r\n";
    uint32_t http_len = sizeof(http_buf) - 1;
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
    p->flowflags |= FLOW_PKT_TOSERVER;
    p->flowflags |= FLOW_PKT_ESTABLISHED;
    p->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    f.alproto = ALPROTO_HTTP1;

    StreamTcpInitConfig(true);

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert http any any -> any any "
                               "(msg:\"http_host header test\"; "
                               "content:\"co\"; http_host;  "
                               "content:\"ec\"; within:4; http_host;  "
                               "sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParserParse(
            NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER, http_buf, http_len);
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

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);

    if (!PacketAlertCheck(p, 1)) {
        printf("sid 1 didn't match but should have: ");
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
    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);

    StreamTcpFreeConfig(true);
    FLOW_DESTROY(&f);
    UTHFreePackets(&p, 1);
    return result;
}

/**
 * \test Test that the http_host header content matches against a http request
 *       which holds the content.
 */
static int DetectEngineHttpHHTest11(void)
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
        "Host: CONNECT\r\n"
        "User-Agent: www.onetwothreefourfivesixseven.org\r\n\r\n";
    uint32_t http_len = sizeof(http_buf) - 1;
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
    p->flowflags |= FLOW_PKT_TOSERVER;
    p->flowflags |= FLOW_PKT_ESTABLISHED;
    p->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    f.alproto = ALPROTO_HTTP1;

    StreamTcpInitConfig(true);

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert http any any -> any any "
                               "(msg:\"http_host header test\"; "
                               "content:\"co\"; http_host;  "
                               "content:!\"ec\"; within:3; http_host;  "
                               "sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParserParse(
            NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER, http_buf, http_len);
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

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);

    if (!PacketAlertCheck(p, 1)) {
        printf("sid 1 didn't match but should have: ");
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
    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);

    StreamTcpFreeConfig(true);
    FLOW_DESTROY(&f);
    UTHFreePackets(&p, 1);
    return result;
}

/**
 * \test Test that the http_host header content matches against a http request
 *       which holds the content.
 */
static int DetectEngineHttpHHTest12(void)
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
        "Host: CONNECT\r\n"
        "User-Agent: www.onetwothreefourfivesixseven.org\r\n\r\n";
    uint32_t http_len = sizeof(http_buf) - 1;
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
    p->flowflags |= FLOW_PKT_TOSERVER;
    p->flowflags |= FLOW_PKT_ESTABLISHED;
    p->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    f.alproto = ALPROTO_HTTP1;

    StreamTcpInitConfig(true);

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert http any any -> any any "
                               "(msg:\"http_host header test\"; "
                               "content:\"co\"; http_host;  "
                               "content:\"ec\"; within:3; http_host;  "
                               "sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParserParse(
            NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER, http_buf, http_len);
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

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);

    if (PacketAlertCheck(p, 1)) {
        printf("sid 1 matched but shouldn't have: ");
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
    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);

    StreamTcpFreeConfig(true);
    FLOW_DESTROY(&f);
    UTHFreePackets(&p, 1);
    return result;
}

/**
 * \test Test that the http_host header content matches against a http request
 *       which holds the content.
 */
static int DetectEngineHttpHHTest13(void)
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
        "Host: CONNECT\r\n"
        "User-Agent: www.onetwothreefourfivesixseven.org\r\n\r\n";
    uint32_t http_len = sizeof(http_buf) - 1;
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
    p->flowflags |= FLOW_PKT_TOSERVER;
    p->flowflags |= FLOW_PKT_ESTABLISHED;
    p->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    f.alproto = ALPROTO_HTTP1;

    StreamTcpInitConfig(true);

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert http any any -> any any "
                               "(msg:\"http_host header test\"; "
                               "content:\"co\"; http_host;  "
                               "content:!\"ec\"; within:4; http_host;  "
                               "sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParserParse(
            NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER, http_buf, http_len);
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

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);

    if (PacketAlertCheck(p, 1)) {
        printf("sid 1 matched but shouldn't have: ");
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
    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);

    StreamTcpFreeConfig(true);
    FLOW_DESTROY(&f);
    UTHFreePackets(&p, 1);
    return result;
}

/**
 * \test Test that the http_host header content matches against a http request
 *       which holds the content.
 */
static int DetectEngineHttpHHTest14(void)
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
        "Host: CONNECT\r\n"
        "User-Agent: www.onetwothreefourfivesixseven.org\r\n\r\n";
    uint32_t http_len = sizeof(http_buf) - 1;
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
    p->flowflags |= FLOW_PKT_TOSERVER;
    p->flowflags |= FLOW_PKT_ESTABLISHED;
    p->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    f.alproto = ALPROTO_HTTP1;

    StreamTcpInitConfig(true);

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert http any any -> any any "
                               "(msg:\"http_host header test\"; "
                               "content:\"co\"; http_host;  "
                               "content:\"ec\"; distance:2; http_host;  "
                               "sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParserParse(
            NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER, http_buf, http_len);
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

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);

    if (!PacketAlertCheck(p, 1)) {
        printf("sid 1 didn't match but should have: ");
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
    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);

    StreamTcpFreeConfig(true);
    FLOW_DESTROY(&f);
    UTHFreePackets(&p, 1);
    return result;
}

/**
 * \test Test that the http_host header content matches against a http request
 *       which holds the content.
 */
static int DetectEngineHttpHHTest15(void)
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
        "Host: CONNECT\r\n"
        "User-Agent: www.onetwothreefourfivesixseven.org\r\n\r\n";
    uint32_t http_len = sizeof(http_buf) - 1;
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
    p->flowflags |= FLOW_PKT_TOSERVER;
    p->flowflags |= FLOW_PKT_ESTABLISHED;
    p->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    f.alproto = ALPROTO_HTTP1;

    StreamTcpInitConfig(true);

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert http any any -> any any "
                               "(msg:\"http_host header test\"; "
                               "content:\"co\"; http_host;  "
                               "content:!\"ec\"; distance:3; http_host;  "
                               "sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParserParse(
            NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER, http_buf, http_len);
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

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);

    if (!PacketAlertCheck(p, 1)) {
        printf("sid 1 didn't match but should have: ");
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
    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);

    StreamTcpFreeConfig(true);
    FLOW_DESTROY(&f);
    UTHFreePackets(&p, 1);
    return result;
}

/**
 * \test Test that the http_host header content matches against a http request
 *       which holds the content.
 */
static int DetectEngineHttpHHTest16(void)
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
        "Host: CONNECT\r\n"
        "User-Agent: www.onetwothreefourfivesixseven.org\r\n\r\n";
    uint32_t http_len = sizeof(http_buf) - 1;
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
    p->flowflags |= FLOW_PKT_TOSERVER;
    p->flowflags |= FLOW_PKT_ESTABLISHED;
    p->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    f.alproto = ALPROTO_HTTP1;

    StreamTcpInitConfig(true);

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert http any any -> any any "
                               "(msg:\"http_host header test\"; "
                               "content:\"co\"; http_host;  "
                               "content:\"ec\"; distance:3; http_host;  "
                               "sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParserParse(
            NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER, http_buf, http_len);
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

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);

    if (PacketAlertCheck(p, 1)) {
        printf("sid 1 matched but shouldn't have: ");
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
    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);

    StreamTcpFreeConfig(true);
    FLOW_DESTROY(&f);
    UTHFreePackets(&p, 1);
    return result;
}

/**
 * \test Test that the http_host header content matches against a http request
 *       which holds the content.
 */
static int DetectEngineHttpHHTest17(void)
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
        "Host: CONNECT\r\n"
        "User-Agent: www.onetwothreefourfivesixseven.org\r\n\r\n";
    uint32_t http_len = sizeof(http_buf) - 1;
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
    p->flowflags |= FLOW_PKT_TOSERVER;
    p->flowflags |= FLOW_PKT_ESTABLISHED;
    p->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    f.alproto = ALPROTO_HTTP1;

    StreamTcpInitConfig(true);

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert http any any -> any any "
                               "(msg:\"http_host header test\"; "
                               "content:\"co\"; http_host;  "
                               "content:!\"ec\"; distance:2; http_host;  "
                               "sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParserParse(
            NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER, http_buf, http_len);
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

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);

    if (PacketAlertCheck(p, 1)) {
        printf("sid 1 matched but shouldn't have: ");
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
    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);

    StreamTcpFreeConfig(true);
    FLOW_DESTROY(&f);
    UTHFreePackets(&p, 1);
    return result;
}

static int DetectEngineHttpHHTest18(void)
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
        "Host: www.kaboom.com\r\n"
        "User-Agent: www.onetwothreefourfivesixseven.org\r\n\r\n";
    uint32_t http_len = sizeof(http_buf) - 1;
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
    p->flowflags |= FLOW_PKT_TOSERVER;
    p->flowflags |= FLOW_PKT_ESTABLISHED;
    p->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    f.alproto = ALPROTO_HTTP1;

    StreamTcpInitConfig(true);

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert http any any -> any any "
                               "(msg:\"http_host header test\"; "
                               "content:\"kaboom\"; http_host;  "
                               "sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParserParse(
            NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER, http_buf, http_len);
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

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);

    if (!PacketAlertCheck(p, 1)) {
        printf("sid 1 didn't match but should have: ");
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
    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);

    StreamTcpFreeConfig(true);
    FLOW_DESTROY(&f);
    UTHFreePackets(&p, 1);
    return result;
}

static int DetectEngineHttpHHTest19(void)
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
        "Host: www.kaboom.com:8080\r\n"
        "User-Agent: www.onetwothreefourfivesixseven.org\r\n\r\n";
    uint32_t http_len = sizeof(http_buf) - 1;
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
    p->flowflags |= FLOW_PKT_TOSERVER;
    p->flowflags |= FLOW_PKT_ESTABLISHED;
    p->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    f.alproto = ALPROTO_HTTP1;

    StreamTcpInitConfig(true);

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert http any any -> any any "
                               "(msg:\"http_host header test\"; "
                               "content:\"kaboom\"; http_host;  "
                               "sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParserParse(
            NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER, http_buf, http_len);
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

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);

    if (!PacketAlertCheck(p, 1)) {
        printf("sid 1 didn't match but should have: ");
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
    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);

    StreamTcpFreeConfig(true);
    FLOW_DESTROY(&f);
    UTHFreePackets(&p, 1);
    return result;
}

static int DetectEngineHttpHHTest20(void)
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
        "Host: www.kaboom.com:8080\r\n"
        "User-Agent: www.onetwothreefourfivesixseven.org\r\n\r\n";
    uint32_t http_len = sizeof(http_buf) - 1;
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
    p->flowflags |= FLOW_PKT_TOSERVER;
    p->flowflags |= FLOW_PKT_ESTABLISHED;
    p->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    f.alproto = ALPROTO_HTTP1;

    StreamTcpInitConfig(true);

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert http any any -> any any "
                               "(msg:\"http_host header test\"; "
                               "content:\"8080\"; http_host;  "
                               "sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParserParse(
            NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER, http_buf, http_len);
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

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);

    if (PacketAlertCheck(p, 1)) {
        printf("sid 1 matched but it shouldn't have: ");
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
    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);

    StreamTcpFreeConfig(true);
    FLOW_DESTROY(&f);
    UTHFreePackets(&p, 1);
    return result;
}

static int DetectEngineHttpHHTest21(void)
{
    TcpSession ssn;
    Packet *p = NULL;
    ThreadVars th_v;
    DetectEngineCtx *de_ctx = NULL;
    DetectEngineThreadCtx *det_ctx = NULL;
    HtpState *http_state = NULL;
    Flow f;
    uint8_t http_buf[] =
        "GET http://www.kaboom.com/index.html HTTP/1.0\r\n"
        "User-Agent: www.onetwothreefourfivesixseven.org\r\n\r\n";
    uint32_t http_len = sizeof(http_buf) - 1;
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
    p->flowflags |= FLOW_PKT_TOSERVER;
    p->flowflags |= FLOW_PKT_ESTABLISHED;
    p->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    f.alproto = ALPROTO_HTTP1;

    StreamTcpInitConfig(true);

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert http any any -> any any "
                               "(msg:\"http_host header test\"; "
                               "content:\"kaboom\"; http_host;  "
                               "sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParserParse(
            NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER, http_buf, http_len);
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

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);

    if (!PacketAlertCheck(p, 1)) {
        printf("sid 1 didn't match but should have: ");
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
    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);

    StreamTcpFreeConfig(true);
    FLOW_DESTROY(&f);
    UTHFreePackets(&p, 1);
    return result;
}

static int DetectEngineHttpHHTest22(void)
{
    TcpSession ssn;
    Packet *p = NULL;
    ThreadVars th_v;
    DetectEngineCtx *de_ctx = NULL;
    DetectEngineThreadCtx *det_ctx = NULL;
    HtpState *http_state = NULL;
    Flow f;
    uint8_t http_buf[] =
        "GET http://www.kaboom.com:8080/index.html HTTP/1.0\r\n"
        "User-Agent: www.onetwothreefourfivesixseven.org\r\n\r\n";
    uint32_t http_len = sizeof(http_buf) - 1;
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
    p->flowflags |= FLOW_PKT_TOSERVER;
    p->flowflags |= FLOW_PKT_ESTABLISHED;
    p->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    f.alproto = ALPROTO_HTTP1;

    StreamTcpInitConfig(true);

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert http any any -> any any "
                               "(msg:\"http_host header test\"; "
                               "content:\"kaboom\"; http_host;  "
                               "sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParserParse(
            NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER, http_buf, http_len);
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

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);

    if (!PacketAlertCheck(p, 1)) {
        printf("sid 1 didn't match but should have: ");
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
    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);

    StreamTcpFreeConfig(true);
    FLOW_DESTROY(&f);
    UTHFreePackets(&p, 1);
    return result;
}

static int DetectEngineHttpHHTest23(void)
{
    TcpSession ssn;
    Packet *p = NULL;
    ThreadVars th_v;
    DetectEngineCtx *de_ctx = NULL;
    DetectEngineThreadCtx *det_ctx = NULL;
    HtpState *http_state = NULL;
    Flow f;
    uint8_t http_buf[] =
        "GET http://www.kaboom.com:8080/index.html HTTP/1.0\r\n"
        "User-Agent: www.onetwothreefourfivesixseven.org\r\n\r\n";
    uint32_t http_len = sizeof(http_buf) - 1;
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
    p->flowflags |= FLOW_PKT_TOSERVER;
    p->flowflags |= FLOW_PKT_ESTABLISHED;
    p->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    f.alproto = ALPROTO_HTTP1;

    StreamTcpInitConfig(true);

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert http any any -> any any "
                               "(msg:\"http_host header test\"; "
                               "content:\"8080\"; http_host;  "
                               "sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParserParse(
            NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER, http_buf, http_len);
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

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);

    if (PacketAlertCheck(p, 1)) {
        printf("sid 1 matched but it shouldn't have: ");
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
    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);

    StreamTcpFreeConfig(true);
    FLOW_DESTROY(&f);
    UTHFreePackets(&p, 1);
    return result;
}

static int DetectEngineHttpHHTest24(void)
{
    TcpSession ssn;
    Packet *p = NULL;
    ThreadVars th_v;
    DetectEngineCtx *de_ctx = NULL;
    DetectEngineThreadCtx *det_ctx = NULL;
    HtpState *http_state = NULL;
    Flow f;
    uint8_t http_buf[] =
        "GET http://www.kaboom.com:8080/index.html HTTP/1.0\r\n"
        "Host: www.rabbit.com\r\n"
        "User-Agent: www.onetwothreefourfivesixseven.org\r\n\r\n";
    uint32_t http_len = sizeof(http_buf) - 1;
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
    p->flowflags |= FLOW_PKT_TOSERVER;
    p->flowflags |= FLOW_PKT_ESTABLISHED;
    p->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    f.alproto = ALPROTO_HTTP1;

    StreamTcpInitConfig(true);

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert http any any -> any any "
                               "(msg:\"http_host header test\"; "
                               "content:\"kaboom\"; http_host;  "
                               "sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParserParse(
            NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER, http_buf, http_len);
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

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);

    if (!PacketAlertCheck(p, 1)) {
        printf("sid 1 didn't match but it should have: ");
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
    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);

    StreamTcpFreeConfig(true);
    FLOW_DESTROY(&f);
    UTHFreePackets(&p, 1);
    return result;
}

static int DetectEngineHttpHHTest25(void)
{
    TcpSession ssn;
    Packet *p = NULL;
    ThreadVars th_v;
    DetectEngineCtx *de_ctx = NULL;
    DetectEngineThreadCtx *det_ctx = NULL;
    HtpState *http_state = NULL;
    Flow f;
    uint8_t http_buf[] =
        "GET http://www.kaboom.com:8080/index.html HTTP/1.0\r\n"
        "Host: www.rabbit.com\r\n"
        "User-Agent: www.onetwothreefourfivesixseven.org\r\n\r\n";
    uint32_t http_len = sizeof(http_buf) - 1;
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
    p->flowflags |= FLOW_PKT_TOSERVER;
    p->flowflags |= FLOW_PKT_ESTABLISHED;
    p->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    f.alproto = ALPROTO_HTTP1;

    StreamTcpInitConfig(true);

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert http any any -> any any "
                               "(msg:\"http_host header test\"; "
                               "content:\"rabbit\"; http_host; "
                               "sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParserParse(
            NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER, http_buf, http_len);
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

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);

    if (PacketAlertCheck(p, 1)) {
        printf("sid 1 matched but it shouldn't have: ");
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
    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);

    StreamTcpFreeConfig(true);
    FLOW_DESTROY(&f);
    UTHFreePackets(&p, 1);
    return result;
}

/**
 * \test Test that a signature containting a http_host is correctly parsed
 *       and the keyword is registered.
 */
static int DetectHttpHHTest01(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(msg:\"Testing http_host\"; "
                               "content:\"one\"; http_host; sid:1;)");
    if (de_ctx->sig_list != NULL) {
        result = 1;
    } else {
        goto end;
    }

 end:
    DetectEngineCtxFree(de_ctx);

    return result;
}

/**
 * \test Test that a signature containing an valid http_host entry is
 *       parsed.
 */
static int DetectHttpHHTest02(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(msg:\"Testing http_host\"; "
                               "content:\"one\"; http_host; sid:1;)");
    if (de_ctx->sig_list != NULL)
        result = 1;

 end:
    DetectEngineCtxFree(de_ctx);

    return result;
}

/**
 * \test Test that an invalid signature containing no content but a
 *       http_host is invalidated.
 */
static int DetectHttpHHTest03(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(msg:\"Testing http_host\"; "
                               "http_host; sid:1;)");
    if (de_ctx->sig_list == NULL)
        result = 1;

 end:
    DetectEngineCtxFree(de_ctx);

    return result;
}

/**
 * \test Test that an invalid signature containing a rawbytes along with a
 *       http_host is invalidated.
 */
static int DetectHttpHHTest04(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(msg:\"Testing http_host\"; "
                               "content:\"one\"; rawbytes; http_host; sid:1;)");
    if (de_ctx->sig_list == NULL)
        result = 1;

 end:
    DetectEngineCtxFree(de_ctx);

    return result;
}

/**
 * \test Test that a http_host with nocase is parsed.
 */
static int DetectHttpHHTest05(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(msg:\"Testing http_host\"; "
                               "content:\"one\"; http_host; sid:1;)");
    if (de_ctx->sig_list != NULL)
        result = 1;

 end:
    DetectEngineCtxFree(de_ctx);

    return result;
}

/** \test invalid sig: uppercase content */
static int DetectHttpHHTest05a(void)
{
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    de_ctx->flags |= DE_QUIET;

    Signature *s = DetectEngineAppendSig(de_ctx,
            "alert tcp any any -> any any "
            "(content:\"ABC\"; http_host; sid:1;)");
    FAIL_IF_NOT_NULL(s);

    DetectEngineCtxFree(de_ctx);
    PASS;
}

/**
 *\test Test that the http_host content matches against a http request
 *      which holds the content.
 */
static int DetectHttpHHTest06(void)
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
        "User-Agent: www.openinfosecfoundation.org\r\n"
        "Host: This is dummy message body\r\n"
        "Content-Type: text/html\r\n"
        "\r\n";
    uint32_t http_len = sizeof(http_buf) - 1;
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
    p->flowflags |= FLOW_PKT_TOSERVER;
    p->flowflags |= FLOW_PKT_ESTABLISHED;
    p->flags |= PKT_HAS_FLOW | PKT_STREAM_EST;
    f.alproto = ALPROTO_HTTP1;

    StreamTcpInitConfig(true);

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert http any any -> any any "
                               "(msg:\"http host test\"; "
                               "content:\"message\"; http_host; "
                               "sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParserParse(
            NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER, http_buf, http_len);
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
    UTHFreePackets(&p, 1);
    return result;
}

/**
 *\test Test that the http_host content matches against a http request
 *      which holds the content.
 */
static int DetectHttpHHTest07(void)
{
    TcpSession ssn;
    Packet *p1 = NULL;
    Packet *p2 = NULL;
    ThreadVars th_v;
    DetectEngineCtx *de_ctx = NULL;
    DetectEngineThreadCtx *det_ctx = NULL;
    HtpState *http_state = NULL;
    Flow f;
    uint8_t http1_buf[] =
        "GET /index.html HTTP/1.0\r\n"
        "User-Agent: www.openinfosecfoundation.org\r\n"
        "Host: This is dummy message";
    uint8_t http2_buf[] =
        "body1\r\n\r\n";
    uint32_t http1_len = sizeof(http1_buf) - 1;
    uint32_t http2_len = sizeof(http2_buf) - 1;
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
    p2->flowflags |= FLOW_PKT_TOSERVER;
    p2->flowflags |= FLOW_PKT_ESTABLISHED;
    p2->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    f.alproto = ALPROTO_HTTP1;

    StreamTcpInitConfig(true);

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert http any any -> any any "
                               "(msg:\"http host test\"; "
                               "content:\"message\"; http_host; "
                               "sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParserParse(
            NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER, http1_buf, http1_len);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
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
        printf("sid 1 matched on p1 but shouldn't have: ");
        goto end;
    }

    r = AppLayerParserParse(
            NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER, http2_buf, http2_len);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
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
 *\test Test that the http_host content matches against a http request
 *      which holds the content.
 */
static int DetectHttpHHTest08(void)
{
    TcpSession ssn;
    Packet *p1 = NULL;
    Packet *p2 = NULL;
    ThreadVars th_v;
    DetectEngineCtx *de_ctx = NULL;
    DetectEngineThreadCtx *det_ctx = NULL;
    HtpState *http_state = NULL;
    Flow f;
    uint8_t http1_buf[] =
        "GET /index.html HTTP/1.0\r\n"
        "User-Agent: www.openinfosecfoundation.org\r\n"
        "host: This is dummy mess";
    uint8_t http2_buf[] =
        "age body\r\n\r\n";
    uint32_t http1_len = sizeof(http1_buf) - 1;
    uint32_t http2_len = sizeof(http2_buf) - 1;
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
    p2->flowflags |= FLOW_PKT_TOSERVER;
    p2->flowflags |= FLOW_PKT_ESTABLISHED;
    p2->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    f.alproto = ALPROTO_HTTP1;

    StreamTcpInitConfig(true);

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert http any any -> any any "
                               "(msg:\"http host test\"; "
                               "content:\"message\"; http_host; "
                               "sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParserParse(
            NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER, http1_buf, http1_len);
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

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p1);

    if ((PacketAlertCheck(p1, 1))) {
        printf("sid 1 didn't match but should have");
        goto end;
    }

    r = AppLayerParserParse(
            NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER, http2_buf, http2_len);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
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

/**
 *\test Test that the http_host content matches against a http request
 *      which holds the content, against a cross boundary present pattern.
 */
static int DetectHttpHHTest09(void)
{
    TcpSession ssn;
    Packet *p1 = NULL;
    Packet *p2 = NULL;
    ThreadVars th_v;
    DetectEngineCtx *de_ctx = NULL;
    DetectEngineThreadCtx *det_ctx = NULL;
    HtpState *http_state = NULL;
    Flow f;
    uint8_t http1_buf[] =
        "GET /index.html HTTP/1.0\r\n"
        "User-Agent: www.openinfosecfoundation.org\r\n"
        "Host: This is dummy body1";
    uint8_t http2_buf[] =
        "This is dummy message body2\r\n"
        "Content-Type: text/html\r\n"
        "Content-Length: 46\r\n"
        "\r\n"
        "This is dummy body1";
    uint32_t http1_len = sizeof(http1_buf) - 1;
    uint32_t http2_len = sizeof(http2_buf) - 1;
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
    p2->flowflags |= FLOW_PKT_TOSERVER;
    p2->flowflags |= FLOW_PKT_ESTABLISHED;
    p2->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    f.alproto = ALPROTO_HTTP1;

    StreamTcpInitConfig(true);

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert http any any -> any any "
                               "(msg:\"http host test\"; "
                               "content:\"body1this\"; http_host; "
                               "sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParserParse(
            NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER, http1_buf, http1_len);
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

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p1);

    if ((PacketAlertCheck(p1, 1))) {
        printf("sid 1 didn't match but should have");
        goto end;
    }

    r = AppLayerParserParse(
            NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER, http2_buf, http2_len);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
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

/**
 *\test Test that the http_host content matches against a http request
 *      against a case insensitive pattern.
 */
static int DetectHttpHHTest10(void)
{
    TcpSession ssn;
    Packet *p1 = NULL;
    Packet *p2 = NULL;
    ThreadVars th_v;
    DetectEngineCtx *de_ctx = NULL;
    DetectEngineThreadCtx *det_ctx = NULL;
    HtpState *http_state = NULL;
    Flow f;
    uint8_t http1_buf[] =
        "GET /index.html HTTP/1.0\r\n"
        "User-Agent: www.openinfosecfoundation.org\r\n"
        "Host: This is dummy bodY1";
    uint8_t http2_buf[] =
        "This is dummy message body2\r\n"
        "Content-Type: text/html\r\n"
        "Content-Length: 46\r\n"
        "\r\n"
        "This is dummy bodY1";
    uint32_t http1_len = sizeof(http1_buf) - 1;
    uint32_t http2_len = sizeof(http2_buf) - 1;
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
    p2->flowflags |= FLOW_PKT_TOSERVER;
    p2->flowflags |= FLOW_PKT_ESTABLISHED;
    p2->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    f.alproto = ALPROTO_HTTP1;

    StreamTcpInitConfig(true);

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert http any any -> any any "
                               "(msg:\"http host test\"; "
                               "content:\"body1this\"; http_host; "
                               "sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParserParse(
            NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER, http1_buf, http1_len);
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
        printf("sid 1 didn't match but should have\n");
        goto end;
    }

    r = AppLayerParserParse(
            NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER, http2_buf, http2_len);
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

/**
 *\test Test that the negated http_host content matches against a
 *      http request which doesn't hold the content.
 */
static int DetectHttpHHTest11(void)
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
        "User-Agent: www.openinfosecfoundation.org\r\n"
        "Host: This is dummy message body\r\n"
        "Content-Type: text/html\r\n"
        "\r\n";
    uint32_t http_len = sizeof(http_buf) - 1;
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
    p->flowflags |= FLOW_PKT_TOSERVER;
    p->flowflags |= FLOW_PKT_ESTABLISHED;
    p->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    f.alproto = ALPROTO_HTTP1;

    StreamTcpInitConfig(true);

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert http any any -> any any "
                               "(msg:\"http host test\"; "
                               "content:!\"message\"; http_host; "
                               "sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParserParse(
            NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER, http_buf, http_len);
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

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);

    if (PacketAlertCheck(p, 1)) {
        printf("sid 1 matched but shouldn't have");
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
 *\test Negative test that the negated http_host content matches against a
 *      http request which holds hold the content.
 */
static int DetectHttpHHTest12(void)
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
        "User-Agent: www.openinfosecfoundation.org\r\n"
        "Host: This is dummy body\r\n"
        "\r\n";
    uint32_t http_len = sizeof(http_buf) - 1;
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
    p->flowflags |= FLOW_PKT_TOSERVER;
    p->flowflags |= FLOW_PKT_ESTABLISHED;
    p->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    f.alproto = ALPROTO_HTTP1;

    StreamTcpInitConfig(true);

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert http any any -> any any "
                               "(msg:\"http host test\"; "
                               "content:!\"message\"; http_host; "
                               "sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParserParse(
            NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER, http_buf, http_len);
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

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);

    if (!(PacketAlertCheck(p, 1))) {
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
    UTHFreePackets(&p, 1);
    return result;
}

/**
 * \test Test that the http_host content matches against a http request
 *       which holds the content.
 */
static int DetectHttpHHTest13(void)
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
        "User-Agent: www.openinfosecfoundation.org\r\n"
        "Host: longbufferabcdefghijklmnopqrstuvwxyz0123456789bufferend\r\n"
        "Content-Type: text/html\r\n"
        "\r\n";
    uint32_t http_len = sizeof(http_buf) - 1;
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
    p->flowflags |= FLOW_PKT_TOSERVER;
    p->flowflags |= FLOW_PKT_ESTABLISHED;
    p->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    f.alproto = ALPROTO_HTTP1;

    StreamTcpInitConfig(true);

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert http any any -> any any "
                               "(msg:\"http host test\"; "
                               "content:\"abcdefghijklmnopqrstuvwxyz0123456789\"; http_host; "
                               "sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParserParse(
            NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER, http_buf, http_len);
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

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);

    if (!(PacketAlertCheck(p, 1))) {
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
    UTHFreePackets(&p, 1);
    return result;
}

/**
 * \test multiple http transactions and body chunks of request handling
 */
static int DetectHttpHHTest14(void)
{
    int result = 0;
    Signature *s = NULL;
    DetectEngineThreadCtx *det_ctx = NULL;
    ThreadVars th_v;
    Flow f;
    TcpSession ssn;
    Packet *p = NULL;
    uint8_t httpbuf1[] = "POST / HTTP/1.1\r\n";
    uint8_t httpbuf2[] = "Cookie: dummy1\r\n";
    uint8_t httpbuf3[] = "Host: Body one!!\r\n\r\n";
    uint32_t httplen1 = sizeof(httpbuf1) - 1; /* minus the \0 */
    uint32_t httplen2 = sizeof(httpbuf2) - 1; /* minus the \0 */
    uint32_t httplen3 = sizeof(httpbuf3) - 1; /* minus the \0 */
    uint8_t httpbuf4[] = "GET /?var=val HTTP/1.1\r\n";
    uint8_t httpbuf5[] = "Cookie: dummy2\r\n";
    uint8_t httpbuf6[] = "Host: Body two\r\n\r\n";
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
    if (de_ctx == NULL) {
        goto end;
    }

    de_ctx->flags |= DE_QUIET;

    s = DetectEngineAppendSig(de_ctx, "alert tcp any any -> any any (content:\"POST\"; http_method; content:\"dummy1\"; http_cookie; content:\"body one\"; http_host; sid:1; rev:1;)");
    if (s == NULL) {
        printf("sig parse failed: ");
        goto end;
    }
    s = DetectEngineAppendSig(de_ctx, "alert tcp any any -> any any (content:\"GET\"; http_method; content:\"dummy2\"; http_cookie; content:\"body two\"; http_host; sid:2; rev:1;)");
    if (s == NULL) {
        printf("sig2 parse failed: ");
        goto end;
    }

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParserParse(
            NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER, httpbuf1, httplen1);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    if (PacketAlertCheck(p, 1)) {
        printf("sig 1 alerted: ");
        goto end;
    }
    p->alerts.cnt = 0;

    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER, httpbuf2, httplen2);
    if (r != 0) {
        printf("toserver chunk 2 returned %" PRId32 ", expected 0: ", r);
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    if (PacketAlertCheck(p, 1)) {
        printf("sig 1 alerted (2): ");
        goto end;
    }
    p->alerts.cnt = 0;

    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER, httpbuf3, httplen3);
    if (r != 0) {
        printf("toserver chunk 3 returned %" PRId32 ", expected 0: ", r);
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    if (!(PacketAlertCheck(p, 1))) {
        printf("sig 1 didn't alert: ");
        goto end;
    }
    p->alerts.cnt = 0;

    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER, httpbuf4, httplen4);
    if (r != 0) {
        printf("toserver chunk 5 returned %" PRId32 ", expected 0: ", r);
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    if (PacketAlertCheck(p, 1) || PacketAlertCheck(p, 2)) {
        printf("sig 1 alerted (4): ");
        goto end;
    }
    p->alerts.cnt = 0;

    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER, httpbuf5, httplen5);
    if (r != 0) {
        printf("toserver chunk 6 returned %" PRId32 ", expected 0: ", r);
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    if ((PacketAlertCheck(p, 1)) || (PacketAlertCheck(p, 2))) {
        printf("sig 1 alerted (request 2, chunk 6): ");
        goto end;
    }
    p->alerts.cnt = 0;

    SCLogDebug("sending data chunk 7");

    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER, httpbuf6, httplen6);
    if (r != 0) {
        printf("toserver chunk 7 returned %" PRId32 ", expected 0: ", r);
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    if (PacketAlertCheck(p, 1) || !(PacketAlertCheck(p, 2))) {
        printf("signature 2 didn't match or sig 1 matched, but shouldn't have: ");
        goto end;
    }
    p->alerts.cnt = 0;

    HtpState *htp_state = f.alstate;
    if (htp_state == NULL) {
        printf("no http state: ");
        result = 0;
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

static int DetectHttpHHTest22(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; content:\"two\"; http_host; "
                               "content:\"three\"; distance:10; http_host; content:\"four\"; sid:1;)");
    if (de_ctx->sig_list == NULL) {
        printf("de_ctx->sig_list == NULL\n");
        goto end;
    }

    if (de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH] == NULL) {
        printf("de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH] == NULL\n");
        goto end;
    }

    if (de_ctx->sig_list->sm_lists[g_http_host_buffer_id] == NULL) {
        printf("de_ctx->sig_list->sm_lists[g_http_host_buffer_id] == NULL\n");
        goto end;
    }

    DetectContentData *cd1 = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[DETECT_SM_LIST_PMATCH]->prev->ctx;
    DetectContentData *cd2 = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[DETECT_SM_LIST_PMATCH]->ctx;
    DetectContentData *hhhd1 = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_http_host_buffer_id]->prev->ctx;
    DetectContentData *hhhd2 = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_http_host_buffer_id]->ctx;
    if (cd1->flags != 0 || memcmp(cd1->content, "one", cd1->content_len) != 0 ||
        cd2->flags != 0 || memcmp(cd2->content, "four", cd2->content_len) != 0 ||
        hhhd1->flags != (DETECT_CONTENT_RELATIVE_NEXT) ||
        memcmp(hhhd1->content, "two", hhhd1->content_len) != 0 ||
        hhhd2->flags != (DETECT_CONTENT_DISTANCE) ||
        memcmp(hhhd2->content, "three", hhhd1->content_len) != 0) {
        goto end;
    }

    if (!DETECT_CONTENT_IS_SINGLE(cd1) ||
        !DETECT_CONTENT_IS_SINGLE(cd2) ||
        DETECT_CONTENT_IS_SINGLE(hhhd1) ||
        DETECT_CONTENT_IS_SINGLE(hhhd2)) {
        goto end;
    }

    result = 1;

 end:
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectHttpHHTest23(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_host; pcre:/two/; "
                               "content:\"three\"; distance:10; http_host; content:\"four\"; sid:1;)");
    if (de_ctx->sig_list == NULL) {
        printf("de_ctx->sig_list == NULL\n");
        goto end;
    }

    if (de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH] == NULL) {
        printf("de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH] == NULL\n");
        goto end;
    }

    if (de_ctx->sig_list->sm_lists[g_http_host_buffer_id] == NULL) {
        printf("de_ctx->sig_list->sm_lists[g_http_host_buffer_id] == NULL\n");
        goto end;
    }

    DetectPcreData *pd1 = (DetectPcreData *)de_ctx->sig_list->sm_lists_tail[DETECT_SM_LIST_PMATCH]->prev->ctx;
    DetectContentData *cd2 = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[DETECT_SM_LIST_PMATCH]->ctx;
    DetectContentData *hhhd1 = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_http_host_buffer_id]->prev->ctx;
    DetectContentData *hhhd2 = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_http_host_buffer_id]->ctx;
    if (pd1->flags != 0 ||
        cd2->flags != 0 || memcmp(cd2->content, "four", cd2->content_len) != 0 ||
        hhhd1->flags != (DETECT_CONTENT_RELATIVE_NEXT) ||
        memcmp(hhhd1->content, "one", hhhd1->content_len) != 0 ||
        hhhd2->flags != (DETECT_CONTENT_DISTANCE) ||
        memcmp(hhhd2->content, "three", hhhd1->content_len) != 0) {
        goto end;
    }

    if (!DETECT_CONTENT_IS_SINGLE(cd2) ||
        DETECT_CONTENT_IS_SINGLE(hhhd1) ||
        DETECT_CONTENT_IS_SINGLE(hhhd2)) {
        goto end;
    }

    result = 1;

 end:
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectHttpHHTest24(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_host; pcre:/two/; "
                               "content:\"three\"; distance:10; within:15; http_host; content:\"four\"; sid:1;)");
    if (de_ctx->sig_list == NULL) {
        printf("de_ctx->sig_list == NULL\n");
        goto end;
    }

    if (de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH] == NULL) {
        printf("de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH] == NULL\n");
        goto end;
    }

    if (de_ctx->sig_list->sm_lists[g_http_host_buffer_id] == NULL) {
        printf("de_ctx->sig_list->sm_lists[g_http_host_buffer_id] == NULL\n");
        goto end;
    }

    DetectPcreData *pd1 = (DetectPcreData *)de_ctx->sig_list->sm_lists_tail[DETECT_SM_LIST_PMATCH]->prev->ctx;
    DetectContentData *cd2 = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[DETECT_SM_LIST_PMATCH]->ctx;
    DetectContentData *hhhd1 = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_http_host_buffer_id]->prev->ctx;
    DetectContentData *hhhd2 = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_http_host_buffer_id]->ctx;
    if (pd1->flags != 0 ||
        cd2->flags != 0 || memcmp(cd2->content, "four", cd2->content_len) != 0 ||
        hhhd1->flags != (DETECT_CONTENT_RELATIVE_NEXT) ||
        memcmp(hhhd1->content, "one", hhhd1->content_len) != 0 ||
        hhhd2->flags != (DETECT_CONTENT_DISTANCE | DETECT_CONTENT_WITHIN) ||
        memcmp(hhhd2->content, "three", hhhd1->content_len) != 0) {
        goto end;
    }

    if (!DETECT_CONTENT_IS_SINGLE(cd2) ||
        DETECT_CONTENT_IS_SINGLE(hhhd1) ||
        DETECT_CONTENT_IS_SINGLE(hhhd2)) {
        goto end;
    }

    result = 1;

 end:
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectHttpHHTest25(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_host; pcre:/two/; "
                               "content:\"three\"; distance:10; http_host; "
                               "content:\"four\"; distance:10; sid:1;)");
    if (de_ctx->sig_list == NULL) {
        printf("de_ctx->sig_list == NULL\n");
        goto end;
    }

    if (de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH] == NULL) {
        printf("de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH] == NULL\n");
        goto end;
    }

    if (de_ctx->sig_list->sm_lists[g_http_host_buffer_id] == NULL) {
        printf("de_ctx->sig_list->sm_lists[g_http_host_buffer_id] == NULL\n");
        goto end;
    }

    DetectPcreData *pd1 = (DetectPcreData *)de_ctx->sig_list->sm_lists_tail[DETECT_SM_LIST_PMATCH]->prev->ctx;
    DetectContentData *cd2 = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[DETECT_SM_LIST_PMATCH]->ctx;
    DetectContentData *hhhd1 = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_http_host_buffer_id]->prev->ctx;
    DetectContentData *hhhd2 = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_http_host_buffer_id]->ctx;
    if (pd1->flags != DETECT_PCRE_RELATIVE_NEXT ||
        cd2->flags != DETECT_CONTENT_DISTANCE ||
        memcmp(cd2->content, "four", cd2->content_len) != 0 ||
        hhhd1->flags != (DETECT_CONTENT_RELATIVE_NEXT) ||
        memcmp(hhhd1->content, "one", hhhd1->content_len) != 0 ||
        hhhd2->flags != (DETECT_CONTENT_DISTANCE) ||
        memcmp(hhhd2->content, "three", hhhd1->content_len) != 0) {
        goto end;
    }

    if (DETECT_CONTENT_IS_SINGLE(cd2) ||
        DETECT_CONTENT_IS_SINGLE(hhhd1) ||
        DETECT_CONTENT_IS_SINGLE(hhhd2)) {
        goto end;
    }

    result = 1;

 end:
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectHttpHHTest26(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; offset:10; http_host; pcre:/two/; "
                               "content:\"three\"; distance:10; http_host; within:10; "
                               "content:\"four\"; distance:10; sid:1;)");
    if (de_ctx->sig_list == NULL) {
        printf("de_ctx->sig_list == NULL\n");
        goto end;
    }

    if (de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH] == NULL) {
        printf("de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH] == NULL\n");
        goto end;
    }

    if (de_ctx->sig_list->sm_lists[g_http_host_buffer_id] == NULL) {
        printf("de_ctx->sig_list->sm_lists[g_http_host_buffer_id] == NULL\n");
        goto end;
    }

    DetectPcreData *pd1 = (DetectPcreData *)de_ctx->sig_list->sm_lists_tail[DETECT_SM_LIST_PMATCH]->prev->ctx;
    DetectContentData *cd2 = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[DETECT_SM_LIST_PMATCH]->ctx;
    DetectContentData *hhhd1 = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_http_host_buffer_id]->prev->ctx;
    DetectContentData *hhhd2 = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_http_host_buffer_id]->ctx;
    if (pd1->flags != (DETECT_PCRE_RELATIVE_NEXT) ||
        cd2->flags != DETECT_CONTENT_DISTANCE ||
        memcmp(cd2->content, "four", cd2->content_len) != 0 ||
        hhhd1->flags != (DETECT_CONTENT_RELATIVE_NEXT | DETECT_CONTENT_OFFSET) ||
        memcmp(hhhd1->content, "one", hhhd1->content_len) != 0 ||
        hhhd2->flags != (DETECT_CONTENT_DISTANCE | DETECT_CONTENT_WITHIN) ||
        memcmp(hhhd2->content, "three", hhhd1->content_len) != 0) {
        printf ("failed: http_host incorrect flags");
        goto end;
    }

    if (DETECT_CONTENT_IS_SINGLE(cd2) ||
        DETECT_CONTENT_IS_SINGLE(hhhd1) ||
        DETECT_CONTENT_IS_SINGLE(hhhd2)) {
        goto end;
    }

    result = 1;

 end:
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectHttpHHTest27(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; offset:10; http_host; pcre:/two/; "
                               "content:\"three\"; distance:10; http_host; within:10; "
                               "content:\"four\"; distance:10; sid:1;)");
    if (de_ctx->sig_list == NULL) {
        printf("de_ctx->sig_list == NULL\n");
        goto end;
    }

    result = 1;

 end:
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectHttpHHTest28(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_host; pcre:/two/; "
                               "content:\"three\"; http_host; depth:10; "
                               "content:\"four\"; distance:10; sid:1;)");
    if (de_ctx->sig_list == NULL) {
        printf("de_ctx->sig_list == NULL\n");
        goto end;
    }

    if (de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH] == NULL) {
        printf("de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH] == NULL\n");
        goto end;
    }

    if (de_ctx->sig_list->sm_lists[g_http_host_buffer_id] == NULL) {
        printf("de_ctx->sig_list->sm_lists[g_http_host_buffer_id] == NULL\n");
        goto end;
    }

    DetectPcreData *pd1 = (DetectPcreData *)de_ctx->sig_list->sm_lists_tail[DETECT_SM_LIST_PMATCH]->prev->ctx;
    DetectContentData *cd2 = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[DETECT_SM_LIST_PMATCH]->ctx;
    DetectContentData *hhhd1 = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_http_host_buffer_id]->prev->ctx;
    DetectContentData *hhhd2 = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_http_host_buffer_id]->ctx;
    if (pd1->flags != (DETECT_PCRE_RELATIVE_NEXT) ||
        cd2->flags != DETECT_CONTENT_DISTANCE ||
        memcmp(cd2->content, "four", cd2->content_len) != 0 ||
        hhhd1->flags != (0) ||
        memcmp(hhhd1->content, "one", hhhd1->content_len) != 0 ||
        hhhd2->flags != (DETECT_CONTENT_DEPTH) ||
        memcmp(hhhd2->content, "three", hhhd1->content_len) != 0) {
        goto end;
    }

    if (DETECT_CONTENT_IS_SINGLE(cd2) ||
        !DETECT_CONTENT_IS_SINGLE(hhhd1) ||
        DETECT_CONTENT_IS_SINGLE(hhhd2)) {
        goto end;
    }

    result = 1;

 end:
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectHttpHHTest29(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_host; "
                               "content:\"two\"; distance:0; http_host; sid:1;)");
    if (de_ctx->sig_list == NULL) {
        printf("de_ctx->sig_list == NULL\n");
        goto end;
    }

    if (de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH] != NULL) {
        printf("de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH] != NULL\n");
        goto end;
    }

    if (de_ctx->sig_list->sm_lists[g_http_host_buffer_id] == NULL) {
        printf("de_ctx->sig_list->sm_lists[g_http_host_buffer_id] == NULL\n");
        goto end;
    }

    DetectContentData *hhhd1 = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_http_host_buffer_id]->prev->ctx;
    DetectContentData *hhhd2 = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_http_host_buffer_id]->ctx;
    if (hhhd1->flags != (DETECT_CONTENT_RELATIVE_NEXT) ||
        memcmp(hhhd1->content, "one", hhhd1->content_len) != 0 ||
        hhhd2->flags != (DETECT_CONTENT_DISTANCE) ||
        memcmp(hhhd2->content, "two", hhhd1->content_len) != 0) {
        goto end;
    }

    result = 1;

 end:
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectHttpHHTest30(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_host; "
                               "content:\"two\"; within:5; http_host; sid:1;)");
    if (de_ctx->sig_list == NULL) {
        printf("de_ctx->sig_list == NULL\n");
        goto end;
    }

    if (de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH] != NULL) {
        printf("de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH] != NULL\n");
        goto end;
    }

    if (de_ctx->sig_list->sm_lists[g_http_host_buffer_id] == NULL) {
        printf("de_ctx->sig_list->sm_lists[g_http_host_buffer_id] == NULL\n");
        goto end;
    }

    DetectContentData *hhhd1 = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_http_host_buffer_id]->prev->ctx;
    DetectContentData *hhhd2 = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_http_host_buffer_id]->ctx;
    if (hhhd1->flags != (DETECT_CONTENT_RELATIVE_NEXT) ||
        memcmp(hhhd1->content, "one", hhhd1->content_len) != 0 ||
        hhhd2->flags != (DETECT_CONTENT_WITHIN) ||
        memcmp(hhhd2->content, "two", hhhd1->content_len) != 0) {
        goto end;
    }

    result = 1;

 end:
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectHttpHHTest31(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; within:5; http_host; sid:1;)");
    if (de_ctx->sig_list == NULL) {
        printf("de_ctx->sig_list == NULL\n");
        goto end;
    }

    result = 1;

 end:
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectHttpHHTest32(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_host; within:5; sid:1;)");
    if (de_ctx->sig_list == NULL) {
        printf("de_ctx->sig_list != NULL\n");
        goto end;
    }

    result = 1;

 end:
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectHttpHHTest33(void)
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
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectHttpHHTest34(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(pcre:/one/W; "
                               "content:\"two\"; within:5; http_host; sid:1;)");
    if (de_ctx->sig_list == NULL) {
        printf("de_ctx->sig_list == NULL\n");
        goto end;
    }

    if (de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH] != NULL) {
        printf("de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH] != NULL\n");
        goto end;
    }

    if (de_ctx->sig_list->sm_lists[g_http_host_buffer_id] == NULL) {
        printf("de_ctx->sig_list->sm_lists[g_http_host_buffer_id] == NULL\n");
        goto end;
    }

    if (de_ctx->sig_list->sm_lists_tail[g_http_host_buffer_id] == NULL ||
        de_ctx->sig_list->sm_lists_tail[g_http_host_buffer_id]->type != DETECT_CONTENT ||
        de_ctx->sig_list->sm_lists_tail[g_http_host_buffer_id]->prev == NULL ||
        de_ctx->sig_list->sm_lists_tail[g_http_host_buffer_id]->prev->type != DETECT_PCRE) {

        goto end;
    }

    DetectPcreData *pd1 = (DetectPcreData *)de_ctx->sig_list->sm_lists_tail[g_http_host_buffer_id]->prev->ctx;
    DetectContentData *hhhd2 = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_http_host_buffer_id]->ctx;
    if (pd1->flags != (DETECT_PCRE_RELATIVE_NEXT) ||
        hhhd2->flags != (DETECT_CONTENT_WITHIN) ||
        memcmp(hhhd2->content, "two", hhhd2->content_len) != 0) {
        goto end;
    }

    result = 1;

 end:
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectHttpHHTest35(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"two\"; http_host; "
                               "pcre:/one/WR; sid:1;)");
    if (de_ctx->sig_list == NULL) {
        printf("de_ctx->sig_list == NULL\n");
        goto end;
    }

    if (de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH] != NULL) {
        printf("de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH] != NULL\n");
        goto end;
    }

    if (de_ctx->sig_list->sm_lists[g_http_host_buffer_id] == NULL) {
        printf("de_ctx->sig_list->sm_lists[g_http_host_buffer_id] == NULL\n");
        goto end;
    }

    if (de_ctx->sig_list->sm_lists_tail[g_http_host_buffer_id] == NULL ||
        de_ctx->sig_list->sm_lists_tail[g_http_host_buffer_id]->type != DETECT_PCRE ||
        de_ctx->sig_list->sm_lists_tail[g_http_host_buffer_id]->prev == NULL ||
        de_ctx->sig_list->sm_lists_tail[g_http_host_buffer_id]->prev->type != DETECT_CONTENT) {

        goto end;
    }

    DetectContentData *hhhd1 = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_http_host_buffer_id]->prev->ctx;
    DetectPcreData *pd2 = (DetectPcreData *)de_ctx->sig_list->sm_lists_tail[g_http_host_buffer_id]->ctx;
    if (pd2->flags != (DETECT_PCRE_RELATIVE) ||
        hhhd1->flags != (DETECT_CONTENT_RELATIVE_NEXT) ||
        memcmp(hhhd1->content, "two", hhhd1->content_len) != 0) {
        goto end;
    }

    result = 1;

 end:
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectHttpHHTest36(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(pcre:/one/W; "
                               "content:\"two\"; distance:5; http_host; sid:1;)");
    if (de_ctx->sig_list == NULL) {
        printf("de_ctx->sig_list == NULL\n");
        goto end;
    }

    if (de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH] != NULL) {
        printf("de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH] != NULL\n");
        goto end;
    }

    if (de_ctx->sig_list->sm_lists[g_http_host_buffer_id] == NULL) {
        printf("de_ctx->sig_list->sm_lists[g_http_host_buffer_id] == NULL\n");
        goto end;
    }

    if (de_ctx->sig_list->sm_lists_tail[g_http_host_buffer_id] == NULL ||
        de_ctx->sig_list->sm_lists_tail[g_http_host_buffer_id]->type != DETECT_CONTENT ||
        de_ctx->sig_list->sm_lists_tail[g_http_host_buffer_id]->prev == NULL ||
        de_ctx->sig_list->sm_lists_tail[g_http_host_buffer_id]->prev->type != DETECT_PCRE) {

        goto end;
    }

    DetectPcreData *pd1 = (DetectPcreData *)de_ctx->sig_list->sm_lists_tail[g_http_host_buffer_id]->prev->ctx;
    DetectContentData *hhhd2 = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_http_host_buffer_id]->ctx;
    if (pd1->flags != (DETECT_PCRE_RELATIVE_NEXT) ||
        hhhd2->flags != (DETECT_CONTENT_DISTANCE) ||
        memcmp(hhhd2->content, "two", hhhd2->content_len) != 0) {
        goto end;
    }

    result = 1;

 end:
    DetectEngineCtxFree(de_ctx);
    return result;
}

/**
 * \test Test that a signature containting a http_raw_host is correctly parsed
 *       and the keyword is registered.
 */
static int DetectHttpHRHTest01(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(msg:\"Testing http_raw_host\"; "
                               "content:\"one\"; http_raw_host;  sid:1;)");
    if (de_ctx->sig_list != NULL) {
        result = 1;
    } else {
        goto end;
    }

 end:
    DetectEngineCtxFree(de_ctx);

    return result;
}

/**
 * \test Test that a signature containing an valid http_raw_host entry is
 *       parsed.
 */
static int DetectHttpHRHTest02(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(msg:\"Testing http_raw_host\"; "
                               "content:\"one\"; http_raw_host;  sid:1;)");
    if (de_ctx->sig_list != NULL)
        result = 1;

 end:
    DetectEngineCtxFree(de_ctx);

    return result;
}

/**
 * \test Test that an invalid signature containing no content but a
 *       http_raw_host is invalidated.
 */
static int DetectHttpHRHTest03(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(msg:\"Testing http_raw_host\"; "
                               "http_raw_host; sid:1;)");
    if (de_ctx->sig_list == NULL)
        result = 1;

 end:
    DetectEngineCtxFree(de_ctx);

    return result;
}

/**
 * \test Test that an invalid signature containing a rawbytes along with a
 *       http_raw_host is invalidated.
 */
static int DetectHttpHRHTest04(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(msg:\"Testing http_raw_host\"; "
                               "content:\"one\"; rawbytes; http_raw_host; sid:1;)");
    if (de_ctx->sig_list == NULL)
        result = 1;

 end:
    DetectEngineCtxFree(de_ctx);

    return result;
}

/**
 * \test Test that a http_raw_host with nocase is parsed.
 */
static int DetectHttpHRHTest05(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(msg:\"Testing http_raw_host\"; "
                               "content:\"one\"; http_raw_host;  sid:1;)");
    if (de_ctx->sig_list != NULL)
        result = 1;

 end:
    DetectEngineCtxFree(de_ctx);

    return result;
}

/**
 *\test Test that the http_raw_host content matches against a http request
 *      which holds the content.
 */
static int DetectHttpHRHTest06(void)
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
        "User-Agent: www.openinfosecfoundation.org\r\n"
        "Host: This is dummy message body\r\n"
        "Content-Type: text/html\r\n"
        "\r\n";
    uint32_t http_len = sizeof(http_buf) - 1;
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
    p->flowflags |= FLOW_PKT_TOSERVER;
    p->flowflags |= FLOW_PKT_ESTABLISHED;
    p->flags |= PKT_HAS_FLOW | PKT_STREAM_EST;
    f.alproto = ALPROTO_HTTP1;

    StreamTcpInitConfig(true);

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert http any any -> any any "
                               "(msg:\"http host test\"; "
                               "content:\"message\"; http_raw_host;  "
                               "sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParserParse(
            NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER, http_buf, http_len);
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
    UTHFreePackets(&p, 1);
    return result;
}

/**
 *\test Test that the http_raw_host content matches against a http request
 *      which holds the content.
 */
static int DetectHttpHRHTest07(void)
{
    TcpSession ssn;
    Packet *p1 = NULL;
    Packet *p2 = NULL;
    ThreadVars th_v;
    DetectEngineCtx *de_ctx = NULL;
    DetectEngineThreadCtx *det_ctx = NULL;
    HtpState *http_state = NULL;
    Flow f;
    uint8_t http1_buf[] =
        "GET /index.html HTTP/1.0\r\n"
        "User-Agent: www.openinfosecfoundation.org\r\n"
        "Host: This is dummy message";
    uint8_t http2_buf[] =
        "body1\r\n\r\n";
    uint32_t http1_len = sizeof(http1_buf) - 1;
    uint32_t http2_len = sizeof(http2_buf) - 1;
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
    p2->flowflags |= FLOW_PKT_TOSERVER;
    p2->flowflags |= FLOW_PKT_ESTABLISHED;
    p2->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    f.alproto = ALPROTO_HTTP1;

    StreamTcpInitConfig(true);

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert http any any -> any any "
                               "(msg:\"http host test\"; "
                               "content:\"message\"; http_raw_host;  "
                               "sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParserParse(
            NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER, http1_buf, http1_len);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
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
        printf("sid 1 matched on p1 but shouldn't have: ");
        goto end;
    }

    r = AppLayerParserParse(
            NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER, http2_buf, http2_len);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
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
 *\test Test that the http_raw_host content matches against a http request
 *      which holds the content.
 */
static int DetectHttpHRHTest08(void)
{
    TcpSession ssn;
    Packet *p1 = NULL;
    Packet *p2 = NULL;
    ThreadVars th_v;
    DetectEngineCtx *de_ctx = NULL;
    DetectEngineThreadCtx *det_ctx = NULL;
    HtpState *http_state = NULL;
    Flow f;
    uint8_t http1_buf[] =
        "GET /index.html HTTP/1.0\r\n"
        "User-Agent: www.openinfosecfoundation.org\r\n"
        "host: This is dummy mess";
    uint8_t http2_buf[] =
        "age body\r\n\r\n";
    uint32_t http1_len = sizeof(http1_buf) - 1;
    uint32_t http2_len = sizeof(http2_buf) - 1;
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
    p2->flowflags |= FLOW_PKT_TOSERVER;
    p2->flowflags |= FLOW_PKT_ESTABLISHED;
    p2->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    f.alproto = ALPROTO_HTTP1;

    StreamTcpInitConfig(true);

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert http any any -> any any "
                               "(msg:\"http host test\"; "
                               "content:\"message\"; http_raw_host;  "
                               "sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParserParse(
            NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER, http1_buf, http1_len);
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

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p1);

    if ((PacketAlertCheck(p1, 1))) {
        printf("sid 1 didn't match but should have");
        goto end;
    }

    r = AppLayerParserParse(
            NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER, http2_buf, http2_len);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
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

/**
 *\test Test that the http_raw_host content matches against a http request
 *      which holds the content, against a cross boundary present pattern.
 */
static int DetectHttpHRHTest09(void)
{
    TcpSession ssn;
    Packet *p1 = NULL;
    Packet *p2 = NULL;
    ThreadVars th_v;
    DetectEngineCtx *de_ctx = NULL;
    DetectEngineThreadCtx *det_ctx = NULL;
    HtpState *http_state = NULL;
    Flow f;
    uint8_t http1_buf[] =
        "GET /index.html HTTP/1.0\r\n"
        "User-Agent: www.openinfosecfoundation.org\r\n"
        "Host: This is dummy body1";
    uint8_t http2_buf[] =
        "This is dummy message body2\r\n"
        "Content-Type: text/html\r\n"
        "Content-Length: 46\r\n"
        "\r\n"
        "This is dummy body1";
    uint32_t http1_len = sizeof(http1_buf) - 1;
    uint32_t http2_len = sizeof(http2_buf) - 1;
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
    p2->flowflags |= FLOW_PKT_TOSERVER;
    p2->flowflags |= FLOW_PKT_ESTABLISHED;
    p2->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    f.alproto = ALPROTO_HTTP1;

    StreamTcpInitConfig(true);

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert http any any -> any any "
                               "(msg:\"http host test\"; "
                               "content:\"body1This\"; http_raw_host;  "
                               "sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParserParse(
            NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER, http1_buf, http1_len);
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

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p1);

    if ((PacketAlertCheck(p1, 1))) {
        printf("sid 1 didn't match but should have");
        goto end;
    }

    r = AppLayerParserParse(
            NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER, http2_buf, http2_len);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
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

/**
 *\test Test that the http_raw_host content matches against a http request
 *      against a case insensitive pattern.
 */
static int DetectHttpHRHTest10(void)
{
    TcpSession ssn;
    Packet *p1 = NULL;
    Packet *p2 = NULL;
    ThreadVars th_v;
    DetectEngineCtx *de_ctx = NULL;
    DetectEngineThreadCtx *det_ctx = NULL;
    HtpState *http_state = NULL;
    Flow f;
    uint8_t http1_buf[] =
        "GET /index.html HTTP/1.0\r\n"
        "User-Agent: www.openinfosecfoundation.org\r\n"
        "Host: This is dummy bodY1";
    uint8_t http2_buf[] =
        "This is dummy message body2\r\n"
        "Content-Type: text/html\r\n"
        "Content-Length: 46\r\n"
        "\r\n"
        "This is dummy bodY1";
    uint32_t http1_len = sizeof(http1_buf) - 1;
    uint32_t http2_len = sizeof(http2_buf) - 1;
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
    p2->flowflags |= FLOW_PKT_TOSERVER;
    p2->flowflags |= FLOW_PKT_ESTABLISHED;
    p2->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    f.alproto = ALPROTO_HTTP1;

    StreamTcpInitConfig(true);

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert http any any -> any any "
                               "(msg:\"http host test\"; "
                               "content:\"bodY1This\"; http_raw_host; "
                               "sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParserParse(
            NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER, http1_buf, http1_len);
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
        printf("sid 1 didn't match but should have\n");
        goto end;
    }

    r = AppLayerParserParse(
            NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER, http2_buf, http2_len);
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

/**
 *\test Test that the negated http_raw_host content matches against a
 *      http request which doesn't hold the content.
 */
static int DetectHttpHRHTest11(void)
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
        "User-Agent: www.openinfosecfoundation.org\r\n"
        "Host: This is dummy message body\r\n"
        "Content-Type: text/html\r\n"
        "\r\n";
    uint32_t http_len = sizeof(http_buf) - 1;
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
    p->flowflags |= FLOW_PKT_TOSERVER;
    p->flowflags |= FLOW_PKT_ESTABLISHED;
    p->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    f.alproto = ALPROTO_HTTP1;

    StreamTcpInitConfig(true);

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert http any any -> any any "
                               "(msg:\"http host test\"; "
                               "content:!\"message\"; http_raw_host;  "
                               "sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParserParse(
            NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER, http_buf, http_len);
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

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);

    if (PacketAlertCheck(p, 1)) {
        printf("sid 1 matched but shouldn't have");
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
 *\test Negative test that the negated http_raw_host content matches against a
 *      http request which holds hold the content.
 */
static int DetectHttpHRHTest12(void)
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
        "User-Agent: www.openinfosecfoundation.org\r\n"
        "Host: This is dummy body\r\n"
        "\r\n";
    uint32_t http_len = sizeof(http_buf) - 1;
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
    p->flowflags |= FLOW_PKT_TOSERVER;
    p->flowflags |= FLOW_PKT_ESTABLISHED;
    p->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    f.alproto = ALPROTO_HTTP1;

    StreamTcpInitConfig(true);

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert http any any -> any any "
                               "(msg:\"http host test\"; "
                               "content:!\"message\"; http_raw_host;  "
                               "sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParserParse(
            NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER, http_buf, http_len);
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

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);

    if (!(PacketAlertCheck(p, 1))) {
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
    UTHFreePackets(&p, 1);
    return result;
}

/**
 * \test Test that the http_raw_host content matches against a http request
 *       which holds the content.
 */
static int DetectHttpHRHTest13(void)
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
        "User-Agent: www.openinfosecfoundation.org\r\n"
        "Host: longbufferabcdefghijklmnopqrstuvwxyz0123456789bufferend\r\n"
        "Content-Type: text/html\r\n"
        "\r\n";
    uint32_t http_len = sizeof(http_buf) - 1;
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
    p->flowflags |= FLOW_PKT_TOSERVER;
    p->flowflags |= FLOW_PKT_ESTABLISHED;
    p->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    f.alproto = ALPROTO_HTTP1;

    StreamTcpInitConfig(true);

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert http any any -> any any "
                               "(msg:\"http host test\"; "
                               "content:\"abcdefghijklmnopqrstuvwxyz0123456789\"; http_raw_host;  "
                               "sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParserParse(
            NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER, http_buf, http_len);
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

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);

    if (!(PacketAlertCheck(p, 1))) {
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
    UTHFreePackets(&p, 1);
    return result;
}

/**
 * \test multiple http transactions and body chunks of request handling
 */
static int DetectHttpHRHTest14(void)
{
    int result = 0;
    Signature *s = NULL;
    DetectEngineThreadCtx *det_ctx = NULL;
    ThreadVars th_v;
    Flow f;
    TcpSession ssn;
    Packet *p = NULL;
    uint8_t httpbuf1[] = "POST / HTTP/1.1\r\n";
    uint8_t httpbuf2[] = "Cookie: dummy1\r\n";
    uint8_t httpbuf3[] = "Host: Body one!!\r\n\r\n";
    uint32_t httplen1 = sizeof(httpbuf1) - 1; /* minus the \0 */
    uint32_t httplen2 = sizeof(httpbuf2) - 1; /* minus the \0 */
    uint32_t httplen3 = sizeof(httpbuf3) - 1; /* minus the \0 */
    uint8_t httpbuf4[] = "GET /?var=val HTTP/1.1\r\n";
    uint8_t httpbuf5[] = "Cookie: dummy2\r\n";
    uint8_t httpbuf6[] = "Host: Body two\r\n\r\n";
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
    if (de_ctx == NULL) {
        goto end;
    }

    de_ctx->flags |= DE_QUIET;

    s = DetectEngineAppendSig(de_ctx, "alert tcp any any -> any any (content:\"POST\"; http_method; content:\"dummy1\"; http_cookie; content:\"Body one\"; http_raw_host;  sid:1; rev:1;)");
    if (s == NULL) {
        printf("sig parse failed: ");
        goto end;
    }
    s = DetectEngineAppendSig(de_ctx, "alert tcp any any -> any any (content:\"GET\"; http_method; content:\"dummy2\"; http_cookie; content:\"Body two\"; http_raw_host;  sid:2; rev:1;)");
    if (s == NULL) {
        printf("sig2 parse failed: ");
        goto end;
    }

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParserParse(
            NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER, httpbuf1, httplen1);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    if (PacketAlertCheck(p, 1)) {
        printf("sig 1 alerted: ");
        goto end;
    }
    p->alerts.cnt = 0;

    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER, httpbuf2, httplen2);
    if (r != 0) {
        printf("toserver chunk 2 returned %" PRId32 ", expected 0: ", r);
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    if (PacketAlertCheck(p, 1)) {
        printf("sig 1 alerted (2): ");
        goto end;
    }
    p->alerts.cnt = 0;

    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER, httpbuf3, httplen3);
    if (r != 0) {
        printf("toserver chunk 3 returned %" PRId32 ", expected 0: ", r);
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    if (!(PacketAlertCheck(p, 1))) {
        printf("sig 1 didn't alert: ");
        goto end;
    }
    p->alerts.cnt = 0;

    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER, httpbuf4, httplen4);
    if (r != 0) {
        printf("toserver chunk 5 returned %" PRId32 ", expected 0: ", r);
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    if (PacketAlertCheck(p, 1) || PacketAlertCheck(p, 2)) {
        printf("sig 1 alerted (4): ");
        goto end;
    }
    p->alerts.cnt = 0;

    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER, httpbuf5, httplen5);
    if (r != 0) {
        printf("toserver chunk 6 returned %" PRId32 ", expected 0: ", r);
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    if ((PacketAlertCheck(p, 1)) || (PacketAlertCheck(p, 2))) {
        printf("sig 1 alerted (request 2, chunk 6): ");
        goto end;
    }
    p->alerts.cnt = 0;

    SCLogDebug("sending data chunk 7");

    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER, httpbuf6, httplen6);
    if (r != 0) {
        printf("toserver chunk 7 returned %" PRId32 ", expected 0: ", r);
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    if (PacketAlertCheck(p, 1) || !(PacketAlertCheck(p, 2))) {
        printf("signature 2 didn't match or sig 1 matched, but shouldn't have: ");
        goto end;
    }
    p->alerts.cnt = 0;

    HtpState *htp_state = f.alstate;
    if (htp_state == NULL) {
        printf("no http state: ");
        result = 0;
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

static int DetectHttpHRHTest22(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; content:\"two\"; http_raw_host;  "
                               "content:\"three\"; distance:10; http_raw_host;  content:\"four\"; sid:1;)");
    if (de_ctx->sig_list == NULL) {
        printf("de_ctx->sig_list == NULL\n");
        goto end;
    }

    if (de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH] == NULL) {
        printf("de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH] == NULL\n");
        goto end;
    }

    if (de_ctx->sig_list->sm_lists[g_http_raw_host_buffer_id] == NULL) {
        printf("de_ctx->sig_list->sm_lists[g_http_raw_host_buffer_id] == NULL\n");
        goto end;
    }

    DetectContentData *cd1 = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[DETECT_SM_LIST_PMATCH]->prev->ctx;
    DetectContentData *cd2 = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[DETECT_SM_LIST_PMATCH]->ctx;
    DetectContentData *hrhhd1 = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_http_raw_host_buffer_id]->prev->ctx;
    DetectContentData *hrhhd2 = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_http_raw_host_buffer_id]->ctx;
    if (cd1->flags != 0 || memcmp(cd1->content, "one", cd1->content_len) != 0 ||
        cd2->flags != 0 || memcmp(cd2->content, "four", cd2->content_len) != 0 ||
        hrhhd1->flags != (DETECT_CONTENT_RELATIVE_NEXT) ||
        memcmp(hrhhd1->content, "two", hrhhd1->content_len) != 0 ||
        hrhhd2->flags != (DETECT_CONTENT_DISTANCE) ||
        memcmp(hrhhd2->content, "three", hrhhd1->content_len) != 0) {
        goto end;
    }

    if (!DETECT_CONTENT_IS_SINGLE(cd1) ||
        !DETECT_CONTENT_IS_SINGLE(cd2) ||
        DETECT_CONTENT_IS_SINGLE(hrhhd1) ||
        DETECT_CONTENT_IS_SINGLE(hrhhd2)) {
        goto end;
    }

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectHttpHRHTest23(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_raw_host;  pcre:/two/; "
                               "content:\"three\"; distance:10; http_raw_host;  content:\"four\"; sid:1;)");
    if (de_ctx->sig_list == NULL) {
        printf("de_ctx->sig_list == NULL\n");
        goto end;
    }

    if (de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH] == NULL) {
        printf("de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH] == NULL\n");
        goto end;
    }

    if (de_ctx->sig_list->sm_lists[g_http_raw_host_buffer_id] == NULL) {
        printf("de_ctx->sig_list->sm_lists[g_http_raw_host_buffer_id] == NULL\n");
        goto end;
    }

    DetectPcreData *pd1 = (DetectPcreData *)de_ctx->sig_list->sm_lists_tail[DETECT_SM_LIST_PMATCH]->prev->ctx;
    DetectContentData *cd2 = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[DETECT_SM_LIST_PMATCH]->ctx;
    DetectContentData *hrhhd1 = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_http_raw_host_buffer_id]->prev->ctx;
    DetectContentData *hrhhd2 = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_http_raw_host_buffer_id]->ctx;
    if (pd1->flags != 0 ||
        cd2->flags != 0 || memcmp(cd2->content, "four", cd2->content_len) != 0 ||
        hrhhd1->flags != (DETECT_CONTENT_RELATIVE_NEXT) ||
        memcmp(hrhhd1->content, "one", hrhhd1->content_len) != 0 ||
        hrhhd2->flags != (DETECT_CONTENT_DISTANCE) ||
        memcmp(hrhhd2->content, "three", hrhhd1->content_len) != 0) {
        goto end;
    }

    if (!DETECT_CONTENT_IS_SINGLE(cd2) ||
        DETECT_CONTENT_IS_SINGLE(hrhhd1) ||
        DETECT_CONTENT_IS_SINGLE(hrhhd2)) {
        goto end;
    }

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectHttpHRHTest24(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_raw_host;  pcre:/two/; "
                               "content:\"three\"; distance:10; within:15; http_raw_host;  content:\"four\"; sid:1;)");
    if (de_ctx->sig_list == NULL) {
        printf("de_ctx->sig_list == NULL\n");
        goto end;
    }

    if (de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH] == NULL) {
        printf("de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH] == NULL\n");
        goto end;
    }

    if (de_ctx->sig_list->sm_lists[g_http_raw_host_buffer_id] == NULL) {
        printf("de_ctx->sig_list->sm_lists[g_http_raw_host_buffer_id] == NULL\n");
        goto end;
    }

    DetectPcreData *pd1 = (DetectPcreData *)de_ctx->sig_list->sm_lists_tail[DETECT_SM_LIST_PMATCH]->prev->ctx;
    DetectContentData *cd2 = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[DETECT_SM_LIST_PMATCH]->ctx;
    DetectContentData *hrhhd1 = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_http_raw_host_buffer_id]->prev->ctx;
    DetectContentData *hrhhd2 = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_http_raw_host_buffer_id]->ctx;
    if (pd1->flags != 0 ||
        cd2->flags != 0 || memcmp(cd2->content, "four", cd2->content_len) != 0 ||
        hrhhd1->flags != (DETECT_CONTENT_RELATIVE_NEXT) ||
        memcmp(hrhhd1->content, "one", hrhhd1->content_len) != 0 ||
        hrhhd2->flags != (DETECT_CONTENT_DISTANCE | DETECT_CONTENT_WITHIN) ||
        memcmp(hrhhd2->content, "three", hrhhd1->content_len) != 0) {
        goto end;
    }

    if (!DETECT_CONTENT_IS_SINGLE(cd2) ||
        DETECT_CONTENT_IS_SINGLE(hrhhd1) ||
        DETECT_CONTENT_IS_SINGLE(hrhhd2)) {
        goto end;
    }

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectHttpHRHTest25(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_raw_host;  pcre:/two/; "
                               "content:\"three\"; distance:10; http_raw_host;  "
                               "content:\"four\"; distance:10; sid:1;)");
    if (de_ctx->sig_list == NULL) {
        printf("de_ctx->sig_list == NULL\n");
        goto end;
    }

    if (de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH] == NULL) {
        printf("de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH] == NULL\n");
        goto end;
    }

    if (de_ctx->sig_list->sm_lists[g_http_raw_host_buffer_id] == NULL) {
        printf("de_ctx->sig_list->sm_lists[g_http_raw_host_buffer_id] == NULL\n");
        goto end;
    }

    DetectPcreData *pd1 = (DetectPcreData *)de_ctx->sig_list->sm_lists_tail[DETECT_SM_LIST_PMATCH]->prev->ctx;
    DetectContentData *cd2 = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[DETECT_SM_LIST_PMATCH]->ctx;
    DetectContentData *hrhhd1 = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_http_raw_host_buffer_id]->prev->ctx;
    DetectContentData *hrhhd2 = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_http_raw_host_buffer_id]->ctx;
    if (pd1->flags != DETECT_PCRE_RELATIVE_NEXT ||
        cd2->flags != DETECT_CONTENT_DISTANCE ||
        memcmp(cd2->content, "four", cd2->content_len) != 0 ||
        hrhhd1->flags != (DETECT_CONTENT_RELATIVE_NEXT) ||
        memcmp(hrhhd1->content, "one", hrhhd1->content_len) != 0 ||
        hrhhd2->flags != (DETECT_CONTENT_DISTANCE) ||
        memcmp(hrhhd2->content, "three", hrhhd1->content_len) != 0) {
        goto end;
    }

    if (DETECT_CONTENT_IS_SINGLE(cd2) ||
        DETECT_CONTENT_IS_SINGLE(hrhhd1) ||
        DETECT_CONTENT_IS_SINGLE(hrhhd2)) {
        goto end;
    }

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectHttpHRHTest26(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; offset:10; http_raw_host;  pcre:/two/; "
                               "content:\"three\"; distance:10; http_raw_host;  within:10; "
                               "content:\"four\"; distance:10; sid:1;)");
    if (de_ctx->sig_list == NULL) {
        printf("de_ctx->sig_list == NULL\n");
        goto end;
    }

    if (de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH] == NULL) {
        printf("de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH] == NULL\n");
        goto end;
    }

    if (de_ctx->sig_list->sm_lists[g_http_raw_host_buffer_id] == NULL) {
        printf("de_ctx->sig_list->sm_lists[g_http_raw_host_buffer_id] == NULL\n");
        goto end;
    }

    DetectPcreData *pd1 = (DetectPcreData *)de_ctx->sig_list->sm_lists_tail[DETECT_SM_LIST_PMATCH]->prev->ctx;
    DetectContentData *cd2 = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[DETECT_SM_LIST_PMATCH]->ctx;
    DetectContentData *hrhhd1 = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_http_raw_host_buffer_id]->prev->ctx;
    DetectContentData *hrhhd2 = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_http_raw_host_buffer_id]->ctx;
    if (pd1->flags != (DETECT_PCRE_RELATIVE_NEXT) ||
        cd2->flags != DETECT_CONTENT_DISTANCE ||
        memcmp(cd2->content, "four", cd2->content_len) != 0 ||
        hrhhd1->flags != (DETECT_CONTENT_RELATIVE_NEXT | DETECT_CONTENT_OFFSET) ||
        memcmp(hrhhd1->content, "one", hrhhd1->content_len) != 0 ||
        hrhhd2->flags != (DETECT_CONTENT_DISTANCE | DETECT_CONTENT_WITHIN) ||
        memcmp(hrhhd2->content, "three", hrhhd1->content_len) != 0) {
        printf ("failed: http_raw_host incorrect flags");
        goto end;
    }

    if (DETECT_CONTENT_IS_SINGLE(cd2) ||
        DETECT_CONTENT_IS_SINGLE(hrhhd1) ||
        DETECT_CONTENT_IS_SINGLE(hrhhd2)) {
        goto end;
    }

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectHttpHRHTest27(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; offset:10; http_raw_host;  pcre:/two/; "
                               "content:\"three\"; distance:10; http_raw_host;  within:10; "
                               "content:\"four\"; distance:10; sid:1;)");
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

static int DetectHttpHRHTest28(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_raw_host; nocase; pcre:/two/; "
                               "content:\"three\"; http_raw_host;  depth:10; "
                               "content:\"four\"; distance:10; sid:1;)");
    if (de_ctx->sig_list == NULL) {
        printf("de_ctx->sig_list == NULL\n");
        goto end;
    }

    if (de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH] == NULL) {
        printf("de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH] == NULL\n");
        goto end;
    }

    if (de_ctx->sig_list->sm_lists[g_http_raw_host_buffer_id] == NULL) {
        printf("de_ctx->sig_list->sm_lists[g_http_raw_host_buffer_id] == NULL\n");
        goto end;
    }

    DetectPcreData *pd1 = (DetectPcreData *)de_ctx->sig_list->sm_lists_tail[DETECT_SM_LIST_PMATCH]->prev->ctx;
    DetectContentData *cd2 = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[DETECT_SM_LIST_PMATCH]->ctx;
    DetectContentData *hrhhd1 = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_http_raw_host_buffer_id]->prev->ctx;
    DetectContentData *hrhhd2 = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_http_raw_host_buffer_id]->ctx;
    if (pd1->flags != (DETECT_PCRE_RELATIVE_NEXT) ||
        cd2->flags != DETECT_CONTENT_DISTANCE ||
        memcmp(cd2->content, "four", cd2->content_len) != 0 ||
        hrhhd1->flags != (DETECT_CONTENT_NOCASE) ||
        memcmp(hrhhd1->content, "one", hrhhd1->content_len) != 0 ||
        hrhhd2->flags != (DETECT_CONTENT_DEPTH) ||
        memcmp(hrhhd2->content, "three", hrhhd1->content_len) != 0) {
        goto end;
    }

    if (DETECT_CONTENT_IS_SINGLE(cd2) ||
        !DETECT_CONTENT_IS_SINGLE(hrhhd1) ||
        DETECT_CONTENT_IS_SINGLE(hrhhd2)) {
        goto end;
    }

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectHttpHRHTest29(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_raw_host;  "
                               "content:\"two\"; distance:0; http_raw_host;  sid:1;)");
    if (de_ctx->sig_list == NULL) {
        printf("de_ctx->sig_list == NULL\n");
        goto end;
    }

    if (de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH] != NULL) {
        printf("de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH] != NULL\n");
        goto end;
    }

    if (de_ctx->sig_list->sm_lists[g_http_raw_host_buffer_id] == NULL) {
        printf("de_ctx->sig_list->sm_lists[g_http_raw_host_buffer_id] == NULL\n");
        goto end;
    }

    DetectContentData *hrhhd1 = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_http_raw_host_buffer_id]->prev->ctx;
    DetectContentData *hrhhd2 = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_http_raw_host_buffer_id]->ctx;
    if (hrhhd1->flags != (DETECT_CONTENT_RELATIVE_NEXT) ||
        memcmp(hrhhd1->content, "one", hrhhd1->content_len) != 0 ||
        hrhhd2->flags != (DETECT_CONTENT_DISTANCE) ||
        memcmp(hrhhd2->content, "two", hrhhd1->content_len) != 0) {
        goto end;
    }

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectHttpHRHTest30(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_raw_host;  "
                               "content:\"two\"; within:5; http_raw_host;  sid:1;)");
    if (de_ctx->sig_list == NULL) {
        printf("de_ctx->sig_list == NULL\n");
        goto end;
    }

    if (de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH] != NULL) {
        printf("de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH] != NULL\n");
        goto end;
    }

    if (de_ctx->sig_list->sm_lists[g_http_raw_host_buffer_id] == NULL) {
        printf("de_ctx->sig_list->sm_lists[g_http_raw_host_buffer_id] == NULL\n");
        goto end;
    }

    DetectContentData *hrhhd1 = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_http_raw_host_buffer_id]->prev->ctx;
    DetectContentData *hrhhd2 = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_http_raw_host_buffer_id]->ctx;
    if (hrhhd1->flags != (DETECT_CONTENT_RELATIVE_NEXT) ||
        memcmp(hrhhd1->content, "one", hrhhd1->content_len) != 0 ||
        hrhhd2->flags != (DETECT_CONTENT_WITHIN) ||
        memcmp(hrhhd2->content, "two", hrhhd1->content_len) != 0) {
        goto end;
    }

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectHttpHRHTest31(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; within:5; http_raw_host;  sid:1;)");
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

static int DetectHttpHRHTest32(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"one\"; http_raw_host;  within:5; sid:1;)");
    if (de_ctx->sig_list == NULL) {
        printf("de_ctx->sig_list != NULL\n");
        goto end;
    }

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectHttpHRHTest33(void)
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

static int DetectHttpHRHTest34(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(pcre:/one/Zi; "
                               "content:\"two\"; within:5; http_raw_host;  sid:1;)");
    if (de_ctx->sig_list == NULL) {
        printf("de_ctx->sig_list == NULL\n");
        goto end;
    }

    if (de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH] != NULL) {
        printf("de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH] != NULL\n");
        goto end;
    }

    if (de_ctx->sig_list->sm_lists[g_http_raw_host_buffer_id] == NULL) {
        printf("de_ctx->sig_list->sm_lists[g_http_raw_host_buffer_id] == NULL\n");
        goto end;
    }

    if (de_ctx->sig_list->sm_lists_tail[g_http_raw_host_buffer_id] == NULL ||
        de_ctx->sig_list->sm_lists_tail[g_http_raw_host_buffer_id]->type != DETECT_CONTENT ||
        de_ctx->sig_list->sm_lists_tail[g_http_raw_host_buffer_id]->prev == NULL ||
        de_ctx->sig_list->sm_lists_tail[g_http_raw_host_buffer_id]->prev->type != DETECT_PCRE) {

        goto end;
    }

    DetectPcreData *pd1 = (DetectPcreData *)de_ctx->sig_list->sm_lists_tail[g_http_raw_host_buffer_id]->prev->ctx;
    DetectContentData *hrhhd2 = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_http_raw_host_buffer_id]->ctx;
    if (pd1->flags != (DETECT_PCRE_RELATIVE_NEXT | DETECT_PCRE_CASELESS) ||
        hrhhd2->flags != (DETECT_CONTENT_WITHIN) ||
        memcmp(hrhhd2->content, "two", hrhhd2->content_len) != 0) {
        goto end;
    }

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectHttpHRHTest35(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(content:\"two\"; http_raw_host;  "
                               "pcre:/one/ZRi; sid:1;)");
    if (de_ctx->sig_list == NULL) {
        printf("de_ctx->sig_list == NULL\n");
        goto end;
    }

    if (de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH] != NULL) {
        printf("de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH] != NULL\n");
        goto end;
    }

    if (de_ctx->sig_list->sm_lists[g_http_raw_host_buffer_id] == NULL) {
        printf("de_ctx->sig_list->sm_lists[g_http_raw_host_buffer_id] == NULL\n");
        goto end;
    }

    if (de_ctx->sig_list->sm_lists_tail[g_http_raw_host_buffer_id] == NULL ||
        de_ctx->sig_list->sm_lists_tail[g_http_raw_host_buffer_id]->type != DETECT_PCRE ||
        de_ctx->sig_list->sm_lists_tail[g_http_raw_host_buffer_id]->prev == NULL ||
        de_ctx->sig_list->sm_lists_tail[g_http_raw_host_buffer_id]->prev->type != DETECT_CONTENT) {

        goto end;
    }

    DetectContentData *hrhhd1 = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_http_raw_host_buffer_id]->prev->ctx;
    DetectPcreData *pd2 = (DetectPcreData *)de_ctx->sig_list->sm_lists_tail[g_http_raw_host_buffer_id]->ctx;
    if (pd2->flags != (DETECT_PCRE_RELATIVE | DETECT_PCRE_CASELESS) ||
        hrhhd1->flags != (DETECT_CONTENT_RELATIVE_NEXT) ||
        memcmp(hrhhd1->content, "two", hrhhd1->content_len) != 0) {
        goto end;
    }

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectHttpHRHTest36(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(pcre:/one/Zi; "
                               "content:\"two\"; distance:5; http_raw_host;  sid:1;)");
    if (de_ctx->sig_list == NULL) {
        printf("de_ctx->sig_list == NULL\n");
        goto end;
    }

    if (de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH] != NULL) {
        printf("de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH] != NULL\n");
        goto end;
    }

    if (de_ctx->sig_list->sm_lists[g_http_raw_host_buffer_id] == NULL) {
        printf("de_ctx->sig_list->sm_lists[g_http_raw_host_buffer_id] == NULL\n");
        goto end;
    }

    if (de_ctx->sig_list->sm_lists_tail[g_http_raw_host_buffer_id] == NULL ||
        de_ctx->sig_list->sm_lists_tail[g_http_raw_host_buffer_id]->type != DETECT_CONTENT ||
        de_ctx->sig_list->sm_lists_tail[g_http_raw_host_buffer_id]->prev == NULL ||
        de_ctx->sig_list->sm_lists_tail[g_http_raw_host_buffer_id]->prev->type != DETECT_PCRE) {

        goto end;
    }

    DetectPcreData *pd1 = (DetectPcreData *)de_ctx->sig_list->sm_lists_tail[g_http_raw_host_buffer_id]->prev->ctx;
    DetectContentData *hrhhd2 = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_http_raw_host_buffer_id]->ctx;
    if (pd1->flags != (DETECT_PCRE_RELATIVE_NEXT | DETECT_PCRE_CASELESS) ||
        hrhhd2->flags != (DETECT_CONTENT_DISTANCE) ||
        memcmp(hrhhd2->content, "two", hrhhd2->content_len) != 0) {
        goto end;
    }

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

/**
 *\test Test that the http_raw_host content matches against a http request
 *      against a case insensitive pattern.
 */
static int DetectHttpHRHTest37(void)
{
    TcpSession ssn;
    Packet *p1 = NULL;
    Packet *p2 = NULL;
    ThreadVars th_v;
    DetectEngineCtx *de_ctx = NULL;
    DetectEngineThreadCtx *det_ctx = NULL;
    HtpState *http_state = NULL;
    Flow f;
    uint8_t http1_buf[] =
        "GET /index.html HTTP/1.0\r\n"
        "User-Agent: www.openinfosecfoundation.org\r\n"
        "Host: This is dummy bodY1";
    uint8_t http2_buf[] =
        "This is dummy message body2\r\n"
        "Content-Type: text/html\r\n"
        "Content-Length: 46\r\n"
        "\r\n"
        "This is dummy bodY1";
    uint32_t http1_len = sizeof(http1_buf) - 1;
    uint32_t http2_len = sizeof(http2_buf) - 1;
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
    p2->flowflags |= FLOW_PKT_TOSERVER;
    p2->flowflags |= FLOW_PKT_ESTABLISHED;
    p2->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    f.alproto = ALPROTO_HTTP1;

    StreamTcpInitConfig(true);

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert http any any -> any any "
                               "(msg:\"http host test\"; "
                               "content:\"body1this\"; http_raw_host; nocase; "
                               "sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParserParse(
            NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER, http1_buf, http1_len);
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
        printf("sid 1 didn't match but should have\n");
        goto end;
    }

    r = AppLayerParserParse(
            NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER, http2_buf, http2_len);
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

/**
 * \test Test that the http_raw_host content matches against a http request
 *       which holds the content.
 */
static int DetectEngineHttpHRHTest01(void)
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
        "Host: CONNECT\r\n"
        "User-Agent: www.onetwothreefourfivesixseven.org\r\n\r\n";
    uint32_t http_len = sizeof(http_buf) - 1;
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
    p->flowflags |= FLOW_PKT_TOSERVER;
    p->flowflags |= FLOW_PKT_ESTABLISHED;
    p->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    f.alproto = ALPROTO_HTTP1;

    StreamTcpInitConfig(true);

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert http any any -> any any "
                               "(msg:\"http host header test\"; "
                               "content:\"CONNECT\"; http_raw_host;  "
                               "sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParserParse(
            NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER, http_buf, http_len);
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
 * \test Test that the http_raw_host content matches against a http request
 *       which holds the content.
 */
static int DetectEngineHttpHRHTest02(void)
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
        "Host: CONNECT\r\n"
        "User-Agent: www.onetwothreefourfivesixseven.org\r\n\r\n";
    uint32_t http_len = sizeof(http_buf) - 1;
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
    p->flowflags |= FLOW_PKT_TOSERVER;
    p->flowflags |= FLOW_PKT_ESTABLISHED;
    p->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    f.alproto = ALPROTO_HTTP1;

    StreamTcpInitConfig(true);

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert http any any -> any any "
                               "(msg:\"http host header test\"; "
                               "content:\"CO\"; depth:4; http_raw_host;  "
                               "sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParserParse(
            NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER, http_buf, http_len);
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
 * \test Test that the http_raw_host content matches against a http request
 *       which holds the content.
 */
static int DetectEngineHttpHRHTest03(void)
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
        "Host: CONNECT\r\n"
        "User-Agent: www.onetwothreefourfivesixseven.org\r\n\r\n";
    uint32_t http_len = sizeof(http_buf) - 1;
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
    p->flowflags |= FLOW_PKT_TOSERVER;
    p->flowflags |= FLOW_PKT_ESTABLISHED;
    p->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    f.alproto = ALPROTO_HTTP1;

    StreamTcpInitConfig(true);

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert http any any -> any any "
                               "(msg:\"http_raw_host header test\"; "
                               "content:!\"ECT\"; depth:4; http_raw_host;  "
                               "sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParserParse(
            NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER, http_buf, http_len);
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
 * \test Test that the http_raw_host content matches against a http request
 *       which holds the content.
 */
static int DetectEngineHttpHRHTest04(void)
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
        "Host: CONNECT\r\n"
        "User-Agent: www.onetwothreefourfivesixseven.org\r\n\r\n";
    uint32_t http_len = sizeof(http_buf) - 1;
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
    p->flowflags |= FLOW_PKT_TOSERVER;
    p->flowflags |= FLOW_PKT_ESTABLISHED;
    p->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    f.alproto = ALPROTO_HTTP1;

    StreamTcpInitConfig(true);

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert http any any -> any any "
                               "(msg:\"http host header test\"; "
                               "content:\"ECT\"; depth:4; http_raw_host;  "
                               "sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParserParse(
            NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER, http_buf, http_len);
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

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);

    if (PacketAlertCheck(p, 1)) {
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
    UTHFreePackets(&p, 1);
    return result;
}

/**
 * \test Test that the http_raw_host content matches against a http request
 *       which holds the content.
 */
static int DetectEngineHttpHRHTest05(void)
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
        "Host: CONNECT\r\n"
        "User-Agent: www.onetwothreefourfivesixseven.org\r\n\r\n";
    uint32_t http_len = sizeof(http_buf) - 1;
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
    p->flowflags |= FLOW_PKT_TOSERVER;
    p->flowflags |= FLOW_PKT_ESTABLISHED;
    p->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    f.alproto = ALPROTO_HTTP1;

    StreamTcpInitConfig(true);

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert http any any -> any any "
                               "(msg:\"http host header test\"; "
                               "content:!\"CON\"; depth:4; http_raw_host;  "
                               "sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParserParse(
            NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER, http_buf, http_len);
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

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);

    if (PacketAlertCheck(p, 1)) {
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
    UTHFreePackets(&p, 1);
    return result;
}

/**
 * \test Test that the http_raw_host header content matches against a http request
 *       which holds the content.
 */
static int DetectEngineHttpHRHTest06(void)
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
        "Host: CONNECT\r\n"
        "User-Agent: www.onetwothreefourfivesixseven.org\r\n\r\n";
    uint32_t http_len = sizeof(http_buf) - 1;
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
    p->flowflags |= FLOW_PKT_TOSERVER;
    p->flowflags |= FLOW_PKT_ESTABLISHED;
    p->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    f.alproto = ALPROTO_HTTP1;

    StreamTcpInitConfig(true);

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert http any any -> any any "
                               "(msg:\"http host header test\"; "
                               "content:\"ECT\"; offset:3; http_raw_host;  "
                               "sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParserParse(
            NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER, http_buf, http_len);
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
 * \test Test that the http_raw_host content matches against a http request
 *       which holds the content.
 */
static int DetectEngineHttpHRHTest07(void)
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
        "Host: CONNECT\r\n"
        "User-Agent: www.onetwothreefourfivesixseven.org\r\n\r\n";
    uint32_t http_len = sizeof(http_buf) - 1;
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
    p->flowflags |= FLOW_PKT_TOSERVER;
    p->flowflags |= FLOW_PKT_ESTABLISHED;
    p->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    f.alproto = ALPROTO_HTTP1;

    StreamTcpInitConfig(true);

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert http any any -> any any "
                               "(msg:\"http host header test\"; "
                               "content:!\"CO\"; offset:3; http_raw_host;  "
                               "sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParserParse(
            NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER, http_buf, http_len);
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
 * \test Test that the http_raw_host header content matches against a http request
 *       which holds the content.
 */
static int DetectEngineHttpHRHTest08(void)
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
        "Host: CONNECT\r\n"
        "User-Agent: www.onetwothreefourfivesixseven.org\r\n\r\n";
    uint32_t http_len = sizeof(http_buf) - 1;
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
    p->flowflags |= FLOW_PKT_TOSERVER;
    p->flowflags |= FLOW_PKT_ESTABLISHED;
    p->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    f.alproto = ALPROTO_HTTP1;

    StreamTcpInitConfig(true);

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert http any any -> any any "
                               "(msg:\"http host header test\"; "
                               "content:!\"ECT\"; offset:3; http_raw_host;  "
                               "sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParserParse(
            NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER, http_buf, http_len);
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

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);

    if (PacketAlertCheck(p, 1)) {
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
    UTHFreePackets(&p, 1);
    return result;
}

/**
 * \test Test that the http_raw_host header content matches against a http request
 *       which holds the content.
 */
static int DetectEngineHttpHRHTest09(void)
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
        "Host: CONNECT\r\n"
        "User-Agent: www.onetwothreefourfivesixseven.org\r\n\r\n";
    uint32_t http_len = sizeof(http_buf) - 1;
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
    p->flowflags |= FLOW_PKT_TOSERVER;
    p->flowflags |= FLOW_PKT_ESTABLISHED;
    p->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    f.alproto = ALPROTO_HTTP1;

    StreamTcpInitConfig(true);

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert http any any -> any any "
                               "(msg:\"http host header test\"; "
                               "content:\"CON\"; offset:3; http_raw_host;  "
                               "sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParserParse(
            NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER, http_buf, http_len);
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

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);

    if (PacketAlertCheck(p, 1)) {
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
    UTHFreePackets(&p, 1);
    return result;
}

/**
 * \test Test that the http_raw_host header content matches against a http request
 *       which holds the content.
 */
static int DetectEngineHttpHRHTest10(void)
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
        "Host: CONNECT\r\n"
        "User-Agent: www.onetwothreefourfivesixseven.org\r\n\r\n";
    uint32_t http_len = sizeof(http_buf) - 1;
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
    p->flowflags |= FLOW_PKT_TOSERVER;
    p->flowflags |= FLOW_PKT_ESTABLISHED;
    p->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    f.alproto = ALPROTO_HTTP1;

    StreamTcpInitConfig(true);

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert http any any -> any any "
                               "(msg:\"http_raw_host header test\"; "
                               "content:\"CO\"; http_raw_host;  "
                               "content:\"EC\"; within:4; http_raw_host;  "
                               "sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParserParse(
            NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER, http_buf, http_len);
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

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);

    if (!PacketAlertCheck(p, 1)) {
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
 * \test Test that the http_raw_host header content matches against a http request
 *       which holds the content.
 */
static int DetectEngineHttpHRHTest11(void)
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
        "Host: CONNECT\r\n"
        "User-Agent: www.onetwothreefourfivesixseven.org\r\n\r\n";
    uint32_t http_len = sizeof(http_buf) - 1;
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
    p->flowflags |= FLOW_PKT_TOSERVER;
    p->flowflags |= FLOW_PKT_ESTABLISHED;
    p->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    f.alproto = ALPROTO_HTTP1;

    StreamTcpInitConfig(true);

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert http any any -> any any "
                               "(msg:\"http_raw_host header test\"; "
                               "content:\"CO\"; http_raw_host;  "
                               "content:!\"EC\"; within:3; http_raw_host;  "
                               "sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParserParse(
            NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER, http_buf, http_len);
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

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);

    if (!PacketAlertCheck(p, 1)) {
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
 * \test Test that the http_raw_host header content matches against a http request
 *       which holds the content.
 */
static int DetectEngineHttpHRHTest12(void)
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
        "Host: CONNECT\r\n"
        "User-Agent: www.onetwothreefourfivesixseven.org\r\n\r\n";
    uint32_t http_len = sizeof(http_buf) - 1;
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
    p->flowflags |= FLOW_PKT_TOSERVER;
    p->flowflags |= FLOW_PKT_ESTABLISHED;
    p->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    f.alproto = ALPROTO_HTTP1;

    StreamTcpInitConfig(true);

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert http any any -> any any "
                               "(msg:\"http_raw_host header test\"; "
                               "content:\"CO\"; http_raw_host;  "
                               "content:\"EC\"; within:3; http_raw_host;  "
                               "sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParserParse(
            NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER, http_buf, http_len);
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

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);

    if (PacketAlertCheck(p, 1)) {
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
    UTHFreePackets(&p, 1);
    return result;
}

/**
 * \test Test that the http_raw_host header content matches against a http request
 *       which holds the content.
 */
static int DetectEngineHttpHRHTest13(void)
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
        "Host: CONNECT\r\n"
        "User-Agent: www.onetwothreefourfivesixseven.org\r\n\r\n";
    uint32_t http_len = sizeof(http_buf) - 1;
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
    p->flowflags |= FLOW_PKT_TOSERVER;
    p->flowflags |= FLOW_PKT_ESTABLISHED;
    p->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    f.alproto = ALPROTO_HTTP1;

    StreamTcpInitConfig(true);

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert http any any -> any any "
                               "(msg:\"http_raw_host header test\"; "
                               "content:\"CO\"; http_raw_host;  "
                               "content:!\"EC\"; within:4; http_raw_host;  "
                               "sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParserParse(
            NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER, http_buf, http_len);
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

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);

    if (PacketAlertCheck(p, 1)) {
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
    UTHFreePackets(&p, 1);
    return result;
}

/**
 * \test Test that the http_raw_host header content matches against a http request
 *       which holds the content.
 */
static int DetectEngineHttpHRHTest14(void)
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
        "Host: CONNECT\r\n"
        "User-Agent: www.onetwothreefourfivesixseven.org\r\n\r\n";
    uint32_t http_len = sizeof(http_buf) - 1;
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
    p->flowflags |= FLOW_PKT_TOSERVER;
    p->flowflags |= FLOW_PKT_ESTABLISHED;
    p->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    f.alproto = ALPROTO_HTTP1;

    StreamTcpInitConfig(true);

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert http any any -> any any "
                               "(msg:\"http_raw_host header test\"; "
                               "content:\"CO\"; http_raw_host;  "
                               "content:\"EC\"; distance:2; http_raw_host;  "
                               "sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParserParse(
            NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER, http_buf, http_len);
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

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);

    if (!PacketAlertCheck(p, 1)) {
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
 * \test Test that the http_raw_host header content matches against a http request
 *       which holds the content.
 */
static int DetectEngineHttpHRHTest15(void)
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
        "Host: CONNECT\r\n"
        "User-Agent: www.onetwothreefourfivesixseven.org\r\n\r\n";
    uint32_t http_len = sizeof(http_buf) - 1;
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
    p->flowflags |= FLOW_PKT_TOSERVER;
    p->flowflags |= FLOW_PKT_ESTABLISHED;
    p->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    f.alproto = ALPROTO_HTTP1;

    StreamTcpInitConfig(true);

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert http any any -> any any "
                               "(msg:\"http_raw_host header test\"; "
                               "content:\"CO\"; http_raw_host;  "
                               "content:!\"EC\"; distance:3; http_raw_host;  "
                               "sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParserParse(
            NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER, http_buf, http_len);
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

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);

    if (!PacketAlertCheck(p, 1)) {
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
 * \test Test that the http_raw_host header content matches against a http request
 *       which holds the content.
 */
static int DetectEngineHttpHRHTest16(void)
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
        "Host: CONNECT\r\n"
        "User-Agent: www.onetwothreefourfivesixseven.org\r\n\r\n";
    uint32_t http_len = sizeof(http_buf) - 1;
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
    p->flowflags |= FLOW_PKT_TOSERVER;
    p->flowflags |= FLOW_PKT_ESTABLISHED;
    p->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    f.alproto = ALPROTO_HTTP1;

    StreamTcpInitConfig(true);

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert http any any -> any any "
                               "(msg:\"http_raw_host header test\"; "
                               "content:\"CO\"; http_raw_host;  "
                               "content:\"EC\"; distance:3; http_raw_host;  "
                               "sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParserParse(
            NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER, http_buf, http_len);
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

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);

    if (PacketAlertCheck(p, 1)) {
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
    UTHFreePackets(&p, 1);
    return result;
}

/**
 * \test Test that the http_raw_host header content matches against a http request
 *       which holds the content.
 */
static int DetectEngineHttpHRHTest17(void)
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
        "Host: CONNECT\r\n"
        "User-Agent: www.onetwothreefourfivesixseven.org\r\n\r\n";
    uint32_t http_len = sizeof(http_buf) - 1;
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
    p->flowflags |= FLOW_PKT_TOSERVER;
    p->flowflags |= FLOW_PKT_ESTABLISHED;
    p->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    f.alproto = ALPROTO_HTTP1;

    StreamTcpInitConfig(true);

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert http any any -> any any "
                               "(msg:\"http_raw_host header test\"; "
                               "content:\"CO\"; http_raw_host;  "
                               "content:!\"EC\"; distance:2; http_raw_host;  "
                               "sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParserParse(
            NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER, http_buf, http_len);
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

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);

    if (PacketAlertCheck(p, 1)) {
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
    UTHFreePackets(&p, 1);
    return result;
}

static int DetectEngineHttpHRHTest18(void)
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
        "Host: www.kaboom.com:8080\r\n"
        "User-Agent: www.onetwothreefourfivesixseven.org\r\n\r\n";
    uint32_t http_len = sizeof(http_buf) - 1;
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
    p->flowflags |= FLOW_PKT_TOSERVER;
    p->flowflags |= FLOW_PKT_ESTABLISHED;
    p->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    f.alproto = ALPROTO_HTTP1;

    StreamTcpInitConfig(true);

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert http any any -> any any "
                               "(msg:\"http_raw_host header test\"; "
                               "content:\"kaboom\"; http_raw_host; nocase; "
                               "sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParserParse(
            NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER, http_buf, http_len);
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

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);

    if (!PacketAlertCheck(p, 1)) {
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

static int DetectEngineHttpHRHTest19(void)
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
        "Host: www.kaboom.com:8080\r\n"
        "User-Agent: www.onetwothreefourfivesixseven.org\r\n\r\n";
    uint32_t http_len = sizeof(http_buf) - 1;
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
    p->flowflags |= FLOW_PKT_TOSERVER;
    p->flowflags |= FLOW_PKT_ESTABLISHED;
    p->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    f.alproto = ALPROTO_HTTP1;

    StreamTcpInitConfig(true);

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert http any any -> any any "
                               "(msg:\"http_raw_host header test\"; "
                               "content:\"kaboom\"; http_raw_host; nocase; "
                               "sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParserParse(
            NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER, http_buf, http_len);
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

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);

    if (!PacketAlertCheck(p, 1)) {
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

static int DetectEngineHttpHRHTest20(void)
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
        "Host: www.kaboom.com:8080\r\n"
        "User-Agent: www.onetwothreefourfivesixseven.org\r\n\r\n";
    uint32_t http_len = sizeof(http_buf) - 1;
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
    p->flowflags |= FLOW_PKT_TOSERVER;
    p->flowflags |= FLOW_PKT_ESTABLISHED;
    p->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    f.alproto = ALPROTO_HTTP1;

    StreamTcpInitConfig(true);

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert http any any -> any any "
                               "(msg:\"http_raw_host header test\"; "
                               "content:\"8080\"; http_raw_host; nocase; "
                               "sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParserParse(
            NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER, http_buf, http_len);
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

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);

    if (!PacketAlertCheck(p, 1)) {
        printf("sid 1 didn't match but it should have: ");
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

static int DetectEngineHttpHRHTest21(void)
{
    TcpSession ssn;
    Packet *p = NULL;
    ThreadVars th_v;
    DetectEngineCtx *de_ctx = NULL;
    DetectEngineThreadCtx *det_ctx = NULL;
    HtpState *http_state = NULL;
    Flow f;
    uint8_t http_buf[] =
        "GET http://www.kaboom.com/index.html HTTP/1.0\r\n"
        "User-Agent: www.onetwothreefourfivesixseven.org\r\n\r\n";
    uint32_t http_len = sizeof(http_buf) - 1;
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
    p->flowflags |= FLOW_PKT_TOSERVER;
    p->flowflags |= FLOW_PKT_ESTABLISHED;
    p->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    f.alproto = ALPROTO_HTTP1;

    StreamTcpInitConfig(true);

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert http any any -> any any "
                               "(msg:\"http_raw_host header test\"; "
                               "content:\"kaboom\"; http_raw_host; nocase; "
                               "sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParserParse(
            NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER, http_buf, http_len);
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

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);

    if (!PacketAlertCheck(p, 1)) {
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

static int DetectEngineHttpHRHTest22(void)
{
    TcpSession ssn;
    Packet *p = NULL;
    ThreadVars th_v;
    DetectEngineCtx *de_ctx = NULL;
    DetectEngineThreadCtx *det_ctx = NULL;
    HtpState *http_state = NULL;
    Flow f;
    uint8_t http_buf[] =
        "GET http://www.kaboom.com:8080/index.html HTTP/1.0\r\n"
        "User-Agent: www.onetwothreefourfivesixseven.org\r\n\r\n";
    uint32_t http_len = sizeof(http_buf) - 1;
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
    p->flowflags |= FLOW_PKT_TOSERVER;
    p->flowflags |= FLOW_PKT_ESTABLISHED;
    p->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    f.alproto = ALPROTO_HTTP1;

    StreamTcpInitConfig(true);

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert http any any -> any any "
                               "(msg:\"http_raw_host header test\"; "
                               "content:\"kaboom\"; http_raw_host; nocase; "
                               "sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParserParse(
            NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER, http_buf, http_len);
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

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);

    if (!PacketAlertCheck(p, 1)) {
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

static int DetectEngineHttpHRHTest23(void)
{
    TcpSession ssn;
    Packet *p = NULL;
    ThreadVars th_v;
    DetectEngineCtx *de_ctx = NULL;
    DetectEngineThreadCtx *det_ctx = NULL;
    HtpState *http_state = NULL;
    Flow f;
    uint8_t http_buf[] =
        "GET http://www.kaboom.com:8080/index.html HTTP/1.0\r\n"
        "User-Agent: www.onetwothreefourfivesixseven.org\r\n\r\n";
    uint32_t http_len = sizeof(http_buf) - 1;
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
    p->flowflags |= FLOW_PKT_TOSERVER;
    p->flowflags |= FLOW_PKT_ESTABLISHED;
    p->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    f.alproto = ALPROTO_HTTP1;

    StreamTcpInitConfig(true);

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert http any any -> any any "
                               "(msg:\"http_raw_host header test\"; "
                               "content:\"8080\"; http_raw_host; nocase; "
                               "sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParserParse(
            NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER, http_buf, http_len);
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

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);

    if (PacketAlertCheck(p, 1)) {
        printf("sid 1 matched but it shouldn't have: ");
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

static int DetectEngineHttpHRHTest24(void)
{
    TcpSession ssn;
    Packet *p = NULL;
    ThreadVars th_v;
    DetectEngineCtx *de_ctx = NULL;
    DetectEngineThreadCtx *det_ctx = NULL;
    HtpState *http_state = NULL;
    Flow f;
    uint8_t http_buf[] =
        "GET http://www.kaboom.com:8080/index.html HTTP/1.0\r\n"
        "Host: www.rabbit.com\r\n"
        "User-Agent: www.onetwothreefourfivesixseven.org\r\n\r\n";
    uint32_t http_len = sizeof(http_buf) - 1;
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
    p->flowflags |= FLOW_PKT_TOSERVER;
    p->flowflags |= FLOW_PKT_ESTABLISHED;
    p->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    f.alproto = ALPROTO_HTTP1;

    StreamTcpInitConfig(true);

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert http any any -> any any "
                               "(msg:\"http_raw_host header test\"; "
                               "content:\"kaboom\"; http_raw_host; nocase; "
                               "sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParserParse(
            NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER, http_buf, http_len);
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

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);

    if (!PacketAlertCheck(p, 1)) {
        printf("sid 1 didn't match but it should have: ");
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

static int DetectEngineHttpHRHTest25(void)
{
    TcpSession ssn;
    Packet *p = NULL;
    ThreadVars th_v;
    DetectEngineCtx *de_ctx = NULL;
    DetectEngineThreadCtx *det_ctx = NULL;
    HtpState *http_state = NULL;
    Flow f;
    uint8_t http_buf[] =
        "GET http://www.kaboom.com:8080/index.html HTTP/1.0\r\n"
        "Host: www.rabbit.com\r\n"
        "User-Agent: www.onetwothreefourfivesixseven.org\r\n\r\n";
    uint32_t http_len = sizeof(http_buf) - 1;
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
    p->flowflags |= FLOW_PKT_TOSERVER;
    p->flowflags |= FLOW_PKT_ESTABLISHED;
    p->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    f.alproto = ALPROTO_HTTP1;

    StreamTcpInitConfig(true);

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert http any any -> any any "
                               "(msg:\"http_raw_host header test\"; "
                               "content:\"rabbit\"; http_raw_host; nocase; "
                               "sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParserParse(
            NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER, http_buf, http_len);
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

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);

    if (PacketAlertCheck(p, 1)) {
        printf("sid 1 matched but it shouldn't have: ");
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

void DetectHttpHHRegisterTests(void)
{
    UtRegisterTest("DetectHttpHHTest01", DetectHttpHHTest01);
    UtRegisterTest("DetectHttpHHTest02", DetectHttpHHTest02);
    UtRegisterTest("DetectHttpHHTest03", DetectHttpHHTest03);
    UtRegisterTest("DetectHttpHHTest04", DetectHttpHHTest04);
    UtRegisterTest("DetectHttpHHTest05", DetectHttpHHTest05);
    UtRegisterTest("DetectHttpHHTest05a", DetectHttpHHTest05a);
    UtRegisterTest("DetectHttpHHTest06", DetectHttpHHTest06);
    UtRegisterTest("DetectHttpHHTest07", DetectHttpHHTest07);
    UtRegisterTest("DetectHttpHHTest08", DetectHttpHHTest08);
    UtRegisterTest("DetectHttpHHTest09", DetectHttpHHTest09);
    UtRegisterTest("DetectHttpHHTest10", DetectHttpHHTest10);
    UtRegisterTest("DetectHttpHHTest11", DetectHttpHHTest11);
    UtRegisterTest("DetectHttpHHTest12", DetectHttpHHTest12);
    UtRegisterTest("DetectHttpHHTest13", DetectHttpHHTest13);
    UtRegisterTest("DetectHttpHHTest14", DetectHttpHHTest14);

    UtRegisterTest("DetectHttpHHTest22", DetectHttpHHTest22);
    UtRegisterTest("DetectHttpHHTest23", DetectHttpHHTest23);
    UtRegisterTest("DetectHttpHHTest24", DetectHttpHHTest24);
    UtRegisterTest("DetectHttpHHTest25", DetectHttpHHTest25);
    UtRegisterTest("DetectHttpHHTest26", DetectHttpHHTest26);
    UtRegisterTest("DetectHttpHHTest27", DetectHttpHHTest27);
    UtRegisterTest("DetectHttpHHTest28", DetectHttpHHTest28);
    UtRegisterTest("DetectHttpHHTest29", DetectHttpHHTest29);
    UtRegisterTest("DetectHttpHHTest30", DetectHttpHHTest30);
    UtRegisterTest("DetectHttpHHTest31", DetectHttpHHTest31);
    UtRegisterTest("DetectHttpHHTest32", DetectHttpHHTest32);
    UtRegisterTest("DetectHttpHHTest33", DetectHttpHHTest33);
    UtRegisterTest("DetectHttpHHTest34", DetectHttpHHTest34);
    UtRegisterTest("DetectHttpHHTest35", DetectHttpHHTest35);
    UtRegisterTest("DetectHttpHHTest36", DetectHttpHHTest36);

    UtRegisterTest("DetectEngineHttpHHTest01", DetectEngineHttpHHTest01);
    UtRegisterTest("DetectEngineHttpHHTest02", DetectEngineHttpHHTest02);
    UtRegisterTest("DetectEngineHttpHHTest03", DetectEngineHttpHHTest03);
    UtRegisterTest("DetectEngineHttpHHTest04", DetectEngineHttpHHTest04);
    UtRegisterTest("DetectEngineHttpHHTest05", DetectEngineHttpHHTest05);
    UtRegisterTest("DetectEngineHttpHHTest06", DetectEngineHttpHHTest06);
    UtRegisterTest("DetectEngineHttpHHTest07", DetectEngineHttpHHTest07);
    UtRegisterTest("DetectEngineHttpHHTest08", DetectEngineHttpHHTest08);
    UtRegisterTest("DetectEngineHttpHHTest09", DetectEngineHttpHHTest09);
    UtRegisterTest("DetectEngineHttpHHTest10", DetectEngineHttpHHTest10);
    UtRegisterTest("DetectEngineHttpHHTest11", DetectEngineHttpHHTest11);
    UtRegisterTest("DetectEngineHttpHHTest12", DetectEngineHttpHHTest12);
    UtRegisterTest("DetectEngineHttpHHTest13", DetectEngineHttpHHTest13);
    UtRegisterTest("DetectEngineHttpHHTest14", DetectEngineHttpHHTest14);
    UtRegisterTest("DetectEngineHttpHHTest15", DetectEngineHttpHHTest15);
    UtRegisterTest("DetectEngineHttpHHTest16", DetectEngineHttpHHTest16);
    UtRegisterTest("DetectEngineHttpHHTest17", DetectEngineHttpHHTest17);
    UtRegisterTest("DetectEngineHttpHHTest18", DetectEngineHttpHHTest18);
    UtRegisterTest("DetectEngineHttpHHTest19", DetectEngineHttpHHTest19);
    UtRegisterTest("DetectEngineHttpHHTest20", DetectEngineHttpHHTest20);
    UtRegisterTest("DetectEngineHttpHHTest21", DetectEngineHttpHHTest21);
    UtRegisterTest("DetectEngineHttpHHTest22", DetectEngineHttpHHTest22);
    UtRegisterTest("DetectEngineHttpHHTest23", DetectEngineHttpHHTest23);
    UtRegisterTest("DetectEngineHttpHHTest24", DetectEngineHttpHHTest24);
    UtRegisterTest("DetectEngineHttpHHTest25", DetectEngineHttpHHTest25);

    UtRegisterTest("DetectHttpHRHTest01", DetectHttpHRHTest01);
    UtRegisterTest("DetectHttpHRHTest02", DetectHttpHRHTest02);
    UtRegisterTest("DetectHttpHRHTest03", DetectHttpHRHTest03);
    UtRegisterTest("DetectHttpHRHTest04", DetectHttpHRHTest04);
    UtRegisterTest("DetectHttpHRHTest05", DetectHttpHRHTest05);
    UtRegisterTest("DetectHttpHRHTest06", DetectHttpHRHTest06);
    UtRegisterTest("DetectHttpHRHTest07", DetectHttpHRHTest07);
    UtRegisterTest("DetectHttpHRHTest08", DetectHttpHRHTest08);
    UtRegisterTest("DetectHttpHRHTest09", DetectHttpHRHTest09);
    UtRegisterTest("DetectHttpHRHTest10", DetectHttpHRHTest10);
    UtRegisterTest("DetectHttpHRHTest11", DetectHttpHRHTest11);
    UtRegisterTest("DetectHttpHRHTest12", DetectHttpHRHTest12);
    UtRegisterTest("DetectHttpHRHTest13", DetectHttpHRHTest13);
    UtRegisterTest("DetectHttpHRHTest14", DetectHttpHRHTest14);

    UtRegisterTest("DetectHttpHRHTest22", DetectHttpHRHTest22);
    UtRegisterTest("DetectHttpHRHTest23", DetectHttpHRHTest23);
    UtRegisterTest("DetectHttpHRHTest24", DetectHttpHRHTest24);
    UtRegisterTest("DetectHttpHRHTest25", DetectHttpHRHTest25);
    UtRegisterTest("DetectHttpHRHTest26", DetectHttpHRHTest26);
    UtRegisterTest("DetectHttpHRHTest27", DetectHttpHRHTest27);
    UtRegisterTest("DetectHttpHRHTest28", DetectHttpHRHTest28);
    UtRegisterTest("DetectHttpHRHTest29", DetectHttpHRHTest29);
    UtRegisterTest("DetectHttpHRHTest30", DetectHttpHRHTest30);
    UtRegisterTest("DetectHttpHRHTest31", DetectHttpHRHTest31);
    UtRegisterTest("DetectHttpHRHTest32", DetectHttpHRHTest32);
    UtRegisterTest("DetectHttpHRHTest33", DetectHttpHRHTest33);
    UtRegisterTest("DetectHttpHRHTest34", DetectHttpHRHTest34);
    UtRegisterTest("DetectHttpHRHTest35", DetectHttpHRHTest35);
    UtRegisterTest("DetectHttpHRHTest36", DetectHttpHRHTest36);
    UtRegisterTest("DetectHttpHRHTest37", DetectHttpHRHTest37);

    UtRegisterTest("DetectEngineHttpHRHTest01", DetectEngineHttpHRHTest01);
    UtRegisterTest("DetectEngineHttpHRHTest02", DetectEngineHttpHRHTest02);
    UtRegisterTest("DetectEngineHttpHRHTest03", DetectEngineHttpHRHTest03);
    UtRegisterTest("DetectEngineHttpHRHTest04", DetectEngineHttpHRHTest04);
    UtRegisterTest("DetectEngineHttpHRHTest05", DetectEngineHttpHRHTest05);
    UtRegisterTest("DetectEngineHttpHRHTest06", DetectEngineHttpHRHTest06);
    UtRegisterTest("DetectEngineHttpHRHTest07", DetectEngineHttpHRHTest07);
    UtRegisterTest("DetectEngineHttpHRHTest08", DetectEngineHttpHRHTest08);
    UtRegisterTest("DetectEngineHttpHRHTest09", DetectEngineHttpHRHTest09);
    UtRegisterTest("DetectEngineHttpHRHTest10", DetectEngineHttpHRHTest10);
    UtRegisterTest("DetectEngineHttpHRHTest11", DetectEngineHttpHRHTest11);
    UtRegisterTest("DetectEngineHttpHRHTest12", DetectEngineHttpHRHTest12);
    UtRegisterTest("DetectEngineHttpHRHTest13", DetectEngineHttpHRHTest13);
    UtRegisterTest("DetectEngineHttpHRHTest14", DetectEngineHttpHRHTest14);
    UtRegisterTest("DetectEngineHttpHRHTest15", DetectEngineHttpHRHTest15);
    UtRegisterTest("DetectEngineHttpHRHTest16", DetectEngineHttpHRHTest16);
    UtRegisterTest("DetectEngineHttpHRHTest17", DetectEngineHttpHRHTest17);
    UtRegisterTest("DetectEngineHttpHRHTest18", DetectEngineHttpHRHTest18);
    UtRegisterTest("DetectEngineHttpHRHTest19", DetectEngineHttpHRHTest19);
    UtRegisterTest("DetectEngineHttpHRHTest20", DetectEngineHttpHRHTest20);
    UtRegisterTest("DetectEngineHttpHRHTest21", DetectEngineHttpHRHTest21);
    UtRegisterTest("DetectEngineHttpHRHTest22", DetectEngineHttpHRHTest22);
    UtRegisterTest("DetectEngineHttpHRHTest23", DetectEngineHttpHRHTest23);
    UtRegisterTest("DetectEngineHttpHRHTest24", DetectEngineHttpHRHTest24);
    UtRegisterTest("DetectEngineHttpHRHTest25", DetectEngineHttpHRHTest25);
}

/**
 * @}
 */
