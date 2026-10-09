/* Copyright (C) 2025 Open Information Security Foundation
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
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

/**
 * \file
 *
 * Tests for the http.trailer buffers. The peer asserts, that header buffers do not see
 * this data, are in tests/detect-http-header.c and tests/detect-http-raw-header.c.
 */

#include "../suricata-common.h"
#include "../flow.h"
#include "../flow-util.h"
#include "../app-layer.h"
#include "../app-layer-parser.h"
#include "../app-layer-htp.h"
#include "../detect.h"
#include "../detect-parse.h"
#include "../detect-engine.h"
#include "../detect-engine-alert.h"
#include "../detect-engine-build.h"
#include "../stream-tcp.h"
#include "../counters.h"
#include "../util-unittest.h"
#include "../util-unittest-helper.h"

/* chunked request, two trailer fields */
static uint8_t trailer_test_buf[] = "GET /index.html HTTP/1.0\r\n"
                                    "host: boom\r\n"
                                    "Transfer-Encoding: chunked\r\n"
                                    "\r\n"
                                    "13\r\n"
                                    "This is dummy body1\r\n"
                                    "0\r\n"
                                    "Dummy-Header: kaboom\r\n"
                                    "Header2: value2\r\n"
                                    "\r\n";

/* same message with an empty trailer section */
static uint8_t trailer_test_buf_nofields[] = "GET /index.html HTTP/1.0\r\n"
                                             "host: boom\r\n"
                                             "Transfer-Encoding: chunked\r\n"
                                             "\r\n"
                                             "13\r\n"
                                             "This is dummy body1\r\n"
                                             "0\r\n"
                                             "\r\n";

/**
 * \brief Run one rule over a to-server stream and check whether it alerted.
 *
 * The whole transaction is handed to the parser in one go, so trailer state is
 * reached during the parse and detection runs on the following packet.
 */
static int DetectHttpTrailerRun(const char *sig, uint8_t *buf, uint32_t buf_len, bool expect)
{
    TcpSession ssn;
    Packet *p = NULL;
    ThreadVars th_v;
    DetectEngineCtx *de_ctx = NULL;
    DetectEngineThreadCtx *det_ctx = NULL;
    Flow f;
    int result = 0;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&th_v, 0, sizeof(th_v));
    StatsThreadInit(&th_v.stats);
    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    p = UTHBuildPacket(NULL, 0, IPPROTO_TCP);
    if (p == NULL)
        goto end;
    if (alp_tctx == NULL)
        goto end;

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
    FAIL_IF_NULL(de_ctx);
    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, sig);
    if (de_ctx->sig_list == NULL)
        goto end;

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    FAIL_IF(AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER, buf, buf_len) !=
            0);
    FAIL_IF_NULL(f.alstate);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    if (expect)
        FAIL_IF(!PacketAlertCheck(p, 1));
    else
        FAIL_IF(PacketAlertCheck(p, 1));

    result = 1;
end:
    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
    if (det_ctx != NULL)
        DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);
    StreamTcpFreeConfig(true);
    FLOW_DESTROY(&f);
    UTHFreePackets(&p, 1);
    StatsThreadCleanup(&th_v.stats);
    return result;
}

/** \test a trailer field matches on http.trailer */
static int DetectHttpTrailerTest01(void)
{
    return DetectHttpTrailerRun("alert http any any -> any any (flow:to_server; http.trailer; "
                                "content:\"Dummy-Header\"; sid:1;)",
            trailer_test_buf, sizeof(trailer_test_buf) - 1, true);
}

/** \test the raw buffer holds the field block as sent: name, value, order */
static int DetectHttpTrailerTest02(void)
{
    return DetectHttpTrailerRun("alert http any any -> any any (flow:to_server; http.trailer.raw; "
                                "content:\"Dummy-Header: kaboom|0d 0a|Header2\"; sid:1;)",
            trailer_test_buf, sizeof(trailer_test_buf) - 1, true);
}

/** \test http.trailer_names carries the field names */
static int DetectHttpTrailerTest03(void)
{
    return DetectHttpTrailerRun(
            "alert http any any -> any any (flow:to_server; http.trailer_names; "
            "content:\"Header2\"; sid:1;)",
            trailer_test_buf, sizeof(trailer_test_buf) - 1, true);
}

/** \test ... and not the values */
static int DetectHttpTrailerTest04(void)
{
    return DetectHttpTrailerRun(
            "alert http any any -> any any (flow:to_server; http.trailer_names; "
            "content:\"kaboom\"; sid:1;)",
            trailer_test_buf, sizeof(trailer_test_buf) - 1, false);
}

/** \test one rule can use a header buffer and a trailer buffer */
static int DetectHttpTrailerTest05(void)
{
    return DetectHttpTrailerRun("alert http any any -> any any (flow:to_server; http.header; "
                                "content:\"host: boom\"; http.trailer; content:\"Header2\"; "
                                "sid:1;)",
            trailer_test_buf, sizeof(trailer_test_buf) - 1, true);
}

/** \test a trailer section without fields has nothing to match */
static int DetectHttpTrailerTest06(void)
{
    return DetectHttpTrailerRun("alert http any any -> any any (flow:to_server; http.trailer; "
                                "content:\"Dummy-Header\"; sid:1;)",
            trailer_test_buf_nofields, sizeof(trailer_test_buf_nofields) - 1, false);
}

void DetectHttpTrailerRegisterTests(void)
{
    UtRegisterTest("DetectHttpTrailerTest01", DetectHttpTrailerTest01);
    UtRegisterTest("DetectHttpTrailerTest02", DetectHttpTrailerTest02);
    UtRegisterTest("DetectHttpTrailerTest03", DetectHttpTrailerTest03);
    UtRegisterTest("DetectHttpTrailerTest04", DetectHttpTrailerTest04);
    UtRegisterTest("DetectHttpTrailerTest05", DetectHttpTrailerTest05);
    UtRegisterTest("DetectHttpTrailerTest06", DetectHttpTrailerTest06);
}
