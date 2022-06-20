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
 * \brief Handle HTTP request body match corresponding to http_client_body
 * keyword.
 *
 */

#include "../suricata-common.h"
#include "../suricata.h"
#include "../decode.h"

#include "detect.h"
#include "detect-engine.h"
#include "detect-engine-mpm.h"
#include "detect-parse.h"
#include "detect-engine-state.h"
#include "detect-engine-content-inspection.h"
#include "detect-engine-prefilter.h"
#include "detect-isdataat.h"
#include "stream-tcp-reassemble.h"
#include "detect-engine-build.h"

#include "flow-util.h"
#include "util-debug.h"
#include "util-print.h"
#include "flow.h"

#include "app-layer-parser.h"

#include "stream-tcp.h"

#include "util-unittest.h"
#include "util-unittest-helper.h"
#include "app-layer.h"
#include "app-layer-htp.h"
#include "app-layer-protos.h"

#include "conf.h"
#include "conf-yaml-loader.h"

#include "util-validate.h"

#ifdef UNITTESTS

/**
 * \test Test parser accepting valid rules and rejecting invalid rules
 */
static int DetectHttpClientBodyParserTest01(void)
{
    FAIL_IF_NOT(UTHParseSignature("alert http any any -> any any (flow:to_server; content:\"abc\"; http_client_body; sid:1;)", true));
    FAIL_IF_NOT(UTHParseSignature("alert http any any -> any any (flow:to_server; content:\"abc\"; nocase; http_client_body; sid:1;)", true));
    FAIL_IF_NOT(UTHParseSignature("alert http any any -> any any (flow:to_server; content:\"abc\"; endswith; http_client_body; sid:1;)", true));
    FAIL_IF_NOT(UTHParseSignature("alert http any any -> any any (flow:to_server; content:\"abc\"; startswith; http_client_body; sid:1;)", true));
    FAIL_IF_NOT(UTHParseSignature("alert http any any -> any any (flow:to_server; content:\"abc\"; startswith; endswith; http_client_body; sid:1;)", true));

    FAIL_IF_NOT(UTHParseSignature("alert http any any -> any any (flow:to_server; content:\"abc\"; rawbytes; http_client_body; sid:1;)", false));
    FAIL_IF_NOT(UTHParseSignature("alert tcp any any -> any any (flow:to_server; http_client_body; sid:1;)", false));
    FAIL_IF_NOT(UTHParseSignature("alert tls any any -> any any (flow:to_server; content:\"abc\"; http_client_body; sid:1;)", false));
    PASS;
}

/**
 * \test Test parser accepting valid rules and rejecting invalid rules
 */
static int DetectHttpClientBodyParserTest02(void)
{
    FAIL_IF_NOT(UTHParseSignature("alert http any any -> any any (flow:to_server; http.request_body; content:\"abc\"; sid:1;)", true));
    FAIL_IF_NOT(UTHParseSignature("alert http any any -> any any (flow:to_server; http.request_body; content:\"abc\"; nocase; sid:1;)", true));
    FAIL_IF_NOT(UTHParseSignature("alert http any any -> any any (flow:to_server; http.request_body; content:\"abc\"; endswith; sid:1;)", true));
    FAIL_IF_NOT(UTHParseSignature("alert http any any -> any any (flow:to_server; http.request_body; content:\"abc\"; startswith; sid:1;)", true));
    FAIL_IF_NOT(UTHParseSignature("alert http any any -> any any (flow:to_server; http.request_body; content:\"abc\"; startswith; endswith; sid:1;)", true));
    FAIL_IF_NOT(UTHParseSignature("alert http any any -> any any (flow:to_server; http.request_body; bsize:10; sid:1;)", true));

    FAIL_IF_NOT(UTHParseSignature("alert http any any -> any any (flow:to_server; http.request_body; content:\"abc\"; rawbytes; sid:1;)", false));
    FAIL_IF_NOT(UTHParseSignature("alert tcp any any -> any any (flow:to_server; http.request_body; sid:1;)", false));
    FAIL_IF_NOT(UTHParseSignature("alert tls any any -> any any (flow:to_server; http.request_body; content:\"abc\"; sid:1;)", false));
    PASS;
}

struct TestSteps {
    const uint8_t *input;
    size_t input_size;      /**< if 0 strlen will be used */
    int direction;          /**< STREAM_TOSERVER, STREAM_TOCLIENT */
    int expect;
};

static int RunTest (struct TestSteps *steps, const char *sig, const char *yaml)
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
        FAIL_IF_NOT (b->expect == match);

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
    }
    PASS;
}

static int DetectEngineHttpClientBodyTest01(void)
{
    struct TestSteps steps[] = {
        {   (const uint8_t *)"GET /index.html HTTP/1.1\r\n"
            "Host: www.openinfosecfoundation.org\r\n"
            "Content-Type: text/html\r\n"
            "Content-Length: 46\r\n"
            "\r\n"
            "This is dummy body1",
            0, STREAM_TOSERVER, 0 },
        {   (const uint8_t *)"This is dummy message body2",
            0, STREAM_TOSERVER, 1 },
        {   NULL, 0, 0, 0 },
    };

    const char *sig = "alert http any any -> any any (content:\"body1This\"; http_client_body; sid:1;)";
    return RunTest(steps, sig, NULL);
}

static int DetectEngineHttpClientBodyTest02(void)
{
    struct TestSteps steps[] = {
        {   (const uint8_t *)"GET /index.html HTTP/1.1\r\n"
            "Host: www.openinfosecfoundation.org\r\n"
            "Content-Type: text/html\r\n"
            "Content-Length: 19\r\n"
            "\r\n"
            "This is dummy body1",
            0, STREAM_TOSERVER, 1 },
        {   NULL, 0, 0, 0 },
    };

    const char *sig = "alert http any any -> any any (content:\"body1\"; http_client_body; offset:5; sid:1;)";
    return RunTest(steps, sig, NULL);
}

static int DetectEngineHttpClientBodyTest03(void)
{
    struct TestSteps steps[] = {
        {   (const uint8_t *)"GET /index.html HTTP/1.1\r\n"
            "Host: www.openinfosecfoundation.org\r\n"
            "Content-Type: text/html\r\n"
            "Content-Length: 46\r\n"
            "\r\n"
            "This is dummy body1",
            0, STREAM_TOSERVER, 0 },
        {   (const uint8_t *)"This is dummy message body2",
            0, STREAM_TOSERVER, 0 },
        {   NULL, 0, 0, 0 },
    };

    const char *sig = "alert http any any -> any any (content:\"body1\"; http_client_body; offset:16; sid:1;)";
    return RunTest(steps, sig, NULL);
}

static int DetectEngineHttpClientBodyTest04(void)
{
    struct TestSteps steps[] = {
        {   (const uint8_t *)"GET /index.html HTTP/1.1\r\n"
            "Host: www.openinfosecfoundation.org\r\n"
            "Content-Type: text/html\r\n"
            "Content-Length: 46\r\n"
            "\r\n"
            "This is dummy body1",
            0, STREAM_TOSERVER, 0 },
        {   (const uint8_t *)"This is dummy message body2",
            0, STREAM_TOSERVER, 1 },
        {   NULL, 0, 0, 0 },
    };

    const char *sig = "alert http any any -> any any (content:!\"body1\"; http_client_body; offset:16; sid:1;)";
    return RunTest(steps, sig, NULL);
}

static int DetectEngineHttpClientBodyTest05(void)
{
    struct TestSteps steps[] = {
        {   (const uint8_t *)"GET /index.html HTTP/1.1\r\n"
            "Host: www.openinfosecfoundation.org\r\n"
            "Content-Type: text/html\r\n"
            "Content-Length: 46\r\n"
            "\r\n"
            "This is dummy body1",
            0, STREAM_TOSERVER, 0 },
        {   (const uint8_t *)"This is dummy message body2",
            0, STREAM_TOSERVER, 1 },
        {   NULL, 0, 0, 0 },
    };

    const char *sig = "alert http any any -> any any (content:\"body1\"; http_client_body; depth:25; sid:1;)";
    return RunTest(steps, sig, NULL);
}

static int DetectEngineHttpClientBodyTest06(void)
{
    struct TestSteps steps[] = {
        {   (const uint8_t *)"GET /index.html HTTP/1.1\r\n"
            "Host: www.openinfosecfoundation.org\r\n"
            "Content-Type: text/html\r\n"
            "Content-Length: 46\r\n"
            "\r\n"
            "This is dummy body1",
            0, STREAM_TOSERVER, 0 },
        {   (const uint8_t *)"This is dummy message body2",
            0, STREAM_TOSERVER, 0 },
        {   NULL, 0, 0, 0 },
    };

    const char *sig = "alert http any any -> any any (content:!\"body1\"; http_client_body; depth:25; sid:1;)";
    return RunTest(steps, sig, NULL);
}

static int DetectEngineHttpClientBodyTest07(void)
{
    struct TestSteps steps[] = {
        {   (const uint8_t *)"GET /index.html HTTP/1.1\r\n"
            "Host: www.openinfosecfoundation.org\r\n"
            "Content-Type: text/html\r\n"
            "Content-Length: 46\r\n"
            "\r\n"
            "This is dummy body1",
            0, STREAM_TOSERVER, 0 },
        {   (const uint8_t *)"This is dummy message body2",
            0, STREAM_TOSERVER, 1 },
        {   NULL, 0, 0, 0 },
    };

    const char *sig = "alert http any any -> any any (content:!\"body1\"; http_client_body; depth:15; sid:1;)";
    return RunTest(steps, sig, NULL);
}

static int DetectEngineHttpClientBodyTest08(void)
{
    struct TestSteps steps[] = {
        {   (const uint8_t *)"GET /index.html HTTP/1.1\r\n"
            "Host: www.openinfosecfoundation.org\r\n"
            "Content-Type: text/html\r\n"
            "Content-Length: 46\r\n"
            "\r\n"
            "This is dummy body1",
            0, STREAM_TOSERVER, 0 },
        {   (const uint8_t *)"This is dummy message body2",
            0, STREAM_TOSERVER, 1 },
        {   NULL, 0, 0, 0 },
    };

    const char *sig = "alert http any any -> any any (content:\"This is dummy body1This is dummy message body2\"; http_client_body; sid:1;)";
    return RunTest(steps, sig, NULL);
}

static int DetectEngineHttpClientBodyTest09(void)
{
    struct TestSteps steps[] = {
        {   (const uint8_t *)"GET /index.html HTTP/1.1\r\n"
            "Host: www.openinfosecfoundation.org\r\n"
            "Content-Type: text/html\r\n"
            "Content-Length: 46\r\n"
            "\r\n"
            "This is dummy body1",
            0, STREAM_TOSERVER, 0 },
        {   (const uint8_t *)"This is dummy message body2",
            0, STREAM_TOSERVER, 1 },
        {   NULL, 0, 0, 0 },
    };

    const char *sig = "alert http any any -> any any (content:\"body1\"; http_client_body; content:\"This\"; http_client_body; within:5; sid:1;)";
    return RunTest(steps, sig, NULL);
}

static int DetectEngineHttpClientBodyTest10(void)
{
    struct TestSteps steps[] = {
        {   (const uint8_t *)"GET /index.html HTTP/1.1\r\n"
            "Host: www.openinfosecfoundation.org\r\n"
            "Content-Type: text/html\r\n"
            "Content-Length: 46\r\n"
            "\r\n"
            "This is dummy body1",
            0, STREAM_TOSERVER, 0 },
        {   (const uint8_t *)"This is dummy message body2",
            0, STREAM_TOSERVER, 1 },
        {   NULL, 0, 0, 0 },
    };

    const char *sig = "alert http any any -> any any (content:\"body1\"; http_client_body; content:!\"boom\"; http_client_body; within:5; sid:1;)";
    return RunTest(steps, sig, NULL);
}

static int DetectEngineHttpClientBodyTest11(void)
{
    struct TestSteps steps[] = {
        {   (const uint8_t *)"GET /index.html HTTP/1.1\r\n"
            "Host: www.openinfosecfoundation.org\r\n"
            "Content-Type: text/html\r\n"
            "Content-Length: 46\r\n"
            "\r\n"
            "This is dummy body1",
            0, STREAM_TOSERVER, 0 },
        {   (const uint8_t *)"This is dummy message body2",
            0, STREAM_TOSERVER, 0 },
        {   NULL, 0, 0, 0 },
    };

    const char *sig = "alert http any any -> any any (content:\"body1\"; http_client_body; content:\"boom\"; http_client_body; within:5; sid:1;)";
    return RunTest(steps, sig, NULL);
}

static int DetectEngineHttpClientBodyTest12(void)
{
    struct TestSteps steps[] = {
        {   (const uint8_t *)"GET /index.html HTTP/1.1\r\n"
            "Host: www.openinfosecfoundation.org\r\n"
            "Content-Type: text/html\r\n"
            "Content-Length: 46\r\n"
            "\r\n"
            "This is dummy body1",
            0, STREAM_TOSERVER, 0 },
        {   (const uint8_t *)"This is dummy message body2",
            0, STREAM_TOSERVER, 0 },
        {   NULL, 0, 0, 0 },
    };

    const char *sig = "alert http any any -> any any (content:\"body1\"; http_client_body; content:!\"This\"; http_client_body; within:5; sid:1;)";
    return RunTest(steps, sig, NULL);
}

static int DetectEngineHttpClientBodyTest13(void)
{
    struct TestSteps steps[] = {
        {   (const uint8_t *)"GET /index.html HTTP/1.1\r\n"
            "Host: www.openinfosecfoundation.org\r\n"
            "Content-Type: text/html\r\n"
            "Content-Length: 46\r\n"
            "\r\n"
            "This is dummy body1",
            0, STREAM_TOSERVER, 0 },
        {   (const uint8_t *)"This is dummy message body2",
            0, STREAM_TOSERVER, 1 },
        {   NULL, 0, 0, 0 },
    };

    const char *sig = "alert http any any -> any any (content:\"body1\"; http_client_body; content:\"dummy\"; http_client_body; distance:5; sid:1;)";
    return RunTest(steps, sig, NULL);
}

static int DetectEngineHttpClientBodyTest14(void)
{
    struct TestSteps steps[] = {
        {   (const uint8_t *)"GET /index.html HTTP/1.1\r\n"
            "Host: www.openinfosecfoundation.org\r\n"
            "Content-Type: text/html\r\n"
            "Content-Length: 46\r\n"
            "\r\n"
            "This is dummy body1",
            0, STREAM_TOSERVER, 0 },
        {   (const uint8_t *)"This is dummy message body2",
            0, STREAM_TOSERVER, 1 },
        {   NULL, 0, 0, 0 },
    };

    const char *sig = "alert http any any -> any any (content:\"body1\"; http_client_body; content:!\"dummy\"; http_client_body; distance:10; sid:1;)";
    return RunTest(steps, sig, NULL);
}

static int DetectEngineHttpClientBodyTest15(void)
{
    struct TestSteps steps[] = {
        {   (const uint8_t *)"GET /index.html HTTP/1.1\r\n"
            "Host: www.openinfosecfoundation.org\r\n"
            "Content-Type: text/html\r\n"
            "Content-Length: 46\r\n"
            "\r\n"
            "This is dummy body1",
            0, STREAM_TOSERVER, 0 },
        {   (const uint8_t *)"This is dummy message body2",
            0, STREAM_TOSERVER, 0 },
        {   NULL, 0, 0, 0 },
    };

    const char *sig = "alert http any any -> any any (content:\"body1\"; http_client_body; content:\"dummy\"; http_client_body; distance:10; sid:1;)";
    return RunTest(steps, sig, NULL);
}

static int DetectEngineHttpClientBodyTest16(void)
{
    struct TestSteps steps[] = {
        {   (const uint8_t *)"GET /index.html HTTP/1.1\r\n"
            "Host: www.openinfosecfoundation.org\r\n"
            "Content-Type: text/html\r\n"
            "Content-Length: 46\r\n"
            "\r\n"
            "This is dummy body1",
            0, STREAM_TOSERVER, 0 },
        {   (const uint8_t *)"This is dummy message body2",
            0, STREAM_TOSERVER, 0 },
        {   NULL, 0, 0, 0 },
    };

    const char *sig = "alert http any any -> any any (content:\"body1\"; http_client_body; content:!\"dummy\"; http_client_body; distance:5; sid:1;)";
    return RunTest(steps, sig, NULL);
}

static int DetectEngineHttpClientBodyTest17(void)
{
    struct TestSteps steps[] = {
        {   (const uint8_t *)"GET /index.html HTTP/1.1\r\n"
            "Host: www.openinfosecfoundation.org\r\n"
            "Content-Type: text/html\r\n"
            "Content-Length: 19\r\n"
            "\r\n"
            "This is dummy body1",
            0, STREAM_TOSERVER, 0 },
        {   NULL, 0, 0, 0 },
    };

    const char *sig = "alert http any any -> any any (content:\"body1\"; http_client_body; content:\"bambu\"; http_client_body; sid:1;)";
    return RunTest(steps, sig, NULL);
}

static int DetectEngineHttpClientBodyTest18(void)
{
    struct TestSteps steps[] = {
        {   (const uint8_t *)"GET /index.html HTTP/1.1\r\n"
            "Host: www.openinfosecfoundation.org\r\n"
            "Content-Type: text/html\r\n"
            "Content-Length: 19\r\n"
            "\r\n"
            "This is dummy body1",
            0, STREAM_TOSERVER, 0 },
        {   NULL, 0, 0, 0 },
    };

    const char *sig = "alert http any any -> any any (content:\"body1\"; http_client_body; content:\"bambu\"; http_client_body; fast_pattern; sid:1;)";
    return RunTest(steps, sig, NULL);
}

static int DetectEngineHttpClientBodyTest19(void)
{
    struct TestSteps steps[] = {
        {   (const uint8_t *)"GET /index.html HTTP/1.1\r\n"
            "Host: www.openinfosecfoundation.org\r\n"
            "Content-Type: text/html\r\n"
            "Content-Length: 19\r\n"
            "\r\n"
            "This is dummy body1",
            0, STREAM_TOSERVER, 0 },
        {   NULL, 0, 0, 0 },
    };

    const char *sig = "alert http any any -> any any (content:\"bambu\"; http_client_body; content:\"is\"; http_client_body; sid:1;)";
    return RunTest(steps, sig, NULL);
}

static int DetectEngineHttpClientBodyTest20(void)
{
    struct TestSteps steps[] = {
        {   (const uint8_t *)"GET /index.html HTTP/1.1\r\n"
            "Host: www.openinfosecfoundation.org\r\n"
            "Content-Type: text/html\r\n"
            "Content-Length: 19\r\n"
            "\r\n"
            "This is dummy body1",
            0, STREAM_TOSERVER, 1 },
        {   NULL, 0, 0, 0 },
    };

    const char *sig = "alert http any any -> any any (content:\"is\"; http_client_body; fast_pattern; sid:1;)";
    return RunTest(steps, sig, NULL);
}

static int DetectEngineHttpClientBodyTest21(void)
{
    struct TestSteps steps[] = {
        {   (const uint8_t *)"GET /index.html HTTP/1.1\r\n"
            "Host: www.openinfosecfoundation.org\r\n"
            "Content-Type: text/html\r\n"
            "Content-Length: 46\r\n"
            "\r\n"
            "This is dummy body1",
            0, STREAM_TOSERVER, 0 },
        {   (const uint8_t *)"This is dummy message body2",
            0, STREAM_TOSERVER, 1 },
        {   NULL, 0, 0, 0 },
    };

    const char *sig = "alert http any any -> any any (pcre:/body1/P; content:!\"dummy\"; http_client_body; within:7; sid:1;)";
    return RunTest(steps, sig, NULL);
}

static int DetectEngineHttpClientBodyTest22(void)
{
    struct TestSteps steps[] = {
        {   (const uint8_t *)"GET /index.html HTTP/1.1\r\n"
            "Host: www.openinfosecfoundation.org\r\n"
            "Content-Type: text/html\r\n"
            "Content-Length: 46\r\n"
            "\r\n"
            "This is dummy body1",
            0, STREAM_TOSERVER, 0 },
        {   (const uint8_t *)"This is dummy message body2",
            0, STREAM_TOSERVER, 1 },
        {   NULL, 0, 0, 0 },
    };

    const char *sig = "alert http any any -> any any (pcre:/body1/P; content:!\"dummy\"; within:7; http_client_body; sid:1;)";
    return RunTest(steps, sig, NULL);
}

static int DetectEngineHttpClientBodyTest23(void)
{
    struct TestSteps steps[] = {
        {   (const uint8_t *)"GET /index.html HTTP/1.1\r\n"
            "Host: www.openinfosecfoundation.org\r\n"
            "Content-Type: text/html\r\n"
            "Content-Length: 46\r\n"
            "\r\n"
            "This is dummy body1",
            0, STREAM_TOSERVER, 0 },
        {   (const uint8_t *)"This is dummy message body2",
            0, STREAM_TOSERVER, 0 },
        {   NULL, 0, 0, 0 },
    };

    const char *sig = "alert http any any -> any any (pcre:/body1/P; content:!\"dummy\"; distance:3; http_client_body; sid:1;)";
    return RunTest(steps, sig, NULL);
}

static int DetectEngineHttpClientBodyTest24(void)
{
    struct TestSteps steps[] = {
        {   (const uint8_t *)"GET /index.html HTTP/1.1\r\n"
            "Host: www.openinfosecfoundation.org\r\n"
            "Content-Type: text/html\r\n"
            "Content-Length: 46\r\n"
            "\r\n"
            "This is dummy body1",
            0, STREAM_TOSERVER, 0 },
        {   (const uint8_t *)"This is dummy message body2",
            0, STREAM_TOSERVER, 1 },
        {   NULL, 0, 0, 0 },
    };

    const char *sig = "alert http any any -> any any (pcre:/body1/P; content:!\"dummy\"; distance:13; http_client_body; sid:1;)";
    return RunTest(steps, sig, NULL);
}

static int DetectEngineHttpClientBodyTest25(void)
{
    struct TestSteps steps[] = {
        {   (const uint8_t *)"GET /index.html HTTP/1.1\r\n"
            "Host: www.openinfosecfoundation.org\r\n"
            "Content-Type: text/html\r\n"
            "Content-Length: 46\r\n"
            "\r\n"
            "This is dummy body1",
            0, STREAM_TOSERVER, 0 },
        {   (const uint8_t *)"This is dummy message body2",
            0, STREAM_TOSERVER, 1 },
        {   NULL, 0, 0, 0 },
    };

    const char *sig = "alert http any any -> any any (pcre:/body1/P; content:\"dummy\"; within:15; http_client_body; sid:1;)";
    return RunTest(steps, sig, NULL);
}

static int DetectEngineHttpClientBodyTest26(void)
{
    struct TestSteps steps[] = {
        {   (const uint8_t *)"GET /index.html HTTP/1.1\r\n"
            "Host: www.openinfosecfoundation.org\r\n"
            "Content-Type: text/html\r\n"
            "Content-Length: 46\r\n"
            "\r\n"
            "This is dummy body1",
            0, STREAM_TOSERVER, 0 },
        {   (const uint8_t *)"This is dummy message body2",
            0, STREAM_TOSERVER, 0 },
        {   NULL, 0, 0, 0 },
    };

    const char *sig = "alert http any any -> any any (pcre:/body1/P; content:\"dummy\"; within:10; http_client_body; sid:1;)";
    return RunTest(steps, sig, NULL);
}

static int DetectEngineHttpClientBodyTest27(void)
{
    struct TestSteps steps[] = {
        {   (const uint8_t *)"GET /index.html HTTP/1.1\r\n"
            "Host: www.openinfosecfoundation.org\r\n"
            "Content-Type: text/html\r\n"
            "Content-Length: 46\r\n"
            "\r\n"
            "This is dummy body1",
            0, STREAM_TOSERVER, 0 },
        {   (const uint8_t *)"This is dummy message body2",
            0, STREAM_TOSERVER, 1 },
        {   NULL, 0, 0, 0 },
    };

    const char *sig = "alert http any any -> any any (pcre:/body1/P; content:\"dummy\"; distance:8; http_client_body; sid:1;)";
    return RunTest(steps, sig, NULL);
}

static int DetectEngineHttpClientBodyTest28(void)
{
    struct TestSteps steps[] = {
        {   (const uint8_t *)"GET /index.html HTTP/1.1\r\n"
            "Host: www.openinfosecfoundation.org\r\n"
            "Content-Type: text/html\r\n"
            "Content-Length: 46\r\n"
            "\r\n"
            "This is dummy body1",
            0, STREAM_TOSERVER, 0 },
        {   (const uint8_t *)"This is dummy message body2",
            0, STREAM_TOSERVER, 0 },
        {   NULL, 0, 0, 0 },
    };

    const char *sig = "alert http any any -> any any (pcre:/body1/P; content:\"dummy\"; distance:14; http_client_body; sid:1;)";
    return RunTest(steps, sig, NULL);
}

static int DetectEngineHttpClientBodyTest29(void)
{
    const char *request_buffer = "GET /one HTTP/1.0\r\n"
                                 "Host: localhost\r\n\r\n";
#define TOTAL_REQUESTS 45
    uint8_t *http_buf = SCMalloc(TOTAL_REQUESTS * strlen(request_buffer));
    if (unlikely(http_buf == NULL))
        return 0;
    for (int i = 0; i < TOTAL_REQUESTS; i++) {
        memcpy(http_buf + i * strlen(request_buffer), request_buffer,
               strlen(request_buffer));
    }
    uint32_t http_buf_len = TOTAL_REQUESTS * strlen(request_buffer);
#undef TOTAL_REQUESTS

    struct TestSteps steps[] = {
        {   (const uint8_t *)http_buf,
            (size_t)http_buf_len, STREAM_TOSERVER, 0 },

        {   (const uint8_t *)"HTTP/1.0 200 ok\r\n"
            "Content-Type: text/html\r\n"
            "Content-Length: 5\r\n"
            "\r\n"
            "dummy",
            0, STREAM_TOCLIENT, 0 },

        {   NULL, 0, 0, 0 },
    };

    const char *sig = "alert http any any -> any any (content:\"dummyone\"; fast_pattern:0,3; http_server_body; sid:1;)";
    int result = RunTest(steps, sig, NULL);
    SCFree(http_buf);
    return result;
}

static int DetectEngineHttpClientBodyTest30(void)
{
    const char yaml[] = "\
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
    struct TestSteps steps[] = {
        {   (const uint8_t *)"GET /index.html HTTP/1.1\r\n"
            "Host: www.openinfosecfoundation.org\r\n"
            "Content-Type: text/html\r\n"
            "Content-Length: 46\r\n"
            "\r\n"
            "This is dummy body1",
            0, STREAM_TOSERVER, 0 },
        {   (const uint8_t *)"This is dummy message body2",
            0, STREAM_TOSERVER, 0 },
        {   NULL, 0, 0, 0 },
    };

    const char *sig = "alert http any any -> any any (content:\"bags\"; within:4; http_client_body; sid:1;)";
    return RunTest(steps, sig, yaml);
}

static int DetectEngineHttpClientBodyTest31(void)
{
    const char yaml[] = "\
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

    struct TestSteps steps[] = {
        {   (const uint8_t *)"GET /index.html HTTP/1.1\r\n"
            "Host: www.openinfosecfoundation.org\r\n"
            "Content-Type: text/html\r\n"
            "Content-Length: 46\r\n"
            "\r\n"
            "This is dummy body1",
            0, STREAM_TOSERVER, 0 },
        {   (const uint8_t *)"This is dummy message body2",
            0, STREAM_TOSERVER, 0 },
        {   NULL, 0, 0, 0 },
    };

    const char *sig = "alert http any any -> any any (content:\"bags\"; depth:4; http_client_body; sid:1;)";
    return RunTest(steps, sig, yaml);
}

/**
 * \test Test that a signature containting a http_client_body is correctly parsed
 *       and the keyword is registered.
 */
static int DetectHttpClientBodyTest01(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;
    SigMatch *sm = NULL;

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(msg:\"Testing http_client_body\"; "
                               "content:\"one\"; http_client_body; sid:1;)");
    if (de_ctx->sig_list != NULL) {
        result = 1;
    } else {
        goto end;
    }

    sm = de_ctx->sig_list->sm_lists[DETECT_SM_LIST_MATCH];
    if (sm != NULL) {
        result &= (sm->type == DETECT_CONTENT);
        result &= (sm->next == NULL);
    }

 end:
    DetectEngineCtxFree(de_ctx);

    return result;
}

/**
 * \test Test that a signature containing an valid http_client_body entry is
 *       parsed.
 */
static int DetectHttpClientBodyTest02(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(msg:\"Testing http_client_body\"; "
                               "content:\"one\"; http_client_body:; sid:1;)");
    if (de_ctx->sig_list != NULL)
        result = 1;

 end:
    DetectEngineCtxFree(de_ctx);

    return result;
}

/**
 * \test Test that an invalid signature containing no content but a http_client_body
 *       is invalidated.
 */
static int DetectHttpClientBodyTest03(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(msg:\"Testing http_client_body\"; "
                               "http_client_body; sid:1;)");
    if (de_ctx->sig_list == NULL)
        result = 1;

 end:
    DetectEngineCtxFree(de_ctx);

    return result;
}

/**
 * \test Test that an invalid signature containing a rawbytes along with a
 *       http_client_body is invalidated.
 */
static int DetectHttpClientBodyTest04(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(msg:\"Testing http_client_body\"; "
                               "content:\"one\"; rawbytes; http_client_body; sid:1;)");
    if (de_ctx->sig_list == NULL)
        result = 1;

 end:
    DetectEngineCtxFree(de_ctx);

    return result;
}

/**
 * \test Test that an invalid signature containing a rawbytes along with a
 *       http_client_body is invalidated.
 */
static int DetectHttpClientBodyTest05(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(msg:\"Testing http_client_body\"; "
                               "content:\"one\"; http_client_body; nocase; sid:1;)");
    if (de_ctx->sig_list != NULL)
        result = 1;

 end:
    DetectEngineCtxFree(de_ctx);

    return result;
}

/**
 *\test Test that the http_client_body content matches against a http request
 *      which holds the content.
 */
static int DetectHttpClientBodyTest06(void)
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
        "Content-Type: text/html\r\n"
        "Content-Length: 26\r\n"
        "\r\n"
        "This is dummy message body";
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
                               "(msg:\"http client body test\"; "
                               "content:\"message\"; http_client_body; "
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
 *\test Test that the http_client_body content matches against a http request
 *      which holds the content.
 */
static int DetectHttpClientBodyTest07(void)
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
        "Host: www.openinfosecfoundation.org\r\n"
        "User-Agent: Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.1.7) Gecko/20091221 Firefox/3.5.7\r\n"
        "Content-Type: text/html\r\n"
        "Content-Length: 54\r\n"
        "\r\n"
        "This is dummy message body1";
    uint8_t http2_buf[] =
        "This is dummy message body2";
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
                               "(msg:\"http client body test\"; "
                               "content:\"message\"; http_client_body; "
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
 *\test Test that the http_client_body content matches against a http request
 *      which holds the content.
 */
static int DetectHttpClientBodyTest08(void)
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
        "Host: www.openinfosecfoundation.org\r\n"
        "User-Agent: Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.1.7) Gecko/20091221 Firefox/3.5.7\r\n"
        "Content-Type: text/html\r\n"
        "Content-Length: 46\r\n"
        "\r\n"
        "This is dummy body1";
    uint8_t http2_buf[] =
        "This is dummy message body2";
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
                               "(msg:\"http client body test\"; "
                               "content:\"message\"; http_client_body; "
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
 *\test Test that the http_client_body content matches against a http request
 *      which holds the content, against a cross boundary present pattern.
 */
static int DetectHttpClientBodyTest09(void)
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
        "Host: www.openinfosecfoundation.org\r\n"
        "User-Agent: Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.1.7) Gecko/20091221 Firefox/3.5.7\r\n"
        "Content-Type: text/html\r\n"
        "Content-Length: 46\r\n"
        "\r\n"
        "This is dummy body1";
    uint8_t http2_buf[] =
        "This is dummy message body2";
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
                               "(msg:\"http client body test\"; "
                               "content:\"body1This\"; http_client_body; "
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
 *\test Test that the http_client_body content matches against a http request
 *      against a case insensitive pattern.
 */
static int DetectHttpClientBodyTest10(void)
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
        "Host: www.openinfosecfoundation.org\r\n"
        "User-Agent: Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.1.7) Gecko/20091221 Firefox/3.5.7\r\n"
        "Content-Type: text/html\r\n"
        "Content-Length: 46\r\n"
        "\r\n"
        "This is dummy bodY1";
    uint8_t http2_buf[] =
        "This is dummy message body2";
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
                               "(msg:\"http client body test\"; "
                               "content:\"body1This\"; http_client_body; nocase;"
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
 *\test Test that the negated http_client_body content matches against a
 *      http request which doesn't hold the content.
 */
static int DetectHttpClientBodyTest11(void)
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
        "Content-Type: text/html\r\n"
        "Content-Length: 26\r\n"
        "\r\n"
        "This is dummy message body";
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
                               "(msg:\"http client body test\"; "
                               "content:!\"message1\"; http_client_body; "
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
 *\test Negative test that the negated http_client_body content matches against a
 *      http request which holds hold the content.
 */
static int DetectHttpClientBodyTest12(void)
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
        "Content-Type: text/html\r\n"
        "Content-Length: 26\r\n"
        "\r\n"
        "This is dummy message body";
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
                               "(msg:\"http client body test\"; "
                               "content:!\"message\"; http_client_body; "
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

    if ((PacketAlertCheck(p, 1))) {
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
 *\test Test that the http_client_body content matches against a http request
 *      which holds the content.
 */
static int DetectHttpClientBodyTest13(void)
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
        "Content-Type: text/html\r\n"
        "Content-Length: 55\r\n"
        "\r\n"
        "longbufferabcdefghijklmnopqrstuvwxyz0123456789bufferend";
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
                               "(msg:\"http client body test\"; "
                               "content:\"abcdefghijklmnopqrstuvwxyz0123456789\"; http_client_body; "
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

/** \test multiple http transactions and body chunks of request handling */
static int DetectHttpClientBodyTest14(void)
{
    int result = 0;
    Signature *s = NULL;
    DetectEngineThreadCtx *det_ctx = NULL;
    ThreadVars th_v;
    Flow f;
    TcpSession ssn;
    Packet *p = NULL;
    uint8_t httpbuf1[] = "POST / HTTP/1.1\r\n";
    uint8_t httpbuf2[] = "User-Agent: Mozilla/1.0\r\nContent-Length: 10\r\n";
    uint8_t httpbuf3[] = "Cookie: dummy\r\n\r\n";
    uint8_t httpbuf4[] = "Body one!!";
    uint32_t httplen1 = sizeof(httpbuf1) - 1; /* minus the \0 */
    uint32_t httplen2 = sizeof(httpbuf2) - 1; /* minus the \0 */
    uint32_t httplen3 = sizeof(httpbuf3) - 1; /* minus the \0 */
    uint32_t httplen4 = sizeof(httpbuf4) - 1; /* minus the \0 */
    uint8_t httpbuf5[] = "GET /?var=val HTTP/1.1\r\n";
    uint8_t httpbuf6[] = "User-Agent: Firefox/1.0\r\n";
    uint8_t httpbuf7[] = "Cookie: dummy2\r\nContent-Length: 10\r\n\r\nBody two!!";
    uint32_t httplen5 = sizeof(httpbuf5) - 1; /* minus the \0 */
    uint32_t httplen6 = sizeof(httpbuf6) - 1; /* minus the \0 */
    uint32_t httplen7 = sizeof(httpbuf7) - 1; /* minus the \0 */
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

    s = DetectEngineAppendSig(de_ctx, "alert tcp any any -> any any (content:\"POST\"; http_method; content:\"Mozilla\"; http_header; content:\"dummy\"; http_cookie; content:\"one\"; http_client_body; sid:1; rev:1;)");
    if (s == NULL) {
        printf("sig parse failed: ");
        goto end;
    }
    s = DetectEngineAppendSig(de_ctx, "alert tcp any any -> any any (content:\"GET\"; http_method; content:\"Firefox\"; http_header; content:\"dummy2\"; http_cookie; content:\"two\"; http_client_body; sid:2; rev:1;)");
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
    if (PacketAlertCheck(p, 1)) {
        printf("signature matched, but shouldn't have: ");
        goto end;
    }
    p->alerts.cnt = 0;

    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER, httpbuf4, httplen4);
    if (r != 0) {
        printf("toserver chunk 4 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    if (!(PacketAlertCheck(p, 1))) {
        printf("sig 1 didn't alert: ");
        goto end;
    }
    p->alerts.cnt = 0;

    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER, httpbuf5, httplen5);
    if (r != 0) {
        printf("toserver chunk 5 returned %" PRId32 ", expected 0: ", r);
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    if (PacketAlertCheck(p, 1)) {
        printf("sig 1 alerted (5): ");
        goto end;
    }
    p->alerts.cnt = 0;

    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER, httpbuf6, httplen6);
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

    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER, httpbuf7, httplen7);
    if (r != 0) {
        printf("toserver chunk 7 returned %" PRId32 ", expected 0: ", r);
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    if (!(PacketAlertCheck(p, 2))) {
        printf("signature 2 didn't match, but should have: ");
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

/** \test multiple http transactions and body chunks of request handling */
static int DetectHttpClientBodyTest15(void)
{
    int result = 0;
    Signature *s = NULL;
    DetectEngineThreadCtx *det_ctx = NULL;
    ThreadVars th_v;
    Flow f;
    TcpSession ssn;
    Packet *p = NULL;
    uint8_t httpbuf1[] = "POST / HTTP/1.1\r\n";
    uint8_t httpbuf2[] = "User-Agent: Mozilla/1.0\r\nContent-Length: 10\r\n";
    uint8_t httpbuf3[] = "Cookie: dummy\r\n\r\n";
    uint8_t httpbuf4[] = "Body one!!";
    uint32_t httplen1 = sizeof(httpbuf1) - 1; /* minus the \0 */
    uint32_t httplen2 = sizeof(httpbuf2) - 1; /* minus the \0 */
    uint32_t httplen3 = sizeof(httpbuf3) - 1; /* minus the \0 */
    uint32_t httplen4 = sizeof(httpbuf4) - 1; /* minus the \0 */
    uint8_t httpbuf5[] = "GET /?var=val HTTP/1.1\r\n";
    uint8_t httpbuf6[] = "User-Agent: Firefox/1.0\r\n";
    uint8_t httpbuf7[] = "Cookie: dummy2\r\nContent-Length: 10\r\n\r\nBody two!!";
    uint32_t httplen5 = sizeof(httpbuf5) - 1; /* minus the \0 */
    uint32_t httplen6 = sizeof(httpbuf6) - 1; /* minus the \0 */
    uint32_t httplen7 = sizeof(httpbuf7) - 1; /* minus the \0 */
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

    s = DetectEngineAppendSig(de_ctx, "alert tcp any any -> any any (content:\"POST\"; http_method; content:\"Mozilla\"; http_header; content:\"dummy\"; http_cookie; content:\"one\"; http_client_body; sid:1; rev:1;)");
    if (s == NULL) {
        printf("sig parse failed: ");
        goto end;
    }
    s = DetectEngineAppendSig(de_ctx, "alert tcp any any -> any any (content:\"GET\"; http_method; content:\"Firefox\"; http_header; content:\"dummy2\"; http_cookie; content:\"two\"; http_client_body; sid:2; rev:1;)");
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
    if (PacketAlertCheck(p, 1)) {
        printf("signature matched, but shouldn't have: ");
        goto end;
    }
    p->alerts.cnt = 0;

    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER, httpbuf4, httplen4);
    if (r != 0) {
        printf("toserver chunk 4 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    if (!(PacketAlertCheck(p, 1))) {
        printf("sig 1 didn't alert: ");
        goto end;
    }
    p->alerts.cnt = 0;

    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER, httpbuf5, httplen5);
    if (r != 0) {
        printf("toserver chunk 5 returned %" PRId32 ", expected 0: ", r);
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    if (PacketAlertCheck(p, 1)) {
        printf("sig 1 alerted (5): ");
        goto end;
    }
    p->alerts.cnt = 0;

    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER, httpbuf6, httplen6);
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

    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER, httpbuf7, httplen7);
    if (r != 0) {
        printf("toserver chunk 7 returned %" PRId32 ", expected 0: ", r);
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    if (!(PacketAlertCheck(p, 2))) {
        printf("signature 2 didn't match, but should have: ");
        goto end;
    }
    p->alerts.cnt = 0;

    HtpState *htp_state = f.alstate;
    if (htp_state == NULL) {
        printf("no http state: ");
        result = 0;
        goto end;
    }

    /* hardcoded check of the transactions and it's client body chunks */
    if (AppLayerParserGetTxCnt(&f, htp_state) != 2) {
        printf("The http app layer doesn't have 2 transactions, but it should: ");
        goto end;
    }

    htp_tx_t *t1 = AppLayerParserGetTx(IPPROTO_TCP, ALPROTO_HTTP1, htp_state, 0);
    htp_tx_t *t2 = AppLayerParserGetTx(IPPROTO_TCP, ALPROTO_HTTP1, htp_state, 1);

    HtpTxUserData *htud = (HtpTxUserData *) htp_tx_get_user_data(t1);

    HtpBodyChunk *cur = htud->request_body.first;
    if (htud->request_body.first == NULL) {
        SCLogDebug("No body data in t1 (it should be removed only when the tx is destroyed): ");
        goto end;
    }

    if (StreamingBufferSegmentCompareRawData(htud->request_body.sb, &cur->sbseg,
                (uint8_t *)"Body one!!", 10) != 1)
    {
        SCLogDebug("Body data in t1 is not correctly set: ");
        goto end;
    }

    htud = (HtpTxUserData *) htp_tx_get_user_data(t2);

    cur = htud->request_body.first;
    if (htud->request_body.first == NULL) {
        SCLogDebug("No body data in t1 (it should be removed only when the tx is destroyed): ");
        goto end;
    }

    if (StreamingBufferSegmentCompareRawData(htud->request_body.sb, &cur->sbseg,
                (uint8_t *)"Body two!!", 10) != 1)
    {
        SCLogDebug("Body data in t1 is not correctly set: ");
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

static int DetectHttpClientBodyTest22(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert icmp any any -> any any "
                               "(content:\"one\"; content:\"two\"; http_client_body; "
                               "content:\"three\"; distance:10; http_client_body; content:\"four\"; sid:1;)");
    if (de_ctx->sig_list == NULL) {
        printf("de_ctx->sig_list == NULL\n");
        goto end;
    }

    if (de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH] == NULL) {
        printf("de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH] == NULL\n");
        goto end;
    }

    if (de_ctx->sig_list->sm_lists[g_http_client_body_buffer_id] == NULL) {
        printf("de_ctx->sig_list->sm_lists[g_http_client_body_buffer_id] == NULL\n");
        goto end;
    }

    DetectContentData *cd1 = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[DETECT_SM_LIST_PMATCH]->prev->ctx;
    DetectContentData *cd2 = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[DETECT_SM_LIST_PMATCH]->ctx;
    DetectContentData *hcbd1 = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_http_client_body_buffer_id]->prev->ctx;
    DetectContentData *hcbd2 = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_http_client_body_buffer_id]->ctx;
    if (cd1->flags != 0 || memcmp(cd1->content, "one", cd1->content_len) != 0 ||
        cd2->flags != 0 || memcmp(cd2->content, "four", cd2->content_len) != 0 ||
        hcbd1->flags != DETECT_CONTENT_RELATIVE_NEXT ||
        memcmp(hcbd1->content, "two", hcbd1->content_len) != 0 ||
        hcbd2->flags != DETECT_CONTENT_DISTANCE ||
        memcmp(hcbd2->content, "three", hcbd1->content_len) != 0) {
        goto end;
    }

    if (!DETECT_CONTENT_IS_SINGLE(cd1) ||
        !DETECT_CONTENT_IS_SINGLE(cd2) ||
        DETECT_CONTENT_IS_SINGLE(hcbd1) ||
        DETECT_CONTENT_IS_SINGLE(hcbd2)) {
        goto end;
    }

    result = 1;

 end:
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectHttpClientBodyTest23(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert icmp any any -> any any "
                               "(content:\"one\"; http_client_body; pcre:/two/; "
                               "content:\"three\"; distance:10; http_client_body; content:\"four\"; sid:1;)");
    if (de_ctx->sig_list == NULL) {
        printf("de_ctx->sig_list == NULL\n");
        goto end;
    }

    if (de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH] == NULL) {
        printf("de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH] == NULL\n");
        goto end;
    }

    if (de_ctx->sig_list->sm_lists[g_http_client_body_buffer_id] == NULL) {
        printf("de_ctx->sig_list->sm_lists[g_http_client_body_buffer_id] == NULL\n");
        goto end;
    }

    DetectPcreData *pd1 = (DetectPcreData *)de_ctx->sig_list->sm_lists_tail[DETECT_SM_LIST_PMATCH]->prev->ctx;
    DetectContentData *cd2 = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[DETECT_SM_LIST_PMATCH]->ctx;
    DetectContentData *hcbd1 = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_http_client_body_buffer_id]->prev->ctx;
    DetectContentData *hcbd2 = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_http_client_body_buffer_id]->ctx;
    if (pd1->flags != 0 ||
        cd2->flags != 0 || memcmp(cd2->content, "four", cd2->content_len) != 0 ||
        hcbd1->flags != DETECT_CONTENT_RELATIVE_NEXT ||
        memcmp(hcbd1->content, "one", hcbd1->content_len) != 0 ||
        hcbd2->flags != DETECT_CONTENT_DISTANCE ||
        memcmp(hcbd2->content, "three", hcbd1->content_len) != 0) {
        goto end;
    }

    if (!DETECT_CONTENT_IS_SINGLE(cd2) ||
        DETECT_CONTENT_IS_SINGLE(hcbd1) ||
        DETECT_CONTENT_IS_SINGLE(hcbd2)) {
        goto end;
    }

    result = 1;

 end:
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectHttpClientBodyTest24(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert icmp any any -> any any "
                               "(content:\"one\"; http_client_body; pcre:/two/; "
                               "content:\"three\"; distance:10; within:15; http_client_body; content:\"four\"; sid:1;)");
    if (de_ctx->sig_list == NULL) {
        printf("de_ctx->sig_list == NULL\n");
        goto end;
    }

    if (de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH] == NULL) {
        printf("de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH] == NULL\n");
        goto end;
    }

    if (de_ctx->sig_list->sm_lists[g_http_client_body_buffer_id] == NULL) {
        printf("de_ctx->sig_list->sm_lists[g_http_client_body_buffer_id] == NULL\n");
        goto end;
    }

    DetectPcreData *pd1 = (DetectPcreData *)de_ctx->sig_list->sm_lists_tail[DETECT_SM_LIST_PMATCH]->prev->ctx;
    DetectContentData *cd2 = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[DETECT_SM_LIST_PMATCH]->ctx;
    DetectContentData *hcbd1 = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_http_client_body_buffer_id]->prev->ctx;
    DetectContentData *hcbd2 = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_http_client_body_buffer_id]->ctx;
    if (pd1->flags != 0 ||
        cd2->flags != 0 || memcmp(cd2->content, "four", cd2->content_len) != 0 ||
        hcbd1->flags != DETECT_CONTENT_RELATIVE_NEXT ||
        memcmp(hcbd1->content, "one", hcbd1->content_len) != 0 ||
        hcbd2->flags != (DETECT_CONTENT_DISTANCE | DETECT_CONTENT_WITHIN) ||
        memcmp(hcbd2->content, "three", hcbd1->content_len) != 0) {
        goto end;
    }

    if (!DETECT_CONTENT_IS_SINGLE(cd2) ||
        DETECT_CONTENT_IS_SINGLE(hcbd1) ||
        DETECT_CONTENT_IS_SINGLE(hcbd2)) {
        goto end;
    }

    result = 1;

 end:
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectHttpClientBodyTest25(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert icmp any any -> any any "
                               "(content:\"one\"; http_client_body; pcre:/two/; "
                               "content:\"three\"; distance:10; http_client_body; "
                               "content:\"four\"; distance:10; sid:1;)");
    if (de_ctx->sig_list == NULL) {
        printf("de_ctx->sig_list == NULL\n");
        goto end;
    }

    if (de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH] == NULL) {
        printf("de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH] == NULL\n");
        goto end;
    }

    if (de_ctx->sig_list->sm_lists[g_http_client_body_buffer_id] == NULL) {
        printf("de_ctx->sig_list->sm_lists[g_http_client_body_buffer_id] == NULL\n");
        goto end;
    }

    DetectPcreData *pd1 = (DetectPcreData *)de_ctx->sig_list->sm_lists_tail[DETECT_SM_LIST_PMATCH]->prev->ctx;
    DetectContentData *cd2 = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[DETECT_SM_LIST_PMATCH]->ctx;
    DetectContentData *hcbd1 = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_http_client_body_buffer_id]->prev->ctx;
    DetectContentData *hcbd2 = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_http_client_body_buffer_id]->ctx;
    if (pd1->flags != DETECT_PCRE_RELATIVE_NEXT ||
        cd2->flags != DETECT_CONTENT_DISTANCE ||
        memcmp(cd2->content, "four", cd2->content_len) != 0 ||
        hcbd1->flags != DETECT_CONTENT_RELATIVE_NEXT ||
        memcmp(hcbd1->content, "one", hcbd1->content_len) != 0 ||
        hcbd2->flags != DETECT_CONTENT_DISTANCE ||
        memcmp(hcbd2->content, "three", hcbd1->content_len) != 0) {
        goto end;
    }

    if (DETECT_CONTENT_IS_SINGLE(cd2) ||
        DETECT_CONTENT_IS_SINGLE(hcbd1) ||
        DETECT_CONTENT_IS_SINGLE(hcbd2)) {
        goto end;
    }

    result = 1;

 end:
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectHttpClientBodyTest26(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert icmp any any -> any any "
                               "(content:\"one\"; offset:10; http_client_body; pcre:/two/; "
                               "content:\"three\"; distance:10; http_client_body; within:10; "
                               "content:\"four\"; distance:10; sid:1;)");
    if (de_ctx->sig_list == NULL) {
        printf("de_ctx->sig_list == NULL\n");
        goto end;
    }

    if (de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH] == NULL) {
        printf("de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH] == NULL\n");
        goto end;
    }

    if (de_ctx->sig_list->sm_lists[g_http_client_body_buffer_id] == NULL) {
        printf("de_ctx->sig_list->sm_lists[g_http_client_body_buffer_id] == NULL\n");
        goto end;
    }

    DetectPcreData *pd1 = (DetectPcreData *)de_ctx->sig_list->sm_lists_tail[DETECT_SM_LIST_PMATCH]->prev->ctx;
    DetectContentData *cd2 = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[DETECT_SM_LIST_PMATCH]->ctx;
    DetectContentData *hcbd1 = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_http_client_body_buffer_id]->prev->ctx;
    DetectContentData *hcbd2 = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_http_client_body_buffer_id]->ctx;
    if (pd1->flags != (DETECT_PCRE_RELATIVE_NEXT) ||
        cd2->flags != DETECT_CONTENT_DISTANCE ||
        memcmp(cd2->content, "four", cd2->content_len) != 0 ||
        hcbd1->flags != (DETECT_CONTENT_RELATIVE_NEXT | DETECT_CONTENT_OFFSET) ||
        memcmp(hcbd1->content, "one", hcbd1->content_len) != 0 ||
        hcbd2->flags != (DETECT_CONTENT_DISTANCE | DETECT_CONTENT_WITHIN) ||
        memcmp(hcbd2->content, "three", hcbd1->content_len) != 0) {
        printf ("failed: http_client_body incorrect flags");
        goto end;
    }

    if (DETECT_CONTENT_IS_SINGLE(cd2) ||
        DETECT_CONTENT_IS_SINGLE(hcbd1) ||
        DETECT_CONTENT_IS_SINGLE(hcbd2)) {
        goto end;
    }

    result = 1;

 end:
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectHttpClientBodyTest27(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert icmp any any -> any any "
                               "(content:\"one\"; offset:10; http_client_body; pcre:/two/; "
                               "content:\"three\"; distance:10; http_client_body; within:10; "
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

static int DetectHttpClientBodyTest28(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert icmp any any -> any any "
                               "(content:\"one\"; http_client_body; pcre:/two/; "
                               "content:\"three\"; http_client_body; depth:10; "
                               "content:\"four\"; distance:10; sid:1;)");
    if (de_ctx->sig_list == NULL) {
        printf("de_ctx->sig_list == NULL\n");
        goto end;
    }

    if (de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH] == NULL) {
        printf("de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH] == NULL\n");
        goto end;
    }

    if (de_ctx->sig_list->sm_lists[g_http_client_body_buffer_id] == NULL) {
        printf("de_ctx->sig_list->sm_lists[g_http_client_body_buffer_id] == NULL\n");
        goto end;
    }

    DetectPcreData *pd1 = (DetectPcreData *)de_ctx->sig_list->sm_lists_tail[DETECT_SM_LIST_PMATCH]->prev->ctx;
    DetectContentData *cd2 = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[DETECT_SM_LIST_PMATCH]->ctx;
    DetectContentData *hcbd1 = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_http_client_body_buffer_id]->prev->ctx;
    DetectContentData *hcbd2 = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_http_client_body_buffer_id]->ctx;
    if (pd1->flags != (DETECT_PCRE_RELATIVE_NEXT) ||
        cd2->flags != DETECT_CONTENT_DISTANCE ||
        memcmp(cd2->content, "four", cd2->content_len) != 0 ||
        hcbd1->flags != 0 ||
        memcmp(hcbd1->content, "one", hcbd1->content_len) != 0 ||
        hcbd2->flags != DETECT_CONTENT_DEPTH ||
        memcmp(hcbd2->content, "three", hcbd1->content_len) != 0) {
        goto end;
    }

    if (DETECT_CONTENT_IS_SINGLE(cd2) ||
        !DETECT_CONTENT_IS_SINGLE(hcbd1) ||
        DETECT_CONTENT_IS_SINGLE(hcbd2)) {
        goto end;
    }

    result = 1;

 end:
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectHttpClientBodyTest29(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert icmp any any -> any any "
                               "(content:\"one\"; http_client_body; "
                               "content:\"two\"; distance:0; http_client_body; sid:1;)");
    if (de_ctx->sig_list == NULL) {
        printf("de_ctx->sig_list == NULL\n");
        goto end;
    }

    if (de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH] != NULL) {
        printf("de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH] != NULL\n");
        goto end;
    }

    if (de_ctx->sig_list->sm_lists[g_http_client_body_buffer_id] == NULL) {
        printf("de_ctx->sig_list->sm_lists[g_http_client_body_buffer_id] == NULL\n");
        goto end;
    }

    DetectContentData *hcbd1 = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_http_client_body_buffer_id]->prev->ctx;
    DetectContentData *hcbd2 = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_http_client_body_buffer_id]->ctx;
    if (hcbd1->flags != DETECT_CONTENT_RELATIVE_NEXT ||
        memcmp(hcbd1->content, "one", hcbd1->content_len) != 0 ||
        hcbd2->flags != DETECT_CONTENT_DISTANCE ||
        memcmp(hcbd2->content, "two", hcbd1->content_len) != 0) {
        goto end;
    }

    result = 1;

 end:
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectHttpClientBodyTest30(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert icmp any any -> any any "
                               "(content:\"one\"; http_client_body; "
                               "content:\"two\"; within:5; http_client_body; sid:1;)");
    if (de_ctx->sig_list == NULL) {
        printf("de_ctx->sig_list == NULL\n");
        goto end;
    }

    if (de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH] != NULL) {
        printf("de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH] != NULL\n");
        goto end;
    }

    if (de_ctx->sig_list->sm_lists[g_http_client_body_buffer_id] == NULL) {
        printf("de_ctx->sig_list->sm_lists[g_http_client_body_buffer_id] == NULL\n");
        goto end;
    }

    DetectContentData *hcbd1 = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_http_client_body_buffer_id]->prev->ctx;
    DetectContentData *hcbd2 = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_http_client_body_buffer_id]->ctx;
    if (hcbd1->flags != DETECT_CONTENT_RELATIVE_NEXT ||
        memcmp(hcbd1->content, "one", hcbd1->content_len) != 0 ||
        hcbd2->flags != DETECT_CONTENT_WITHIN ||
        memcmp(hcbd2->content, "two", hcbd1->content_len) != 0) {
        goto end;
    }

    result = 1;

 end:
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectHttpClientBodyTest31(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert icmp any any -> any any "
                               "(content:\"one\"; within:5; http_client_body; sid:1;)");
    if (de_ctx->sig_list == NULL) {
        printf("de_ctx->sig_list == NULL\n");
        goto end;
    }

    result = 1;

 end:
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectHttpClientBodyTest32(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert icmp any any -> any any "
                               "(content:\"one\"; http_client_body; within:5; sid:1;)");
    if (de_ctx->sig_list == NULL) {
        printf("de_ctx->sig_list != NULL\n");
        goto end;
    }

    result = 1;

 end:
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectHttpClientBodyTest33(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert icmp any any -> any any "
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

static int DetectHttpClientBodyTest34(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert icmp any any -> any any "
                               "(pcre:/one/P; "
                               "content:\"two\"; within:5; http_client_body; sid:1;)");
    if (de_ctx->sig_list == NULL) {
        printf("de_ctx->sig_list == NULL\n");
        goto end;
    }

    if (de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH] != NULL) {
        printf("de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH] != NULL\n");
        goto end;
    }

    if (de_ctx->sig_list->sm_lists[g_http_client_body_buffer_id] == NULL) {
        printf("de_ctx->sig_list->sm_lists[g_http_client_body_buffer_id] == NULL\n");
        goto end;
    }

    if (de_ctx->sig_list->sm_lists_tail[g_http_client_body_buffer_id] == NULL ||
        de_ctx->sig_list->sm_lists_tail[g_http_client_body_buffer_id]->type != DETECT_CONTENT ||
        de_ctx->sig_list->sm_lists_tail[g_http_client_body_buffer_id]->prev == NULL ||
        de_ctx->sig_list->sm_lists_tail[g_http_client_body_buffer_id]->prev->type != DETECT_PCRE) {

        goto end;
    }

    DetectPcreData *pd1 = (DetectPcreData *)de_ctx->sig_list->sm_lists_tail[g_http_client_body_buffer_id]->prev->ctx;
    DetectContentData *hcbd2 = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_http_client_body_buffer_id]->ctx;
    if (pd1->flags != (DETECT_PCRE_RELATIVE_NEXT) ||
        hcbd2->flags != DETECT_CONTENT_WITHIN ||
        memcmp(hcbd2->content, "two", hcbd2->content_len) != 0) {
        goto end;
    }

    result = 1;

 end:
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectHttpClientBodyTest35(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert icmp any any -> any any "
                               "(content:\"two\"; http_client_body; "
                               "pcre:/one/PR; sid:1;)");
    if (de_ctx->sig_list == NULL) {
        printf("de_ctx->sig_list == NULL\n");
        goto end;
    }

    if (de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH] != NULL) {
        printf("de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH] != NULL\n");
        goto end;
    }

    if (de_ctx->sig_list->sm_lists[g_http_client_body_buffer_id] == NULL) {
        printf("de_ctx->sig_list->sm_lists[g_http_client_body_buffer_id] == NULL\n");
        goto end;
    }

    if (de_ctx->sig_list->sm_lists_tail[g_http_client_body_buffer_id] == NULL ||
        de_ctx->sig_list->sm_lists_tail[g_http_client_body_buffer_id]->type != DETECT_PCRE ||
        de_ctx->sig_list->sm_lists_tail[g_http_client_body_buffer_id]->prev == NULL ||
        de_ctx->sig_list->sm_lists_tail[g_http_client_body_buffer_id]->prev->type != DETECT_CONTENT) {

        goto end;
    }

    DetectContentData *hcbd1 = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_http_client_body_buffer_id]->prev->ctx;
    DetectPcreData *pd2 = (DetectPcreData *)de_ctx->sig_list->sm_lists_tail[g_http_client_body_buffer_id]->ctx;
    if (pd2->flags != (DETECT_PCRE_RELATIVE) ||
        hcbd1->flags != DETECT_CONTENT_RELATIVE_NEXT ||
        memcmp(hcbd1->content, "two", hcbd1->content_len) != 0) {
        goto end;
    }

    result = 1;

 end:
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectHttpClientBodyTest36(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert icmp any any -> any any "
                               "(pcre:/one/P; "
                               "content:\"two\"; distance:5; http_client_body; sid:1;)");
    if (de_ctx->sig_list == NULL) {
        printf("de_ctx->sig_list == NULL\n");
        goto end;
    }

    if (de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH] != NULL) {
        printf("de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH] != NULL\n");
        goto end;
    }

    if (de_ctx->sig_list->sm_lists[g_http_client_body_buffer_id] == NULL) {
        printf("de_ctx->sig_list->sm_lists[g_http_client_body_buffer_id] == NULL\n");
        goto end;
    }

    if (de_ctx->sig_list->sm_lists_tail[g_http_client_body_buffer_id] == NULL ||
        de_ctx->sig_list->sm_lists_tail[g_http_client_body_buffer_id]->type != DETECT_CONTENT ||
        de_ctx->sig_list->sm_lists_tail[g_http_client_body_buffer_id]->prev == NULL ||
        de_ctx->sig_list->sm_lists_tail[g_http_client_body_buffer_id]->prev->type != DETECT_PCRE) {

        goto end;
    }

    DetectPcreData *pd1 = (DetectPcreData *)de_ctx->sig_list->sm_lists_tail[g_http_client_body_buffer_id]->prev->ctx;
    DetectContentData *hcbd2 = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_http_client_body_buffer_id]->ctx;
    if (pd1->flags != (DETECT_PCRE_RELATIVE_NEXT) ||
        hcbd2->flags != DETECT_CONTENT_DISTANCE ||
        memcmp(hcbd2->content, "two", hcbd2->content_len) != 0) {
        goto end;
    }

    result = 1;

 end:
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectHttpClientBodyIsdataatParseTest(void)
{
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    de_ctx->flags |= DE_QUIET;

    Signature *s = DetectEngineAppendSig(de_ctx,
            "alert tcp any any -> any any ("
            "content:\"one\"; http_client_body; "
            "isdataat:!4,relative; sid:1;)");
    FAIL_IF_NULL(s);

    SigMatch *sm = s->init_data->smlists_tail[g_http_client_body_buffer_id];
    FAIL_IF_NULL(sm);
    FAIL_IF_NOT(sm->type == DETECT_ISDATAAT);

    DetectIsdataatData *data = (DetectIsdataatData *)sm->ctx;
    FAIL_IF_NOT(data->flags & ISDATAAT_RELATIVE);
    FAIL_IF_NOT(data->flags & ISDATAAT_NEGATED);
    FAIL_IF(data->flags & ISDATAAT_RAWBYTES);

    DetectEngineCtxFree(de_ctx);
    PASS;
}

void DetectHttpClientBodyRegisterTests(void)
{
    UtRegisterTest("DetectHttpClientBodyParserTest01", DetectHttpClientBodyParserTest01);
    UtRegisterTest("DetectHttpClientBodyParserTest02", DetectHttpClientBodyParserTest02);
    UtRegisterTest("DetectHttpClientBodyTest01", DetectHttpClientBodyTest01);
    UtRegisterTest("DetectHttpClientBodyTest02", DetectHttpClientBodyTest02);
    UtRegisterTest("DetectHttpClientBodyTest03", DetectHttpClientBodyTest03);
    UtRegisterTest("DetectHttpClientBodyTest04", DetectHttpClientBodyTest04);
    UtRegisterTest("DetectHttpClientBodyTest05", DetectHttpClientBodyTest05);
    UtRegisterTest("DetectHttpClientBodyTest06", DetectHttpClientBodyTest06);
    UtRegisterTest("DetectHttpClientBodyTest07", DetectHttpClientBodyTest07);
    UtRegisterTest("DetectHttpClientBodyTest08", DetectHttpClientBodyTest08);
    UtRegisterTest("DetectHttpClientBodyTest09", DetectHttpClientBodyTest09);
    UtRegisterTest("DetectHttpClientBodyTest10", DetectHttpClientBodyTest10);
    UtRegisterTest("DetectHttpClientBodyTest11", DetectHttpClientBodyTest11);
    UtRegisterTest("DetectHttpClientBodyTest12", DetectHttpClientBodyTest12);
    UtRegisterTest("DetectHttpClientBodyTest13", DetectHttpClientBodyTest13);
    UtRegisterTest("DetectHttpClientBodyTest14", DetectHttpClientBodyTest14);
    UtRegisterTest("DetectHttpClientBodyTest15", DetectHttpClientBodyTest15);

    UtRegisterTest("DetectHttpClientBodyTest22", DetectHttpClientBodyTest22);
    UtRegisterTest("DetectHttpClientBodyTest23", DetectHttpClientBodyTest23);
    UtRegisterTest("DetectHttpClientBodyTest24", DetectHttpClientBodyTest24);
    UtRegisterTest("DetectHttpClientBodyTest25", DetectHttpClientBodyTest25);
    UtRegisterTest("DetectHttpClientBodyTest26", DetectHttpClientBodyTest26);
    UtRegisterTest("DetectHttpClientBodyTest27", DetectHttpClientBodyTest27);
    UtRegisterTest("DetectHttpClientBodyTest28", DetectHttpClientBodyTest28);
    UtRegisterTest("DetectHttpClientBodyTest29", DetectHttpClientBodyTest29);
    UtRegisterTest("DetectHttpClientBodyTest30", DetectHttpClientBodyTest30);
    UtRegisterTest("DetectHttpClientBodyTest31", DetectHttpClientBodyTest31);
    UtRegisterTest("DetectHttpClientBodyTest32", DetectHttpClientBodyTest32);
    UtRegisterTest("DetectHttpClientBodyTest33", DetectHttpClientBodyTest33);
    UtRegisterTest("DetectHttpClientBodyTest34", DetectHttpClientBodyTest34);
    UtRegisterTest("DetectHttpClientBodyTest35", DetectHttpClientBodyTest35);
    UtRegisterTest("DetectHttpClientBodyTest36", DetectHttpClientBodyTest36);

    UtRegisterTest("DetectHttpClientBodyIsdataatParseTest",
            DetectHttpClientBodyIsdataatParseTest);

    UtRegisterTest("DetectEngineHttpClientBodyTest01",
                   DetectEngineHttpClientBodyTest01);
    UtRegisterTest("DetectEngineHttpClientBodyTest02",
                   DetectEngineHttpClientBodyTest02);
    UtRegisterTest("DetectEngineHttpClientBodyTest03",
                   DetectEngineHttpClientBodyTest03);
    UtRegisterTest("DetectEngineHttpClientBodyTest04",
                   DetectEngineHttpClientBodyTest04);
    UtRegisterTest("DetectEngineHttpClientBodyTest05",
                   DetectEngineHttpClientBodyTest05);
    UtRegisterTest("DetectEngineHttpClientBodyTest06",
                   DetectEngineHttpClientBodyTest06);
    UtRegisterTest("DetectEngineHttpClientBodyTest07",
                   DetectEngineHttpClientBodyTest07);
    UtRegisterTest("DetectEngineHttpClientBodyTest08",
                   DetectEngineHttpClientBodyTest08);
    UtRegisterTest("DetectEngineHttpClientBodyTest09",
                   DetectEngineHttpClientBodyTest09);
    UtRegisterTest("DetectEngineHttpClientBodyTest10",
                   DetectEngineHttpClientBodyTest10);
    UtRegisterTest("DetectEngineHttpClientBodyTest11",
                   DetectEngineHttpClientBodyTest11);
    UtRegisterTest("DetectEngineHttpClientBodyTest12",
                   DetectEngineHttpClientBodyTest12);
    UtRegisterTest("DetectEngineHttpClientBodyTest13",
                   DetectEngineHttpClientBodyTest13);
    UtRegisterTest("DetectEngineHttpClientBodyTest14",
                   DetectEngineHttpClientBodyTest14);
    UtRegisterTest("DetectEngineHttpClientBodyTest15",
                   DetectEngineHttpClientBodyTest15);
    UtRegisterTest("DetectEngineHttpClientBodyTest16",
                   DetectEngineHttpClientBodyTest16);
    UtRegisterTest("DetectEngineHttpClientBodyTest17",
                   DetectEngineHttpClientBodyTest17);
    UtRegisterTest("DetectEngineHttpClientBodyTest18",
                   DetectEngineHttpClientBodyTest18);
    UtRegisterTest("DetectEngineHttpClientBodyTest19",
                   DetectEngineHttpClientBodyTest19);
    UtRegisterTest("DetectEngineHttpClientBodyTest20",
                   DetectEngineHttpClientBodyTest20);
    UtRegisterTest("DetectEngineHttpClientBodyTest21",
                   DetectEngineHttpClientBodyTest21);
    UtRegisterTest("DetectEngineHttpClientBodyTest22",
                   DetectEngineHttpClientBodyTest22);
    UtRegisterTest("DetectEngineHttpClientBodyTest23",
                   DetectEngineHttpClientBodyTest23);
    UtRegisterTest("DetectEngineHttpClientBodyTest24",
                   DetectEngineHttpClientBodyTest24);
    UtRegisterTest("DetectEngineHttpClientBodyTest25",
                   DetectEngineHttpClientBodyTest25);
    UtRegisterTest("DetectEngineHttpClientBodyTest26",
                   DetectEngineHttpClientBodyTest26);
    UtRegisterTest("DetectEngineHttpClientBodyTest27",
                   DetectEngineHttpClientBodyTest27);
    UtRegisterTest("DetectEngineHttpClientBodyTest28",
                   DetectEngineHttpClientBodyTest28);
    UtRegisterTest("DetectEngineHttpClientBodyTest29",
                   DetectEngineHttpClientBodyTest29);

    UtRegisterTest("DetectEngineHttpClientBodyTest30",
                   DetectEngineHttpClientBodyTest30);
    UtRegisterTest("DetectEngineHttpClientBodyTest31",
                   DetectEngineHttpClientBodyTest31);
}

#endif

/**
 * @}
 */
