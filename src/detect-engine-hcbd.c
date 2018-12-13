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
 * \brief Handle HTTP request body match corresponding to http_client_body
 * keyword.
 *
 */

#include "suricata-common.h"
#include "suricata.h"
#include "decode.h"

#include "detect.h"
#include "detect-engine.h"
#include "detect-engine-mpm.h"
#include "detect-parse.h"
#include "detect-engine-state.h"
#include "detect-engine-content-inspection.h"
#include "detect-engine-prefilter.h"
#include "detect-engine-hcbd.h"

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

/***********************************Unittests**********************************/

#ifdef UNITTESTS

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

    StreamTcpInitConfig(TRUE);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    de_ctx->flags |= DE_QUIET;

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;
    f.flags |= FLOW_IPV4;
    f.alproto = ALPROTO_HTTP;

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

        int r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_HTTP,
                                    b->direction, (uint8_t *)b->input,
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

    StreamTcpFreeConfig(TRUE);
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

#endif /* UNITTESTS */

void DetectEngineHttpClientBodyRegisterTests(void)
{

#ifdef UNITTESTS
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
#endif /* UNITTESTS */

    return;
}
/**
 * @}
 */
