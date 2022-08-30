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
 * \file   detect-ssl-version.c
 *
 * \author Gurvinder Singh <gurvindersinghdahiya@gmail.com>
 *
 */

#include "detect-engine-build.h"

/**
 * \test DetectSslVersionTestParse01 is a test to make sure that we parse the
 *      "ssl_version" option correctly when given valid ssl_version option
 */
static int DetectSslVersionTestParse01(void)
{
    DetectSslVersionData *ssl = NULL;
    ssl = DetectSslVersionParse(NULL, "SSlv3");
    FAIL_IF_NULL(ssl);
    FAIL_IF_NOT(ssl->data[SSLv3].ver == SSL_VERSION_3);
    DetectSslVersionFree(NULL, ssl);
    PASS;
}

/**
 * \test DetectSslVersionTestParse02 is a test to make sure that we parse the
 *      "ssl_version" option correctly when given an invalid ssl_version option
 *       it should return ssl = NULL
 */
static int DetectSslVersionTestParse02(void)
{
    DetectSslVersionData *ssl = NULL;
    ssl = DetectSslVersionParse(NULL, "2.5");
    FAIL_IF_NOT_NULL(ssl);
    DetectSslVersionFree(NULL, ssl);
    ssl = DetectSslVersionParse(NULL, "tls1.0, !");
    FAIL_IF_NOT_NULL(ssl);
    DetectSslVersionFree(NULL, ssl);
    ssl = DetectSslVersionParse(NULL, "tls1.0, !tls1.0");
    FAIL_IF_NOT_NULL(ssl);
    DetectSslVersionFree(NULL, ssl);
    ssl = DetectSslVersionParse(NULL, "tls1.1, tls1.1");
    FAIL_IF_NOT_NULL(ssl);
    DetectSslVersionFree(NULL, ssl);
    ssl = DetectSslVersionParse(NULL, "tls1.1, !tls1.2");
    FAIL_IF_NOT_NULL(ssl);
    DetectSslVersionFree(NULL, ssl);
    PASS;
}

/**
 * \test DetectSslVersionTestParse03 is a test to make sure that we parse the
 *      "ssl_version" options correctly when given valid ssl_version options
 */
static int DetectSslVersionTestParse03(void)
{
    DetectSslVersionData *ssl = NULL;
    ssl = DetectSslVersionParse(NULL, "SSlv3 , tls1.0");
    FAIL_IF_NULL(ssl);
    FAIL_IF_NOT(ssl->data[SSLv3].ver == SSL_VERSION_3);
    FAIL_IF_NOT(ssl->data[TLS10].ver == TLS_VERSION_10);
    DetectSslVersionFree(NULL, ssl);
    ssl = DetectSslVersionParse(NULL, " !tls1.2");
    FAIL_IF_NULL(ssl);
    FAIL_IF_NOT(ssl->data[TLS12].ver == TLS_VERSION_12);
    FAIL_IF_NOT(ssl->data[TLS12].flags & DETECT_SSL_VERSION_NEGATED);
    DetectSslVersionFree(NULL, ssl);
    PASS;
}

#include "stream-tcp-reassemble.h"

/** \test Send a get request in three chunks + more data. */
static int DetectSslVersionTestDetect01(void)
{
    Flow f;
    uint8_t sslbuf1[] = { 0x16 };
    uint32_t ssllen1 = sizeof(sslbuf1);
    uint8_t sslbuf2[] = { 0x03 };
    uint32_t ssllen2 = sizeof(sslbuf2);
    uint8_t sslbuf3[] = { 0x01 };
    uint32_t ssllen3 = sizeof(sslbuf3);
    uint8_t sslbuf4[] = { 0x01, 0x00, 0x00, 0xad, 0x03, 0x01 };
    uint32_t ssllen4 = sizeof(sslbuf4);
    TcpSession ssn;
    Packet *p = NULL;
    Signature *s = NULL;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx = NULL;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&th_v, 0, sizeof(th_v));
    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    p = UTHBuildPacket(NULL, 0, IPPROTO_TCP);

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;
    p->flow = &f;
    p->flowflags |= FLOW_PKT_TOSERVER;
    p->flowflags |= FLOW_PKT_ESTABLISHED;
    p->flags |= PKT_HAS_FLOW | PKT_STREAM_EST;
    f.alproto = ALPROTO_TLS;

    StreamTcpInitConfig(true);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);

    de_ctx->flags |= DE_QUIET;

    s = de_ctx->sig_list = SigInit(de_ctx,"alert tls any any -> any any (msg:\"TLS\"; ssl_version:tls1.0; sid:1;)");
    FAIL_IF_NULL(s);

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_TLS,
                                STREAM_TOSERVER, sslbuf1, ssllen1);
    FAIL_IF(r != 0);

    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_TLS, STREAM_TOSERVER,
                            sslbuf2, ssllen2);
    FAIL_IF(r != 0);

    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_TLS, STREAM_TOSERVER,
                            sslbuf3, ssllen3);
    FAIL_IF(r != 0);

    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_TLS, STREAM_TOSERVER,
                            sslbuf4, ssllen4);
    FAIL_IF(r != 0);

    SSLState *app_state = f.alstate;
    FAIL_IF_NULL(app_state);

    FAIL_IF(app_state->client_connp.content_type != 0x16);

    FAIL_IF(app_state->client_connp.version != TLS_VERSION_10);

    SCLogDebug("app_state is at %p, app_state->server_connp.version 0x%02X app_state->client_connp.version 0x%02X",
        app_state, app_state->server_connp.version, app_state->client_connp.version);

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);

    FAIL_IF_NOT(PacketAlertCheck(p, 1));

    AppLayerParserThreadCtxFree(alp_tctx);
    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);

    StreamTcpFreeConfig(true);
    FLOW_DESTROY(&f);

    UTHFreePackets(&p, 1);

    PASS;
}

static int DetectSslVersionTestDetect02(void)
{
    Flow f;
    uint8_t sslbuf1[] = { 0x16 };
    uint32_t ssllen1 = sizeof(sslbuf1);
    uint8_t sslbuf2[] = { 0x03 };
    uint32_t ssllen2 = sizeof(sslbuf2);
    uint8_t sslbuf3[] = { 0x01 };
    uint32_t ssllen3 = sizeof(sslbuf3);
    uint8_t sslbuf4[] = { 0x01, 0x00, 0x00, 0xad, 0x03, 0x02 };
    uint32_t ssllen4 = sizeof(sslbuf4);
    TcpSession ssn;
    Packet *p = NULL;
    Signature *s = NULL;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx = NULL;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&th_v, 0, sizeof(th_v));
    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    p = UTHBuildPacket(NULL, 0, IPPROTO_TCP);

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;
    p->flow = &f;
    p->flowflags |= FLOW_PKT_TOSERVER;
    p->flowflags |= FLOW_PKT_ESTABLISHED;
    p->flags |= PKT_HAS_FLOW | PKT_STREAM_EST;
    f.alproto = ALPROTO_TLS;

    StreamTcpInitConfig(true);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);

    de_ctx->flags |= DE_QUIET;

    s = de_ctx->sig_list = SigInit(de_ctx,"alert tls any any -> any any (msg:\"TLS\"; ssl_version:tls1.0; sid:1;)");
    FAIL_IF_NULL(s);

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_TLS,
                                STREAM_TOSERVER, sslbuf1, ssllen1);
    FAIL_IF(r != 0);

    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_TLS, STREAM_TOSERVER,
                            sslbuf2, ssllen2);
    FAIL_IF(r != 0);

    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_TLS, STREAM_TOSERVER,
                            sslbuf3, ssllen3);
    FAIL_IF(r != 0);

    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_TLS, STREAM_TOSERVER,
                            sslbuf4, ssllen4);
    FAIL_IF(r != 0);

    SSLState *app_state = f.alstate;
    FAIL_IF_NULL(app_state);

    FAIL_IF(app_state->client_connp.content_type != 0x16);

    FAIL_IF(app_state->client_connp.version != TLS_VERSION_10);

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);

    FAIL_IF_NOT(PacketAlertCheck(p, 1));

    AppLayerParserThreadCtxFree(alp_tctx);
    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);
    StreamTcpFreeConfig(true);
    FLOW_DESTROY(&f);
    UTHFreePackets(&p, 1);

    PASS;
}

/**
 * \brief this function registers unit tests for DetectSslVersion
 */
static void DetectSslVersionRegisterTests(void)
{
    UtRegisterTest("DetectSslVersionTestParse01", DetectSslVersionTestParse01);
    UtRegisterTest("DetectSslVersionTestParse02", DetectSslVersionTestParse02);
    UtRegisterTest("DetectSslVersionTestParse03", DetectSslVersionTestParse03);
    UtRegisterTest("DetectSslVersionTestDetect01",
                   DetectSslVersionTestDetect01);
    UtRegisterTest("DetectSslVersionTestDetect02",
                   DetectSslVersionTestDetect02);
}
