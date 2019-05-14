/* Copyright (C) 2007-2019 Open Information Security Foundation
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
 * \file
 *
 * \author Victor Julien <victor@inliniac.net>
 *
 */

/**
 * \test DetectTlsVersionTestParse01 is a test to make sure that we parse the "id"
 *       option correctly when given valid id option
 */
static int DetectTlsVersionTestParse01 (void)
{
    DetectTlsVersionData *tls = NULL;
    tls = DetectTlsVersionParse("1.0");
    FAIL_IF_NULL(tls);
    FAIL_IF_NOT(tls->ver == TLS_VERSION_10);
    DetectTlsVersionFree(tls);
    PASS;
}

/**
 * \test DetectTlsVersionTestParse02 is a test to make sure that we parse the "id"
 *       option correctly when given an invalid id option
 *       it should return id_d = NULL
 */
static int DetectTlsVersionTestParse02 (void)
{
    DetectTlsVersionData *tls = NULL;
    tls = DetectTlsVersionParse("2.5");
    FAIL_IF_NOT_NULL(tls);
    DetectTlsVersionFree(tls);
    PASS;
}

#include "stream-tcp-reassemble.h"

/** \test Send a get request in three chunks + more data. */
static int DetectTlsVersionTestDetect01(void)
{
    Flow f;
    uint8_t tlsbuf1[] = { 0x16 };
    uint32_t tlslen1 = sizeof(tlsbuf1);
    uint8_t tlsbuf2[] = { 0x03 };
    uint32_t tlslen2 = sizeof(tlsbuf2);
    uint8_t tlsbuf3[] = { 0x01 };
    uint32_t tlslen3 = sizeof(tlsbuf3);
    uint8_t tlsbuf4[] = { 0x01, 0x00, 0x00, 0xad, 0x03, 0x01 };
    uint32_t tlslen4 = sizeof(tlsbuf4);
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
    p->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    f.alproto = ALPROTO_TLS;

    StreamTcpInitConfig(TRUE);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);

    de_ctx->flags |= DE_QUIET;

    s = de_ctx->sig_list = SigInit(de_ctx,"alert tls any any -> any any (msg:\"TLS\"; tls.version:1.0; sid:1;)");
    FAIL_IF_NULL(s);

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_TLS,
                                STREAM_TOSERVER, tlsbuf1, tlslen1);
    FAIL_IF(r != 0);

    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_TLS, STREAM_TOSERVER,
                            tlsbuf2, tlslen2);
    FAIL_IF(r != 0);

    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_TLS, STREAM_TOSERVER,
                            tlsbuf3, tlslen3);
    FAIL_IF(r != 0);

    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_TLS, STREAM_TOSERVER,
                            tlsbuf4, tlslen4);
    FAIL_IF(r != 0);

    SSLState *ssl_state = f.alstate;
    FAIL_IF_NULL(ssl_state);

    FAIL_IF(ssl_state->client_connp.content_type != 0x16);

    FAIL_IF(ssl_state->client_connp.version != TLS_VERSION_10);

    SCLogDebug("ssl_state is at %p, ssl_state->server_version 0x%02X "
               "ssl_state->client_version 0x%02X",
               ssl_state, ssl_state->server_connp.version,
               ssl_state->client_connp.version);

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);

    FAIL_IF_NOT(PacketAlertCheck(p, 1));

    AppLayerParserThreadCtxFree(alp_tctx);
    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);

    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);

    StreamTcpFreeConfig(TRUE);
    FLOW_DESTROY(&f);

    UTHFreePackets(&p, 1);

    PASS;
}

static int DetectTlsVersionTestDetect02(void)
{
    Flow f;
    uint8_t tlsbuf1[] = { 0x16 };
    uint32_t tlslen1 = sizeof(tlsbuf1);
    uint8_t tlsbuf2[] = { 0x03 };
    uint32_t tlslen2 = sizeof(tlsbuf2);
    uint8_t tlsbuf3[] = { 0x01 };
    uint32_t tlslen3 = sizeof(tlsbuf3);
    uint8_t tlsbuf4[] = { 0x01, 0x00, 0x00, 0xad, 0x03, 0x02 };
    uint32_t tlslen4 = sizeof(tlsbuf4);
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
    p->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    f.alproto = ALPROTO_TLS;

    StreamTcpInitConfig(TRUE);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);

    de_ctx->flags |= DE_QUIET;

    s = de_ctx->sig_list = SigInit(de_ctx,"alert tls any any -> any any (msg:\"TLS\"; tls.version:1.0; sid:1;)");
    FAIL_IF_NULL(s);

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_TLS,
                                STREAM_TOSERVER, tlsbuf1, tlslen1);
    FAIL_IF(r != 0);

    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_TLS, STREAM_TOSERVER,
                            tlsbuf2, tlslen2);
    FAIL_IF(r != 0);

    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_TLS, STREAM_TOSERVER,
                            tlsbuf3, tlslen3);
    FAIL_IF(r != 0);

    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_TLS, STREAM_TOSERVER,
                            tlsbuf4, tlslen4);
    FAIL_IF(r != 0);

    SSLState *ssl_state = f.alstate;
    FAIL_IF_NULL(ssl_state);

    FAIL_IF(ssl_state->client_connp.content_type != 0x16);

    FAIL_IF(ssl_state->client_connp.version != TLS_VERSION_10);

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);

    FAIL_IF_NOT(PacketAlertCheck(p, 1));

    AppLayerParserThreadCtxFree(alp_tctx);
    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);

    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);

    StreamTcpFreeConfig(TRUE);
    FLOW_DESTROY(&f);

    UTHFreePackets(&p, 1);

    PASS;
}

/**
 * \brief this function registers unit tests for DetectTlsVersion
 */
static void DetectTlsVersionRegisterTests(void)
{
    UtRegisterTest("DetectTlsVersionTestParse01", DetectTlsVersionTestParse01);
    UtRegisterTest("DetectTlsVersionTestParse02", DetectTlsVersionTestParse02);
    UtRegisterTest("DetectTlsVersionTestDetect01",
                   DetectTlsVersionTestDetect01);
    UtRegisterTest("DetectTlsVersionTestDetect02",
                   DetectTlsVersionTestDetect02);
}
