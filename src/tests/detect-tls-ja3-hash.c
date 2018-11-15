/* Copyright (C) 2019 Open Information Security Foundation
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
 * \author Mats Klepsland <mats.klepsland@gmail.com>
 *
 */

#ifndef HAVE_NSS

static void DetectTlsJa3HashRegisterTests(void)
{
    /* Don't register any tests */
}

#else /* HAVE_NSS */

/**
 * \test Test matching on a simple client hello packet
 */
static int DetectTlsJa3HashTest01(void)
{
    /* Client hello */
    uint8_t buf[] = { 0x16, 0x03, 0x03, 0x00, 0x82, 0x01, 0x00, 0x00, 0x7E,
                      0x03, 0x03, 0x57, 0x04, 0x9F, 0x5D, 0xC9, 0x5C, 0x87,
                      0xAE, 0xF2, 0xA7, 0x4A, 0xFC, 0x59, 0x78, 0x23, 0x31,
                      0x61, 0x2D, 0x29, 0x92, 0xB6, 0x70, 0xA5, 0xA1, 0xFC,
                      0x0E, 0x79, 0xFE, 0xC3, 0x97, 0x37, 0xC0, 0x00, 0x00,
                      0x44, 0x00, 0x04, 0x00, 0x05, 0x00, 0x0A, 0x00, 0x0D,
                      0x00, 0x10, 0x00, 0x13, 0x00, 0x16, 0x00, 0x2F, 0x00,
                      0x30, 0x00, 0x31, 0x00, 0x32, 0x00, 0x33, 0x00, 0x35,
                      0x00, 0x36, 0x00, 0x37, 0x00, 0x38, 0x00, 0x39, 0x00,
                      0x3C, 0x00, 0x3D, 0x00, 0x3E, 0x00, 0x3F, 0x00, 0x40,
                      0x00, 0x41, 0x00, 0x44, 0x00, 0x45, 0x00, 0x66, 0x00,
                      0x67, 0x00, 0x68, 0x00, 0x69, 0x00, 0x6A, 0x00, 0x6B,
                      0x00, 0x84, 0x00, 0x87, 0x00, 0xFF, 0x01, 0x00, 0x00,
                      0x13, 0x00, 0x00, 0x00, 0x0F, 0x00, 0x0D, 0x00, 0x00,
                      0x0A, 0x67, 0x6F, 0x6F, 0x67, 0x6C, 0x65, 0x2E, 0x63,
                      0x6F, 0x6D, };


    Flow f;
    SSLState *ssl_state = NULL;
    Packet *p = NULL;
    ThreadVars tv;
    DetectEngineThreadCtx *det_ctx = NULL;
    TcpSession ssn;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&tv, 0, sizeof(ThreadVars));
    memset(&f, 0, sizeof(Flow));
    memset(&ssn, 0, sizeof(TcpSession));

    p = UTHBuildPacketReal(buf, sizeof(buf), IPPROTO_TCP,
                           "192.168.1.5", "192.168.1.1",
                           41424, 443);

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.flags |= FLOW_IPV4;
    f.proto = IPPROTO_TCP;
    f.protomap = FlowGetProtoMapping(f.proto);

    p->flow = &f;
    p->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    p->flowflags |= FLOW_PKT_TOSERVER|FLOW_PKT_ESTABLISHED;
    f.alproto = ALPROTO_TLS;

    StreamTcpInitConfig(TRUE);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);

    de_ctx->mpm_matcher = mpm_default_matcher;
    de_ctx->flags |= DE_QUIET;

    Signature *s = DetectEngineAppendSig(de_ctx, "alert tls any any -> any any "
                              "(msg:\"Test ja3.hash\"; ja3.hash; "
                              "content:\"e7eca2baf4458d095b7f45da28c16c34\"; "
                              "sid:1;)");
    FAIL_IF_NULL(s);

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&tv, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_TLS,
                                STREAM_TOSERVER, buf, sizeof(buf));
    FAIL_IF(r != 0);

    ssl_state = f.alstate;
    FAIL_IF_NULL(ssl_state);

    FAIL_IF_NULL(ssl_state->client_connp.ja3_hash);

    SigMatchSignatures(&tv, de_ctx, det_ctx, p);

    FAIL_IF_NOT(PacketAlertCheck(p, 1));

    AppLayerParserThreadCtxFree(alp_tctx);
    DetectEngineThreadCtxDeinit(&tv, det_ctx);
    DetectEngineCtxFree(de_ctx);

    StreamTcpFreeConfig(TRUE);
    FLOW_DESTROY(&f);
    UTHFreePacket(p);

    PASS;
}

/**
 * \test Test matching on a simple client hello packet
 */
static int DetectTlsJa3HashTest02(void)
{
    /* Client hello */
    uint8_t buf[] = { 0x16, 0x03, 0x01, 0x00, 0xc0, 0x01, 0x00, 0x00, 0xbc,
                      0x03, 0x03, 0x03, 0xb7, 0x16, 0x16, 0x5a, 0xe7, 0xc1,
                      0xbd, 0x46, 0x2f, 0xff, 0xf3, 0x68, 0xb8, 0x6f, 0x6e,
                      0x93, 0xdf, 0x06, 0x6a, 0xa7, 0x2d, 0xa0, 0xea, 0x9f,
                      0x48, 0xb5, 0xe7, 0x91, 0x20, 0xd7, 0x25, 0x00, 0x00,
                      0x1c, 0x0a, 0x0a, 0xc0, 0x2b, 0xc0, 0x2f, 0xc0, 0x2c,
                      0xc0, 0x30, 0xcc, 0xa9, 0xcc, 0xa8, 0xc0, 0x13, 0xc0,
                      0x14, 0x00, 0x9c, 0x00, 0x9d, 0x00, 0x2f, 0x00, 0x35,
                      0x00, 0x0a, 0x01, 0x00, 0x00, 0x77, 0x1a, 0x1a, 0x00,
                      0x00, 0xff, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
                      0x12, 0x00, 0x10, 0x00, 0x00, 0x0d, 0x77, 0x77, 0x77,
                      0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x6e,
                      0x6f, 0x00, 0x17, 0x00, 0x00, 0x00, 0x23, 0x00, 0x00,
                      0x00, 0x0d, 0x00, 0x14, 0x00, 0x12, 0x04, 0x03, 0x08,
                      0x04, 0x04, 0x01, 0x05, 0x03, 0x08, 0x05, 0x05, 0x01,
                      0x08, 0x06, 0x06, 0x01, 0x02, 0x01, 0x00, 0x05, 0x00,
                      0x05, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x12, 0x00,
                      0x00, 0x00, 0x10, 0x00, 0x0e, 0x00, 0x0c, 0x02, 0x68,
                      0x32, 0x08, 0x68, 0x74, 0x74, 0x70, 0x2f, 0x31, 0x2e,
                      0x31, 0x00, 0x0b, 0x00, 0x02, 0x01, 0x00, 0x00, 0x0a,
                      0x00, 0x0a, 0x00, 0x08, 0xba, 0xba, 0x00, 0x1d, 0x00,
                      0x17, 0x00, 0x18, 0x0a, 0x0a, 0x00, 0x01, 0x00 };

    Flow f;
    SSLState *ssl_state = NULL;
    ThreadVars tv;
    DetectEngineThreadCtx *det_ctx = NULL;
    TcpSession ssn;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&tv, 0, sizeof(ThreadVars));
    memset(&f, 0, sizeof(Flow));
    memset(&ssn, 0, sizeof(TcpSession));

    Packet *p = UTHBuildPacketReal(buf, sizeof(buf), IPPROTO_TCP,
                                   "192.168.1.5", "192.168.1.1",
                                   41424, 443);

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.flags |= FLOW_IPV4;
    f.proto = IPPROTO_TCP;
    f.protomap = FlowGetProtoMapping(f.proto);

    p->flow = &f;
    p->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    p->flowflags |= FLOW_PKT_TOSERVER|FLOW_PKT_ESTABLISHED;
    f.alproto = ALPROTO_TLS;

    StreamTcpInitConfig(TRUE);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);

    de_ctx->mpm_matcher = mpm_default_matcher;
    de_ctx->flags |= DE_QUIET;

    Signature *s = DetectEngineAppendSig(de_ctx, "alert tls any any -> any any "
                              "(msg:\"Test ja3.hash\"; ja3.hash; "
                              "content:\"bc6c386f480ee97b9d9e52d472b772d8\"; "
                              "sid:1;)");
    FAIL_IF_NULL(s);

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&tv, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_TLS,
                                STREAM_TOSERVER, buf, sizeof(buf));
    FAIL_IF(r != 0);

    ssl_state = f.alstate;
    FAIL_IF_NULL(ssl_state);

    FAIL_IF_NULL(ssl_state->client_connp.ja3_hash);

    SigMatchSignatures(&tv, de_ctx, det_ctx, p);

    FAIL_IF_NOT(PacketAlertCheck(p, 1));

    AppLayerParserThreadCtxFree(alp_tctx);
    DetectEngineThreadCtxDeinit(&tv, det_ctx);
    DetectEngineCtxFree(de_ctx);

    StreamTcpFreeConfig(TRUE);
    FLOW_DESTROY(&f);
    UTHFreePacket(p);

    PASS;
}

static void DetectTlsJa3HashRegisterTests(void)
{
    UtRegisterTest("DetectTlsJa3HashTest01", DetectTlsJa3HashTest01);
    UtRegisterTest("DetectTlsJa3HashTest02", DetectTlsJa3HashTest02);
}

#endif /* HAVE_NSS */
