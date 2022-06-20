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
 * \author Mats Klepsland <mats.klepsland@gmail.com>
 *
 */

#include "detect-engine-build.h"
#include "app-layer-parser.h"

/**
 * \test Test matching on a simple google.com SNI
 */
static int DetectTlsSniTest01(void)
{
    /* client hello */
    uint8_t buf[] = { 0x16, 0x03, 0x03, 0x00, 0x84, 0x01, 0x00, 0x00, 0x7E,
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

    StreamTcpInitConfig(true);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);

    de_ctx->mpm_matcher = mpm_default_matcher;
    de_ctx->flags |= DE_QUIET;

    Signature *s = DetectEngineAppendSig(de_ctx, "alert tls any any -> any any "
                                    "(msg:\"Test tls.sni option\"; "
                                    "tls.sni; content:\"google.com\"; sid:1;)");
    FAIL_IF_NULL(s);

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&tv, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_TLS,
                                STREAM_TOSERVER, buf, sizeof(buf));
    FAIL_IF(r != 0);

    ssl_state = f.alstate;
    FAIL_IF_NULL(ssl_state);

    /* do detect */
    SigMatchSignatures(&tv, de_ctx, det_ctx, p);

    FAIL_IF_NOT(PacketAlertCheck(p, 1));

    AppLayerParserThreadCtxFree(alp_tctx);
    DetectEngineThreadCtxDeinit(&tv, det_ctx);
    DetectEngineCtxFree(de_ctx);

    StreamTcpFreeConfig(true);
    FLOW_DESTROY(&f);
    UTHFreePacket(p);

    PASS;
}

/**
 * \test Test matching on a simple google.com SNI with pcre
 */
static int DetectTlsSniTest02(void)
{
    /* client hello */
    uint8_t buf[] = { 0x16, 0x03, 0x03, 0x00, 0x84, 0x01, 0x00, 0x00, 0x7E,
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

    StreamTcpInitConfig(true);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);

    de_ctx->mpm_matcher = mpm_default_matcher;
    de_ctx->flags |= DE_QUIET;

    Signature *s = DetectEngineAppendSig(de_ctx, "alert tls any any -> any any "
                                        "(msg:\"Test tls.sni option\"; "
                                        "tls.sni; content:\"google\"; nocase; "
                                        "pcre:\"/google\\.com$/i\"; sid:1;)");
    FAIL_IF_NULL(s);

    s = DetectEngineAppendSig(de_ctx, "alert tls any any -> any any "
                              "(msg:\"Test tls.sni option\"; "
                              "tls.sni; content:\"google\"; nocase; "
                              "pcre:\"/^\\.[a-z]{2,3}$/iR\"; sid:2;)");
    FAIL_IF_NULL(s);

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&tv, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_TLS,
                                STREAM_TOSERVER, buf, sizeof(buf));
    FAIL_IF(r != 0);

    ssl_state = f.alstate;
    FAIL_IF_NULL(ssl_state);

    /* do detect */
    SigMatchSignatures(&tv, de_ctx, det_ctx, p);

    FAIL_IF_NOT(PacketAlertCheck(p, 1));
    FAIL_IF_NOT(PacketAlertCheck(p, 2));

    AppLayerParserThreadCtxFree(alp_tctx);
    DetectEngineThreadCtxDeinit(&tv, det_ctx);
    DetectEngineCtxFree(de_ctx);

    StreamTcpFreeConfig(true);
    FLOW_DESTROY(&f);
    UTHFreePacket(p);

    PASS;
}

static void DetectTlsSniRegisterTests(void)
{
    UtRegisterTest("DetectTlsSniTest01", DetectTlsSniTest01);
    UtRegisterTest("DetectTlsSniTest02", DetectTlsSniTest02);
}
