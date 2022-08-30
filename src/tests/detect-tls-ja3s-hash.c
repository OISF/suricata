/* Copyright (C) 2022 Open Information Security Foundation
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
 * \test Test matching on a JA3S hash from a ServerHello record
 */
static int DetectTlsJa3SHashTest01(void)
{
    /* client hello */
    uint8_t client_hello[] = {
            0x16, 0x03, 0x01, 0x00, 0xc8, 0x01, 0x00, 0x00,
            0xc4, 0x03, 0x03, 0xd6, 0x08, 0x5a, 0xa2, 0x86,
            0x5b, 0x85, 0xd4, 0x40, 0xab, 0xbe, 0xc0, 0xbc,
            0x41, 0xf2, 0x26, 0xf0, 0xfe, 0x21, 0xee, 0x8b,
            0x4c, 0x7e, 0x07, 0xc8, 0xec, 0xd2, 0x00, 0x46,
            0x4c, 0xeb, 0xb7, 0x00, 0x00, 0x16, 0xc0, 0x2b,
            0xc0, 0x2f, 0xc0, 0x0a, 0xc0, 0x09, 0xc0, 0x13,
            0xc0, 0x14, 0x00, 0x33, 0x00, 0x39, 0x00, 0x2f,
            0x00, 0x35, 0x00, 0x0a, 0x01, 0x00, 0x00, 0x85,
            0x00, 0x00, 0x00, 0x12, 0x00, 0x10, 0x00, 0x00,
            0x0d, 0x77, 0x77, 0x77, 0x2e, 0x67, 0x6f, 0x6f,
            0x67, 0x6c, 0x65, 0x2e, 0x6e, 0x6f, 0xff, 0x01,
            0x00, 0x01, 0x00, 0x00, 0x0a, 0x00, 0x08, 0x00,
            0x06, 0x00, 0x17, 0x00, 0x18, 0x00, 0x19, 0x00,
            0x0b, 0x00, 0x02, 0x01, 0x00, 0x00, 0x23, 0x00,
            0x00, 0x33, 0x74, 0x00, 0x00, 0x00, 0x10, 0x00,
            0x29, 0x00, 0x27, 0x05, 0x68, 0x32, 0x2d, 0x31,
            0x36, 0x05, 0x68, 0x32, 0x2d, 0x31, 0x35, 0x05,
            0x68, 0x32, 0x2d, 0x31, 0x34, 0x02, 0x68, 0x32,
            0x08, 0x73, 0x70, 0x64, 0x79, 0x2f, 0x33, 0x2e,
            0x31, 0x08, 0x68, 0x74, 0x74, 0x70, 0x2f, 0x31,
            0x2e, 0x31, 0x00, 0x05, 0x00, 0x05, 0x01, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x0d, 0x00, 0x16, 0x00,
            0x14, 0x04, 0x01, 0x05, 0x01, 0x06, 0x01, 0x02,
            0x01, 0x04, 0x03, 0x05, 0x03, 0x06, 0x03, 0x02,
            0x03, 0x04, 0x02, 0x02, 0x02
    };

    /* server hello */
    uint8_t server_hello[] = {
            0x16, 0x03, 0x03, 0x00, 0x48, 0x02, 0x00, 0x00,
            0x44, 0x03, 0x03, 0x57, 0x91, 0xb8, 0x63, 0xdd,
            0xdb, 0xbb, 0x23, 0xcf, 0x0b, 0x43, 0x02, 0x1d,
            0x46, 0x11, 0x27, 0x5c, 0x98, 0xcf, 0x67, 0xe1,
            0x94, 0x3d, 0x62, 0x7d, 0x38, 0x48, 0x21, 0x23,
            0xa5, 0x62, 0x31, 0x00, 0xc0, 0x2f, 0x00, 0x00,
            0x1c, 0xff, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x23, 0x00, 0x00, 0x00, 0x10,
            0x00, 0x05, 0x00, 0x03, 0x02, 0x68, 0x32, 0x00,
            0x0b, 0x00, 0x02, 0x01, 0x00
    };

    Flow f;
    SSLState *ssl_state = NULL;
    TcpSession ssn;
    Packet *p1 = NULL;
    Packet *p2 = NULL;
    ThreadVars tv;
    DetectEngineThreadCtx *det_ctx = NULL;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&tv, 0, sizeof(ThreadVars));
    memset(&f, 0, sizeof(Flow));
    memset(&ssn, 0, sizeof(TcpSession));

    p1 = UTHBuildPacketReal(client_hello, sizeof(client_hello), IPPROTO_TCP,
                            "192.168.1.5", "192.168.1.1", 51251, 443);
    p2 = UTHBuildPacketReal(server_hello, sizeof(server_hello), IPPROTO_TCP,
                            "192.168.1.1", "192.168.1.5", 443, 51251);

    FLOW_INITIALIZE(&f);
    f.flags |= FLOW_IPV4;
    f.proto = IPPROTO_TCP;
    f.protomap = FlowGetProtoMapping(f.proto);
    f.alproto = ALPROTO_TLS;

    p1->flow = &f;
    p1->flags |= PKT_HAS_FLOW | PKT_STREAM_EST;
    p1->flowflags |= FLOW_PKT_TOSERVER;
    p1->flowflags |= FLOW_PKT_ESTABLISHED;
    p1->pcap_cnt = 1;

    p2->flow = &f;
    p2->flags |= PKT_HAS_FLOW | PKT_STREAM_EST;
    p2->flowflags |= FLOW_PKT_TOCLIENT;
    p2->flowflags |= FLOW_PKT_ESTABLISHED;
    p2->pcap_cnt = 2;

    StreamTcpInitConfig(true);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);

    de_ctx->mpm_matcher = mpm_default_matcher;
    de_ctx->flags |= DE_QUIET;

    Signature *s = DetectEngineAppendSig(de_ctx, "alert tls any any -> any any "
                                "(msg:\"Test ja3s.hash\"; "
                                "ja3s.hash; "
                                "content:\"8217013c502e3461d19c75bb02a12aaf\"; "
                                "sid:1;)");
    FAIL_IF_NULL(s);

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&tv, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_TLS,
                                STREAM_TOSERVER, client_hello,
                                sizeof(client_hello));

    FAIL_IF(r != 0);

    ssl_state = f.alstate;
    FAIL_IF_NULL(ssl_state);

    SigMatchSignatures(&tv, de_ctx, det_ctx, p1);

    FAIL_IF(PacketAlertCheck(p1, 1));

    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_TLS, STREAM_TOCLIENT,
                            server_hello, sizeof(server_hello));

    FAIL_IF(r != 0);

    FAIL_IF_NULL(ssl_state->server_connp.ja3_hash);

    SigMatchSignatures(&tv, de_ctx, det_ctx, p2);

    FAIL_IF_NOT(PacketAlertCheck(p2, 1));

    AppLayerParserThreadCtxFree(alp_tctx);
    DetectEngineThreadCtxDeinit(&tv, det_ctx);
    DetectEngineCtxFree(de_ctx);
    StreamTcpFreeConfig(true);
    FLOW_DESTROY(&f);
    UTHFreePacket(p1);
    UTHFreePacket(p2);

    PASS;
}

void DetectTlsJa3SHashRegisterTests(void)
{
    UtRegisterTest("DetectTlsJa3SHashTest01", DetectTlsJa3SHashTest01);
}
