/* Copyright (C) 2007-2010 Open Information Security Foundation
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
 * \author Anoop Saldanha <anoopsaldanha@gmail.com>
 */

#include "suricata-common.h"
#include "suricata.h"

#include "decode.h"

#include "detect.h"
#include "detect-engine.h"
#include "detect-parse.h"
#include "detect-pcre.h"
#include "detect-isdataat.h"
#include "detect-bytetest.h"
#include "detect-bytejump.h"
#include "detect-byte-extract.h"
#include "detect-content.h"
#include "detect-engine-content-inspection.h"
#include "detect-engine-dcepayload.h"
#include "detect-engine-build.h"
#include "app-layer-parser.h"

#include "stream-tcp.h"

#include "app-layer.h"
#include "flow-util.h"
#include "util-debug.h"

#include "util-unittest.h"
#include "util-unittest-helper.h"

#include "detect-dce-iface.h"

static int g_dce_stub_data_buffer_id = 0;


/**************************************Unittests*******************************/

#ifdef UNITTESTS
#include "detect-engine-alert.h"

/**
 * \test Test the working of byte_test endianness.
 */
static int DcePayloadTest15(void)
{
    int result = 0;

    uint8_t request1[] = {
        0x05, 0x00, 0x00, 0x03, 0x10, 0x00, 0x00, 0x00,
        0x68, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
        0x50, 0x00, 0x00, 0x00, 0x00, 0x00, 0x1a, 0x00,
        0x76, 0x7e, 0x32, 0x00, 0x0f, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x0f, 0x00, 0x00, 0x00,
        0x5c, 0x00, 0x5c, 0x00, 0x31, 0x00, 0x37, 0x00,
        0x31, 0x00, 0x2e, 0x00, 0x37, 0x00, 0x31, 0x00,
        0x2e, 0x00, 0x38, 0x00, 0x34, 0x00, 0x2e, 0x00,
        0x36, 0x00, 0x37, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
        0x84, 0xf9, 0x7f, 0x01, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff,
        0x14, 0xfa, 0x7f, 0x01, 0x00, 0x00, 0x00, 0x00
    };
    uint32_t request1_len = sizeof(request1);

    TcpSession ssn;
    Packet *p = NULL;
    ThreadVars tv;
    DetectEngineCtx *de_ctx = NULL;
    DetectEngineThreadCtx *det_ctx = NULL;
    Flow f;
    int r;

    const char *sig1 = "alert tcp any any -> any any "
        "(dce_stub_data; content:\"|5c 00 5c 00 31|\"; distance:0; "
        "byte_test:2,=,14080,0,relative,dce; sid:1;)";
    const char *sig2 = "alert tcp any any -> any any "
        "(dce_stub_data; content:\"|5c 00 5c 00 31|\"; distance:0; "
        "byte_test:2,=,46,5,relative,dce; sid:2;)";

    Signature *s;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&tv, 0, sizeof(ThreadVars));
    memset(&f, 0, sizeof(Flow));
    memset(&ssn, 0, sizeof(TcpSession));

    p = UTHBuildPacket(NULL, 0, IPPROTO_TCP);
    p->flow = &f;
    p->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    p->flowflags |= FLOW_PKT_TOSERVER;
    p->flowflags |= FLOW_PKT_ESTABLISHED;

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;
    f.flags |= FLOW_IPV4;
    f.alproto = ALPROTO_DCERPC;

    StreamTcpInitConfig(true);

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;
    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx, sig1);
    s = de_ctx->sig_list;
    if (s == NULL)
        goto end;
    s->next = SigInit(de_ctx, sig2);
    if (s->next == NULL)
        goto end;

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&tv, (void *)de_ctx, (void *)&det_ctx);

    /* request 1 */
    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_DCERPC,
                            STREAM_TOSERVER, request1, request1_len);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        goto end;
    }
    /* detection phase */
    SigMatchSignatures(&tv, de_ctx, det_ctx, p);
    if (!(PacketAlertCheck(p, 1))) {
        printf("sid 1 didn't match but should have for packet: ");
        goto end;
    }
    if (!(PacketAlertCheck(p, 2))) {
        printf("sid 2 didn't match but should have for packet: ");
        goto end;
    }

    result = 1;

end:
    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
    if (de_ctx != NULL) {
        SigGroupCleanup(de_ctx);
        SigCleanSignatures(de_ctx);

        DetectEngineThreadCtxDeinit(&tv, (void *)det_ctx);
        DetectEngineCtxFree(de_ctx);
    }

    StreamTcpFreeConfig(true);

    UTHFreePackets(&p, 1);
    return result;
}

/**
 * \test Test the working of byte_test endianness.
 */
static int DcePayloadTest16(void)
{
    int result = 0;

    uint8_t request1[] = {
        0x05, 0x00, 0x00, 0x03, 0x10, 0x00, 0x00, 0x00,
        0x68, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
        0x50, 0x00, 0x00, 0x00, 0x00, 0x00, 0x1a, 0x00,
        0x76, 0x7e, 0x32, 0x00, 0x0f, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x0f, 0x00, 0x00, 0x00,
        0x5c, 0x00, 0x5c, 0x00, 0x31, 0x00, 0x37, 0x00,
        0x31, 0x00, 0x2e, 0x00, 0x37, 0x00, 0x31, 0x00,
        0x2e, 0x00, 0x38, 0x00, 0x34, 0x00, 0x2e, 0x00,
        0x36, 0x00, 0x37, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
        0x84, 0xf9, 0x7f, 0x01, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff,
        0x14, 0xfa, 0x7f, 0x01, 0x00, 0x00, 0x00, 0x00
    };
    uint32_t request1_len = sizeof(request1);

    TcpSession ssn;
    Packet *p = NULL;
    ThreadVars tv;
    DetectEngineCtx *de_ctx = NULL;
    DetectEngineThreadCtx *det_ctx = NULL;
    Flow f;
    int r;

    const char *sig1 = "alert tcp any any -> any any "
        "(dce_stub_data; content:\"|5c 00 5c 00 31|\"; distance:0; "
        "byte_test:2,=,55,0,relative; sid:1;)";
    const char *sig2 = "alert tcp any any -> any any "
        "(dce_stub_data; content:\"|5c 00 5c 00 31|\"; distance:0; "
        "byte_test:2,=,11776,5,relative; sid:2;)";

    Signature *s;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&tv, 0, sizeof(ThreadVars));
    memset(&f, 0, sizeof(Flow));
    memset(&ssn, 0, sizeof(TcpSession));

    p = UTHBuildPacket(NULL, 0, IPPROTO_TCP);
    p->flow = &f;
    p->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    p->flowflags |= FLOW_PKT_TOSERVER;
    p->flowflags |= FLOW_PKT_ESTABLISHED;

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;
    f.flags |= FLOW_IPV4;
    f.alproto = ALPROTO_DCERPC;

    StreamTcpInitConfig(true);

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;
    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx, sig1);
    s = de_ctx->sig_list;
    if (s == NULL)
        goto end;
    s->next = SigInit(de_ctx, sig2);
    if (s->next == NULL)
        goto end;

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&tv, (void *)de_ctx, (void *)&det_ctx);

    /* request 1 */
    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_DCERPC,
                            STREAM_TOSERVER, request1, request1_len);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        goto end;
    }
    /* detection phase */
    SigMatchSignatures(&tv, de_ctx, det_ctx, p);
    if (!(PacketAlertCheck(p, 1))) {
        printf("sid 1 didn't match but should have for packet: ");
        goto end;
    }
    if (!(PacketAlertCheck(p, 2))) {
        printf("sid 2 didn't match but should have for packet: ");
        goto end;
    }

    result = 1;

end:
    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
    if (de_ctx != NULL) {
        SigGroupCleanup(de_ctx);
        SigCleanSignatures(de_ctx);

        DetectEngineThreadCtxDeinit(&tv, (void *)det_ctx);
        DetectEngineCtxFree(de_ctx);
    }

    StreamTcpFreeConfig(true);

    UTHFreePackets(&p, 1);
    return result;
}

/**
 * \test Test the working of byte_test endianness.
 */
static int DcePayloadTest17(void)
{
    int result = 0;

    uint8_t request1[] = {
        0x05, 0x00, 0x00, 0x03, 0x10, 0x00, 0x00, 0x00,
        0x68, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
        0x50, 0x00, 0x00, 0x00, 0x00, 0x00, 0x1a, 0x00,
        0x76, 0x7e, 0x32, 0x00, 0x0f, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x0f, 0x00, 0x00, 0x00,
        0x5c, 0x00, 0x5c, 0x00, 0x31, 0x00, 0x37, 0x00,
        0x31, 0x00, 0x2e, 0x00, 0x37, 0x00, 0x31, 0x00,
        0x2e, 0x00, 0x38, 0x00, 0x34, 0x00, 0x2e, 0x00,
        0x36, 0x00, 0x37, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
        0x84, 0xf9, 0x7f, 0x01, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff,
        0x14, 0xfa, 0x7f, 0x01, 0x00, 0x00, 0x00, 0x00
    };
    uint32_t request1_len = sizeof(request1);

    TcpSession ssn;
    Packet *p = NULL;
    ThreadVars tv;
    DetectEngineCtx *de_ctx = NULL;
    DetectEngineThreadCtx *det_ctx = NULL;
    Flow f;
    int r;

    const char *sig1 = "alert tcp any any -> any any "
        "(dce_stub_data; content:\"|5c 00 5c 00 31|\"; distance:0; "
        "byte_test:2,=,55,0,relative,big; sid:1;)";
    const char *sig2 = "alert tcp any any -> any any "
        "(dce_stub_data; content:\"|5c 00 5c 00 31|\"; distance:0; "
        "byte_test:2,=,46,5,relative,little; sid:2;)";

    Signature *s;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&tv, 0, sizeof(ThreadVars));
    memset(&f, 0, sizeof(Flow));
    memset(&ssn, 0, sizeof(TcpSession));

    p = UTHBuildPacket(NULL, 0, IPPROTO_TCP);
    p->flow = &f;
    p->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    p->flowflags |= FLOW_PKT_TOSERVER;
    p->flowflags |= FLOW_PKT_ESTABLISHED;

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;
    f.flags |= FLOW_IPV4;
    f.alproto = ALPROTO_DCERPC;

    StreamTcpInitConfig(true);

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;
    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx, sig1);
    s = de_ctx->sig_list;
    if (s == NULL)
        goto end;
    s->next = SigInit(de_ctx, sig2);
    if (s->next == NULL)
        goto end;

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&tv, (void *)de_ctx, (void *)&det_ctx);

    /* request 1 */
    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_DCERPC,
                            STREAM_TOSERVER, request1, request1_len);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        goto end;
    }
    /* detection phase */
    SigMatchSignatures(&tv, de_ctx, det_ctx, p);
    if (!(PacketAlertCheck(p, 1))) {
        printf("sid 1 didn't match but should have for packet: ");
        goto end;
    }
    if (!(PacketAlertCheck(p, 2))) {
        printf("sid 2 didn't match but should have for packet: ");
        goto end;
    }

    result = 1;

end:
    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
    if (de_ctx != NULL) {
        SigGroupCleanup(de_ctx);
        SigCleanSignatures(de_ctx);

        DetectEngineThreadCtxDeinit(&tv, (void *)det_ctx);
        DetectEngineCtxFree(de_ctx);
    }

    StreamTcpFreeConfig(true);

    UTHFreePackets(&p, 1);
    return result;
}

/**
 * \test Test the working of byte_jump endianness.
 */
static int DcePayloadTest18(void)
{
    int result = 0;

    uint8_t request1[] = {
        0x05, 0x00, 0x00, 0x03, 0x10, 0x00, 0x00, 0x00,
        0x68, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
        0x50, 0x00, 0x00, 0x00, 0x00, 0x00, 0x1a, 0x00,
        0x76, 0x7e, 0x32, 0x00, 0x0f, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x0f, 0x00, 0x00, 0x00,
        0x5c, 0x00, 0x5c, 0x00, 0x31, 0x03, 0x00, 0x03,
        0x00, 0x00, 0x2e, 0x00, 0x37, 0x00, 0x31, 0x00,
        0x2e, 0x00, 0x38, 0x00, 0x34, 0x00, 0x2e, 0x00,
        0x36, 0x00, 0x37, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
        0x84, 0xf9, 0x7f, 0x01, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff,
        0x14, 0xfa, 0x7f, 0x01, 0x00, 0x00, 0x00, 0x00
    };
    uint32_t request1_len = sizeof(request1);

    TcpSession ssn;
    Packet *p = NULL;
    ThreadVars tv;
    DetectEngineCtx *de_ctx = NULL;
    DetectEngineThreadCtx *det_ctx = NULL;
    Flow f;
    int r;

    const char *sig1 = "alert tcp any any -> any any "
        "(dce_stub_data; content:\"|5c 00 5c 00 31|\"; distance:0; "
        "byte_jump:2,0,relative,dce; byte_test:2,=,46,0,relative,dce; sid:1;)";
    const char *sig2 = "alert tcp any any -> any any "
        "(dce_stub_data; content:\"|5c 00 5c 00 31|\"; distance:0; "
        "byte_jump:2,2,relative,dce; byte_test:2,=,14080,0,relative; sid:2;)";

    Signature *s;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&tv, 0, sizeof(ThreadVars));
    memset(&f, 0, sizeof(Flow));
    memset(&ssn, 0, sizeof(TcpSession));

    p = UTHBuildPacket(NULL, 0, IPPROTO_TCP);
    p->flow = &f;
    p->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    p->flowflags |= FLOW_PKT_TOSERVER;
    p->flowflags |= FLOW_PKT_ESTABLISHED;

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;
    f.flags |= FLOW_IPV4;
    f.alproto = ALPROTO_DCERPC;

    StreamTcpInitConfig(true);

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;
    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx, sig1);
    s = de_ctx->sig_list;
    if (s == NULL)
        goto end;
    s->next = SigInit(de_ctx, sig2);
    if (s->next == NULL)
        goto end;

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&tv, (void *)de_ctx, (void *)&det_ctx);

    /* request 1 */
    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_DCERPC,
                            STREAM_TOSERVER, request1, request1_len);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        goto end;
    }
    /* detection phase */
    SigMatchSignatures(&tv, de_ctx, det_ctx, p);
    if (!(PacketAlertCheck(p, 1))) {
        printf("sid 1 didn't match but should have for packet: ");
        goto end;
    }
    if (!(PacketAlertCheck(p, 2))) {
        printf("sid 2 didn't match but should have for packet: ");
        goto end;
    }

    result = 1;

end:
    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
    if (de_ctx != NULL) {
        SigGroupCleanup(de_ctx);
        SigCleanSignatures(de_ctx);

        DetectEngineThreadCtxDeinit(&tv, (void *)det_ctx);
        DetectEngineCtxFree(de_ctx);
    }

    StreamTcpFreeConfig(true);

    UTHFreePackets(&p, 1);
    return result;
}

/**
 * \test Test the working of byte_jump endianness.
 */
static int DcePayloadTest19(void)
{
    int result = 0;

    uint8_t request1[] = {
        0x05, 0x00, 0x00, 0x03, 0x10, 0x00, 0x00, 0x00,
        0x68, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
        0x50, 0x00, 0x00, 0x00, 0x00, 0x00, 0x1a, 0x00,
        0x76, 0x7e, 0x32, 0x00, 0x0f, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x0f, 0x00, 0x00, 0x00,
        0x5c, 0x00, 0x5c, 0x00, 0x31, 0x00, 0x03, 0x00,
        0x03, 0x00, 0x2e, 0x00, 0x37, 0x00, 0x31, 0x00,
        0x2e, 0x00, 0x38, 0x00, 0x34, 0x00, 0x2e, 0x00,
        0x36, 0x00, 0x37, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
        0x84, 0xf9, 0x7f, 0x01, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff,
        0x14, 0xfa, 0x7f, 0x01, 0x00, 0x00, 0x00, 0x00
    };
    uint32_t request1_len = sizeof(request1);

    TcpSession ssn;
    Packet *p = NULL;
    ThreadVars tv;
    DetectEngineCtx *de_ctx = NULL;
    DetectEngineThreadCtx *det_ctx = NULL;
    Flow f;
    int r;

    const char *sig1 = "alert tcp any any -> any any "
        "(dce_stub_data; content:\"|5c 00 5c 00 31|\"; distance:0; "
        "byte_jump:2,0,relative; byte_test:2,=,46,0,relative,dce; sid:1;)";
    const char *sig2 = "alert tcp any any -> any any "
        "(dce_stub_data; content:\"|5c 00 5c 00 31|\"; distance:0; "
        "byte_jump:2,2,relative; byte_test:2,=,14080,0,relative; sid:2;)";

    Signature *s;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&tv, 0, sizeof(ThreadVars));
    memset(&f, 0, sizeof(Flow));
    memset(&ssn, 0, sizeof(TcpSession));

    p = UTHBuildPacket(NULL, 0, IPPROTO_TCP);
    p->flow = &f;
    p->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    p->flowflags |= FLOW_PKT_TOSERVER;
    p->flowflags |= FLOW_PKT_ESTABLISHED;

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;
    f.flags |= FLOW_IPV4;
    f.alproto = ALPROTO_DCERPC;

    StreamTcpInitConfig(true);

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;
    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx, sig1);
    s = de_ctx->sig_list;
    if (s == NULL)
        goto end;
    s->next = SigInit(de_ctx, sig2);
    if (s->next == NULL)
        goto end;

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&tv, (void *)de_ctx, (void *)&det_ctx);

    /* request 1 */
    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_DCERPC,
                            STREAM_TOSERVER, request1, request1_len);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        goto end;
    }
    /* detection phase */
    SigMatchSignatures(&tv, de_ctx, det_ctx, p);
    if (!(PacketAlertCheck(p, 1))) {
        printf("sid 1 didn't match but should have for packet: ");
        goto end;
    }
    if (!(PacketAlertCheck(p, 2))) {
        printf("sid 2 didn't match but should have for packet: ");
        goto end;
    }

    result = 1;

end:
    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
    if (de_ctx != NULL) {
        SigGroupCleanup(de_ctx);
        SigCleanSignatures(de_ctx);

        DetectEngineThreadCtxDeinit(&tv, (void *)det_ctx);
        DetectEngineCtxFree(de_ctx);
    }

    StreamTcpFreeConfig(true);

    UTHFreePackets(&p, 1);
    return result;
}

/**
 * \test Test the working of byte_jump endianness.
 */
static int DcePayloadTest20(void)
{
    int result = 0;

    uint8_t request1[] = {
        0x05, 0x00, 0x00, 0x03, 0x10, 0x00, 0x00, 0x00,
        0x68, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
        0x50, 0x00, 0x00, 0x00, 0x00, 0x00, 0x1a, 0x00,
        0x76, 0x7e, 0x32, 0x00, 0x0f, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x0f, 0x00, 0x00, 0x00,
        0x5c, 0x00, 0x5c, 0x00, 0x31, 0x00, 0x03, 0x03,
        0x00, 0x00, 0x2e, 0x00, 0x37, 0x00, 0x31, 0x00,
        0x2e, 0x00, 0x38, 0x00, 0x34, 0x00, 0x2e, 0x00,
        0x36, 0x00, 0x37, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
        0x84, 0xf9, 0x7f, 0x01, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff,
        0x14, 0xfa, 0x7f, 0x01, 0x00, 0x00, 0x00, 0x00
    };
    uint32_t request1_len = sizeof(request1);

    TcpSession ssn;
    Packet *p = NULL;
    ThreadVars tv;
    DetectEngineCtx *de_ctx = NULL;
    DetectEngineThreadCtx *det_ctx = NULL;
    Flow f;
    int r;

    const char *sig1 = "alert tcp any any -> any any "
        "(dce_stub_data; content:\"|5c 00 5c 00 31|\"; distance:0; "
        "byte_jump:2,0,relative,big; byte_test:2,=,46,0,relative,dce; sid:1;)";
    const char *sig2 = "alert tcp any any -> any any "
        "(dce_stub_data; content:\"|5c 00 5c 00 31|\"; distance:0; "
        "byte_jump:2,2,little,relative; byte_test:2,=,14080,0,relative; sid:2;)";

    Signature *s;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&tv, 0, sizeof(ThreadVars));
    memset(&f, 0, sizeof(Flow));
    memset(&ssn, 0, sizeof(TcpSession));

    p = UTHBuildPacket(NULL, 0, IPPROTO_TCP);
    p->flow = &f;
    p->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    p->flowflags |= FLOW_PKT_TOSERVER;
    p->flowflags |= FLOW_PKT_ESTABLISHED;

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;
    f.flags |= FLOW_IPV4;
    f.alproto = ALPROTO_DCERPC;

    StreamTcpInitConfig(true);

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;
    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx, sig1);
    s = de_ctx->sig_list;
    if (s == NULL)
        goto end;
    s->next = SigInit(de_ctx, sig2);
    if (s->next == NULL)
        goto end;

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&tv, (void *)de_ctx, (void *)&det_ctx);

    /* request 1 */
    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_DCERPC,
                            STREAM_TOSERVER, request1, request1_len);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        goto end;
    }
    /* detection phase */
    SigMatchSignatures(&tv, de_ctx, det_ctx, p);
    if (!(PacketAlertCheck(p, 1))) {
        printf("sid 1 didn't match but should have for packet: ");
        goto end;
    }
    if (!(PacketAlertCheck(p, 2))) {
        printf("sid 2 didn't match but should have for packet: ");
        goto end;
    }

    result = 1;

end:
    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
    if (de_ctx != NULL) {
        SigGroupCleanup(de_ctx);
        SigCleanSignatures(de_ctx);

        DetectEngineThreadCtxDeinit(&tv, (void *)det_ctx);
        DetectEngineCtxFree(de_ctx);
    }

    StreamTcpFreeConfig(true);

    UTHFreePackets(&p, 1);
    return result;
}

#endif /* UNITTESTS */

void DcePayloadRegisterTests(void)
{
    g_dce_stub_data_buffer_id = DetectBufferTypeGetByName("dce_stub_data");

#ifdef UNITTESTS
    UtRegisterTest("DcePayloadTest15", DcePayloadTest15);
    UtRegisterTest("DcePayloadTest16", DcePayloadTest16);
    UtRegisterTest("DcePayloadTest17", DcePayloadTest17);
    UtRegisterTest("DcePayloadTest18", DcePayloadTest18);
    UtRegisterTest("DcePayloadTest19", DcePayloadTest19);
    UtRegisterTest("DcePayloadTest20", DcePayloadTest20);
#endif /* UNITTESTS */
}
