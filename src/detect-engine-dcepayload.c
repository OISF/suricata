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

#include "detect-engine.h"
#include "detect-pcre.h"
#include "detect-isdataat.h"
#include "detect-bytetest.h"
#include "detect-bytejump.h"
#include "detect-content.h"
#include "detect-engine-dcepayload.h"
#include "detect-engine-build.h"
#include "app-layer-parser.h"

#include "stream-tcp.h"

#include "flow-util.h"

#include "util-unittest.h"
#include "util-unittest-helper.h"

static int g_dce_stub_data_buffer_id = 0;


/**************************************Unittests*******************************/

#ifdef UNITTESTS

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

/**
 * \test Test content for dce sig.
 */
static int DcePayloadParseTest25(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 1;
    Signature *s = NULL;
    SigMatch *sm = NULL;
    DetectContentData *data = NULL;

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    s = de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                                   "(msg:\"Testing bytejump_body\"; "
                                   "content:\"one\"; content:\"two\"; "
                                   "content:\"three\"; within:10; "
                                   "content:\"four\"; distance:4; "
                                   "dce_iface:3919286a-b10c-11d0-9ba8-00c04fd92ef5; "
                                   "sid:1;)");
    if (de_ctx->sig_list == NULL) {
        result = 0;
        goto end;
    }

    if (s->init_data->smlists_tail[g_dce_stub_data_buffer_id] != NULL) {
        result = 0;
        goto end;
    }
    if (s->init_data->smlists_tail[DETECT_SM_LIST_PMATCH] == NULL) {
        result = 0;
        goto end;
    }

    sm = s->init_data->smlists[DETECT_SM_LIST_PMATCH];
    if (sm->type != DETECT_CONTENT) {
        result = 0;
        goto end;
    }
    data = (DetectContentData *)sm->ctx;
    if (data->flags & DETECT_CONTENT_RAWBYTES ||
        data->flags & DETECT_CONTENT_NOCASE ||
        data->flags & DETECT_CONTENT_WITHIN ||
        data->flags & DETECT_CONTENT_DISTANCE ||
        data->flags & DETECT_CONTENT_FAST_PATTERN ||
        data->flags & DETECT_CONTENT_NEGATED ) {
        result = 0;
        goto end;
    }
    result &= (strncmp((char *)data->content, "one", 3) == 0);
    if (result == 0)
        goto end;

    sm = sm->next;
    if (sm->type != DETECT_CONTENT) {
        result = 0;
        goto end;
    }
    data = (DetectContentData *)sm->ctx;
    if (data->flags & DETECT_CONTENT_RAWBYTES ||
        data->flags & DETECT_CONTENT_NOCASE ||
        data->flags & DETECT_CONTENT_WITHIN ||
        data->flags & DETECT_CONTENT_DISTANCE ||
        data->flags & DETECT_CONTENT_FAST_PATTERN ||
        data->flags & DETECT_CONTENT_NEGATED ) {
        result = 0;
        goto end;
    }
    result &= (strncmp((char *)data->content, "two", 3) == 0);
    if (result == 0)
        goto end;

    sm = sm->next;
    if (sm->type != DETECT_CONTENT) {
        result = 0;
        goto end;
    }
    data = (DetectContentData *)sm->ctx;
    if (data->flags & DETECT_CONTENT_RAWBYTES ||
        data->flags & DETECT_CONTENT_NOCASE ||
        !(data->flags & DETECT_CONTENT_WITHIN) ||
        data->flags & DETECT_CONTENT_DISTANCE ||
        data->flags & DETECT_CONTENT_FAST_PATTERN ||
        data->flags & DETECT_CONTENT_NEGATED ) {
        result = 0;
        goto end;
    }
    result &= (strncmp((char *)data->content, "three", 5) == 0);
    if (result == 0)
        goto end;

    sm = sm->next;
    if (sm->type != DETECT_CONTENT) {
        result = 0;
        goto end;
    }
    data = (DetectContentData *)sm->ctx;
    if (data->flags & DETECT_CONTENT_RAWBYTES ||
        data->flags & DETECT_CONTENT_NOCASE ||
        data->flags & DETECT_CONTENT_WITHIN ||
        !(data->flags & DETECT_CONTENT_DISTANCE) ||
        data->flags & DETECT_CONTENT_FAST_PATTERN ||
        data->flags & DETECT_CONTENT_NEGATED ) {
        result = 0;
        goto end;
    }
    result &= (strncmp((char *)data->content, "four", 4) == 0);
    if (result == 0)
        goto end;

 end:
    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);

    return result;
}

/**
 * \test Test content for dce sig.
 */
static int DcePayloadParseTest26(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 1;
    Signature *s = NULL;
    SigMatch *sm = NULL;
    DetectContentData *data = NULL;

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    s = de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                                   "(msg:\"Testing bytejump_body\"; "
                                   "dce_stub_data; "
                                   "pkt_data; "
                                   "content:\"one\"; "
                                   "content:\"two\"; "
                                   "content:\"three\"; within:5; "
                                   "content:\"four\"; distance:10; "
                                   "sid:1;)");
    if (de_ctx->sig_list == NULL) {
        result = 0;
        goto end;
    }

    if (s->init_data->smlists_tail[g_dce_stub_data_buffer_id] != NULL) {
        result = 0;
        goto end;
    }
    if (s->init_data->smlists_tail[DETECT_SM_LIST_PMATCH] == NULL) {
        result = 0;
        goto end;
    }

    sm = s->init_data->smlists[DETECT_SM_LIST_PMATCH];
    if (sm->type != DETECT_CONTENT) {
        result = 0;
        goto end;
    }
    data = (DetectContentData *)sm->ctx;
    if (data->flags & DETECT_CONTENT_RAWBYTES ||
        data->flags & DETECT_CONTENT_NOCASE ||
        data->flags & DETECT_CONTENT_WITHIN ||
        data->flags & DETECT_CONTENT_DISTANCE ||
        data->flags & DETECT_CONTENT_FAST_PATTERN ||
        data->flags & DETECT_CONTENT_NEGATED ) {
        result = 0;
        printf("one failed\n");
        goto end;
    }
    result &= (strncmp((char *)data->content, "one", 3) == 0);
    if (result == 0)
        goto end;

    sm = sm->next;
    if (sm->type != DETECT_CONTENT) {
        result = 0;
        goto end;
    }
    data = (DetectContentData *)sm->ctx;
    if (data->flags & DETECT_CONTENT_RAWBYTES ||
        data->flags & DETECT_CONTENT_NOCASE ||
        data->flags & DETECT_CONTENT_WITHIN ||
        data->flags & DETECT_CONTENT_DISTANCE ||
        data->flags & DETECT_CONTENT_FAST_PATTERN ||
        data->flags & DETECT_CONTENT_NEGATED ) {
        result = 0;
        printf("two failed\n");
        goto end;
    }
    result &= (strncmp((char *)data->content, "two", 3) == 0);
    if (result == 0)
        goto end;

    sm = sm->next;
    if (sm->type != DETECT_CONTENT) {
        result = 0;
        goto end;
    }
    data = (DetectContentData *)sm->ctx;
    if (data->flags & DETECT_CONTENT_RAWBYTES ||
        data->flags & DETECT_CONTENT_NOCASE ||
        !(data->flags & DETECT_CONTENT_WITHIN) ||
        data->flags & DETECT_CONTENT_DISTANCE ||
        data->flags & DETECT_CONTENT_FAST_PATTERN ||
        data->flags & DETECT_CONTENT_NEGATED ) {
        printf("three failed\n");
        result = 0;
        goto end;
    }
    result &= (strncmp((char *)data->content, "three", 5) == 0);
    if (result == 0)
        goto end;

    sm = sm->next;
    if (sm->type != DETECT_CONTENT) {
        result = 0;
        goto end;
    }
    data = (DetectContentData *)sm->ctx;
    if (data->flags & DETECT_CONTENT_RAWBYTES ||
        data->flags & DETECT_CONTENT_NOCASE ||
        data->flags & DETECT_CONTENT_WITHIN ||
        !(data->flags & DETECT_CONTENT_DISTANCE) ||
        data->flags & DETECT_CONTENT_FAST_PATTERN ||
        data->flags & DETECT_CONTENT_NEGATED ) {
        printf("four failed\n");
        result = 0;
        goto end;
    }
    result &= (strncmp((char *)data->content, "four", 4) == 0);
    if (result == 0)
        goto end;

 end:
    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);

    return result;
}

/**
 * \test Test content for dce sig.
 */
static int DcePayloadParseTest27(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 1;
    Signature *s = NULL;
    SigMatch *sm = NULL;
    DetectContentData *data = NULL;

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    s = de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                                   "(msg:\"Testing bytejump_body\"; "
                                   "dce_stub_data; "
                                   "content:\"one\"; distance:10; within:5; "
                                   "content:\"two\"; within:5;"
                                   "content:\"three\"; within:5; "
                                   "content:\"four\"; distance:10; "
                                   "sid:1;)");
    if (de_ctx->sig_list == NULL) {
        result = 0;
        goto end;
    }

    if (s->init_data->smlists_tail[g_dce_stub_data_buffer_id] == NULL) {
        result = 0;
        goto end;
    }
    if (s->init_data->smlists_tail[DETECT_SM_LIST_PMATCH] != NULL) {
        result = 0;
        goto end;
    }

    sm = s->init_data->smlists[g_dce_stub_data_buffer_id];
    if (sm->type != DETECT_CONTENT) {
        result = 0;
        goto end;
    }
    data = (DetectContentData *)sm->ctx;
    if (data->flags & DETECT_CONTENT_RAWBYTES ||
        data->flags & DETECT_CONTENT_NOCASE ||
        !(data->flags & DETECT_CONTENT_WITHIN) ||
        !(data->flags & DETECT_CONTENT_DISTANCE) ||
        data->flags & DETECT_CONTENT_FAST_PATTERN ||
        data->flags & DETECT_CONTENT_NEGATED ) {
        result = 0;
        printf("one failed\n");
        goto end;
    }
    result &= (strncmp((char *)data->content, "one", 3) == 0);
    if (result == 0)
        goto end;

    sm = sm->next;
    if (sm->type != DETECT_CONTENT) {
        result = 0;
        goto end;
    }
    data = (DetectContentData *)sm->ctx;
    if (data->flags & DETECT_CONTENT_RAWBYTES ||
        data->flags & DETECT_CONTENT_NOCASE ||
        !(data->flags & DETECT_CONTENT_WITHIN) ||
        data->flags & DETECT_CONTENT_DISTANCE ||
        data->flags & DETECT_CONTENT_FAST_PATTERN ||
        data->flags & DETECT_CONTENT_NEGATED ) {
        result = 0;
        printf("two failed\n");
        goto end;
    }
    result &= (strncmp((char *)data->content, "two", 3) == 0);
    if (result == 0)
        goto end;

    sm = sm->next;
    if (sm->type != DETECT_CONTENT) {
        result = 0;
        goto end;
    }
    data = (DetectContentData *)sm->ctx;
    if (data->flags & DETECT_CONTENT_RAWBYTES ||
        data->flags & DETECT_CONTENT_NOCASE ||
        !(data->flags & DETECT_CONTENT_WITHIN) ||
        data->flags & DETECT_CONTENT_DISTANCE ||
        data->flags & DETECT_CONTENT_FAST_PATTERN ||
        data->flags & DETECT_CONTENT_NEGATED ) {
        printf("three failed\n");
        result = 0;
        goto end;
    }
    result &= (strncmp((char *)data->content, "three", 5) == 0);
    if (result == 0)
        goto end;

    sm = sm->next;
    if (sm->type != DETECT_CONTENT) {
        result = 0;
        goto end;
    }
    data = (DetectContentData *)sm->ctx;
    if (data->flags & DETECT_CONTENT_RAWBYTES ||
        data->flags & DETECT_CONTENT_NOCASE ||
        data->flags & DETECT_CONTENT_WITHIN ||
        !(data->flags & DETECT_CONTENT_DISTANCE) ||
        data->flags & DETECT_CONTENT_FAST_PATTERN ||
        data->flags & DETECT_CONTENT_NEGATED ) {
        printf("four failed\n");
        result = 0;
        goto end;
    }
    result &= (strncmp((char *)data->content, "four", 4) == 0);
    if (result == 0)
        goto end;

 end:
    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);

    return result;
}

/**
 * \test Test content for dce sig.
 */
static int DcePayloadParseTest28(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 1;
    Signature *s = NULL;
    SigMatch *sm = NULL;
    DetectContentData *data = NULL;

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    s = de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                                   "(msg:\"Testing bytejump_body\"; "
                                   "dce_stub_data; "
                                   "content:\"one\"; distance:10; within:5; "
                                   "content:\"two\"; within:5;"
                                   "pkt_data; "
                                   "content:\"three\";"
                                   "content:\"four\";"
                                   "sid:1;)");
    if (de_ctx->sig_list == NULL) {
        result = 0;
        goto end;
    }

    if (s->init_data->smlists_tail[g_dce_stub_data_buffer_id] == NULL) {
        result = 0;
        goto end;
    }
    if (s->init_data->smlists_tail[DETECT_SM_LIST_PMATCH] == NULL) {
        result = 0;
        goto end;
    }

    sm = s->init_data->smlists[g_dce_stub_data_buffer_id];
    if (sm->type != DETECT_CONTENT) {
        result = 0;
        goto end;
    }
    data = (DetectContentData *)sm->ctx;
    if (data->flags & DETECT_CONTENT_RAWBYTES ||
        data->flags & DETECT_CONTENT_NOCASE ||
        !(data->flags & DETECT_CONTENT_WITHIN) ||
        !(data->flags & DETECT_CONTENT_DISTANCE) ||
        data->flags & DETECT_CONTENT_FAST_PATTERN ||
        data->flags & DETECT_CONTENT_NEGATED ) {
        result = 0;
        printf("one failed\n");
        goto end;
    }
    result &= (strncmp((char *)data->content, "one", 3) == 0);
    if (result == 0)
        goto end;

    sm = sm->next;
    if (sm->type != DETECT_CONTENT) {
        result = 0;
        goto end;
    }
    data = (DetectContentData *)sm->ctx;
    if (data->flags & DETECT_CONTENT_RAWBYTES ||
        data->flags & DETECT_CONTENT_NOCASE ||
        !(data->flags & DETECT_CONTENT_WITHIN) ||
        data->flags & DETECT_CONTENT_DISTANCE ||
        data->flags & DETECT_CONTENT_FAST_PATTERN ||
        data->flags & DETECT_CONTENT_NEGATED ) {
        result = 0;
        printf("two failed\n");
        goto end;
    }
    result &= (strncmp((char *)data->content, "two", 3) == 0);
    if (result == 0)
        goto end;

    sm = s->init_data->smlists[DETECT_SM_LIST_PMATCH];
    if (sm->type != DETECT_CONTENT) {
        result = 0;
        goto end;
    }
    data = (DetectContentData *)sm->ctx;
    if (data->flags & DETECT_CONTENT_RAWBYTES ||
        data->flags & DETECT_CONTENT_NOCASE ||
        data->flags & DETECT_CONTENT_WITHIN ||
        data->flags & DETECT_CONTENT_DISTANCE ||
        data->flags & DETECT_CONTENT_FAST_PATTERN ||
        data->flags & DETECT_CONTENT_NEGATED ) {
        printf("three failed\n");
        result = 0;
        goto end;
    }
    result &= (strncmp((char *)data->content, "three", 5) == 0);
    if (result == 0)
        goto end;

    sm = sm->next;
    if (sm->type != DETECT_CONTENT) {
        result = 0;
        goto end;
    }
    data = (DetectContentData *)sm->ctx;
    if (data->flags & DETECT_CONTENT_RAWBYTES ||
        data->flags & DETECT_CONTENT_NOCASE ||
        data->flags & DETECT_CONTENT_WITHIN ||
        data->flags & DETECT_CONTENT_DISTANCE ||
        data->flags & DETECT_CONTENT_FAST_PATTERN ||
        data->flags & DETECT_CONTENT_NEGATED ) {
        printf("four failed\n");
        result = 0;
        goto end;
    }
    result &= (strncmp((char *)data->content, "four", 4) == 0);
    if (result == 0)
        goto end;

 end:
    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);

    return result;
}

/**
 * \test Test content for dce sig.
 */
static int DcePayloadParseTest29(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 1;
    Signature *s = NULL;
    SigMatch *sm = NULL;
    DetectContentData *data = NULL;
    DetectPcreData *pd = NULL;

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    s = de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                                   "(msg:\"Testing bytejump_body\"; "
                                   "dce_stub_data; "
                                   "pkt_data; "
                                   "pcre:/boom/; "
                                   "content:\"one\"; distance:10; within:5; "
                                   "content:\"two\"; within:5;"
                                   "content:\"three\";"
                                   "content:\"four\";"
                                   "sid:1;)");
    if (de_ctx->sig_list == NULL) {
        result = 0;
        goto end;
    }

    if (s->init_data->smlists_tail[g_dce_stub_data_buffer_id] != NULL) {
        result = 0;
        goto end;
    }
    if (s->init_data->smlists_tail[DETECT_SM_LIST_PMATCH] == NULL) {
        result = 0;
        goto end;
    }

    sm = s->init_data->smlists[DETECT_SM_LIST_PMATCH];
    if (sm->type != DETECT_PCRE) {
        result = 0;
        goto end;
    }
    pd = (DetectPcreData *)sm->ctx;
    if (pd->flags & DETECT_PCRE_RAWBYTES ||
        pd->flags & DETECT_PCRE_RELATIVE) {
        result = 0;
        printf("one failed\n");
        goto end;
    }

    sm = sm->next;
    if (sm->type != DETECT_CONTENT) {
        result = 0;
        goto end;
    }
    data = (DetectContentData *)sm->ctx;
    if (data->flags & DETECT_CONTENT_RAWBYTES ||
        data->flags & DETECT_CONTENT_NOCASE ||
        !(data->flags & DETECT_CONTENT_WITHIN) ||
        !(data->flags & DETECT_CONTENT_DISTANCE) ||
        data->flags & DETECT_CONTENT_FAST_PATTERN ||
        data->flags & DETECT_CONTENT_NEGATED ) {
        result = 0;
        printf("one failed\n");
        goto end;
    }
    result &= (strncmp((char *)data->content, "one", 3) == 0);
    if (result == 0)
        goto end;

    sm = sm->next;
    if (sm->type != DETECT_CONTENT) {
        result = 0;
        goto end;
    }
    data = (DetectContentData *)sm->ctx;
    if (data->flags & DETECT_CONTENT_RAWBYTES ||
        data->flags & DETECT_CONTENT_NOCASE ||
        !(data->flags & DETECT_CONTENT_WITHIN) ||
        data->flags & DETECT_CONTENT_DISTANCE ||
        data->flags & DETECT_CONTENT_FAST_PATTERN ||
        data->flags & DETECT_CONTENT_NEGATED ) {
        result = 0;
        printf("two failed\n");
        goto end;
    }
    result &= (strncmp((char *)data->content, "two", 3) == 0);
    if (result == 0)
        goto end;

    sm = sm->next;
    if (sm->type != DETECT_CONTENT) {
        result = 0;
        goto end;
    }
    data = (DetectContentData *)sm->ctx;
    if (data->flags & DETECT_CONTENT_RAWBYTES ||
        data->flags & DETECT_CONTENT_NOCASE ||
        data->flags & DETECT_CONTENT_WITHIN ||
        data->flags & DETECT_CONTENT_DISTANCE ||
        data->flags & DETECT_CONTENT_FAST_PATTERN ||
        data->flags & DETECT_CONTENT_NEGATED ) {
        printf("three failed\n");
        result = 0;
        goto end;
    }
    result &= (strncmp((char *)data->content, "three", 5) == 0);
    if (result == 0)
        goto end;

    sm = sm->next;
    if (sm->type != DETECT_CONTENT) {
        result = 0;
        goto end;
    }
    data = (DetectContentData *)sm->ctx;
    if (data->flags & DETECT_CONTENT_RAWBYTES ||
        data->flags & DETECT_CONTENT_NOCASE ||
        data->flags & DETECT_CONTENT_WITHIN ||
        data->flags & DETECT_CONTENT_DISTANCE ||
        data->flags & DETECT_CONTENT_FAST_PATTERN ||
        data->flags & DETECT_CONTENT_NEGATED ) {
        printf("four failed\n");
        result = 0;
        goto end;
    }
    result &= (strncmp((char *)data->content, "four", 4) == 0);
    if (result == 0)
        goto end;

 end:
    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);

    return result;
}

/**
 * \test Test content for dce sig.
 */
static int DcePayloadParseTest30(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 1;
    Signature *s = NULL;
    SigMatch *sm = NULL;
    DetectContentData *data = NULL;
    DetectBytejumpData *bd = NULL;

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    s = de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                                   "(msg:\"Testing bytejump_body\"; "
                                   "dce_stub_data; "
                                   "pkt_data; "
                                   "byte_jump:2,5; "
                                   "content:\"one\"; distance:10; within:5; "
                                   "content:\"two\"; within:5;"
                                   "content:\"three\";"
                                   "content:\"four\";"
                                   "sid:1;)");
    if (de_ctx->sig_list == NULL) {
        result = 0;
        goto end;
    }

    if (s->init_data->smlists_tail[g_dce_stub_data_buffer_id] != NULL) {
        result = 0;
        goto end;
    }
    if (s->init_data->smlists_tail[DETECT_SM_LIST_PMATCH] == NULL) {
        result = 0;
        goto end;
    }

    sm = s->init_data->smlists[DETECT_SM_LIST_PMATCH];
    if (sm->type != DETECT_BYTEJUMP) {
        result = 0;
        goto end;
    }
    bd = (DetectBytejumpData *)sm->ctx;
    if (bd->flags & DETECT_BYTEJUMP_BEGIN ||
        bd->flags & DETECT_BYTEJUMP_LITTLE ||
        bd->flags & DETECT_BYTEJUMP_BIG ||
        bd->flags & DETECT_BYTEJUMP_STRING ||
        bd->flags & DETECT_BYTEJUMP_RELATIVE ||
        bd->flags & DETECT_BYTEJUMP_ALIGN ||
        bd->flags & DETECT_BYTEJUMP_DCE ) {
        result = 0;
        printf("one failed\n");
        goto end;
    }

    sm = sm->next;
    if (sm->type != DETECT_CONTENT) {
        result = 0;
        goto end;
    }
    data = (DetectContentData *)sm->ctx;
    if (data->flags & DETECT_CONTENT_RAWBYTES ||
        data->flags & DETECT_CONTENT_NOCASE ||
        !(data->flags & DETECT_CONTENT_WITHIN) ||
        !(data->flags & DETECT_CONTENT_DISTANCE) ||
        data->flags & DETECT_CONTENT_FAST_PATTERN ||
        data->flags & DETECT_CONTENT_NEGATED ) {
        result = 0;
        printf("one failed\n");
        goto end;
    }
    result &= (strncmp((char *)data->content, "one", 3) == 0);
    if (result == 0)
        goto end;

    sm = sm->next;
    if (sm->type != DETECT_CONTENT) {
        result = 0;
        goto end;
    }
    data = (DetectContentData *)sm->ctx;
    if (data->flags & DETECT_CONTENT_RAWBYTES ||
        data->flags & DETECT_CONTENT_NOCASE ||
        !(data->flags & DETECT_CONTENT_WITHIN) ||
        data->flags & DETECT_CONTENT_DISTANCE ||
        data->flags & DETECT_CONTENT_FAST_PATTERN ||
        data->flags & DETECT_CONTENT_NEGATED ) {
        result = 0;
        printf("two failed\n");
        goto end;
    }
    result &= (strncmp((char *)data->content, "two", 3) == 0);
    if (result == 0)
        goto end;

    sm = sm->next;
    if (sm->type != DETECT_CONTENT) {
        result = 0;
        goto end;
    }
    data = (DetectContentData *)sm->ctx;
    if (data->flags & DETECT_CONTENT_RAWBYTES ||
        data->flags & DETECT_CONTENT_NOCASE ||
        data->flags & DETECT_CONTENT_WITHIN ||
        data->flags & DETECT_CONTENT_DISTANCE ||
        data->flags & DETECT_CONTENT_FAST_PATTERN ||
        data->flags & DETECT_CONTENT_NEGATED ) {
        printf("three failed\n");
        result = 0;
        goto end;
    }
    result &= (strncmp((char *)data->content, "three", 5) == 0);
    if (result == 0)
        goto end;

    sm = sm->next;
    if (sm->type != DETECT_CONTENT) {
        result = 0;
        goto end;
    }
    data = (DetectContentData *)sm->ctx;
    if (data->flags & DETECT_CONTENT_RAWBYTES ||
        data->flags & DETECT_CONTENT_NOCASE ||
        data->flags & DETECT_CONTENT_WITHIN ||
        data->flags & DETECT_CONTENT_DISTANCE ||
        data->flags & DETECT_CONTENT_FAST_PATTERN ||
        data->flags & DETECT_CONTENT_NEGATED ) {
        printf("four failed\n");
        result = 0;
        goto end;
    }
    result &= (strncmp((char *)data->content, "four", 4) == 0);
    if (result == 0)
        goto end;

 end:
    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);

    return result;
}

/**
 * \test Test content for dce sig.
 */
static int DcePayloadParseTest31(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 1;
    Signature *s = NULL;
    SigMatch *sm = NULL;
    DetectContentData *data = NULL;
    DetectBytejumpData *bd = NULL;

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    s = de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                                   "(msg:\"Testing bytejump_body\"; "
                                   "dce_stub_data; "
                                   "byte_jump:2,5,relative; "
                                   "content:\"one\"; distance:10; within:5; "
                                   "content:\"two\"; within:5;"
                                   "pkt_data; "
                                   "content:\"three\";"
                                   "content:\"four\";"
                                   "sid:1;)");
    if (de_ctx->sig_list == NULL) {
        result = 0;
        goto end;
    }

    if (s->init_data->smlists_tail[g_dce_stub_data_buffer_id] == NULL) {
        result = 0;
        goto end;
    }
    if (s->init_data->smlists_tail[DETECT_SM_LIST_PMATCH] == NULL) {
        result = 0;
        goto end;
    }

    sm = s->init_data->smlists[g_dce_stub_data_buffer_id];
    if (sm->type != DETECT_BYTEJUMP) {
        result = 0;
        goto end;
    }
    bd = (DetectBytejumpData *)sm->ctx;
    if (bd->flags & DETECT_BYTEJUMP_BEGIN ||
        bd->flags & DETECT_BYTEJUMP_LITTLE ||
        bd->flags & DETECT_BYTEJUMP_BIG ||
        bd->flags & DETECT_BYTEJUMP_STRING ||
        !(bd->flags & DETECT_BYTEJUMP_RELATIVE) ||
        bd->flags & DETECT_BYTEJUMP_ALIGN ||
        bd->flags & DETECT_BYTEJUMP_DCE ) {
        result = 0;
        printf("one failed\n");
        goto end;
    }

    sm = sm->next;
    if (sm->type != DETECT_CONTENT) {
        result = 0;
        goto end;
    }
    data = (DetectContentData *)sm->ctx;
    if (data->flags & DETECT_CONTENT_RAWBYTES ||
        data->flags & DETECT_CONTENT_NOCASE ||
        !(data->flags & DETECT_CONTENT_WITHIN) ||
        !(data->flags & DETECT_CONTENT_DISTANCE) ||
        data->flags & DETECT_CONTENT_FAST_PATTERN ||
        data->flags & DETECT_CONTENT_NEGATED ) {
        result = 0;
        printf("one failed\n");
        goto end;
    }
    result &= (strncmp((char *)data->content, "one", 3) == 0);
    if (result == 0)
        goto end;

    sm = sm->next;
    if (sm->type != DETECT_CONTENT) {
        result = 0;
        goto end;
    }
    data = (DetectContentData *)sm->ctx;
    if (data->flags & DETECT_CONTENT_RAWBYTES ||
        data->flags & DETECT_CONTENT_NOCASE ||
        !(data->flags & DETECT_CONTENT_WITHIN) ||
        data->flags & DETECT_CONTENT_DISTANCE ||
        data->flags & DETECT_CONTENT_FAST_PATTERN ||
        data->flags & DETECT_CONTENT_NEGATED ) {
        result = 0;
        printf("two failed\n");
        goto end;
    }
    result &= (strncmp((char *)data->content, "two", 3) == 0);
    if (result == 0)
        goto end;

    sm = s->init_data->smlists[DETECT_SM_LIST_PMATCH];
    if (sm->type != DETECT_CONTENT) {
        result = 0;
        goto end;
    }
    data = (DetectContentData *)sm->ctx;
    if (data->flags & DETECT_CONTENT_RAWBYTES ||
        data->flags & DETECT_CONTENT_NOCASE ||
        data->flags & DETECT_CONTENT_WITHIN ||
        data->flags & DETECT_CONTENT_DISTANCE ||
        data->flags & DETECT_CONTENT_FAST_PATTERN ||
        data->flags & DETECT_CONTENT_NEGATED ) {
        printf("three failed\n");
        result = 0;
        goto end;
    }
    result &= (strncmp((char *)data->content, "three", 5) == 0);
    if (result == 0)
        goto end;

    sm = sm->next;
    if (sm->type != DETECT_CONTENT) {
        result = 0;
        goto end;
    }
    data = (DetectContentData *)sm->ctx;
    if (data->flags & DETECT_CONTENT_RAWBYTES ||
        data->flags & DETECT_CONTENT_NOCASE ||
        data->flags & DETECT_CONTENT_WITHIN ||
        data->flags & DETECT_CONTENT_DISTANCE ||
        data->flags & DETECT_CONTENT_FAST_PATTERN ||
        data->flags & DETECT_CONTENT_NEGATED ) {
        printf("four failed\n");
        result = 0;
        goto end;
    }
    result &= (strncmp((char *)data->content, "four", 4) == 0);
    if (result == 0)
        goto end;

 end:
    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);

    return result;
}

/**
 * \test Test content for dce sig.
 */
static int DcePayloadParseTest32(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 1;
    Signature *s = NULL;
    SigMatch *sm = NULL;
    DetectContentData *data = NULL;
    DetectBytejumpData *bd = NULL;

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    s = de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                                   "(msg:\"Testing bytejump_body\"; "
                                   "dce_stub_data; "
                                   "byte_jump:2,5,relative; "
                                   "content:\"one\"; distance:10; within:5; "
                                   "content:\"two\"; within:5;"
                                   "pkt_data; "
                                   "content:\"three\";"
                                   "content:\"four\"; within:4; "
                                   "sid:1;)");
    if (de_ctx->sig_list == NULL) {
        result = 0;
        goto end;
    }

    if (s->init_data->smlists_tail[g_dce_stub_data_buffer_id] == NULL) {
        result = 0;
        goto end;
    }
    if (s->init_data->smlists_tail[DETECT_SM_LIST_PMATCH] == NULL) {
        result = 0;
        goto end;
    }

    sm = s->init_data->smlists[g_dce_stub_data_buffer_id];
    if (sm->type != DETECT_BYTEJUMP) {
        result = 0;
        goto end;
    }
    bd = (DetectBytejumpData *)sm->ctx;
    if (bd->flags & DETECT_BYTEJUMP_BEGIN ||
        bd->flags & DETECT_BYTEJUMP_LITTLE ||
        bd->flags & DETECT_BYTEJUMP_BIG ||
        bd->flags & DETECT_BYTEJUMP_STRING ||
        !(bd->flags & DETECT_BYTEJUMP_RELATIVE) ||
        bd->flags & DETECT_BYTEJUMP_ALIGN ||
        bd->flags & DETECT_BYTEJUMP_DCE ) {
        result = 0;
        printf("one failed\n");
        goto end;
    }

    sm = sm->next;
    if (sm->type != DETECT_CONTENT) {
        result = 0;
        goto end;
    }
    data = (DetectContentData *)sm->ctx;
    if (data->flags & DETECT_CONTENT_RAWBYTES ||
        data->flags & DETECT_CONTENT_NOCASE ||
        !(data->flags & DETECT_CONTENT_WITHIN) ||
        !(data->flags & DETECT_CONTENT_DISTANCE) ||
        data->flags & DETECT_CONTENT_FAST_PATTERN ||
        data->flags & DETECT_CONTENT_NEGATED ) {
        result = 0;
        printf("one failed\n");
        goto end;
    }
    result &= (strncmp((char *)data->content, "one", 3) == 0);
    if (result == 0)
        goto end;

    sm = sm->next;
    if (sm->type != DETECT_CONTENT) {
        result = 0;
        goto end;
    }
    data = (DetectContentData *)sm->ctx;
    if (data->flags & DETECT_CONTENT_RAWBYTES ||
        data->flags & DETECT_CONTENT_NOCASE ||
        !(data->flags & DETECT_CONTENT_WITHIN) ||
        data->flags & DETECT_CONTENT_DISTANCE ||
        data->flags & DETECT_CONTENT_FAST_PATTERN ||
        data->flags & DETECT_CONTENT_NEGATED ) {
        result = 0;
        printf("two failed\n");
        goto end;
    }
    result &= (strncmp((char *)data->content, "two", 3) == 0);
    if (result == 0)
        goto end;

    sm = s->init_data->smlists[DETECT_SM_LIST_PMATCH];
    if (sm->type != DETECT_CONTENT) {
        result = 0;
        goto end;
    }
    data = (DetectContentData *)sm->ctx;
    if (data->flags & DETECT_CONTENT_RAWBYTES ||
        data->flags & DETECT_CONTENT_NOCASE ||
        data->flags & DETECT_CONTENT_WITHIN ||
        data->flags & DETECT_CONTENT_DISTANCE ||
        data->flags & DETECT_CONTENT_FAST_PATTERN ||
        data->flags & DETECT_CONTENT_NEGATED ) {
        printf("three failed\n");
        result = 0;
        goto end;
    }
    result &= (strncmp((char *)data->content, "three", 5) == 0);
    if (result == 0)
        goto end;

    sm = sm->next;
    if (sm->type != DETECT_CONTENT) {
        result = 0;
        goto end;
    }
    data = (DetectContentData *)sm->ctx;
    if (data->flags & DETECT_CONTENT_RAWBYTES ||
        data->flags & DETECT_CONTENT_NOCASE ||
        !(data->flags & DETECT_CONTENT_WITHIN) ||
        data->flags & DETECT_CONTENT_DISTANCE ||
        data->flags & DETECT_CONTENT_FAST_PATTERN ||
        data->flags & DETECT_CONTENT_NEGATED ) {
        printf("four failed\n");
        result = 0;
        goto end;
    }
    result &= (strncmp((char *)data->content, "four", 4) == 0);
    if (result == 0)
        goto end;

 end:
    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);

    return result;
}

/**
 * \test Test content for dce sig.
 */
static int DcePayloadParseTest33(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 1;
    Signature *s = NULL;
    SigMatch *sm = NULL;
    DetectContentData *data = NULL;
    DetectPcreData *pd = NULL;

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    s = de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                                   "(msg:\"Testing bytejump_body\"; "
                                   "dce_stub_data; "
                                   "pcre:/boom/R; "
                                   "content:\"one\"; distance:10; within:5; "
                                   "content:\"two\"; within:5;"
                                   "pkt_data; "
                                   "content:\"three\";"
                                   "content:\"four\"; distance:5;"
                                   "sid:1;)");
    if (de_ctx->sig_list == NULL) {
        result = 0;
        goto end;
    }

    if (s->init_data->smlists_tail[g_dce_stub_data_buffer_id] == NULL) {
        result = 0;
        goto end;
    }
    if (s->init_data->smlists_tail[DETECT_SM_LIST_PMATCH] == NULL) {
        result = 0;
        goto end;
    }

    sm = s->init_data->smlists[g_dce_stub_data_buffer_id];
    if (sm->type != DETECT_PCRE) {
        result = 0;
        goto end;
    }
    pd = (DetectPcreData *)sm->ctx;
    if ( pd->flags & DETECT_PCRE_RAWBYTES ||
         !(pd->flags & DETECT_PCRE_RELATIVE)) {
        result = 0;
        printf("one failed\n");
        goto end;
    }

    sm = sm->next;
    if (sm->type != DETECT_CONTENT) {
        result = 0;
        goto end;
    }
    data = (DetectContentData *)sm->ctx;
    if (data->flags & DETECT_CONTENT_RAWBYTES ||
        data->flags & DETECT_CONTENT_NOCASE ||
        !(data->flags & DETECT_CONTENT_WITHIN) ||
        !(data->flags & DETECT_CONTENT_DISTANCE) ||
        data->flags & DETECT_CONTENT_FAST_PATTERN ||
        data->flags & DETECT_CONTENT_NEGATED ) {
        result = 0;
        printf("one failed\n");
        goto end;
    }
    result &= (strncmp((char *)data->content, "one", 3) == 0);
    if (result == 0)
        goto end;

    sm = sm->next;
    if (sm->type != DETECT_CONTENT) {
        result = 0;
        goto end;
    }
    data = (DetectContentData *)sm->ctx;
    if (data->flags & DETECT_CONTENT_RAWBYTES ||
        data->flags & DETECT_CONTENT_NOCASE ||
        !(data->flags & DETECT_CONTENT_WITHIN) ||
        data->flags & DETECT_CONTENT_DISTANCE ||
        data->flags & DETECT_CONTENT_FAST_PATTERN ||
        data->flags & DETECT_CONTENT_NEGATED ) {
        result = 0;
        printf("two failed\n");
        goto end;
    }
    result &= (strncmp((char *)data->content, "two", 3) == 0);
    if (result == 0)
        goto end;

    sm = s->init_data->smlists[DETECT_SM_LIST_PMATCH];
    if (sm->type != DETECT_CONTENT) {
        result = 0;
        goto end;
    }
    data = (DetectContentData *)sm->ctx;
    if (data->flags & DETECT_CONTENT_RAWBYTES ||
        data->flags & DETECT_CONTENT_NOCASE ||
        data->flags & DETECT_CONTENT_WITHIN ||
        data->flags & DETECT_CONTENT_DISTANCE ||
        data->flags & DETECT_CONTENT_FAST_PATTERN ||
        data->flags & DETECT_CONTENT_NEGATED ) {
        printf("three failed\n");
        result = 0;
        goto end;
    }
    result &= (strncmp((char *)data->content, "three", 5) == 0);
    if (result == 0)
        goto end;

    sm = sm->next;
    if (sm->type != DETECT_CONTENT) {
        result = 0;
        goto end;
    }
    data = (DetectContentData *)sm->ctx;
    if (data->flags & DETECT_CONTENT_RAWBYTES ||
        data->flags & DETECT_CONTENT_NOCASE ||
        data->flags & DETECT_CONTENT_WITHIN ||
        !(data->flags & DETECT_CONTENT_DISTANCE) ||
        data->flags & DETECT_CONTENT_FAST_PATTERN ||
        data->flags & DETECT_CONTENT_NEGATED ) {
        printf("four failed\n");
        result = 0;
        goto end;
    }
    result &= (strncmp((char *)data->content, "four", 4) == 0);
    if (result == 0)
        goto end;

 end:
    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);

    return result;
}

/**
 * \test Test content for dce sig.
 */
static int DcePayloadParseTest34(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 1;
    Signature *s = NULL;
    SigMatch *sm = NULL;
    DetectContentData *data = NULL;
    DetectPcreData *pd = NULL;
    DetectBytejumpData *bd = NULL;

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    s = de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                                   "(msg:\"Testing bytejump_body\"; "
                                   "dce_iface:12345678-1234-1234-1234-123456789012; "
                                   "dce_opnum:10; dce_stub_data; "
                                   "pcre:/boom/R; "
                                   "byte_jump:1,2,relative,align,dce; "
                                   "content:\"one\"; within:4; distance:8; "
                                   "pkt_data; "
                                   "content:\"two\"; "
                                   "sid:1;)");
    if (de_ctx->sig_list == NULL) {
        result = 0;
        goto end;
    }

    if (s->init_data->smlists_tail[g_dce_stub_data_buffer_id] == NULL) {
        result = 0;
        goto end;
    }
    if (s->init_data->smlists_tail[DETECT_SM_LIST_PMATCH] == NULL) {
        result = 0;
        goto end;
    }

    sm = s->init_data->smlists[g_dce_stub_data_buffer_id];
    if (sm->type != DETECT_PCRE) {
        result = 0;
        goto end;
    }
    pd = (DetectPcreData *)sm->ctx;
    if ( pd->flags & DETECT_PCRE_RAWBYTES ||
         !(pd->flags & DETECT_PCRE_RELATIVE)) {
        result = 0;
        goto end;
    }

    sm = sm->next;
    if (sm->type != DETECT_BYTEJUMP) {
        result = 0;
        goto end;
    }
    bd = (DetectBytejumpData *)sm->ctx;
    if (bd->flags & DETECT_BYTEJUMP_BEGIN ||
        bd->flags & DETECT_BYTEJUMP_LITTLE ||
        bd->flags & DETECT_BYTEJUMP_BIG ||
        bd->flags & DETECT_BYTEJUMP_STRING ||
        !(bd->flags & DETECT_BYTEJUMP_RELATIVE) ||
        !(bd->flags & DETECT_BYTEJUMP_ALIGN) ||
        !(bd->flags & DETECT_BYTEJUMP_DCE) ) {
        result = 0;
        printf("one failed\n");
        goto end;
    }

    sm = sm->next;
    if (sm->type != DETECT_CONTENT) {
        result = 0;
        goto end;
    }
    data = (DetectContentData *)sm->ctx;
    if (data->flags & DETECT_CONTENT_RAWBYTES ||
        data->flags & DETECT_CONTENT_NOCASE ||
        !(data->flags & DETECT_CONTENT_WITHIN) ||
        !(data->flags & DETECT_CONTENT_DISTANCE) ||
        data->flags & DETECT_CONTENT_FAST_PATTERN ||
        data->flags & DETECT_CONTENT_NEGATED ) {
        result = 0;
        printf("two failed\n");
        goto end;
    }
    result &= (strncmp((char *)data->content, "one", 3) == 0);
    if (result == 0)
        goto end;

    result &= (sm->next == NULL);

    sm = s->init_data->smlists[DETECT_SM_LIST_PMATCH];
    if (sm->type != DETECT_CONTENT) {
        result = 0;
        goto end;
    }
    data = (DetectContentData *)sm->ctx;
    if (data->flags & DETECT_CONTENT_RAWBYTES ||
        data->flags & DETECT_CONTENT_NOCASE ||
        data->flags & DETECT_CONTENT_WITHIN ||
        data->flags & DETECT_CONTENT_DISTANCE ||
        data->flags & DETECT_CONTENT_FAST_PATTERN ||
        data->flags & DETECT_CONTENT_NEGATED ) {
        printf("three failed\n");
        result = 0;
        goto end;
    }
    result &= (strncmp((char *)data->content, "two", 3) == 0);
    if (result == 0)
        goto end;

    result &= (sm->next == NULL);

 end:
    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);

    return result;
}

/**
 * \test Test content for dce sig.
 */
static int DcePayloadParseTest35(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 1;
    Signature *s = NULL;
    SigMatch *sm = NULL;
    DetectContentData *data = NULL;
    DetectBytetestData *bd = NULL;

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    s = de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                                   "(msg:\"Testing bytejump_body\"; "
                                   "dce_iface:12345678-1234-1234-1234-123456789012; "
                                   "dce_opnum:10; dce_stub_data; "
                                   "byte_test:1,=,0,0,relative,dce; "
                                   "pkt_data; "
                                   "content:\"one\"; "
                                   "sid:1;)");
    if (de_ctx->sig_list == NULL) {
        result = 0;
        goto end;
    }

    if (s->init_data->smlists_tail[g_dce_stub_data_buffer_id] == NULL) {
        result = 0;
        goto end;
    }
    if (s->init_data->smlists_tail[DETECT_SM_LIST_PMATCH] == NULL) {
        result = 0;
        goto end;
    }

    sm = s->init_data->smlists[g_dce_stub_data_buffer_id];
    if (sm->type != DETECT_BYTETEST) {
        result = 0;
        goto end;
    }
    bd = (DetectBytetestData *)sm->ctx;
    if (bd->flags & DETECT_BYTETEST_LITTLE ||
        bd->flags & DETECT_BYTETEST_BIG ||
        bd->flags & DETECT_BYTETEST_STRING ||
        !(bd->flags & DETECT_BYTEJUMP_RELATIVE) ||
        !(bd->flags & DETECT_BYTETEST_DCE) ) {
        result = 0;
        printf("one failed\n");
        goto end;
    }

    result &= (sm->next == NULL);

    sm = s->init_data->smlists[DETECT_SM_LIST_PMATCH];
    if (sm->type != DETECT_CONTENT) {
        result = 0;
        goto end;
    }
    data = (DetectContentData *)sm->ctx;
    if (data->flags & DETECT_CONTENT_RAWBYTES ||
        data->flags & DETECT_CONTENT_NOCASE ||
        data->flags & DETECT_CONTENT_WITHIN ||
        data->flags & DETECT_CONTENT_DISTANCE ||
        data->flags & DETECT_CONTENT_FAST_PATTERN ||
        data->flags & DETECT_CONTENT_NEGATED ) {
        result = 0;
        printf("two failed\n");
        goto end;
    }
    result &= (strncmp((char *)data->content, "one", 3) == 0);
    if (result == 0)
        goto end;

    result &= (sm->next == NULL);

 end:
    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);

    return result;
}

/**
 * \test Test content for dce sig.
 */
static int DcePayloadParseTest36(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 1;
    Signature *s = NULL;
    SigMatch *sm = NULL;
    DetectContentData *data = NULL;
    DetectIsdataatData *isd = NULL;

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    s = de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                                   "(msg:\"Testing bytejump_body\"; "
                                   "dce_iface:12345678-1234-1234-1234-123456789012; "
                                   "dce_opnum:10; dce_stub_data; "
                                   "isdataat:10,relative; "
                                   "content:\"one\"; within:4; distance:8; "
                                   "pkt_data; "
                                   "content:\"two\"; "
                                   "sid:1;)");
    if (de_ctx->sig_list == NULL) {
        result = 0;
        goto end;
    }

    if (s->init_data->smlists_tail[g_dce_stub_data_buffer_id] == NULL) {
        result = 0;
        goto end;
    }
    if (s->init_data->smlists_tail[DETECT_SM_LIST_PMATCH] == NULL) {
        result = 0;
        goto end;
    }

    sm = s->init_data->smlists[g_dce_stub_data_buffer_id];
    if (sm->type != DETECT_ISDATAAT) {
        result = 0;
        goto end;
    }
    isd = (DetectIsdataatData *)sm->ctx;
    if ( isd->flags & ISDATAAT_RAWBYTES ||
         !(isd->flags & ISDATAAT_RELATIVE)) {
        result = 0;
        goto end;
    }

    sm = sm->next;
    if (sm->type != DETECT_CONTENT) {
        result = 0;
        goto end;
    }
    data = (DetectContentData *)sm->ctx;
    if (data->flags & DETECT_CONTENT_RAWBYTES ||
        data->flags & DETECT_CONTENT_NOCASE ||
        !(data->flags & DETECT_CONTENT_WITHIN) ||
        !(data->flags & DETECT_CONTENT_DISTANCE) ||
        data->flags & DETECT_CONTENT_FAST_PATTERN ||
        data->flags & DETECT_CONTENT_NEGATED ) {
        result = 0;
        printf("two failed\n");
        goto end;
    }
    result &= (strncmp((char *)data->content, "one", 3) == 0);
    if (result == 0)
        goto end;

    result &= (sm->next == NULL);

    sm = s->init_data->smlists[DETECT_SM_LIST_PMATCH];
    if (sm->type != DETECT_CONTENT) {
        result = 0;
        goto end;
    }
    data = (DetectContentData *)sm->ctx;
    if (data->flags & DETECT_CONTENT_RAWBYTES ||
        data->flags & DETECT_CONTENT_NOCASE ||
        data->flags & DETECT_CONTENT_WITHIN ||
        data->flags & DETECT_CONTENT_DISTANCE ||
        data->flags & DETECT_CONTENT_FAST_PATTERN ||
        data->flags & DETECT_CONTENT_NEGATED ) {
        printf("three failed\n");
        result = 0;
        goto end;
    }
    result &= (strncmp((char *)data->content, "two", 3) == 0);
    if (result == 0)
        goto end;

    result &= (sm->next == NULL);

 end:
    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);

    return result;
}

/**
 * \test Test content for dce sig.
 */
static int DcePayloadParseTest37(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 1;
    Signature *s = NULL;
    SigMatch *sm = NULL;
    DetectContentData *data = NULL;
    DetectBytejumpData *bjd = NULL;
    DetectBytetestData *btd = NULL;

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    s = de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                                   "(msg:\"Testing bytejump_body\"; "
                                   "dce_iface:12345678-1234-1234-1234-123456789012; "
                                   "dce_opnum:10; dce_stub_data; "
                                   "byte_jump:1,2,relative,align,dce; "
                                   "byte_test:1,=,2,0,relative,dce; "
                                   "pkt_data; "
                                   "content:\"one\"; "
                                   "sid:1;)");
    if (de_ctx->sig_list == NULL) {
        result = 0;
        goto end;
    }

    if (s->init_data->smlists_tail[g_dce_stub_data_buffer_id] == NULL) {
        result = 0;
        goto end;
    }
    if (s->init_data->smlists_tail[DETECT_SM_LIST_PMATCH] == NULL) {
        result = 0;
        goto end;
    }

    sm = s->init_data->smlists[g_dce_stub_data_buffer_id];
    if (sm->type != DETECT_BYTEJUMP) {
        result = 0;
        goto end;
    }
    bjd = (DetectBytejumpData *)sm->ctx;
    if (bjd->flags & DETECT_BYTEJUMP_BEGIN ||
        bjd->flags & DETECT_BYTEJUMP_LITTLE ||
        bjd->flags & DETECT_BYTEJUMP_BIG ||
        bjd->flags & DETECT_BYTEJUMP_STRING ||
        !(bjd->flags & DETECT_BYTEJUMP_RELATIVE) ||
        !(bjd->flags & DETECT_BYTEJUMP_ALIGN) ||
        !(bjd->flags & DETECT_BYTEJUMP_DCE) ) {
        result = 0;
        printf("one failed\n");
        goto end;
    }

    sm = sm->next;
    if (sm->type != DETECT_BYTETEST) {
        result = 0;
        goto end;
    }
    btd = (DetectBytetestData *)sm->ctx;
    if (btd->flags & DETECT_BYTETEST_LITTLE ||
        btd->flags & DETECT_BYTETEST_BIG ||
        btd->flags & DETECT_BYTETEST_STRING ||
        !(btd->flags & DETECT_BYTETEST_RELATIVE) ||
        !(btd->flags & DETECT_BYTETEST_DCE) ) {
        result = 0;
        printf("one failed\n");
        goto end;
    }

    result &= (sm->next == NULL);

    sm = s->init_data->smlists[DETECT_SM_LIST_PMATCH];
    if (sm->type != DETECT_CONTENT) {
        result = 0;
        goto end;
    }
    data = (DetectContentData *)sm->ctx;
    if (data->flags & DETECT_CONTENT_RAWBYTES ||
        data->flags & DETECT_CONTENT_NOCASE ||
        data->flags & DETECT_CONTENT_WITHIN ||
        data->flags & DETECT_CONTENT_DISTANCE ||
        data->flags & DETECT_CONTENT_FAST_PATTERN ||
        data->flags & DETECT_CONTENT_NEGATED ) {
        printf("three failed\n");
        result = 0;
        goto end;
    }
    result &= (strncmp((char *)data->content, "one", 3) == 0);
    if (result == 0)
        goto end;

    result &= (sm->next == NULL);

 end:
    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);

    return result;
}

/**
 * \test Test content for dce sig.
 */
static int DcePayloadParseTest38(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 1;
    Signature *s = NULL;
    SigMatch *sm = NULL;
    DetectContentData *data = NULL;
    DetectPcreData *pd = NULL;
    DetectBytejumpData *bjd = NULL;
    DetectBytetestData *btd = NULL;

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    s = de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                                   "(msg:\"Testing bytejump_body\"; "
                                   "dce_iface:12345678-1234-1234-1234-123456789012; "
                                   "dce_opnum:10; dce_stub_data; "
                                   "pcre:/boom/R; "
                                   "byte_jump:1,2,relative,align,dce; "
                                   "byte_test:1,=,2,0,relative,dce; "
                                   "pkt_data; "
                                   "content:\"one\"; "
                                   "sid:1;)");
    if (de_ctx->sig_list == NULL) {
        result = 0;
        goto end;
    }

    if (s->init_data->smlists_tail[g_dce_stub_data_buffer_id] == NULL) {
        result = 0;
        goto end;
    }
    if (s->init_data->smlists_tail[DETECT_SM_LIST_PMATCH] == NULL) {
        result = 0;
        goto end;
    }

    sm = s->init_data->smlists[g_dce_stub_data_buffer_id];
    if (sm->type != DETECT_PCRE) {
        result = 0;
        goto end;
    }
    pd = (DetectPcreData *)sm->ctx;
    if ( pd->flags & DETECT_PCRE_RAWBYTES ||
         !(pd->flags & DETECT_PCRE_RELATIVE)) {
        result = 0;
        printf("one failed\n");
        goto end;
    }

    sm = sm->next;
    if (sm->type != DETECT_BYTEJUMP) {
        result = 0;
        goto end;
    }
    bjd = (DetectBytejumpData *)sm->ctx;
    if (bjd->flags & DETECT_BYTEJUMP_BEGIN ||
        bjd->flags & DETECT_BYTEJUMP_LITTLE ||
        bjd->flags & DETECT_BYTEJUMP_BIG ||
        bjd->flags & DETECT_BYTEJUMP_STRING ||
        !(bjd->flags & DETECT_BYTEJUMP_RELATIVE) ||
        !(bjd->flags & DETECT_BYTEJUMP_ALIGN) ||
        !(bjd->flags & DETECT_BYTEJUMP_DCE) ) {
        result = 0;
        printf("one failed\n");
        goto end;
    }

    sm = sm->next;
    if (sm->type != DETECT_BYTETEST) {
        result = 0;
        goto end;
    }
    btd = (DetectBytetestData *)sm->ctx;
    if (btd->flags & DETECT_BYTETEST_LITTLE ||
        btd->flags & DETECT_BYTETEST_BIG ||
        btd->flags & DETECT_BYTETEST_STRING ||
        !(btd->flags & DETECT_BYTETEST_RELATIVE) ||
        !(btd->flags & DETECT_BYTETEST_DCE) ) {
        result = 0;
        printf("one failed\n");
        goto end;
    }

    result &= (sm->next == NULL);

    sm = s->init_data->smlists[DETECT_SM_LIST_PMATCH];
    if (sm->type != DETECT_CONTENT) {
        result = 0;
        goto end;
    }
    data = (DetectContentData *)sm->ctx;
    if (data->flags & DETECT_CONTENT_RAWBYTES ||
        data->flags & DETECT_CONTENT_NOCASE ||
        data->flags & DETECT_CONTENT_WITHIN ||
        data->flags & DETECT_CONTENT_DISTANCE ||
        data->flags & DETECT_CONTENT_FAST_PATTERN ||
        data->flags & DETECT_CONTENT_NEGATED ) {
        printf("three failed\n");
        result = 0;
        goto end;
    }
    result &= (strncmp((char *)data->content, "one", 3) == 0);
    if (result == 0)
        goto end;

    result &= (sm->next == NULL);

 end:
    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);

    return result;
}

/**
 * \test Test content for dce sig.
 */
static int DcePayloadParseTest39(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 1;
    Signature *s = NULL;
    SigMatch *sm = NULL;
    DetectContentData *data = NULL;

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    s = de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                                   "(msg:\"Testing bytejump_body\"; "
                                   "content:\"one\"; "
                                   "dce_iface:12345678-1234-1234-1234-123456789012; "
                                   "dce_opnum:10; dce_stub_data; "
                                   "content:\"two\"; within:4; distance:8; "
                                   "sid:1;)");
    if (de_ctx->sig_list == NULL) {
        result = 0;
        goto end;
    }

    if (s->init_data->smlists_tail[g_dce_stub_data_buffer_id] == NULL) {
        result = 0;
        goto end;
    }
    if (s->init_data->smlists_tail[DETECT_SM_LIST_PMATCH] == NULL) {
        result = 0;
        goto end;
    }

    sm = s->init_data->smlists[DETECT_SM_LIST_PMATCH];
    if (sm->type != DETECT_CONTENT) {
        result = 0;
        goto end;
    }
    data = (DetectContentData *)sm->ctx;
    if (data->flags & DETECT_CONTENT_RAWBYTES ||
        data->flags & DETECT_CONTENT_NOCASE ||
        data->flags & DETECT_CONTENT_WITHIN ||
        data->flags & DETECT_CONTENT_DISTANCE ||
        data->flags & DETECT_CONTENT_FAST_PATTERN ||
        data->flags & DETECT_CONTENT_NEGATED ) {
        printf("three failed\n");
        result = 0;
        goto end;
    }
    result &= (strncmp((char *)data->content, "one", 3) == 0);
    if (result == 0)
        goto end;

    result &= (sm->next == NULL);

    sm = s->init_data->smlists[g_dce_stub_data_buffer_id];
    data = (DetectContentData *)sm->ctx;
    if (data->flags & DETECT_CONTENT_RAWBYTES ||
        data->flags & DETECT_CONTENT_NOCASE ||
        !(data->flags & DETECT_CONTENT_WITHIN) ||
        !(data->flags & DETECT_CONTENT_DISTANCE) ||
        data->flags & DETECT_CONTENT_FAST_PATTERN ||
        data->flags & DETECT_CONTENT_NEGATED ) {
        printf("three failed\n");
        result = 0;
        goto end;
    }
    result &= (strncmp((char *)data->content, "two", 3) == 0);
    if (result == 0)
        goto end;

    result &= (sm->next == NULL);

 end:
    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);

    return result;
}

/**
 * \test Test content for dce sig.
 */
static int DcePayloadParseTest40(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 1;
    Signature *s = NULL;
    SigMatch *sm = NULL;
    DetectContentData *data = NULL;
    DetectBytetestData *btd = NULL;

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    s = de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                                   "(msg:\"Testing bytejump_body\"; "
                                   "dce_iface:12345678-1234-1234-1234-123456789012; "
                                   "dce_opnum:10; dce_stub_data; "
                                   "content:\"one\"; within:10; "
                                   "content:\"two\"; distance:20; within:30; "
                                   "byte_test:1,=,2,0,relative,dce; "
                                   "pkt_data; "
                                   "content:\"three\"; "
                                   "sid:1;)");
    if (de_ctx->sig_list == NULL) {
        result = 0;
        goto end;
    }

    if (s->init_data->smlists_tail[g_dce_stub_data_buffer_id] == NULL) {
        result = 0;
        goto end;
    }
    if (s->init_data->smlists_tail[DETECT_SM_LIST_PMATCH] == NULL) {
        result = 0;
        goto end;
    }

    sm = s->init_data->smlists[g_dce_stub_data_buffer_id];
    if (sm->type != DETECT_CONTENT) {
        result = 0;
        goto end;
    }
    data = (DetectContentData *)sm->ctx;
    if (data->flags & DETECT_CONTENT_RAWBYTES ||
        data->flags & DETECT_CONTENT_NOCASE ||
        !(data->flags & DETECT_CONTENT_WITHIN) ||
        data->flags & DETECT_CONTENT_DISTANCE ||
        data->flags & DETECT_CONTENT_FAST_PATTERN ||
        data->flags & DETECT_CONTENT_NEGATED ) {
        printf("three failed\n");
        result = 0;
        goto end;
    }
    result &= (strncmp((char *)data->content, "one", 3) == 0);
    if (result == 0)
        goto end;


    sm = sm->next;
    if (sm->type != DETECT_CONTENT) {
        result = 0;
        goto end;
    }
    data = (DetectContentData *)sm->ctx;
    if (data->flags & DETECT_CONTENT_RAWBYTES ||
        data->flags & DETECT_CONTENT_NOCASE ||
        !(data->flags & DETECT_CONTENT_WITHIN) ||
        !(data->flags & DETECT_CONTENT_DISTANCE) ||
        data->flags & DETECT_CONTENT_FAST_PATTERN ||
        data->flags & DETECT_CONTENT_NEGATED ) {
        printf("three failed\n");
        result = 0;
        goto end;
    }
    result &= (strncmp((char *)data->content, "two", 3) == 0);
    if (result == 0)
        goto end;

    sm = sm->next;
    if (sm->type != DETECT_BYTETEST) {
        result = 0;
        goto end;
    }
    btd = (DetectBytetestData *)sm->ctx;
    if (btd->flags & DETECT_BYTETEST_LITTLE ||
        btd->flags & DETECT_BYTETEST_BIG ||
        btd->flags & DETECT_BYTETEST_STRING ||
        !(btd->flags & DETECT_BYTETEST_RELATIVE) ||
        !(btd->flags & DETECT_BYTETEST_DCE) ) {
        result = 0;
        printf("one failed\n");
        goto end;
    }

    result &= (sm->next == NULL);

    sm = s->init_data->smlists[DETECT_SM_LIST_PMATCH];
    if (sm->type != DETECT_CONTENT) {
        result = 0;
        goto end;
    }
    data = (DetectContentData *)sm->ctx;
    if (data->flags & DETECT_CONTENT_RAWBYTES ||
        data->flags & DETECT_CONTENT_NOCASE ||
        data->flags & DETECT_CONTENT_WITHIN ||
        data->flags & DETECT_CONTENT_DISTANCE ||
        data->flags & DETECT_CONTENT_FAST_PATTERN ||
        data->flags & DETECT_CONTENT_NEGATED ) {
        printf("three failed\n");
        result = 0;
        goto end;
    }
    result &= (strncmp((char *)data->content, "three", 5) == 0);
    if (result == 0)
        goto end;

    result &= (sm->next == NULL);

 end:
    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);

    return result;
}

/**
 * \test Test content for dce sig.
 */
static int DcePayloadParseTest41(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 1;
    Signature *s = NULL;
    SigMatch *sm = NULL;
    DetectContentData *data = NULL;
    DetectBytetestData *btd = NULL;

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    s = de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                                   "(msg:\"Testing bytejump_body\"; "
                                   "dce_iface:12345678-1234-1234-1234-123456789012; "
                                   "dce_opnum:10; dce_stub_data; "
                                   "content:\"one\"; within:10; "
                                   "pkt_data; "
                                   "content:\"two\"; "
                                   "byte_test:1,=,2,0,relative,dce; "
                                   "content:\"three\"; "
                                   "sid:1;)");
    if (de_ctx->sig_list == NULL) {
        result = 0;
        goto end;
    }

    if (s->init_data->smlists_tail[g_dce_stub_data_buffer_id] == NULL) {
        result = 0;
        goto end;
    }
    if (s->init_data->smlists_tail[DETECT_SM_LIST_PMATCH] == NULL) {
        result = 0;
        goto end;
    }

    sm = s->init_data->smlists[g_dce_stub_data_buffer_id];
    if (sm->type != DETECT_CONTENT) {
        result = 0;
        goto end;
    }
    data = (DetectContentData *)sm->ctx;
    if (data->flags & DETECT_CONTENT_RAWBYTES ||
        data->flags & DETECT_CONTENT_NOCASE ||
        !(data->flags & DETECT_CONTENT_WITHIN) ||
        data->flags & DETECT_CONTENT_DISTANCE ||
        data->flags & DETECT_CONTENT_FAST_PATTERN ||
        data->flags & DETECT_CONTENT_NEGATED ) {
        printf("three failed\n");
        result = 0;
        goto end;
    }
    result &= (strncmp((char *)data->content, "one", 3) == 0);
    if (result == 0)
        goto end;

    result &= (sm->next == NULL);

    sm = s->init_data->smlists[DETECT_SM_LIST_PMATCH];
    if (sm->type != DETECT_CONTENT) {
        result = 0;
        goto end;
    }
    data = (DetectContentData *)sm->ctx;
    if (data->flags & DETECT_CONTENT_RAWBYTES ||
        data->flags & DETECT_CONTENT_NOCASE ||
        data->flags & DETECT_CONTENT_WITHIN ||
        data->flags & DETECT_CONTENT_DISTANCE ||
        data->flags & DETECT_CONTENT_FAST_PATTERN ||
        data->flags & DETECT_CONTENT_NEGATED ) {
        printf("three failed\n");
        result = 0;
        goto end;
    }
    result &= (strncmp((char *)data->content, "two", 3) == 0);
    if (result == 0)
        goto end;

    sm = sm->next;
    if (sm->type != DETECT_BYTETEST) {
        result = 0;
        goto end;
    }
    btd = (DetectBytetestData *)sm->ctx;
    if (btd->flags & DETECT_BYTETEST_LITTLE ||
        btd->flags & DETECT_BYTETEST_BIG ||
        btd->flags & DETECT_BYTETEST_STRING ||
        !(btd->flags & DETECT_BYTETEST_RELATIVE) ||
        !(btd->flags & DETECT_BYTETEST_DCE) ) {
        result = 0;
        printf("one failed\n");
        goto end;
    }

    sm = sm->next;
    if (sm->type != DETECT_CONTENT) {
        result = 0;
        goto end;
    }
    data = (DetectContentData *)sm->ctx;
    if (data->flags & DETECT_CONTENT_RAWBYTES ||
        data->flags & DETECT_CONTENT_NOCASE ||
        data->flags & DETECT_CONTENT_WITHIN ||
        data->flags & DETECT_CONTENT_DISTANCE ||
        data->flags & DETECT_CONTENT_FAST_PATTERN ||
        data->flags & DETECT_CONTENT_NEGATED ) {
        printf("three failed\n");
        result = 0;
        goto end;
    }
    result &= (strncmp((char *)data->content, "three", 5) == 0);
    if (result == 0)
        goto end;

    result &= (sm->next == NULL);

 end:
    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);

    return result;
}

/**
 * \test Test content for dce sig.
 */
static int DcePayloadParseTest44(void)
{
    DetectEngineCtx *de_ctx = NULL;
    Signature *s = NULL;
    SigMatch *sm = NULL;
    DetectContentData *data = NULL;
    DetectIsdataatData *isd = NULL;

    de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    de_ctx->flags |= DE_QUIET;

    s = DetectEngineAppendSig(de_ctx, "alert tcp any any -> any any ("
            "content:\"one\"; "
            "dce_iface:12345678-1234-1234-1234-123456789012; "
            "dce_opnum:10; dce_stub_data; "
            "isdataat:10,relative; "
            "content:\"one\"; within:4; distance:8; "
            "pkt_data; "
            "content:\"two\"; "
            "sid:1;)");
    FAIL_IF_NULL(s);

    FAIL_IF_NULL(s->init_data->smlists_tail[g_dce_stub_data_buffer_id]);
    FAIL_IF_NULL(s->init_data->smlists_tail[DETECT_SM_LIST_PMATCH]);

    /* isdataat:10,relative; */
    sm = s->init_data->smlists[g_dce_stub_data_buffer_id];
    FAIL_IF(sm->type != DETECT_ISDATAAT);
    isd = (DetectIsdataatData *)sm->ctx;
    FAIL_IF(isd->flags & ISDATAAT_RAWBYTES);
    FAIL_IF_NOT(isd->flags & ISDATAAT_RELATIVE);
    FAIL_IF_NULL(sm->next);

    sm = sm->next;

    /* content:\"one\"; within:4; distance:8; */
    FAIL_IF(sm->type != DETECT_CONTENT);
    data = (DetectContentData *)sm->ctx;
    FAIL_IF (data->flags & DETECT_CONTENT_RAWBYTES ||
            data->flags & DETECT_CONTENT_NOCASE ||
            !(data->flags & DETECT_CONTENT_WITHIN) ||
            !(data->flags & DETECT_CONTENT_DISTANCE) ||
            data->flags & DETECT_CONTENT_FAST_PATTERN ||
            data->flags & DETECT_CONTENT_RELATIVE_NEXT ||
            data->flags & DETECT_CONTENT_NEGATED );

    FAIL_IF_NOT(strncmp((char *)data->content, "one", 3) == 0);
    FAIL_IF_NOT(sm->next == NULL);

    /* first content:\"one\"; */
    sm = s->init_data->smlists[DETECT_SM_LIST_PMATCH];
    FAIL_IF(sm->type != DETECT_CONTENT);
    data = (DetectContentData *)sm->ctx;
    FAIL_IF(data->flags & DETECT_CONTENT_RAWBYTES);
    FAIL_IF(data->flags & DETECT_CONTENT_NOCASE);
    FAIL_IF(data->flags & DETECT_CONTENT_WITHIN);
    FAIL_IF(data->flags & DETECT_CONTENT_DISTANCE);
    FAIL_IF(data->flags & DETECT_CONTENT_FAST_PATTERN);
    FAIL_IF(data->flags & DETECT_CONTENT_RELATIVE_NEXT);
    FAIL_IF(data->flags & DETECT_CONTENT_NEGATED );
    FAIL_IF_NOT(strncmp((char *)data->content, "one", 3) == 0);

    FAIL_IF_NULL(sm->next);
    sm = sm->next;

    FAIL_IF(sm->type != DETECT_CONTENT);

    data = (DetectContentData *)sm->ctx;
    FAIL_IF(data->flags & DETECT_CONTENT_RAWBYTES ||
            data->flags & DETECT_CONTENT_NOCASE ||
            data->flags & DETECT_CONTENT_WITHIN ||
            data->flags & DETECT_CONTENT_DISTANCE ||
            data->flags & DETECT_CONTENT_FAST_PATTERN ||
            data->flags & DETECT_CONTENT_NEGATED );

    FAIL_IF_NOT(strncmp((char *)data->content, "two", 3) == 0);

    FAIL_IF_NOT(sm->next == NULL);

    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);

    PASS;
}

/**
 * \test Test content for dce sig.
 */
static int DcePayloadParseTest45(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 1;
    Signature *s = NULL;
    SigMatch *sm = NULL;
    DetectContentData *data = NULL;
    DetectBytejumpData *bjd = NULL;

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    s = de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                                   "(msg:\"Testing bytejump_body\"; "
                                   "dce_iface:12345678-1234-1234-1234-123456789012; "
                                   "content:\"one\"; "
                                   "dce_opnum:10; dce_stub_data; "
                                   "byte_jump:1,2,relative,align,dce; "
                                   "pkt_data; "
                                   "content:\"two\"; "
                                   "sid:1;)");
    if (de_ctx->sig_list == NULL) {
        result = 0;
        goto end;
    }

    if (s->init_data->smlists_tail[g_dce_stub_data_buffer_id] == NULL) {
        result = 0;
        goto end;
    }
    if (s->init_data->smlists_tail[DETECT_SM_LIST_PMATCH] == NULL) {
        result = 0;
        goto end;
    }

    sm = s->init_data->smlists[g_dce_stub_data_buffer_id];
    if (sm->type != DETECT_BYTEJUMP) {
        result = 0;
        goto end;
    }
    bjd = (DetectBytejumpData *)sm->ctx;
    if (bjd->flags & DETECT_BYTEJUMP_BEGIN ||
        bjd->flags & DETECT_BYTEJUMP_LITTLE ||
        bjd->flags & DETECT_BYTEJUMP_BIG ||
        bjd->flags & DETECT_BYTEJUMP_STRING ||
        !(bjd->flags & DETECT_BYTEJUMP_RELATIVE) ||
        !(bjd->flags & DETECT_BYTEJUMP_ALIGN) ||
        !(bjd->flags & DETECT_BYTEJUMP_DCE) ) {
        result = 0;
        printf("one failed\n");
        goto end;
    }

    result &= (sm->next == NULL);

    sm = s->init_data->smlists[DETECT_SM_LIST_PMATCH];
    if (sm->type != DETECT_CONTENT) {
        result = 0;
        goto end;
    }
    data = (DetectContentData *)sm->ctx;
    if (data->flags & DETECT_CONTENT_RAWBYTES ||
        data->flags & DETECT_CONTENT_NOCASE ||
        data->flags & DETECT_CONTENT_WITHIN ||
        data->flags & DETECT_CONTENT_DISTANCE ||
        data->flags & DETECT_CONTENT_FAST_PATTERN ||
        data->flags & DETECT_CONTENT_RELATIVE_NEXT ||
        data->flags & DETECT_CONTENT_NEGATED ) {
        printf("one failed\n");
        result = 0;
        goto end;
    }
    result &= (strncmp((char *)data->content, "one", 3) == 0);
    if (result == 0)
        goto end;

    sm = sm->next;
    if (sm->type != DETECT_CONTENT) {
        result = 0;
        goto end;
    }
    data = (DetectContentData *)sm->ctx;
    if (data->flags & DETECT_CONTENT_RAWBYTES ||
        data->flags & DETECT_CONTENT_NOCASE ||
        data->flags & DETECT_CONTENT_WITHIN ||
        data->flags & DETECT_CONTENT_DISTANCE ||
        data->flags & DETECT_CONTENT_FAST_PATTERN ||
        data->flags & DETECT_CONTENT_RELATIVE_NEXT ||
        data->flags & DETECT_CONTENT_NEGATED ) {
        printf("two failed\n");
        result = 0;
        goto end;
    }
    result &= (strncmp((char *)data->content, "two", 3) == 0);
    if (result == 0)
        goto end;

    result &= (sm->next == NULL);

 end:
    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);

    return result;
}

/**
 * \test Test content for dce sig.
 */
static int DcePayloadParseTest46(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 1;
    Signature *s = NULL;
    SigMatch *sm = NULL;
    DetectContentData *data = NULL;
    DetectBytetestData *btd = NULL;

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    s = de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                                   "(msg:\"Testing bytejump_body\"; "
                                   "dce_iface:12345678-1234-1234-1234-123456789012; "
                                   "content:\"one\"; "
                                   "dce_opnum:10; dce_stub_data; "
                                   "byte_test:1,=,2,0,relative,dce; "
                                   "pkt_data; "
                                   "content:\"two\"; "
                                   "sid:1;)");
    if (de_ctx->sig_list == NULL) {
        result = 0;
        goto end;
    }

    if (s->init_data->smlists_tail[g_dce_stub_data_buffer_id] == NULL) {
        result = 0;
        goto end;
    }
    if (s->init_data->smlists_tail[DETECT_SM_LIST_PMATCH] == NULL) {
        result = 0;
        goto end;
    }

    sm = s->init_data->smlists[g_dce_stub_data_buffer_id];
    if (sm->type != DETECT_BYTETEST) {
        result = 0;
        goto end;
    }
    btd = (DetectBytetestData *)sm->ctx;
    if (btd->flags & DETECT_BYTETEST_LITTLE ||
        btd->flags & DETECT_BYTETEST_BIG ||
        btd->flags & DETECT_BYTETEST_STRING ||
        !(btd->flags & DETECT_BYTETEST_RELATIVE) ||
        !(btd->flags & DETECT_BYTETEST_DCE) ) {
        result = 0;
        printf("one failed\n");
        goto end;
    }

    result &= (sm->next == NULL);

    sm = s->init_data->smlists[DETECT_SM_LIST_PMATCH];
    if (sm->type != DETECT_CONTENT) {
        result = 0;
        goto end;
    }
    data = (DetectContentData *)sm->ctx;
    if (data->flags & DETECT_CONTENT_RAWBYTES ||
        data->flags & DETECT_CONTENT_NOCASE ||
        data->flags & DETECT_CONTENT_WITHIN ||
        data->flags & DETECT_CONTENT_DISTANCE ||
        data->flags & DETECT_CONTENT_FAST_PATTERN ||
        data->flags & DETECT_CONTENT_RELATIVE_NEXT ||
        data->flags & DETECT_CONTENT_NEGATED ) {
        printf("one failed\n");
        result = 0;
        goto end;
    }
    result &= (strncmp((char *)data->content, "one", 3) == 0);
    if (result == 0)
        goto end;

    sm = sm->next;
    if (sm->type != DETECT_CONTENT) {
        result = 0;
        goto end;
    }
    data = (DetectContentData *)sm->ctx;
    if (data->flags & DETECT_CONTENT_RAWBYTES ||
        data->flags & DETECT_CONTENT_NOCASE ||
        data->flags & DETECT_CONTENT_WITHIN ||
        data->flags & DETECT_CONTENT_DISTANCE ||
        data->flags & DETECT_CONTENT_FAST_PATTERN ||
        data->flags & DETECT_CONTENT_RELATIVE_NEXT ||
        data->flags & DETECT_CONTENT_NEGATED ) {
        printf("two failed\n");
        result = 0;
        goto end;
    }
    result &= (strncmp((char *)data->content, "two", 3) == 0);
    if (result == 0)
        goto end;

    result &= (sm->next == NULL);

 end:
    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);

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

    UtRegisterTest("DcePayloadParseTest25", DcePayloadParseTest25);
    UtRegisterTest("DcePayloadParseTest26", DcePayloadParseTest26);
    UtRegisterTest("DcePayloadParseTest27", DcePayloadParseTest27);
    UtRegisterTest("DcePayloadParseTest28", DcePayloadParseTest28);
    UtRegisterTest("DcePayloadParseTest29", DcePayloadParseTest29);
    UtRegisterTest("DcePayloadParseTest30", DcePayloadParseTest30);
    UtRegisterTest("DcePayloadParseTest31", DcePayloadParseTest31);
    UtRegisterTest("DcePayloadParseTest32", DcePayloadParseTest32);
    UtRegisterTest("DcePayloadParseTest33", DcePayloadParseTest33);
    UtRegisterTest("DcePayloadParseTest34", DcePayloadParseTest34);
    UtRegisterTest("DcePayloadParseTest35", DcePayloadParseTest35);
    UtRegisterTest("DcePayloadParseTest36", DcePayloadParseTest36);
    UtRegisterTest("DcePayloadParseTest37", DcePayloadParseTest37);
    UtRegisterTest("DcePayloadParseTest38", DcePayloadParseTest38);
    UtRegisterTest("DcePayloadParseTest39", DcePayloadParseTest39);
    UtRegisterTest("DcePayloadParseTest40", DcePayloadParseTest40);
    UtRegisterTest("DcePayloadParseTest41", DcePayloadParseTest41);

    UtRegisterTest("DcePayloadParseTest44", DcePayloadParseTest44);
    UtRegisterTest("DcePayloadParseTest45", DcePayloadParseTest45);
    UtRegisterTest("DcePayloadParseTest46", DcePayloadParseTest46);
#endif /* UNITTESTS */

    return;
}
