/* Copyright (C) 2015 Open Information Security Foundation
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

#include "suricata-common.h"

#include "detect.h"
#include "detect-parse.h"
#include "detect-engine-mpm.h"
#include "detect-dnp3-data.h"

void DetectDNP3DataRegisterTests(void);

static int DetectDNP3DataSetup(DetectEngineCtx *de_ctx, Signature *s, char *str)
{
    SCEnter();
    s->list = DETECT_SM_LIST_DNP3_DATA_MATCH;
    s->alproto = ALPROTO_DNP3;
    SCReturnInt(0);
}

uint32_t DetectDNP3DataInspectMpm(DetectEngineThreadCtx *det_ctx, Flow *f,
    DNP3State *dnp3_state, uint8_t flags, void *txv, uint64_t tx_id)
{
    SCEnter();
    DNP3Transaction *tx = (DNP3Transaction *)txv;

    SCLogInfo("DetectDNP3DataInspectMpm: flags=0x%02x", flags);

    if (flags & STREAM_TOSERVER && tx->request_buffer != NULL) {
        SCLogInfo("Calling DNP3DataPatternSearch on request buffer.");
        SCReturnUInt(DNP3DataPatternSearch(det_ctx, tx->request_buffer,
                tx->request_buffer_len, flags));
    }
    else if (flags & STREAM_TOCLIENT && tx->response_buffer != NULL) {
        SCLogInfo("Calling DNP3DataPatternSearch on response buffer.");
        SCReturnUInt(DNP3DataPatternSearch(det_ctx, tx->response_buffer,
                tx->response_buffer_len, flags));
    }

    SCReturnUInt(0);
}

void DetectDNP3DataRegister(void)
{
    SCEnter();

    sigmatch_table[DETECT_AL_DNP3DATA].name          = "dnp3_data";
    sigmatch_table[DETECT_AL_DNP3DATA].Match         = NULL;
    sigmatch_table[DETECT_AL_DNP3DATA].AppLayerMatch = NULL;
    sigmatch_table[DETECT_AL_DNP3DATA].alproto       = ALPROTO_DNP3;
    sigmatch_table[DETECT_AL_DNP3DATA].Setup         = DetectDNP3DataSetup;
    sigmatch_table[DETECT_AL_DNP3DATA].Free          = NULL;
    sigmatch_table[DETECT_AL_DNP3DATA].RegisterTests =
        DetectDNP3DataRegisterTests;

    sigmatch_table[DETECT_AL_DNP3DATA].flags |= SIGMATCH_NOOPT;
    sigmatch_table[DETECT_AL_DNP3DATA].flags |= SIGMATCH_PAYLOAD;

    SCReturn;
}

#ifdef UNITTESTS

#include "util-unittest.h"
#include "util-unittest-helper.h"

#include "app-layer-parser.h"
#include "detect-engine.h"
#include "flow-util.h"
#include "stream-tcp.h"

#define FAIL_IF(expr) do {                                      \
        if (expr) {                                             \
            printf("Failed at %s:%d\n", __FILE__, __LINE__);    \
            goto fail;                                          \
        }                                                       \
    } while (0);

/**
 * Test request (to server) content match.
 */
static int DetectDNP3DataTest01(void)
{
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();
    DetectEngineThreadCtx *det_ctx = NULL;
    DetectEngineCtx *de_ctx = NULL;
    Flow f;
    Packet *p;
    TcpSession tcp;
    ThreadVars tv;

    int result = 0;

    uint8_t request[] = {
        0x05, 0x64, 0x1a, 0xc4, 0x02, 0x00, 0x01, 0x00,
        0xa5, 0xe9,

        0xff, 0xc9, 0x05, 0x0c, 0x01, 0x28, 0x01, 0x00,
        0x00, 0x00, 0x01, 0x01, 0x01, 0x00, 0x00, 0x00,

        /* CRC. */
        0x72, 0xef,

        0x00, 0x00, 0x00, 0x00, 0x00,

        /* CRC. */
        0xff, 0xff,
    };

    /* Setup flow. */
    memset(&f, 0, sizeof(Flow));
    memset(&tcp, 0, sizeof(TcpSession));
    p = UTHBuildPacket(request, sizeof(request), IPPROTO_TCP);
    FLOW_INITIALIZE(&f);
    f.alproto = ALPROTO_DNP3;
    f.protoctx = (void *)&tcp;
    f.proto = IPPROTO_TCP;
    f.flags |= FLOW_IPV4;
    p->flow = &f;
    p->flags |= PKT_HAS_FLOW | PKT_STREAM_EST;
    p->flowflags |= FLOW_PKT_TOSERVER | FLOW_PKT_ESTABLISHED;
    StreamTcpInitConfig(TRUE);

    de_ctx = DetectEngineCtxInit();
    FAIL_IF(de_ctx == NULL);

    /* Either direction - should match. */
    Signature *s = DetectEngineAppendSig(de_ctx,
        "alert dnp3 any any -> any any ("
        "msg:\"DetectDNP3DataTest01\"; "
        "dnp3_data; "
        "content:\"|01 01 01 00 00 00 00 00 00 00|\"; "
        "sid:1; rev:1;)");
    FAIL_IF(s == NULL);

    /* To server - should match. */
    s = DetectEngineAppendSig(de_ctx,
        "alert dnp3 any any -> any any ("
        "msg:\"DetectDNP3DataTest01\"; "
        "flow:established,to_server; "
        "dnp3_data; "
        "content:\"|01 01 01 00 00 00 00 00 00 00|\"; "
        "sid:2; rev:1;)");
    FAIL_IF(s == NULL);

    /* To client - should not match. */
    s = DetectEngineAppendSig(de_ctx,
        "alert dnp3 any any -> any any ("
        "msg:\"DetectDNP3DataTest01\"; "
        "flow:established,to_client; "
        "dnp3_data; "
        "content:\"|01 01 01 00 00 00 00 00 00 00|\"; "
        "sid:3; rev:1;)");
    FAIL_IF(s == NULL);

    /* The content of a CRC - should not match. */
    s = DetectEngineAppendSig(de_ctx,
        "alert dnp3 any any -> any any ("
        "msg:\"DetectDNP3DataTest01\"; "
        "dnp3_data; "
        "content:\"|72 ef|\"; "
        "sid:4; rev:1;)");
    FAIL_IF(s == NULL);

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&tv, (void *)de_ctx, (void *)&det_ctx);

    SCMutexLock(&f.m);
    int r = AppLayerParserParse(alp_tctx, &f, ALPROTO_DNP3, STREAM_TOSERVER,
        request, sizeof(request));
    SCMutexUnlock(&f.m);
    FAIL_IF(r);

    FAIL_IF(f.alstate == NULL);

    SigMatchSignatures(&tv, de_ctx, det_ctx, p);
    FAIL_IF(!PacketAlertCheck(p, 1));
    FAIL_IF(!PacketAlertCheck(p, 2));
    FAIL_IF(PacketAlertCheck(p, 3));
    FAIL_IF(PacketAlertCheck(p, 4));

    result = 1;
fail:
    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
    if (det_ctx != NULL)
        DetectEngineThreadCtxDeinit(&tv, det_ctx);
    if (de_ctx != NULL)
        SigGroupCleanup(de_ctx);
    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);
    StreamTcpFreeConfig(TRUE);
    FLOW_DESTROY(&f);
    UTHFreePacket(p);
    return result;
}

/**
 * Test response (to client) content match.
 */
static int DetectDNP3DataTest02(void)
{
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();
    DetectEngineThreadCtx *det_ctx = NULL;
    DetectEngineCtx *de_ctx = NULL;
    Flow f;
    Packet *p;
    TcpSession tcp;
    ThreadVars tv;

    int result = 0;

    uint8_t request[] = {
        0x05, 0x64, 0x1a, 0xc4, 0x02, 0x00, 0x01, 0x00,
        0xa5, 0xe9,

        0xff, 0xc9, 0x05, 0x0c, 0x01, 0x28, 0x01, 0x00,
        0x00, 0x00, 0x01, 0x01, 0x01, 0x00, 0x00, 0x00,

        /* CRC. */
        0x72, 0xef,

        0x00, 0x00, 0x00, 0x00, 0x00,

        /* CRC. */
        0xff, 0xff,
    };

    uint8_t response[] = {
        0x05, 0x64, 0x1c, 0x44, 0x01, 0x00, 0x02, 0x00,
        0xe2, 0x59,

        0xc3, 0xc9, 0x81, 0x00, 0x00, 0x0c, 0x01, 0x28,
        0x01, 0x00, 0x00, 0x00, 0x01, 0x01, 0x01, 0x00,

        /* CRC. */
        0x7a, 0x65,

        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,

        /* CRC. */
        0xff, 0xff
    };

    /* Setup flow. */
    memset(&f, 0, sizeof(Flow));
    memset(&tcp, 0, sizeof(TcpSession));
    p = UTHBuildPacket(response, sizeof(response), IPPROTO_TCP);
    FLOW_INITIALIZE(&f);
    f.alproto = ALPROTO_DNP3;
    f.protoctx = (void *)&tcp;
    f.proto = IPPROTO_TCP;
    f.flags |= FLOW_IPV4;
    p->flow = &f;
    p->flags |= PKT_HAS_FLOW | PKT_STREAM_EST;
    p->flowflags |= FLOW_PKT_TOCLIENT | FLOW_PKT_ESTABLISHED;
    StreamTcpInitConfig(TRUE);

    de_ctx = DetectEngineCtxInit();
    FAIL_IF(de_ctx == NULL);

    /* Either direction - should match. */
    Signature *s = DetectEngineAppendSig(de_ctx,
        "alert dnp3 any any -> any any ("
        "msg:\"DetectDNP3DataTest01\"; "
        "dnp3_data; "
        "content:\"|01 01 01 00 00 00 00|\"; "
        "sid:1; rev:1;)");
    FAIL_IF(s == NULL);

    /* To server - should not match. */
    s = DetectEngineAppendSig(de_ctx,
        "alert dnp3 any any -> any any ("
        "msg:\"DetectDNP3DataTest01\"; "
        "flow:established,to_server; "
        "dnp3_data; "
        "content:\"|01 01 01 00 00 00 00|\"; "
        "sid:2; rev:1;)");
    FAIL_IF(s == NULL);

    /* To client - should match. */
    s = DetectEngineAppendSig(de_ctx,
        "alert dnp3 any any -> any any ("
        "msg:\"DetectDNP3DataTest01\"; "
        "flow:established,to_client; "
        "dnp3_data; "
        "content:\"|01 01 01 00 00 00 00|\"; "
        "sid:3; rev:1;)");
    FAIL_IF(s == NULL);

    /* The content of a CRC - should not match. */
    s = DetectEngineAppendSig(de_ctx,
        "alert dnp3 any any -> any any ("
        "msg:\"DetectDNP3DataTest01\"; "
        "dnp3_data; "
        "content:\"|7a 65|\"; "
        "sid:4; rev:1;)");
    FAIL_IF(s == NULL);

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&tv, (void *)de_ctx, (void *)&det_ctx);

    /* Send through the request, then response. */
    SCMutexLock(&f.m);
    int r = AppLayerParserParse(alp_tctx, &f, ALPROTO_DNP3, STREAM_TOSERVER,
        request, sizeof(request));
    SCMutexUnlock(&f.m);
    FAIL_IF(r);
    FAIL_IF(f.alstate == NULL);

    SCMutexLock(&f.m);
    r = AppLayerParserParse(alp_tctx, &f, ALPROTO_DNP3, STREAM_TOCLIENT,
        response, sizeof(response));
    SCMutexUnlock(&f.m);
    FAIL_IF(r);

    SigMatchSignatures(&tv, de_ctx, det_ctx, p);
    FAIL_IF(!PacketAlertCheck(p, 1));
    FAIL_IF(PacketAlertCheck(p, 2));
    FAIL_IF(!PacketAlertCheck(p, 3));
    FAIL_IF(PacketAlertCheck(p, 4));

    result = 1;
fail:
    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
    if (det_ctx != NULL)
        DetectEngineThreadCtxDeinit(&tv, det_ctx);
    if (de_ctx != NULL)
        SigGroupCleanup(de_ctx);
    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);
    StreamTcpFreeConfig(TRUE);
    FLOW_DESTROY(&f);
    UTHFreePacket(p);
    return result;
}

#endif

void DetectDNP3DataRegisterTests(void)
{
#ifdef UNITTESTS
    UtRegisterTest("DetectDNP3DataTest01", DetectDNP3DataTest01, 1);
    UtRegisterTest("DetectDNP3DataTest02", DetectDNP3DataTest02, 1);
#endif
}
