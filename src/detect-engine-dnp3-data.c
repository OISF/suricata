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
#include "stream.h"
#include "detect-engine-content-inspection.h"

#include "app-layer-dnp3.h"
#include "detect-dnp3-data.h"

int DetectEngineInspectDNP3(ThreadVars *tv, DetectEngineCtx *de_ctx,
    DetectEngineThreadCtx *det_ctx, Signature *s, Flow *f, uint8_t flags,
    void *alstate, void *txv, uint64_t tx_id)
{
    SCEnter();
    DNP3Transaction *tx = (DNP3Transaction *)txv;

    int r = 0;

    /* Content match - should probably be put into its own file. */
    if (flags & STREAM_TOSERVER && tx->request_buffer != NULL) {
        r = DetectEngineContentInspection(de_ctx, det_ctx, s,
            s->sm_lists[DETECT_SM_LIST_DNP3_DATA_MATCH], f, tx->request_buffer,
            tx->request_buffer_len, 0,
            DETECT_ENGINE_CONTENT_INSPECTION_MODE_DNP3_DATA, NULL);
    }
    else if (flags & STREAM_TOCLIENT && tx->response_buffer != NULL) {
        r = DetectEngineContentInspection(de_ctx, det_ctx, s,
            s->sm_lists[DETECT_SM_LIST_DNP3_DATA_MATCH], f, tx->response_buffer,
            tx->response_buffer_len, 0,
            DETECT_ENGINE_CONTENT_INSPECTION_MODE_DNP3_DATA, NULL);
    }

    SCReturnInt(r);
}

#ifdef UNITTESTS

#include "util-unittest.h"
#include "app-layer-parser.h"
#include "detect-parse.h"
#include "detect-engine.h"
#include "flow-util.h"
#include "stream-tcp.h"
#include "util-unittest.h"
#include "util-unittest-helper.h"

#define FAIL_IF(expr) do {                                      \
        if (expr) {                                             \
            printf("Failed at %s:%d\n", __FILE__, __LINE__);    \
            goto end;                                           \
        }                                                       \
    } while (0);

int DetectEngineInspectDNP3FuncTest01(void)
{
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();
    DetectEngineThreadCtx *det_ctx = NULL;
    DetectEngineCtx *de_ctx = NULL;
    Flow f;
    Signature *s = NULL;
    TcpSession ssn;
    ThreadVars tv;

    int result = 0;

    static uint8_t request[] = {
        /* DNP3 start. */
        0x05, 0x64, 0x1a, 0xc4, 0x02, 0x00, 0x01, 0x00,
        0xa5, 0xe9,

        /* Transport header. */
        0xff,

        /* Application layer. */
        0xc9, 0x05, 0x0c, 0x01, 0x28, 0x01, 0x00, 0x00,
        0x00, 0x01, 0x01, 0x01, 0x00, 0x00, 0x00, 0x72,
        0xef, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff
    };

    static uint8_t response[] = {
        /* DNP3 start. */
        0x05, 0x64, 0x1c, 0x44, 0x01, 0x00, 0x02, 0x00,
        0xe2, 0x59,

        /* Transport header. */
        0xc3,

        /* Application layer. */
        0xc9, 0x81, 0x00, 0x00, 0x0c, 0x01, 0x28, 0x01,
        0x00, 0x00, 0x00, 0x01, 0x01, 0x01, 0x00, 0x7a,
        0x65, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xff, 0xff
    };

    memset(&tv, 0, sizeof(ThreadVars));
    memset(&f, 0, sizeof(Flow));
    memset(&ssn, 0, sizeof(TcpSession));

    Packet *prequest = UTHBuildPacket(request, sizeof(request), IPPROTO_TCP);
    Packet *presponse = UTHBuildPacket(response, sizeof(response), IPPROTO_TCP);

    FLOW_INITIALIZE(&f);
    f.alproto   = ALPROTO_DNP3;
    f.protoctx  = (void *)&ssn;
    f.proto     = IPPROTO_TCP;
    f.flags     |= FLOW_IPV4;

    prequest->flow = &f;
    prequest->flags |= PKT_HAS_FLOW | PKT_STREAM_EST;
    prequest->flowflags |= FLOW_PKT_TOSERVER | FLOW_PKT_ESTABLISHED;

    presponse->flow = &f;
    presponse->flags |= PKT_HAS_FLOW | PKT_STREAM_EST;
    presponse->flowflags |= FLOW_PKT_TOCLIENT | FLOW_PKT_ESTABLISHED;

    StreamTcpInitConfig(TRUE);
    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    s = de_ctx->sig_list = SigInit(de_ctx, "alert dnp3 any any -> any any (msg:\"Test - DNP3 application function code.\"; dnp3_func: 5; sid:1; rev:1;)");
    if (s == NULL)
        goto end;

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&tv, (void *)de_ctx, (void *)&det_ctx);

    SCMutexLock(&f.m);
    int r = AppLayerParserParse(alp_tctx, &f, ALPROTO_DNP3, STREAM_TOSERVER,
        request, sizeof(request));
    SCMutexUnlock(&f.m);
    FAIL_IF(r != 0);

    DNP3State *dnp3_state = f.alstate;
    FAIL_IF(dnp3_state == NULL);

    /* As the response hasn't been seen we should not have an alert yet. */
    SigMatchSignatures(&tv, de_ctx, det_ctx, prequest);
    FAIL_IF(PacketAlertCheck(prequest, 1));

    SCMutexLock(&f.m);
    r = AppLayerParserParse(alp_tctx, &f, ALPROTO_DNP3, STREAM_TOCLIENT,
        response, sizeof(response));
    SCMutexUnlock(&f.m);
    FAIL_IF(r != 0);

    /* Now that the response has been seen, we should have alert. */
    SigMatchSignatures(&tv, de_ctx, det_ctx, presponse);
    FAIL_IF(!PacketAlertCheck(presponse, 1));

    result = 1;
end:
    return result;
}

static int DetectEngineInspectDNP3IndTest01(void)
{
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();
    DetectEngineThreadCtx *det_ctx = NULL;
    DetectEngineCtx *de_ctx = NULL;
    Flow f;
    Signature *s = NULL;
    TcpSession ssn;
    ThreadVars tv;

    int result = 0;

    uint8_t request[] = {
        0x05, 0x64, 0x0d, 0xc4, 0x01, 0x00, 0x01, 0x00,
        0x1b, 0x45, 0xc9, 0xcd, 0x01, 0x01, 0x00, 0x00,
        0x00, 0x03, 0x0e, 0x21
    };

    /* Response with internal indications: 0x86 0x00. */
    uint8_t response[] = {
        0x05, 0x64, 0x10, 0x44, 0x01, 0x00, 0x01, 0x00,
        0xfb, 0x3e, 0xc9, 0xcd, 0x81, 0x86, 0x00, 0x01,
        0x01, 0x00, 0x00, 0x03, 0x0a, 0x92, 0xdc
    };

    memset(&tv, 0, sizeof(ThreadVars));
    memset(&f, 0, sizeof(Flow));
    memset(&ssn, 0, sizeof(TcpSession));

    Packet *prequest = UTHBuildPacket(request, sizeof(request), IPPROTO_TCP);
    Packet *presponse = UTHBuildPacket(response, sizeof(response), IPPROTO_TCP);

    FLOW_INITIALIZE(&f);
    f.alproto   = ALPROTO_DNP3;
    f.protoctx  = (void *)&ssn;
    f.proto     = IPPROTO_TCP;
    f.flags     |= FLOW_IPV4;

    prequest->flow = &f;
    prequest->flags |= PKT_HAS_FLOW | PKT_STREAM_EST;
    prequest->flowflags |= FLOW_PKT_TOSERVER | FLOW_PKT_ESTABLISHED;

    presponse->flow = &f;
    presponse->flags |= PKT_HAS_FLOW | PKT_STREAM_EST;
    presponse->flowflags |= FLOW_PKT_TOCLIENT | FLOW_PKT_ESTABLISHED;

    StreamTcpInitConfig(TRUE);
    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    s = de_ctx->sig_list = SigInit(de_ctx, "alert dnp3 any any -> any any (msg:\"Test - DNP3 internal indicators.\"; dnp3.ind: device_restart; sid:1; rev:1;)");
    if (s == NULL)
        goto end;

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&tv, (void *)de_ctx, (void *)&det_ctx);

    SCMutexLock(&f.m);
    int r = AppLayerParserParse(alp_tctx, &f, ALPROTO_DNP3, STREAM_TOSERVER,
        request, sizeof(request));
    SCMutexUnlock(&f.m);
    FAIL_IF(r != 0);

    DNP3State *dnp3_state = f.alstate;
    FAIL_IF(dnp3_state == NULL);

    /* As the response hasn't been seen we should not have an alert yet. */
    SigMatchSignatures(&tv, de_ctx, det_ctx, prequest);
    FAIL_IF(PacketAlertCheck(prequest, 1));

    SCMutexLock(&f.m);
    r = AppLayerParserParse(alp_tctx, &f, ALPROTO_DNP3, STREAM_TOCLIENT,
        response, sizeof(response));
    SCMutexUnlock(&f.m);
    FAIL_IF(r != 0);

    /* Now that the response has been seen, we should have alert. */
    SigMatchSignatures(&tv, de_ctx, det_ctx, presponse);
    FAIL_IF(!PacketAlertCheck(presponse, 1));

    result = 1;
end:
    return result;
};

#endif /* UNITTESTS */

void DetectEngineInspectDNP3RegisterTests(void)
{
#ifdef UNITTESTS
    UtRegisterTest("DetectEngineInspectDNP3FuncTest01",
        DetectEngineInspectDNP3FuncTest01, 1);
    UtRegisterTest("DetectEngineInspectDNP3IndTest01",
        DetectEngineInspectDNP3IndTest01, 1);
#endif
}
