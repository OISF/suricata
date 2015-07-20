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

/** \file
 *
 *  \author Victor Julien <victor@inliniac.net>
 *  \author Pablo Rincon Crespo <pablo.rincon.crespo@gmail.com>
 *
 *  Based on detect-engine-uri.c
 */

#include "suricata-common.h"
#include "suricata.h"
#include "decode.h"

#include "detect.h"
#include "detect-engine.h"
#include "detect-parse.h"
#include "detect-engine-state.h"
#include "detect-engine-content-inspection.h"

#include "flow-util.h"
#include "util-debug.h"
#include "util-print.h"
#include "flow.h"

#include "stream-tcp.h"

#include "app-layer-parser.h"

#include "util-unittest.h"
#include "util-unittest-helper.h"
#include "app-layer.h"
#include "app-layer-htp.h"
#include "app-layer-protos.h"

/**
 * \brief Do the content inspection & validation for a signature
 *
 * \param de_ctx Detection engine context
 * \param det_ctx Detection engine thread context
 * \param s Signature to inspect
 * \param sm SigMatch to inspect
 * \param f Flow
 * \param flags app layer flags
 * \param state App layer state
 *
 * \retval 0 no match.
 * \retval 1 match.
 * \retval 2 Sig can't match.
 */
int DetectEngineInspectPacketUris(ThreadVars *tv,
                                  DetectEngineCtx *de_ctx,
                                  DetectEngineThreadCtx *det_ctx,
                                  Signature *s, Flow *f, uint8_t flags,
                                  void *alstate,
                                  void *txv, uint64_t tx_id)
{
    HtpTxUserData *tx_ud = htp_tx_get_user_data(txv);

    if (tx_ud == NULL || tx_ud->request_uri_normalized == NULL) {
        if (AppLayerParserGetStateProgress(IPPROTO_TCP, ALPROTO_HTTP, txv, flags) > HTP_REQUEST_LINE)
            return DETECT_ENGINE_INSPECT_SIG_CANT_MATCH;
        else
            return DETECT_ENGINE_INSPECT_SIG_NO_MATCH;
    }

    det_ctx->discontinue_matching = 0;
    det_ctx->buffer_offset = 0;
    det_ctx->inspection_recursion_counter = 0;

#if 0
    PrintRawDataFp(stdout, (uint8_t *)bstr_ptr(tx_ud->request_uri_normalized),
                   bstr_len(tx_ud->request_uri_normalized));
#endif

    /* Inspect all the uricontents fetched on each
     * transaction at the app layer */
    int r = DetectEngineContentInspection(de_ctx, det_ctx, s, s->sm_lists[DETECT_SM_LIST_UMATCH],
                                          f,
                                          bstr_ptr(tx_ud->request_uri_normalized),
                                          bstr_len(tx_ud->request_uri_normalized),
                                          0,
                                          DETECT_ENGINE_CONTENT_INSPECTION_MODE_URI, NULL);
    if (r == 1) {
        return DETECT_ENGINE_INSPECT_SIG_MATCH;
    } else {
        return DETECT_ENGINE_INSPECT_SIG_CANT_MATCH;
    }
}

/***********************************Unittests**********************************/

#ifdef UNITTESTS
/** \test Test a simple uricontent option */
static int UriTestSig01(void)
{
    int result = 0;
    Flow f;
    HtpState *http_state = NULL;
    uint8_t http_buf1[] = "POST /one HTTP/1.0\r\n"
        "User-Agent: Mozilla/1.0\r\n"
        "Cookie: hellocatch\r\n\r\n";
    uint32_t http_buf1_len = sizeof(http_buf1) - 1;
    uint8_t http_buf2[] = "POST /oneself HTTP/1.0\r\n"
        "User-Agent: Mozilla/1.0\r\n"
        "Cookie: hellocatch\r\n\r\n";
    uint32_t http_buf2_len = sizeof(http_buf2) - 1;
    TcpSession ssn;
    Packet *p = NULL;
    Signature *s = NULL;
    ThreadVars tv;
    DetectEngineThreadCtx *det_ctx = NULL;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&tv, 0, sizeof(ThreadVars));
    memset(&f, 0, sizeof(Flow));
    memset(&ssn, 0, sizeof(TcpSession));

    p = UTHBuildPacket(http_buf1, http_buf1_len, IPPROTO_TCP);

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;
    f.flags |= FLOW_IPV4;

    p->flow = &f;
    p->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    p->flowflags |= FLOW_PKT_TOSERVER;
    p->flowflags |= FLOW_PKT_ESTABLISHED;
    f.alproto = ALPROTO_HTTP;

    StreamTcpInitConfig(TRUE);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }
    de_ctx->mpm_matcher = MPM_B2G;
    de_ctx->flags |= DE_QUIET;

    s = de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                                   "(msg:\"Test uricontent option\"; "
                                   "uricontent:\"one\"; sid:1;)");
    if (s == NULL) {
        goto end;
    }

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&tv, (void *)de_ctx, (void *)&det_ctx);

    SCMutexLock(&f.m);
    int r = AppLayerParserParse(alp_tctx, &f, ALPROTO_HTTP, STREAM_TOSERVER, http_buf1, http_buf1_len);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);

    http_state = f.alstate;
    if (http_state == NULL) {
        printf("no http state: ");
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&tv, de_ctx, det_ctx, p);

    if (!PacketAlertCheck(p, 1)) {
        printf("sig 1 alerted, but it should not: ");
        goto end;
    }

    DetectEngineStateReset(f.de_state, STREAM_TOSERVER | STREAM_TOCLIENT);

    SCMutexLock(&f.m);
    r = AppLayerParserParse(alp_tctx, &f, ALPROTO_HTTP, STREAM_TOSERVER, http_buf2, http_buf2_len);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);

    http_state = f.alstate;
    if (http_state == NULL) {
        printf("no http state: ");
        goto end;
    }

    if (!PacketAlertCheck(p, 1)) {
        printf("sig 1 alerted, but it should not: ");
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&tv, de_ctx, det_ctx, p);

    result = 1;

end:
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

/** \test Test the pcre /U option */
static int UriTestSig02(void)
{
    int result = 0;
    Flow f;
    HtpState *http_state = NULL;
    uint8_t http_buf1[] = "POST /on HTTP/1.0\r\n"
        "User-Agent: Mozilla/1.0\r\n"
        "Cookie: hellocatch\r\n\r\n";
    uint32_t http_buf1_len = sizeof(http_buf1) - 1;
    uint8_t http_buf2[] = "POST /one HTTP/1.0\r\n"
        "User-Agent: Mozilla/1.0\r\n"
        "Cookie: hellocatch\r\n\r\n";
    uint32_t http_buf2_len = sizeof(http_buf2) - 1;
    TcpSession ssn;
    Packet *p = NULL;
    Signature *s = NULL;
    ThreadVars tv;
    DetectEngineThreadCtx *det_ctx = NULL;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&tv, 0, sizeof(ThreadVars));
    memset(&f, 0, sizeof(Flow));
    memset(&ssn, 0, sizeof(TcpSession));

    p = UTHBuildPacket(http_buf1, http_buf1_len, IPPROTO_TCP);

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;
    f.flags |= FLOW_IPV4;

    p->flow = &f;
    p->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    p->flowflags |= FLOW_PKT_TOSERVER;
    p->flowflags |= FLOW_PKT_ESTABLISHED;
    f.alproto = ALPROTO_HTTP;

    StreamTcpInitConfig(TRUE);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }
    de_ctx->mpm_matcher = MPM_B2G;
    de_ctx->flags |= DE_QUIET;

    s = de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                                   "(msg:\"Test pcre /U option\"; "
                                   "pcre:/one/U; sid:1;)");
    if (s == NULL) {
        goto end;
    }

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&tv, (void *)de_ctx, (void *)&det_ctx);

    SCMutexLock(&f.m);
    int r = AppLayerParserParse(alp_tctx, &f, ALPROTO_HTTP, STREAM_TOSERVER, http_buf1, http_buf1_len);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);

    http_state = f.alstate;
    if (http_state == NULL) {
        printf("no http state: ");
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&tv, de_ctx, det_ctx, p);

    if (PacketAlertCheck(p, 1)) {
        printf("sig 1 alerted with payload2, but it should not: ");
        goto end;
    }

    DetectEngineStateReset(f.de_state, STREAM_TOSERVER | STREAM_TOCLIENT);

    SCMutexLock(&f.m);
    r = AppLayerParserParse(alp_tctx, &f, ALPROTO_HTTP, STREAM_TOSERVER, http_buf2, http_buf2_len);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);

    http_state = f.alstate;
    if (http_state == NULL) {
        printf("no http state: ");
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&tv, de_ctx, det_ctx, p);

    if (!PacketAlertCheck(p, 1)) {
        printf("sig 1 didnt alert, but it should: ");
        goto end;
    }

    result = 1;

end:
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

/** \test Test the pcre /U option */
static int UriTestSig03(void)
{
    int result = 0;
    Flow f;
    HtpState *http_state = NULL;
    uint8_t http_buf1[] = "POST /one HTTP/1.0\r\n"
        "User-Agent: Mozilla/1.0\r\n"
        "Cookie: hellocatch\r\n\r\n";
    uint32_t http_buf1_len = sizeof(http_buf1) - 1;
    uint8_t http_buf2[] = "POST /oneself HTTP/1.0\r\n"
        "User-Agent: Mozilla/1.0\r\n"
        "Cookie: hellocatch\r\n\r\n";
    uint32_t http_buf2_len = sizeof(http_buf2) - 1;
    TcpSession ssn;
    Packet *p = NULL;
    Signature *s = NULL;
    ThreadVars tv;
    DetectEngineThreadCtx *det_ctx = NULL;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&tv, 0, sizeof(ThreadVars));
    memset(&f, 0, sizeof(Flow));
    memset(&ssn, 0, sizeof(TcpSession));

    p = UTHBuildPacket(http_buf1, http_buf1_len, IPPROTO_TCP);

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;
    f.flags |= FLOW_IPV4;

    p->flow = &f;
    p->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    p->flowflags |= FLOW_PKT_TOSERVER;
    p->flowflags |= FLOW_PKT_ESTABLISHED;
    f.alproto = ALPROTO_HTTP;

    StreamTcpInitConfig(TRUE);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }
    de_ctx->mpm_matcher = MPM_B2G;
    de_ctx->flags |= DE_QUIET;

    s = de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                                   "(msg:\"Test pcre /U option\"; "
                                   "pcre:/blah/U; sid:1;)");
    if (s == NULL) {
        goto end;
    }

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&tv, (void *)de_ctx, (void *)&det_ctx);

    SCMutexLock(&f.m);
    int r = AppLayerParserParse(alp_tctx, &f, ALPROTO_HTTP, STREAM_TOSERVER, http_buf1, http_buf1_len);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);

    http_state = f.alstate;
    if (http_state == NULL) {
        printf("no http state: ");
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&tv, de_ctx, det_ctx, p);

    if (PacketAlertCheck(p, 1)) {
        printf("sig 1 alerted, but it should not: ");
        goto end;
    }

    DetectEngineStateReset(f.de_state, STREAM_TOSERVER | STREAM_TOCLIENT);

    SCMutexLock(&f.m);
    r = AppLayerParserParse(alp_tctx, &f, ALPROTO_HTTP, STREAM_TOSERVER, http_buf2, http_buf2_len);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);

    http_state = f.alstate;
    if (http_state == NULL) {
        printf("no http state: ");
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&tv, de_ctx, det_ctx, p);

    if (PacketAlertCheck(p, 1)) {
        printf("sig 1 alerted, but it should not: ");
        goto end;
    }

    result = 1;

end:
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

/** \test Test the urilen option */
static int UriTestSig04(void)
{
    int result = 0;
    Flow f;
    HtpState *http_state = NULL;
    uint8_t http_buf1[] = "POST /one HTTP/1.0\r\n"
        "User-Agent: Mozilla/1.0\r\n"
        "Cookie: hellocatch\r\n\r\n";
    uint32_t http_buf1_len = sizeof(http_buf1) - 1;
    uint8_t http_buf2[] = "POST /oneself HTTP/1.0\r\n"
        "User-Agent: Mozilla/1.0\r\n"
        "Cookie: hellocatch\r\n\r\n";
    uint32_t http_buf2_len = sizeof(http_buf2) - 1;
    TcpSession ssn;
    Packet *p = NULL;
    Signature *s = NULL;
    ThreadVars tv;
    DetectEngineThreadCtx *det_ctx = NULL;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&tv, 0, sizeof(ThreadVars));
    memset(&f, 0, sizeof(Flow));
    memset(&ssn, 0, sizeof(TcpSession));

    p = UTHBuildPacket(http_buf1, http_buf1_len, IPPROTO_TCP);

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;
    f.flags |= FLOW_IPV4;

    p->flow = &f;
    p->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    p->flowflags |= FLOW_PKT_TOSERVER;
    p->flowflags |= FLOW_PKT_ESTABLISHED;
    f.alproto = ALPROTO_HTTP;

    StreamTcpInitConfig(TRUE);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }
    de_ctx->mpm_matcher = MPM_B2G;
    de_ctx->flags |= DE_QUIET;

    s = de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                                   "(msg:\"Test urilen option\"; "
                                   "urilen:>20; sid:1;)");
    if (s == NULL) {
        goto end;
    }

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&tv, (void *)de_ctx, (void *)&det_ctx);

    SCMutexLock(&f.m);
    int r = AppLayerParserParse(alp_tctx, &f, ALPROTO_HTTP, STREAM_TOSERVER, http_buf1, http_buf1_len);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);

    http_state = f.alstate;
    if (http_state == NULL) {
        printf("no http state: ");
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&tv, de_ctx, det_ctx, p);

    if (PacketAlertCheck(p, 1)) {
        printf("sig 1 alerted, but it should not: ");
        goto end;
    }

    DetectEngineStateReset(f.de_state, STREAM_TOSERVER | STREAM_TOCLIENT);

    SCMutexLock(&f.m);
    r = AppLayerParserParse(alp_tctx, &f, ALPROTO_HTTP, STREAM_TOSERVER, http_buf2, http_buf2_len);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);

    http_state = f.alstate;
    if (http_state == NULL) {
        printf("no http state: ");
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&tv, de_ctx, det_ctx, p);

    if (PacketAlertCheck(p, 1)) {
        printf("sig 1 alerted, but it should not: ");
        goto end;
    }

    result = 1;

end:
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

/** \test Test the urilen option */
static int UriTestSig05(void)
{
    int result = 0;
    Flow f;
    HtpState *http_state = NULL;
    uint8_t http_buf1[] = "POST /one HTTP/1.0\r\n"
        "User-Agent: Mozilla/1.0\r\n"
        "Cookie: hellocatch\r\n\r\n";
    uint32_t http_buf1_len = sizeof(http_buf1) - 1;
    uint8_t http_buf2[] = "POST /oneself HTTP/1.0\r\n"
        "User-Agent: Mozilla/1.0\r\n"
        "Cookie: hellocatch\r\n\r\n";
    uint32_t http_buf2_len = sizeof(http_buf2) - 1;
    TcpSession ssn;
    Packet *p = NULL;
    Signature *s = NULL;
    ThreadVars tv;
    DetectEngineThreadCtx *det_ctx = NULL;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&tv, 0, sizeof(ThreadVars));
    memset(&f, 0, sizeof(Flow));
    memset(&ssn, 0, sizeof(TcpSession));

    p = UTHBuildPacket(http_buf1, http_buf1_len, IPPROTO_TCP);

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;
    f.flags |= FLOW_IPV4;

    p->flow = &f;
    p->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    p->flowflags |= FLOW_PKT_TOSERVER;
    p->flowflags |= FLOW_PKT_ESTABLISHED;
    f.alproto = ALPROTO_HTTP;

    StreamTcpInitConfig(TRUE);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }
    de_ctx->mpm_matcher = MPM_B2G;
    de_ctx->flags |= DE_QUIET;

    s = de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                                   "(msg:\"Test urilen option\"; "
                                   "urilen:>4; sid:1;)");
    if (s == NULL) {
        goto end;
    }

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&tv, (void *)de_ctx, (void *)&det_ctx);

    SCMutexLock(&f.m);
    int r = AppLayerParserParse(alp_tctx, &f, ALPROTO_HTTP, STREAM_TOSERVER, http_buf1, http_buf1_len);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);

    http_state = f.alstate;
    if (http_state == NULL) {
        printf("no http state: ");
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&tv, de_ctx, det_ctx, p);

    if (PacketAlertCheck(p, 1)) {
        printf("sig 1 alerted, but it should not: ");
        goto end;
    }

    DetectEngineStateReset(f.de_state, STREAM_TOSERVER | STREAM_TOCLIENT);

    SCMutexLock(&f.m);
    r = AppLayerParserParse(alp_tctx, &f, ALPROTO_HTTP, STREAM_TOSERVER, http_buf2, http_buf2_len);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);

    http_state = f.alstate;
    if (http_state == NULL) {
        printf("no http state: ");
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&tv, de_ctx, det_ctx, p);

    if (!PacketAlertCheck(p, 1)) {
        printf("sig 1 didnt alert with payload2, but it should: ");
        goto end;
    }

    result = 1;

end:
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

/** \test Test the pcre /U option */
static int UriTestSig06(void)
{
    int result = 0;
    Flow f;
    HtpState *http_state = NULL;
    uint8_t http_buf1[] = "POST /oneoneoneone HTTP/1.0\r\n"
        "User-Agent: Mozilla/1.0\r\n"
        "Cookie: hellocatch\r\n\r\n";
    uint32_t http_buf1_len = sizeof(http_buf1) - 1;
    uint8_t http_buf2[] = "POST /oneself HTTP/1.0\r\n"
        "User-Agent: Mozilla/1.0\r\n"
        "Cookie: hellocatch\r\n\r\n";
    uint32_t http_buf2_len = sizeof(http_buf2) - 1;
    TcpSession ssn;
    Packet *p = NULL;
    Signature *s = NULL;
    ThreadVars tv;
    DetectEngineThreadCtx *det_ctx = NULL;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&tv, 0, sizeof(ThreadVars));
    memset(&f, 0, sizeof(Flow));
    memset(&ssn, 0, sizeof(TcpSession));

    p = UTHBuildPacket(http_buf1, http_buf1_len, IPPROTO_TCP);

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;
    f.flags |= FLOW_IPV4;

    p->flow = &f;
    p->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    p->flowflags |= FLOW_PKT_TOSERVER;
    p->flowflags |= FLOW_PKT_ESTABLISHED;
    f.alproto = ALPROTO_HTTP;

    StreamTcpInitConfig(TRUE);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }
    de_ctx->mpm_matcher = MPM_B2G;
    de_ctx->flags |= DE_QUIET;

    s = de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                                   "(msg:\"Test pcre /U option\"; "
                                   "pcre:/(oneself)+/U; sid:1;)");
    if (s == NULL) {
        goto end;
    }

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&tv, (void *)de_ctx, (void *)&det_ctx);

    SCMutexLock(&f.m);
    int r = AppLayerParserParse(alp_tctx, &f, ALPROTO_HTTP, STREAM_TOSERVER, http_buf1, http_buf1_len);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);

    http_state = f.alstate;
    if (http_state == NULL) {
        printf("no http state: ");
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&tv, de_ctx, det_ctx, p);

    if (PacketAlertCheck(p, 1)) {
        printf("sig 1 alerted, but it should not: ");
        goto end;
    }

    DetectEngineStateReset(f.de_state, STREAM_TOSERVER | STREAM_TOCLIENT);

    SCMutexLock(&f.m);
    r = AppLayerParserParse(alp_tctx, &f, ALPROTO_HTTP, STREAM_TOSERVER, http_buf2, http_buf2_len);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);

    http_state = f.alstate;
    if (http_state == NULL) {
        printf("no http state: ");
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&tv, de_ctx, det_ctx, p);

    if (!PacketAlertCheck(p, 1)) {
        printf("sig 1 didnt alert on payload2, but it should: ");
        goto end;
    }

    result = 1;

end:
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

/** \test Test the pcre /U option in combination with urilen */
static int UriTestSig07(void)
{
    int result = 0;
    Flow f;
    HtpState *http_state = NULL;
    uint8_t http_buf1[] = "POST /oneoneoneone HTTP/1.0\r\n"
        "User-Agent: Mozilla/1.0\r\n"
        "Cookie: hellocatch\r\n\r\n";
    uint32_t http_buf1_len = sizeof(http_buf1) - 1;
    uint8_t http_buf2[] = "POST /oneoneself HTTP/1.0\r\n"
        "User-Agent: Mozilla/1.0\r\n"
        "Cookie: hellocatch\r\n\r\n";
    uint32_t http_buf2_len = sizeof(http_buf2) - 1;
    TcpSession ssn;
    Packet *p = NULL;
    Signature *s = NULL;
    ThreadVars tv;
    DetectEngineThreadCtx *det_ctx = NULL;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&tv, 0, sizeof(ThreadVars));
    memset(&f, 0, sizeof(Flow));
    memset(&ssn, 0, sizeof(TcpSession));

    p = UTHBuildPacket(http_buf1, http_buf1_len, IPPROTO_TCP);

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;
    f.flags |= FLOW_IPV4;

    p->flow = &f;
    p->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    p->flowflags |= FLOW_PKT_TOSERVER;
    p->flowflags |= FLOW_PKT_ESTABLISHED;
    f.alproto = ALPROTO_HTTP;

    StreamTcpInitConfig(TRUE);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }
    de_ctx->mpm_matcher = MPM_B2G;
    de_ctx->flags |= DE_QUIET;

    s = de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                                   "(msg:\"Test pcre /U option with urilen \"; "
                                   "pcre:/(one){2,}(self)?/U; urilen:3<>20; sid:1;)");
    if (s == NULL) {
        goto end;
    }

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&tv, (void *)de_ctx, (void *)&det_ctx);

    SCMutexLock(&f.m);
    int r = AppLayerParserParse(alp_tctx, &f, ALPROTO_HTTP, STREAM_TOSERVER, http_buf1, http_buf1_len);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);

    http_state = f.alstate;
    if (http_state == NULL) {
        printf("no http state: ");
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&tv, de_ctx, det_ctx, p);

    if (!PacketAlertCheck(p, 1)) {
        printf("sig 1 didnt alert, but it should: ");
        goto end;
    }

    DetectEngineStateReset(f.de_state, STREAM_TOSERVER | STREAM_TOCLIENT);

    SCMutexLock(&f.m);
    r = AppLayerParserParse(alp_tctx, &f, ALPROTO_HTTP, STREAM_TOSERVER, http_buf2, http_buf2_len);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);

    http_state = f.alstate;
    if (http_state == NULL) {
        printf("no http state: ");
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&tv, de_ctx, det_ctx, p);

    if (!PacketAlertCheck(p, 1)) {
        printf("sig 1 didnt alert with payload2, but it should: ");
        goto end;
    }

    result = 1;

end:
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

/** \test Test the pcre /U option in combination with urilen */
static int UriTestSig08(void)
{
    int result = 0;
    Flow f;
    HtpState *http_state = NULL;
    uint8_t http_buf1[] = "POST /oneoneoneone HTTP/1.0\r\n"
        "User-Agent: Mozilla/1.0\r\n"
        "Cookie: hellocatch\r\n\r\n";
    uint32_t http_buf1_len = sizeof(http_buf1) - 1;
    uint8_t http_buf2[] = "POST /oneoneself HTTP/1.0\r\n"
        "User-Agent: Mozilla/1.0\r\n"
        "Cookie: hellocatch\r\n\r\n";
    uint32_t http_buf2_len = sizeof(http_buf2) - 1;
    TcpSession ssn;
    Packet *p = NULL;
    Signature *s = NULL;
    ThreadVars tv;
    DetectEngineThreadCtx *det_ctx = NULL;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&tv, 0, sizeof(ThreadVars));
    memset(&f, 0, sizeof(Flow));
    memset(&ssn, 0, sizeof(TcpSession));

    p = UTHBuildPacket(http_buf1, http_buf1_len, IPPROTO_TCP);

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;
    f.flags |= FLOW_IPV4;

    p->flow = &f;
    p->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    p->flowflags |= FLOW_PKT_TOSERVER;
    p->flowflags |= FLOW_PKT_ESTABLISHED;
    f.alproto = ALPROTO_HTTP;

    StreamTcpInitConfig(TRUE);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }
    de_ctx->mpm_matcher = MPM_B2G;
    de_ctx->flags |= DE_QUIET;

    s = de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                                   "(msg:\"Test pcre /U option with urilen\"; "
                                   "pcre:/(blabla){2,}(self)?/U; urilen:3<>20; sid:1;)");
    if (s == NULL) {
        goto end;
    }

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&tv, (void *)de_ctx, (void *)&det_ctx);

    SCMutexLock(&f.m);
    int r = AppLayerParserParse(alp_tctx, &f, ALPROTO_HTTP, STREAM_TOSERVER, http_buf1, http_buf1_len);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);

    http_state = f.alstate;
    if (http_state == NULL) {
        printf("no http state: ");
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&tv, de_ctx, det_ctx, p);

    if (PacketAlertCheck(p, 1)) {
        printf("sig 1 alerted, but it should not: ");
        goto end;
    }

    DetectEngineStateReset(f.de_state, STREAM_TOSERVER | STREAM_TOCLIENT);

    SCMutexLock(&f.m);
    r = AppLayerParserParse(alp_tctx, &f, ALPROTO_HTTP, STREAM_TOSERVER, http_buf2, http_buf2_len);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);

    http_state = f.alstate;
    if (http_state == NULL) {
        printf("no http state: ");
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&tv, de_ctx, det_ctx, p);

    if (PacketAlertCheck(p, 1)) {
        printf("sig 1 alerted, but it should not: ");
        goto end;
    }

    result = 1;

end:
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

/** \test Test the pcre /U option in combination with urilen */
static int UriTestSig09(void)
{
    int result = 0;
    Flow f;
    HtpState *http_state = NULL;
    uint8_t http_buf1[] = "POST /oneoneoneone HTTP/1.0\r\n"
        "User-Agent: Mozilla/1.0\r\n"
        "Cookie: hellocatch\r\n\r\n";
    uint32_t http_buf1_len = sizeof(http_buf1) - 1;
    uint8_t http_buf2[] = "POST /oneoneself HTTP/1.0\r\n"
        "User-Agent: Mozilla/1.0\r\n"
        "Cookie: hellocatch\r\n\r\n";
    uint32_t http_buf2_len = sizeof(http_buf2) - 1;
    TcpSession ssn;
    Packet *p = NULL;
    Signature *s = NULL;
    ThreadVars tv;
    DetectEngineThreadCtx *det_ctx = NULL;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&tv, 0, sizeof(ThreadVars));
    memset(&f, 0, sizeof(Flow));
    memset(&ssn, 0, sizeof(TcpSession));

    p = UTHBuildPacket(http_buf1, http_buf1_len, IPPROTO_TCP);

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;
    f.flags |= FLOW_IPV4;

    p->flow = &f;
    p->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    p->flowflags |= FLOW_PKT_TOSERVER;
    p->flowflags |= FLOW_PKT_ESTABLISHED;
    f.alproto = ALPROTO_HTTP;

    StreamTcpInitConfig(TRUE);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }
    de_ctx->mpm_matcher = MPM_B2G;
    de_ctx->flags |= DE_QUIET;

    s = de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                                   "(msg:\"Test pcre /U option with urilen \"; "
                                   "pcre:/(one){2,}(self)?/U; urilen:<2; sid:1;)");
    if (s == NULL) {
        goto end;
    }

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&tv, (void *)de_ctx, (void *)&det_ctx);

    SCMutexLock(&f.m);
    int r = AppLayerParserParse(alp_tctx, &f, ALPROTO_HTTP, STREAM_TOSERVER, http_buf1, http_buf1_len);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);

    http_state = f.alstate;
    if (http_state == NULL) {
        printf("no http state: ");
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&tv, de_ctx, det_ctx, p);

    if (PacketAlertCheck(p, 1)) {
        printf("sig 1 alerted, but it should not: ");
        goto end;
    }

    DetectEngineStateReset(f.de_state, STREAM_TOSERVER | STREAM_TOCLIENT);

    SCMutexLock(&f.m);
    r = AppLayerParserParse(alp_tctx, &f, ALPROTO_HTTP, STREAM_TOSERVER, http_buf2, http_buf2_len);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);

    http_state = f.alstate;
    if (http_state == NULL) {
        printf("no http state: ");
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&tv, de_ctx, det_ctx, p);

    if (PacketAlertCheck(p, 1)) {
        printf("sig 1 alerted, but it should not: ");
        goto end;
    }

    result = 1;

end:
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

/** \test Test the uricontent option in combination with urilen */
static int UriTestSig10(void)
{
    int result = 0;
    Flow f;
    HtpState *http_state = NULL;
    uint8_t http_buf1[] = "POST /oneoneoneone HTTP/1.0\r\n"
        "User-Agent: Mozilla/1.0\r\n"
        "Cookie: hellocatch\r\n\r\n";
    uint32_t http_buf1_len = sizeof(http_buf1) - 1;
    uint8_t http_buf2[] = "POST /oneoneself HTTP/1.0\r\n"
        "User-Agent: Mozilla/1.0\r\n"
        "Cookie: hellocatch\r\n\r\n";
    uint32_t http_buf2_len = sizeof(http_buf2) - 1;
    TcpSession ssn;
    Packet *p = NULL;
    Signature *s = NULL;
    ThreadVars tv;
    DetectEngineThreadCtx *det_ctx = NULL;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&tv, 0, sizeof(ThreadVars));
    memset(&f, 0, sizeof(Flow));
    memset(&ssn, 0, sizeof(TcpSession));

    p = UTHBuildPacket(http_buf1, http_buf1_len, IPPROTO_TCP);

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;
    f.flags |= FLOW_IPV4;

    p->flow = &f;
    p->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    p->flowflags |= FLOW_PKT_TOSERVER;
    p->flowflags |= FLOW_PKT_ESTABLISHED;
    f.alproto = ALPROTO_HTTP;

    StreamTcpInitConfig(TRUE);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }
    de_ctx->mpm_matcher = MPM_B2G;
    de_ctx->flags |= DE_QUIET;

    s = de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                                   "(msg:\"Test uricontent with urilen option\"; "
                                   "uricontent:\"one\"; urilen:<2; sid:1;)");
    if (s == NULL) {
        goto end;
    }

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&tv, (void *)de_ctx, (void *)&det_ctx);

    SCMutexLock(&f.m);
    int r = AppLayerParserParse(alp_tctx, &f, ALPROTO_HTTP, STREAM_TOSERVER, http_buf1, http_buf1_len);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);

    http_state = f.alstate;
    if (http_state == NULL) {
        printf("no http state: ");
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&tv, de_ctx, det_ctx, p);

    if (PacketAlertCheck(p, 1)) {
        printf("sig 1 alerted, but it should not: ");
        goto end;
    }

    DetectEngineStateReset(f.de_state, STREAM_TOSERVER | STREAM_TOCLIENT);

    SCMutexLock(&f.m);
    r = AppLayerParserParse(alp_tctx, &f, ALPROTO_HTTP, STREAM_TOSERVER, http_buf2, http_buf2_len);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);

    http_state = f.alstate;
    if (http_state == NULL) {
        printf("no http state: ");
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&tv, de_ctx, det_ctx, p);

    if (PacketAlertCheck(p, 1)) {
        printf("sig 1 alerted, but it should not: ");
        goto end;
    }

    result = 1;

end:
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

/** \test Test content, uricontent, urilen, pcre /U options */
static int UriTestSig11(void)
{
    int result = 0;
    Flow f;
    HtpState *http_state = NULL;
    uint8_t http_buf1[] = "POST /oneoneoneone HTTP/1.0\r\n"
        "User-Agent: Mozilla/1.0\r\n"
        "Cookie: hellocatch\r\n\r\n";
    uint32_t http_buf1_len = sizeof(http_buf1) - 1;
    uint8_t http_buf2[] = "POST /oneoneself HTTP/1.0\r\n"
        "User-Agent: Mozilla/1.0\r\n"
        "Cookie: hellocatch\r\n\r\n";
    uint32_t http_buf2_len = sizeof(http_buf2) - 1;
    TcpSession ssn;
    Packet *p = NULL;
    Signature *s = NULL;
    ThreadVars tv;
    DetectEngineThreadCtx *det_ctx = NULL;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&tv, 0, sizeof(ThreadVars));
    memset(&f, 0, sizeof(Flow));
    memset(&ssn, 0, sizeof(TcpSession));

    p = UTHBuildPacket(http_buf1, http_buf1_len, IPPROTO_TCP);

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;
    f.flags |= FLOW_IPV4;

    p->flow = &f;
    p->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    p->flowflags |= FLOW_PKT_TOSERVER;
    p->flowflags |= FLOW_PKT_ESTABLISHED;
    f.alproto = ALPROTO_HTTP;

    StreamTcpInitConfig(TRUE);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }
    de_ctx->mpm_matcher = MPM_B2G;
    de_ctx->flags |= DE_QUIET;

    s = de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                                   "(msg:\"Test content, uricontent, pcre /U and urilen options\"; "
                                   "content:\"one\"; uricontent:\"one\"; pcre:/(one){2,}(self)?/U;"
                                   "urilen:<2; sid:1;)");
    if (s == NULL) {
        goto end;
    }

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&tv, (void *)de_ctx, (void *)&det_ctx);

    SCMutexLock(&f.m);
    int r = AppLayerParserParse(alp_tctx, &f, ALPROTO_HTTP, STREAM_TOSERVER, http_buf1, http_buf1_len);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);

    http_state = f.alstate;
    if (http_state == NULL) {
        printf("no http state: ");
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&tv, de_ctx, det_ctx, p);

    if (PacketAlertCheck(p, 1)) {
        printf("sig 1 alerted, but it should not: ");
        goto end;
    }

    DetectEngineStateReset(f.de_state, STREAM_TOSERVER | STREAM_TOCLIENT);

    SCMutexLock(&f.m);
    r = AppLayerParserParse(alp_tctx, &f, ALPROTO_HTTP, STREAM_TOSERVER, http_buf2, http_buf2_len);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);

    http_state = f.alstate;
    if (http_state == NULL) {
        printf("no http state: ");
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&tv, de_ctx, det_ctx, p);

    if (PacketAlertCheck(p, 1)) {
        printf("sig 1 alerted, but it should not: ");
        goto end;
    }

    result = 1;

end:
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

/** \test Test uricontent, urilen, pcre /U options */
static int UriTestSig12(void)
{
    int result = 0;
    Flow f;
    HtpState *http_state = NULL;
    uint8_t http_buf1[] = "POST /oneoneoneone HTTP/1.0\r\n"
        "User-Agent: Mozilla/1.0\r\n"
        "Cookie: hellocatch\r\n\r\n";
    uint32_t http_buf1_len = sizeof(http_buf1) - 1;
    uint8_t http_buf2[] = "POST /oneoneself HTTP/1.0\r\n"
        "User-Agent: Mozilla/1.0\r\n"
        "Cookie: hellocatch\r\n\r\n";
    uint32_t http_buf2_len = sizeof(http_buf2) - 1;
    TcpSession ssn;
    Packet *p = NULL;
    Signature *s = NULL;
    ThreadVars tv;
    DetectEngineThreadCtx *det_ctx = NULL;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&tv, 0, sizeof(ThreadVars));
    memset(&f, 0, sizeof(Flow));
    memset(&ssn, 0, sizeof(TcpSession));

    p = UTHBuildPacket(http_buf1, http_buf1_len, IPPROTO_TCP);

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;
    f.flags |= FLOW_IPV4;

    p->flow = &f;
    p->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    p->flowflags |= FLOW_PKT_TOSERVER;
    p->flowflags |= FLOW_PKT_ESTABLISHED;
    f.alproto = ALPROTO_HTTP;

    StreamTcpInitConfig(TRUE);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }
    de_ctx->mpm_matcher = MPM_B2G;
    de_ctx->flags |= DE_QUIET;

    s = de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                                   "(msg:\"Test pcre /U, uricontent and urilen option\"; "
                                   "uricontent:\"one\"; "
                                   "pcre:/(one)+self/U; urilen:>2; sid:1;)");
    if (s == NULL) {
        goto end;
    }

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&tv, (void *)de_ctx, (void *)&det_ctx);

    SCMutexLock(&f.m);
    int r = AppLayerParserParse(alp_tctx, &f, ALPROTO_HTTP, STREAM_TOSERVER, http_buf1, http_buf1_len);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);

    http_state = f.alstate;
    if (http_state == NULL) {
        printf("no http state: ");
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&tv, de_ctx, det_ctx, p);

    if (PacketAlertCheck(p, 1)) {
        printf("sig 1 alerted, but it should not: ");
        goto end;
    }

    DetectEngineStateReset(f.de_state, STREAM_TOSERVER | STREAM_TOCLIENT);

    SCMutexLock(&f.m);
    r = AppLayerParserParse(alp_tctx, &f, ALPROTO_HTTP, STREAM_TOSERVER, http_buf2, http_buf2_len);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);

    http_state = f.alstate;
    if (http_state == NULL) {
        printf("no http state: ");
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&tv, de_ctx, det_ctx, p);

    if (!PacketAlertCheck(p, 1)) {
        printf("sig 1 didnt alert with payload2, but it should: ");
        goto end;
    }

    result = 1;

end:
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

/** \test Test uricontent, urilen */
static int UriTestSig13(void)
{
    int result = 0;
    Flow f;
    HtpState *http_state = NULL;
    uint8_t http_buf1[] = "POST /one HTTP/1.0\r\n"
        "User-Agent: Mozilla/1.0\r\n"
        "Cookie: hellocatch\r\n\r\n";
    uint32_t http_buf1_len = sizeof(http_buf1) - 1;
    uint8_t http_buf2[] = "POST /oneself HTTP/1.0\r\n"
        "User-Agent: Mozilla/1.0\r\n"
        "Cookie: hellocatch\r\n\r\n";
    uint32_t http_buf2_len = sizeof(http_buf2) - 1;
    TcpSession ssn;
    Packet *p = NULL;
    Signature *s = NULL;
    ThreadVars tv;
    DetectEngineThreadCtx *det_ctx = NULL;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&tv, 0, sizeof(ThreadVars));
    memset(&f, 0, sizeof(Flow));
    memset(&ssn, 0, sizeof(TcpSession));

    p = UTHBuildPacket(http_buf1, http_buf1_len, IPPROTO_TCP);

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;
    f.flags |= FLOW_IPV4;

    p->flow = &f;
    p->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    p->flowflags |= FLOW_PKT_TOSERVER;
    p->flowflags |= FLOW_PKT_ESTABLISHED;
    f.alproto = ALPROTO_HTTP;

    StreamTcpInitConfig(TRUE);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }
    de_ctx->mpm_matcher = MPM_B2G;
    de_ctx->flags |= DE_QUIET;

    s = de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                                   "(msg:\"Test urilen option\"; "
                                   "urilen:>2; uricontent:\"one\"; sid:1;)");
    if (s == NULL) {
        goto end;
    }

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&tv, (void *)de_ctx, (void *)&det_ctx);

    SCMutexLock(&f.m);
    int r = AppLayerParserParse(alp_tctx, &f, ALPROTO_HTTP, STREAM_TOSERVER, http_buf1, http_buf1_len);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);

    http_state = f.alstate;
    if (http_state == NULL) {
        printf("no http state: ");
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&tv, de_ctx, det_ctx, p);

    if (!PacketAlertCheck(p, 1)) {
        printf("sig 1 didnt alert with pkt, but it should: ");
        goto end;
    }

    DetectEngineStateReset(f.de_state, STREAM_TOSERVER | STREAM_TOCLIENT);

    SCMutexLock(&f.m);
    r = AppLayerParserParse(alp_tctx, &f, ALPROTO_HTTP, STREAM_TOSERVER, http_buf2, http_buf2_len);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);

    http_state = f.alstate;
    if (http_state == NULL) {
        printf("no http state: ");
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&tv, de_ctx, det_ctx, p);


    if (!PacketAlertCheck(p, 1)) {
        printf("sig 1 didnt alert with payload2, but it should: ");
        goto end;
    }

    result = 1;

end:
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

/** \test Test uricontent, pcre /U */
static int UriTestSig14(void)
{
    int result = 0;
    Flow f;
    HtpState *http_state = NULL;
    uint8_t http_buf1[] = "POST /one HTTP/1.0\r\n"
        "User-Agent: Mozilla/1.0\r\n"
        "Cookie: hellocatch\r\n\r\n";
    uint32_t http_buf1_len = sizeof(http_buf1) - 1;
    uint8_t http_buf2[] = "POST /oneself HTTP/1.0\r\n"
        "User-Agent: Mozilla/1.0\r\n"
        "Cookie: hellocatch\r\n\r\n";
    uint32_t http_buf2_len = sizeof(http_buf2) - 1;
    TcpSession ssn;
    Packet *p = NULL;
    Signature *s = NULL;
    ThreadVars tv;
    DetectEngineThreadCtx *det_ctx = NULL;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&tv, 0, sizeof(ThreadVars));
    memset(&f, 0, sizeof(Flow));
    memset(&ssn, 0, sizeof(TcpSession));

    p = UTHBuildPacket(http_buf1, http_buf1_len, IPPROTO_TCP);

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;
    f.flags |= FLOW_IPV4;

    p->flow = &f;
    p->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    p->flowflags |= FLOW_PKT_TOSERVER;
    p->flowflags |= FLOW_PKT_ESTABLISHED;
    f.alproto = ALPROTO_HTTP;

    StreamTcpInitConfig(TRUE);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }
    de_ctx->mpm_matcher = MPM_B2G;
    de_ctx->flags |= DE_QUIET;

    s = de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                                   "(msg:\"Test uricontent option\"; "
                                   "uricontent:\"one\"; pcre:/one(self)?/U;sid:1;)");
    if (s == NULL) {
        goto end;
    }

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&tv, (void *)de_ctx, (void *)&det_ctx);

    SCMutexLock(&f.m);
    int r = AppLayerParserParse(alp_tctx, &f, ALPROTO_HTTP, STREAM_TOSERVER, http_buf1, http_buf1_len);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);

    http_state = f.alstate;
    if (http_state == NULL) {
        printf("no http state: ");
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&tv, de_ctx, det_ctx, p);

    if (!PacketAlertCheck(p, 1)) {
        printf("sig 1 didnt alert with pkt, but it should: ");
        goto end;
    }

    DetectEngineStateReset(f.de_state, STREAM_TOSERVER | STREAM_TOCLIENT);

    SCMutexLock(&f.m);
    r = AppLayerParserParse(alp_tctx, &f, ALPROTO_HTTP, STREAM_TOSERVER, http_buf2, http_buf2_len);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);

    http_state = f.alstate;
    if (http_state == NULL) {
        printf("no http state: ");
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&tv, de_ctx, det_ctx, p);


    if (!PacketAlertCheck(p, 1)) {
        printf("sig 1 didnt alert with payload2, but it should: ");
        goto end;
    }

    result = 1;

end:
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

/** \test Test pcre /U with anchored regex (bug 155) */
static int UriTestSig15(void)
{
    int result = 0;
    Flow f;
    HtpState *http_state = NULL;
    uint8_t http_buf1[] = "POST /one HTTP/1.0\r\n"
        "User-Agent: Mozilla/1.0\r\n"
        "Cookie: hellocatch\r\n\r\n";
    uint32_t http_buf1_len = sizeof(http_buf1) - 1;
    uint8_t http_buf2[] = "POST /oneself HTTP/1.0\r\n"
        "User-Agent: Mozilla/1.0\r\n"
        "Cookie: hellocatch\r\n\r\n";
    uint32_t http_buf2_len = sizeof(http_buf2) - 1;
    TcpSession ssn;
    Packet *p = NULL;
    Signature *s = NULL;
    ThreadVars tv;
    DetectEngineThreadCtx *det_ctx = NULL;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&tv, 0, sizeof(ThreadVars));
    memset(&f, 0, sizeof(Flow));
    memset(&ssn, 0, sizeof(TcpSession));

    p = UTHBuildPacket(http_buf1, http_buf1_len, IPPROTO_TCP);

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;
    f.flags |= FLOW_IPV4;

    p->flow = &f;
    p->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    p->flowflags |= FLOW_PKT_TOSERVER;
    p->flowflags |= FLOW_PKT_ESTABLISHED;
    f.alproto = ALPROTO_HTTP;

    StreamTcpInitConfig(TRUE);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }
    de_ctx->mpm_matcher = MPM_B2G;
    de_ctx->flags |= DE_QUIET;

    s = de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                                   "(msg:\"Test uricontent option\"; "
                                   "uricontent:\"one\"; pcre:/^\\/one(self)?$/U;sid:1;)");
    if (s == NULL) {
        goto end;
    }

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&tv, (void *)de_ctx, (void *)&det_ctx);

    SCMutexLock(&f.m);
    int r = AppLayerParserParse(alp_tctx, &f, ALPROTO_HTTP, STREAM_TOSERVER, http_buf1, http_buf1_len);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);

    http_state = f.alstate;
    if (http_state == NULL) {
        printf("no http state: ");
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&tv, de_ctx, det_ctx, p);

    if (!PacketAlertCheck(p, 1)) {
        printf("sig 1 didnt alert with pkt, but it should: ");
        goto end;
    }

    DetectEngineStateReset(f.de_state, STREAM_TOSERVER | STREAM_TOCLIENT);

    SCMutexLock(&f.m);
    r = AppLayerParserParse(alp_tctx, &f, ALPROTO_HTTP, STREAM_TOSERVER, http_buf2, http_buf2_len);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);

    http_state = f.alstate;
    if (http_state == NULL) {
        printf("no http state: ");
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&tv, de_ctx, det_ctx, p);


    if (!PacketAlertCheck(p, 1)) {
        printf("sig 1 didnt alert with payload2, but it should: ");
        goto end;
    }

    result = 1;

end:
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

/** \test Test pcre /U with anchored regex (bug 155) */
static int UriTestSig16(void)
{
    int result = 0;
    Flow f;
    HtpState *http_state = NULL;
    uint8_t http_buf1[] = "POST /search?q=123&aq=7123abcee HTTP/1.0\r\n"
        "User-Agent: Mozilla/1.0/\r\n"
        "Host: 1.2.3.4\r\n\r\n";
    uint32_t http_buf1_len = sizeof(http_buf1) - 1;
    uint8_t http_buf2[] = "POST /search?q=123&aq=7123abcee HTTP/1.0\r\n"
        "User-Agent: Mozilla/1.0\r\n"
        "Cookie: hellocatch\r\n\r\n";
    uint32_t http_buf2_len = sizeof(http_buf2) - 1;
    TcpSession ssn;
    Packet *p = NULL;
    Signature *s = NULL;
    ThreadVars tv;
    DetectEngineThreadCtx *det_ctx = NULL;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&tv, 0, sizeof(ThreadVars));
    memset(&f, 0, sizeof(Flow));
    memset(&ssn, 0, sizeof(TcpSession));

    p = UTHBuildPacket(http_buf1, http_buf1_len, IPPROTO_TCP);

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;
    f.flags |= FLOW_IPV4;

    p->flow = &f;
    p->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    p->flowflags |= FLOW_PKT_TOSERVER;
    p->flowflags |= FLOW_PKT_ESTABLISHED;
    f.alproto = ALPROTO_HTTP;

    StreamTcpInitConfig(TRUE);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }
    de_ctx->mpm_matcher = MPM_B2G;
    de_ctx->flags |= DE_QUIET;

    s = de_ctx->sig_list = SigInit(de_ctx, "drop tcp any any -> any any (msg:\"ET TROJAN Downadup/Conficker A or B Worm reporting\"; flow:to_server,established; uricontent:\"/search?q=\"; pcre:\"/^\\/search\\?q=[0-9]{1,3}(&aq=7(\\?[0-9a-f]{8})?)?/U\"; pcre:\"/\\x0d\\x0aHost\\: \\d+\\.\\d+\\.\\d+\\.\\d+\\x0d\\x0a/\"; sid:2009024; rev:9;)");
    if (s == NULL) {
        goto end;
    }

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&tv, (void *)de_ctx, (void *)&det_ctx);

    SCMutexLock(&f.m);
    int r = AppLayerParserParse(alp_tctx, &f, ALPROTO_HTTP, STREAM_TOSERVER, http_buf1, http_buf1_len);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);

    http_state = f.alstate;
    if (http_state == NULL) {
        printf("no http state: ");
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&tv, de_ctx, det_ctx, p);

    if (!PacketAlertCheck(p, 2009024)) {
        printf("sig 1 didnt alert with pkt, but it should: ");
        goto end;
    }
    p->alerts.cnt = 0;

    DetectEngineStateReset(f.de_state, STREAM_TOSERVER | STREAM_TOCLIENT);
    p->payload = http_buf2;
    p->payload_len = http_buf2_len;

    SCMutexLock(&f.m);
    r = AppLayerParserParse(alp_tctx, &f, ALPROTO_HTTP, STREAM_TOSERVER, http_buf2, http_buf2_len);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);

    http_state = f.alstate;
    if (http_state == NULL) {
        printf("no http state: ");
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&tv, de_ctx, det_ctx, p);

    if (PacketAlertCheck(p, 2009024)) {
        printf("sig 1 alerted, but it should not (host should not match): ");
        goto end;
    }

    result = 1;

end:
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
 * \test Test multiple relative contents
 */
static int UriTestSig17(void)
{
    int result = 0;
    uint8_t *http_buf = (uint8_t *)"POST /now_this_is_is_big_big_string_now HTTP/1.0\r\n"
        "User-Agent: Mozilla/1.0\r\n";
    uint32_t http_buf_len = strlen((char *)http_buf);
    Flow f;
    TcpSession ssn;
    HtpState *http_state = NULL;
    Packet *p = NULL;
    ThreadVars tv;
    DetectEngineThreadCtx *det_ctx = NULL;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&tv, 0, sizeof(ThreadVars));
    memset(&f, 0, sizeof(Flow));
    memset(&ssn, 0, sizeof(TcpSession));

    p = UTHBuildPacket(http_buf, http_buf_len, IPPROTO_TCP);

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;
    f.flags |= FLOW_IPV4;

    p->flow = &f;
    p->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    p->flowflags |= FLOW_PKT_TOSERVER;
    p->flowflags |= FLOW_PKT_ESTABLISHED;
    f.alproto = ALPROTO_HTTP;

    StreamTcpInitConfig(TRUE);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }
    de_ctx->mpm_matcher = MPM_B2G;
    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(msg:\"test multiple relative uricontents\"; "
                               "uricontent:\"this\"; uricontent:\"is\"; within:6; "
                               "uricontent:\"big\"; within:8; "
                               "uricontent:\"string\"; within:8; sid:1;)");
    if (de_ctx->sig_list == NULL) {
        goto end;
    }

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&tv, (void *)de_ctx, (void *)&det_ctx);

    SCMutexLock(&f.m);
    int r = AppLayerParserParse(alp_tctx, &f, ALPROTO_HTTP, STREAM_TOSERVER, http_buf, http_buf_len);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);

    http_state = f.alstate;
    if (http_state == NULL) {
        printf("no http state: ");
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&tv, de_ctx, det_ctx, p);

    if (!PacketAlertCheck(p, 1)) {
        printf("sig 1 alerted, but it should not: ");
        goto end;
    }

    result = 1;

end:
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
 * \test Test multiple relative contents
 */
static int UriTestSig18(void)
{
    int result = 0;
    uint8_t *http_buf = (uint8_t *)"POST /now_this_is_is_is_big_big_big_string_now HTTP/1.0\r\n"
        "User-Agent: Mozilla/1.0\r\n";
    uint32_t http_buf_len = strlen((char *)http_buf);
    Flow f;
    TcpSession ssn;
    HtpState *http_state = NULL;
    Packet *p = NULL;
    ThreadVars tv;
    DetectEngineThreadCtx *det_ctx = NULL;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&tv, 0, sizeof(ThreadVars));
    memset(&f, 0, sizeof(Flow));
    memset(&ssn, 0, sizeof(TcpSession));

    p = UTHBuildPacket(http_buf, http_buf_len, IPPROTO_TCP);

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;
    f.flags |= FLOW_IPV4;

    p->flow = &f;
    p->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    p->flowflags |= FLOW_PKT_TOSERVER;
    p->flowflags |= FLOW_PKT_ESTABLISHED;
    f.alproto = ALPROTO_HTTP;

    StreamTcpInitConfig(TRUE);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }
    de_ctx->mpm_matcher = MPM_B2G;
    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(msg:\"test multiple relative uricontents\"; "
                               "uricontent:\"this\"; uricontent:\"is\"; within:9; "
                               "uricontent:\"big\"; within:12; "
                               "uricontent:\"string\"; within:8; sid:1;)");
    if (de_ctx->sig_list == NULL) {
        goto end;
    }

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&tv, (void *)de_ctx, (void *)&det_ctx);

    SCMutexLock(&f.m);
    int r = AppLayerParserParse(alp_tctx, &f, ALPROTO_HTTP, STREAM_TOSERVER, http_buf, http_buf_len);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);

    http_state = f.alstate;
    if (http_state == NULL) {
        printf("no http state: ");
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&tv, de_ctx, det_ctx, p);

    if (!PacketAlertCheck(p, 1)) {
        printf("sig 1 alerted, but it should not: ");
        goto end;
    }

    result = 1;

end:
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
 * \test Test multiple relative contents
 */
static int UriTestSig19(void)
{
    int result = 0;
    uint8_t *http_buf = (uint8_t *)"POST /this_this_now_is_is_____big_string_now HTTP/1.0\r\n"
        "User-Agent: Mozilla/1.0\r\n";
    uint32_t http_buf_len = strlen((char *)http_buf);
    Flow f;
    TcpSession ssn;
    HtpState *http_state = NULL;
    Packet *p = NULL;
    ThreadVars tv;
    DetectEngineThreadCtx *det_ctx = NULL;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&tv, 0, sizeof(ThreadVars));
    memset(&f, 0, sizeof(Flow));
    memset(&ssn, 0, sizeof(TcpSession));

    p = UTHBuildPacket(http_buf, http_buf_len, IPPROTO_TCP);

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;
    f.flags |= FLOW_IPV4;

    p->flow = &f;
    p->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    p->flowflags |= FLOW_PKT_TOSERVER;
    p->flowflags |= FLOW_PKT_ESTABLISHED;
    f.alproto = ALPROTO_HTTP;

    StreamTcpInitConfig(TRUE);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }
    de_ctx->mpm_matcher = MPM_B2G;
    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(msg:\"test multiple relative uricontents\"; "
                               "uricontent:\"now\"; uricontent:\"this\"; "
                               "uricontent:\"is\"; within:12; "
                               "uricontent:\"big\"; within:8; "
                               "uricontent:\"string\"; within:8; sid:1;)");
    if (de_ctx->sig_list == NULL) {
        goto end;
    }

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&tv, (void *)de_ctx, (void *)&det_ctx);

    SCMutexLock(&f.m);
    int r = AppLayerParserParse(alp_tctx, &f, ALPROTO_HTTP, STREAM_TOSERVER, http_buf, http_buf_len);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);

    http_state = f.alstate;
    if (http_state == NULL) {
        printf("no http state: ");
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&tv, de_ctx, det_ctx, p);

    if (!PacketAlertCheck(p, 1)) {
        printf("sig 1 alerted, but it should not: ");
        goto end;
    }

    result = 1;

end:
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
 * \test Test multiple relative contents with offset
 */
static int UriTestSig20(void)
{
    int result = 0;
    uint8_t *http_buf = (uint8_t *)"POST /_________thus_thus_is_a_big HTTP/1.0\r\n"
        "User-Agent: Mozilla/1.0\r\n";
    uint32_t http_buf_len = strlen((char *)http_buf);
    Flow f;
    TcpSession ssn;
    HtpState *http_state = NULL;
    Packet *p = NULL;
    ThreadVars tv;
    DetectEngineThreadCtx *det_ctx = NULL;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&tv, 0, sizeof(ThreadVars));
    memset(&f, 0, sizeof(Flow));
    memset(&ssn, 0, sizeof(TcpSession));

    p = UTHBuildPacket(http_buf, http_buf_len, IPPROTO_TCP);

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;
    f.flags |= FLOW_IPV4;

    p->flow = &f;
    p->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    p->flowflags |= FLOW_PKT_TOSERVER;
    p->flowflags |= FLOW_PKT_ESTABLISHED;
    f.alproto = ALPROTO_HTTP;

    StreamTcpInitConfig(TRUE);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }
    de_ctx->mpm_matcher = MPM_B2G;
    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(msg:\"test multiple relative uricontents\"; "
                               "uricontent:\"thus\"; offset:8; "
                               "uricontent:\"is\"; within:6; "
                               "uricontent:\"big\"; within:8; sid:1;)");
    if (de_ctx->sig_list == NULL) {
        goto end;
    }

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&tv, (void *)de_ctx, (void *)&det_ctx);

    SCMutexLock(&f.m);
    int r = AppLayerParserParse(alp_tctx, &f, ALPROTO_HTTP, STREAM_TOSERVER, http_buf, http_buf_len);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);

    http_state = f.alstate;
    if (http_state == NULL) {
        printf("no http state: ");
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&tv, de_ctx, det_ctx, p);

    if (!PacketAlertCheck(p, 1)) {
        printf("sig 1 alerted, but it should not: ");
        goto end;
    }

    result = 1;

end:
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
 * \test Test multiple relative contents with a negated content.
 */
static int UriTestSig21(void)
{
    int result = 0;
    uint8_t *http_buf = (uint8_t *)"POST /we_need_to_fix_this_and_yes_fix_this_now HTTP/1.0\r\n"
        "User-Agent: Mozilla/1.0\r\n";
    uint32_t http_buf_len = strlen((char *)http_buf);
    Flow f;
    TcpSession ssn;
    HtpState *http_state = NULL;
    Packet *p = NULL;
    ThreadVars tv;
    DetectEngineThreadCtx *det_ctx = NULL;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&tv, 0, sizeof(ThreadVars));
    memset(&f, 0, sizeof(Flow));
    memset(&ssn, 0, sizeof(TcpSession));

    p = UTHBuildPacket(http_buf, http_buf_len, IPPROTO_TCP);

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;
    f.flags |= FLOW_IPV4;

    p->flow = &f;
    p->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    p->flowflags |= FLOW_PKT_TOSERVER;
    p->flowflags |= FLOW_PKT_ESTABLISHED;
    f.alproto = ALPROTO_HTTP;

    StreamTcpInitConfig(TRUE);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }
    de_ctx->mpm_matcher = MPM_B2G;
    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(msg:\"test multiple relative uricontents\"; "
                               "uricontent:\"fix\"; uricontent:\"this\"; within:6; "
                               "uricontent:!\"and\"; distance:0; sid:1;)");
    if (de_ctx->sig_list == NULL) {
        goto end;
    }

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&tv, (void *)de_ctx, (void *)&det_ctx);

    SCMutexLock(&f.m);
    int r = AppLayerParserParse(alp_tctx, &f, ALPROTO_HTTP, STREAM_TOSERVER, http_buf, http_buf_len);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);

    http_state = f.alstate;
    if (http_state == NULL) {
        printf("no http state: ");
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&tv, de_ctx, det_ctx, p);

    if (!PacketAlertCheck(p, 1)) {
        printf("sig 1 alerted, but it should not: ");
        goto end;
    }

    result = 1;

end:
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
 * \test Test relative pcre.
 */
static int UriTestSig22(void)
{
    int result = 0;
    uint8_t *http_buf = (uint8_t *)"POST /this_is_a_super_duper_"
        "nova_in_super_nova_now HTTP/1.0\r\n"
        "User-Agent: Mozilla/1.0\r\n";
    uint32_t http_buf_len = strlen((char *)http_buf);
    Flow f;
    TcpSession ssn;
    HtpState *http_state = NULL;
    Packet *p = NULL;
    ThreadVars tv;
    DetectEngineThreadCtx *det_ctx = NULL;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&tv, 0, sizeof(ThreadVars));
    memset(&f, 0, sizeof(Flow));
    memset(&ssn, 0, sizeof(TcpSession));

    p = UTHBuildPacket(http_buf, http_buf_len, IPPROTO_TCP);

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;
    f.flags |= FLOW_IPV4;

    p->flow = &f;
    p->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    p->flowflags |= FLOW_PKT_TOSERVER;
    p->flowflags |= FLOW_PKT_ESTABLISHED;
    f.alproto = ALPROTO_HTTP;

    StreamTcpInitConfig(TRUE);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }
    de_ctx->mpm_matcher = MPM_B2G;
    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(msg:\"test multiple relative uricontents\"; "
                               "pcre:/super/U; uricontent:\"nova\"; within:7; sid:1;)");
    if (de_ctx->sig_list == NULL) {
        goto end;
    }

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&tv, (void *)de_ctx, (void *)&det_ctx);

    SCMutexLock(&f.m);
    int r = AppLayerParserParse(alp_tctx, &f, ALPROTO_HTTP, STREAM_TOSERVER, http_buf, http_buf_len);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);

    http_state = f.alstate;
    if (http_state == NULL) {
        printf("no http state: ");
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&tv, de_ctx, det_ctx, p);

    if (!PacketAlertCheck(p, 1)) {
        printf("sig 1 didn't alert, but it should have: ");
        goto end;
    }

    result = 1;

end:
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
 * \test Test multiple relative contents with a negated content.
 */
static int UriTestSig23(void)
{
    int result = 0;
    uint8_t *http_buf = (uint8_t *)"POST /we_need_to_fix_this_and_yes_fix_this_now HTTP/1.0\r\n"
        "User-Agent: Mozilla/1.0\r\n";
    uint32_t http_buf_len = strlen((char *)http_buf);
    Flow f;
    TcpSession ssn;
    HtpState *http_state = NULL;
    Packet *p = NULL;
    ThreadVars tv;
    DetectEngineThreadCtx *det_ctx = NULL;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&tv, 0, sizeof(ThreadVars));
    memset(&f, 0, sizeof(Flow));
    memset(&ssn, 0, sizeof(TcpSession));

    p = UTHBuildPacket(http_buf, http_buf_len, IPPROTO_TCP);

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;
    f.flags |= FLOW_IPV4;

    p->flow = &f;
    p->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    p->flowflags |= FLOW_PKT_TOSERVER;
    p->flowflags |= FLOW_PKT_ESTABLISHED;
    f.alproto = ALPROTO_HTTP;

    StreamTcpInitConfig(TRUE);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }
    de_ctx->mpm_matcher = MPM_B2G;
    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(msg:\"test multiple relative uricontents\"; "
                               "uricontent:!\"fix_this_now\"; sid:1;)");
    if (de_ctx->sig_list == NULL) {
        goto end;
    }

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&tv, (void *)de_ctx, (void *)&det_ctx);

    SCMutexLock(&f.m);
    int r = AppLayerParserParse(alp_tctx, &f, ALPROTO_HTTP, STREAM_TOSERVER, http_buf, http_buf_len);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);

    http_state = f.alstate;
    if (http_state == NULL) {
        printf("no http state: ");
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&tv, de_ctx, det_ctx, p);

    if (PacketAlertCheck(p, 1)) {
        printf("sig 1 alerted, but it should not: ");
        goto end;
    }

    result = 1;

end:
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
 * \test Test multiple relative contents with a negated content.
 */
static int UriTestSig24(void)
{
    int result = 0;
    uint8_t *http_buf = (uint8_t *)"POST /we_need_to_fix_this_and_yes_fix_this_now HTTP/1.0\r\n"
        "User-Agent: Mozilla/1.0\r\n";
    uint32_t http_buf_len = strlen((char *)http_buf);
    Flow f;
    TcpSession ssn;
    HtpState *http_state = NULL;
    Packet *p = NULL;
    ThreadVars tv;
    DetectEngineThreadCtx *det_ctx = NULL;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&tv, 0, sizeof(ThreadVars));
    memset(&f, 0, sizeof(Flow));
    memset(&ssn, 0, sizeof(TcpSession));

    p = UTHBuildPacket(http_buf, http_buf_len, IPPROTO_TCP);

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;
    f.flags |= FLOW_IPV4;

    p->flow = &f;
    p->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    p->flowflags |= FLOW_PKT_TOSERVER;
    p->flowflags |= FLOW_PKT_ESTABLISHED;
    f.alproto = ALPROTO_HTTP;

    StreamTcpInitConfig(TRUE);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }
    de_ctx->mpm_matcher = MPM_B2G;
    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(msg:\"test multiple relative uricontents\"; "
                               "uricontent:\"we_need_to\"; uricontent:!\"fix_this_now\"; sid:1;)");
    if (de_ctx->sig_list == NULL) {
        goto end;
    }

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&tv, (void *)de_ctx, (void *)&det_ctx);

    SCMutexLock(&f.m);
    int r = AppLayerParserParse(alp_tctx, &f, ALPROTO_HTTP, STREAM_TOSERVER, http_buf, http_buf_len);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);

    http_state = f.alstate;
    if (http_state == NULL) {
        printf("no http state: ");
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&tv, de_ctx, det_ctx, p);

    if (PacketAlertCheck(p, 1)) {
        printf("sig 1 alerted, but it should not: ");
        goto end;
    }

    result = 1;

end:
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
 * \test Test normalized uricontents.
 */
static int UriTestSig25(void)
{
    int result = 0;
    uint8_t *http_buf = (uint8_t *)"POST /normalized%20uri "
        "HTTP/1.0\r\nUser-Agent: Mozilla/1.0\r\n";
    uint32_t http_buf_len = strlen((char *)http_buf);
    Flow f;
    TcpSession ssn;
    HtpState *http_state = NULL;
    Packet *p = NULL;
    ThreadVars tv;
    DetectEngineThreadCtx *det_ctx = NULL;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&tv, 0, sizeof(ThreadVars));
    memset(&f, 0, sizeof(Flow));
    memset(&ssn, 0, sizeof(TcpSession));

    p = UTHBuildPacket(http_buf, http_buf_len, IPPROTO_TCP);

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;
    f.flags |= FLOW_IPV4;

    p->flow = &f;
    p->flowflags |= FLOW_PKT_TOSERVER;
    p->flowflags |= FLOW_PKT_ESTABLISHED;
    f.alproto = ALPROTO_HTTP;
    p->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;

    StreamTcpInitConfig(TRUE);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }
    de_ctx->mpm_matcher = MPM_B2G;
    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(msg:\"test multiple relative uricontents\"; "
                               "pcre:/normalized/U; uricontent:\"normalized uri\"; sid:1;)");
    if (de_ctx->sig_list == NULL) {
        goto end;
    }

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&tv, (void *)de_ctx, (void *)&det_ctx);

    SCMutexLock(&f.m);
    int r = AppLayerParserParse(alp_tctx, &f, ALPROTO_HTTP, STREAM_TOSERVER, http_buf, http_buf_len);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);

    http_state = f.alstate;
    if (http_state == NULL) {
        printf("no http state: ");
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&tv, de_ctx, det_ctx, p);

    if (!PacketAlertCheck(p, 1)) {
        printf("sig 1 didn't alert, but it should have: ");
        goto end;
    }

    result = 1;

end:
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
 * \test Test multiple relative contents with a negated content.
 */
static int UriTestSig26(void)
{
    int result = 0;
    uint8_t *http_buf = (uint8_t *)"POST /we_need_to_fix_this_and_yes_fix_this_now HTTP/1.0\r\n"
        "User-Agent: Mozilla/1.0\r\n";
    uint32_t http_buf_len = strlen((char *)http_buf);
    Flow f;
    TcpSession ssn;
    HtpState *http_state = NULL;
    Packet *p = NULL;
    ThreadVars tv;
    DetectEngineThreadCtx *det_ctx = NULL;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&tv, 0, sizeof(ThreadVars));
    memset(&f, 0, sizeof(Flow));
    memset(&ssn, 0, sizeof(TcpSession));

    p = UTHBuildPacket(http_buf, http_buf_len, IPPROTO_TCP);

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;
    f.flags |= FLOW_IPV4;

    p->flow = &f;
    p->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    p->flowflags |= FLOW_PKT_TOSERVER;
    p->flowflags |= FLOW_PKT_ESTABLISHED;
    f.alproto = ALPROTO_HTTP;

    StreamTcpInitConfig(TRUE);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }
    de_ctx->mpm_matcher = MPM_B2G;
    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(msg:\"test multiple relative uricontents\"; "
                               "uricontent:\"fix_this\"; isdataat:4,relative; sid:1;)");
    if (de_ctx->sig_list == NULL) {
        goto end;
    }

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&tv, (void *)de_ctx, (void *)&det_ctx);

    SCMutexLock(&f.m);
    int r = AppLayerParserParse(alp_tctx, &f, ALPROTO_HTTP, STREAM_TOSERVER, http_buf, http_buf_len);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);

    http_state = f.alstate;
    if (http_state == NULL) {
        printf("no http state: ");
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&tv, de_ctx, det_ctx, p);

    if (!PacketAlertCheck(p, 1)) {
        printf("sig 1 didn't alert, but it should have: ");
        goto end;
    }

    result = 1;

end:
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
 * \test Test multiple relative contents with a negated content.
 */
static int UriTestSig27(void)
{
    int result = 0;
    uint8_t *http_buf = (uint8_t *)"POST /we_need_to_fix_this_and_yes_fix_this_now HTTP/1.0\r\n"
        "User-Agent: Mozilla/1.0\r\n";
    uint32_t http_buf_len = strlen((char *)http_buf);
    Flow f;
    TcpSession ssn;
    HtpState *http_state = NULL;
    Packet *p = NULL;
    ThreadVars tv;
    DetectEngineThreadCtx *det_ctx = NULL;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&tv, 0, sizeof(ThreadVars));
    memset(&f, 0, sizeof(Flow));
    memset(&ssn, 0, sizeof(TcpSession));

    p = UTHBuildPacket(http_buf, http_buf_len, IPPROTO_TCP);

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;
    f.flags |= FLOW_IPV4;

    p->flow = &f;
    p->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    p->flowflags |= FLOW_PKT_TOSERVER;
    p->flowflags |= FLOW_PKT_ESTABLISHED;
    f.alproto = ALPROTO_HTTP;

    StreamTcpInitConfig(TRUE);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }
    de_ctx->mpm_matcher = MPM_B2G;
    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(msg:\"test multiple relative uricontents\"; "
                               "uricontent:\"fix_this\"; isdataat:!10,relative; sid:1;)");
    if (de_ctx->sig_list == NULL) {
        goto end;
    }

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&tv, (void *)de_ctx, (void *)&det_ctx);

    SCMutexLock(&f.m);
    int r = AppLayerParserParse(alp_tctx, &f, ALPROTO_HTTP, STREAM_TOSERVER, http_buf, http_buf_len);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);

    http_state = f.alstate;
    if (http_state == NULL) {
        printf("no http state: ");
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&tv, de_ctx, det_ctx, p);

    if (!PacketAlertCheck(p, 1)) {
        printf("sig 1 didn't alert, but it should have: ");
        goto end;
    }

    result = 1;

end:
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




































static int UriTestSig28(void)
{
    int result = 0;
    uint8_t *http_buf = (uint8_t *)"POST /this_b5ig_string_now_in_http HTTP/1.0\r\n"
        "User-Agent: Mozilla/1.0\r\n";
    uint32_t http_buf_len = strlen((char *)http_buf);
    Flow f;
    TcpSession ssn;
    HtpState *http_state = NULL;
    Packet *p = NULL;
    ThreadVars tv;
    DetectEngineThreadCtx *det_ctx = NULL;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&tv, 0, sizeof(ThreadVars));
    memset(&f, 0, sizeof(Flow));
    memset(&ssn, 0, sizeof(TcpSession));

    p = UTHBuildPacket(http_buf, http_buf_len, IPPROTO_TCP);

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;
    f.flags |= FLOW_IPV4;

    p->flow = &f;
    p->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    p->flowflags |= FLOW_PKT_TOSERVER;
    p->flowflags |= FLOW_PKT_ESTABLISHED;
    f.alproto = ALPROTO_HTTP;

    StreamTcpInitConfig(TRUE);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }
    de_ctx->mpm_matcher = MPM_B2G;
    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,
                               "alert tcp any any -> any any (msg:\"dummy\"; "
                               "uricontent:\"this\"; "
                               "byte_extract:1,2,one,string,dec,relative; "
                               "uricontent:\"ring\"; distance:one; sid:1;)");
    if (de_ctx->sig_list == NULL) {
        goto end;
    }

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&tv, (void *)de_ctx, (void *)&det_ctx);

    SCMutexLock(&f.m);
    int r = AppLayerParserParse(alp_tctx, &f, ALPROTO_HTTP, STREAM_TOSERVER, http_buf, http_buf_len);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);

    http_state = f.alstate;
    if (http_state == NULL) {
        printf("no http state: ");
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&tv, de_ctx, det_ctx, p);

    if (!PacketAlertCheck(p, 1)) {
        printf("sig 1 didn't alert, but should have: ");
        goto end;
    }

    result = 1;

end:
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

static int UriTestSig29(void)
{
    int result = 0;
    uint8_t *http_buf = (uint8_t *)"POST /this_b5ig_string_now_in_http HTTP/1.0\r\n"
        "User-Agent: Mozilla/1.0\r\n";
    uint32_t http_buf_len = strlen((char *)http_buf);
    Flow f;
    TcpSession ssn;
    HtpState *http_state = NULL;
    Packet *p = NULL;
    ThreadVars tv;
    DetectEngineThreadCtx *det_ctx = NULL;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&tv, 0, sizeof(ThreadVars));
    memset(&f, 0, sizeof(Flow));
    memset(&ssn, 0, sizeof(TcpSession));

    p = UTHBuildPacket(http_buf, http_buf_len, IPPROTO_TCP);

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;
    f.flags |= FLOW_IPV4;

    p->flow = &f;
    p->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    p->flowflags |= FLOW_PKT_TOSERVER;
    p->flowflags |= FLOW_PKT_ESTABLISHED;
    f.alproto = ALPROTO_HTTP;

    StreamTcpInitConfig(TRUE);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }
    de_ctx->mpm_matcher = MPM_B2G;
    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,
                               "alert tcp any any -> any any (msg:\"dummy\"; "
                               "uricontent:\"this\"; "
                               "byte_extract:1,2,one,string,dec,relative; "
                               "uricontent:\"ring\"; distance:one; sid:1;)");
    if (de_ctx->sig_list == NULL) {
        goto end;
    }

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&tv, (void *)de_ctx, (void *)&det_ctx);

    SCMutexLock(&f.m);
    int r = AppLayerParserParse(alp_tctx, &f, ALPROTO_HTTP, STREAM_TOSERVER, http_buf, http_buf_len);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);

    http_state = f.alstate;
    if (http_state == NULL) {
        printf("no http state: ");
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&tv, de_ctx, det_ctx, p);

    if (!PacketAlertCheck(p, 1)) {
        printf("sig 1 didn't alert, but should have: ");
        goto end;
    }

    result = 1;

end:
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

static int UriTestSig30(void)
{
    int result = 0;
    uint8_t *http_buf = (uint8_t *)"POST /this_b5ig_string_now_in_http HTTP/1.0\r\n"
        "User-Agent: Mozilla/1.0\r\n";
    uint32_t http_buf_len = strlen((char *)http_buf);
    Flow f;
    TcpSession ssn;
    HtpState *http_state = NULL;
    Packet *p = NULL;
    ThreadVars tv;
    DetectEngineThreadCtx *det_ctx = NULL;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&tv, 0, sizeof(ThreadVars));
    memset(&f, 0, sizeof(Flow));
    memset(&ssn, 0, sizeof(TcpSession));

    p = UTHBuildPacket(http_buf, http_buf_len, IPPROTO_TCP);

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;
    f.flags |= FLOW_IPV4;

    p->flow = &f;
    p->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    p->flowflags |= FLOW_PKT_TOSERVER;
    p->flowflags |= FLOW_PKT_ESTABLISHED;
    f.alproto = ALPROTO_HTTP;

    StreamTcpInitConfig(TRUE);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }
    de_ctx->mpm_matcher = MPM_B2G;
    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,
                               "alert tcp any any -> any any (msg:\"dummy\"; "
                               "uricontent:\"this\"; "
                               "byte_extract:1,2,one,string,dec,relative; "
                               "uricontent:\"_b5ig\"; offset:one; sid:1;)");
    if (de_ctx->sig_list == NULL) {
        goto end;
    }

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&tv, (void *)de_ctx, (void *)&det_ctx);

    SCMutexLock(&f.m);
    int r = AppLayerParserParse(alp_tctx, &f, ALPROTO_HTTP, STREAM_TOSERVER, http_buf, http_buf_len);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);

    http_state = f.alstate;
    if (http_state == NULL) {
        printf("no http state: ");
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&tv, de_ctx, det_ctx, p);

    if (!PacketAlertCheck(p, 1)) {
        printf("sig 1 didn't alert, but should have: ");
        goto end;
    }

    result = 1;

end:
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

static int UriTestSig31(void)
{
    int result = 0;
    uint8_t *http_buf = (uint8_t *)"POST /this_b5ig_string_now_in_http HTTP/1.0\r\n"
        "User-Agent: Mozilla/1.0\r\n";
    uint32_t http_buf_len = strlen((char *)http_buf);
    Flow f;
    TcpSession ssn;
    HtpState *http_state = NULL;
    Packet *p = NULL;
    ThreadVars tv;
    DetectEngineThreadCtx *det_ctx = NULL;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&tv, 0, sizeof(ThreadVars));
    memset(&f, 0, sizeof(Flow));
    memset(&ssn, 0, sizeof(TcpSession));

    p = UTHBuildPacket(http_buf, http_buf_len, IPPROTO_TCP);

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;
    f.flags |= FLOW_IPV4;

    p->flow = &f;
    p->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    p->flowflags |= FLOW_PKT_TOSERVER;
    p->flowflags |= FLOW_PKT_ESTABLISHED;
    f.alproto = ALPROTO_HTTP;

    StreamTcpInitConfig(TRUE);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }
    de_ctx->mpm_matcher = MPM_B2G;
    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,
                               "alert tcp any any -> any any (msg:\"dummy\"; "
                               "uricontent:\"this\"; "
                               "byte_extract:1,2,one,string,dec,relative; "
                               "uricontent:\"his\"; depth:one; sid:1;)");
    if (de_ctx->sig_list == NULL) {
        goto end;
    }

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&tv, (void *)de_ctx, (void *)&det_ctx);

    SCMutexLock(&f.m);
    int r = AppLayerParserParse(alp_tctx, &f, ALPROTO_HTTP, STREAM_TOSERVER, http_buf, http_buf_len);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);

    http_state = f.alstate;
    if (http_state == NULL) {
        printf("no http state: ");
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&tv, de_ctx, det_ctx, p);

    if (!PacketAlertCheck(p, 1)) {
        printf("sig 1 didn't alert, but should have: ");
        goto end;
    }

    result = 1;

end:
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

static int UriTestSig32(void)
{
    int result = 0;
    uint8_t *http_buf = (uint8_t *)"POST /this_b5ig_string_now_in_http HTTP/1.0\r\n"
        "User-Agent: Mozilla/1.0\r\n";
    uint32_t http_buf_len = strlen((char *)http_buf);
    Flow f;
    TcpSession ssn;
    HtpState *http_state = NULL;
    Packet *p = NULL;
    ThreadVars tv;
    DetectEngineThreadCtx *det_ctx = NULL;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&tv, 0, sizeof(ThreadVars));
    memset(&f, 0, sizeof(Flow));
    memset(&ssn, 0, sizeof(TcpSession));

    p = UTHBuildPacket(http_buf, http_buf_len, IPPROTO_TCP);

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;
    f.flags |= FLOW_IPV4;

    p->flow = &f;
    p->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    p->flowflags |= FLOW_PKT_TOSERVER;
    p->flowflags |= FLOW_PKT_ESTABLISHED;
    f.alproto = ALPROTO_HTTP;

    StreamTcpInitConfig(TRUE);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }
    de_ctx->mpm_matcher = MPM_B2G;
    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,
                               "alert tcp any any -> any any (msg:\"dummy\"; "
                               "uricontent:\"this\"; "
                               "byte_extract:1,2,one,string,dec,relative; "
                               "uricontent:\"g_st\"; within:one; sid:1;)");
    if (de_ctx->sig_list == NULL) {
        goto end;
    }

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&tv, (void *)de_ctx, (void *)&det_ctx);

    SCMutexLock(&f.m);
    int r = AppLayerParserParse(alp_tctx, &f, ALPROTO_HTTP, STREAM_TOSERVER, http_buf, http_buf_len);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);

    http_state = f.alstate;
    if (http_state == NULL) {
        printf("no http state: ");
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&tv, de_ctx, det_ctx, p);

    if (!PacketAlertCheck(p, 1)) {
        printf("sig 1 didn't alert, but should have: ");
        goto end;
    }

    result = 1;

end:
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

static int UriTestSig33(void)
{
    int result = 0;
    uint8_t *http_buf = (uint8_t *)"POST /normalized%20uri "
        "HTTP/1.0\r\nUser-Agent: Mozilla/1.0\r\n";
    uint32_t http_buf_len = strlen((char *)http_buf);
    Flow f;
    TcpSession ssn;
    HtpState *http_state = NULL;
    Packet *p = NULL;
    ThreadVars tv;
    DetectEngineThreadCtx *det_ctx = NULL;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&tv, 0, sizeof(ThreadVars));
    memset(&f, 0, sizeof(Flow));
    memset(&ssn, 0, sizeof(TcpSession));

    p = UTHBuildPacket(http_buf, http_buf_len, IPPROTO_TCP);

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;
    f.flags |= FLOW_IPV4;

    p->flow = &f;
    p->flowflags |= FLOW_PKT_TOSERVER;
    p->flowflags |= FLOW_PKT_ESTABLISHED;
    f.alproto = ALPROTO_HTTP;
    p->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;

    StreamTcpInitConfig(TRUE);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }
    de_ctx->mpm_matcher = MPM_B2G;
    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(msg:\"test multiple relative uricontents\"; "
                               "urilen:15; sid:1;)");
    if (de_ctx->sig_list == NULL) {
        goto end;
    }

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&tv, (void *)de_ctx, (void *)&det_ctx);

    SCMutexLock(&f.m);
    int r = AppLayerParserParse(alp_tctx, &f, ALPROTO_HTTP, STREAM_TOSERVER, http_buf, http_buf_len);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);

    http_state = f.alstate;
    if (http_state == NULL) {
        printf("no http state: ");
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&tv, de_ctx, det_ctx, p);

    if (!PacketAlertCheck(p, 1)) {
        printf("sig 1 didn't alert, but it should have: ");
        goto end;
    }

    result = 1;

end:
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

static int UriTestSig34(void)
{
    int result = 0;
    uint8_t *http_buf = (uint8_t *)"POST /normalized%20uri "
        "HTTP/1.0\r\nUser-Agent: Mozilla/1.0\r\n";
    uint32_t http_buf_len = strlen((char *)http_buf);
    Flow f;
    TcpSession ssn;
    HtpState *http_state = NULL;
    Packet *p = NULL;
    ThreadVars tv;
    DetectEngineThreadCtx *det_ctx = NULL;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&tv, 0, sizeof(ThreadVars));
    memset(&f, 0, sizeof(Flow));
    memset(&ssn, 0, sizeof(TcpSession));

    p = UTHBuildPacket(http_buf, http_buf_len, IPPROTO_TCP);

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;
    f.flags |= FLOW_IPV4;

    p->flow = &f;
    p->flowflags |= FLOW_PKT_TOSERVER;
    p->flowflags |= FLOW_PKT_ESTABLISHED;
    f.alproto = ALPROTO_HTTP;
    p->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;

    StreamTcpInitConfig(TRUE);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }
    de_ctx->mpm_matcher = MPM_B2G;
    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(msg:\"test multiple relative uricontents\"; "
                               "urilen:15, norm; sid:1;)");
    if (de_ctx->sig_list == NULL) {
        goto end;
    }

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&tv, (void *)de_ctx, (void *)&det_ctx);

    SCMutexLock(&f.m);
    int r = AppLayerParserParse(alp_tctx, &f, ALPROTO_HTTP, STREAM_TOSERVER, http_buf, http_buf_len);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);

    http_state = f.alstate;
    if (http_state == NULL) {
        printf("no http state: ");
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&tv, de_ctx, det_ctx, p);

    if (!PacketAlertCheck(p, 1)) {
        printf("sig 1 didn't alert, but it should have: ");
        goto end;
    }

    result = 1;

end:
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

static int UriTestSig35(void)
{
    int result = 0;
    uint8_t *http_buf = (uint8_t *)"POST /normalized%20uri "
        "HTTP/1.0\r\nUser-Agent: Mozilla/1.0\r\n";
    uint32_t http_buf_len = strlen((char *)http_buf);
    Flow f;
    TcpSession ssn;
    HtpState *http_state = NULL;
    Packet *p = NULL;
    ThreadVars tv;
    DetectEngineThreadCtx *det_ctx = NULL;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&tv, 0, sizeof(ThreadVars));
    memset(&f, 0, sizeof(Flow));
    memset(&ssn, 0, sizeof(TcpSession));

    p = UTHBuildPacket(http_buf, http_buf_len, IPPROTO_TCP);

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;
    f.flags |= FLOW_IPV4;

    p->flow = &f;
    p->flowflags |= FLOW_PKT_TOSERVER;
    p->flowflags |= FLOW_PKT_ESTABLISHED;
    f.alproto = ALPROTO_HTTP;
    p->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;

    StreamTcpInitConfig(TRUE);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }
    de_ctx->mpm_matcher = MPM_B2G;
    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(msg:\"test multiple relative uricontents\"; "
                               "urilen:16; sid:1;)");
    if (de_ctx->sig_list == NULL) {
        goto end;
    }

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&tv, (void *)de_ctx, (void *)&det_ctx);

    SCMutexLock(&f.m);
    int r = AppLayerParserParse(alp_tctx, &f, ALPROTO_HTTP, STREAM_TOSERVER, http_buf, http_buf_len);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);

    http_state = f.alstate;
    if (http_state == NULL) {
        printf("no http state: ");
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&tv, de_ctx, det_ctx, p);

    if (PacketAlertCheck(p, 1)) {
        printf("sig 1 alerted, but it shouldn't have: ");
        goto end;
    }

    result = 1;

end:
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

static int UriTestSig36(void)
{
    int result = 0;
    uint8_t *http_buf = (uint8_t *)"POST /normalized%20uri "
        "HTTP/1.0\r\nUser-Agent: Mozilla/1.0\r\n";
    uint32_t http_buf_len = strlen((char *)http_buf);
    Flow f;
    TcpSession ssn;
    HtpState *http_state = NULL;
    Packet *p = NULL;
    ThreadVars tv;
    DetectEngineThreadCtx *det_ctx = NULL;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&tv, 0, sizeof(ThreadVars));
    memset(&f, 0, sizeof(Flow));
    memset(&ssn, 0, sizeof(TcpSession));

    p = UTHBuildPacket(http_buf, http_buf_len, IPPROTO_TCP);

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;
    f.flags |= FLOW_IPV4;

    p->flow = &f;
    p->flowflags |= FLOW_PKT_TOSERVER;
    p->flowflags |= FLOW_PKT_ESTABLISHED;
    f.alproto = ALPROTO_HTTP;
    p->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;

    StreamTcpInitConfig(TRUE);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }
    de_ctx->mpm_matcher = MPM_B2G;
    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(msg:\"test multiple relative uricontents\"; "
                               "urilen:16, norm; sid:1;)");
    if (de_ctx->sig_list == NULL) {
        goto end;
    }

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&tv, (void *)de_ctx, (void *)&det_ctx);

    SCMutexLock(&f.m);
    int r = AppLayerParserParse(alp_tctx, &f, ALPROTO_HTTP, STREAM_TOSERVER, http_buf, http_buf_len);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);

    http_state = f.alstate;
    if (http_state == NULL) {
        printf("no http state: ");
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&tv, de_ctx, det_ctx, p);

    if (PacketAlertCheck(p, 1)) {
        printf("sig 1 alerted, but it shouldn't have: ");
        goto end;
    }

    result = 1;

end:
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

static int UriTestSig37(void)
{
    int result = 0;
    uint8_t *http_buf = (uint8_t *)"POST /normalized%20uri "
        "HTTP/1.0\r\nUser-Agent: Mozilla/1.0\r\n";
    uint32_t http_buf_len = strlen((char *)http_buf);
    Flow f;
    TcpSession ssn;
    HtpState *http_state = NULL;
    Packet *p = NULL;
    ThreadVars tv;
    DetectEngineThreadCtx *det_ctx = NULL;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&tv, 0, sizeof(ThreadVars));
    memset(&f, 0, sizeof(Flow));
    memset(&ssn, 0, sizeof(TcpSession));

    p = UTHBuildPacket(http_buf, http_buf_len, IPPROTO_TCP);

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;
    f.flags |= FLOW_IPV4;

    p->flow = &f;
    p->flowflags |= FLOW_PKT_TOSERVER;
    p->flowflags |= FLOW_PKT_ESTABLISHED;
    f.alproto = ALPROTO_HTTP;
    p->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;

    StreamTcpInitConfig(TRUE);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }
    de_ctx->mpm_matcher = MPM_B2G;
    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(msg:\"test multiple relative uricontents\"; "
                               "urilen:17, raw; sid:1;)");
    if (de_ctx->sig_list == NULL) {
        goto end;
    }

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&tv, (void *)de_ctx, (void *)&det_ctx);

    SCMutexLock(&f.m);
    int r = AppLayerParserParse(alp_tctx, &f, ALPROTO_HTTP, STREAM_TOSERVER, http_buf, http_buf_len);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);

    http_state = f.alstate;
    if (http_state == NULL) {
        printf("no http state: ");
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&tv, de_ctx, det_ctx, p);

    if (!PacketAlertCheck(p, 1)) {
        printf("sig 1 didn't alert, but it should have: ");
        goto end;
    }

    result = 1;

end:
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

static int UriTestSig38(void)
{
    int result = 0;
    uint8_t *http_buf = (uint8_t *)"POST /normalized%20uri "
        "HTTP/1.0\r\nUser-Agent: Mozilla/1.0\r\n";
    uint32_t http_buf_len = strlen((char *)http_buf);
    Flow f;
    TcpSession ssn;
    HtpState *http_state = NULL;
    Packet *p = NULL;
    ThreadVars tv;
    DetectEngineThreadCtx *det_ctx = NULL;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&tv, 0, sizeof(ThreadVars));
    memset(&f, 0, sizeof(Flow));
    memset(&ssn, 0, sizeof(TcpSession));

    p = UTHBuildPacket(http_buf, http_buf_len, IPPROTO_TCP);

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;
    f.flags |= FLOW_IPV4;

    p->flow = &f;
    p->flowflags |= FLOW_PKT_TOSERVER;
    p->flowflags |= FLOW_PKT_ESTABLISHED;
    f.alproto = ALPROTO_HTTP;
    p->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;

    StreamTcpInitConfig(TRUE);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }
    de_ctx->mpm_matcher = MPM_B2G;
    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(msg:\"test multiple relative uricontents\"; "
                               "urilen:18, raw; sid:1;)");
    if (de_ctx->sig_list == NULL) {
        goto end;
    }

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&tv, (void *)de_ctx, (void *)&det_ctx);

    SCMutexLock(&f.m);
    int r = AppLayerParserParse(alp_tctx, &f, ALPROTO_HTTP, STREAM_TOSERVER, http_buf, http_buf_len);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);

    http_state = f.alstate;
    if (http_state == NULL) {
        printf("no http state: ");
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&tv, de_ctx, det_ctx, p);

    if (PacketAlertCheck(p, 1)) {
        printf("sig 1 alerted, but it shouldn't have: ");
        goto end;
    }

    result = 1;

end:
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

#endif /* UNITTESTS */

void UriRegisterTests(void)
{

#ifdef UNITTESTS
    UtRegisterTest("UriTestSig01", UriTestSig01, 1);
    UtRegisterTest("UriTestSig02", UriTestSig02, 1);
    UtRegisterTest("UriTestSig03", UriTestSig03, 1);
    UtRegisterTest("UriTestSig04", UriTestSig04, 1);
    UtRegisterTest("UriTestSig05", UriTestSig05, 1);
    UtRegisterTest("UriTestSig06", UriTestSig06, 1);
    UtRegisterTest("UriTestSig07", UriTestSig07, 1);
    UtRegisterTest("UriTestSig08", UriTestSig08, 1);
    UtRegisterTest("UriTestSig09", UriTestSig09, 1);
    UtRegisterTest("UriTestSig10", UriTestSig10, 1);
    UtRegisterTest("UriTestSig11", UriTestSig11, 1);
    UtRegisterTest("UriTestSig12", UriTestSig12, 1);
    UtRegisterTest("UriTestSig13", UriTestSig13, 1);
    UtRegisterTest("UriTestSig14", UriTestSig14, 1);
    UtRegisterTest("UriTestSig15", UriTestSig15, 1);
    UtRegisterTest("UriTestSig16", UriTestSig16, 1);
    UtRegisterTest("UriTestSig17", UriTestSig17, 1);
    UtRegisterTest("UriTestSig18", UriTestSig18, 1);
    UtRegisterTest("UriTestSig19", UriTestSig19, 1);
    UtRegisterTest("UriTestSig20", UriTestSig20, 1);
    UtRegisterTest("UriTestSig21", UriTestSig21, 1);
    UtRegisterTest("UriTestSig22", UriTestSig22, 1);
    UtRegisterTest("UriTestSig23", UriTestSig23, 1);
    UtRegisterTest("UriTestSig24", UriTestSig24, 1);
    UtRegisterTest("UriTestSig25", UriTestSig25, 1);
    UtRegisterTest("UriTestSig26", UriTestSig26, 1);
    UtRegisterTest("UriTestSig27", UriTestSig27, 1);

    UtRegisterTest("UriTestSig28", UriTestSig28, 1);
    UtRegisterTest("UriTestSig29", UriTestSig29, 1);
    UtRegisterTest("UriTestSig30", UriTestSig30, 1);
    UtRegisterTest("UriTestSig31", UriTestSig31, 1);
    UtRegisterTest("UriTestSig32", UriTestSig32, 1);
    UtRegisterTest("UriTestSig33", UriTestSig33, 1);
    UtRegisterTest("UriTestSig34", UriTestSig34, 1);
    UtRegisterTest("UriTestSig35", UriTestSig35, 1);
    UtRegisterTest("UriTestSig36", UriTestSig36, 1);
    UtRegisterTest("UriTestSig37", UriTestSig37, 1);
    UtRegisterTest("UriTestSig38", UriTestSig38, 1);
#endif /* UNITTESTS */

    return;
}
