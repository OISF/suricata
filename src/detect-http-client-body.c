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
 * \ingroup httplayer
 *
 * @{
 */


/**
 * \file
 *
 * \author Anoop Saldanha <anoopsaldanha@gmail.com>
 *
 * Implements support for the http_client_body keyword
 */

#include "suricata-common.h"
#include "threads.h"
#include "decode.h"

#include "detect.h"
#include "detect-parse.h"
#include "detect-engine.h"
#include "detect-engine-mpm.h"
#include "detect-engine-state.h"
#include "detect-content.h"
#include "detect-pcre.h"

#include "flow.h"
#include "flow-var.h"
#include "flow-util.h"

#include "util-debug.h"
#include "util-unittest.h"
#include "util-unittest-helper.h"
#include "util-spm.h"

#include "app-layer.h"
#include "app-layer-parser.h"
#include "app-layer-htp.h"
#include "detect-http-client-body.h"
#include "detect-engine-hcbd.h"
#include "stream-tcp.h"

static int DetectHttpClientBodySetup(DetectEngineCtx *, Signature *, const char *);
static void DetectHttpClientBodyRegisterTests(void);
static void DetectHttpClientBodyFree(void *);
static void DetectHttpClientBodySetupCallback(Signature *s);
static int g_http_client_body_buffer_id = 0;

/**
 * \brief Registers the keyword handlers for the "http_client_body" keyword.
 */
void DetectHttpClientBodyRegister(void)
{
    sigmatch_table[DETECT_AL_HTTP_CLIENT_BODY].name = "http_client_body";
    sigmatch_table[DETECT_AL_HTTP_CLIENT_BODY].desc = "content modifier to match only on HTTP request-body";
    sigmatch_table[DETECT_AL_HTTP_CLIENT_BODY].url = DOC_URL DOC_VERSION "/rules/http-keywords.html#http_client-body";
    sigmatch_table[DETECT_AL_HTTP_CLIENT_BODY].Match = NULL;
    sigmatch_table[DETECT_AL_HTTP_CLIENT_BODY].Setup = DetectHttpClientBodySetup;
    sigmatch_table[DETECT_AL_HTTP_CLIENT_BODY].Free  = DetectHttpClientBodyFree;
    sigmatch_table[DETECT_AL_HTTP_CLIENT_BODY].RegisterTests = DetectHttpClientBodyRegisterTests;

    sigmatch_table[DETECT_AL_HTTP_CLIENT_BODY].flags |= SIGMATCH_NOOPT ;

    DetectAppLayerMpmRegister("http_client_body", SIG_FLAG_TOSERVER, 2,
            PrefilterTxHttpRequestBodyRegister);

    DetectAppLayerInspectEngineRegister("http_client_body",
            ALPROTO_HTTP, SIG_FLAG_TOSERVER, HTP_REQUEST_BODY,
            DetectEngineInspectHttpClientBody);

    DetectBufferTypeSetDescriptionByName("http_client_body",
            "http request body");

    DetectBufferTypeRegisterSetupCallback("http_client_body",
            DetectHttpClientBodySetupCallback);

    g_http_client_body_buffer_id = DetectBufferTypeGetByName("http_client_body");
}

static void DetectHttpClientBodySetupCallback(Signature *s)
{
    SCLogDebug("callback invoked by %u", s->id);
    AppLayerHtpEnableRequestBodyCallback();
    s->mask |= SIG_MASK_REQUIRE_HTTP_STATE;
}

/**
 * \brief The setup function for the http_client_body keyword for a signature.
 *
 * \param de_ctx Pointer to the detection engine context.
 * \param s      Pointer to signature for the current Signature being parsed
 *               from the rules.
 * \param m      Pointer to the head of the SigMatchs for the current rule
 *               being parsed.
 * \param arg    Pointer to the string holding the keyword value.
 *
 * \retval  0 On success
 * \retval -1 On failure
 */
int DetectHttpClientBodySetup(DetectEngineCtx *de_ctx, Signature *s, const char *arg)
{
    return DetectEngineContentModifierBufferSetup(de_ctx, s, arg,
                                                  DETECT_AL_HTTP_CLIENT_BODY,
                                                  g_http_client_body_buffer_id,
                                                  ALPROTO_HTTP);
}

/**
 * \brief The function to free the http_client_body data.
 *
 * \param ptr Pointer to the http_client_body.
 */
void DetectHttpClientBodyFree(void *ptr)
{
    SCEnter();
    DetectContentData *hcbd = (DetectContentData *)ptr;
    if (hcbd == NULL)
        SCReturn;

    if (hcbd->content != NULL)
        SCFree(hcbd->content);

    SpmDestroyCtx(hcbd->spm_ctx);
    SCFree(hcbd);

    SCReturn;
}

/************************************Unittests*********************************/

#ifdef UNITTESTS

#include "detect-isdataat.h"
#include "stream-tcp-reassemble.h"

/**
 * \test Test that a signature containting a http_client_body is correctly parsed
 *       and the keyword is registered.
 */
static int DetectHttpClientBodyTest01(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;
    SigMatch *sm = NULL;

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(msg:\"Testing http_client_body\"; "
                               "content:\"one\"; http_client_body; sid:1;)");
    if (de_ctx->sig_list != NULL) {
        result = 1;
    } else {
        goto end;
    }

    sm = de_ctx->sig_list->sm_lists[DETECT_SM_LIST_MATCH];
    if (sm != NULL) {
        result &= (sm->type == DETECT_CONTENT);
        result &= (sm->next == NULL);
    }

 end:
    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);

    return result;
}

/**
 * \test Test that a signature containing an valid http_client_body entry is
 *       parsed.
 */
static int DetectHttpClientBodyTest02(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(msg:\"Testing http_client_body\"; "
                               "content:\"one\"; http_client_body:; sid:1;)");
    if (de_ctx->sig_list != NULL)
        result = 1;

 end:
    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);

    return result;
}

/**
 * \test Test that an invalid signature containing no content but a http_client_body
 *       is invalidated.
 */
static int DetectHttpClientBodyTest03(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(msg:\"Testing http_client_body\"; "
                               "http_client_body; sid:1;)");
    if (de_ctx->sig_list == NULL)
        result = 1;

 end:
    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);

    return result;
}

/**
 * \test Test that an invalid signature containing a rawbytes along with a
 *       http_client_body is invalidated.
 */
static int DetectHttpClientBodyTest04(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(msg:\"Testing http_client_body\"; "
                               "content:\"one\"; rawbytes; http_client_body; sid:1;)");
    if (de_ctx->sig_list == NULL)
        result = 1;

 end:
    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);

    return result;
}

/**
 * \test Test that an invalid signature containing a rawbytes along with a
 *       http_client_body is invalidated.
 */
static int DetectHttpClientBodyTest05(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(msg:\"Testing http_client_body\"; "
                               "content:\"one\"; http_client_body; nocase; sid:1;)");
    if (de_ctx->sig_list != NULL)
        result = 1;

 end:
    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);

    return result;
}

/**
 *\test Test that the http_client_body content matches against a http request
 *      which holds the content.
 */
static int DetectHttpClientBodyTest06(void)
{
    TcpSession ssn;
    Packet *p = NULL;
    ThreadVars th_v;
    DetectEngineCtx *de_ctx = NULL;
    DetectEngineThreadCtx *det_ctx = NULL;
    HtpState *http_state = NULL;
    Flow f;
    uint8_t http_buf[] =
        "GET /index.html HTTP/1.0\r\n"
        "Host: www.openinfosecfoundation.org\r\n"
        "User-Agent: Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.1.7) Gecko/20091221 Firefox/3.5.7\r\n"
        "Content-Type: text/html\r\n"
        "Content-Length: 26\r\n"
        "\r\n"
        "This is dummy message body";
    uint32_t http_len = sizeof(http_buf) - 1;
    int result = 0;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&th_v, 0, sizeof(th_v));
    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    p = UTHBuildPacket(NULL, 0, IPPROTO_TCP);

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;
    f.flags |= FLOW_IPV4;

    p->flow = &f;
    p->flowflags |= FLOW_PKT_TOSERVER;
    p->flowflags |= FLOW_PKT_ESTABLISHED;
    p->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    f.alproto = ALPROTO_HTTP;

    StreamTcpInitConfig(TRUE);

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert http any any -> any any "
                               "(msg:\"http client body test\"; "
                               "content:\"message\"; http_client_body; "
                               "sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    FLOWLOCK_WRLOCK(&f);
    int r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_HTTP,
                                STREAM_TOSERVER, http_buf, http_len);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        FLOWLOCK_UNLOCK(&f);
        goto end;
    }
    FLOWLOCK_UNLOCK(&f);

    http_state = f.alstate;
    if (http_state == NULL) {
        printf("no http state: \n");
        result = 0;
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);

    if (!(PacketAlertCheck(p, 1))) {
        printf("sid 1 didn't match but should have\n");
        goto end;
    }

    result = 1;
end:
    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
    if (de_ctx != NULL)
        SigGroupCleanup(de_ctx);
    if (de_ctx != NULL)
        SigCleanSignatures(de_ctx);
    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);

    StreamTcpFreeConfig(TRUE);
    FLOW_DESTROY(&f);
    UTHFreePackets(&p, 1);
    return result;
}

/**
 *\test Test that the http_client_body content matches against a http request
 *      which holds the content.
 */
static int DetectHttpClientBodyTest07(void)
{
    TcpSession ssn;
    Packet *p1 = NULL;
    Packet *p2 = NULL;
    ThreadVars th_v;
    DetectEngineCtx *de_ctx = NULL;
    DetectEngineThreadCtx *det_ctx = NULL;
    HtpState *http_state = NULL;
    Flow f;
    uint8_t http1_buf[] =
        "GET /index.html HTTP/1.0\r\n"
        "Host: www.openinfosecfoundation.org\r\n"
        "User-Agent: Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.1.7) Gecko/20091221 Firefox/3.5.7\r\n"
        "Content-Type: text/html\r\n"
        "Content-Length: 54\r\n"
        "\r\n"
        "This is dummy message body1";
    uint8_t http2_buf[] =
        "This is dummy message body2";
    uint32_t http1_len = sizeof(http1_buf) - 1;
    uint32_t http2_len = sizeof(http2_buf) - 1;
    int result = 0;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&th_v, 0, sizeof(th_v));
    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    p1 = UTHBuildPacket(NULL, 0, IPPROTO_TCP);
    p2 = UTHBuildPacket(NULL, 0, IPPROTO_TCP);

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;
    f.flags |= FLOW_IPV4;

    p1->flow = &f;
    p1->flowflags |= FLOW_PKT_TOSERVER;
    p1->flowflags |= FLOW_PKT_ESTABLISHED;
    p1->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    p2->flow = &f;
    p2->flowflags |= FLOW_PKT_TOSERVER;
    p2->flowflags |= FLOW_PKT_ESTABLISHED;
    p2->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    f.alproto = ALPROTO_HTTP;

    StreamTcpInitConfig(TRUE);

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert http any any -> any any "
                               "(msg:\"http client body test\"; "
                               "content:\"message\"; http_client_body; "
                               "sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    FLOWLOCK_WRLOCK(&f);
    int r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_HTTP,
                                STREAM_TOSERVER, http1_buf, http1_len);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        FLOWLOCK_UNLOCK(&f);
        goto end;
    }
    FLOWLOCK_UNLOCK(&f);

    http_state = f.alstate;
    if (http_state == NULL) {
        printf("no http state: ");
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p1);

    if (PacketAlertCheck(p1, 1)) {
        printf("sid 1 matched on p1 but shouldn't have: ");
        goto end;
    }

    FLOWLOCK_WRLOCK(&f);
    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_HTTP,
                            STREAM_TOSERVER, http2_buf, http2_len);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        FLOWLOCK_UNLOCK(&f);
        goto end;
    }
    FLOWLOCK_UNLOCK(&f);

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p2);
    if (!(PacketAlertCheck(p2, 1))) {
        printf("sid 1 didn't match on p2 but should have: ");
        goto end;
    }

    result = 1;
end:
    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
    if (de_ctx != NULL)
        SigGroupCleanup(de_ctx);
    if (de_ctx != NULL)
        SigCleanSignatures(de_ctx);
    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);

    StreamTcpFreeConfig(TRUE);
    FLOW_DESTROY(&f);
    UTHFreePackets(&p1, 1);
    UTHFreePackets(&p2, 1);
    return result;
}

/**
 *\test Test that the http_client_body content matches against a http request
 *      which holds the content.
 */
static int DetectHttpClientBodyTest08(void)
{
    TcpSession ssn;
    Packet *p1 = NULL;
    Packet *p2 = NULL;
    ThreadVars th_v;
    DetectEngineCtx *de_ctx = NULL;
    DetectEngineThreadCtx *det_ctx = NULL;
    HtpState *http_state = NULL;
    Flow f;
    uint8_t http1_buf[] =
        "GET /index.html HTTP/1.0\r\n"
        "Host: www.openinfosecfoundation.org\r\n"
        "User-Agent: Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.1.7) Gecko/20091221 Firefox/3.5.7\r\n"
        "Content-Type: text/html\r\n"
        "Content-Length: 46\r\n"
        "\r\n"
        "This is dummy body1";
    uint8_t http2_buf[] =
        "This is dummy message body2";
    uint32_t http1_len = sizeof(http1_buf) - 1;
    uint32_t http2_len = sizeof(http2_buf) - 1;
    int result = 0;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&th_v, 0, sizeof(th_v));
    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    p1 = UTHBuildPacket(NULL, 0, IPPROTO_TCP);
    p2 = UTHBuildPacket(NULL, 0, IPPROTO_TCP);

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;
    f.flags |= FLOW_IPV4;

    p1->flow = &f;
    p1->flowflags |= FLOW_PKT_TOSERVER;
    p1->flowflags |= FLOW_PKT_ESTABLISHED;
    p1->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    p2->flow = &f;
    p2->flowflags |= FLOW_PKT_TOSERVER;
    p2->flowflags |= FLOW_PKT_ESTABLISHED;
    p2->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    f.alproto = ALPROTO_HTTP;

    StreamTcpInitConfig(TRUE);

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert http any any -> any any "
                               "(msg:\"http client body test\"; "
                               "content:\"message\"; http_client_body; "
                               "sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    FLOWLOCK_WRLOCK(&f);
    int r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_HTTP,
                                STREAM_TOSERVER, http1_buf, http1_len);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        FLOWLOCK_UNLOCK(&f);
        goto end;
    }
    FLOWLOCK_UNLOCK(&f);

    http_state = f.alstate;
    if (http_state == NULL) {
        printf("no http state: ");
        result = 0;
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p1);

    if ((PacketAlertCheck(p1, 1))) {
        printf("sid 1 didn't match but should have");
        goto end;
    }

    FLOWLOCK_WRLOCK(&f);
    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_HTTP,
                            STREAM_TOSERVER, http2_buf, http2_len);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        FLOWLOCK_UNLOCK(&f);
        goto end;
    }
    FLOWLOCK_UNLOCK(&f);

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p2);

    if (!(PacketAlertCheck(p2, 1))) {
        printf("sid 1 didn't match but should have");
        goto end;
    }

    result = 1;
end:
    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
    if (de_ctx != NULL)
        SigGroupCleanup(de_ctx);
    if (de_ctx != NULL)
        SigCleanSignatures(de_ctx);
    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);

    StreamTcpFreeConfig(TRUE);
    FLOW_DESTROY(&f);
    UTHFreePackets(&p1, 1);
    UTHFreePackets(&p2, 1);
    return result;
}

/**
 *\test Test that the http_client_body content matches against a http request
 *      which holds the content, against a cross boundary present pattern.
 */
static int DetectHttpClientBodyTest09(void)
{
    TcpSession ssn;
    Packet *p1 = NULL;
    Packet *p2 = NULL;
    ThreadVars th_v;
    DetectEngineCtx *de_ctx = NULL;
    DetectEngineThreadCtx *det_ctx = NULL;
    HtpState *http_state = NULL;
    Flow f;
    uint8_t http1_buf[] =
        "GET /index.html HTTP/1.0\r\n"
        "Host: www.openinfosecfoundation.org\r\n"
        "User-Agent: Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.1.7) Gecko/20091221 Firefox/3.5.7\r\n"
        "Content-Type: text/html\r\n"
        "Content-Length: 46\r\n"
        "\r\n"
        "This is dummy body1";
    uint8_t http2_buf[] =
        "This is dummy message body2";
    uint32_t http1_len = sizeof(http1_buf) - 1;
    uint32_t http2_len = sizeof(http2_buf) - 1;
    int result = 0;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&th_v, 0, sizeof(th_v));
    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    p1 = UTHBuildPacket(NULL, 0, IPPROTO_TCP);
    p2 = UTHBuildPacket(NULL, 0, IPPROTO_TCP);

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;
    f.flags |= FLOW_IPV4;

    p1->flow = &f;
    p1->flowflags |= FLOW_PKT_TOSERVER;
    p1->flowflags |= FLOW_PKT_ESTABLISHED;
    p1->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    p2->flow = &f;
    p2->flowflags |= FLOW_PKT_TOSERVER;
    p2->flowflags |= FLOW_PKT_ESTABLISHED;
    p2->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    f.alproto = ALPROTO_HTTP;

    StreamTcpInitConfig(TRUE);

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert http any any -> any any "
                               "(msg:\"http client body test\"; "
                               "content:\"body1This\"; http_client_body; "
                               "sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    FLOWLOCK_WRLOCK(&f);
    int r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_HTTP,
                                STREAM_TOSERVER, http1_buf, http1_len);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        FLOWLOCK_UNLOCK(&f);
        goto end;
    }
    FLOWLOCK_UNLOCK(&f);

    http_state = f.alstate;
    if (http_state == NULL) {
        printf("no http state: ");
        result = 0;
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p1);

    if ((PacketAlertCheck(p1, 1))) {
        printf("sid 1 didn't match but should have");
        goto end;
    }

    FLOWLOCK_WRLOCK(&f);
    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_HTTP,
                            STREAM_TOSERVER, http2_buf, http2_len);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        FLOWLOCK_UNLOCK(&f);
        goto end;
    }
    FLOWLOCK_UNLOCK(&f);

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p2);

    if (!(PacketAlertCheck(p2, 1))) {
        printf("sid 1 didn't match but should have");
        goto end;
    }

    result = 1;
end:
    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
    if (de_ctx != NULL)
        SigGroupCleanup(de_ctx);
    if (de_ctx != NULL)
        SigCleanSignatures(de_ctx);
    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);

    StreamTcpFreeConfig(TRUE);
    FLOW_DESTROY(&f);
    UTHFreePackets(&p1, 1);
    UTHFreePackets(&p2, 1);
    return result;
}

/**
 *\test Test that the http_client_body content matches against a http request
 *      against a case insensitive pattern.
 */
static int DetectHttpClientBodyTest10(void)
{
    TcpSession ssn;
    Packet *p1 = NULL;
    Packet *p2 = NULL;
    ThreadVars th_v;
    DetectEngineCtx *de_ctx = NULL;
    DetectEngineThreadCtx *det_ctx = NULL;
    HtpState *http_state = NULL;
    Flow f;
    uint8_t http1_buf[] =
        "GET /index.html HTTP/1.0\r\n"
        "Host: www.openinfosecfoundation.org\r\n"
        "User-Agent: Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.1.7) Gecko/20091221 Firefox/3.5.7\r\n"
        "Content-Type: text/html\r\n"
        "Content-Length: 46\r\n"
        "\r\n"
        "This is dummy bodY1";
    uint8_t http2_buf[] =
        "This is dummy message body2";
    uint32_t http1_len = sizeof(http1_buf) - 1;
    uint32_t http2_len = sizeof(http2_buf) - 1;
    int result = 0;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&th_v, 0, sizeof(th_v));
    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    p1 = UTHBuildPacket(NULL, 0, IPPROTO_TCP);
    p2 = UTHBuildPacket(NULL, 0, IPPROTO_TCP);

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;
    f.flags |= FLOW_IPV4;

    p1->flow = &f;
    p1->flowflags |= FLOW_PKT_TOSERVER;
    p1->flowflags |= FLOW_PKT_ESTABLISHED;
    p1->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    p2->flow = &f;
    p2->flowflags |= FLOW_PKT_TOSERVER;
    p2->flowflags |= FLOW_PKT_ESTABLISHED;
    p2->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    f.alproto = ALPROTO_HTTP;

    StreamTcpInitConfig(TRUE);

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert http any any -> any any "
                               "(msg:\"http client body test\"; "
                               "content:\"body1This\"; http_client_body; nocase;"
                               "sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    FLOWLOCK_WRLOCK(&f);
    int r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_HTTP,
                                STREAM_TOSERVER, http1_buf, http1_len);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        FLOWLOCK_UNLOCK(&f);
        goto end;
    }
    FLOWLOCK_UNLOCK(&f);

    http_state = f.alstate;
    if (http_state == NULL) {
        printf("no http state: \n");
        result = 0;
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p1);

    if ((PacketAlertCheck(p1, 1))) {
        printf("sid 1 didn't match but should have\n");
        goto end;
    }

    FLOWLOCK_WRLOCK(&f);
    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_HTTP,
                            STREAM_TOSERVER, http2_buf, http2_len);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: \n", r);
        result = 0;
        FLOWLOCK_UNLOCK(&f);
        goto end;
    }
    FLOWLOCK_UNLOCK(&f);

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p2);

    if (!(PacketAlertCheck(p2, 1))) {
        printf("sid 1 didn't match but should have");
        goto end;
    }

    result = 1;
end:
    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
    if (de_ctx != NULL)
        SigGroupCleanup(de_ctx);
    if (de_ctx != NULL)
        SigCleanSignatures(de_ctx);
    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);

    StreamTcpFreeConfig(TRUE);
    FLOW_DESTROY(&f);
    UTHFreePackets(&p1, 1);
    UTHFreePackets(&p2, 1);
    return result;
}

/**
 *\test Test that the negated http_client_body content matches against a
 *      http request which doesn't hold the content.
 */
static int DetectHttpClientBodyTest11(void)
{
    TcpSession ssn;
    Packet *p = NULL;
    ThreadVars th_v;
    DetectEngineCtx *de_ctx = NULL;
    DetectEngineThreadCtx *det_ctx = NULL;
    HtpState *http_state = NULL;
    Flow f;
    uint8_t http_buf[] =
        "GET /index.html HTTP/1.0\r\n"
        "Host: www.openinfosecfoundation.org\r\n"
        "User-Agent: Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.1.7) Gecko/20091221 Firefox/3.5.7\r\n"
        "Content-Type: text/html\r\n"
        "Content-Length: 26\r\n"
        "\r\n"
        "This is dummy message body";
    uint32_t http_len = sizeof(http_buf) - 1;
    int result = 0;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&th_v, 0, sizeof(th_v));
    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    p = UTHBuildPacket(NULL, 0, IPPROTO_TCP);

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;
    f.flags |= FLOW_IPV4;

    p->flow = &f;
    p->flowflags |= FLOW_PKT_TOSERVER;
    p->flowflags |= FLOW_PKT_ESTABLISHED;
    p->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    f.alproto = ALPROTO_HTTP;

    StreamTcpInitConfig(TRUE);

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert http any any -> any any "
                               "(msg:\"http client body test\"; "
                               "content:!\"message1\"; http_client_body; "
                               "sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    FLOWLOCK_WRLOCK(&f);
    int r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_HTTP,
                                STREAM_TOSERVER, http_buf, http_len);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        FLOWLOCK_UNLOCK(&f);
        goto end;
    }
    FLOWLOCK_UNLOCK(&f);

    http_state = f.alstate;
    if (http_state == NULL) {
        printf("no http state: ");
        result = 0;
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);

    if (!(PacketAlertCheck(p, 1))) {
        printf("sid 1 didn't match but should have");
        goto end;
    }

    result = 1;
end:
    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
    if (de_ctx != NULL)
        SigGroupCleanup(de_ctx);
    if (de_ctx != NULL)
        SigCleanSignatures(de_ctx);
    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);

    StreamTcpFreeConfig(TRUE);
    FLOW_DESTROY(&f);
    UTHFreePackets(&p, 1);
    return result;
}

/**
 *\test Negative test that the negated http_client_body content matches against a
 *      http request which holds hold the content.
 */
static int DetectHttpClientBodyTest12(void)
{
    TcpSession ssn;
    Packet *p = NULL;
    ThreadVars th_v;
    DetectEngineCtx *de_ctx = NULL;
    DetectEngineThreadCtx *det_ctx = NULL;
    HtpState *http_state = NULL;
    Flow f;
    uint8_t http_buf[] =
        "GET /index.html HTTP/1.0\r\n"
        "Host: www.openinfosecfoundation.org\r\n"
        "User-Agent: Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.1.7) Gecko/20091221 Firefox/3.5.7\r\n"
        "Content-Type: text/html\r\n"
        "Content-Length: 26\r\n"
        "\r\n"
        "This is dummy message body";
    uint32_t http_len = sizeof(http_buf) - 1;
    int result = 0;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&th_v, 0, sizeof(th_v));
    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    p = UTHBuildPacket(NULL, 0, IPPROTO_TCP);

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;
    f.flags |= FLOW_IPV4;

    p->flow = &f;
    p->flowflags |= FLOW_PKT_TOSERVER;
    p->flowflags |= FLOW_PKT_ESTABLISHED;
    p->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    f.alproto = ALPROTO_HTTP;

    StreamTcpInitConfig(TRUE);

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert http any any -> any any "
                               "(msg:\"http client body test\"; "
                               "content:!\"message\"; http_client_body; "
                               "sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    FLOWLOCK_WRLOCK(&f);
    int r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_HTTP,
                                STREAM_TOSERVER, http_buf, http_len);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        FLOWLOCK_UNLOCK(&f);
        goto end;
    }
    FLOWLOCK_UNLOCK(&f);

    http_state = f.alstate;
    if (http_state == NULL) {
        printf("no http state: ");
        result = 0;
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);

    if ((PacketAlertCheck(p, 1))) {
        printf("sid 1 didn't match but should have");
        goto end;
    }

    result = 1;
end:
    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
    if (de_ctx != NULL)
        SigGroupCleanup(de_ctx);
    if (de_ctx != NULL)
        SigCleanSignatures(de_ctx);
    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);

    StreamTcpFreeConfig(TRUE);
    FLOW_DESTROY(&f);
    UTHFreePackets(&p, 1);
    return result;
}

/**
 *\test Test that the http_client_body content matches against a http request
 *      which holds the content.
 */
static int DetectHttpClientBodyTest13(void)
{
    TcpSession ssn;
    Packet *p = NULL;
    ThreadVars th_v;
    DetectEngineCtx *de_ctx = NULL;
    DetectEngineThreadCtx *det_ctx = NULL;
    HtpState *http_state = NULL;
    Flow f;
    uint8_t http_buf[] =
        "GET /index.html HTTP/1.0\r\n"
        "Host: www.openinfosecfoundation.org\r\n"
        "User-Agent: Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.1.7) Gecko/20091221 Firefox/3.5.7\r\n"
        "Content-Type: text/html\r\n"
        "Content-Length: 55\r\n"
        "\r\n"
        "longbufferabcdefghijklmnopqrstuvwxyz0123456789bufferend";
    uint32_t http_len = sizeof(http_buf) - 1;
    int result = 0;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&th_v, 0, sizeof(th_v));
    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    p = UTHBuildPacket(NULL, 0, IPPROTO_TCP);

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;
    f.flags |= FLOW_IPV4;

    p->flow = &f;
    p->flowflags |= FLOW_PKT_TOSERVER;
    p->flowflags |= FLOW_PKT_ESTABLISHED;
    p->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    f.alproto = ALPROTO_HTTP;

    StreamTcpInitConfig(TRUE);

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert http any any -> any any "
                               "(msg:\"http client body test\"; "
                               "content:\"abcdefghijklmnopqrstuvwxyz0123456789\"; http_client_body; "
                               "sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    FLOWLOCK_WRLOCK(&f);
    int r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_HTTP,
                                STREAM_TOSERVER, http_buf, http_len);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        FLOWLOCK_UNLOCK(&f);
        goto end;
    }
    FLOWLOCK_UNLOCK(&f);

    http_state = f.alstate;
    if (http_state == NULL) {
        printf("no http state: ");
        result = 0;
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);

    if (!(PacketAlertCheck(p, 1))) {
        printf("sid 1 didn't match but should have");
        goto end;
    }

    result = 1;
end:
    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
    if (de_ctx != NULL)
        SigGroupCleanup(de_ctx);
    if (de_ctx != NULL)
        SigCleanSignatures(de_ctx);
    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);

    StreamTcpFreeConfig(TRUE);
    FLOW_DESTROY(&f);
    UTHFreePackets(&p, 1);
    return result;
}

/** \test multiple http transactions and body chunks of request handling */
static int DetectHttpClientBodyTest14(void)
{
    int result = 0;
    Signature *s = NULL;
    DetectEngineThreadCtx *det_ctx = NULL;
    ThreadVars th_v;
    Flow f;
    TcpSession ssn;
    Packet *p = NULL;
    uint8_t httpbuf1[] = "POST / HTTP/1.1\r\n";
    uint8_t httpbuf2[] = "User-Agent: Mozilla/1.0\r\nContent-Length: 10\r\n";
    uint8_t httpbuf3[] = "Cookie: dummy\r\n\r\n";
    uint8_t httpbuf4[] = "Body one!!";
    uint32_t httplen1 = sizeof(httpbuf1) - 1; /* minus the \0 */
    uint32_t httplen2 = sizeof(httpbuf2) - 1; /* minus the \0 */
    uint32_t httplen3 = sizeof(httpbuf3) - 1; /* minus the \0 */
    uint32_t httplen4 = sizeof(httpbuf4) - 1; /* minus the \0 */
    uint8_t httpbuf5[] = "GET /?var=val HTTP/1.1\r\n";
    uint8_t httpbuf6[] = "User-Agent: Firefox/1.0\r\n";
    uint8_t httpbuf7[] = "Cookie: dummy2\r\nContent-Length: 10\r\n\r\nBody two!!";
    uint32_t httplen5 = sizeof(httpbuf5) - 1; /* minus the \0 */
    uint32_t httplen6 = sizeof(httpbuf6) - 1; /* minus the \0 */
    uint32_t httplen7 = sizeof(httpbuf7) - 1; /* minus the \0 */
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&th_v, 0, sizeof(th_v));
    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    p = UTHBuildPacket(NULL, 0, IPPROTO_TCP);

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;
    f.flags |= FLOW_IPV4;

    p->flow = &f;
    p->flowflags |= FLOW_PKT_TOSERVER;
    p->flowflags |= FLOW_PKT_ESTABLISHED;
    p->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    f.alproto = ALPROTO_HTTP;

    StreamTcpInitConfig(TRUE);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }

    de_ctx->flags |= DE_QUIET;

    s = DetectEngineAppendSig(de_ctx, "alert tcp any any -> any any (content:\"POST\"; http_method; content:\"Mozilla\"; http_header; content:\"dummy\"; http_cookie; content:\"one\"; http_client_body; sid:1; rev:1;)");
    if (s == NULL) {
        printf("sig parse failed: ");
        goto end;
    }
    s = DetectEngineAppendSig(de_ctx, "alert tcp any any -> any any (content:\"GET\"; http_method; content:\"Firefox\"; http_header; content:\"dummy2\"; http_cookie; content:\"two\"; http_client_body; sid:2; rev:1;)");
    if (s == NULL) {
        printf("sig2 parse failed: ");
        goto end;
    }

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    FLOWLOCK_WRLOCK(&f);
    int r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_HTTP,
                                STREAM_TOSERVER, httpbuf1, httplen1);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        FLOWLOCK_UNLOCK(&f);
        goto end;
    }
    FLOWLOCK_UNLOCK(&f);

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    if (PacketAlertCheck(p, 1)) {
        printf("sig 1 alerted: ");
        goto end;
    }
    p->alerts.cnt = 0;

    FLOWLOCK_WRLOCK(&f);
    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_HTTP,
                            STREAM_TOSERVER, httpbuf2, httplen2);
    if (r != 0) {
        printf("toserver chunk 2 returned %" PRId32 ", expected 0: ", r);
        FLOWLOCK_UNLOCK(&f);
        goto end;
    }
    FLOWLOCK_UNLOCK(&f);

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    if (PacketAlertCheck(p, 1)) {
        printf("sig 1 alerted (2): ");
        FLOWLOCK_UNLOCK(&f);
        goto end;
    }
    p->alerts.cnt = 0;

    FLOWLOCK_WRLOCK(&f);
    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_HTTP,
                            STREAM_TOSERVER, httpbuf3, httplen3);
    if (r != 0) {
        printf("toserver chunk 3 returned %" PRId32 ", expected 0: ", r);
    FLOWLOCK_UNLOCK(&f);
        goto end;
    }
    FLOWLOCK_UNLOCK(&f);

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    if (PacketAlertCheck(p, 1)) {
        printf("signature matched, but shouldn't have: ");
        goto end;
    }
    p->alerts.cnt = 0;

    FLOWLOCK_WRLOCK(&f);
    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_HTTP,
                            STREAM_TOSERVER, httpbuf4, httplen4);
    if (r != 0) {
        printf("toserver chunk 4 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        FLOWLOCK_UNLOCK(&f);
        goto end;
    }
    FLOWLOCK_UNLOCK(&f);

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    if (!(PacketAlertCheck(p, 1))) {
        printf("sig 1 didn't alert: ");
        goto end;
    }
    p->alerts.cnt = 0;

    FLOWLOCK_WRLOCK(&f);
    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_HTTP,
                            STREAM_TOSERVER, httpbuf5, httplen5);
    if (r != 0) {
        printf("toserver chunk 5 returned %" PRId32 ", expected 0: ", r);
        FLOWLOCK_UNLOCK(&f);
        goto end;
    }
    FLOWLOCK_UNLOCK(&f);

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    if (PacketAlertCheck(p, 1)) {
        printf("sig 1 alerted (5): ");
        goto end;
    }
    p->alerts.cnt = 0;

    FLOWLOCK_WRLOCK(&f);
    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_HTTP,
                            STREAM_TOSERVER, httpbuf6, httplen6);
    if (r != 0) {
        printf("toserver chunk 6 returned %" PRId32 ", expected 0: ", r);
        FLOWLOCK_UNLOCK(&f);
        goto end;
    }
    FLOWLOCK_UNLOCK(&f);

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    if ((PacketAlertCheck(p, 1)) || (PacketAlertCheck(p, 2))) {
        printf("sig 1 alerted (request 2, chunk 6): ");
        goto end;
    }
    p->alerts.cnt = 0;

    SCLogDebug("sending data chunk 7");

    FLOWLOCK_WRLOCK(&f);
    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_HTTP,
                            STREAM_TOSERVER, httpbuf7, httplen7);
    if (r != 0) {
        printf("toserver chunk 7 returned %" PRId32 ", expected 0: ", r);
        FLOWLOCK_UNLOCK(&f);
        goto end;
    }
    FLOWLOCK_UNLOCK(&f);

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    if (!(PacketAlertCheck(p, 2))) {
        printf("signature 2 didn't match, but should have: ");
        goto end;
    }
    p->alerts.cnt = 0;

    HtpState *htp_state = f.alstate;
    if (htp_state == NULL) {
        printf("no http state: ");
        result = 0;
        goto end;
    }

    if (AppLayerParserGetTxCnt(&f, htp_state) != 2) {
        printf("The http app layer doesn't have 2 transactions, but it should: ");
        goto end;
    }

    result = 1;
end:
    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
    if (det_ctx != NULL) {
        DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    }
    if (de_ctx != NULL) {
        SigGroupCleanup(de_ctx);
        DetectEngineCtxFree(de_ctx);
    }

    StreamTcpFreeConfig(TRUE);
    FLOW_DESTROY(&f);
    UTHFreePacket(p);
    return result;
}

/** \test multiple http transactions and body chunks of request handling */
static int DetectHttpClientBodyTest15(void)
{
    int result = 0;
    Signature *s = NULL;
    DetectEngineThreadCtx *det_ctx = NULL;
    ThreadVars th_v;
    Flow f;
    TcpSession ssn;
    Packet *p = NULL;
    uint8_t httpbuf1[] = "POST / HTTP/1.1\r\n";
    uint8_t httpbuf2[] = "User-Agent: Mozilla/1.0\r\nContent-Length: 10\r\n";
    uint8_t httpbuf3[] = "Cookie: dummy\r\n\r\n";
    uint8_t httpbuf4[] = "Body one!!";
    uint32_t httplen1 = sizeof(httpbuf1) - 1; /* minus the \0 */
    uint32_t httplen2 = sizeof(httpbuf2) - 1; /* minus the \0 */
    uint32_t httplen3 = sizeof(httpbuf3) - 1; /* minus the \0 */
    uint32_t httplen4 = sizeof(httpbuf4) - 1; /* minus the \0 */
    uint8_t httpbuf5[] = "GET /?var=val HTTP/1.1\r\n";
    uint8_t httpbuf6[] = "User-Agent: Firefox/1.0\r\n";
    uint8_t httpbuf7[] = "Cookie: dummy2\r\nContent-Length: 10\r\n\r\nBody two!!";
    uint32_t httplen5 = sizeof(httpbuf5) - 1; /* minus the \0 */
    uint32_t httplen6 = sizeof(httpbuf6) - 1; /* minus the \0 */
    uint32_t httplen7 = sizeof(httpbuf7) - 1; /* minus the \0 */
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&th_v, 0, sizeof(th_v));
    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    p = UTHBuildPacket(NULL, 0, IPPROTO_TCP);

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;
    f.flags |= FLOW_IPV4;

    p->flow = &f;
    p->flowflags |= FLOW_PKT_TOSERVER;
    p->flowflags |= FLOW_PKT_ESTABLISHED;
    p->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    f.alproto = ALPROTO_HTTP;

    StreamTcpInitConfig(TRUE);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }

    de_ctx->flags |= DE_QUIET;

    s = DetectEngineAppendSig(de_ctx, "alert tcp any any -> any any (content:\"POST\"; http_method; content:\"Mozilla\"; http_header; content:\"dummy\"; http_cookie; content:\"one\"; http_client_body; sid:1; rev:1;)");
    if (s == NULL) {
        printf("sig parse failed: ");
        goto end;
    }
    s = DetectEngineAppendSig(de_ctx, "alert tcp any any -> any any (content:\"GET\"; http_method; content:\"Firefox\"; http_header; content:\"dummy2\"; http_cookie; content:\"two\"; http_client_body; sid:2; rev:1;)");
    if (s == NULL) {
        printf("sig2 parse failed: ");
        goto end;
    }

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    FLOWLOCK_WRLOCK(&f);
    int r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_HTTP,
                                STREAM_TOSERVER, httpbuf1, httplen1);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        FLOWLOCK_UNLOCK(&f);
        goto end;
    }
    FLOWLOCK_UNLOCK(&f);

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    if (PacketAlertCheck(p, 1)) {
        printf("sig 1 alerted: ");
        goto end;
    }
    p->alerts.cnt = 0;

    FLOWLOCK_WRLOCK(&f);
    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_HTTP,
                            STREAM_TOSERVER, httpbuf2, httplen2);
    if (r != 0) {
        printf("toserver chunk 2 returned %" PRId32 ", expected 0: ", r);
        FLOWLOCK_UNLOCK(&f);
        goto end;
    }
    FLOWLOCK_UNLOCK(&f);

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    if (PacketAlertCheck(p, 1)) {
        printf("sig 1 alerted (2): ");
        goto end;
    }
    p->alerts.cnt = 0;

    FLOWLOCK_WRLOCK(&f);
    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_HTTP,
                            STREAM_TOSERVER, httpbuf3, httplen3);
    if (r != 0) {
        printf("toserver chunk 3 returned %" PRId32 ", expected 0: ", r);
        FLOWLOCK_UNLOCK(&f);
        goto end;
    }
    FLOWLOCK_UNLOCK(&f);

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    if (PacketAlertCheck(p, 1)) {
        printf("signature matched, but shouldn't have: ");
        goto end;
    }
    p->alerts.cnt = 0;

    FLOWLOCK_WRLOCK(&f);
    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_HTTP,
                            STREAM_TOSERVER, httpbuf4, httplen4);
    if (r != 0) {
        printf("toserver chunk 4 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        FLOWLOCK_UNLOCK(&f);
        goto end;
    }
    FLOWLOCK_UNLOCK(&f);

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    if (!(PacketAlertCheck(p, 1))) {
        printf("sig 1 didn't alert: ");
        goto end;
    }
    p->alerts.cnt = 0;

    FLOWLOCK_WRLOCK(&f);
    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_HTTP,
                            STREAM_TOSERVER, httpbuf5, httplen5);
    if (r != 0) {
        printf("toserver chunk 5 returned %" PRId32 ", expected 0: ", r);
        FLOWLOCK_UNLOCK(&f);
        goto end;
    }
    FLOWLOCK_UNLOCK(&f);

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    if (PacketAlertCheck(p, 1)) {
        printf("sig 1 alerted (5): ");
        goto end;
    }
    p->alerts.cnt = 0;

    FLOWLOCK_WRLOCK(&f);
    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_HTTP,
                            STREAM_TOSERVER, httpbuf6, httplen6);
    if (r != 0) {
        printf("toserver chunk 6 returned %" PRId32 ", expected 0: ", r);
        FLOWLOCK_UNLOCK(&f);
        goto end;
    }
    FLOWLOCK_UNLOCK(&f);

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    if ((PacketAlertCheck(p, 1)) || (PacketAlertCheck(p, 2))) {
        printf("sig 1 alerted (request 2, chunk 6): ");
        goto end;
    }
    p->alerts.cnt = 0;

    SCLogDebug("sending data chunk 7");

    FLOWLOCK_WRLOCK(&f);
    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_HTTP,
                            STREAM_TOSERVER, httpbuf7, httplen7);
    if (r != 0) {
        printf("toserver chunk 7 returned %" PRId32 ", expected 0: ", r);
        FLOWLOCK_UNLOCK(&f);
        goto end;
    }
    FLOWLOCK_UNLOCK(&f);

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    if (!(PacketAlertCheck(p, 2))) {
        printf("signature 2 didn't match, but should have: ");
        goto end;
    }
    p->alerts.cnt = 0;

    HtpState *htp_state = f.alstate;
    if (htp_state == NULL) {
        printf("no http state: ");
        result = 0;
        goto end;
    }

    /* hardcoded check of the transactions and it's client body chunks */
    if (AppLayerParserGetTxCnt(&f, htp_state) != 2) {
        printf("The http app layer doesn't have 2 transactions, but it should: ");
        goto end;
    }

    htp_tx_t *t1 = AppLayerParserGetTx(IPPROTO_TCP, ALPROTO_HTTP, htp_state, 0);
    htp_tx_t *t2 = AppLayerParserGetTx(IPPROTO_TCP, ALPROTO_HTTP, htp_state, 1);

    HtpTxUserData *htud = (HtpTxUserData *) htp_tx_get_user_data(t1);

    HtpBodyChunk *cur = htud->request_body.first;
    if (htud->request_body.first == NULL) {
        SCLogDebug("No body data in t1 (it should be removed only when the tx is destroyed): ");
        goto end;
    }

    if (StreamingBufferSegmentCompareRawData(htud->request_body.sb, &cur->sbseg,
                (uint8_t *)"Body one!!", 10) != 1)
    {
        SCLogDebug("Body data in t1 is not correctly set: ");
        goto end;
    }

    htud = (HtpTxUserData *) htp_tx_get_user_data(t2);

    cur = htud->request_body.first;
    if (htud->request_body.first == NULL) {
        SCLogDebug("No body data in t1 (it should be removed only when the tx is destroyed): ");
        goto end;
    }

    if (StreamingBufferSegmentCompareRawData(htud->request_body.sb, &cur->sbseg,
                (uint8_t *)"Body two!!", 10) != 1)
    {
        SCLogDebug("Body data in t1 is not correctly set: ");
        goto end;
    }

    result = 1;
end:
    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
    if (det_ctx != NULL) {
        DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    }
    if (de_ctx != NULL) {
        SigGroupCleanup(de_ctx);
        DetectEngineCtxFree(de_ctx);
    }

    StreamTcpFreeConfig(TRUE);
    FLOW_DESTROY(&f);
    UTHFreePacket(p);
    return result;
}















static int DetectHttpClientBodyTest22(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert icmp any any -> any any "
                               "(content:\"one\"; content:\"two\"; http_client_body; "
                               "content:\"three\"; distance:10; http_client_body; content:\"four\"; sid:1;)");
    if (de_ctx->sig_list == NULL) {
        printf("de_ctx->sig_list == NULL\n");
        goto end;
    }

    if (de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH] == NULL) {
        printf("de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH] == NULL\n");
        goto end;
    }

    if (de_ctx->sig_list->sm_lists[g_http_client_body_buffer_id] == NULL) {
        printf("de_ctx->sig_list->sm_lists[g_http_client_body_buffer_id] == NULL\n");
        goto end;
    }

    DetectContentData *cd1 = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[DETECT_SM_LIST_PMATCH]->prev->ctx;
    DetectContentData *cd2 = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[DETECT_SM_LIST_PMATCH]->ctx;
    DetectContentData *hcbd1 = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_http_client_body_buffer_id]->prev->ctx;
    DetectContentData *hcbd2 = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_http_client_body_buffer_id]->ctx;
    if (cd1->flags != 0 || memcmp(cd1->content, "one", cd1->content_len) != 0 ||
        cd2->flags != 0 || memcmp(cd2->content, "four", cd2->content_len) != 0 ||
        hcbd1->flags != DETECT_CONTENT_RELATIVE_NEXT ||
        memcmp(hcbd1->content, "two", hcbd1->content_len) != 0 ||
        hcbd2->flags != DETECT_CONTENT_DISTANCE ||
        memcmp(hcbd2->content, "three", hcbd1->content_len) != 0) {
        goto end;
    }

    if (!DETECT_CONTENT_IS_SINGLE(cd1) ||
        !DETECT_CONTENT_IS_SINGLE(cd2) ||
        DETECT_CONTENT_IS_SINGLE(hcbd1) ||
        DETECT_CONTENT_IS_SINGLE(hcbd2)) {
        goto end;
    }

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectHttpClientBodyTest23(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert icmp any any -> any any "
                               "(content:\"one\"; http_client_body; pcre:/two/; "
                               "content:\"three\"; distance:10; http_client_body; content:\"four\"; sid:1;)");
    if (de_ctx->sig_list == NULL) {
        printf("de_ctx->sig_list == NULL\n");
        goto end;
    }

    if (de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH] == NULL) {
        printf("de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH] == NULL\n");
        goto end;
    }

    if (de_ctx->sig_list->sm_lists[g_http_client_body_buffer_id] == NULL) {
        printf("de_ctx->sig_list->sm_lists[g_http_client_body_buffer_id] == NULL\n");
        goto end;
    }

    DetectPcreData *pd1 = (DetectPcreData *)de_ctx->sig_list->sm_lists_tail[DETECT_SM_LIST_PMATCH]->prev->ctx;
    DetectContentData *cd2 = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[DETECT_SM_LIST_PMATCH]->ctx;
    DetectContentData *hcbd1 = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_http_client_body_buffer_id]->prev->ctx;
    DetectContentData *hcbd2 = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_http_client_body_buffer_id]->ctx;
    if (pd1->flags != 0 ||
        cd2->flags != 0 || memcmp(cd2->content, "four", cd2->content_len) != 0 ||
        hcbd1->flags != DETECT_CONTENT_RELATIVE_NEXT ||
        memcmp(hcbd1->content, "one", hcbd1->content_len) != 0 ||
        hcbd2->flags != DETECT_CONTENT_DISTANCE ||
        memcmp(hcbd2->content, "three", hcbd1->content_len) != 0) {
        goto end;
    }

    if (!DETECT_CONTENT_IS_SINGLE(cd2) ||
        DETECT_CONTENT_IS_SINGLE(hcbd1) ||
        DETECT_CONTENT_IS_SINGLE(hcbd2)) {
        goto end;
    }

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectHttpClientBodyTest24(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert icmp any any -> any any "
                               "(content:\"one\"; http_client_body; pcre:/two/; "
                               "content:\"three\"; distance:10; within:15; http_client_body; content:\"four\"; sid:1;)");
    if (de_ctx->sig_list == NULL) {
        printf("de_ctx->sig_list == NULL\n");
        goto end;
    }

    if (de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH] == NULL) {
        printf("de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH] == NULL\n");
        goto end;
    }

    if (de_ctx->sig_list->sm_lists[g_http_client_body_buffer_id] == NULL) {
        printf("de_ctx->sig_list->sm_lists[g_http_client_body_buffer_id] == NULL\n");
        goto end;
    }

    DetectPcreData *pd1 = (DetectPcreData *)de_ctx->sig_list->sm_lists_tail[DETECT_SM_LIST_PMATCH]->prev->ctx;
    DetectContentData *cd2 = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[DETECT_SM_LIST_PMATCH]->ctx;
    DetectContentData *hcbd1 = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_http_client_body_buffer_id]->prev->ctx;
    DetectContentData *hcbd2 = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_http_client_body_buffer_id]->ctx;
    if (pd1->flags != 0 ||
        cd2->flags != 0 || memcmp(cd2->content, "four", cd2->content_len) != 0 ||
        hcbd1->flags != DETECT_CONTENT_RELATIVE_NEXT ||
        memcmp(hcbd1->content, "one", hcbd1->content_len) != 0 ||
        hcbd2->flags != (DETECT_CONTENT_DISTANCE | DETECT_CONTENT_WITHIN) ||
        memcmp(hcbd2->content, "three", hcbd1->content_len) != 0) {
        goto end;
    }

    if (!DETECT_CONTENT_IS_SINGLE(cd2) ||
        DETECT_CONTENT_IS_SINGLE(hcbd1) ||
        DETECT_CONTENT_IS_SINGLE(hcbd2)) {
        goto end;
    }

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectHttpClientBodyTest25(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert icmp any any -> any any "
                               "(content:\"one\"; http_client_body; pcre:/two/; "
                               "content:\"three\"; distance:10; http_client_body; "
                               "content:\"four\"; distance:10; sid:1;)");
    if (de_ctx->sig_list == NULL) {
        printf("de_ctx->sig_list == NULL\n");
        goto end;
    }

    if (de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH] == NULL) {
        printf("de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH] == NULL\n");
        goto end;
    }

    if (de_ctx->sig_list->sm_lists[g_http_client_body_buffer_id] == NULL) {
        printf("de_ctx->sig_list->sm_lists[g_http_client_body_buffer_id] == NULL\n");
        goto end;
    }

    DetectPcreData *pd1 = (DetectPcreData *)de_ctx->sig_list->sm_lists_tail[DETECT_SM_LIST_PMATCH]->prev->ctx;
    DetectContentData *cd2 = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[DETECT_SM_LIST_PMATCH]->ctx;
    DetectContentData *hcbd1 = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_http_client_body_buffer_id]->prev->ctx;
    DetectContentData *hcbd2 = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_http_client_body_buffer_id]->ctx;
    if (pd1->flags != DETECT_PCRE_RELATIVE_NEXT ||
        cd2->flags != DETECT_CONTENT_DISTANCE ||
        memcmp(cd2->content, "four", cd2->content_len) != 0 ||
        hcbd1->flags != DETECT_CONTENT_RELATIVE_NEXT ||
        memcmp(hcbd1->content, "one", hcbd1->content_len) != 0 ||
        hcbd2->flags != DETECT_CONTENT_DISTANCE ||
        memcmp(hcbd2->content, "three", hcbd1->content_len) != 0) {
        goto end;
    }

    if (DETECT_CONTENT_IS_SINGLE(cd2) ||
        DETECT_CONTENT_IS_SINGLE(hcbd1) ||
        DETECT_CONTENT_IS_SINGLE(hcbd2)) {
        goto end;
    }

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectHttpClientBodyTest26(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert icmp any any -> any any "
                               "(content:\"one\"; offset:10; http_client_body; pcre:/two/; "
                               "content:\"three\"; distance:10; http_client_body; within:10; "
                               "content:\"four\"; distance:10; sid:1;)");
    if (de_ctx->sig_list == NULL) {
        printf("de_ctx->sig_list == NULL\n");
        goto end;
    }

    if (de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH] == NULL) {
        printf("de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH] == NULL\n");
        goto end;
    }

    if (de_ctx->sig_list->sm_lists[g_http_client_body_buffer_id] == NULL) {
        printf("de_ctx->sig_list->sm_lists[g_http_client_body_buffer_id] == NULL\n");
        goto end;
    }

    DetectPcreData *pd1 = (DetectPcreData *)de_ctx->sig_list->sm_lists_tail[DETECT_SM_LIST_PMATCH]->prev->ctx;
    DetectContentData *cd2 = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[DETECT_SM_LIST_PMATCH]->ctx;
    DetectContentData *hcbd1 = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_http_client_body_buffer_id]->prev->ctx;
    DetectContentData *hcbd2 = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_http_client_body_buffer_id]->ctx;
    if (pd1->flags != (DETECT_PCRE_RELATIVE_NEXT) ||
        cd2->flags != DETECT_CONTENT_DISTANCE ||
        memcmp(cd2->content, "four", cd2->content_len) != 0 ||
        hcbd1->flags != (DETECT_CONTENT_RELATIVE_NEXT | DETECT_CONTENT_OFFSET) ||
        memcmp(hcbd1->content, "one", hcbd1->content_len) != 0 ||
        hcbd2->flags != (DETECT_CONTENT_DISTANCE | DETECT_CONTENT_WITHIN) ||
        memcmp(hcbd2->content, "three", hcbd1->content_len) != 0) {
        printf ("failed: http_client_body incorrect flags");
        goto end;
    }

    if (DETECT_CONTENT_IS_SINGLE(cd2) ||
        DETECT_CONTENT_IS_SINGLE(hcbd1) ||
        DETECT_CONTENT_IS_SINGLE(hcbd2)) {
        goto end;
    }

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectHttpClientBodyTest27(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert icmp any any -> any any "
                               "(content:\"one\"; offset:10; http_client_body; pcre:/two/; "
                               "content:\"three\"; distance:10; http_client_body; within:10; "
                               "content:\"four\"; distance:10; sid:1;)");
    if (de_ctx->sig_list == NULL) {
        printf("de_ctx->sig_list == NULL\n");
        goto end;
    }

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectHttpClientBodyTest28(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert icmp any any -> any any "
                               "(content:\"one\"; http_client_body; pcre:/two/; "
                               "content:\"three\"; http_client_body; depth:10; "
                               "content:\"four\"; distance:10; sid:1;)");
    if (de_ctx->sig_list == NULL) {
        printf("de_ctx->sig_list == NULL\n");
        goto end;
    }

    if (de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH] == NULL) {
        printf("de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH] == NULL\n");
        goto end;
    }

    if (de_ctx->sig_list->sm_lists[g_http_client_body_buffer_id] == NULL) {
        printf("de_ctx->sig_list->sm_lists[g_http_client_body_buffer_id] == NULL\n");
        goto end;
    }

    DetectPcreData *pd1 = (DetectPcreData *)de_ctx->sig_list->sm_lists_tail[DETECT_SM_LIST_PMATCH]->prev->ctx;
    DetectContentData *cd2 = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[DETECT_SM_LIST_PMATCH]->ctx;
    DetectContentData *hcbd1 = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_http_client_body_buffer_id]->prev->ctx;
    DetectContentData *hcbd2 = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_http_client_body_buffer_id]->ctx;
    if (pd1->flags != (DETECT_PCRE_RELATIVE_NEXT) ||
        cd2->flags != DETECT_CONTENT_DISTANCE ||
        memcmp(cd2->content, "four", cd2->content_len) != 0 ||
        hcbd1->flags != 0 ||
        memcmp(hcbd1->content, "one", hcbd1->content_len) != 0 ||
        hcbd2->flags != DETECT_CONTENT_DEPTH ||
        memcmp(hcbd2->content, "three", hcbd1->content_len) != 0) {
        goto end;
    }

    if (DETECT_CONTENT_IS_SINGLE(cd2) ||
        !DETECT_CONTENT_IS_SINGLE(hcbd1) ||
        DETECT_CONTENT_IS_SINGLE(hcbd2)) {
        goto end;
    }

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectHttpClientBodyTest29(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert icmp any any -> any any "
                               "(content:\"one\"; http_client_body; "
                               "content:\"two\"; distance:0; http_client_body; sid:1;)");
    if (de_ctx->sig_list == NULL) {
        printf("de_ctx->sig_list == NULL\n");
        goto end;
    }

    if (de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH] != NULL) {
        printf("de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH] != NULL\n");
        goto end;
    }

    if (de_ctx->sig_list->sm_lists[g_http_client_body_buffer_id] == NULL) {
        printf("de_ctx->sig_list->sm_lists[g_http_client_body_buffer_id] == NULL\n");
        goto end;
    }

    DetectContentData *hcbd1 = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_http_client_body_buffer_id]->prev->ctx;
    DetectContentData *hcbd2 = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_http_client_body_buffer_id]->ctx;
    if (hcbd1->flags != DETECT_CONTENT_RELATIVE_NEXT ||
        memcmp(hcbd1->content, "one", hcbd1->content_len) != 0 ||
        hcbd2->flags != DETECT_CONTENT_DISTANCE ||
        memcmp(hcbd2->content, "two", hcbd1->content_len) != 0) {
        goto end;
    }

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectHttpClientBodyTest30(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert icmp any any -> any any "
                               "(content:\"one\"; http_client_body; "
                               "content:\"two\"; within:5; http_client_body; sid:1;)");
    if (de_ctx->sig_list == NULL) {
        printf("de_ctx->sig_list == NULL\n");
        goto end;
    }

    if (de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH] != NULL) {
        printf("de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH] != NULL\n");
        goto end;
    }

    if (de_ctx->sig_list->sm_lists[g_http_client_body_buffer_id] == NULL) {
        printf("de_ctx->sig_list->sm_lists[g_http_client_body_buffer_id] == NULL\n");
        goto end;
    }

    DetectContentData *hcbd1 = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_http_client_body_buffer_id]->prev->ctx;
    DetectContentData *hcbd2 = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_http_client_body_buffer_id]->ctx;
    if (hcbd1->flags != DETECT_CONTENT_RELATIVE_NEXT ||
        memcmp(hcbd1->content, "one", hcbd1->content_len) != 0 ||
        hcbd2->flags != DETECT_CONTENT_WITHIN ||
        memcmp(hcbd2->content, "two", hcbd1->content_len) != 0) {
        goto end;
    }

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectHttpClientBodyTest31(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert icmp any any -> any any "
                               "(content:\"one\"; within:5; http_client_body; sid:1;)");
    if (de_ctx->sig_list == NULL) {
        printf("de_ctx->sig_list == NULL\n");
        goto end;
    }

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectHttpClientBodyTest32(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert icmp any any -> any any "
                               "(content:\"one\"; http_client_body; within:5; sid:1;)");
    if (de_ctx->sig_list == NULL) {
        printf("de_ctx->sig_list != NULL\n");
        goto end;
    }

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectHttpClientBodyTest33(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert icmp any any -> any any "
                               "(content:\"one\"; within:5; sid:1;)");
    if (de_ctx->sig_list == NULL) {
        printf("de_ctx->sig_list == NULL\n");
        goto end;
    }

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectHttpClientBodyTest34(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert icmp any any -> any any "
                               "(pcre:/one/P; "
                               "content:\"two\"; within:5; http_client_body; sid:1;)");
    if (de_ctx->sig_list == NULL) {
        printf("de_ctx->sig_list == NULL\n");
        goto end;
    }

    if (de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH] != NULL) {
        printf("de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH] != NULL\n");
        goto end;
    }

    if (de_ctx->sig_list->sm_lists[g_http_client_body_buffer_id] == NULL) {
        printf("de_ctx->sig_list->sm_lists[g_http_client_body_buffer_id] == NULL\n");
        goto end;
    }

    if (de_ctx->sig_list->sm_lists_tail[g_http_client_body_buffer_id] == NULL ||
        de_ctx->sig_list->sm_lists_tail[g_http_client_body_buffer_id]->type != DETECT_CONTENT ||
        de_ctx->sig_list->sm_lists_tail[g_http_client_body_buffer_id]->prev == NULL ||
        de_ctx->sig_list->sm_lists_tail[g_http_client_body_buffer_id]->prev->type != DETECT_PCRE) {

        goto end;
    }

    DetectPcreData *pd1 = (DetectPcreData *)de_ctx->sig_list->sm_lists_tail[g_http_client_body_buffer_id]->prev->ctx;
    DetectContentData *hcbd2 = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_http_client_body_buffer_id]->ctx;
    if (pd1->flags != (DETECT_PCRE_RELATIVE_NEXT) ||
        hcbd2->flags != DETECT_CONTENT_WITHIN ||
        memcmp(hcbd2->content, "two", hcbd2->content_len) != 0) {
        goto end;
    }

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectHttpClientBodyTest35(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert icmp any any -> any any "
                               "(content:\"two\"; http_client_body; "
                               "pcre:/one/PR; sid:1;)");
    if (de_ctx->sig_list == NULL) {
        printf("de_ctx->sig_list == NULL\n");
        goto end;
    }

    if (de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH] != NULL) {
        printf("de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH] != NULL\n");
        goto end;
    }

    if (de_ctx->sig_list->sm_lists[g_http_client_body_buffer_id] == NULL) {
        printf("de_ctx->sig_list->sm_lists[g_http_client_body_buffer_id] == NULL\n");
        goto end;
    }

    if (de_ctx->sig_list->sm_lists_tail[g_http_client_body_buffer_id] == NULL ||
        de_ctx->sig_list->sm_lists_tail[g_http_client_body_buffer_id]->type != DETECT_PCRE ||
        de_ctx->sig_list->sm_lists_tail[g_http_client_body_buffer_id]->prev == NULL ||
        de_ctx->sig_list->sm_lists_tail[g_http_client_body_buffer_id]->prev->type != DETECT_CONTENT) {

        goto end;
    }

    DetectContentData *hcbd1 = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_http_client_body_buffer_id]->prev->ctx;
    DetectPcreData *pd2 = (DetectPcreData *)de_ctx->sig_list->sm_lists_tail[g_http_client_body_buffer_id]->ctx;
    if (pd2->flags != (DETECT_PCRE_RELATIVE) ||
        hcbd1->flags != DETECT_CONTENT_RELATIVE_NEXT ||
        memcmp(hcbd1->content, "two", hcbd1->content_len) != 0) {
        goto end;
    }

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectHttpClientBodyTest36(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert icmp any any -> any any "
                               "(pcre:/one/P; "
                               "content:\"two\"; distance:5; http_client_body; sid:1;)");
    if (de_ctx->sig_list == NULL) {
        printf("de_ctx->sig_list == NULL\n");
        goto end;
    }

    if (de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH] != NULL) {
        printf("de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH] != NULL\n");
        goto end;
    }

    if (de_ctx->sig_list->sm_lists[g_http_client_body_buffer_id] == NULL) {
        printf("de_ctx->sig_list->sm_lists[g_http_client_body_buffer_id] == NULL\n");
        goto end;
    }

    if (de_ctx->sig_list->sm_lists_tail[g_http_client_body_buffer_id] == NULL ||
        de_ctx->sig_list->sm_lists_tail[g_http_client_body_buffer_id]->type != DETECT_CONTENT ||
        de_ctx->sig_list->sm_lists_tail[g_http_client_body_buffer_id]->prev == NULL ||
        de_ctx->sig_list->sm_lists_tail[g_http_client_body_buffer_id]->prev->type != DETECT_PCRE) {

        goto end;
    }

    DetectPcreData *pd1 = (DetectPcreData *)de_ctx->sig_list->sm_lists_tail[g_http_client_body_buffer_id]->prev->ctx;
    DetectContentData *hcbd2 = (DetectContentData *)de_ctx->sig_list->sm_lists_tail[g_http_client_body_buffer_id]->ctx;
    if (pd1->flags != (DETECT_PCRE_RELATIVE_NEXT) ||
        hcbd2->flags != DETECT_CONTENT_DISTANCE ||
        memcmp(hcbd2->content, "two", hcbd2->content_len) != 0) {
        goto end;
    }

    result = 1;

 end:
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

static int DetectHttpClientBodyIsdataatParseTest(void)
{
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    de_ctx->flags |= DE_QUIET;

    Signature *s = DetectEngineAppendSig(de_ctx,
            "alert tcp any any -> any any ("
            "content:\"one\"; http_client_body; "
            "isdataat:!4,relative; sid:1;)");
    FAIL_IF_NULL(s);

    SigMatch *sm = s->init_data->smlists_tail[g_http_client_body_buffer_id];
    FAIL_IF_NULL(sm);
    FAIL_IF_NOT(sm->type == DETECT_ISDATAAT);

    DetectIsdataatData *data = (DetectIsdataatData *)sm->ctx;
    FAIL_IF_NOT(data->flags & ISDATAAT_RELATIVE);
    FAIL_IF_NOT(data->flags & ISDATAAT_NEGATED);
    FAIL_IF(data->flags & ISDATAAT_RAWBYTES);

    DetectEngineCtxFree(de_ctx);
    PASS;
}

#endif /* UNITTESTS */

void DetectHttpClientBodyRegisterTests(void)
{
#ifdef UNITTESTS
    UtRegisterTest("DetectHttpClientBodyTest01", DetectHttpClientBodyTest01);
    UtRegisterTest("DetectHttpClientBodyTest02", DetectHttpClientBodyTest02);
    UtRegisterTest("DetectHttpClientBodyTest03", DetectHttpClientBodyTest03);
    UtRegisterTest("DetectHttpClientBodyTest04", DetectHttpClientBodyTest04);
    UtRegisterTest("DetectHttpClientBodyTest05", DetectHttpClientBodyTest05);
    UtRegisterTest("DetectHttpClientBodyTest06", DetectHttpClientBodyTest06);
    UtRegisterTest("DetectHttpClientBodyTest07", DetectHttpClientBodyTest07);
    UtRegisterTest("DetectHttpClientBodyTest08", DetectHttpClientBodyTest08);
    UtRegisterTest("DetectHttpClientBodyTest09", DetectHttpClientBodyTest09);
    UtRegisterTest("DetectHttpClientBodyTest10", DetectHttpClientBodyTest10);
    UtRegisterTest("DetectHttpClientBodyTest11", DetectHttpClientBodyTest11);
    UtRegisterTest("DetectHttpClientBodyTest12", DetectHttpClientBodyTest12);
    UtRegisterTest("DetectHttpClientBodyTest13", DetectHttpClientBodyTest13);
    UtRegisterTest("DetectHttpClientBodyTest14", DetectHttpClientBodyTest14);
    UtRegisterTest("DetectHttpClientBodyTest15", DetectHttpClientBodyTest15);

    UtRegisterTest("DetectHttpClientBodyTest22", DetectHttpClientBodyTest22);
    UtRegisterTest("DetectHttpClientBodyTest23", DetectHttpClientBodyTest23);
    UtRegisterTest("DetectHttpClientBodyTest24", DetectHttpClientBodyTest24);
    UtRegisterTest("DetectHttpClientBodyTest25", DetectHttpClientBodyTest25);
    UtRegisterTest("DetectHttpClientBodyTest26", DetectHttpClientBodyTest26);
    UtRegisterTest("DetectHttpClientBodyTest27", DetectHttpClientBodyTest27);
    UtRegisterTest("DetectHttpClientBodyTest28", DetectHttpClientBodyTest28);
    UtRegisterTest("DetectHttpClientBodyTest29", DetectHttpClientBodyTest29);
    UtRegisterTest("DetectHttpClientBodyTest30", DetectHttpClientBodyTest30);
    UtRegisterTest("DetectHttpClientBodyTest31", DetectHttpClientBodyTest31);
    UtRegisterTest("DetectHttpClientBodyTest32", DetectHttpClientBodyTest32);
    UtRegisterTest("DetectHttpClientBodyTest33", DetectHttpClientBodyTest33);
    UtRegisterTest("DetectHttpClientBodyTest34", DetectHttpClientBodyTest34);
    UtRegisterTest("DetectHttpClientBodyTest35", DetectHttpClientBodyTest35);
    UtRegisterTest("DetectHttpClientBodyTest36", DetectHttpClientBodyTest36);

    UtRegisterTest("DetectHttpClientBodyIsdataatParseTest",
            DetectHttpClientBodyIsdataatParseTest);

#endif /* UNITTESTS */

    return;
}
/**
 * @}
 */
