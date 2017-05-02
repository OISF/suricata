/* Copyright (C) 2007-2016 Open Information Security Foundation
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
 * \author Victor Julien <victor@inliniac.net>
 *
 * Implements support for the http_request_line keyword.
 */

#include "suricata-common.h"
#include "threads.h"
#include "decode.h"

#include "detect.h"
#include "detect-parse.h"
#include "detect-engine.h"
#include "detect-engine-mpm.h"
#include "detect-engine-state.h"
#include "detect-engine-prefilter.h"
#include "detect-engine-content-inspection.h"
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
#include "stream-tcp.h"
#include "detect-http-request-line.h"

static int DetectHttpRequestLineSetup(DetectEngineCtx *, Signature *, const char *);
static void DetectHttpRequestLineRegisterTests(void);
static int PrefilterTxHttpRequestLineRegister(SigGroupHead *sgh, MpmCtx *mpm_ctx);
static int DetectEngineInspectHttpRequestLine(ThreadVars *tv,
        DetectEngineCtx *de_ctx, DetectEngineThreadCtx *det_ctx,
        const Signature *s, const SigMatchData *smd,
        Flow *f, uint8_t flags, void *alstate, void *txv, uint64_t tx_id);
static void DetectHttpRequestLineSetupCallback(Signature *s);
static int g_http_request_line_buffer_id = 0;

/**
 * \brief Registers the keyword handlers for the "http_request_line" keyword.
 */
void DetectHttpRequestLineRegister(void)
{
    sigmatch_table[DETECT_AL_HTTP_REQUEST_LINE].name = "http_request_line";
    sigmatch_table[DETECT_AL_HTTP_REQUEST_LINE].desc = "content modifier to match only on the HTTP request line";
    sigmatch_table[DETECT_AL_HTTP_REQUEST_LINE].url = DOC_URL DOC_VERSION "/rules/http-keywords.html#http_request-line";
    sigmatch_table[DETECT_AL_HTTP_REQUEST_LINE].Match = NULL;
    sigmatch_table[DETECT_AL_HTTP_REQUEST_LINE].Setup = DetectHttpRequestLineSetup;
    sigmatch_table[DETECT_AL_HTTP_REQUEST_LINE].RegisterTests = DetectHttpRequestLineRegisterTests;

    sigmatch_table[DETECT_AL_HTTP_REQUEST_LINE].flags |= SIGMATCH_NOOPT;

    DetectAppLayerMpmRegister("http_request_line", SIG_FLAG_TOSERVER, 2,
            PrefilterTxHttpRequestLineRegister);

    DetectAppLayerInspectEngineRegister("http_request_line",
            ALPROTO_HTTP, SIG_FLAG_TOSERVER, HTP_REQUEST_LINE,
            DetectEngineInspectHttpRequestLine);

    DetectBufferTypeSetDescriptionByName("http_request_line",
            "http request line");

    DetectBufferTypeRegisterSetupCallback("http_request_line",
            DetectHttpRequestLineSetupCallback);

    g_http_request_line_buffer_id = DetectBufferTypeGetByName("http_request_line");
}

/**
 * \brief The setup function for the http_request_line keyword for a signature.
 *
 * \param de_ctx Pointer to the detection engine context.
 * \param s      Pointer to the signature for the current Signature being
 *               parsed from the rules.
 * \param m      Pointer to the head of the SigMatch for the current rule
 *               being parsed.
 * \param arg    Pointer to the string holding the keyword value.
 *
 * \retval  0 On success
 * \retval -1 On failure
 */
static int DetectHttpRequestLineSetup(DetectEngineCtx *de_ctx, Signature *s, const char *arg)
{
    s->init_data->list = g_http_request_line_buffer_id;
    s->alproto = ALPROTO_HTTP;
    return 0;
}

static void DetectHttpRequestLineSetupCallback(Signature *s)
{
    SCLogDebug("callback invoked by %u", s->id);
    s->mask |= SIG_MASK_REQUIRE_HTTP_STATE;
}

/** \brief HTTP request line Mpm prefilter callback
 *
 *  \param det_ctx detection engine thread ctx
 *  \param p packet to inspect
 *  \param f flow to inspect
 *  \param txv tx to inspect
 *  \param pectx inspection context
 */
static void PrefilterTxHttpRequestLine(DetectEngineThreadCtx *det_ctx,
        const void *pectx,
        Packet *p, Flow *f, void *txv,
        const uint64_t idx, const uint8_t flags)
{
    SCEnter();

    const MpmCtx *mpm_ctx = (MpmCtx *)pectx;
    htp_tx_t *tx = (htp_tx_t *)txv;

    if (tx->request_line == NULL)
        return;

    const uint32_t buffer_len = bstr_len(tx->request_line);
    const uint8_t *buffer = bstr_ptr(tx->request_line);

    if (buffer_len >= mpm_ctx->minlen) {
        (void)mpm_table[mpm_ctx->mpm_type].Search(mpm_ctx,
                &det_ctx->mtcu, &det_ctx->pmq, buffer, buffer_len);
    }
}

static int PrefilterTxHttpRequestLineRegister(SigGroupHead *sgh, MpmCtx *mpm_ctx)
{
    SCEnter();

    return PrefilterAppendTxEngine(sgh, PrefilterTxHttpRequestLine,
        ALPROTO_HTTP, HTP_REQUEST_LINE,
        mpm_ctx, NULL, "http_request_line");
}

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
static int DetectEngineInspectHttpRequestLine(ThreadVars *tv,
        DetectEngineCtx *de_ctx, DetectEngineThreadCtx *det_ctx,
        const Signature *s, const SigMatchData *smd,
        Flow *f, uint8_t flags, void *alstate, void *txv, uint64_t tx_id)
{
    htp_tx_t *tx = (htp_tx_t *)txv;

    if (tx->request_line == NULL) {
        if (AppLayerParserGetStateProgress(IPPROTO_TCP, ALPROTO_HTTP, txv, flags) > HTP_REQUEST_LINE)
            return DETECT_ENGINE_INSPECT_SIG_CANT_MATCH;
        else
            return DETECT_ENGINE_INSPECT_SIG_NO_MATCH;
    }

    det_ctx->discontinue_matching = 0;
    det_ctx->buffer_offset = 0;
    det_ctx->inspection_recursion_counter = 0;

    /* Inspect all the uricontents fetched on each
     * transaction at the app layer */
    int r = DetectEngineContentInspection(de_ctx, det_ctx,
                                          s, smd,
                                          f,
                                          bstr_ptr(tx->request_line),
                                          bstr_len(tx->request_line),
                                          0,
                                          DETECT_ENGINE_CONTENT_INSPECTION_MODE_STATE, NULL);
    if (r == 1) {
        return DETECT_ENGINE_INSPECT_SIG_MATCH;
    } else {
        return DETECT_ENGINE_INSPECT_SIG_CANT_MATCH;
    }
}

/************************************Unittests*********************************/

#ifdef UNITTESTS

#include "stream-tcp-reassemble.h"

/**
 * \test Test that a signature containting a http_request_line is correctly parsed
 *       and the keyword is registered.
 */
static int DetectHttpRequestLineTest01(void)
{
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(http_request_line; content:\"GET /\"; sid:1;)");
    FAIL_IF_NULL(de_ctx->sig_list);

    DetectEngineCtxFree(de_ctx);
    PASS;
}


/**
 *\test Test that the http_request_line content matches against a http request
 *      which holds the content.
 */
static int DetectHttpRequestLineTest02(void)
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
        "User-Agent: This is dummy message body\r\n"
        "Content-Type: text/html\r\n"
        "\r\n";
    uint32_t http_len = sizeof(http_buf) - 1;

    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();
    FAIL_IF_NULL(alp_tctx);

    memset(&th_v, 0, sizeof(th_v));
    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    p = UTHBuildPacket(NULL, 0, IPPROTO_TCP);
    FAIL_IF_NULL(p);

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;
    f.flags |= FLOW_IPV4;

    p->flow = &f;
    p->flowflags |= FLOW_PKT_TOSERVER;
    p->flowflags |= FLOW_PKT_ESTABLISHED;
    p->flags |= PKT_HAS_FLOW | PKT_STREAM_EST;
    f.alproto = ALPROTO_HTTP;

    StreamTcpInitConfig(TRUE);

    de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert http any any -> any any "
                               "(http_request_line; content:\"GET /index.html HTTP/1.0\"; "
                               "sid:1;)");
    FAIL_IF_NULL(de_ctx->sig_list);

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParserParse(&th_v, alp_tctx, &f, ALPROTO_HTTP, STREAM_TOSERVER, http_buf, http_len);
    FAIL_IF(r != 0);

    http_state = f.alstate;
    FAIL_IF_NULL(http_state);

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);

    FAIL_IF(!(PacketAlertCheck(p, 1)));

    AppLayerParserThreadCtxFree(alp_tctx);
    DetectEngineCtxFree(de_ctx);

    StreamTcpFreeConfig(TRUE);
    FLOW_DESTROY(&f);
    UTHFreePackets(&p, 1);
    PASS;
}

#endif /* UNITTESTS */

static void DetectHttpRequestLineRegisterTests(void)
{
#ifdef UNITTESTS
    UtRegisterTest("DetectHttpRequestLineTest01", DetectHttpRequestLineTest01);
    UtRegisterTest("DetectHttpRequestLineTest02", DetectHttpRequestLineTest02);
#endif /* UNITTESTS */

    return;
}
/**
 * @}
 */
