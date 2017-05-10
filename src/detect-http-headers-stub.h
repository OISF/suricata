/* Copyright (C) 2007-2017 Open Information Security Foundation
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
 * Stub for per HTTP header detection keyword. Meant to be included into
 * a C file.
 */

/**
 * \ingroup httplayer
 *
 * @{
 */

#include "suricata-common.h"
#include "threads.h"
#include "decode.h"
#include "flow.h"
#include "app-layer.h"
#include "app-layer-parser.h"
#include "app-layer-htp.h"

#include "detect.h"
#include "detect-parse.h"
#include "detect-engine.h"
#include "detect-engine-mpm.h"
#include "detect-engine-state.h"
#include "detect-engine-prefilter.h"
#include "detect-engine-content-inspection.h"
#include "detect-content.h"
#include "detect-http-header.h"

#include "util-debug.h"

static int g_buffer_id = 0;

#ifdef KEYWORD_TOSERVER
/** \brief HTTP Headers Mpm prefilter callback
 *
 *  \param det_ctx detection engine thread ctx
 *  \param p packet to inspect
 *  \param f flow to inspect
 *  \param txv tx to inspect
 *  \param pectx inspection context
 */
static void PrefilterTxHttpRequestHeader(DetectEngineThreadCtx *det_ctx,
        const void *pectx,
        Packet *p, Flow *f, void *txv,
        const uint64_t idx, const uint8_t flags)
{
    SCEnter();
    const MpmCtx *mpm_ctx = (MpmCtx *)pectx;
    htp_tx_t *tx = (htp_tx_t *)txv;

    if (tx->request_headers == NULL)
        return;

    htp_header_t *h = (htp_header_t *)htp_table_get_c(tx->request_headers,
                                                      HEADER_NAME);
    if (h == NULL || h->value == NULL) {
        SCLogDebug("HTTP %s header not present in this request", HEADER_NAME);
        return;
    }

    const uint32_t buffer_len = bstr_len(h->value);
    const uint8_t *buffer = bstr_ptr(h->value);

    if (buffer_len >= mpm_ctx->minlen) {
        (void)mpm_table[mpm_ctx->mpm_type].Search(mpm_ctx,
                &det_ctx->mtcu, &det_ctx->pmq, buffer, buffer_len);
    }
}
#if 0
static void PrefilterTxHttpRequestTrailers(DetectEngineThreadCtx *det_ctx,
        const void *pectx,
        Packet *p, Flow *f, void *txv,
        const uint64_t idx, const uint8_t flags)
{
    SCEnter();

    const MpmCtx *mpm_ctx = (MpmCtx *)pectx;
    htp_tx_t *tx = (htp_tx_t *)txv;

    if (tx->request_headers == NULL)
        return;
    const HtpTxUserData *htud = (const HtpTxUserData *)htp_tx_get_user_data(tx);
    /* if the request wasn't flagged as having a trailer, we skip */
    if (htud && !htud->request_has_trailers)
        return;

    HtpState *htp_state = f->alstate;
    uint32_t buffer_len = 0;
    const uint8_t *buffer = DetectEngineHHDGetBufferForTX(tx, idx,
                                                    NULL, det_ctx,
                                                    f, htp_state,
                                                    flags,
                                                    &buffer_len);

    if (buffer_len >= mpm_ctx->minlen) {
        (void)mpm_table[mpm_ctx->mpm_type].Search(mpm_ctx,
                &det_ctx->mtcu, &det_ctx->pmq, buffer, buffer_len);
    }
}
#endif
static int PrefilterTxHttpRequestHeaderRegister(SigGroupHead *sgh, MpmCtx *mpm_ctx)
{
    SCEnter();

    int r = PrefilterAppendTxEngine(sgh, PrefilterTxHttpRequestHeader,
        ALPROTO_HTTP, HTP_REQUEST_HEADERS,
        mpm_ctx, NULL, KEYWORD_NAME " (request)");
    return r;
#if 0
    if (r != 0)
        return r;
    return PrefilterAppendTxEngine(sgh, PrefilterTxHttpRequestTrailers,
        ALPROTO_HTTP, HTP_REQUEST_TRAILER,
        mpm_ctx, NULL, "http_header (request)");
#endif
}
#endif

#ifdef KEYWORD_TOCLIENT
/** \brief HTTP Headers Mpm prefilter callback
 *
 *  \param det_ctx detection engine thread ctx
 *  \param p packet to inspect
 *  \param f flow to inspect
 *  \param txv tx to inspect
 *  \param pectx inspection context
 */
static void PrefilterTxHttpResponseHeader(DetectEngineThreadCtx *det_ctx,
        const void *pectx,
        Packet *p, Flow *f, void *txv,
        const uint64_t idx, const uint8_t flags)
{
    SCEnter();
    const MpmCtx *mpm_ctx = (MpmCtx *)pectx;
    htp_tx_t *tx = (htp_tx_t *)txv;

    if (tx->response_headers == NULL)
        return;

    htp_header_t *h = (htp_header_t *)htp_table_get_c(tx->response_headers,
                                                      HEADER_NAME);
    if (h == NULL || h->value == NULL) {
        SCLogDebug("HTTP %s header not present in this request", HEADER_NAME);
        return;
    }

    const uint32_t buffer_len = bstr_len(h->value);
    const uint8_t *buffer = bstr_ptr(h->value);

    if (buffer_len >= mpm_ctx->minlen) {
        (void)mpm_table[mpm_ctx->mpm_type].Search(mpm_ctx,
                &det_ctx->mtcu, &det_ctx->pmq, buffer, buffer_len);
    }
}
#if 0
static void PrefilterTxHttpResponseTrailers(DetectEngineThreadCtx *det_ctx,
        const void *pectx,
        Packet *p, Flow *f, void *txv,
        const uint64_t idx, const uint8_t flags)
{
    SCEnter();

    const MpmCtx *mpm_ctx = (MpmCtx *)pectx;
    htp_tx_t *tx = (htp_tx_t *)txv;

    if (tx->response_headers == NULL)
        return;
    const HtpTxUserData *htud = (const HtpTxUserData *)htp_tx_get_user_data(tx);
    /* if the request wasn't flagged as having a trailer, we skip */
    if (htud && !htud->response_has_trailers)
        return;

    HtpState *htp_state = f->alstate;
    uint32_t buffer_len = 0;
    const uint8_t *buffer = DetectEngineHHDGetBufferForTX(tx, idx,
                                                    NULL, det_ctx,
                                                    f, htp_state,
                                                    flags,
                                                    &buffer_len);

    if (buffer_len >= mpm_ctx->minlen) {
        (void)mpm_table[mpm_ctx->mpm_type].Search(mpm_ctx,
                &det_ctx->mtcu, &det_ctx->pmq, buffer, buffer_len);
    }
}
#endif
static int PrefilterTxHttpResponseHeaderRegister(SigGroupHead *sgh, MpmCtx *mpm_ctx)
{
    SCEnter();

    int r = PrefilterAppendTxEngine(sgh, PrefilterTxHttpResponseHeader,
        ALPROTO_HTTP, HTP_RESPONSE_HEADERS,
        mpm_ctx, NULL, KEYWORD_NAME " (response)");
    return r;
#if 0
    if (r != 0)
        return r;
    return PrefilterAppendTxEngine(sgh, PrefilterTxHttpRequestTrailers,
        ALPROTO_HTTP, HTP_REQUEST_TRAILER,
        mpm_ctx, NULL, "http_header (request)");
#endif
}
#endif

#ifdef KEYWORD_TOSERVER
static int InspectEngineHttpRequestHeader(ThreadVars *tv,
        DetectEngineCtx *de_ctx, DetectEngineThreadCtx *det_ctx,
        const Signature *s, const SigMatchData *smd,
        Flow *f, uint8_t flags, void *alstate, void *txv, uint64_t tx_id)
{
    htp_tx_t *tx = (htp_tx_t *)txv;
    if (tx->request_headers == NULL)
        goto end;

    htp_header_t *h = (htp_header_t *)htp_table_get_c(tx->request_headers,
                                                      HEADER_NAME);
    if (h == NULL || h->value == NULL) {
        SCLogDebug("HTTP UA header not present in this request");
        goto end;
    }

    const uint32_t buffer_len = bstr_len(h->value);
    uint8_t *buffer = bstr_ptr(h->value);

    if (buffer_len == 0)
        goto end;

    det_ctx->buffer_offset = 0;
    det_ctx->discontinue_matching = 0;
    det_ctx->inspection_recursion_counter = 0;
    int r = DetectEngineContentInspection(de_ctx, det_ctx, s, smd,
                                          f,
                                          buffer, buffer_len,
                                          0,
                                          DETECT_ENGINE_CONTENT_INSPECTION_MODE_STATE, NULL);
    if (r == 1)
        return DETECT_ENGINE_INSPECT_SIG_MATCH;

 end:
    if (AppLayerParserGetStateProgress(IPPROTO_TCP, ALPROTO_HTTP, tx, flags) > HTP_REQUEST_HEADERS)
        return DETECT_ENGINE_INSPECT_SIG_CANT_MATCH;
    else
        return DETECT_ENGINE_INSPECT_SIG_NO_MATCH;
}
#endif
#ifdef KEYWORD_TOCLIENT
static int InspectEngineHttpResponseHeader(ThreadVars *tv,
        DetectEngineCtx *de_ctx, DetectEngineThreadCtx *det_ctx,
        const Signature *s, const SigMatchData *smd,
        Flow *f, uint8_t flags, void *alstate, void *txv, uint64_t tx_id)
{
    htp_tx_t *tx = (htp_tx_t *)txv;
    if (tx->response_headers == NULL)
        goto end;

    htp_header_t *h = (htp_header_t *)htp_table_get_c(tx->response_headers,
                                                      HEADER_NAME);
    if (h == NULL || h->value == NULL) {
        SCLogDebug("HTTP header not present in this request");
        goto end;
    }

    const uint32_t buffer_len = bstr_len(h->value);
    uint8_t *buffer = bstr_ptr(h->value);

    if (buffer_len == 0)
        goto end;

    det_ctx->buffer_offset = 0;
    det_ctx->discontinue_matching = 0;
    det_ctx->inspection_recursion_counter = 0;
    int r = DetectEngineContentInspection(de_ctx, det_ctx, s, smd,
                                          f,
                                          buffer, buffer_len,
                                          0,
                                          DETECT_ENGINE_CONTENT_INSPECTION_MODE_STATE, NULL);
    if (r == 1)
        return DETECT_ENGINE_INSPECT_SIG_MATCH;

 end:
    if (AppLayerParserGetStateProgress(IPPROTO_TCP, ALPROTO_HTTP, tx, flags) > HTP_RESPONSE_HEADERS)
        return DETECT_ENGINE_INSPECT_SIG_CANT_MATCH;
    else
        return DETECT_ENGINE_INSPECT_SIG_NO_MATCH;
}
#endif

/**
 * \brief The setup function for the http_header keyword for a signature.
 *
 * \param de_ctx Pointer to the detection engine context.
 * \param s      Pointer to signature for the current Signature being parsed
 *               from the rules.
 * \param m      Pointer to the head of the SigMatchs for the current rule
 *               being parsed.
 * \param arg    Pointer to the string holding the keyword value.
 *
 * \retval  0 On success.
 * \retval -1 On failure.
 */
static int DetectHttpHeadersSetup(DetectEngineCtx *de_ctx, Signature *s, const char *arg)
{
    s->init_data->list = g_buffer_id;
    return 0;
}

static void DetectHttpHeadersSetupCallback(Signature *s)
{
    SCLogDebug("callback invoked by %u", s->id);
    s->mask |= SIG_MASK_REQUIRE_HTTP_STATE;
}

static void DetectHttpHeadersRegisterStub(void)
{
    sigmatch_table[KEYWORD_ID].name = KEYWORD_NAME;
    sigmatch_table[KEYWORD_ID].desc = KEYWORD_NAME " sticky buffer for the " BUFFER_DESC;
    sigmatch_table[KEYWORD_ID].url = DOC_URL DOC_VERSION "/rules/" KEYWORD_DOC;
    sigmatch_table[KEYWORD_ID].Setup = DetectHttpHeadersSetup;
    sigmatch_table[KEYWORD_ID].flags |= SIGMATCH_NOOPT;
#ifdef KEYWORD_TOSERVER
    DetectAppLayerMpmRegister(BUFFER_NAME, SIG_FLAG_TOSERVER, 2,
            PrefilterTxHttpRequestHeaderRegister);
#endif
#ifdef KEYWORD_TOCLIENT
    DetectAppLayerMpmRegister(BUFFER_NAME, SIG_FLAG_TOCLIENT, 2,
            PrefilterTxHttpResponseHeaderRegister);
#endif
#ifdef KEYWORD_TOSERVER
    DetectAppLayerInspectEngineRegister(BUFFER_NAME,
            ALPROTO_HTTP, SIG_FLAG_TOSERVER, HTP_REQUEST_HEADERS,
            InspectEngineHttpRequestHeader);
#endif
#ifdef KEYWORD_TOCLIENT
    DetectAppLayerInspectEngineRegister(BUFFER_NAME,
            ALPROTO_HTTP, SIG_FLAG_TOCLIENT, HTP_RESPONSE_HEADERS,
            InspectEngineHttpResponseHeader);
#endif

    DetectBufferTypeSetDescriptionByName(BUFFER_NAME, BUFFER_DESC);

    DetectBufferTypeRegisterSetupCallback(BUFFER_NAME,
            DetectHttpHeadersSetupCallback);

    g_buffer_id = DetectBufferTypeGetByName(BUFFER_NAME);
}
