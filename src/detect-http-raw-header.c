/* Copyright (C) 2007-2022 Open Information Security Foundation
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
 * \author Pablo Rincon <pablo.rincon.crespo@gmail.com>
 *
 * Implements support for http_raw_header keyword.
 */

#include "suricata-common.h"
#include "threads.h"
#include "decode.h"

#include "detect.h"
#include "detect-parse.h"
#include "detect-engine.h"
#include "detect-engine-mpm.h"
#include "detect-engine-prefilter.h"
#include "detect-content.h"

#include "flow.h"
#include "flow-var.h"
#include "flow-util.h"

#include "util-debug.h"

#include "app-layer.h"
#include "app-layer-parser.h"
#include "app-layer-htp.h"
#include "detect-http-raw-header.h"

static int DetectHttpRawHeaderSetup(DetectEngineCtx *, Signature *, const char *);
static int DetectHttpRawHeaderSetupSticky(DetectEngineCtx *de_ctx, Signature *s, const char *str);
#ifdef UNITTESTS
static void DetectHttpRawHeaderRegisterTests(void);
#endif
static bool DetectHttpRawHeaderValidateCallback(const Signature *s, const char **sigerror);
static int g_http_raw_header_buffer_id = 0;
static InspectionBuffer *GetData(DetectEngineThreadCtx *det_ctx,
        const DetectEngineTransforms *transforms, Flow *_f,
        const uint8_t flow_flags, void *txv, const int list_id);
static InspectionBuffer *GetData2(DetectEngineThreadCtx *det_ctx,
        const DetectEngineTransforms *transforms, Flow *_f, const uint8_t flow_flags, void *txv,
        const int list_id);

static int PrefilterMpmHttpHeaderRawRequestRegister(DetectEngineCtx *de_ctx,
        SigGroupHead *sgh, MpmCtx *mpm_ctx,
        const DetectBufferMpmRegistery *mpm_reg, int list_id);
static int PrefilterMpmHttpHeaderRawResponseRegister(DetectEngineCtx *de_ctx,
        SigGroupHead *sgh, MpmCtx *mpm_ctx,
        const DetectBufferMpmRegistery *mpm_reg, int list_id);

/**
 * \brief Registers the keyword handlers for the "http_raw_header" keyword.
 */
void DetectHttpRawHeaderRegister(void)
{
    /* http_raw_header content modifier */
    sigmatch_table[DETECT_AL_HTTP_RAW_HEADER].name = "http_raw_header";
    sigmatch_table[DETECT_AL_HTTP_RAW_HEADER].desc = "content modifier to match the raw HTTP header buffer";
    sigmatch_table[DETECT_AL_HTTP_RAW_HEADER].url = "/rules/http-keywords.html#http-header-and-http-raw-header";
    sigmatch_table[DETECT_AL_HTTP_RAW_HEADER].Setup = DetectHttpRawHeaderSetup;
#ifdef UNITTESTS
    sigmatch_table[DETECT_AL_HTTP_RAW_HEADER].RegisterTests = DetectHttpRawHeaderRegisterTests;
#endif
    sigmatch_table[DETECT_AL_HTTP_RAW_HEADER].flags |= SIGMATCH_NOOPT|SIGMATCH_INFO_CONTENT_MODIFIER;
    sigmatch_table[DETECT_AL_HTTP_RAW_HEADER].alternative = DETECT_HTTP_RAW_HEADER;

    /* http.header.raw sticky buffer */
    sigmatch_table[DETECT_HTTP_RAW_HEADER].name = "http.header.raw";
    sigmatch_table[DETECT_HTTP_RAW_HEADER].desc = "sticky buffer to match the raw HTTP header buffer";
    sigmatch_table[DETECT_HTTP_RAW_HEADER].url = "/rules/http-keywords.html#http-header-and-http-raw-header";
    sigmatch_table[DETECT_HTTP_RAW_HEADER].Setup = DetectHttpRawHeaderSetupSticky;
    sigmatch_table[DETECT_HTTP_RAW_HEADER].flags |= SIGMATCH_NOOPT|SIGMATCH_INFO_STICKY_BUFFER;

    DetectAppLayerInspectEngineRegister2("http_raw_header", ALPROTO_HTTP1, SIG_FLAG_TOSERVER,
            HTP_REQUEST_HEADERS + 1, DetectEngineInspectBufferGeneric, GetData);
    DetectAppLayerInspectEngineRegister2("http_raw_header", ALPROTO_HTTP1, SIG_FLAG_TOCLIENT,
            HTP_RESPONSE_HEADERS + 1, DetectEngineInspectBufferGeneric, GetData);

    DetectAppLayerMpmRegister2("http_raw_header", SIG_FLAG_TOSERVER, 2,
            PrefilterMpmHttpHeaderRawRequestRegister, NULL, ALPROTO_HTTP1,
            0); /* progress handled in register */
    DetectAppLayerMpmRegister2("http_raw_header", SIG_FLAG_TOCLIENT, 2,
            PrefilterMpmHttpHeaderRawResponseRegister, NULL, ALPROTO_HTTP1,
            0); /* progress handled in register */

    DetectAppLayerInspectEngineRegister2("http_raw_header", ALPROTO_HTTP2, SIG_FLAG_TOSERVER,
            HTTP2StateDataClient, DetectEngineInspectBufferGeneric, GetData2);
    DetectAppLayerInspectEngineRegister2("http_raw_header", ALPROTO_HTTP2, SIG_FLAG_TOCLIENT,
            HTTP2StateDataServer, DetectEngineInspectBufferGeneric, GetData2);

    DetectAppLayerMpmRegister2("http_raw_header", SIG_FLAG_TOSERVER, 2, PrefilterGenericMpmRegister,
            GetData2, ALPROTO_HTTP2, HTTP2StateDataClient);
    DetectAppLayerMpmRegister2("http_raw_header", SIG_FLAG_TOCLIENT, 2, PrefilterGenericMpmRegister,
            GetData2, ALPROTO_HTTP2, HTTP2StateDataServer);

    DetectBufferTypeSetDescriptionByName("http_raw_header",
            "raw http headers");

    DetectBufferTypeRegisterValidateCallback("http_raw_header",
            DetectHttpRawHeaderValidateCallback);

    g_http_raw_header_buffer_id = DetectBufferTypeGetByName("http_raw_header");
}

/**
 * \brief The setup function for the http_raw_header keyword for a signature.
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
int DetectHttpRawHeaderSetup(DetectEngineCtx *de_ctx, Signature *s, const char *arg)
{
    return DetectEngineContentModifierBufferSetup(
            de_ctx, s, arg, DETECT_AL_HTTP_RAW_HEADER, g_http_raw_header_buffer_id, ALPROTO_HTTP1);
}

/**
 * \brief this function setup the http.header.raw keyword used in the rule
 *
 * \param de_ctx   Pointer to the Detection Engine Context
 * \param s        Pointer to the Signature to which the current keyword belongs
 * \param str      Should hold an empty string always
 *
 * \retval 0       On success
 */
static int DetectHttpRawHeaderSetupSticky(DetectEngineCtx *de_ctx, Signature *s, const char *str)
{
    if (DetectBufferSetActiveList(s, g_http_raw_header_buffer_id) < 0)
        return -1;
    if (DetectSignatureSetAppProto(s, ALPROTO_HTTP) < 0)
        return -1;
    return 0;
}

static bool DetectHttpRawHeaderValidateCallback(const Signature *s, const char **sigerror)
{
    if ((s->flags & (SIG_FLAG_TOCLIENT|SIG_FLAG_TOSERVER)) == (SIG_FLAG_TOCLIENT|SIG_FLAG_TOSERVER)) {
        *sigerror = "http_raw_header signature "
                "without a flow direction. Use flow:to_server for "
                "inspecting request headers or flow:to_client for "
                "inspecting response headers.";

        SCLogError(SC_ERR_INVALID_SIGNATURE, "%s", *sigerror);
        SCReturnInt(false);
    }
    return true;
}

static InspectionBuffer *GetData(DetectEngineThreadCtx *det_ctx,
        const DetectEngineTransforms *transforms, Flow *_f,
        const uint8_t flow_flags, void *txv, const int list_id)
{
    InspectionBuffer *buffer = InspectionBufferGet(det_ctx, list_id);
    if (buffer->inspect == NULL) {
        htp_tx_t *tx = (htp_tx_t *)txv;

        HtpTxUserData *tx_ud = htp_tx_get_user_data(tx);
        if (tx_ud == NULL)
            return NULL;

        const bool ts = ((flow_flags & STREAM_TOSERVER) != 0);
        const uint8_t *data = ts ?
            tx_ud->request_headers_raw : tx_ud->response_headers_raw;
        if (data == NULL)
            return NULL;
        const uint32_t data_len = ts ?
            tx_ud->request_headers_raw_len : tx_ud->response_headers_raw_len;

        InspectionBufferSetup(det_ctx, list_id, buffer, data, data_len);
        InspectionBufferApplyTransforms(buffer, transforms);
    }

    return buffer;
}

static InspectionBuffer *GetData2(DetectEngineThreadCtx *det_ctx,
        const DetectEngineTransforms *transforms, Flow *_f, const uint8_t flow_flags, void *txv,
        const int list_id)
{
    InspectionBuffer *buffer = InspectionBufferGet(det_ctx, list_id);
    if (buffer->inspect == NULL) {
        uint32_t b_len = 0;
        const uint8_t *b = NULL;

        if (rs_http2_tx_get_headers_raw(txv, flow_flags, &b, &b_len) != 1)
            return NULL;
        if (b == NULL || b_len == 0)
            return NULL;

        InspectionBufferSetup(det_ctx, list_id, buffer, b, b_len);
        InspectionBufferApplyTransforms(buffer, transforms);
    }

    return buffer;
}

typedef struct PrefilterMpmHttpHeaderRawCtx {
    int list_id;
    const MpmCtx *mpm_ctx;
    const DetectEngineTransforms *transforms;
} PrefilterMpmHttpHeaderRawCtx;

/** \brief Generic Mpm prefilter callback
 *
 *  \param det_ctx detection engine thread ctx
 *  \param p packet to inspect
 *  \param f flow to inspect
 *  \param txv tx to inspect
 *  \param pectx inspection context
 */
static void PrefilterMpmHttpHeaderRaw(DetectEngineThreadCtx *det_ctx,
        const void *pectx,
        Packet *p, Flow *f, void *txv,
        const uint64_t idx, const uint8_t flags)
{
    SCEnter();

    const PrefilterMpmHttpHeaderRawCtx *ctx = pectx;
    const MpmCtx *mpm_ctx = ctx->mpm_ctx;
    SCLogDebug("running on list %d", ctx->list_id);

    const int list_id = ctx->list_id;

    InspectionBuffer *buffer = GetData(det_ctx, ctx->transforms, f,
            flags, txv, list_id);
    if (buffer == NULL)
        return;

    const uint32_t data_len = buffer->inspect_len;
    const uint8_t *data = buffer->inspect;

    SCLogDebug("mpm'ing buffer:");
    //PrintRawDataFp(stdout, data, data_len);

    if (data != NULL && data_len >= mpm_ctx->minlen) {
        (void)mpm_table[mpm_ctx->mpm_type].Search(mpm_ctx,
                &det_ctx->mtcu, &det_ctx->pmq, data, data_len);
    }
}

static void PrefilterMpmHttpTrailerRaw(DetectEngineThreadCtx *det_ctx,
        const void *pectx,
        Packet *p, Flow *f, void *txv,
        const uint64_t idx, const uint8_t flags)
{
    SCEnter();

    htp_tx_t *tx = txv;
    const HtpTxUserData *htud = (const HtpTxUserData *)htp_tx_get_user_data(tx);
    /* if the request wasn't flagged as having a trailer, we skip */
    if (htud && (
            ((flags & STREAM_TOSERVER) && !htud->request_has_trailers) ||
            ((flags & STREAM_TOCLIENT) && !htud->response_has_trailers))) {
        SCReturn;
    }
    PrefilterMpmHttpHeaderRaw(det_ctx, pectx, p, f, txv, idx, flags);
    SCReturn;
}

static void PrefilterMpmHttpHeaderRawFree(void *ptr)
{
    SCFree(ptr);
}

static int PrefilterMpmHttpHeaderRawRequestRegister(DetectEngineCtx *de_ctx,
        SigGroupHead *sgh, MpmCtx *mpm_ctx,
        const DetectBufferMpmRegistery *mpm_reg, int list_id)
{
    SCEnter();

    /* header */
    PrefilterMpmHttpHeaderRawCtx *pectx = SCCalloc(1, sizeof(*pectx));
    if (pectx == NULL)
        return -1;
    pectx->list_id = list_id;
    pectx->mpm_ctx = mpm_ctx;
    pectx->transforms = &mpm_reg->transforms;

    int r = PrefilterAppendTxEngine(de_ctx, sgh, PrefilterMpmHttpHeaderRaw,
            mpm_reg->app_v2.alproto, HTP_REQUEST_HEADERS+1,
            pectx, PrefilterMpmHttpHeaderRawFree, mpm_reg->pname);
    if (r != 0) {
        SCFree(pectx);
        return r;
    }

    /* trailer */
    pectx = SCCalloc(1, sizeof(*pectx));
    if (pectx == NULL)
        return -1;
    pectx->list_id = list_id;
    pectx->mpm_ctx = mpm_ctx;
    pectx->transforms = &mpm_reg->transforms;

    r = PrefilterAppendTxEngine(de_ctx, sgh, PrefilterMpmHttpTrailerRaw,
            mpm_reg->app_v2.alproto, HTP_REQUEST_TRAILER+1,
            pectx, PrefilterMpmHttpHeaderRawFree, mpm_reg->pname);
    if (r != 0) {
        SCFree(pectx);
    }
    return r;
}

static int PrefilterMpmHttpHeaderRawResponseRegister(DetectEngineCtx *de_ctx,
        SigGroupHead *sgh, MpmCtx *mpm_ctx,
        const DetectBufferMpmRegistery *mpm_reg, int list_id)
{
    SCEnter();

    /* header */
    PrefilterMpmHttpHeaderRawCtx *pectx = SCCalloc(1, sizeof(*pectx));
    if (pectx == NULL)
        return -1;
    pectx->list_id = list_id;
    pectx->mpm_ctx = mpm_ctx;
    pectx->transforms = &mpm_reg->transforms;

    int r = PrefilterAppendTxEngine(de_ctx, sgh, PrefilterMpmHttpHeaderRaw,
            mpm_reg->app_v2.alproto, HTP_RESPONSE_HEADERS,
            pectx, PrefilterMpmHttpHeaderRawFree, mpm_reg->pname);
    if (r != 0) {
        SCFree(pectx);
        return r;
    }

    /* trailer */
    pectx = SCCalloc(1, sizeof(*pectx));
    if (pectx == NULL)
        return -1;
    pectx->list_id = list_id;
    pectx->mpm_ctx = mpm_ctx;
    pectx->transforms = &mpm_reg->transforms;

    r = PrefilterAppendTxEngine(de_ctx, sgh, PrefilterMpmHttpTrailerRaw,
            mpm_reg->app_v2.alproto, HTP_RESPONSE_TRAILER,
            pectx, PrefilterMpmHttpHeaderRawFree, mpm_reg->pname);
    if (r != 0) {
        SCFree(pectx);
    }
    return r;
}

/************************************Unittests*********************************/

#ifdef UNITTESTS
#include "tests/detect-http-raw-header.c"
#endif

/**
 * @}
 */
