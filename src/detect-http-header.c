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
 * Implements support for http_header keyword.
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

#include "util-debug.h"
#include "util-print.h"
#include "util-memcmp.h"
#include "util-profiling.h"

#include "app-layer.h"
#include "app-layer-parser.h"

#include "app-layer-htp.h"
#include "detect-http-header.h"
#include "detect-http-header-common.h"

static int DetectHttpHeaderSetup(DetectEngineCtx *, Signature *, const char *);
#ifdef UNITTESTS
static void DetectHttpHeaderRegisterTests(void);
#endif
static int g_http_header_buffer_id = 0;
static int g_keyword_thread_id = 0;

#define BUFFER_SIZE_STEP    1024
static HttpHeaderThreadDataConfig g_td_config = { BUFFER_SIZE_STEP };

static uint8_t *GetBufferForTX(
        htp_tx_t *tx, DetectEngineThreadCtx *det_ctx, Flow *f, uint8_t flags, uint32_t *buffer_len)
{
    *buffer_len = 0;

    HttpHeaderThreadData *hdr_td = NULL;
    HttpHeaderBuffer *buf =
            HttpHeaderGetBufferSpace(det_ctx, f, flags, g_keyword_thread_id, &hdr_td);
    if (unlikely(buf == NULL)) {
        return NULL;
    }

    htp_table_t *headers;
    if (flags & STREAM_TOSERVER) {
        if (AppLayerParserGetStateProgress(IPPROTO_TCP, ALPROTO_HTTP1, tx, flags) <=
                HTP_REQUEST_HEADERS)
            return NULL;
        headers = tx->request_headers;
    } else {
        if (AppLayerParserGetStateProgress(IPPROTO_TCP, ALPROTO_HTTP1, tx, flags) <=
                HTP_RESPONSE_HEADERS)
            return NULL;
        headers = tx->response_headers;
    }
    if (headers == NULL)
        return NULL;

    size_t i = 0;
    size_t no_of_headers = htp_table_size(headers);
    for (; i < no_of_headers; i++) {
        htp_header_t *h = htp_table_get_index(headers, i, NULL);
        size_t size1 = bstr_size(h->name);
        size_t size2 = bstr_size(h->value);

        if (flags & STREAM_TOSERVER) {
            if (size1 == 6 &&
                SCMemcmpLowercase("cookie", bstr_ptr(h->name), 6) == 0) {
                continue;
            }
        } else {
            if (size1 == 10 &&
                SCMemcmpLowercase("set-cookie", bstr_ptr(h->name), 10) == 0) {
                continue;
            }
        }

        size_t size = size1 + size2 + 4;
#if 0
        if (i + 1 == no_of_headers)
            size += 2;
#endif
        if (size + buf->len > buf->size) {
            if (HttpHeaderExpandBuffer(hdr_td, buf, size) != 0) {
                return NULL;
            }
        }

        memcpy(buf->buffer + buf->len, bstr_ptr(h->name), bstr_size(h->name));
        buf->len += bstr_size(h->name);
        buf->buffer[buf->len++] = ':';
        buf->buffer[buf->len++] = ' ';
        memcpy(buf->buffer + buf->len, bstr_ptr(h->value), bstr_size(h->value));
        buf->len += bstr_size(h->value);
        buf->buffer[buf->len++] = '\r';
        buf->buffer[buf->len++] = '\n';
#if 0 // looks like this breaks existing rules
        if (i + 1 == no_of_headers) {
            buf->buffer[buf->len++] = '\r';
            buf->buffer[buf->len++] = '\n';
        }
#endif
    }

    *buffer_len = buf->len;
    return buf->buffer;
}

static InspectionBuffer *GetBuffer2ForTX(DetectEngineThreadCtx *det_ctx,
        const DetectEngineTransforms *transforms, Flow *_f, const uint8_t flow_flags, void *txv,
        const int list_id)
{
    InspectionBuffer *buffer = InspectionBufferGet(det_ctx, list_id);
    if (buffer->inspect == NULL) {
        uint32_t b_len = 0;
        const uint8_t *b = NULL;

        if (rs_http2_tx_get_headers(txv, flow_flags, &b, &b_len) != 1)
            return NULL;
        if (b == NULL || b_len == 0)
            return NULL;

        InspectionBufferSetup(det_ctx, list_id, buffer, b, b_len);
        InspectionBufferApplyTransforms(buffer, transforms);
    }

    return buffer;
}

/** \internal
 *  \brief custom inspect function to utilize the cached headers
 */
static uint8_t DetectEngineInspectBufferHttpHeader(DetectEngineCtx *de_ctx,
        DetectEngineThreadCtx *det_ctx, const DetectEngineAppInspectionEngine *engine,
        const Signature *s, Flow *f, uint8_t flags, void *alstate, void *txv, uint64_t tx_id)
{
    SCEnter();

    const int list_id = engine->sm_list;
    InspectionBuffer *buffer = InspectionBufferGet(det_ctx, list_id);
    if (buffer->inspect == NULL) {
        SCLogDebug("setting up inspect buffer %d", list_id);

        /* if prefilter didn't already run, we need to consider transformations */
        const DetectEngineTransforms *transforms = NULL;
        if (!engine->mpm) {
            transforms = engine->v2.transforms;
        }

        uint32_t rawdata_len = 0;
        uint8_t *rawdata = GetBufferForTX(txv, det_ctx, f, flags, &rawdata_len);
        if (rawdata_len == 0) {
            SCLogDebug("no data");
            goto end;
        }
        /* setup buffer and apply transforms */
        InspectionBufferSetup(det_ctx, list_id, buffer, rawdata, rawdata_len);
        InspectionBufferApplyTransforms(buffer, transforms);
    }

    const uint32_t data_len = buffer->inspect_len;
    const uint8_t *data = buffer->inspect;
    const uint64_t offset = buffer->inspect_offset;

    /* Inspect all the uricontents fetched on each
     * transaction at the app layer */
    const bool match = DetectEngineContentInspection(de_ctx, det_ctx, s, engine->smd, NULL, f,
            (uint8_t *)data, data_len, offset, DETECT_CI_FLAGS_SINGLE,
            DETECT_ENGINE_CONTENT_INSPECTION_MODE_STATE);
    if (match) {
        return DETECT_ENGINE_INSPECT_SIG_MATCH;
    }
end:
    if (flags & STREAM_TOSERVER) {
        if (AppLayerParserGetStateProgress(IPPROTO_TCP, ALPROTO_HTTP1, txv, flags) >
                HTP_REQUEST_HEADERS)
            return DETECT_ENGINE_INSPECT_SIG_CANT_MATCH;
    } else {
        if (AppLayerParserGetStateProgress(IPPROTO_TCP, ALPROTO_HTTP1, txv, flags) >
                HTP_RESPONSE_HEADERS)
            return DETECT_ENGINE_INSPECT_SIG_CANT_MATCH;
    }
    return DETECT_ENGINE_INSPECT_SIG_NO_MATCH;
}

typedef struct PrefilterMpmHttpHeaderCtx {
    int list_id;
    const MpmCtx *mpm_ctx;
    const DetectEngineTransforms *transforms;
} PrefilterMpmHttpHeaderCtx;

/** \brief Generic Mpm prefilter callback
 *
 *  \param det_ctx detection engine thread ctx
 *  \param p packet to inspect
 *  \param f flow to inspect
 *  \param txv tx to inspect
 *  \param pectx inspection context
 */
static void PrefilterMpmHttpHeader(DetectEngineThreadCtx *det_ctx, const void *pectx, Packet *p,
        Flow *f, void *txv, const uint64_t idx, const AppLayerTxData *_txd, const uint8_t flags)
{
    SCEnter();

    const PrefilterMpmHttpHeaderCtx *ctx = pectx;
    const MpmCtx *mpm_ctx = ctx->mpm_ctx;
    SCLogDebug("running on list %d", ctx->list_id);

    const int list_id = ctx->list_id;
    InspectionBuffer *buffer = InspectionBufferGet(det_ctx, list_id);
    if (buffer->inspect == NULL) {
        uint32_t rawdata_len = 0;
        uint8_t *rawdata = GetBufferForTX(txv, det_ctx, f, flags, &rawdata_len);
        if (rawdata_len == 0)
            return;

        /* setup buffer and apply transforms */
        InspectionBufferSetup(det_ctx, list_id, buffer, rawdata, rawdata_len);
        InspectionBufferApplyTransforms(buffer, ctx->transforms);
    }

    const uint32_t data_len = buffer->inspect_len;
    const uint8_t *data = buffer->inspect;

    SCLogDebug("mpm'ing buffer:");
    //PrintRawDataFp(stdout, data, data_len);

    if (data != NULL && data_len >= mpm_ctx->minlen) {
        (void)mpm_table[mpm_ctx->mpm_type].Search(
                mpm_ctx, &det_ctx->mtc, &det_ctx->pmq, data, data_len);
        PREFILTER_PROFILING_ADD_BYTES(det_ctx, data_len);
    }
}

static void PrefilterMpmHttpTrailer(DetectEngineThreadCtx *det_ctx, const void *pectx, Packet *p,
        Flow *f, void *txv, const uint64_t idx, const AppLayerTxData *_txd, const uint8_t flags)
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
    PrefilterMpmHttpHeader(det_ctx, pectx, p, f, txv, idx, _txd, flags);
    SCReturn;
}

static void PrefilterMpmHttpHeaderFree(void *ptr)
{
    SCFree(ptr);
}

static int PrefilterMpmHttpHeaderRequestRegister(DetectEngineCtx *de_ctx, SigGroupHead *sgh,
        MpmCtx *mpm_ctx, const DetectBufferMpmRegistry *mpm_reg, int list_id)
{
    SCEnter();

    /* header */
    PrefilterMpmHttpHeaderCtx *pectx = SCCalloc(1, sizeof(*pectx));
    if (pectx == NULL)
        return -1;
    pectx->list_id = list_id;
    pectx->mpm_ctx = mpm_ctx;
    pectx->transforms = &mpm_reg->transforms;

    int r = PrefilterAppendTxEngine(de_ctx, sgh, PrefilterMpmHttpHeader,
            mpm_reg->app_v2.alproto, HTP_REQUEST_HEADERS,
            pectx, PrefilterMpmHttpHeaderFree, mpm_reg->pname);
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

    r = PrefilterAppendTxEngine(de_ctx, sgh, PrefilterMpmHttpTrailer,
            mpm_reg->app_v2.alproto, HTP_REQUEST_TRAILER,
            pectx, PrefilterMpmHttpHeaderFree, mpm_reg->pname);
    if (r != 0) {
        SCFree(pectx);
    }
    return r;
}

static int PrefilterMpmHttpHeaderResponseRegister(DetectEngineCtx *de_ctx, SigGroupHead *sgh,
        MpmCtx *mpm_ctx, const DetectBufferMpmRegistry *mpm_reg, int list_id)
{
    SCEnter();

    /* header */
    PrefilterMpmHttpHeaderCtx *pectx = SCCalloc(1, sizeof(*pectx));
    if (pectx == NULL)
        return -1;
    pectx->list_id = list_id;
    pectx->mpm_ctx = mpm_ctx;
    pectx->transforms = &mpm_reg->transforms;

    int r = PrefilterAppendTxEngine(de_ctx, sgh, PrefilterMpmHttpHeader,
            mpm_reg->app_v2.alproto, HTP_RESPONSE_HEADERS,
            pectx, PrefilterMpmHttpHeaderFree, mpm_reg->pname);
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

    r = PrefilterAppendTxEngine(de_ctx, sgh, PrefilterMpmHttpTrailer,
            mpm_reg->app_v2.alproto, HTP_RESPONSE_TRAILER,
            pectx, PrefilterMpmHttpHeaderFree, mpm_reg->pname);
    if (r != 0) {
        SCFree(pectx);
    }
    return r;
}

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
static int DetectHttpHeaderSetup(DetectEngineCtx *de_ctx, Signature *s, const char *arg)
{
    return DetectEngineContentModifierBufferSetup(
            de_ctx, s, arg, DETECT_AL_HTTP_HEADER, g_http_header_buffer_id, ALPROTO_HTTP1);
}

/**
 * \brief this function setup the http.header keyword used in the rule
 *
 * \param de_ctx   Pointer to the Detection Engine Context
 * \param s        Pointer to the Signature to which the current keyword belongs
 * \param str      Should hold an empty string always
 *
 * \retval 0       On success
 */
static int DetectHttpHeaderSetupSticky(DetectEngineCtx *de_ctx, Signature *s, const char *str)
{
    if (DetectBufferSetActiveList(de_ctx, s, g_http_header_buffer_id) < 0)
        return -1;
    if (DetectSignatureSetAppProto(s, ALPROTO_HTTP) < 0)
        return -1;
    return 0;
}

/**
 * \brief Registers the keyword handlers for the "http_header" keyword.
 */
void DetectHttpHeaderRegister(void)
{
    /* http_header content modifier */
    sigmatch_table[DETECT_AL_HTTP_HEADER].name = "http_header";
    sigmatch_table[DETECT_AL_HTTP_HEADER].desc = "content modifier to match only on the HTTP header-buffer";
    sigmatch_table[DETECT_AL_HTTP_HEADER].url = "/rules/http-keywords.html#http-header-and-http-raw-header";
    sigmatch_table[DETECT_AL_HTTP_HEADER].Setup = DetectHttpHeaderSetup;
#ifdef UNITTESTS
    sigmatch_table[DETECT_AL_HTTP_HEADER].RegisterTests = DetectHttpHeaderRegisterTests;
#endif
    sigmatch_table[DETECT_AL_HTTP_HEADER].flags |= SIGMATCH_NOOPT ;
    sigmatch_table[DETECT_AL_HTTP_HEADER].flags |= SIGMATCH_INFO_CONTENT_MODIFIER;
    sigmatch_table[DETECT_AL_HTTP_HEADER].alternative = DETECT_HTTP_HEADER;

    /* http.header sticky buffer */
    sigmatch_table[DETECT_HTTP_HEADER].name = "http.header";
    sigmatch_table[DETECT_HTTP_HEADER].desc = "sticky buffer to match on the normalized HTTP header-buffer";
    sigmatch_table[DETECT_HTTP_HEADER].url = "/rules/http-keywords.html#http-header-and-http-raw-header";
    sigmatch_table[DETECT_HTTP_HEADER].Setup = DetectHttpHeaderSetupSticky;
    sigmatch_table[DETECT_HTTP_HEADER].flags |= SIGMATCH_NOOPT;
    sigmatch_table[DETECT_HTTP_HEADER].flags |= SIGMATCH_INFO_STICKY_BUFFER;

    DetectAppLayerInspectEngineRegister("http_header", ALPROTO_HTTP1, SIG_FLAG_TOSERVER,
            HTP_REQUEST_HEADERS, DetectEngineInspectBufferHttpHeader, NULL);
    DetectAppLayerMpmRegister("http_header", SIG_FLAG_TOSERVER, 2,
            PrefilterMpmHttpHeaderRequestRegister, NULL, ALPROTO_HTTP1,
            0); /* not used, registered twice: HEADERS/TRAILER */

    DetectAppLayerInspectEngineRegister("http_header", ALPROTO_HTTP1, SIG_FLAG_TOCLIENT,
            HTP_RESPONSE_HEADERS, DetectEngineInspectBufferHttpHeader, NULL);
    DetectAppLayerMpmRegister("http_header", SIG_FLAG_TOCLIENT, 2,
            PrefilterMpmHttpHeaderResponseRegister, NULL, ALPROTO_HTTP1,
            0); /* not used, registered twice: HEADERS/TRAILER */

    DetectAppLayerInspectEngineRegister("http_header", ALPROTO_HTTP2, SIG_FLAG_TOSERVER,
            HTTP2StateDataClient, DetectEngineInspectBufferGeneric, GetBuffer2ForTX);
    DetectAppLayerMpmRegister("http_header", SIG_FLAG_TOSERVER, 2, PrefilterGenericMpmRegister,
            GetBuffer2ForTX, ALPROTO_HTTP2, HTTP2StateDataClient);

    DetectAppLayerInspectEngineRegister("http_header", ALPROTO_HTTP2, SIG_FLAG_TOCLIENT,
            HTTP2StateDataServer, DetectEngineInspectBufferGeneric, GetBuffer2ForTX);
    DetectAppLayerMpmRegister("http_header", SIG_FLAG_TOCLIENT, 2, PrefilterGenericMpmRegister,
            GetBuffer2ForTX, ALPROTO_HTTP2, HTTP2StateDataServer);

    DetectBufferTypeSetDescriptionByName("http_header",
            "http headers");

    g_http_header_buffer_id = DetectBufferTypeGetByName("http_header");

    g_keyword_thread_id = DetectRegisterThreadCtxGlobalFuncs("http_header",
            HttpHeaderThreadDataInit, &g_td_config, HttpHeaderThreadDataFree);
}

static int g_http_request_header_buffer_id = 0;
static int g_http_response_header_buffer_id = 0;

static InspectionBuffer *GetHttp2HeaderData(DetectEngineThreadCtx *det_ctx, const uint8_t flags,
        const DetectEngineTransforms *transforms, Flow *_f, const struct MpmListIdDataArgs *cbdata,
        int list_id)
{
    SCEnter();

    InspectionBuffer *buffer =
            InspectionBufferMultipleForListGet(det_ctx, list_id, cbdata->local_id);
    if (buffer == NULL)
        return NULL;
    if (buffer->initialized)
        return buffer;

    uint32_t b_len = 0;
    const uint8_t *b = NULL;

    if (rs_http2_tx_get_header(cbdata->txv, flags, cbdata->local_id, &b, &b_len) != 1) {
        InspectionBufferSetupMultiEmpty(buffer);
        return NULL;
    }
    if (b == NULL || b_len == 0) {
        InspectionBufferSetupMultiEmpty(buffer);
        return NULL;
    }

    InspectionBufferSetupMulti(buffer, transforms, b, b_len);

    SCReturnPtr(buffer, "InspectionBuffer");
}

static void PrefilterTxHttp2Header(DetectEngineThreadCtx *det_ctx, const void *pectx, Packet *p,
        Flow *f, void *txv, const uint64_t idx, const AppLayerTxData *_txd, const uint8_t flags)
{
    SCEnter();

    const PrefilterMpmListId *ctx = (const PrefilterMpmListId *)pectx;
    const MpmCtx *mpm_ctx = ctx->mpm_ctx;
    const int list_id = ctx->list_id;

    uint32_t local_id = 0;

    while (1) {
        // loop until we get a NULL

        struct MpmListIdDataArgs cbdata = { local_id, txv };
        InspectionBuffer *buffer =
                GetHttp2HeaderData(det_ctx, flags, ctx->transforms, f, &cbdata, list_id);
        if (buffer == NULL)
            break;

        if (buffer->inspect_len >= mpm_ctx->minlen) {
            (void)mpm_table[mpm_ctx->mpm_type].Search(
                    mpm_ctx, &det_ctx->mtc, &det_ctx->pmq, buffer->inspect, buffer->inspect_len);
            PREFILTER_PROFILING_ADD_BYTES(det_ctx, buffer->inspect_len);
        }

        local_id++;
    }
}

static uint8_t DetectEngineInspectHttp2Header(DetectEngineCtx *de_ctx,
        DetectEngineThreadCtx *det_ctx, const DetectEngineAppInspectionEngine *engine,
        const Signature *s, Flow *f, uint8_t flags, void *alstate, void *txv, uint64_t tx_id)
{
    uint32_t local_id = 0;

    const DetectEngineTransforms *transforms = NULL;
    if (!engine->mpm) {
        transforms = engine->v2.transforms;
    }

    while (1) {
        struct MpmListIdDataArgs cbdata = {
            local_id,
            txv,
        };
        InspectionBuffer *buffer =
                GetHttp2HeaderData(det_ctx, flags, transforms, f, &cbdata, engine->sm_list);
        if (buffer == NULL || buffer->inspect == NULL)
            break;

        const bool match = DetectEngineContentInspection(de_ctx, det_ctx, s, engine->smd, NULL, f,
                buffer->inspect, buffer->inspect_len, buffer->inspect_offset,
                DETECT_CI_FLAGS_SINGLE, DETECT_ENGINE_CONTENT_INSPECTION_MODE_STATE);
        if (match) {
            return DETECT_ENGINE_INSPECT_SIG_MATCH;
        }
        local_id++;
    }

    return DETECT_ENGINE_INSPECT_SIG_NO_MATCH;
}

static int PrefilterMpmHttp2HeaderRegister(DetectEngineCtx *de_ctx, SigGroupHead *sgh,
        MpmCtx *mpm_ctx, const DetectBufferMpmRegistry *mpm_reg, int list_id)
{
    PrefilterMpmListId *pectx = SCCalloc(1, sizeof(*pectx));
    if (pectx == NULL)
        return -1;
    pectx->list_id = list_id;
    pectx->mpm_ctx = mpm_ctx;
    pectx->transforms = &mpm_reg->transforms;

    return PrefilterAppendTxEngine(de_ctx, sgh, PrefilterTxHttp2Header, mpm_reg->app_v2.alproto,
            mpm_reg->app_v2.tx_min_progress, pectx, PrefilterMpmHttpHeaderFree, mpm_reg->name);
}

static InspectionBuffer *GetHttp1HeaderData(DetectEngineThreadCtx *det_ctx, const uint8_t flags,
        const DetectEngineTransforms *transforms, Flow *f, const struct MpmListIdDataArgs *cbdata,
        int list_id)
{
    SCEnter();

    InspectionBuffer *buffer =
            InspectionBufferMultipleForListGet(det_ctx, list_id, cbdata->local_id);
    if (buffer == NULL)
        return NULL;
    if (buffer->initialized)
        return buffer;

    HttpHeaderThreadData *hdr_td = NULL;
    HttpHeaderBuffer *buf =
            HttpHeaderGetBufferSpace(det_ctx, f, flags, g_keyword_thread_id, &hdr_td);
    if (unlikely(buf == NULL)) {
        return NULL;
    }

    htp_tx_t *tx = (htp_tx_t *)cbdata->txv;
    htp_table_t *headers;
    if (flags & STREAM_TOSERVER) {
        headers = tx->request_headers;
    } else {
        headers = tx->response_headers;
    }
    if (cbdata->local_id < htp_table_size(headers)) {
        htp_header_t *h = htp_table_get_index(headers, cbdata->local_id, NULL);
        size_t size1 = bstr_size(h->name);
        size_t size2 = bstr_size(h->value);
        size_t b_len = size1 + 2 + size2;
        if (b_len > buf->size) {
            if (HttpHeaderExpandBuffer(hdr_td, buf, b_len) != 0) {
                return NULL;
            }
        }
        memcpy(buf->buffer, bstr_ptr(h->name), bstr_size(h->name));
        buf->buffer[size1] = ':';
        buf->buffer[size1 + 1] = ' ';
        memcpy(buf->buffer + size1 + 2, bstr_ptr(h->value), bstr_size(h->value));
        buf->len = b_len;
    } else {
        InspectionBufferSetupMultiEmpty(buffer);
        return NULL;
    }
    if (buf->len == 0) {
        InspectionBufferSetupMultiEmpty(buffer);
        return NULL;
    }

    InspectionBufferSetupMulti(buffer, transforms, buf->buffer, buf->len);

    SCReturnPtr(buffer, "InspectionBuffer");
}

static void PrefilterTxHttp1Header(DetectEngineThreadCtx *det_ctx, const void *pectx, Packet *p,
        Flow *f, void *txv, const uint64_t idx, const AppLayerTxData *_txd, const uint8_t flags)
{
    SCEnter();

    const PrefilterMpmListId *ctx = (const PrefilterMpmListId *)pectx;
    const MpmCtx *mpm_ctx = ctx->mpm_ctx;
    const int list_id = ctx->list_id;

    uint32_t local_id = 0;

    while (1) {
        // loop until we get a NULL

        struct MpmListIdDataArgs cbdata = { local_id, txv };
        InspectionBuffer *buffer =
                GetHttp1HeaderData(det_ctx, flags, ctx->transforms, f, &cbdata, list_id);
        if (buffer == NULL)
            break;

        if (buffer->inspect_len >= mpm_ctx->minlen) {
            (void)mpm_table[mpm_ctx->mpm_type].Search(
                    mpm_ctx, &det_ctx->mtc, &det_ctx->pmq, buffer->inspect, buffer->inspect_len);
            PREFILTER_PROFILING_ADD_BYTES(det_ctx, buffer->inspect_len);
        }

        local_id++;
    }
}

static int PrefilterMpmHttp1HeaderRegister(DetectEngineCtx *de_ctx, SigGroupHead *sgh,
        MpmCtx *mpm_ctx, const DetectBufferMpmRegistry *mpm_reg, int list_id)
{
    PrefilterMpmListId *pectx = SCCalloc(1, sizeof(*pectx));
    if (pectx == NULL)
        return -1;
    pectx->list_id = list_id;
    pectx->mpm_ctx = mpm_ctx;
    pectx->transforms = &mpm_reg->transforms;

    return PrefilterAppendTxEngine(de_ctx, sgh, PrefilterTxHttp1Header, mpm_reg->app_v2.alproto,
            mpm_reg->app_v2.tx_min_progress, pectx, PrefilterMpmHttpHeaderFree, mpm_reg->name);
}

static uint8_t DetectEngineInspectHttp1Header(DetectEngineCtx *de_ctx,
        DetectEngineThreadCtx *det_ctx, const DetectEngineAppInspectionEngine *engine,
        const Signature *s, Flow *f, uint8_t flags, void *alstate, void *txv, uint64_t tx_id)
{
    uint32_t local_id = 0;

    const DetectEngineTransforms *transforms = NULL;
    if (!engine->mpm) {
        transforms = engine->v2.transforms;
    }

    while (1) {
        struct MpmListIdDataArgs cbdata = {
            local_id,
            txv,
        };
        InspectionBuffer *buffer =
                GetHttp1HeaderData(det_ctx, flags, transforms, f, &cbdata, engine->sm_list);
        if (buffer == NULL || buffer->inspect == NULL)
            break;

        const bool match = DetectEngineContentInspection(de_ctx, det_ctx, s, engine->smd, NULL, f,
                (uint8_t *)buffer->inspect, buffer->inspect_len, buffer->inspect_offset,
                DETECT_CI_FLAGS_SINGLE, DETECT_ENGINE_CONTENT_INSPECTION_MODE_STATE);
        if (match) {
            return DETECT_ENGINE_INSPECT_SIG_MATCH;
        }
        local_id++;
    }

    return DETECT_ENGINE_INSPECT_SIG_NO_MATCH;
}

static int DetectHTTPRequestHeaderSetup(DetectEngineCtx *de_ctx, Signature *s, const char *arg)
{
    if (DetectBufferSetActiveList(de_ctx, s, g_http_request_header_buffer_id) < 0)
        return -1;

    if (DetectSignatureSetAppProto(s, ALPROTO_HTTP) != 0)
        return -1;

    return 0;
}

void DetectHttpRequestHeaderRegister(void)
{
    sigmatch_table[DETECT_HTTP_REQUEST_HEADER].name = "http.request_header";
    sigmatch_table[DETECT_HTTP_REQUEST_HEADER].desc =
            "sticky buffer to match on only one HTTP header name and value";
    sigmatch_table[DETECT_HTTP_REQUEST_HEADER].url = "/rules/http-keywords.html#request_header";
    sigmatch_table[DETECT_HTTP_REQUEST_HEADER].Setup = DetectHTTPRequestHeaderSetup;
    sigmatch_table[DETECT_HTTP_REQUEST_HEADER].flags |=
            SIGMATCH_NOOPT | SIGMATCH_INFO_STICKY_BUFFER;

    DetectAppLayerMpmRegister("http_request_header", SIG_FLAG_TOSERVER, 2,
            PrefilterMpmHttp2HeaderRegister, NULL, ALPROTO_HTTP2, HTTP2StateOpen);
    DetectAppLayerInspectEngineRegister("http_request_header", ALPROTO_HTTP2, SIG_FLAG_TOSERVER,
            HTTP2StateOpen, DetectEngineInspectHttp2Header, NULL);
    DetectAppLayerMpmRegister("http_request_header", SIG_FLAG_TOSERVER, 2,
            PrefilterMpmHttp1HeaderRegister, NULL, ALPROTO_HTTP1, 0);
    DetectAppLayerInspectEngineRegister("http_request_header", ALPROTO_HTTP1, SIG_FLAG_TOSERVER,
            HTP_REQUEST_HEADERS, DetectEngineInspectHttp1Header, NULL);

    DetectBufferTypeSetDescriptionByName("http_request_header", "HTTP header name and value");
    g_http_request_header_buffer_id = DetectBufferTypeGetByName("http_request_header");
    DetectBufferTypeSupportsMultiInstance("http_request_header");
}

static int DetectHTTPResponseHeaderSetup(DetectEngineCtx *de_ctx, Signature *s, const char *arg)
{
    if (DetectBufferSetActiveList(de_ctx, s, g_http_response_header_buffer_id) < 0)
        return -1;

    if (DetectSignatureSetAppProto(s, ALPROTO_HTTP) != 0)
        return -1;

    return 0;
}

void DetectHttpResponseHeaderRegister(void)
{
    sigmatch_table[DETECT_HTTP_RESPONSE_HEADER].name = "http.response_header";
    sigmatch_table[DETECT_HTTP_RESPONSE_HEADER].desc =
            "sticky buffer to match on only one HTTP header name and value";
    sigmatch_table[DETECT_HTTP_RESPONSE_HEADER].url = "/rules/http2-keywords.html#response_header";
    sigmatch_table[DETECT_HTTP_RESPONSE_HEADER].Setup = DetectHTTPResponseHeaderSetup;
    sigmatch_table[DETECT_HTTP_RESPONSE_HEADER].flags |=
            SIGMATCH_NOOPT | SIGMATCH_INFO_STICKY_BUFFER;

    DetectAppLayerMpmRegister("http_response_header", SIG_FLAG_TOCLIENT, 2,
            PrefilterMpmHttp2HeaderRegister, NULL, ALPROTO_HTTP2, HTTP2StateOpen);
    DetectAppLayerInspectEngineRegister("http_response_header", ALPROTO_HTTP2, SIG_FLAG_TOCLIENT,
            HTTP2StateOpen, DetectEngineInspectHttp2Header, NULL);
    DetectAppLayerMpmRegister("http_response_header", SIG_FLAG_TOCLIENT, 2,
            PrefilterMpmHttp1HeaderRegister, NULL, ALPROTO_HTTP1, 0);
    DetectAppLayerInspectEngineRegister("http_response_header", ALPROTO_HTTP1, SIG_FLAG_TOCLIENT,
            HTP_RESPONSE_HEADERS, DetectEngineInspectHttp1Header, NULL);

    DetectBufferTypeSetDescriptionByName("http_response_header", "HTTP header name and value");
    g_http_response_header_buffer_id = DetectBufferTypeGetByName("http_response_header");
    DetectBufferTypeSupportsMultiInstance("http_response_header");
}

/************************************Unittests*********************************/

#ifdef UNITTESTS
#include "tests/detect-http-header.c"
#endif

/**
 * @}
 */
