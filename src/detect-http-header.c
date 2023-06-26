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
#include "util-validate.h"

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

    const htp_headers_t *headers;
    if (flags & STREAM_TOSERVER) {
        if (AppLayerParserGetStateProgress(IPPROTO_TCP, ALPROTO_HTTP1, tx, flags) <=
                HTP_REQUEST_PROGRESS_HEADERS)
            return NULL;
        headers = htp_tx_request_headers(tx);
    } else {
        if (AppLayerParserGetStateProgress(IPPROTO_TCP, ALPROTO_HTTP1, tx, flags) <=
                HTP_RESPONSE_PROGRESS_HEADERS)
            return NULL;
        headers = htp_tx_response_headers(tx);
    }
    if (headers == NULL)
        return NULL;

    size_t i = 0;
    size_t no_of_headers = htp_headers_size(headers);
    for (; i < no_of_headers; i++) {
        const htp_header_t *h = htp_headers_get_index(headers, i);
        size_t size1 = htp_header_name_len(h);
        size_t size2 = htp_header_value_len(h);

        if (flags & STREAM_TOSERVER) {
            if (size1 == 6 && SCMemcmpLowercase("cookie", htp_header_name_ptr(h), 6) == 0) {
                continue;
            }
        } else {
            if (size1 == 10 && SCMemcmpLowercase("set-cookie", htp_header_name_ptr(h), 10) == 0) {
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

        memcpy(buf->buffer + buf->len, htp_header_name_ptr(h), htp_header_name_len(h));
        buf->len += htp_header_name_len(h);
        buf->buffer[buf->len++] = ':';
        buf->buffer[buf->len++] = ' ';
        memcpy(buf->buffer + buf->len, htp_header_value_ptr(h), htp_header_value_len(h));
        buf->len += htp_header_value_len(h);
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
                HTP_REQUEST_PROGRESS_HEADERS)
            return DETECT_ENGINE_INSPECT_SIG_CANT_MATCH;
    } else {
        if (AppLayerParserGetStateProgress(IPPROTO_TCP, ALPROTO_HTTP1, txv, flags) >
                HTP_RESPONSE_PROGRESS_HEADERS)
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

    int r = PrefilterAppendTxEngine(de_ctx, sgh, PrefilterMpmHttpHeader, mpm_reg->app_v2.alproto,
            HTP_REQUEST_PROGRESS_HEADERS, pectx, PrefilterMpmHttpHeaderFree, mpm_reg->pname);
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

    r = PrefilterAppendTxEngine(de_ctx, sgh, PrefilterMpmHttpTrailer, mpm_reg->app_v2.alproto,
            HTP_REQUEST_PROGRESS_TRAILER, pectx, PrefilterMpmHttpHeaderFree, mpm_reg->pname);
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

    int r = PrefilterAppendTxEngine(de_ctx, sgh, PrefilterMpmHttpHeader, mpm_reg->app_v2.alproto,
            HTP_RESPONSE_PROGRESS_HEADERS, pectx, PrefilterMpmHttpHeaderFree, mpm_reg->pname);
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

    r = PrefilterAppendTxEngine(de_ctx, sgh, PrefilterMpmHttpTrailer, mpm_reg->app_v2.alproto,
            HTP_RESPONSE_PROGRESS_TRAILER, pectx, PrefilterMpmHttpHeaderFree, mpm_reg->pname);
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
            HTP_REQUEST_PROGRESS_HEADERS, DetectEngineInspectBufferHttpHeader, NULL);
    DetectAppLayerMpmRegister("http_header", SIG_FLAG_TOSERVER, 2,
            PrefilterMpmHttpHeaderRequestRegister, NULL, ALPROTO_HTTP1,
            0); /* not used, registered twice: HEADERS/TRAILER */

    DetectAppLayerInspectEngineRegister("http_header", ALPROTO_HTTP1, SIG_FLAG_TOCLIENT,
            HTP_RESPONSE_PROGRESS_HEADERS, DetectEngineInspectBufferHttpHeader, NULL);
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
static int g_request_header_thread_id = 0;
static int g_response_header_thread_id = 0;

typedef struct HttpMultiBufItem {
    uint8_t *buffer;
    size_t len;
} HttpMultiBufItem;

typedef struct HttpMultiBufHeaderThreadData {
    // array of items, being defined as a buffer with its length just above
    HttpMultiBufItem *items;
    // capacity of items (size of allocation)
    size_t cap;
    // length of items (number in use)
    size_t len;
} HttpMultiBufHeaderThreadData;

static void *HttpMultiBufHeaderThreadDataInit(void *data)
{
    HttpMultiBufHeaderThreadData *td = SCCalloc(1, sizeof(*td));

    /* This return value check to satisfy our Cocci malloc checks. */
    if (td == NULL) {
        SCLogError("failed to allocate %" PRIuMAX " bytes: %s", (uintmax_t)sizeof(*td),
                strerror(errno));
        return NULL;
    }
    return td;
}

static void HttpMultiBufHeaderThreadDataFree(void *data)
{
    HttpMultiBufHeaderThreadData *td = data;
    for (size_t i = 0; i < td->cap; i++) {
        SCFree(td->items[i].buffer);
    }
    SCFree(td->items);
    SCFree(td);
}

static InspectionBuffer *GetHttp2HeaderData(DetectEngineThreadCtx *det_ctx,
        const DetectEngineTransforms *transforms, Flow *f, const uint8_t flags, void *txv,
        int list_id, uint32_t local_id)
{
    SCEnter();

    InspectionBuffer *buffer = InspectionBufferMultipleForListGet(det_ctx, list_id, local_id);
    if (buffer == NULL)
        return NULL;
    if (buffer->initialized)
        return buffer;

    uint32_t b_len = 0;
    const uint8_t *b = NULL;

    if (rs_http2_tx_get_header(txv, flags, local_id, &b, &b_len) != 1) {
        InspectionBufferSetupMultiEmpty(buffer);
        return NULL;
    }
    if (b == NULL || b_len == 0) {
        InspectionBufferSetupMultiEmpty(buffer);
        return NULL;
    }

    InspectionBufferSetupMulti(buffer, transforms, b, b_len);
    buffer->flags = DETECT_CI_FLAGS_SINGLE;

    SCReturnPtr(buffer, "InspectionBuffer");
}

static InspectionBuffer *GetHttp1HeaderData(DetectEngineThreadCtx *det_ctx,
        const DetectEngineTransforms *transforms, Flow *f, const uint8_t flags, void *txv,
        int list_id, uint32_t local_id)
{
    SCEnter();
    InspectionBuffer *buffer = InspectionBufferMultipleForListGet(det_ctx, list_id, local_id);
    if (buffer == NULL)
        return NULL;
    if (buffer->initialized)
        return buffer;

    int kw_thread_id;
    if (flags & STREAM_TOSERVER) {
        kw_thread_id = g_request_header_thread_id;
    } else {
        kw_thread_id = g_response_header_thread_id;
    }
    HttpMultiBufHeaderThreadData *hdr_td =
            DetectThreadCtxGetGlobalKeywordThreadCtx(det_ctx, kw_thread_id);
    if (unlikely(hdr_td == NULL)) {
        return NULL;
    }

    htp_tx_t *tx = (htp_tx_t *)txv;
    const htp_headers_t *headers;
    if (flags & STREAM_TOSERVER) {
        headers = htp_tx_request_headers(tx);
    } else {
        headers = htp_tx_response_headers(tx);
    }
    size_t no_of_headers = htp_headers_size(headers);
    if (local_id == 0) {
        // We initialize a big buffer on first item
        // Then, we will just use parts of it
        hdr_td->len = 0;
        if (hdr_td->cap < no_of_headers) {
            void *new_buffer = SCRealloc(hdr_td->items, no_of_headers * sizeof(HttpMultiBufItem));
            if (unlikely(new_buffer == NULL)) {
                return NULL;
            }
            hdr_td->items = new_buffer;
            // zeroes the new part of the items
            memset(hdr_td->items + hdr_td->cap, 0,
                    (no_of_headers - hdr_td->cap) * sizeof(HttpMultiBufItem));
            hdr_td->cap = no_of_headers;
        }
        for (size_t i = 0; i < no_of_headers; i++) {
            const htp_header_t *h = htp_headers_get_index(headers, i);
            size_t size1 = htp_header_name_len(h);
            size_t size2 = htp_header_value_len(h);
            size_t size = size1 + size2 + 2;
            if (hdr_td->items[i].len < size) {
                // Use realloc, as this pointer is not freed until HttpMultiBufHeaderThreadDataFree
                void *tmp = SCRealloc(hdr_td->items[i].buffer, size);
                if (unlikely(tmp == NULL)) {
                    return NULL;
                }
                hdr_td->items[i].buffer = tmp;
            }
            memcpy(hdr_td->items[i].buffer, htp_header_name_ptr(h), size1);
            hdr_td->items[i].buffer[size1] = ':';
            hdr_td->items[i].buffer[size1 + 1] = ' ';
            memcpy(hdr_td->items[i].buffer + size1 + 2, htp_header_value_ptr(h), size2);
            hdr_td->items[i].len = size;
        }
        hdr_td->len = no_of_headers;
    }

    // cbdata->local_id is the index of the requested header buffer
    // hdr_td->len is the number of header buffers
    if (local_id < hdr_td->len) {
        // we have one valid header buffer
        InspectionBufferSetupMulti(
                buffer, transforms, hdr_td->items[local_id].buffer, hdr_td->items[local_id].len);
        buffer->flags = DETECT_CI_FLAGS_SINGLE;
        SCReturnPtr(buffer, "InspectionBuffer");
    } // else there are no more header buffer to get
    InspectionBufferSetupMultiEmpty(buffer);
    return NULL;
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

    DetectAppLayerMultiRegister("http_request_header", ALPROTO_HTTP2, SIG_FLAG_TOSERVER,
            HTTP2StateOpen, GetHttp2HeaderData, 2, HTTP2StateOpen);
    DetectAppLayerMultiRegister("http_request_header", ALPROTO_HTTP1, SIG_FLAG_TOSERVER,
            HTP_REQUEST_PROGRESS_HEADERS, GetHttp1HeaderData, 2, 0);

    DetectBufferTypeSetDescriptionByName("http_request_header", "HTTP header name and value");
    g_http_request_header_buffer_id = DetectBufferTypeGetByName("http_request_header");
    DetectBufferTypeSupportsMultiInstance("http_request_header");
    g_request_header_thread_id = DetectRegisterThreadCtxGlobalFuncs("http_request_header",
            HttpMultiBufHeaderThreadDataInit, NULL, HttpMultiBufHeaderThreadDataFree);
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

    DetectAppLayerMultiRegister("http_response_header", ALPROTO_HTTP2, SIG_FLAG_TOCLIENT,
            HTTP2StateOpen, GetHttp2HeaderData, 2, HTTP2StateOpen);
    DetectAppLayerMultiRegister("http_response_header", ALPROTO_HTTP1, SIG_FLAG_TOCLIENT,
            HTP_RESPONSE_PROGRESS_HEADERS, GetHttp1HeaderData, 2, 0);

    DetectBufferTypeSetDescriptionByName("http_response_header", "HTTP header name and value");
    g_http_response_header_buffer_id = DetectBufferTypeGetByName("http_response_header");
    DetectBufferTypeSupportsMultiInstance("http_response_header");
    g_response_header_thread_id = DetectRegisterThreadCtxGlobalFuncs("http_response_header",
            HttpMultiBufHeaderThreadDataInit, NULL, HttpMultiBufHeaderThreadDataFree);
}

/************************************Unittests*********************************/

#ifdef UNITTESTS
#include "tests/detect-http-header.c"
#endif

/**
 * @}
 */
