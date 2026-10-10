/* Copyright (C) 2026 Open Information Security Foundation
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
 * \author Victor Julien <victor@inliniac.net>
 *
 * Raw bytes of the trailer section of an HTTP/1 chunked message.
 */

#include "suricata-common.h"

#include "detect.h"
#include "detect-parse.h"
#include "detect-engine.h"
#include "detect-engine-buffer.h"
#include "detect-engine-mpm.h"
#include "detect-engine-prefilter.h"
#include "detect-engine-state.h"
#include "detect-content.h"
#include "detect-http-trailer.h"

#include "app-layer.h"
#include "app-layer-parser.h"
#include "app-layer-htp.h"

#include "flow.h"
#include "util-debug.h"
#include "util-print.h"

#define KEYWORD_NAME        "http.trailer.raw"
#define KEYWORD_NAME_LEGACY "http_trailer_raw"
#define KEYWORD_DOC         "http-keywords.html#http-trailer-raw"
#define BUFFER_NAME         "http_trailer_raw"
#define BUFFER_DESC         "raw http trailer data"
static int g_buffer_id = 0;
static int g_http2_thread_id = 0;

static InspectionBuffer *GetData(DetectEngineThreadCtx *det_ctx,
        const DetectEngineTransforms *transforms, Flow *_f, const uint8_t flow_flags, void *txv,
        const int list_id);
static InspectionBuffer *GetData2(DetectEngineThreadCtx *det_ctx,
        const DetectEngineTransforms *transforms, Flow *_f, const uint8_t flow_flags, void *txv,
        const int list_id);

static int DetectHttpTrailerRawSetup(DetectEngineCtx *de_ctx, Signature *s, const char *str)
{
    if (SCDetectBufferSetActiveList(de_ctx, s, g_buffer_id) < 0)
        return -1;
    if (SCDetectSignatureSetAppProto(s, ALPROTO_HTTP) < 0)
        return -1;
    return 0;
}

void DetectHttpTrailerRawRegister(void)
{
    sigmatch_table[DETECT_HTTP_TRAILER_RAW].name = KEYWORD_NAME;
    sigmatch_table[DETECT_HTTP_TRAILER_RAW].alias = KEYWORD_NAME_LEGACY;
    sigmatch_table[DETECT_HTTP_TRAILER_RAW].desc = BUFFER_NAME " sticky buffer";
    sigmatch_table[DETECT_HTTP_TRAILER_RAW].url = "/rules/" KEYWORD_DOC;
    sigmatch_table[DETECT_HTTP_TRAILER_RAW].Setup = DetectHttpTrailerRawSetup;
    sigmatch_table[DETECT_HTTP_TRAILER_RAW].flags |= SIGMATCH_NOOPT | SIGMATCH_INFO_STICKY_BUFFER;

    DetectAppLayerInspectEngineRegister(BUFFER_NAME, ALPROTO_HTTP1, SIG_FLAG_TOSERVER,
            HTP_REQUEST_PROGRESS_TRAILER, DetectEngineInspectBufferGeneric, GetData);
    DetectAppLayerInspectEngineRegister(BUFFER_NAME, ALPROTO_HTTP1, SIG_FLAG_TOCLIENT,
            HTP_RESPONSE_PROGRESS_TRAILER, DetectEngineInspectBufferGeneric, GetData);

    DetectAppLayerMpmRegister(BUFFER_NAME, SIG_FLAG_TOSERVER, 2, PrefilterGenericMpmRegister,
            GetData, ALPROTO_HTTP1, HTP_REQUEST_PROGRESS_TRAILER);
    DetectAppLayerMpmRegister(BUFFER_NAME, SIG_FLAG_TOCLIENT, 2, PrefilterGenericMpmRegister,
            GetData, ALPROTO_HTTP1, HTP_RESPONSE_PROGRESS_TRAILER);

    /* http2: a trailing HEADERS block completes at the trailer state */
    DetectAppLayerInspectEngineRegisterSubState(BUFFER_NAME, ALPROTO_HTTP2, SIG_FLAG_TOSERVER,
            HTTP2TxTypeStream, HTTP2ProgTrailers, DetectEngineInspectBufferGeneric, GetData2);
    DetectAppLayerInspectEngineRegisterSubState(BUFFER_NAME, ALPROTO_HTTP2, SIG_FLAG_TOCLIENT,
            HTTP2TxTypeStream, HTTP2ProgTrailers, DetectEngineInspectBufferGeneric, GetData2);
    DetectAppLayerMpmRegisterSubState(BUFFER_NAME, SIG_FLAG_TOSERVER, 2,
            PrefilterGenericMpmRegister, GetData2, ALPROTO_HTTP2, HTTP2TxTypeStream,
            HTTP2ProgTrailers);
    DetectAppLayerMpmRegisterSubState(BUFFER_NAME, SIG_FLAG_TOCLIENT, 2,
            PrefilterGenericMpmRegister, GetData2, ALPROTO_HTTP2, HTTP2TxTypeStream,
            HTTP2ProgTrailers);

    DetectBufferTypeSetDescriptionByName(BUFFER_NAME, BUFFER_DESC);

    g_buffer_id = DetectBufferTypeGetByName(BUFFER_NAME);

    g_http2_thread_id = SCDetectRegisterThreadCtxGlobalFuncs(
            "http2.trailer_raw", SCDetectThreadBufDataInit, NULL, SCDetectThreadBufDataFree);
}

static InspectionBuffer *GetData(DetectEngineThreadCtx *det_ctx,
        const DetectEngineTransforms *transforms, Flow *_f, const uint8_t flow_flags, void *txv,
        const int list_id)
{
    InspectionBuffer *buffer = SCInspectionBufferGet(det_ctx, list_id);
    if (buffer->inspect == NULL) {
        htp_tx_t *tx = (htp_tx_t *)txv;

        HtpTxUserData *tx_ud = htp_tx_get_user_data(tx);

        const bool ts = ((flow_flags & STREAM_TOSERVER) != 0);
        const uint8_t *data = ts ? tx_ud->request_trailers_raw : tx_ud->response_trailers_raw;
        if (data == NULL)
            return NULL;
        const uint32_t data_len =
                ts ? tx_ud->request_trailers_raw_len : tx_ud->response_trailers_raw_len;
        /* A section with no trailer fields holds only the framing that ends the chunked
         * body - the empty line, possibly with stray whitespace. Not buffer content. */
        const htp_headers_t *trailers =
                ts ? htp_tx_request_trailers(tx) : htp_tx_response_trailers(tx);
        if (trailers == NULL || htp_headers_size(trailers) == 0)
            return NULL;

        SCInspectionBufferSetupAndApplyTransforms(
                det_ctx, list_id, buffer, data, data_len, transforms);
    }

    return buffer;
}

static InspectionBuffer *GetData2(DetectEngineThreadCtx *det_ctx,
        const DetectEngineTransforms *transforms, Flow *_f, const uint8_t flow_flags, void *txv,
        const int list_id)
{
    InspectionBuffer *buffer = SCInspectionBufferGet(det_ctx, list_id);
    if (buffer->inspect == NULL) {
        uint32_t b_len = 0;
        const uint8_t *b = NULL;

        void *thread_buf = SCDetectThreadCtxGetGlobalKeywordThreadCtx(det_ctx, g_http2_thread_id);
        if (thread_buf == NULL)
            return NULL;

        if (SCHttp2TxGetTrailersRaw(txv, flow_flags, &b, &b_len, thread_buf) != 1)
            return NULL;
        if (b == NULL || b_len == 0)
            return NULL;

        SCInspectionBufferSetupAndApplyTransforms(det_ctx, list_id, buffer, b, b_len, transforms);
    }

    return buffer;
}
