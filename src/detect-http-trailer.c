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
 * Trailer fields of an HTTP/1 chunked message, as "Name: value\r\n" per field.
 * The header section is a separate buffer: see detect-http-header.c.
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
#include "detect-http-header-common.h"

#include "app-layer.h"
#include "app-layer-parser.h"
#include "app-layer-htp.h"

#include "flow.h"
#include "util-debug.h"
#include "util-print.h"

#define KEYWORD_NAME        "http.trailer"
#define KEYWORD_NAME_LEGACY "http_trailer"
#define KEYWORD_DOC         "http-keywords.html#http-trailer"
#define BUFFER_NAME         "http_trailer"
#define BUFFER_DESC         "http trailer fields"
static int g_buffer_id = 0;
static int g_keyword_thread_id = 0;

#ifdef UNITTESTS
void DetectHttpTrailerRegisterTests(void);
#endif

#define BUFFER_SIZE_STEP 512
static HttpHeaderThreadDataConfig g_td_config = { BUFFER_SIZE_STEP };

static InspectionBuffer *GetBuffer1ForTX(DetectEngineThreadCtx *det_ctx,
        const DetectEngineTransforms *transforms, Flow *_f, const uint8_t flow_flags, void *txv,
        const int list_id);

static int DetectHttpTrailerSetup(DetectEngineCtx *de_ctx, Signature *s, const char *str)
{
    if (SCDetectBufferSetActiveList(de_ctx, s, g_buffer_id) < 0)
        return -1;
    if (SCDetectSignatureSetAppProto(s, ALPROTO_HTTP) < 0)
        return -1;
    return 0;
}

void DetectHttpTrailerRegister(void)
{
    sigmatch_table[DETECT_HTTP_TRAILER].name = KEYWORD_NAME;
    sigmatch_table[DETECT_HTTP_TRAILER].alias = KEYWORD_NAME_LEGACY;
    sigmatch_table[DETECT_HTTP_TRAILER].desc = BUFFER_NAME " sticky buffer";
    sigmatch_table[DETECT_HTTP_TRAILER].url = "/rules/" KEYWORD_DOC;
    sigmatch_table[DETECT_HTTP_TRAILER].Setup = DetectHttpTrailerSetup;
    sigmatch_table[DETECT_HTTP_TRAILER].flags |= SIGMATCH_NOOPT | SIGMATCH_INFO_STICKY_BUFFER;

#ifdef UNITTESTS
    sigmatch_table[DETECT_HTTP_TRAILER].RegisterTests = DetectHttpTrailerRegisterTests;
#endif

    /* Inspect at the trailer state, the state the trailer section completes in. Rounds
     * while the section is still arriving are not final, the one at COMPLETE is. */
    DetectAppLayerInspectEngineRegister(BUFFER_NAME, ALPROTO_HTTP1, SIG_FLAG_TOSERVER,
            HTP_REQUEST_PROGRESS_TRAILER, DetectEngineInspectBufferGeneric, GetBuffer1ForTX);
    DetectAppLayerInspectEngineRegister(BUFFER_NAME, ALPROTO_HTTP1, SIG_FLAG_TOCLIENT,
            HTP_RESPONSE_PROGRESS_TRAILER, DetectEngineInspectBufferGeneric, GetBuffer1ForTX);

    DetectAppLayerMpmRegister(BUFFER_NAME, SIG_FLAG_TOSERVER, 2, PrefilterGenericMpmRegister,
            GetBuffer1ForTX, ALPROTO_HTTP1, HTP_REQUEST_PROGRESS_TRAILER);
    DetectAppLayerMpmRegister(BUFFER_NAME, SIG_FLAG_TOCLIENT, 2, PrefilterGenericMpmRegister,
            GetBuffer1ForTX, ALPROTO_HTTP1, HTP_RESPONSE_PROGRESS_TRAILER);

    DetectBufferTypeSetDescriptionByName(BUFFER_NAME, BUFFER_DESC);

    g_buffer_id = DetectBufferTypeGetByName(BUFFER_NAME);

    g_keyword_thread_id = SCDetectRegisterThreadCtxGlobalFuncs(
            KEYWORD_NAME, HttpHeaderThreadDataInit, &g_td_config, HttpHeaderThreadDataFree);
}

static uint8_t *GetBufferForTX(
        htp_tx_t *tx, DetectEngineThreadCtx *det_ctx, uint8_t flags, uint32_t *buffer_len)
{
    *buffer_len = 0;

    HttpHeaderThreadData *hdr_td = NULL;
    HttpHeaderBuffer *buf = HttpHeaderGetBufferSpace(det_ctx, flags, g_keyword_thread_id, &hdr_td);
    if (unlikely(buf == NULL)) {
        return NULL;
    }

    const htp_headers_t *trailers =
            (flags & STREAM_TOSERVER) ? htp_tx_request_trailers(tx) : htp_tx_response_trailers(tx);
    if (trailers == NULL)
        return NULL;

    size_t i = 0;
    size_t no_of_trailers = htp_headers_size(trailers);
    for (; i < no_of_trailers; i++) {
        const htp_header_t *h = htp_headers_get_index(trailers, i);
        size_t size = htp_header_name_len(h) + htp_header_value_len(h) + 4;

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
    }

    *buffer_len = buf->len;
    return buf->buffer;
}

static InspectionBuffer *GetBuffer1ForTX(DetectEngineThreadCtx *det_ctx,
        const DetectEngineTransforms *transforms, Flow *_f, const uint8_t flow_flags, void *txv,
        const int list_id)
{
    InspectionBuffer *buffer = SCInspectionBufferGet(det_ctx, list_id);
    if (buffer->inspect == NULL) {
        uint32_t rawdata_len = 0;
        uint8_t *rawdata = GetBufferForTX(txv, det_ctx, flow_flags, &rawdata_len);
        if (rawdata_len == 0)
            return NULL;

        SCInspectionBufferSetupAndApplyTransforms(
                det_ctx, list_id, buffer, rawdata, rawdata_len, transforms);
    }

    return buffer;
}

#ifdef UNITTESTS
#include "tests/detect-http-trailer.c"
#endif
