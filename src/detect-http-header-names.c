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
 * \ingroup httplayer
 *
 * @{
 */


/**
 * \file
 *
 * \author Victor Julien <victor@inliniac.net>
 *
 * Implements support http_header_names
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
#include "detect-http-header-common.h"
#include "detect-http-header-names.h"

#include "flow.h"
#include "flow-var.h"
#include "flow-util.h"

#include "util-debug.h"
#include "util-unittest.h"
#include "util-unittest-helper.h"
#include "util-spm.h"
#include "util-print.h"

#include "app-layer.h"
#include "app-layer-parser.h"

#include "app-layer-htp.h"
#include "detect-http-header.h"
#include "stream-tcp.h"

#define KEYWORD_NAME "http.header_names"
#define KEYWORD_NAME_LEGACY "http_header_names"
#define KEYWORD_DOC "http-keywords.html#http-header-names"
#define BUFFER_NAME "http_header_names"
#define BUFFER_DESC "http header names"
static int g_buffer_id = 0;
static int g_keyword_thread_id = 0;

#define BUFFER_SIZE_STEP    256
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

    /* fill the buffer. \r\nName1\r\nName2\r\n\r\n */
    size_t i = 0;
    size_t no_of_headers = htp_table_size(headers);
    for (; i < no_of_headers; i++) {
        htp_header_t *h = htp_table_get_index(headers, i, NULL);
        size_t size = bstr_size(h->name) + 2; // for \r\n
        if (i == 0)
            size += 2;
        if (i + 1 == no_of_headers)
            size += 2;

        SCLogDebug("size %"PRIuMAX" + buf->len %u vs buf->size %u",
                (uintmax_t)size, buf->len, buf->size);
        if (size + buf->len > buf->size) {
            if (HttpHeaderExpandBuffer(hdr_td, buf, size) != 0) {
                return NULL;
            }
        }

        /* start with a \r\n */
        if (i == 0) {
            buf->buffer[buf->len++] = '\r';
            buf->buffer[buf->len++] = '\n';
        }

        memcpy(buf->buffer + buf->len, bstr_ptr(h->name), bstr_size(h->name));
        buf->len += bstr_size(h->name);
        buf->buffer[buf->len++] = '\r';
        buf->buffer[buf->len++] = '\n';

        /* end with an extra \r\n */
        if (i + 1 == no_of_headers) {
            buf->buffer[buf->len++] = '\r';
            buf->buffer[buf->len++] = '\n';
        }
    }

    *buffer_len = buf->len;
    return buf->buffer;
}

static InspectionBuffer *GetBuffer1ForTX(DetectEngineThreadCtx *det_ctx,
        const DetectEngineTransforms *transforms, Flow *f, const uint8_t flow_flags, void *txv,
        const int list_id)
{
    InspectionBuffer *buffer = InspectionBufferGet(det_ctx, list_id);
    if (buffer->inspect == NULL) {
        uint32_t rawdata_len = 0;
        uint8_t *rawdata = GetBufferForTX(txv, det_ctx, f, flow_flags, &rawdata_len);
        if (rawdata_len == 0)
            return NULL;

        InspectionBufferSetup(det_ctx, list_id, buffer, rawdata, rawdata_len);
        InspectionBufferApplyTransforms(buffer, transforms);
    }

    return buffer;
}

static InspectionBuffer *GetBuffer2ForTX(DetectEngineThreadCtx *det_ctx,
        const DetectEngineTransforms *transforms, Flow *_f, const uint8_t flow_flags, void *txv,
        const int list_id)
{
    InspectionBuffer *buffer = InspectionBufferGet(det_ctx, list_id);
    if (buffer->inspect == NULL) {
        uint32_t b_len = 0;
        const uint8_t *b = NULL;

        if (rs_http2_tx_get_header_names(txv, flow_flags, &b, &b_len) != 1)
            return NULL;
        if (b == NULL || b_len == 0)
            return NULL;

        InspectionBufferSetup(det_ctx, list_id, buffer, b, b_len);
        InspectionBufferApplyTransforms(buffer, transforms);
    }

    return buffer;
}

/**
 * \brief The setup function for the http.header_names keyword for a signature.
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
static int DetectHttpHeaderNamesSetup(DetectEngineCtx *de_ctx, Signature *s, const char *arg)
{
    if (DetectBufferSetActiveList(s, g_buffer_id) < 0)
        return -1;

    if (DetectSignatureSetAppProto(s, ALPROTO_HTTP) < 0)
        return -1;

    return 0;
}

/**
 * \brief Registers the keyword handlers for the "http.header_names" keyword.
 */
void DetectHttpHeaderNamesRegister(void)
{
    sigmatch_table[DETECT_AL_HTTP_HEADER_NAMES].name = KEYWORD_NAME;
    sigmatch_table[DETECT_AL_HTTP_HEADER_NAMES].alias = KEYWORD_NAME_LEGACY;
    sigmatch_table[DETECT_AL_HTTP_HEADER_NAMES].desc = BUFFER_NAME " sticky buffer";
    sigmatch_table[DETECT_AL_HTTP_HEADER_NAMES].url = "/rules/" KEYWORD_DOC;
    sigmatch_table[DETECT_AL_HTTP_HEADER_NAMES].Setup = DetectHttpHeaderNamesSetup;

    sigmatch_table[DETECT_AL_HTTP_HEADER_NAMES].flags |= SIGMATCH_NOOPT | SIGMATCH_INFO_STICKY_BUFFER;

    /* http1 */
    DetectAppLayerMpmRegister2(BUFFER_NAME, SIG_FLAG_TOSERVER, 2, PrefilterGenericMpmRegister,
            GetBuffer1ForTX, ALPROTO_HTTP1, HTP_REQUEST_HEADERS);
    DetectAppLayerMpmRegister2(BUFFER_NAME, SIG_FLAG_TOCLIENT, 2, PrefilterGenericMpmRegister,
            GetBuffer1ForTX, ALPROTO_HTTP1, HTP_RESPONSE_HEADERS);

    DetectAppLayerInspectEngineRegister2(BUFFER_NAME, ALPROTO_HTTP1, SIG_FLAG_TOSERVER,
            HTP_REQUEST_HEADERS, DetectEngineInspectBufferGeneric, GetBuffer1ForTX);
    DetectAppLayerInspectEngineRegister2(BUFFER_NAME, ALPROTO_HTTP1, SIG_FLAG_TOCLIENT,
            HTP_RESPONSE_HEADERS, DetectEngineInspectBufferGeneric, GetBuffer1ForTX);

    /* http2 */
    DetectAppLayerMpmRegister2(BUFFER_NAME, SIG_FLAG_TOSERVER, 2, PrefilterGenericMpmRegister,
            GetBuffer2ForTX, ALPROTO_HTTP2, HTTP2StateDataClient);
    DetectAppLayerMpmRegister2(BUFFER_NAME, SIG_FLAG_TOCLIENT, 2, PrefilterGenericMpmRegister,
            GetBuffer2ForTX, ALPROTO_HTTP2, HTTP2StateDataServer);

    DetectAppLayerInspectEngineRegister2(BUFFER_NAME, ALPROTO_HTTP2, SIG_FLAG_TOSERVER,
            HTTP2StateDataClient, DetectEngineInspectBufferGeneric, GetBuffer2ForTX);
    DetectAppLayerInspectEngineRegister2(BUFFER_NAME, ALPROTO_HTTP2, SIG_FLAG_TOCLIENT,
            HTTP2StateDataServer, DetectEngineInspectBufferGeneric, GetBuffer2ForTX);

    DetectBufferTypeSetDescriptionByName(BUFFER_NAME,
            BUFFER_DESC);

    g_buffer_id = DetectBufferTypeGetByName(BUFFER_NAME);

    g_keyword_thread_id = DetectRegisterThreadCtxGlobalFuncs(KEYWORD_NAME,
            HttpHeaderThreadDataInit, &g_td_config, HttpHeaderThreadDataFree);

    SCLogDebug("keyword %s registered. Thread id %d. "
            "Buffer %s registered. Buffer id %d",
            KEYWORD_NAME, g_keyword_thread_id,
            BUFFER_NAME, g_buffer_id);
}
