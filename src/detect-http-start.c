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
 * \author Victor Julien <victor@inliniac.net>
 *
 * Implements http_start
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
#include "detect-http-start.h"

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

#include "util-print.h"

#define KEYWORD_NAME "http.start"
#define KEYWORD_NAME_LEGACY "http_start"
#define KEYWORD_DOC "http-keywords.html#http-start"
#define BUFFER_NAME "http_start"
#define BUFFER_DESC "http start: request/response line + headers"
static int g_buffer_id = 0;
static int g_keyword_thread_id = 0;

#define BUFFER_SIZE_STEP    2048
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

    bstr *line = NULL;
    htp_table_t *headers;
    if (flags & STREAM_TOSERVER) {
        if (AppLayerParserGetStateProgress(IPPROTO_TCP, ALPROTO_HTTP1, tx, flags) <=
                HTP_REQUEST_HEADERS)
            return NULL;
        line = tx->request_line;
        headers = tx->request_headers;
    } else {
        if (AppLayerParserGetStateProgress(IPPROTO_TCP, ALPROTO_HTTP1, tx, flags) <=
                HTP_RESPONSE_HEADERS)
            return NULL;
        headers = tx->response_headers;
        line = tx->response_line;
    }
    if (line == NULL || headers == NULL)
        return NULL;

    size_t line_size = bstr_len(line) + 2;
    if (line_size + buf->len > buf->size) {
        if (HttpHeaderExpandBuffer(hdr_td, buf, line_size) != 0) {
            return NULL;
        }
    }
    memcpy(buf->buffer + buf->len, bstr_ptr(line), bstr_size(line));
    buf->len += bstr_size(line);
    buf->buffer[buf->len++] = '\r';
    buf->buffer[buf->len++] = '\n';

    size_t i = 0;
    size_t no_of_headers = htp_table_size(headers);
    for (; i < no_of_headers; i++) {
        htp_header_t *h = htp_table_get_index(headers, i, NULL);
        size_t size1 = bstr_size(h->name);
        size_t size2 = bstr_size(h->value);
        size_t size = size1 + size2 + 4;
        if (i + 1 == no_of_headers)
            size += 2;
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

static int DetectHttpStartSetup(DetectEngineCtx *de_ctx, Signature *s, const char *arg)
{
    if (DetectBufferSetActiveList(s, g_buffer_id) < 0)
        return -1;

    if (DetectSignatureSetAppProto(s, ALPROTO_HTTP1) < 0)
        return -1;

    return 0;
}

/**
 * \brief Registers the keyword handlers for the "http_start" keyword.
 */
void DetectHttpStartRegister(void)
{
    sigmatch_table[DETECT_AL_HTTP_START].name = KEYWORD_NAME;
    sigmatch_table[DETECT_AL_HTTP_START].alias = KEYWORD_NAME_LEGACY;
    sigmatch_table[DETECT_AL_HTTP_START].desc = BUFFER_NAME " sticky buffer";
    sigmatch_table[DETECT_AL_HTTP_START].url = "/rules/" KEYWORD_DOC;
    sigmatch_table[DETECT_AL_HTTP_START].Setup = DetectHttpStartSetup;
    sigmatch_table[DETECT_AL_HTTP_START].flags |= SIGMATCH_NOOPT|SIGMATCH_INFO_STICKY_BUFFER;

    DetectAppLayerMpmRegister2(BUFFER_NAME, SIG_FLAG_TOSERVER, 2, PrefilterGenericMpmRegister,
            GetBuffer1ForTX, ALPROTO_HTTP1, HTP_REQUEST_HEADERS);
    DetectAppLayerMpmRegister2(BUFFER_NAME, SIG_FLAG_TOCLIENT, 2, PrefilterGenericMpmRegister,
            GetBuffer1ForTX, ALPROTO_HTTP1, HTP_RESPONSE_HEADERS);

    DetectAppLayerInspectEngineRegister2(BUFFER_NAME, ALPROTO_HTTP1, SIG_FLAG_TOSERVER,
            HTP_REQUEST_HEADERS, DetectEngineInspectBufferGeneric, GetBuffer1ForTX);
    DetectAppLayerInspectEngineRegister2(BUFFER_NAME, ALPROTO_HTTP1, SIG_FLAG_TOCLIENT,
            HTP_RESPONSE_HEADERS, DetectEngineInspectBufferGeneric, GetBuffer1ForTX);

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
