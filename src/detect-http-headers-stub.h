/* Copyright (C) 2007-2019 Open Information Security Foundation
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
#include "flow.h"

#include "detect.h"
#include "detect-parse.h"
#include "detect-engine.h"
#include "detect-engine-mpm.h"
#include "detect-engine-prefilter.h"

#include "util-debug.h"
#include "rust.h"

static int g_buffer_id = 0;

#ifdef KEYWORD_TOSERVER
static InspectionBuffer *GetRequestData(DetectEngineThreadCtx *det_ctx,
        const DetectEngineTransforms *transforms, Flow *_f,
        const uint8_t _flow_flags, void *txv, const int list_id)
{
    SCEnter();

    InspectionBuffer *buffer = InspectionBufferGet(det_ctx, list_id);
    if (buffer->inspect == NULL) {
        htp_tx_t *tx = (htp_tx_t *)txv;

        if (tx->request_headers == NULL)
            return NULL;

        htp_header_t *h = (htp_header_t *)htp_table_get_c(tx->request_headers,
                                                          HEADER_NAME);
        if (h == NULL || h->value == NULL) {
            SCLogDebug("HTTP %s header not present in this request",
                       HEADER_NAME);
            return NULL;
        }

        const uint32_t data_len = bstr_len(h->value);
        const uint8_t *data = bstr_ptr(h->value);

        InspectionBufferSetup(det_ctx, list_id, buffer, data, data_len);
        InspectionBufferApplyTransforms(buffer, transforms);
    }

    return buffer;
}

static InspectionBuffer *GetRequestData2(DetectEngineThreadCtx *det_ctx,
        const DetectEngineTransforms *transforms, Flow *_f, const uint8_t _flow_flags, void *txv,
        const int list_id)
{
    SCEnter();

    InspectionBuffer *buffer = InspectionBufferGet(det_ctx, list_id);
    if (buffer->inspect == NULL) {
        uint32_t b_len = 0;
        const uint8_t *b = NULL;

        if (rs_http2_tx_get_header_value(txv, STREAM_TOSERVER, HEADER_NAME, &b, &b_len) != 1)
            return NULL;
        if (b == NULL || b_len == 0)
            return NULL;

        InspectionBufferSetup(det_ctx, list_id, buffer, b, b_len);
        InspectionBufferApplyTransforms(buffer, transforms);
    }

    return buffer;
}

#endif
#ifdef KEYWORD_TOCLIENT
static InspectionBuffer *GetResponseData(DetectEngineThreadCtx *det_ctx,
        const DetectEngineTransforms *transforms, Flow *_f,
        const uint8_t _flow_flags, void *txv, const int list_id)
{
    SCEnter();

    InspectionBuffer *buffer = InspectionBufferGet(det_ctx, list_id);
    if (buffer->inspect == NULL) {
        htp_tx_t *tx = (htp_tx_t *)txv;

        if (tx->response_headers == NULL)
            return NULL;

        htp_header_t *h = (htp_header_t *)htp_table_get_c(tx->response_headers,
                                                          HEADER_NAME);
        if (h == NULL || h->value == NULL) {
            SCLogDebug("HTTP %s header not present in this request",
                       HEADER_NAME);
            return NULL;
        }

        const uint32_t data_len = bstr_len(h->value);
        const uint8_t *data = bstr_ptr(h->value);

        InspectionBufferSetup(det_ctx, list_id, buffer, data, data_len);
        InspectionBufferApplyTransforms(buffer, transforms);
    }

    return buffer;
}

static InspectionBuffer *GetResponseData2(DetectEngineThreadCtx *det_ctx,
        const DetectEngineTransforms *transforms, Flow *_f, const uint8_t _flow_flags, void *txv,
        const int list_id)
{
    SCEnter();

    InspectionBuffer *buffer = InspectionBufferGet(det_ctx, list_id);
    if (buffer->inspect == NULL) {
        uint32_t b_len = 0;
        const uint8_t *b = NULL;

        if (rs_http2_tx_get_header_value(txv, STREAM_TOCLIENT, HEADER_NAME, &b, &b_len) != 1)
            return NULL;
        if (b == NULL || b_len == 0)
            return NULL;

        InspectionBufferSetup(det_ctx, list_id, buffer, b, b_len);
        InspectionBufferApplyTransforms(buffer, transforms);
    }

    return buffer;
}
#endif

/**
 * \brief this function setup the http.header keyword used in the rule
 *
 * \param de_ctx   Pointer to the Detection Engine Context
 * \param s        Pointer to the Signature to which the current keyword belongs
 * \param str      Should hold an empty string always
 *
 * \retval 0       On success
 */
static int DetectHttpHeadersSetupSticky(DetectEngineCtx *de_ctx, Signature *s, const char *str)
{
    if (DetectBufferSetActiveList(s, g_buffer_id) < 0)
        return -1;

    if (DetectSignatureSetAppProto(s, ALPROTO_HTTP) < 0)
        return -1;

    return 0;
}

static void DetectHttpHeadersRegisterStub(void)
{
    sigmatch_table[KEYWORD_ID].name = KEYWORD_NAME;
#ifdef KEYWORD_NAME_LEGACY
    sigmatch_table[KEYWORD_ID].alias = KEYWORD_NAME_LEGACY;
#endif
    sigmatch_table[KEYWORD_ID].desc = KEYWORD_NAME " sticky buffer for the " BUFFER_DESC;
    sigmatch_table[KEYWORD_ID].url = "/rules/" KEYWORD_DOC;
    sigmatch_table[KEYWORD_ID].Setup = DetectHttpHeadersSetupSticky;
    sigmatch_table[KEYWORD_ID].flags |= SIGMATCH_NOOPT | SIGMATCH_INFO_STICKY_BUFFER;

#ifdef KEYWORD_TOSERVER
    DetectAppLayerMpmRegister2(BUFFER_NAME, SIG_FLAG_TOSERVER, 2, PrefilterGenericMpmRegister,
            GetRequestData, ALPROTO_HTTP1, HTP_REQUEST_HEADERS);
    DetectAppLayerMpmRegister2(BUFFER_NAME, SIG_FLAG_TOSERVER, 2, PrefilterGenericMpmRegister,
            GetRequestData2, ALPROTO_HTTP2, HTTP2StateDataClient);
#endif
#ifdef KEYWORD_TOCLIENT
    DetectAppLayerMpmRegister2(BUFFER_NAME, SIG_FLAG_TOCLIENT, 2, PrefilterGenericMpmRegister,
            GetResponseData, ALPROTO_HTTP1, HTP_RESPONSE_HEADERS);
    DetectAppLayerMpmRegister2(BUFFER_NAME, SIG_FLAG_TOCLIENT, 2, PrefilterGenericMpmRegister,
            GetResponseData2, ALPROTO_HTTP2, HTTP2StateDataServer);
#endif
#ifdef KEYWORD_TOSERVER
    DetectAppLayerInspectEngineRegister2(BUFFER_NAME, ALPROTO_HTTP1, SIG_FLAG_TOSERVER,
            HTP_REQUEST_HEADERS, DetectEngineInspectBufferGeneric, GetRequestData);
    DetectAppLayerInspectEngineRegister2(BUFFER_NAME, ALPROTO_HTTP2, SIG_FLAG_TOSERVER,
            HTTP2StateDataClient, DetectEngineInspectBufferGeneric, GetRequestData2);
#endif
#ifdef KEYWORD_TOCLIENT
    DetectAppLayerInspectEngineRegister2(BUFFER_NAME, ALPROTO_HTTP1, SIG_FLAG_TOCLIENT,
            HTP_RESPONSE_HEADERS, DetectEngineInspectBufferGeneric, GetResponseData);
    DetectAppLayerInspectEngineRegister2(BUFFER_NAME, ALPROTO_HTTP2, SIG_FLAG_TOCLIENT,
            HTTP2StateDataServer, DetectEngineInspectBufferGeneric, GetResponseData2);
#endif

    DetectBufferTypeSetDescriptionByName(BUFFER_NAME, BUFFER_DESC);

    g_buffer_id = DetectBufferTypeGetByName(BUFFER_NAME);
}
