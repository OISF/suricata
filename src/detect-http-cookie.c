/* Copyright (C) 2007-2018 Open Information Security Foundation
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
 * \author Gurvinder Singh <gurvindersinghdahiya@gmail.com>
 *
 * Implements the http_cookie keyword
 */

#include "suricata-common.h"

#include "detect-engine.h"
#include "detect-engine-mpm.h"
#include "detect-engine-prefilter.h"
#include "detect-pcre.h"

#include "app-layer-htp.h"
#include "detect-http-cookie.h"

#ifdef UNITTESTS
#include "stream-tcp.h"
#include "app-layer-parser.h"
#include "app-layer.h"
#include "util-print.h"
#include "util-spm.h"
#include "util-unittest-helper.h"
#include "util-unittest.h"
#include "util-error.h"
#include "util-debug.h"
#include "flow-util.h"
#include "flow-var.h"
#include "flow.h"
#include "detect-content.h"
#include "detect-parse.h"
#include "detect.h"
#include "decode.h"
#include "threads.h"
#endif
static int DetectHttpCookieSetup (DetectEngineCtx *, Signature *, const char *);
static int DetectHttpCookieSetupSticky (DetectEngineCtx *, Signature *, const char *);
#ifdef UNITTESTS
static void DetectHttpCookieRegisterTests(void);
#endif
static int g_http_cookie_buffer_id = 0;

static InspectionBuffer *GetRequestData(DetectEngineThreadCtx *det_ctx,
        const DetectEngineTransforms *transforms,
        Flow *_f, const uint8_t _flow_flags,
        void *txv, const int list_id);
static InspectionBuffer *GetResponseData(DetectEngineThreadCtx *det_ctx,
        const DetectEngineTransforms *transforms,
        Flow *_f, const uint8_t _flow_flags,
        void *txv, const int list_id);
static InspectionBuffer *GetRequestData2(DetectEngineThreadCtx *det_ctx,
        const DetectEngineTransforms *transforms, Flow *_f, const uint8_t _flow_flags, void *txv,
        const int list_id);
static InspectionBuffer *GetResponseData2(DetectEngineThreadCtx *det_ctx,
        const DetectEngineTransforms *transforms, Flow *_f, const uint8_t _flow_flags, void *txv,
        const int list_id);
/**
 * \brief Registration function for keyword: http_cookie
 */
void DetectHttpCookieRegister(void)
{
    /* http_cookie content modifier */
    sigmatch_table[DETECT_AL_HTTP_COOKIE].name = "http_cookie";
    sigmatch_table[DETECT_AL_HTTP_COOKIE].desc = "content modifier to match only on the HTTP cookie-buffer";
    sigmatch_table[DETECT_AL_HTTP_COOKIE].url = "/rules/http-keywords.html#http-cookie";
    sigmatch_table[DETECT_AL_HTTP_COOKIE].Setup = DetectHttpCookieSetup;
#ifdef UNITTESTS
    sigmatch_table[DETECT_AL_HTTP_COOKIE].RegisterTests = DetectHttpCookieRegisterTests;
#endif
    sigmatch_table[DETECT_AL_HTTP_COOKIE].flags |= SIGMATCH_NOOPT;
    sigmatch_table[DETECT_AL_HTTP_COOKIE].flags |= SIGMATCH_INFO_CONTENT_MODIFIER;
    sigmatch_table[DETECT_AL_HTTP_COOKIE].alternative = DETECT_HTTP_COOKIE;

    /* http.cookie sticky buffer */
    sigmatch_table[DETECT_HTTP_COOKIE].name = "http.cookie";
    sigmatch_table[DETECT_HTTP_COOKIE].desc = "sticky buffer to match on the HTTP Cookie/Set-Cookie buffers";
    sigmatch_table[DETECT_HTTP_COOKIE].url = "/rules/http-keywords.html#http-cookie";
    sigmatch_table[DETECT_HTTP_COOKIE].Setup = DetectHttpCookieSetupSticky;
    sigmatch_table[DETECT_HTTP_COOKIE].flags |= SIGMATCH_NOOPT;
    sigmatch_table[DETECT_HTTP_COOKIE].flags |= SIGMATCH_INFO_STICKY_BUFFER;

    DetectAppLayerInspectEngineRegister2("http_cookie", ALPROTO_HTTP1, SIG_FLAG_TOSERVER,
            HTP_REQUEST_HEADERS, DetectEngineInspectBufferGeneric, GetRequestData);
    DetectAppLayerInspectEngineRegister2("http_cookie", ALPROTO_HTTP1, SIG_FLAG_TOCLIENT,
            HTP_REQUEST_HEADERS, DetectEngineInspectBufferGeneric, GetResponseData);

    DetectAppLayerMpmRegister2("http_cookie", SIG_FLAG_TOSERVER, 2, PrefilterGenericMpmRegister,
            GetRequestData, ALPROTO_HTTP1, HTP_REQUEST_HEADERS);
    DetectAppLayerMpmRegister2("http_cookie", SIG_FLAG_TOCLIENT, 2, PrefilterGenericMpmRegister,
            GetResponseData, ALPROTO_HTTP1, HTP_REQUEST_HEADERS);

    DetectAppLayerInspectEngineRegister2("http_cookie", ALPROTO_HTTP2, SIG_FLAG_TOSERVER,
            HTTP2StateDataClient, DetectEngineInspectBufferGeneric, GetRequestData2);
    DetectAppLayerInspectEngineRegister2("http_cookie", ALPROTO_HTTP2, SIG_FLAG_TOCLIENT,
            HTTP2StateDataServer, DetectEngineInspectBufferGeneric, GetResponseData2);

    DetectAppLayerMpmRegister2("http_cookie", SIG_FLAG_TOSERVER, 2, PrefilterGenericMpmRegister,
            GetRequestData2, ALPROTO_HTTP2, HTTP2StateDataClient);
    DetectAppLayerMpmRegister2("http_cookie", SIG_FLAG_TOCLIENT, 2, PrefilterGenericMpmRegister,
            GetResponseData2, ALPROTO_HTTP2, HTTP2StateDataServer);

    DetectBufferTypeSetDescriptionByName("http_cookie",
            "http cookie header");

    g_http_cookie_buffer_id = DetectBufferTypeGetByName("http_cookie");
}

/**
 * \brief this function setups the http_cookie modifier keyword used in the rule
 *
 * \param de_ctx   Pointer to the Detection Engine Context
 * \param s        Pointer to the Signature to which the current keyword belongs
 * \param str      Should hold an empty string always
 *
 * \retval  0 On success
 * \retval -1 On failure
 */

static int DetectHttpCookieSetup(DetectEngineCtx *de_ctx, Signature *s, const char *str)
{
    return DetectEngineContentModifierBufferSetup(
            de_ctx, s, str, DETECT_AL_HTTP_COOKIE, g_http_cookie_buffer_id, ALPROTO_HTTP1);
}

/**
 * \brief this function setup the http.user_agent keyword used in the rule
 *
 * \param de_ctx   Pointer to the Detection Engine Context
 * \param s        Pointer to the Signature to which the current keyword belongs
 * \param str      Should hold an empty string always
 *
 * \retval 0       On success
 */
static int DetectHttpCookieSetupSticky(DetectEngineCtx *de_ctx, Signature *s, const char *str)
{
    if (DetectBufferSetActiveList(s, g_http_cookie_buffer_id) < 0)
        return -1;

    if (DetectSignatureSetAppProto(s, ALPROTO_HTTP) < 0)
        return -1;

    return 0;
}

static InspectionBuffer *GetRequestData(DetectEngineThreadCtx *det_ctx,
        const DetectEngineTransforms *transforms, Flow *_f,
        const uint8_t _flow_flags, void *txv, const int list_id)
{
    InspectionBuffer *buffer = InspectionBufferGet(det_ctx, list_id);
    if (buffer->inspect == NULL) {
        htp_tx_t *tx = (htp_tx_t *)txv;

        if (tx->request_headers == NULL)
            return NULL;

        htp_header_t *h = (htp_header_t *)htp_table_get_c(tx->request_headers,
                "Cookie");
        if (h == NULL || h->value == NULL) {
            SCLogDebug("HTTP cookie header not present in this request");
            return NULL;
        }

        const uint32_t data_len = bstr_len(h->value);
        const uint8_t *data = bstr_ptr(h->value);

        InspectionBufferSetup(det_ctx, list_id, buffer, data, data_len);
        InspectionBufferApplyTransforms(buffer, transforms);
    }

    return buffer;
}

static InspectionBuffer *GetResponseData(DetectEngineThreadCtx *det_ctx,
        const DetectEngineTransforms *transforms, Flow *_f,
        const uint8_t _flow_flags, void *txv, const int list_id)
{
    InspectionBuffer *buffer = InspectionBufferGet(det_ctx, list_id);
    if (buffer->inspect == NULL) {
        htp_tx_t *tx = (htp_tx_t *)txv;

        if (tx->response_headers == NULL)
            return NULL;

        htp_header_t *h = (htp_header_t *)htp_table_get_c(tx->response_headers,
                "Set-Cookie");
        if (h == NULL || h->value == NULL) {
            SCLogDebug("HTTP cookie header not present in this request");
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
    InspectionBuffer *buffer = InspectionBufferGet(det_ctx, list_id);
    if (buffer->inspect == NULL) {
        uint32_t b_len = 0;
        const uint8_t *b = NULL;

        if (rs_http2_tx_get_cookie(txv, STREAM_TOSERVER, &b, &b_len) != 1)
            return NULL;
        if (b == NULL || b_len == 0)
            return NULL;

        InspectionBufferSetup(det_ctx, list_id, buffer, b, b_len);
        InspectionBufferApplyTransforms(buffer, transforms);
    }

    return buffer;
}

static InspectionBuffer *GetResponseData2(DetectEngineThreadCtx *det_ctx,
        const DetectEngineTransforms *transforms, Flow *_f, const uint8_t _flow_flags, void *txv,
        const int list_id)
{
    InspectionBuffer *buffer = InspectionBufferGet(det_ctx, list_id);
    if (buffer->inspect == NULL) {
        uint32_t b_len = 0;
        const uint8_t *b = NULL;

        if (rs_http2_tx_get_cookie(txv, STREAM_TOCLIENT, &b, &b_len) != 1)
            return NULL;
        if (b == NULL || b_len == 0)
            return NULL;

        InspectionBufferSetup(det_ctx, list_id, buffer, b, b_len);
        InspectionBufferApplyTransforms(buffer, transforms);
    }

    return buffer;
}

/******************************** UNITESTS **********************************/

#ifdef UNITTESTS
#include "tests/detect-http-cookie.c"
#endif /* UNITTESTS */

/**
 * @}
 */
