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
 * \author Gerardo Iglesias  <iglesiasg@gmail.com>
 * \author Victor Julien <victor@inliniac.net>
 */

#include "suricata-common.h"

#include "detect-engine.h"
#include "detect-engine-mpm.h"
#include "detect-engine-prefilter.h"
#include "detect-pcre.h"
#include "detect-urilen.h"

#include "app-layer-htp.h"
#include "detect-http-uri.h"

#ifdef UNITTESTS
#include "stream-tcp.h"
#include "app-layer.h"
#include "util-print.h"
#include "util-spm.h"
#include "util-unittest.h"
#include "util-debug.h"
#include "flow-var.h"
#include "flow.h"
#include "detect-content.h"
#include "detect-parse.h"
#include "detect.h"
#include "decode.h"
#include "threads.h"
#endif
#ifdef UNITTESTS
static void DetectHttpUriRegisterTests(void);
#endif
static void DetectHttpUriSetupCallback(const DetectEngineCtx *de_ctx,
                                       Signature *s);
static bool DetectHttpUriValidateCallback(const Signature *s, const char **sigerror);
static InspectionBuffer *GetData(DetectEngineThreadCtx *det_ctx,
        const DetectEngineTransforms *transforms,
        Flow *_f, const uint8_t _flow_flags,
        void *txv, const int list_id);
static InspectionBuffer *GetData2(DetectEngineThreadCtx *det_ctx,
        const DetectEngineTransforms *transforms, Flow *_f, const uint8_t _flow_flags, void *txv,
        const int list_id);
static int DetectHttpUriSetupSticky(DetectEngineCtx *de_ctx, Signature *s, const char *str);
static int DetectHttpRawUriSetup(DetectEngineCtx *, Signature *, const char *);
static void DetectHttpRawUriSetupCallback(const DetectEngineCtx *de_ctx,
                                          Signature *s);
static bool DetectHttpRawUriValidateCallback(const Signature *s, const char **);
static InspectionBuffer *GetRawData(DetectEngineThreadCtx *det_ctx,
        const DetectEngineTransforms *transforms,
        Flow *_f, const uint8_t _flow_flags,
        void *txv, const int list_id);
static int DetectHttpRawUriSetupSticky(DetectEngineCtx *de_ctx, Signature *s, const char *str);

static int g_http_raw_uri_buffer_id = 0;
static int g_http_uri_buffer_id = 0;

/**
 * \brief Registration function for keywords: http_uri and http.uri
 */
void DetectHttpUriRegister (void)
{
    /* http_uri content modifier */
    sigmatch_table[DETECT_AL_HTTP_URI].name = "http_uri";
    sigmatch_table[DETECT_AL_HTTP_URI].desc = "content modifier to match specifically and only on the HTTP uri-buffer";
    sigmatch_table[DETECT_AL_HTTP_URI].url = "/rules/http-keywords.html#http-uri-and-http-uri-raw";
    sigmatch_table[DETECT_AL_HTTP_URI].Setup = DetectHttpUriSetup;
#ifdef UNITTESTS
    sigmatch_table[DETECT_AL_HTTP_URI].RegisterTests = DetectHttpUriRegisterTests;
#endif
    sigmatch_table[DETECT_AL_HTTP_URI].flags |= SIGMATCH_NOOPT|SIGMATCH_INFO_CONTENT_MODIFIER;
    sigmatch_table[DETECT_AL_HTTP_URI].alternative = DETECT_HTTP_URI;

    /* http.uri sticky buffer */
    sigmatch_table[DETECT_HTTP_URI].name = "http.uri";
    sigmatch_table[DETECT_HTTP_URI].alias = "http.uri.normalized";
    sigmatch_table[DETECT_HTTP_URI].desc = "sticky buffer to match specifically and only on the normalized HTTP URI buffer";
    sigmatch_table[DETECT_HTTP_URI].url = "/rules/http-keywords.html#http-uri-and-http-uri-raw";
    sigmatch_table[DETECT_HTTP_URI].Setup = DetectHttpUriSetupSticky;
    sigmatch_table[DETECT_HTTP_URI].flags |= SIGMATCH_NOOPT|SIGMATCH_INFO_STICKY_BUFFER;

    DetectAppLayerInspectEngineRegister2("http_uri", ALPROTO_HTTP1, SIG_FLAG_TOSERVER,
            HTP_REQUEST_LINE, DetectEngineInspectBufferGeneric, GetData);

    DetectAppLayerMpmRegister2("http_uri", SIG_FLAG_TOSERVER, 2, PrefilterGenericMpmRegister,
            GetData, ALPROTO_HTTP1, HTP_REQUEST_LINE);

    DetectAppLayerInspectEngineRegister2("http_uri", ALPROTO_HTTP2, SIG_FLAG_TOSERVER,
            HTTP2StateDataClient, DetectEngineInspectBufferGeneric, GetData2);

    DetectAppLayerMpmRegister2("http_uri", SIG_FLAG_TOSERVER, 2, PrefilterGenericMpmRegister,
            GetData2, ALPROTO_HTTP2, HTTP2StateDataClient);

    DetectBufferTypeSetDescriptionByName("http_uri",
            "http request uri");

    DetectBufferTypeRegisterSetupCallback("http_uri",
            DetectHttpUriSetupCallback);

    DetectBufferTypeRegisterValidateCallback("http_uri",
            DetectHttpUriValidateCallback);

    g_http_uri_buffer_id = DetectBufferTypeGetByName("http_uri");

    /* http_raw_uri content modifier */
    sigmatch_table[DETECT_AL_HTTP_RAW_URI].name = "http_raw_uri";
    sigmatch_table[DETECT_AL_HTTP_RAW_URI].desc = "content modifier to match on the raw HTTP uri";
    sigmatch_table[DETECT_AL_HTTP_RAW_URI].url = "/rules/http-keywords.html#http_uri-and-http_raw-uri";
    sigmatch_table[DETECT_AL_HTTP_RAW_URI].Setup = DetectHttpRawUriSetup;
    sigmatch_table[DETECT_AL_HTTP_RAW_URI].flags |= SIGMATCH_NOOPT|SIGMATCH_INFO_CONTENT_MODIFIER;
    sigmatch_table[DETECT_AL_HTTP_RAW_URI].alternative = DETECT_HTTP_URI_RAW;

    /* http.uri.raw sticky buffer */
    sigmatch_table[DETECT_HTTP_URI_RAW].name = "http.uri.raw";
    sigmatch_table[DETECT_HTTP_URI_RAW].desc = "sticky buffer to match specifically and only on the raw HTTP URI buffer";
    sigmatch_table[DETECT_HTTP_URI_RAW].url = "/rules/http-keywords.html#http-uri-and-http-raw-uri";
    sigmatch_table[DETECT_HTTP_URI_RAW].Setup = DetectHttpRawUriSetupSticky;
    sigmatch_table[DETECT_HTTP_URI_RAW].flags |= SIGMATCH_NOOPT|SIGMATCH_INFO_STICKY_BUFFER;

    DetectAppLayerInspectEngineRegister2("http_raw_uri", ALPROTO_HTTP1, SIG_FLAG_TOSERVER,
            HTP_REQUEST_LINE, DetectEngineInspectBufferGeneric, GetRawData);

    DetectAppLayerMpmRegister2("http_raw_uri", SIG_FLAG_TOSERVER, 2, PrefilterGenericMpmRegister,
            GetRawData, ALPROTO_HTTP1, HTP_REQUEST_LINE);

    // no difference between raw and decoded uri for HTTP2
    DetectAppLayerInspectEngineRegister2("http_raw_uri", ALPROTO_HTTP2, SIG_FLAG_TOSERVER,
            HTTP2StateDataClient, DetectEngineInspectBufferGeneric, GetData2);

    DetectAppLayerMpmRegister2("http_raw_uri", SIG_FLAG_TOSERVER, 2, PrefilterGenericMpmRegister,
            GetData2, ALPROTO_HTTP2, HTTP2StateDataClient);

    DetectBufferTypeSetDescriptionByName("http_raw_uri",
            "raw http uri");

    DetectBufferTypeRegisterSetupCallback("http_raw_uri",
            DetectHttpRawUriSetupCallback);

    DetectBufferTypeRegisterValidateCallback("http_raw_uri",
            DetectHttpRawUriValidateCallback);

    g_http_raw_uri_buffer_id = DetectBufferTypeGetByName("http_raw_uri");
}

/**
 * \brief this function setups the http_uri modifier keyword used in the rule
 *
 * \param de_ctx   Pointer to the Detection Engine Context
 * \param s        Pointer to the Signature to which the current keyword belongs
 * \param str      Should hold an empty string always
 *
 * \retval  0 On success
 * \retval -1 On failure
 */

int DetectHttpUriSetup(DetectEngineCtx *de_ctx, Signature *s, const char *str)
{
    return DetectEngineContentModifierBufferSetup(
            de_ctx, s, str, DETECT_AL_HTTP_URI, g_http_uri_buffer_id, ALPROTO_HTTP1);
}

static bool DetectHttpUriValidateCallback(const Signature *s, const char **sigerror)
{
    return DetectUrilenValidateContent(s, g_http_uri_buffer_id, sigerror);
}

static void DetectHttpUriSetupCallback(const DetectEngineCtx *de_ctx,
                                       Signature *s)
{
    SCLogDebug("callback invoked by %u", s->id);
    DetectUrilenApplyToContent(s, g_http_uri_buffer_id);
}

/**
 * \brief this function setup the http.uri keyword used in the rule
 *
 * \param de_ctx   Pointer to the Detection Engine Context
 * \param s        Pointer to the Signature to which the current keyword belongs
 * \param str      Should hold an empty string always
 *
 * \retval 0       On success
 */
static int DetectHttpUriSetupSticky(DetectEngineCtx *de_ctx, Signature *s, const char *str)
{
    if (DetectBufferSetActiveList(s, g_http_uri_buffer_id) < 0)
        return -1;
    if (DetectSignatureSetAppProto(s, ALPROTO_HTTP) < 0)
        return -1;
    return 0;
}

static InspectionBuffer *GetData(DetectEngineThreadCtx *det_ctx,
        const DetectEngineTransforms *transforms, Flow *_f,
        const uint8_t _flow_flags, void *txv, const int list_id)
{
    SCEnter();

    InspectionBuffer *buffer = InspectionBufferGet(det_ctx, list_id);
    if (buffer->inspect == NULL) {
        htp_tx_t *tx = (htp_tx_t *)txv;
        HtpTxUserData *tx_ud = htp_tx_get_user_data(tx);

        if (tx_ud == NULL || tx_ud->request_uri_normalized == NULL) {
            SCLogDebug("no tx_id or uri");
            return NULL;
        }

        const uint32_t data_len = bstr_len(tx_ud->request_uri_normalized);
        const uint8_t *data = bstr_ptr(tx_ud->request_uri_normalized);

        InspectionBufferSetup(det_ctx, list_id, buffer, data, data_len);
        InspectionBufferApplyTransforms(buffer, transforms);
    }

    return buffer;
}

static InspectionBuffer *GetData2(DetectEngineThreadCtx *det_ctx,
        const DetectEngineTransforms *transforms, Flow *_f, const uint8_t _flow_flags, void *txv,
        const int list_id)
{
    SCEnter();

    InspectionBuffer *buffer = InspectionBufferGet(det_ctx, list_id);
    if (buffer->inspect == NULL) {
        uint32_t b_len = 0;
        const uint8_t *b = NULL;

        if (rs_http2_tx_get_uri(txv, &b, &b_len) != 1)
            return NULL;
        if (b == NULL || b_len == 0)
            return NULL;

        InspectionBufferSetup(det_ctx, list_id, buffer, b, b_len);
        InspectionBufferApplyTransforms(buffer, transforms);
    }

    return buffer;
}

/**
 * \brief Sets up the http_raw_uri modifier keyword.
 *
 * \param de_ctx Pointer to the Detection Engine Context.
 * \param s      Pointer to the Signature to which the current keyword belongs.
 * \param arg    Should hold an empty string always.
 *
 * \retval  0 On success.
 * \retval -1 On failure.
 */
static int DetectHttpRawUriSetup(DetectEngineCtx *de_ctx, Signature *s, const char *arg)
{
    return DetectEngineContentModifierBufferSetup(
            de_ctx, s, arg, DETECT_AL_HTTP_RAW_URI, g_http_raw_uri_buffer_id, ALPROTO_HTTP1);
}

static bool DetectHttpRawUriValidateCallback(const Signature *s, const char **sigerror)
{
    return DetectUrilenValidateContent(s, g_http_raw_uri_buffer_id, sigerror);
}

static void DetectHttpRawUriSetupCallback(const DetectEngineCtx *de_ctx,
                                          Signature *s)
{
    SCLogDebug("callback invoked by %u", s->id);
    DetectUrilenApplyToContent(s, g_http_raw_uri_buffer_id);
}

/**
 * \brief this function setup the http.uri.raw keyword used in the rule
 *
 * \param de_ctx   Pointer to the Detection Engine Context
 * \param s        Pointer to the Signature to which the current keyword belongs
 * \param str      Should hold an empty string always
 *
 * \retval 0       On success
 */
static int DetectHttpRawUriSetupSticky(DetectEngineCtx *de_ctx, Signature *s, const char *str)
{
    if (DetectBufferSetActiveList(s, g_http_raw_uri_buffer_id) < 0)
        return -1;
    if (DetectSignatureSetAppProto(s, ALPROTO_HTTP) < 0)
        return -1;
    return 0;
}

static InspectionBuffer *GetRawData(DetectEngineThreadCtx *det_ctx,
        const DetectEngineTransforms *transforms, Flow *_f,
        const uint8_t _flow_flags, void *txv, const int list_id)
{
    SCEnter();

    InspectionBuffer *buffer = InspectionBufferGet(det_ctx, list_id);
    if (buffer->inspect == NULL) {
        htp_tx_t *tx = (htp_tx_t *)txv;
        if (unlikely(tx->request_uri == NULL)) {
            return NULL;
        }
        const uint32_t data_len = bstr_len(tx->request_uri);
        const uint8_t *data = bstr_ptr(tx->request_uri);

        InspectionBufferSetup(det_ctx, list_id, buffer, data, data_len);
        InspectionBufferApplyTransforms(buffer, transforms);
    }

    return buffer;
}

#ifdef UNITTESTS /* UNITTESTS */
#include "tests/detect-http-uri.c"
#endif /* UNITTESTS */

/**
 * @}
 */
