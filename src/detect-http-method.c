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
 * \ingroup httplayer
 *
 * @{
 */


/**
 * \file
 *
 * \author Brian Rectanus <brectanu@gmail.com>
 *
 * Implements the http_method keyword
 */

#include "suricata-common.h"

#include "detect-engine.h"
#include "detect-engine-mpm.h"
#include "detect-engine-prefilter.h"
#include "detect-content.h"
#include "detect-pcre.h"

#include "app-layer-htp.h"
#include "detect-http-method.h"

#ifdef UNITTESTS
#include "stream-tcp.h"
#endif
static int g_http_method_buffer_id = 0;
static int DetectHttpMethodSetup(DetectEngineCtx *, Signature *, const char *);
static int DetectHttpMethodSetupSticky(DetectEngineCtx *de_ctx, Signature *s, const char *str);
#ifdef UNITTESTS
void DetectHttpMethodRegisterTests(void);
#endif
void DetectHttpMethodFree(void *);
static bool DetectHttpMethodValidateCallback(const Signature *s, const char **sigerror);
static InspectionBuffer *GetData(DetectEngineThreadCtx *det_ctx,
        const DetectEngineTransforms *transforms, Flow *_f,
        const uint8_t _flow_flags, void *txv, const int list_id);
static InspectionBuffer *GetData2(DetectEngineThreadCtx *det_ctx,
        const DetectEngineTransforms *transforms, Flow *_f, const uint8_t _flow_flags, void *txv,
        const int list_id);

/**
 * \brief Registration function for keyword: http_method
 */
void DetectHttpMethodRegister(void)
{
    /* http_method content modifier */
    sigmatch_table[DETECT_AL_HTTP_METHOD].name = "http_method";
    sigmatch_table[DETECT_AL_HTTP_METHOD].desc = "content modifier to match only on the HTTP method-buffer";
    sigmatch_table[DETECT_AL_HTTP_METHOD].url = "/rules/http-keywords.html#http-method";
    sigmatch_table[DETECT_AL_HTTP_METHOD].Match = NULL;
    sigmatch_table[DETECT_AL_HTTP_METHOD].Setup = DetectHttpMethodSetup;
#ifdef UNITTESTS
    sigmatch_table[DETECT_AL_HTTP_METHOD].RegisterTests = DetectHttpMethodRegisterTests;
#endif
    sigmatch_table[DETECT_AL_HTTP_METHOD].flags |= SIGMATCH_NOOPT|SIGMATCH_INFO_CONTENT_MODIFIER;
    sigmatch_table[DETECT_AL_HTTP_METHOD].alternative = DETECT_HTTP_METHOD;

    /* http.method sticky buffer */
    sigmatch_table[DETECT_HTTP_METHOD].name = "http.method";
    sigmatch_table[DETECT_HTTP_METHOD].desc = "sticky buffer to match specifically and only on the HTTP method buffer";
    sigmatch_table[DETECT_HTTP_METHOD].url = "/rules/http-keywords.html#http-method";
    sigmatch_table[DETECT_HTTP_METHOD].Setup = DetectHttpMethodSetupSticky;
    sigmatch_table[DETECT_HTTP_METHOD].flags |= SIGMATCH_NOOPT|SIGMATCH_INFO_STICKY_BUFFER;

    DetectAppLayerInspectEngineRegister2("http_method", ALPROTO_HTTP1, SIG_FLAG_TOSERVER,
            HTP_REQUEST_LINE, DetectEngineInspectBufferGeneric, GetData);

    DetectAppLayerMpmRegister2("http_method", SIG_FLAG_TOSERVER, 4, PrefilterGenericMpmRegister,
            GetData, ALPROTO_HTTP1, HTP_REQUEST_LINE);

    DetectAppLayerInspectEngineRegister2("http_method", ALPROTO_HTTP2, SIG_FLAG_TOSERVER,
            HTTP2StateDataClient, DetectEngineInspectBufferGeneric, GetData2);

    DetectAppLayerMpmRegister2("http_method", SIG_FLAG_TOSERVER, 4, PrefilterGenericMpmRegister,
            GetData2, ALPROTO_HTTP2, HTTP2StateDataClient);

    DetectBufferTypeSetDescriptionByName("http_method",
            "http request method");

    DetectBufferTypeRegisterValidateCallback("http_method",
            DetectHttpMethodValidateCallback);

    g_http_method_buffer_id = DetectBufferTypeGetByName("http_method");

    SCLogDebug("registering http_method rule option");
}

/**
 * \brief This function is used to add the parsed "http_method" option
 *        into the current signature.
 *
 * \param de_ctx Pointer to the Detection Engine Context.
 * \param s      Pointer to the Current Signature.
 * \param str    Pointer to the user provided option string.
 *
 * \retval  0 on Success.
 * \retval -1 on Failure.
 */
static int DetectHttpMethodSetup(DetectEngineCtx *de_ctx, Signature *s, const char *str)
{
    return DetectEngineContentModifierBufferSetup(
            de_ctx, s, str, DETECT_AL_HTTP_METHOD, g_http_method_buffer_id, ALPROTO_HTTP1);
}

/**
 * \brief this function setup the http.method keyword used in the rule
 *
 * \param de_ctx   Pointer to the Detection Engine Context
 * \param s        Pointer to the Signature to which the current keyword belongs
 * \param str      Should hold an empty string always
 *
 * \retval 0       On success
 */
static int DetectHttpMethodSetupSticky(DetectEngineCtx *de_ctx, Signature *s, const char *str)
{
    if (DetectBufferSetActiveList(s, g_http_method_buffer_id) < 0)
        return -1;

    if (DetectSignatureSetAppProto(s, ALPROTO_HTTP) < 0)
        return -1;

    return 0;
}

/**
 *  \retval 1 valid
 *  \retval 0 invalid
 */
static bool DetectHttpMethodValidateCallback(const Signature *s, const char **sigerror)
{
    const SigMatch *sm = s->init_data->smlists[g_http_method_buffer_id];
    for ( ; sm != NULL; sm = sm->next) {
        if (sm->type != DETECT_CONTENT)
            continue;
        const DetectContentData *cd = (const DetectContentData *)sm->ctx;
        if (cd->content && cd->content_len) {
            if (cd->content[cd->content_len-1] == 0x20) {
                *sigerror = "http_method pattern with trailing space";
                SCLogError(SC_ERR_INVALID_SIGNATURE, "%s", *sigerror);
                return false;
            } else if (cd->content[0] == 0x20) {
                *sigerror = "http_method pattern with leading space";
                SCLogError(SC_ERR_INVALID_SIGNATURE, "%s", *sigerror);
                return false;
            } else if (cd->content[cd->content_len-1] == 0x09) {
                *sigerror = "http_method pattern with trailing tab";
                SCLogError(SC_ERR_INVALID_SIGNATURE, "%s", *sigerror);
                return false;
            } else if (cd->content[0] == 0x09) {
                *sigerror = "http_method pattern with leading tab";
                SCLogError(SC_ERR_INVALID_SIGNATURE, "%s", *sigerror);
                return false;
            }
        }
    }
    return true;
}

static InspectionBuffer *GetData(DetectEngineThreadCtx *det_ctx,
        const DetectEngineTransforms *transforms, Flow *_f,
        const uint8_t _flow_flags, void *txv, const int list_id)
{
    InspectionBuffer *buffer = InspectionBufferGet(det_ctx, list_id);
    if (buffer->inspect == NULL) {
        htp_tx_t *tx = (htp_tx_t *)txv;

        if (tx->request_method == NULL)
            return NULL;

        const uint32_t data_len = bstr_len(tx->request_method);
        const uint8_t *data = bstr_ptr(tx->request_method);

        InspectionBufferSetup(det_ctx, list_id, buffer, data, data_len);
        InspectionBufferApplyTransforms(buffer, transforms);
    }

    return buffer;
}

static InspectionBuffer *GetData2(DetectEngineThreadCtx *det_ctx,
        const DetectEngineTransforms *transforms, Flow *_f, const uint8_t _flow_flags, void *txv,
        const int list_id)
{
    InspectionBuffer *buffer = InspectionBufferGet(det_ctx, list_id);
    if (buffer->inspect == NULL) {
        uint32_t b_len = 0;
        const uint8_t *b = NULL;

        if (rs_http2_tx_get_method(txv, &b, &b_len) != 1)
            return NULL;
        if (b == NULL || b_len == 0)
            return NULL;

        InspectionBufferSetup(det_ctx, list_id, buffer, b, b_len);
        InspectionBufferApplyTransforms(buffer, transforms);
    }

    return buffer;
}

#ifdef UNITTESTS
#include "tests/detect-http-method.c"
#endif

/**
 * @}
 */
