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
 * Implements support for the http_response_line keyword.
 */

#include "suricata-common.h"
#ifdef UNITTESTS
#include "util-unittest.h"
#endif

#include "detect-engine.h"
#include "detect-engine-mpm.h"
#include "detect-engine-prefilter.h"
#include "detect-pcre.h"

#include "detect-http-response-line.h"

static int DetectHttpResponseLineSetup(DetectEngineCtx *, Signature *, const char *);
#ifdef UNITTESTS
static void DetectHttpResponseLineRegisterTests(void);
#endif
static InspectionBuffer *GetData(DetectEngineThreadCtx *det_ctx,
        const DetectEngineTransforms *transforms,
        Flow *_f, const uint8_t _flow_flags,
        void *txv, const int list_id);
static int g_http_response_line_id = 0;

/**
 * \brief Registers the keyword handlers for the "http_response_line" keyword.
 */
void DetectHttpResponseLineRegister(void)
{
    sigmatch_table[DETECT_AL_HTTP_RESPONSE_LINE].name = "http.response_line";
    sigmatch_table[DETECT_AL_HTTP_RESPONSE_LINE].alias = "http_response_line";
    sigmatch_table[DETECT_AL_HTTP_RESPONSE_LINE].desc = "content modifier to match only on the HTTP response line";
    sigmatch_table[DETECT_AL_HTTP_RESPONSE_LINE].url = "/rules/http-keywords.html#http-response-line";
    sigmatch_table[DETECT_AL_HTTP_RESPONSE_LINE].Setup = DetectHttpResponseLineSetup;
#ifdef UNITTESTS
    sigmatch_table[DETECT_AL_HTTP_RESPONSE_LINE].RegisterTests = DetectHttpResponseLineRegisterTests;
#endif
    sigmatch_table[DETECT_AL_HTTP_RESPONSE_LINE].flags |= SIGMATCH_NOOPT|SIGMATCH_INFO_STICKY_BUFFER;

    DetectAppLayerInspectEngineRegister2("http_response_line", ALPROTO_HTTP1, SIG_FLAG_TOCLIENT,
            HTP_RESPONSE_LINE, DetectEngineInspectBufferGeneric, GetData);

    DetectAppLayerMpmRegister2("http_response_line", SIG_FLAG_TOCLIENT, 2,
            PrefilterGenericMpmRegister, GetData, ALPROTO_HTTP1, HTP_RESPONSE_LINE);

    DetectBufferTypeSetDescriptionByName("http_response_line",
            "http response line");

    g_http_response_line_id = DetectBufferTypeGetByName("http_response_line");
}

/**
 * \brief The setup function for the http_response_line keyword for a signature.
 *
 * \param de_ctx Pointer to the detection engine context.
 * \param s      Pointer to the signature for the current Signature being
 *               parsed from the rules.
 * \param m      Pointer to the head of the SigMatch for the current rule
 *               being parsed.
 * \param arg    Pointer to the string holding the keyword value.
 *
 * \retval  0 On success
 * \retval -1 On failure
 */
static int DetectHttpResponseLineSetup(DetectEngineCtx *de_ctx, Signature *s, const char *arg)
{
    if (DetectBufferSetActiveList(s, g_http_response_line_id) < 0)
        return -1;

    if (DetectSignatureSetAppProto(s, ALPROTO_HTTP1) < 0)
        return -1;

    return 0;
}

static InspectionBuffer *GetData(DetectEngineThreadCtx *det_ctx,
        const DetectEngineTransforms *transforms,
        Flow *_f, const uint8_t _flow_flags,
        void *txv, const int list_id)
{
    InspectionBuffer *buffer = InspectionBufferGet(det_ctx, list_id);
    if (buffer->inspect == NULL) {
        htp_tx_t *tx = (htp_tx_t *)txv;
        if (unlikely(tx->response_line == NULL)) {
            return NULL;
        }
        const uint32_t data_len = bstr_len(tx->response_line);
        const uint8_t *data = bstr_ptr(tx->response_line);

        InspectionBufferSetup(det_ctx, list_id, buffer, data, data_len);
        InspectionBufferApplyTransforms(buffer, transforms);
    }
    return buffer;
}

/************************************Unittests*********************************/

#ifdef UNITTESTS

/**
 * \test Test that a signature containting a http_response_line is correctly parsed
 *       and the keyword is registered.
 */
static int DetectHttpResponseLineTest01(void)
{
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(http_response_line; content:\"200 OK\"; sid:1;)");
    FAIL_IF_NULL(de_ctx->sig_list);

    DetectEngineCtxFree(de_ctx);
    PASS;
}

void DetectHttpResponseLineRegisterTests(void)
{
    UtRegisterTest("DetectHttpResponseLineTest01", DetectHttpResponseLineTest01);
}
#endif /* UNITTESTS */
/**
 * @}
 */
