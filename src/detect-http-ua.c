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
 * \author Anoop Saldanha <anoopsaldanha@gmail.com>
 *
 * Implements support for the http_user_agent keyword.
 */

#include "suricata-common.h"

#include "detect-engine.h"
#include "detect-engine-mpm.h"
#include "detect-engine-prefilter.h"
#include "detect-pcre.h"

#include "app-layer-htp.h"
#include "detect-http-ua.h"

#ifdef UNITTESTS
#include "stream-tcp.h"
#include "detect-content.h"
#endif
static int DetectHttpUASetup(DetectEngineCtx *, Signature *, const char *);
#ifdef UNITTESTS
static void DetectHttpUARegisterTests(void);
#endif
static int g_http_ua_buffer_id = 0;
static int DetectHttpUserAgentSetup(DetectEngineCtx *, Signature *, const char *);
static InspectionBuffer *GetData(DetectEngineThreadCtx *det_ctx,
        const DetectEngineTransforms *transforms,
        Flow *_f, const uint8_t _flow_flags,
        void *txv, const int list_id);
static InspectionBuffer *GetData2(DetectEngineThreadCtx *det_ctx,
        const DetectEngineTransforms *transforms, Flow *_f, const uint8_t _flow_flags, void *txv,
        const int list_id);

/**
 * \brief Registers the keyword handlers for the "http_user_agent" keyword.
 */
void DetectHttpUARegister(void)
{
    /* http_user_agent content modifier */
    sigmatch_table[DETECT_AL_HTTP_USER_AGENT].name = "http_user_agent";
    sigmatch_table[DETECT_AL_HTTP_USER_AGENT].desc = "content modifier to match only on the HTTP User-Agent header";
    sigmatch_table[DETECT_AL_HTTP_USER_AGENT].url = "/rules/http-keywords.html#http-user-agent";
    sigmatch_table[DETECT_AL_HTTP_USER_AGENT].Setup = DetectHttpUASetup;
#ifdef UNITTESTS
    sigmatch_table[DETECT_AL_HTTP_USER_AGENT].RegisterTests = DetectHttpUARegisterTests;
#endif
    sigmatch_table[DETECT_AL_HTTP_USER_AGENT].flags |= SIGMATCH_NOOPT;
    sigmatch_table[DETECT_AL_HTTP_USER_AGENT].flags |= SIGMATCH_INFO_CONTENT_MODIFIER;
    sigmatch_table[DETECT_AL_HTTP_USER_AGENT].alternative = DETECT_HTTP_UA;

    /* http.user_agent sticky buffer */
    sigmatch_table[DETECT_HTTP_UA].name = "http.user_agent";
    sigmatch_table[DETECT_HTTP_UA].desc = "sticky buffer to match specifically and only on the HTTP User Agent buffer";
    sigmatch_table[DETECT_HTTP_UA].url = "/rules/http-keywords.html#http-user-agent";
    sigmatch_table[DETECT_HTTP_UA].Setup = DetectHttpUserAgentSetup;
    sigmatch_table[DETECT_HTTP_UA].flags |= SIGMATCH_NOOPT;
    sigmatch_table[DETECT_HTTP_UA].flags |= SIGMATCH_INFO_STICKY_BUFFER;

    DetectAppLayerInspectEngineRegister2("http_user_agent", ALPROTO_HTTP1, SIG_FLAG_TOSERVER,
            HTP_REQUEST_HEADERS, DetectEngineInspectBufferGeneric, GetData);

    DetectAppLayerMpmRegister2("http_user_agent", SIG_FLAG_TOSERVER, 2, PrefilterGenericMpmRegister,
            GetData, ALPROTO_HTTP1, HTP_REQUEST_HEADERS);

    DetectAppLayerInspectEngineRegister2("http_user_agent", ALPROTO_HTTP2, SIG_FLAG_TOSERVER,
            HTTP2StateDataClient, DetectEngineInspectBufferGeneric, GetData2);

    DetectAppLayerMpmRegister2("http_user_agent", SIG_FLAG_TOSERVER, 2, PrefilterGenericMpmRegister,
            GetData2, ALPROTO_HTTP2, HTTP2StateDataClient);

    DetectBufferTypeSetDescriptionByName("http_user_agent",
            "http user agent");

    g_http_ua_buffer_id = DetectBufferTypeGetByName("http_user_agent");
}

/**
 * \brief The setup function for the http_user_agent keyword for a signature.
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
int DetectHttpUASetup(DetectEngineCtx *de_ctx, Signature *s, const char *arg)
{
    return DetectEngineContentModifierBufferSetup(
            de_ctx, s, arg, DETECT_AL_HTTP_USER_AGENT, g_http_ua_buffer_id, ALPROTO_HTTP1);
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
static int DetectHttpUserAgentSetup(DetectEngineCtx *de_ctx, Signature *s, const char *str)
{
    if (DetectBufferSetActiveList(s, g_http_ua_buffer_id) < 0)
        return -1;
    if (DetectSignatureSetAppProto(s, ALPROTO_HTTP) < 0)
        return -1;
    return 0;
}

static InspectionBuffer *GetData(DetectEngineThreadCtx *det_ctx,
        const DetectEngineTransforms *transforms, Flow *_f,
        const uint8_t _flow_flags, void *txv, const int list_id)
{
    InspectionBuffer *buffer = InspectionBufferGet(det_ctx, list_id);
    if (buffer->inspect == NULL) {
        htp_tx_t *tx = (htp_tx_t *)txv;

        if (tx->request_headers == NULL)
            return NULL;

        htp_header_t *h = (htp_header_t *)htp_table_get_c(tx->request_headers,
                "User-Agent");
        if (h == NULL || h->value == NULL) {
            SCLogDebug("HTTP UA header not present in this request");
            return NULL;
        }

        const uint32_t data_len = bstr_len(h->value);
        const uint8_t *data = bstr_ptr(h->value);

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

        if (rs_http2_tx_get_useragent(txv, &b, &b_len) != 1)
            return NULL;
        if (b == NULL || b_len == 0)
            return NULL;

        InspectionBufferSetup(det_ctx, list_id, buffer, b, b_len);
        InspectionBufferApplyTransforms(buffer, transforms);
    }

    return buffer;
}

#ifdef UNITTESTS
#include "tests/detect-http-user-agent.c"
#endif /* UNITTESTS */

/**
 * @}
 */
