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
 * \author Anoop Saldanha <anoopsaldanha@gmail.com>
 *
 * Implements support for the http_host keyword.
 */

#include "suricata-common.h"

#include "detect-engine.h"
#include "detect-engine-mpm.h"
#include "detect-engine-prefilter.h"
#include "detect-content.h"
#include "detect-pcre.h"

#include "app-layer-htp.h"
#include "detect-http-host.h"

#ifdef UNITTESTS
#include "stream-tcp.h"
#endif
static int DetectHttpHHSetup(DetectEngineCtx *, Signature *, const char *);
#ifdef UNITTESTS
static void DetectHttpHHRegisterTests(void);
#endif
static bool DetectHttpHostValidateCallback(const Signature *s, const char **sigerror);
static int DetectHttpHostSetup(DetectEngineCtx *, Signature *, const char *);
static InspectionBuffer *GetData(DetectEngineThreadCtx *det_ctx,
        const DetectEngineTransforms *transforms,
        Flow *_f, const uint8_t _flow_flags,
        void *txv, const int list_id);
static InspectionBuffer *GetData2(DetectEngineThreadCtx *det_ctx,
        const DetectEngineTransforms *transforms, Flow *_f, const uint8_t _flow_flags, void *txv,
        const int list_id);
static int DetectHttpHRHSetup(DetectEngineCtx *, Signature *, const char *);
static int g_http_raw_host_buffer_id = 0;
static int DetectHttpHostRawSetupSticky(DetectEngineCtx *de_ctx, Signature *s, const char *str);
static InspectionBuffer *GetRawData(DetectEngineThreadCtx *det_ctx,
        const DetectEngineTransforms *transforms, Flow *_f,
        const uint8_t _flow_flags, void *txv, const int list_id);
static InspectionBuffer *GetRawData2(DetectEngineThreadCtx *det_ctx,
        const DetectEngineTransforms *transforms, Flow *_f, const uint8_t _flow_flags, void *txv,
        const int list_id);
static int g_http_host_buffer_id = 0;

/**
 * \brief Registers the keyword handlers for the "http_host" keyword.
 */
void DetectHttpHHRegister(void)
{
    /* http_host content modifier */
    sigmatch_table[DETECT_AL_HTTP_HOST].name = "http_host";
    sigmatch_table[DETECT_AL_HTTP_HOST].desc = "content modifier to match on the HTTP hostname";
    sigmatch_table[DETECT_AL_HTTP_HOST].url = "/rules/http-keywords.html#http-host-and-http-raw-host";
    sigmatch_table[DETECT_AL_HTTP_HOST].Setup = DetectHttpHHSetup;
#ifdef UNITTESTS
    sigmatch_table[DETECT_AL_HTTP_HOST].RegisterTests = DetectHttpHHRegisterTests;
#endif
    sigmatch_table[DETECT_AL_HTTP_HOST].flags |= SIGMATCH_NOOPT|SIGMATCH_INFO_CONTENT_MODIFIER;
    sigmatch_table[DETECT_AL_HTTP_HOST].alternative = DETECT_HTTP_HOST;

    /* http.host sticky buffer */
    sigmatch_table[DETECT_HTTP_HOST].name = "http.host";
    sigmatch_table[DETECT_HTTP_HOST].desc = "sticky buffer to match on the HTTP Host buffer";
    sigmatch_table[DETECT_HTTP_HOST].url = "/rules/http-keywords.html#http-host-and-http-raw-host";
    sigmatch_table[DETECT_HTTP_HOST].Setup = DetectHttpHostSetup;
    sigmatch_table[DETECT_HTTP_HOST].flags |= SIGMATCH_NOOPT|SIGMATCH_INFO_STICKY_BUFFER;

    DetectAppLayerInspectEngineRegister2("http_host", ALPROTO_HTTP1, SIG_FLAG_TOSERVER,
            HTP_REQUEST_HEADERS, DetectEngineInspectBufferGeneric, GetData);

    DetectAppLayerMpmRegister2("http_host", SIG_FLAG_TOSERVER, 2, PrefilterGenericMpmRegister,
            GetData, ALPROTO_HTTP1, HTP_REQUEST_HEADERS);

    DetectAppLayerInspectEngineRegister2("http_host", ALPROTO_HTTP2, SIG_FLAG_TOSERVER,
            HTTP2StateDataClient, DetectEngineInspectBufferGeneric, GetData2);

    DetectAppLayerMpmRegister2("http_host", SIG_FLAG_TOSERVER, 2, PrefilterGenericMpmRegister,
            GetData2, ALPROTO_HTTP2, HTTP2StateDataClient);

    DetectBufferTypeRegisterValidateCallback("http_host",
            DetectHttpHostValidateCallback);

    DetectBufferTypeSetDescriptionByName("http_host",
            "http host");

    g_http_host_buffer_id = DetectBufferTypeGetByName("http_host");

    /* http_raw_host content modifier */
    sigmatch_table[DETECT_AL_HTTP_RAW_HOST].name = "http_raw_host";
    sigmatch_table[DETECT_AL_HTTP_RAW_HOST].desc = "content modifier to match on the HTTP host header or the raw hostname from the HTTP uri";
    sigmatch_table[DETECT_AL_HTTP_RAW_HOST].url = "/rules/http-keywords.html#http-host-and-http-raw-host";
    sigmatch_table[DETECT_AL_HTTP_RAW_HOST].Setup = DetectHttpHRHSetup;
    sigmatch_table[DETECT_AL_HTTP_RAW_HOST].flags |= SIGMATCH_NOOPT|SIGMATCH_INFO_CONTENT_MODIFIER;
    sigmatch_table[DETECT_AL_HTTP_RAW_HOST].alternative = DETECT_HTTP_HOST_RAW;

    /* http.host sticky buffer */
    sigmatch_table[DETECT_HTTP_HOST_RAW].name = "http.host.raw";
    sigmatch_table[DETECT_HTTP_HOST_RAW].desc = "sticky buffer to match on the HTTP host header or the raw hostname from the HTTP uri";
    sigmatch_table[DETECT_HTTP_HOST_RAW].url = "/rules/http-keywords.html#http-host-and-http-raw-host";
    sigmatch_table[DETECT_HTTP_HOST_RAW].Setup = DetectHttpHostRawSetupSticky;
    sigmatch_table[DETECT_HTTP_HOST_RAW].flags |= SIGMATCH_NOOPT|SIGMATCH_INFO_STICKY_BUFFER;

    DetectAppLayerInspectEngineRegister2("http_raw_host", ALPROTO_HTTP1, SIG_FLAG_TOSERVER,
            HTP_REQUEST_HEADERS, DetectEngineInspectBufferGeneric, GetRawData);

    DetectAppLayerMpmRegister2("http_raw_host", SIG_FLAG_TOSERVER, 2, PrefilterGenericMpmRegister,
            GetRawData, ALPROTO_HTTP1, HTP_REQUEST_HEADERS);

    DetectAppLayerInspectEngineRegister2("http_raw_host", ALPROTO_HTTP2, SIG_FLAG_TOSERVER,
            HTTP2StateDataClient, DetectEngineInspectBufferGeneric, GetRawData2);

    DetectAppLayerMpmRegister2("http_raw_host", SIG_FLAG_TOSERVER, 2, PrefilterGenericMpmRegister,
            GetRawData2, ALPROTO_HTTP2, HTTP2StateDataClient);

    DetectBufferTypeSetDescriptionByName("http_raw_host",
            "http raw host header");

    g_http_raw_host_buffer_id = DetectBufferTypeGetByName("http_raw_host");
}

/**
 * \brief The setup function for the http_host keyword for a signature.
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
static int DetectHttpHHSetup(DetectEngineCtx *de_ctx, Signature *s, const char *arg)
{
    return DetectEngineContentModifierBufferSetup(
            de_ctx, s, arg, DETECT_AL_HTTP_HOST, g_http_host_buffer_id, ALPROTO_HTTP1);
}

static bool DetectHttpHostValidateCallback(const Signature *s, const char **sigerror)
{
    const SigMatch *sm = s->init_data->smlists[g_http_host_buffer_id];
    for ( ; sm != NULL; sm = sm->next) {
        if (sm->type == DETECT_CONTENT) {
            DetectContentData *cd = (DetectContentData *)sm->ctx;
            if (cd->flags & DETECT_CONTENT_NOCASE) {
                *sigerror = "http.host keyword "
                            "specified along with \"nocase\". "
                            "The hostname buffer is normalized "
                            "to lowercase, specifying "
                            "nocase is redundant.";
                SCLogWarning(SC_WARN_POOR_RULE, "rule %u: %s", s->id, *sigerror);
                return false;
            } else {
                uint32_t u;
                for (u = 0; u < cd->content_len; u++) {
                    if (isupper(cd->content[u]))
                        break;
                }
                if (u != cd->content_len) {
                    *sigerror = "A pattern with "
                                "uppercase chararacters detected for http.host. "
                                "The hostname buffer is normalized to lowercase, "
                                "please specify a lowercase pattern.";
                    SCLogWarning(SC_WARN_POOR_RULE, "rule %u: %s", s->id, *sigerror);
                    return false;
                }
            }
        }
    }

    return true;
}

/**
 * \brief this function setup the http.host keyword used in the rule
 *
 * \param de_ctx   Pointer to the Detection Engine Context
 * \param s        Pointer to the Signature to which the current keyword belongs
 * \param str      Should hold an empty string always
 *
 * \retval 0       On success
 */
static int DetectHttpHostSetup(DetectEngineCtx *de_ctx, Signature *s, const char *str)
{
    if (DetectBufferSetActiveList(s, g_http_host_buffer_id) < 0)
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

        if (tx->request_hostname == NULL)
            return NULL;

        const uint32_t data_len = bstr_len(tx->request_hostname);
        const uint8_t *data = bstr_ptr(tx->request_hostname);

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

        if (rs_http2_tx_get_host_norm(txv, &b, &b_len) != 1)
            return NULL;
        if (b == NULL || b_len == 0)
            return NULL;

        InspectionBufferSetup(det_ctx, list_id, buffer, b, b_len);
        InspectionBufferApplyTransforms(buffer, transforms);
    }

    return buffer;
}

static InspectionBuffer *GetRawData2(DetectEngineThreadCtx *det_ctx,
        const DetectEngineTransforms *transforms, Flow *_f, const uint8_t _flow_flags, void *txv,
        const int list_id)
{
    InspectionBuffer *buffer = InspectionBufferGet(det_ctx, list_id);
    if (buffer->inspect == NULL) {
        uint32_t b_len = 0;
        const uint8_t *b = NULL;

        if (rs_http2_tx_get_host(txv, &b, &b_len) != 1)
            return NULL;
        if (b == NULL || b_len == 0)
            return NULL;

        InspectionBufferSetup(det_ctx, list_id, buffer, b, b_len);
        InspectionBufferApplyTransforms(buffer, transforms);
    }

    return buffer;
}

/**
 * \brief The setup function for the http_raw_host keyword for a signature.
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
int DetectHttpHRHSetup(DetectEngineCtx *de_ctx, Signature *s, const char *arg)
{
    return DetectEngineContentModifierBufferSetup(
            de_ctx, s, arg, DETECT_AL_HTTP_RAW_HOST, g_http_raw_host_buffer_id, ALPROTO_HTTP1);
}

/**
 * \brief this function setup the http.host keyword used in the rule
 *
 * \param de_ctx   Pointer to the Detection Engine Context
 * \param s        Pointer to the Signature to which the current keyword belongs
 * \param str      Should hold an empty string always
 *
 * \retval 0       On success
 */
static int DetectHttpHostRawSetupSticky(DetectEngineCtx *de_ctx, Signature *s, const char *str)
{
    if (DetectBufferSetActiveList(s, g_http_raw_host_buffer_id) < 0)
        return -1;
    if (DetectSignatureSetAppProto(s, ALPROTO_HTTP) < 0)
        return -1;
    return 0;
}

static InspectionBuffer *GetRawData(DetectEngineThreadCtx *det_ctx,
        const DetectEngineTransforms *transforms, Flow *_f,
        const uint8_t _flow_flags, void *txv, const int list_id)
{
    InspectionBuffer *buffer = InspectionBufferGet(det_ctx, list_id);
    if (buffer->inspect == NULL) {
        htp_tx_t *tx = (htp_tx_t *)txv;

        const uint8_t *data = NULL;
        uint32_t data_len = 0;

        if (tx->parsed_uri == NULL || tx->parsed_uri->hostname == NULL) {
            if (tx->request_headers == NULL)
                return NULL;

            htp_header_t *h = (htp_header_t *)htp_table_get_c(tx->request_headers,
                    "Host");
            if (h == NULL || h->value == NULL)
                return NULL;

            data = (const uint8_t *)bstr_ptr(h->value);
            data_len = bstr_len(h->value);
        } else {
            data = (const uint8_t *)bstr_ptr(tx->parsed_uri->hostname);
            data_len = bstr_len(tx->parsed_uri->hostname);
        }

        InspectionBufferSetup(det_ctx, list_id, buffer, data, data_len);
        InspectionBufferApplyTransforms(buffer, transforms);
    }

    return buffer;
}

/************************************Unittests*********************************/

#ifdef UNITTESTS
#include "tests/detect-http-host.c"
#endif /* UNITTESTS */

/**
 * @}
 */
