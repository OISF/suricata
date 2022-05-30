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
 * \author Anoop Saldanha <anoopsaldanha@gmail.com>
 *
 * Implements the http_stat_code keyword
 */

#include "suricata-common.h"
#include "threads.h"
#include "debug.h"
#include "decode.h"
#include "detect.h"

#include "detect-parse.h"
#include "detect-engine.h"
#include "detect-content.h"
#include "detect-pcre.h"
#include "detect-engine-mpm.h"
#include "detect-engine-prefilter.h"

#include "flow.h"
#include "flow-var.h"
#include "flow-util.h"

#include "util-debug.h"
#include "util-error.h"
#include "util-unittest.h"
#include "util-unittest-helper.h"
#include "util-spm.h"
#include "util-print.h"

#include "app-layer.h"
#include "app-layer-parser.h"

#include "app-layer-htp.h"
#include "detect-http-stat-code.h"
#include "stream-tcp-private.h"
#include "stream-tcp.h"

static int DetectHttpStatCodeSetup(DetectEngineCtx *, Signature *, const char *);
static int DetectHttpStatCodeSetupSticky(DetectEngineCtx *de_ctx, Signature *s, const char *str);
#ifdef UNITTESTS
static void DetectHttpStatCodeRegisterTests(void);
#endif
static int g_http_stat_code_buffer_id = 0;
static InspectionBuffer *GetData(DetectEngineThreadCtx *det_ctx,
        const DetectEngineTransforms *transforms, Flow *_f,
        const uint8_t _flow_flags, void *txv, const int list_id);
static InspectionBuffer *GetData2(DetectEngineThreadCtx *det_ctx,
        const DetectEngineTransforms *transforms, Flow *_f, const uint8_t _flow_flags, void *txv,
        const int list_id);

/**
 * \brief Registration function for keyword: http_stat_code
 */
void DetectHttpStatCodeRegister (void)
{
    /* http_stat_code content modifier */
    sigmatch_table[DETECT_AL_HTTP_STAT_CODE].name = "http_stat_code";
    sigmatch_table[DETECT_AL_HTTP_STAT_CODE].desc = "content modifier to match only on HTTP stat-code-buffer";
    sigmatch_table[DETECT_AL_HTTP_STAT_CODE].url = "/rules/http-keywords.html#http-stat-code";
    sigmatch_table[DETECT_AL_HTTP_STAT_CODE].Setup = DetectHttpStatCodeSetup;
#ifdef UNITTESTS
    sigmatch_table[DETECT_AL_HTTP_STAT_CODE].RegisterTests = DetectHttpStatCodeRegisterTests;
#endif
    sigmatch_table[DETECT_AL_HTTP_STAT_CODE].flags |= SIGMATCH_NOOPT|SIGMATCH_INFO_CONTENT_MODIFIER;
    sigmatch_table[DETECT_AL_HTTP_STAT_CODE].alternative = DETECT_HTTP_STAT_CODE;

    /* http.stat_code content modifier */
    sigmatch_table[DETECT_HTTP_STAT_CODE].name = "http.stat_code";
    sigmatch_table[DETECT_HTTP_STAT_CODE].desc = "sticky buffer to match only on HTTP stat-code-buffer";
    sigmatch_table[DETECT_HTTP_STAT_CODE].url = "/rules/http-keywords.html#http-stat-code";
    sigmatch_table[DETECT_HTTP_STAT_CODE].Setup = DetectHttpStatCodeSetupSticky;
    sigmatch_table[DETECT_HTTP_STAT_CODE].flags |= SIGMATCH_NOOPT|SIGMATCH_INFO_STICKY_BUFFER;

    DetectAppLayerInspectEngineRegister2("http_stat_code", ALPROTO_HTTP1, SIG_FLAG_TOCLIENT,
            HTP_RESPONSE_PROGRESS_LINE, DetectEngineInspectBufferGeneric, GetData);

    DetectAppLayerMpmRegister2("http_stat_code", SIG_FLAG_TOCLIENT, 4, PrefilterGenericMpmRegister,
            GetData, ALPROTO_HTTP1, HTP_RESPONSE_PROGRESS_LINE);

    DetectAppLayerInspectEngineRegister2("http_stat_code", ALPROTO_HTTP2, SIG_FLAG_TOCLIENT,
            HTTP2StateDataServer, DetectEngineInspectBufferGeneric, GetData2);

    DetectAppLayerMpmRegister2("http_stat_code", SIG_FLAG_TOCLIENT, 4, PrefilterGenericMpmRegister,
            GetData2, ALPROTO_HTTP2, HTTP2StateDataServer);

    DetectBufferTypeSetDescriptionByName("http_stat_code",
            "http response status code");

    g_http_stat_code_buffer_id = DetectBufferTypeGetByName("http_stat_code");
}

/**
 * \brief this function setups the http_stat_code modifier keyword used in the rule
 *
 * \param de_ctx   Pointer to the Detection Engine Context
 * \param s        Pointer to the Signature to which the current keyword belongs
 * \param str      Should hold an empty string always
 *
 * \retval  0 On success
 * \retval -1 On failure
 */

static int DetectHttpStatCodeSetup(DetectEngineCtx *de_ctx, Signature *s, const char *arg)
{
    return DetectEngineContentModifierBufferSetup(
            de_ctx, s, arg, DETECT_AL_HTTP_STAT_CODE, g_http_stat_code_buffer_id, ALPROTO_HTTP1);
}

/**
 * \brief this function setup the http.stat_code keyword used in the rule
 *
 * \param de_ctx   Pointer to the Detection Engine Context
 * \param s        Pointer to the Signature to which the current keyword belongs
 * \param str      Should hold an empty string always
 *
 * \retval 0       On success
 */
static int DetectHttpStatCodeSetupSticky(DetectEngineCtx *de_ctx, Signature *s, const char *str)
{
    if (DetectBufferSetActiveList(s, g_http_stat_code_buffer_id) < 0)
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

        if (htp_tx_response_status(tx) == NULL)
            return NULL;

        const uint32_t data_len = bstr_len(htp_tx_response_status(tx));
        const uint8_t *data = bstr_ptr(htp_tx_response_status(tx));

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

        if (rs_http2_tx_get_status(txv, &b, &b_len) != 1)
            return NULL;
        if (b == NULL || b_len == 0)
            return NULL;

        InspectionBufferSetup(det_ctx, list_id, buffer, b, b_len);
        InspectionBufferApplyTransforms(buffer, transforms);
    }

    return buffer;
}

#ifdef UNITTESTS
#include "tests/detect-http-stat-code.c"
#endif /* UNITTESTS */

/**
 * @}
 */
