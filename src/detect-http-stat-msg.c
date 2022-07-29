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
 * Implements the http_stat_msg keyword
 */

#include "suricata-common.h"

#include "detect-engine.h"
#include "detect-content.h"
#include "detect-pcre.h"
#include "detect-engine-mpm.h"
#include "detect-engine-prefilter.h"

#include "detect-http-stat-msg.h"
#include "stream-tcp.h"

static int DetectHttpStatMsgSetup(DetectEngineCtx *, Signature *, const char *);
#ifdef UNITTESTS
static void DetectHttpStatMsgRegisterTests(void);
#endif
static int g_http_stat_msg_buffer_id = 0;
static InspectionBuffer *GetData(DetectEngineThreadCtx *det_ctx,
        const DetectEngineTransforms *transforms, Flow *_f,
        const uint8_t _flow_flags, void *txv, const int list_id);
static int DetectHttpStatMsgSetupSticky(DetectEngineCtx *de_ctx, Signature *s, const char *str);

/**
 * \brief Registration function for keyword: http_stat_msg
 */
void DetectHttpStatMsgRegister (void)
{
    /* http_stat_msg content modifier */
    sigmatch_table[DETECT_AL_HTTP_STAT_MSG].name = "http_stat_msg";
    sigmatch_table[DETECT_AL_HTTP_STAT_MSG].desc = "content modifier to match on HTTP stat-msg-buffer";
    sigmatch_table[DETECT_AL_HTTP_STAT_MSG].url = "/rules/http-keywords.html#http-stat-msg";
    sigmatch_table[DETECT_AL_HTTP_STAT_MSG].Setup = DetectHttpStatMsgSetup;
#ifdef UNITTESTS
    sigmatch_table[DETECT_AL_HTTP_STAT_MSG].RegisterTests = DetectHttpStatMsgRegisterTests;
#endif
    sigmatch_table[DETECT_AL_HTTP_STAT_MSG].flags |= SIGMATCH_NOOPT|SIGMATCH_INFO_CONTENT_MODIFIER;
    sigmatch_table[DETECT_AL_HTTP_STAT_MSG].alternative = DETECT_HTTP_STAT_MSG;

    /* http.stat_msg sticky buffer */
    sigmatch_table[DETECT_HTTP_STAT_MSG].name = "http.stat_msg";
    sigmatch_table[DETECT_HTTP_STAT_MSG].desc = "sticky buffer to match on the HTTP response status message";
    sigmatch_table[DETECT_HTTP_STAT_MSG].url = "/rules/http-keywords.html#http-stat-msg";
    sigmatch_table[DETECT_HTTP_STAT_MSG].Setup = DetectHttpStatMsgSetupSticky;
    sigmatch_table[DETECT_HTTP_STAT_MSG].flags |= SIGMATCH_NOOPT|SIGMATCH_INFO_STICKY_BUFFER;

    DetectAppLayerInspectEngineRegister2("http_stat_msg", ALPROTO_HTTP1, SIG_FLAG_TOCLIENT,
            HTP_RESPONSE_LINE, DetectEngineInspectBufferGeneric, GetData);

    DetectAppLayerMpmRegister2("http_stat_msg", SIG_FLAG_TOCLIENT, 3, PrefilterGenericMpmRegister,
            GetData, ALPROTO_HTTP1, HTP_RESPONSE_LINE);

    DetectBufferTypeSetDescriptionByName("http_stat_msg",
            "http response status message");

    g_http_stat_msg_buffer_id = DetectBufferTypeGetByName("http_stat_msg");
}

/**
 * \brief this function setups the http_stat_msg modifier keyword used in the rule
 *
 * \param de_ctx   Pointer to the Detection Engine Context
 * \param s        Pointer to the Signature to which the current keyword belongs
 * \param str      Should hold an empty string always
 *
 * \retval  0 On success
 * \retval -1 On failure
 */

static int DetectHttpStatMsgSetup(DetectEngineCtx *de_ctx, Signature *s, const char *arg)
{
    return DetectEngineContentModifierBufferSetup(
            de_ctx, s, arg, DETECT_AL_HTTP_STAT_MSG, g_http_stat_msg_buffer_id, ALPROTO_HTTP1);
}

/**
 * \brief this function setup the http.stat_msg keyword used in the rule
 *
 * \param de_ctx   Pointer to the Detection Engine Context
 * \param s        Pointer to the Signature to which the current keyword belongs
 * \param str      Should hold an empty string always
 *
 * \retval 0       On success
 */
static int DetectHttpStatMsgSetupSticky(DetectEngineCtx *de_ctx, Signature *s, const char *str)
{
    if (DetectBufferSetActiveList(s, g_http_stat_msg_buffer_id) < 0)
        return -1;
    if (DetectSignatureSetAppProto(s, ALPROTO_HTTP1) < 0)
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

        if (tx->response_message == NULL)
            return NULL;

        const uint32_t data_len = bstr_len(tx->response_message);
        const uint8_t *data = bstr_ptr(tx->response_message);

        InspectionBufferSetup(det_ctx, list_id, buffer, data, data_len);
        InspectionBufferApplyTransforms(buffer, transforms);
    }

    return buffer;
}

#ifdef UNITTESTS
#include "tests/detect-http-stat-msg.c"
#endif /* UNITTESTS */

/**
 * @}
 */
