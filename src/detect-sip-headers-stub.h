/* Copyright (C) 2024 Open Information Security Foundation
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
 * \author Giuseppe Longo <giuseppe@glongo.it>
 *
 * Stub for per SIP header detection keyword.
 */

#include "suricata-common.h"
#include "flow.h"

#include "detect.h"
#include "detect-parse.h"
#include "detect-engine.h"
#include "detect-engine-mpm.h"
#include "detect-engine-prefilter.h"
#include "detect-engine-content-inspection.h"

#include "rust.h"

static int g_buffer_id = 0;

#ifdef KEYWORD_TOSERVER
static InspectionBuffer *GetRequestData(DetectEngineThreadCtx *det_ctx,
        const DetectEngineTransforms *transforms, Flow *_f, const uint8_t _flow_flags, void *txv,
        const int list_id, uint32_t local_id)
{
    SCEnter();

    InspectionBuffer *buffer = InspectionBufferMultipleForListGet(det_ctx, list_id, local_id);
    if (buffer->inspect == NULL) {
        uint32_t b_len = 0;
        const uint8_t *b = NULL;

        if (rs_sip_tx_get_header_value(txv, local_id, STREAM_TOSERVER, HEADER_NAME, &b, &b_len) !=
                1) {
            InspectionBufferSetupMultiEmpty(buffer);
            return NULL;
        }
        if (b == NULL || b_len == 0) {
            InspectionBufferSetupMultiEmpty(buffer);
            return NULL;
        }

        InspectionBufferSetupMulti(buffer, transforms, b, b_len);
        buffer->flags = DETECT_CI_FLAGS_SINGLE;
    }

    return buffer;
}

#endif
#ifdef KEYWORD_TOCLIENT
static InspectionBuffer *GetResponseData(DetectEngineThreadCtx *det_ctx,
        const DetectEngineTransforms *transforms, Flow *_f, const uint8_t _flow_flags, void *txv,
        const int list_id, uint32_t local_id)
{
    SCEnter();

    InspectionBuffer *buffer = InspectionBufferMultipleForListGet(det_ctx, list_id, local_id);
    if (buffer->inspect == NULL) {
        uint32_t b_len = 0;
        const uint8_t *b = NULL;

        if (rs_sip_tx_get_header_value(txv, local_id, STREAM_TOCLIENT, HEADER_NAME, &b, &b_len) !=
                1) {
            InspectionBufferSetupMultiEmpty(buffer);
            return NULL;
        }
        if (b == NULL || b_len == 0) {
            InspectionBufferSetupMultiEmpty(buffer);
            return NULL;
        }

        InspectionBufferSetupMulti(buffer, transforms, b, b_len);
        buffer->flags = DETECT_CI_FLAGS_SINGLE;
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
static int DetectSipHeadersSetupSticky(DetectEngineCtx *de_ctx, Signature *s, const char *str)
{
    if (DetectBufferSetActiveList(de_ctx, s, g_buffer_id) < 0)
        return -1;

    if (DetectSignatureSetAppProto(s, ALPROTO_SIP) < 0)
        return -1;

    return 0;
}

static void DetectSipHeadersRegisterStub(void)
{
    sigmatch_table[KEYWORD_ID].name = KEYWORD_NAME;
    sigmatch_table[KEYWORD_ID].desc = KEYWORD_NAME " sticky buffer for the " BUFFER_DESC;
    sigmatch_table[KEYWORD_ID].url = "/rules/" KEYWORD_DOC;
    sigmatch_table[KEYWORD_ID].Setup = DetectSipHeadersSetupSticky;
    sigmatch_table[KEYWORD_ID].flags |= SIGMATCH_NOOPT | SIGMATCH_INFO_STICKY_BUFFER;

#ifdef KEYWORD_TOSERVER
    DetectAppLayerMultiRegister(
            BUFFER_NAME, ALPROTO_SIP, SIG_FLAG_TOSERVER, 0, GetRequestData, 2, 1);
#endif
#ifdef KEYWORD_TOCLIENT
    DetectAppLayerMultiRegister(
            BUFFER_NAME, ALPROTO_SIP, SIG_FLAG_TOCLIENT, 0, GetResponseData, 2, 1);
#endif

    DetectBufferTypeSetDescriptionByName(BUFFER_NAME, BUFFER_DESC);

    DetectBufferTypeSupportsMultiInstance(BUFFER_NAME);

    g_buffer_id = DetectBufferTypeGetByName(BUFFER_NAME);
}
