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
 * Implements support http_protocol sticky buffer
 */

#include "suricata-common.h"
#include "threads.h"
#include "decode.h"

#include "detect.h"
#include "detect-parse.h"
#include "detect-engine.h"
#include "detect-engine-mpm.h"
#include "detect-engine-state.h"
#include "detect-engine-prefilter.h"
#include "detect-engine-content-inspection.h"
#include "detect-content.h"
#include "detect-pcre.h"
#include "detect-http-header-common.h"
#include "detect-http-protocol.h"

#include "flow.h"
#include "flow-var.h"
#include "flow-util.h"

#include "util-debug.h"
#include "util-unittest.h"
#include "util-unittest-helper.h"
#include "util-spm.h"
#include "util-print.h"

#include "app-layer.h"
#include "app-layer-parser.h"

#include "app-layer-htp.h"
#include "detect-http-header.h"
#include "stream-tcp.h"

#include "util-print.h"

#define KEYWORD_NAME "http.protocol"
#define KEYWORD_NAME_LEGACY "http_protocol"
#define KEYWORD_DOC "http-keywords.html#http-protocol"
#define BUFFER_NAME "http_protocol"
#define BUFFER_DESC "http protocol"
static int g_buffer_id = 0;

static int DetectHttpProtocolSetup(DetectEngineCtx *de_ctx, Signature *s, const char *arg)
{
    if (DetectBufferSetActiveList(s, g_buffer_id) < 0)
        return -1;

    if (DetectSignatureSetAppProto(s, ALPROTO_HTTP1) < 0)
        return -1;

    return 0;
}

static InspectionBuffer *GetData(DetectEngineThreadCtx *det_ctx,
        const DetectEngineTransforms *transforms, Flow *_f,
        const uint8_t flow_flags, void *txv, const int list_id)
{
    InspectionBuffer *buffer = InspectionBufferGet(det_ctx, list_id);
    if (buffer->inspect == NULL) {
        bstr *str = NULL;
        htp_tx_t *tx = (htp_tx_t *)txv;

        if (flow_flags & STREAM_TOSERVER)
            str = tx->request_protocol;
        else if (flow_flags & STREAM_TOCLIENT)
            str = tx->response_protocol;

        if (str == NULL) {
            SCLogDebug("HTTP protocol not set");
            return NULL;
        }

        uint32_t data_len = bstr_size(str);
        uint8_t *data = bstr_ptr(str);
        if (data == NULL || data_len == 0) {
            SCLogDebug("HTTP protocol not present");
            return NULL;
        }

        InspectionBufferSetup(det_ctx, list_id, buffer, data, data_len);
        InspectionBufferApplyTransforms(buffer, transforms);
    }

    return buffer;
}

/**
 * \brief Registers the keyword handlers for the "http.protocol" keyword.
 */
void DetectHttpProtocolRegister(void)
{
    sigmatch_table[DETECT_AL_HTTP_PROTOCOL].name = KEYWORD_NAME;
    sigmatch_table[DETECT_AL_HTTP_PROTOCOL].alias = KEYWORD_NAME_LEGACY;
    sigmatch_table[DETECT_AL_HTTP_PROTOCOL].desc = BUFFER_NAME " sticky buffer";
    sigmatch_table[DETECT_AL_HTTP_PROTOCOL].url = "/rules/" KEYWORD_DOC;
    sigmatch_table[DETECT_AL_HTTP_PROTOCOL].Setup = DetectHttpProtocolSetup;
    sigmatch_table[DETECT_AL_HTTP_PROTOCOL].flags |= SIGMATCH_INFO_STICKY_BUFFER | SIGMATCH_NOOPT;

    DetectAppLayerMpmRegister2(BUFFER_NAME, SIG_FLAG_TOSERVER, 2, PrefilterGenericMpmRegister,
            GetData, ALPROTO_HTTP1, HTP_REQUEST_LINE);
    DetectAppLayerMpmRegister2(BUFFER_NAME, SIG_FLAG_TOCLIENT, 2, PrefilterGenericMpmRegister,
            GetData, ALPROTO_HTTP1, HTP_RESPONSE_LINE);
    DetectAppLayerInspectEngineRegister2(BUFFER_NAME, ALPROTO_HTTP1, SIG_FLAG_TOSERVER,
            HTP_REQUEST_LINE, DetectEngineInspectBufferGeneric, GetData);
    DetectAppLayerInspectEngineRegister2(BUFFER_NAME, ALPROTO_HTTP1, SIG_FLAG_TOCLIENT,
            HTP_RESPONSE_LINE, DetectEngineInspectBufferGeneric, GetData);

    DetectBufferTypeSetDescriptionByName(BUFFER_NAME,
            BUFFER_DESC);

    g_buffer_id = DetectBufferTypeGetByName(BUFFER_NAME);
}
