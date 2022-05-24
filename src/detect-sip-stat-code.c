/* Copyright (C) 2019 Open Information Security Foundation
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
 *
 * \author Giuseppe Longo <giuseppe@glongo.it>
 *
 * Implements the sip.stat_code sticky buffer
 *
 */

#include "suricata-common.h"
#include "threads.h"
#include "decode.h"
#include "detect.h"

#include "detect-parse.h"
#include "detect-engine.h"
#include "detect-engine-mpm.h"
#include "detect-engine-prefilter.h"
#include "detect-content.h"
#include "detect-pcre.h"
#include "detect-urilen.h"

#include "flow.h"
#include "flow-var.h"
#include "flow-util.h"

#include "util-debug.h"
#include "util-unittest.h"
#include "util-unittest-helper.h"
#include "util-spm.h"

#include "app-layer.h"
#include "app-layer-parser.h"

#include "detect-sip-stat-code.h"
#include "stream-tcp.h"

#include "rust.h"
#include "app-layer-sip.h"

#define KEYWORD_NAME "sip.stat_code"
#define KEYWORD_DOC  "sip-keywords.html#sip-stat-code"
#define BUFFER_NAME  "sip.method"
#define BUFFER_DESC  "sip response status code"
static int g_buffer_id = 0;

static int DetectSipStatCodeSetup(DetectEngineCtx *de_ctx, Signature *s, const char *str)
{
    if (DetectBufferSetActiveList(s, g_buffer_id) < 0)
        return -1;

    if (DetectSignatureSetAppProto(s, ALPROTO_SIP) < 0)
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
        const uint8_t *b = NULL;
        uint32_t b_len = 0;

        if (rs_sip_tx_get_stat_code(txv, &b, &b_len) != 1)
            return NULL;
        if (b == NULL || b_len == 0)
            return NULL;

        InspectionBufferSetup(det_ctx, list_id, buffer, b, b_len);
        InspectionBufferApplyTransforms(buffer, transforms);
    }

    return buffer;
}

void DetectSipStatCodeRegister (void)
{
    /* sip.stat_code sticky buffer */
    sigmatch_table[DETECT_AL_SIP_STAT_CODE].name = KEYWORD_NAME;
    sigmatch_table[DETECT_AL_SIP_STAT_CODE].desc = "sticky buffer to match on the SIP status code";
    sigmatch_table[DETECT_AL_SIP_STAT_CODE].url = "/rules/" KEYWORD_DOC;
    sigmatch_table[DETECT_AL_SIP_STAT_CODE].Setup = DetectSipStatCodeSetup;
    sigmatch_table[DETECT_AL_SIP_STAT_CODE].flags |= SIGMATCH_NOOPT;

    DetectAppLayerInspectEngineRegister2(BUFFER_NAME, ALPROTO_SIP,
            SIG_FLAG_TOCLIENT, 1,
            DetectEngineInspectBufferGeneric, GetData);

    DetectAppLayerMpmRegister2(BUFFER_NAME, SIG_FLAG_TOCLIENT, 4,
            PrefilterGenericMpmRegister, GetData, ALPROTO_SIP,
            1);

    DetectBufferTypeSetDescriptionByName(BUFFER_NAME, BUFFER_DESC);

    g_buffer_id = DetectBufferTypeGetByName(BUFFER_NAME);

    SCLogDebug("registering " BUFFER_NAME " rule option");
}
