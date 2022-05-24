/* Copyright (C) 2020 Open Information Security Foundation
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
 * \author Frank Honza <frank.honza@dcso.de>
 */

#include "suricata-common.h"
#include "threads.h"
#include "decode.h"
#include "detect.h"

#include "detect-parse.h"
#include "detect-engine.h"
#include "detect-engine-mpm.h"
#include "detect-engine-prefilter.h"
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

#include "detect-ike-nonce-payload.h"
#include "stream-tcp.h"

#include "rust.h"
#include "app-layer-ike.h"
#include "rust-bindings.h"

#define KEYWORD_NAME_NONCE "ike.nonce_payload"
#define KEYWORD_DOC_NONCE  "ike-keywords.html#ike-nonce_payload";
#define BUFFER_NAME_NONCE  "ike.nonce_payload"
#define BUFFER_DESC_NONCE  "ike nonce payload"

static int g_buffer_nonce_id = 0;

static int DetectNonceSetup(DetectEngineCtx *de_ctx, Signature *s, const char *str)
{
    if (DetectBufferSetActiveList(s, g_buffer_nonce_id) < 0)
        return -1;

    if (DetectSignatureSetAppProto(s, ALPROTO_IKE) < 0)
        return -1;

    return 0;
}

static InspectionBuffer *GetNonceData(DetectEngineThreadCtx *det_ctx,
        const DetectEngineTransforms *transforms, Flow *_f, const uint8_t _flow_flags, void *txv,
        const int list_id)
{
    InspectionBuffer *buffer = InspectionBufferGet(det_ctx, list_id);
    if (buffer->inspect == NULL) {
        const uint8_t *b = NULL;
        uint32_t b_len = 0;

        if (rs_ike_state_get_nonce(txv, &b, &b_len) != 1)
            return NULL;
        if (b == NULL || b_len == 0)
            return NULL;

        InspectionBufferSetup(det_ctx, list_id, buffer, b, b_len);
        InspectionBufferApplyTransforms(buffer, transforms);
    }

    return buffer;
}

void DetectIkeNonceRegister(void)
{
    // register nonce
    sigmatch_table[DETECT_AL_IKE_NONCE].name = KEYWORD_NAME_NONCE;
    sigmatch_table[DETECT_AL_IKE_NONCE].url =
            "/rules/" KEYWORD_DOC_NONCE sigmatch_table[DETECT_AL_IKE_NONCE].desc =
                    "sticky buffer to match on the IKE nonce_payload";
    sigmatch_table[DETECT_AL_IKE_NONCE].Setup = DetectNonceSetup;
    sigmatch_table[DETECT_AL_IKE_NONCE].flags |= SIGMATCH_NOOPT | SIGMATCH_INFO_STICKY_BUFFER;

    DetectAppLayerInspectEngineRegister2(BUFFER_NAME_NONCE, ALPROTO_IKE, SIG_FLAG_TOSERVER, 1,
            DetectEngineInspectBufferGeneric, GetNonceData);

    DetectAppLayerMpmRegister2(BUFFER_NAME_NONCE, SIG_FLAG_TOSERVER, 1, PrefilterGenericMpmRegister,
            GetNonceData, ALPROTO_IKE, 1);

    DetectAppLayerInspectEngineRegister2(BUFFER_NAME_NONCE, ALPROTO_IKE, SIG_FLAG_TOCLIENT, 1,
            DetectEngineInspectBufferGeneric, GetNonceData);

    DetectAppLayerMpmRegister2(BUFFER_NAME_NONCE, SIG_FLAG_TOCLIENT, 1, PrefilterGenericMpmRegister,
            GetNonceData, ALPROTO_IKE, 1);

    DetectBufferTypeSetDescriptionByName(BUFFER_NAME_NONCE, BUFFER_DESC_NONCE);

    g_buffer_nonce_id = DetectBufferTypeGetByName(BUFFER_NAME_NONCE);
    SCLogDebug("registering " BUFFER_NAME_NONCE " rule option");
}
