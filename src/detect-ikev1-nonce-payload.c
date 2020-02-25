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
#include "debug.h"
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

#include "detect-ikev1-nonce-payload.h"
#include "stream-tcp.h"

#include "rust.h"
#include "app-layer-ikev1.h"
#include "rust-bindings.h"

#define KEYWORD_NAME_CLIENT_NONCE "ikev1.client_nonce_payload"
#define KEYWORD_DOC_CLIENT_NONCE  "ikev1-keywords.html#ikev1-client_nonce_payload";
#define BUFFER_NAME_CLIENT_NONCE  "ikev1.client_nonce_payload"
#define BUFFER_DESC_CLIENT_NONCE  "ikev1 client nonce payload"

#define KEYWORD_NAME_SERVER_NONCE "ikev1.server_nonce_payload"
#define KEYWORD_DOC_SERVER_NONCE  "ikev1-keywords.html#ikev1-server_nonce_payload";
#define BUFFER_NAME_SERVER_NONCE  "ikev1.server_nonce_payload"
#define BUFFER_DESC_SERVER_NONCE  "ikev1 server nonce payload"

static int g_buffer_client_nonce_id = 0;
static int g_buffer_server_nonce_id = 0;

static int DetectClientNonceSetup(DetectEngineCtx *de_ctx, Signature *s, const char *str)
{
    if (DetectBufferSetActiveList(s, g_buffer_client_nonce_id) < 0)
        return -1;

    if (DetectSignatureSetAppProto(s, ALPROTO_IKEV1) < 0)
        return -1;

    return 0;
}

static int DetectServerNonceSetup(DetectEngineCtx *de_ctx, Signature *s, const char *str)
{
    if (DetectBufferSetActiveList(s, g_buffer_server_nonce_id) < 0)
        return -1;

    if (DetectSignatureSetAppProto(s, ALPROTO_IKEV1) < 0)
        return -1;

    return 0;
}

static InspectionBuffer *GetClientNonceData(DetectEngineThreadCtx *det_ctx,
        const DetectEngineTransforms *transforms, Flow *_f,
        const uint8_t _flow_flags, void *txv, const int list_id)
{
    InspectionBuffer *buffer = InspectionBufferGet(det_ctx, list_id);
    if (buffer->inspect == NULL) {
        const uint8_t *b = NULL;
        uint32_t b_len = 0;

        IKEV1State *state = FlowGetAppState(_f);

        if (rs_ikev1_state_get_client_nonce(state, &b, &b_len) != 1)
            return NULL;
        if (b == NULL || b_len == 0)
            return NULL;

        InspectionBufferSetup(buffer, b, b_len);
        InspectionBufferApplyTransforms(buffer, transforms);
    }

    return buffer;
}

static InspectionBuffer *GetServerNonceData(DetectEngineThreadCtx *det_ctx,
                                          const DetectEngineTransforms *transforms, Flow *_f,
                                          const uint8_t _flow_flags, void *txv, const int list_id)
{
    InspectionBuffer *buffer = InspectionBufferGet(det_ctx, list_id);
    if (buffer->inspect == NULL) {
        const uint8_t *b = NULL;
        uint32_t b_len = 0;

        IKEV1State *state = FlowGetAppState(_f);

        if (rs_ikev1_state_get_server_nonce(state, &b, &b_len) != 1)
            return NULL;
        if (b == NULL || b_len == 0)
            return NULL;

        InspectionBufferSetup(buffer, b, b_len);
        InspectionBufferApplyTransforms(buffer, transforms);
    }

    return buffer;
}

void DetectIkev1NonceRegister(void)
{
    // register client_nonce
    sigmatch_table[DETECT_AL_IKEV1_CLIENT_NONCE].name = KEYWORD_NAME_CLIENT_NONCE;
    sigmatch_table[DETECT_AL_IKEV1_CLIENT_NONCE].url = "/rules/" KEYWORD_DOC_CLIENT_NONCE
    sigmatch_table[DETECT_AL_IKEV1_CLIENT_NONCE].desc = "sticky buffer to match on the IKEv1 client_nonce_payload";
    sigmatch_table[DETECT_AL_IKEV1_CLIENT_NONCE].Setup = DetectClientNonceSetup;
    sigmatch_table[DETECT_AL_IKEV1_CLIENT_NONCE].flags |= SIGMATCH_NOOPT|SIGMATCH_INFO_STICKY_BUFFER;

    DetectAppLayerInspectEngineRegister2(BUFFER_NAME_CLIENT_NONCE, ALPROTO_IKEV1,
            SIG_FLAG_TOSERVER, 3,
            DetectEngineInspectBufferGeneric, GetClientNonceData);

    DetectAppLayerMpmRegister2(BUFFER_NAME_CLIENT_NONCE, SIG_FLAG_TOSERVER, 1,
            PrefilterGenericMpmRegister, GetClientNonceData, ALPROTO_IKEV1,
            3);

    DetectBufferTypeSetDescriptionByName(BUFFER_NAME_CLIENT_NONCE, BUFFER_DESC_CLIENT_NONCE);

    g_buffer_client_nonce_id = DetectBufferTypeGetByName(BUFFER_NAME_CLIENT_NONCE);
    SCLogDebug("registering " BUFFER_NAME_CLIENT_NONCE " rule option");

    // register server_nonce
    sigmatch_table[DETECT_AL_IKEV1_SERVER_NONCE].name = KEYWORD_NAME_SERVER_NONCE;
    sigmatch_table[DETECT_AL_IKEV1_SERVER_NONCE].url = "/rules/" KEYWORD_DOC_SERVER_NONCE
    sigmatch_table[DETECT_AL_IKEV1_SERVER_NONCE].desc = "sticky buffer to match on the IKEv1 server_nonce_payload";
    sigmatch_table[DETECT_AL_IKEV1_SERVER_NONCE].Setup = DetectServerNonceSetup;
    sigmatch_table[DETECT_AL_IKEV1_SERVER_NONCE].flags |= SIGMATCH_NOOPT|SIGMATCH_INFO_STICKY_BUFFER;

    DetectAppLayerInspectEngineRegister2(BUFFER_NAME_SERVER_NONCE, ALPROTO_IKEV1,
            SIG_FLAG_TOCLIENT, 4,
            DetectEngineInspectBufferGeneric, GetServerNonceData);

    DetectAppLayerMpmRegister2(BUFFER_NAME_SERVER_NONCE, SIG_FLAG_TOCLIENT, 1,
            PrefilterGenericMpmRegister, GetServerNonceData, ALPROTO_IKEV1,
            4);

    DetectBufferTypeSetDescriptionByName(BUFFER_NAME_SERVER_NONCE, BUFFER_DESC_SERVER_NONCE);

    g_buffer_server_nonce_id = DetectBufferTypeGetByName(BUFFER_NAME_SERVER_NONCE);
    SCLogDebug("registering " BUFFER_NAME_SERVER_NONCE " rule option");
}
