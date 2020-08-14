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

#include "detect-ike-key-exchange-payload.h"
#include "stream-tcp.h"

#include "rust.h"
#include "app-layer-ike.h"
#include "rust-bindings.h"

#define KEYWORD_NAME_CLIENT_KEY_EXCHANGE "ikev1.client_key_exchange_payload"
#define KEYWORD_DOC_CLIENT_KEY_EXCHANGE  "ike-keywords.html#ike-client_key_exchange_payload";
#define BUFFER_NAME_CLIENT_KEY_EXCHANGE  "ikev1.client_key_exchange_payload"
#define BUFFER_DESC_CLIENT_KEY_EXCHANGE  "ikev1 client key_exchange payload"

#define KEYWORD_NAME_SERVER_KEY_EXCHANGE "ikev1.server_key_exchange_payload"
#define KEYWORD_DOC_SERVER_KEY_EXCHANGE  "ike-keywords.html#ike-server_key_exchange_payload";
#define BUFFER_NAME_SERVER_KEY_EXCHANGE  "ikev1.server_key_exchange_payload"
#define BUFFER_DESC_SERVER_KEY_EXCHANGE  "ikev1 server key_exchange payload"

static int g_buffer_client_key_exchange_id = 0;
static int g_buffer_server_key_exchange_id = 0;

static int DetectClientKeyExchangeSetup(DetectEngineCtx *de_ctx, Signature *s, const char *str)
{
    if (DetectBufferSetActiveList(s, g_buffer_client_key_exchange_id) < 0)
        return -1;

    if (DetectSignatureSetAppProto(s, ALPROTO_IKE) < 0)
        return -1;

    return 0;
}

static int DetectServerKeyExchangeSetup(DetectEngineCtx *de_ctx, Signature *s, const char *str)
{
    if (DetectBufferSetActiveList(s, g_buffer_server_key_exchange_id) < 0)
        return -1;

    if (DetectSignatureSetAppProto(s, ALPROTO_IKE) < 0)
        return -1;

    return 0;
}

static InspectionBuffer *GetClientKeyExchangeData(DetectEngineThreadCtx *det_ctx,
        const DetectEngineTransforms *transforms, Flow *_f,
        const uint8_t _flow_flags, void *txv, const int list_id)
{
    InspectionBuffer *buffer = InspectionBufferGet(det_ctx, list_id);
    if (buffer->inspect == NULL) {
        const uint8_t *b = NULL;
        uint32_t b_len = 0;

        if (rs_ike_state_get_key_exchange(txv, &b, &b_len) != 1)
            return NULL;
        if (b == NULL || b_len == 0)
            return NULL;

        InspectionBufferSetup(buffer, b, b_len);
        InspectionBufferApplyTransforms(buffer, transforms);
    }

    return buffer;
}

static InspectionBuffer *GetServerKeyExchangeData(DetectEngineThreadCtx *det_ctx,
                                          const DetectEngineTransforms *transforms, Flow *_f,
                                          const uint8_t _flow_flags, void *txv, const int list_id)
{
    InspectionBuffer *buffer = InspectionBufferGet(det_ctx, list_id);
    if (buffer->inspect == NULL) {
        const uint8_t *b = NULL;
        uint32_t b_len = 0;

        if (rs_ike_state_get_key_exchange(txv, &b, &b_len) != 1)
            return NULL;
        if (b == NULL || b_len == 0)
            return NULL;

        InspectionBufferSetup(buffer, b, b_len);
        InspectionBufferApplyTransforms(buffer, transforms);
    }

    return buffer;
}

static bool DetectClientKeyExchangeHexadecimalValidateCallback(const Signature *s,
                                                               const char **sigerror)
{
    const SigMatch *sm = s->init_data->smlists[g_buffer_client_key_exchange_id];
    for ( ; sm != NULL; sm = sm->next)
    {
        if (sm->type != DETECT_CONTENT)
            continue;

        const DetectContentData *cd = (DetectContentData *)sm->ctx;

        for (size_t i = 0; i < cd->content_len; ++i)
        {
            if(!isxdigit(cd->content[i]))
            {
                *sigerror = "Invalid ikev1.key_exchange_payload string (should be string of hexademical characters)."
                            "This rule will therefore never match.";
                SCLogWarning(SC_WARN_POOR_RULE,  "rule %u: %s", s->id, *sigerror);
                return FALSE;
            }
        }
    }

    return TRUE;
}

static bool DetectServerKeyExchangeHexadecimalValidateCallback(const Signature *s,
                                                               const char **sigerror)
{
    const SigMatch *sm = s->init_data->smlists[g_buffer_server_key_exchange_id];
    for ( ; sm != NULL; sm = sm->next)
    {
        if (sm->type != DETECT_CONTENT)
            continue;

        const DetectContentData *cd = (DetectContentData *)sm->ctx;

        for (size_t i = 0; i < cd->content_len; ++i)
        {
            if(!isxdigit(cd->content[i]))
            {
                *sigerror = "Invalid ikev1.key_exchange_payload string (should be string of hexademical characters)."
                            "This rule will therefore never match.";
                SCLogWarning(SC_WARN_POOR_RULE,  "rule %u: %s", s->id, *sigerror);
                return FALSE;
            }
        }
    }

    return TRUE;
}

void DetectIkeKeyExchangeRegister(void)
{
    // register client_key_exchange
    sigmatch_table[DETECT_AL_IKE_CLIENT_KEY_EXCHANGE].name = KEYWORD_NAME_CLIENT_KEY_EXCHANGE;
    sigmatch_table[DETECT_AL_IKE_CLIENT_KEY_EXCHANGE].url = "/rules/" KEYWORD_DOC_CLIENT_KEY_EXCHANGE
    sigmatch_table[DETECT_AL_IKE_CLIENT_KEY_EXCHANGE].desc = "sticky buffer to match on the IKEv1 client_key_exchange_payload";
    sigmatch_table[DETECT_AL_IKE_CLIENT_KEY_EXCHANGE].Setup = DetectClientKeyExchangeSetup;
    sigmatch_table[DETECT_AL_IKE_CLIENT_KEY_EXCHANGE].flags |= SIGMATCH_NOOPT|SIGMATCH_INFO_STICKY_BUFFER;

    DetectAppLayerInspectEngineRegister2(BUFFER_NAME_CLIENT_KEY_EXCHANGE, ALPROTO_IKE,
            SIG_FLAG_TOSERVER, 3,
            DetectEngineInspectBufferGeneric, GetClientKeyExchangeData);

    DetectAppLayerMpmRegister2(BUFFER_NAME_CLIENT_KEY_EXCHANGE, SIG_FLAG_TOSERVER, 1,
            PrefilterGenericMpmRegister, GetClientKeyExchangeData, ALPROTO_IKE,
            3);

    DetectBufferTypeSetDescriptionByName(BUFFER_NAME_CLIENT_KEY_EXCHANGE, BUFFER_DESC_CLIENT_KEY_EXCHANGE);

    g_buffer_client_key_exchange_id = DetectBufferTypeGetByName(BUFFER_NAME_CLIENT_KEY_EXCHANGE);
    DetectBufferTypeRegisterValidateCallback(BUFFER_NAME_CLIENT_KEY_EXCHANGE, DetectClientKeyExchangeHexadecimalValidateCallback);
    SCLogDebug("registering " BUFFER_NAME_CLIENT_KEY_EXCHANGE " rule option");

    // register server_key_exchange
    sigmatch_table[DETECT_AL_IKE_SERVER_KEY_EXCHANGE].name = KEYWORD_NAME_SERVER_KEY_EXCHANGE;
    sigmatch_table[DETECT_AL_IKE_SERVER_KEY_EXCHANGE].url = "/rules/" KEYWORD_DOC_SERVER_KEY_EXCHANGE
    sigmatch_table[DETECT_AL_IKE_SERVER_KEY_EXCHANGE].desc = "sticky buffer to match on the IKEv1 server_key_exchange_payload";
    sigmatch_table[DETECT_AL_IKE_SERVER_KEY_EXCHANGE].Setup = DetectServerKeyExchangeSetup;
    sigmatch_table[DETECT_AL_IKE_SERVER_KEY_EXCHANGE].flags |= SIGMATCH_NOOPT|SIGMATCH_INFO_STICKY_BUFFER;

    DetectAppLayerInspectEngineRegister2(BUFFER_NAME_SERVER_KEY_EXCHANGE, ALPROTO_IKE,
            SIG_FLAG_TOCLIENT, 4,
            DetectEngineInspectBufferGeneric, GetServerKeyExchangeData);

    DetectAppLayerMpmRegister2(BUFFER_NAME_SERVER_KEY_EXCHANGE, SIG_FLAG_TOCLIENT, 1,
            PrefilterGenericMpmRegister, GetServerKeyExchangeData, ALPROTO_IKE,
            4);

    DetectBufferTypeSetDescriptionByName(BUFFER_NAME_SERVER_KEY_EXCHANGE, BUFFER_DESC_SERVER_KEY_EXCHANGE);

    g_buffer_server_key_exchange_id = DetectBufferTypeGetByName(BUFFER_NAME_SERVER_KEY_EXCHANGE);
    DetectBufferTypeRegisterValidateCallback(BUFFER_NAME_SERVER_KEY_EXCHANGE, DetectServerKeyExchangeHexadecimalValidateCallback);
    SCLogDebug("registering " BUFFER_NAME_SERVER_KEY_EXCHANGE " rule option");
}
