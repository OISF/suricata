/* Copyright (C) 2023 Open Information Security Foundation
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
 * \file
 *
 * \author Philippe Antoine
 */

#include "suricata-common.h"
#include "detect.h"
#include "detect-parse.h"
#include "detect-engine.h"
#include "detect-engine-content-inspection.h"
#include "detect-engine-uint.h"
#include "detect-engine-prefilter.h"
#include "detect-websocket.h"

#include "rust.h"

static int websocket_tx_id = 0;
static int websocket_payload_id = 0;

/**
 * \internal
 * \brief this function will free memory associated with DetectWebSocketOpcodeData
 *
 * \param de pointer to DetectWebSocketOpcodeData
 */
static void DetectWebSocketOpcodeFree(DetectEngineCtx *de_ctx, void *de_ptr)
{
    rs_detect_u8_free(de_ptr);
}

/**
 * \internal
 * \brief Function to match opcode of a websocket tx
 *
 * \param det_ctx Pointer to the pattern matcher thread.
 * \param f       Pointer to the current flow.
 * \param flags   Flags.
 * \param state   App layer state.
 * \param txv     Pointer to the transaction.
 * \param s       Pointer to the Signature.
 * \param ctx     Pointer to the sigmatch that we will cast into DetectWebSocketOpcodeData.
 *
 * \retval 0 no match.
 * \retval 1 match.
 */
static int DetectWebSocketOpcodeMatch(DetectEngineThreadCtx *det_ctx, Flow *f, uint8_t flags,
        void *state, void *txv, const Signature *s, const SigMatchCtx *ctx)
{
    const DetectU8Data *de = (const DetectU8Data *)ctx;
    uint8_t opc = SCWebSocketGetOpcode(txv);
    return DetectU8Match(opc, de);
}

/**
 * \internal
 * \brief this function is used to add the parsed sigmatch  into the current signature
 *
 * \param de_ctx pointer to the Detection Engine Context
 * \param s pointer to the Current Signature
 * \param rawstr pointer to the user provided options
 *
 * \retval 0 on Success
 * \retval -1 on Failure
 */
static int DetectWebSocketOpcodeSetup(DetectEngineCtx *de_ctx, Signature *s, const char *rawstr)
{
    if (DetectSignatureSetAppProto(s, ALPROTO_WEBSOCKET) < 0)
        return -1;

    DetectU8Data *de = SCWebSocketParseOpcode(rawstr);
    if (de == NULL)
        return -1;

    if (SigMatchAppendSMToList(
                de_ctx, s, DETECT_WEBSOCKET_OPCODE, (SigMatchCtx *)de, websocket_tx_id) == NULL) {
        DetectWebSocketOpcodeFree(de_ctx, de);
        return -1;
    }

    return 0;
}

/**
 * \internal
 * \brief this function will free memory associated with DetectWebSocketMaskData
 *
 * \param de pointer to DetectWebSocketMaskData
 */
static void DetectWebSocketMaskFree(DetectEngineCtx *de_ctx, void *de_ptr)
{
    rs_detect_u32_free(de_ptr);
}

static int DetectWebSocketMaskMatch(DetectEngineThreadCtx *det_ctx, Flow *f, uint8_t flags,
        void *state, void *txv, const Signature *s, const SigMatchCtx *ctx)
{
    uint32_t val;
    const DetectU32Data *du32 = (const DetectU32Data *)ctx;
    if (SCWebSocketGetMask(txv, &val)) {
        return DetectU32Match(val, du32);
    }
    return 0;
}

static int DetectWebSocketMaskSetup(DetectEngineCtx *de_ctx, Signature *s, const char *rawstr)
{
    if (DetectSignatureSetAppProto(s, ALPROTO_WEBSOCKET) < 0)
        return -1;

    DetectU32Data *du32 = DetectU32Parse(rawstr);
    if (du32 == NULL)
        return -1;

    if (SigMatchAppendSMToList(
                de_ctx, s, DETECT_WEBSOCKET_MASK, (SigMatchCtx *)du32, websocket_tx_id) == NULL) {
        DetectWebSocketMaskFree(de_ctx, du32);
        return -1;
    }

    return 0;
}

static void DetectWebSocketFlagsFree(DetectEngineCtx *de_ctx, void *de_ptr)
{
    rs_detect_u8_free(de_ptr);
}

static int DetectWebSocketFlagsMatch(DetectEngineThreadCtx *det_ctx, Flow *f, uint8_t flags,
        void *state, void *txv, const Signature *s, const SigMatchCtx *ctx)
{
    const DetectU8Data *de = (const DetectU8Data *)ctx;
    uint8_t val = SCWebSocketGetFlags(txv);
    return DetectU8Match(val, de);
}

static int DetectWebSocketFlagsSetup(DetectEngineCtx *de_ctx, Signature *s, const char *rawstr)
{
    if (DetectSignatureSetAppProto(s, ALPROTO_WEBSOCKET) < 0)
        return -1;

    DetectU8Data *de = SCWebSocketParseFlags(rawstr);
    if (de == NULL)
        return -1;

    if (SigMatchAppendSMToList(
                de_ctx, s, DETECT_WEBSOCKET_FLAGS, (SigMatchCtx *)de, websocket_tx_id) == NULL) {
        DetectWebSocketOpcodeFree(de_ctx, de);
        return -1;
    }

    return 0;
}

static int DetectWebSocketPayloadSetup(DetectEngineCtx *de_ctx, Signature *s, const char *rulestr)
{
    if (DetectBufferSetActiveList(de_ctx, s, websocket_payload_id) < 0)
        return -1;

    if (DetectSignatureSetAppProto(s, ALPROTO_WEBSOCKET) != 0)
        return -1;

    return 0;
}

static InspectionBuffer *GetData(DetectEngineThreadCtx *det_ctx,
        const DetectEngineTransforms *transforms, Flow *_f, const uint8_t _flow_flags, void *txv,
        const int list_id)
{
    InspectionBuffer *buffer = InspectionBufferGet(det_ctx, list_id);
    if (buffer->inspect == NULL) {
        const uint8_t *b = NULL;
        uint32_t b_len = 0;

        if (!SCWebSocketGetPayload(txv, &b, &b_len))
            return NULL;
        if (b == NULL || b_len == 0)
            return NULL;

        InspectionBufferSetup(det_ctx, list_id, buffer, b, b_len);
        InspectionBufferApplyTransforms(buffer, transforms);
    }
    return buffer;
}

/**
 * \brief Registration function for websocket.opcode: keyword
 */
void DetectWebsocketRegister(void)
{
    sigmatch_table[DETECT_WEBSOCKET_OPCODE].name = "websocket.opcode";
    sigmatch_table[DETECT_WEBSOCKET_OPCODE].desc = "match WebSocket opcode";
    sigmatch_table[DETECT_WEBSOCKET_OPCODE].url = "/rules/websocket-keywords.html#websocket-opcode";
    sigmatch_table[DETECT_WEBSOCKET_OPCODE].AppLayerTxMatch = DetectWebSocketOpcodeMatch;
    sigmatch_table[DETECT_WEBSOCKET_OPCODE].Setup = DetectWebSocketOpcodeSetup;
    sigmatch_table[DETECT_WEBSOCKET_OPCODE].Free = DetectWebSocketOpcodeFree;

    DetectAppLayerInspectEngineRegister("websocket.tx", ALPROTO_WEBSOCKET, SIG_FLAG_TOSERVER, 1,
            DetectEngineInspectGenericList, NULL);
    DetectAppLayerInspectEngineRegister("websocket.tx", ALPROTO_WEBSOCKET, SIG_FLAG_TOCLIENT, 1,
            DetectEngineInspectGenericList, NULL);

    websocket_tx_id = DetectBufferTypeGetByName("websocket.tx");

    sigmatch_table[DETECT_WEBSOCKET_MASK].name = "websocket.mask";
    sigmatch_table[DETECT_WEBSOCKET_MASK].desc = "match WebSocket mask";
    sigmatch_table[DETECT_WEBSOCKET_MASK].url = "/rules/websocket-keywords.html#websocket-mask";
    sigmatch_table[DETECT_WEBSOCKET_MASK].AppLayerTxMatch = DetectWebSocketMaskMatch;
    sigmatch_table[DETECT_WEBSOCKET_MASK].Setup = DetectWebSocketMaskSetup;
    sigmatch_table[DETECT_WEBSOCKET_MASK].Free = DetectWebSocketMaskFree;

    sigmatch_table[DETECT_WEBSOCKET_FLAGS].name = "websocket.flags";
    sigmatch_table[DETECT_WEBSOCKET_FLAGS].desc = "match WebSocket flags";
    sigmatch_table[DETECT_WEBSOCKET_FLAGS].url = "/rules/websocket-keywords.html#websocket-flags";
    sigmatch_table[DETECT_WEBSOCKET_FLAGS].AppLayerTxMatch = DetectWebSocketFlagsMatch;
    sigmatch_table[DETECT_WEBSOCKET_FLAGS].Setup = DetectWebSocketFlagsSetup;
    sigmatch_table[DETECT_WEBSOCKET_FLAGS].Free = DetectWebSocketFlagsFree;

    sigmatch_table[DETECT_WEBSOCKET_PAYLOAD].name = "websocket.payload";
    sigmatch_table[DETECT_WEBSOCKET_PAYLOAD].desc = "match WebSocket payload";
    sigmatch_table[DETECT_WEBSOCKET_PAYLOAD].url =
            "/rules/websocket-keywords.html#websocket-payload";
    sigmatch_table[DETECT_WEBSOCKET_PAYLOAD].Setup = DetectWebSocketPayloadSetup;
    sigmatch_table[DETECT_WEBSOCKET_PAYLOAD].flags |= SIGMATCH_NOOPT;
    DetectAppLayerInspectEngineRegister("websocket.payload", ALPROTO_WEBSOCKET, SIG_FLAG_TOSERVER,
            0, DetectEngineInspectBufferGeneric, GetData);
    DetectAppLayerInspectEngineRegister("websocket.payload", ALPROTO_WEBSOCKET, SIG_FLAG_TOCLIENT,
            0, DetectEngineInspectBufferGeneric, GetData);
    DetectAppLayerMpmRegister("websocket.payload", SIG_FLAG_TOSERVER, 2,
            PrefilterGenericMpmRegister, GetData, ALPROTO_WEBSOCKET, 1);
    DetectAppLayerMpmRegister("websocket.payload", SIG_FLAG_TOCLIENT, 2,
            PrefilterGenericMpmRegister, GetData, ALPROTO_WEBSOCKET, 1);
    websocket_payload_id = DetectBufferTypeGetByName("websocket.payload");
}
