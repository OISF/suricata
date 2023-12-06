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
#include "detect-websocket.h"
#include "util-byte.h"

#include "rust.h"

static int websocket_opcode_id = 0;

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

    if (SigMatchAppendSMToList(de_ctx, s, DETECT_WEBSOCKET_OPCODE, (SigMatchCtx *)de,
                websocket_opcode_id) == NULL) {
        DetectWebSocketOpcodeFree(de_ctx, de);
        return -1;
    }

    return 0;
}

static int DetectWebSocketMaskMatch(DetectEngineThreadCtx *det_ctx, Flow *f, uint8_t flags,
        void *state, void *txv, const Signature *s, const SigMatchCtx *ctx)
{
    bool mask = SCWebSocketGetMask(txv);
    if ((mask && ctx) || (!mask && ctx == NULL)) {
        return 1;
    }
    return 0;
}

static int DetectWebSocketMaskSetup(DetectEngineCtx *de_ctx, Signature *s, const char *rawstr)
{
    if (DetectSignatureSetAppProto(s, ALPROTO_WEBSOCKET) < 0)
        return -1;

    void *dummyptr = NULL;
    if (strcmp(rawstr, "true") == 0) {
        dummyptr = de_ctx;
    } else if (strcmp(rawstr, "false") != 0) {
        SCLogError("invalid websocket.mask boolean value: %s", rawstr);
        return -1;
    }

    if (SigMatchAppendSMToList(de_ctx, s, DETECT_WEBSOCKET_MASK, (SigMatchCtx *)dummyptr,
                websocket_opcode_id) == NULL) {
        return -1;
    }

    return 0;
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

    DetectAppLayerInspectEngineRegister2("websocket.opcode", ALPROTO_WEBSOCKET, SIG_FLAG_TOSERVER,
            1, DetectEngineInspectGenericList, NULL);
    DetectAppLayerInspectEngineRegister2("websocket.opcode", ALPROTO_WEBSOCKET, SIG_FLAG_TOCLIENT,
            1, DetectEngineInspectGenericList, NULL);

    websocket_opcode_id = DetectBufferTypeGetByName("websocket.opcode");

    sigmatch_table[DETECT_WEBSOCKET_MASK].name = "websocket.mask";
    sigmatch_table[DETECT_WEBSOCKET_MASK].desc = "match WebSocket mask";
    sigmatch_table[DETECT_WEBSOCKET_MASK].url = "/rules/websocket-keywords.html#websocket-mask";
    sigmatch_table[DETECT_WEBSOCKET_MASK].AppLayerTxMatch = DetectWebSocketMaskMatch;
    sigmatch_table[DETECT_WEBSOCKET_MASK].Setup = DetectWebSocketMaskSetup;
}
