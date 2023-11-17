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
 *
 * Set up ENIP state keyword
 */

#include "suricata-common.h"
#include "detect-parse.h"
#include "detect-engine.h"
#include "detect-engine-uint.h"
#include "rust.h"

#include "detect-enip-state.h"

static int g_enip_state_id = 0;

static void DetectEnipStateFree(DetectEngineCtx *de_ctx, void *ptr)
{
    rs_detect_u8_free(ptr);
}

/**
 * \brief this function is used to parse enip_state data into the current signature
 *
 * \param de_ctx pointer to the Detection Engine Context
 * \param s pointer to the Current Signature
 * \param rulestr pointer to the user provided enip state options
 *
 * \retval 0 on Success
 * \retval -1 on Failure
 */
static int DetectEnipStateSetup(DetectEngineCtx *de_ctx, Signature *s, const char *rulestr)
{
    if (DetectSignatureSetAppProto(s, ALPROTO_ENIP) != 0)
        return -1;

    DetectU8Data *du8 = DetectU8Parse(rulestr);
    if (du8 == NULL) {
        return -1;
    }

    if (SigMatchAppendSMToList(de_ctx, s, DETECT_ENIP_STATE, (SigMatchCtx *)du8, g_enip_state_id) ==
            NULL) {
        DetectEnipStateFree(de_ctx, du8);
        SCReturnInt(-1);
    }
    SCReturnInt(0);
}

/**
 * \brief This function is used to match enip state type rule option on a transaction with those
 * passed via enip_state:
 *
 * \retval 0 no match
 * \retval 1 match
 */
static int DetectEnipStateMatch(DetectEngineThreadCtx *det_ctx, Flow *f, uint8_t flags, void *state,
        void *txv, const Signature *s, const SigMatchCtx *ctx)

{
    uint8_t value;
    if (!ScEnipTxGetState(txv, &value))
        SCReturnInt(0);
    const DetectU8Data *du8 = (const DetectU8Data *)ctx;
    return DetectU8Match(value, du8);
}

/**
 * \brief Registration function for enip_state: keyword
 */
void DetectEnipStateRegister(void)
{
    sigmatch_table[DETECT_ENIP_STATE].name = "enip.state"; // rule keyword
    sigmatch_table[DETECT_ENIP_STATE].desc = "rules for detecting EtherNet/IP state";
    sigmatch_table[DETECT_ENIP_STATE].url = "/rules/enip-keyword.html#enip-state";
    sigmatch_table[DETECT_ENIP_STATE].Match = NULL;
    sigmatch_table[DETECT_ENIP_STATE].AppLayerTxMatch = DetectEnipStateMatch;
    sigmatch_table[DETECT_ENIP_STATE].Setup = DetectEnipStateSetup;
    sigmatch_table[DETECT_ENIP_STATE].Free = DetectEnipStateFree;

    DetectAppLayerInspectEngineRegister(
            "enip.state", ALPROTO_ENIP, SIG_FLAG_TOSERVER, 0, DetectEngineInspectGenericList, NULL);
    DetectAppLayerInspectEngineRegister(
            "enip.state", ALPROTO_ENIP, SIG_FLAG_TOCLIENT, 0, DetectEngineInspectGenericList, NULL);

    g_enip_state_id = DetectBufferTypeGetByName("enip.state");
}
