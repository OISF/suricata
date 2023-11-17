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
 * Set up ENIP protocol version keyword
 */

#include "suricata-common.h"
#include "detect-parse.h"
#include "detect-engine.h"
#include "detect-engine-uint.h"
#include "rust.h"

#include "detect-enip-protocol-version.h"

static int g_enip_protocol_version_id = 0;

static void DetectEnipProtocolVersionFree(DetectEngineCtx *de_ctx, void *ptr)
{
    rs_detect_u16_free(ptr);
}

/**
 * \brief this function is used to parse enip_protocol_version data into the current signature
 *
 * \param de_ctx pointer to the Detection Engine Context
 * \param s pointer to the Current Signature
 * \param rulestr pointer to the user provided enip protocol_version options
 *
 * \retval 0 on Success
 * \retval -1 on Failure
 */
static int DetectEnipProtocolVersionSetup(
        DetectEngineCtx *de_ctx, Signature *s, const char *rulestr)
{
    if (DetectSignatureSetAppProto(s, ALPROTO_ENIP) != 0)
        return -1;

    DetectU16Data *du16 = DetectU16Parse(rulestr);
    if (du16 == NULL) {
        return -1;
    }

    if (SigMatchAppendSMToList(de_ctx, s, DETECT_ENIP_PROTOCOLVERSION, (SigMatchCtx *)du16,
                g_enip_protocol_version_id) == NULL) {
        DetectEnipProtocolVersionFree(de_ctx, du16);
        SCReturnInt(-1);
    }
    SCReturnInt(0);
}

/**
 * \brief This function is used to match enip protocol_version type rule option on a transaction
 * with those passed via enip_protocol_version:
 *
 * \retval 0 no match
 * \retval 1 match
 */
static int DetectEnipProtocolVersionMatch(DetectEngineThreadCtx *det_ctx, Flow *f, uint8_t flags,
        void *state, void *txv, const Signature *s, const SigMatchCtx *ctx)

{
    uint16_t value;
    if (!ScEnipTxGetProtocolVersion(txv, flags, &value))
        SCReturnInt(0);
    const DetectU16Data *du16 = (const DetectU16Data *)ctx;
    return DetectU16Match(value, du16);
}

/**
 * \brief Registration function for enip_protocol_version: keyword
 */
void DetectEnipProtocolVersionRegister(void)
{
    sigmatch_table[DETECT_ENIP_PROTOCOLVERSION].name = "enip.protocol_version"; // rule keyword
    sigmatch_table[DETECT_ENIP_PROTOCOLVERSION].desc =
            "rules for detecting EtherNet/IP protocol_version";
    sigmatch_table[DETECT_ENIP_PROTOCOLVERSION].url =
            "/rules/enip-keyword.html#enip-protocol-version";
    sigmatch_table[DETECT_ENIP_PROTOCOLVERSION].Match = NULL;
    sigmatch_table[DETECT_ENIP_PROTOCOLVERSION].AppLayerTxMatch = DetectEnipProtocolVersionMatch;
    sigmatch_table[DETECT_ENIP_PROTOCOLVERSION].Setup = DetectEnipProtocolVersionSetup;
    sigmatch_table[DETECT_ENIP_PROTOCOLVERSION].Free = DetectEnipProtocolVersionFree;

    DetectAppLayerInspectEngineRegister("enip.protocol_version", ALPROTO_ENIP, SIG_FLAG_TOSERVER, 0,
            DetectEngineInspectGenericList, NULL);
    DetectAppLayerInspectEngineRegister("enip.protocol_version", ALPROTO_ENIP, SIG_FLAG_TOCLIENT, 0,
            DetectEngineInspectGenericList, NULL);

    g_enip_protocol_version_id = DetectBufferTypeGetByName("enip.protocol_version");
}
