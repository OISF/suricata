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
 * Set up ENIP cip extendedstatus keyword
 */

#include "suricata-common.h"
#include "detect-parse.h"
#include "detect-engine.h"
#include "detect-engine-uint.h"
#include "rust.h"

#include "detect-enip-cip-extendedstatus.h"

static int g_enip_cip_extendedstatus_id = 0;

static void DetectEnipCipExtendedstatusFree(DetectEngineCtx *de_ctx, void *ptr)
{
    rs_detect_u16_free(ptr);
}

/**
 * \brief this function is used to parse enip_cip_extendedstatus data into the current signature
 *
 * \param de_ctx pointer to the Detection Engine Context
 * \param s pointer to the Current Signature
 * \param rulestr pointer to the user provided enip cip_extendedstatus options
 *
 * \retval 0 on Success
 * \retval -1 on Failure
 */
static int DetectEnipCipExtendedstatusSetup(
        DetectEngineCtx *de_ctx, Signature *s, const char *rulestr)
{
    if (DetectSignatureSetAppProto(s, ALPROTO_ENIP) != 0)
        return -1;

    DetectU16Data *du16 = DetectU16Parse(rulestr);
    if (du16 == NULL) {
        return -1;
    }

    if (SigMatchAppendSMToList(de_ctx, s, DETECT_ENIP_CIPEXTENDEDSTATUS, (SigMatchCtx *)du16,
                g_enip_cip_extendedstatus_id) == NULL) {
        DetectEnipCipExtendedstatusFree(de_ctx, du16);
        SCReturnInt(-1);
    }
    SCReturnInt(0);
}

/**
 * \brief This function is used to match enip cip_extendedstatus type rule option on a transaction
 * with those passed via enip_cip_extendedstatus:
 *
 * \retval 0 no match
 * \retval 1 match
 */
static int DetectEnipCipExtendedstatusMatch(DetectEngineThreadCtx *det_ctx, Flow *f, uint8_t flags,
        void *state, void *txv, const Signature *s, const SigMatchCtx *ctx)

{
    return SCEnipTxHasCipExtendedstatus(txv, ctx);
}

/**
 * \brief Registration function for enip_cip_extendedstatus: keyword
 */
void DetectEnipCipExtendedstatusRegister(void)
{
    sigmatch_table[DETECT_ENIP_CIPEXTENDEDSTATUS].name = "enip.cip_extendedstatus"; // rule keyword
    sigmatch_table[DETECT_ENIP_CIPEXTENDEDSTATUS].desc =
            "rules for detecting EtherNet/IP cip_extendedstatus";
    sigmatch_table[DETECT_ENIP_CIPEXTENDEDSTATUS].url =
            "/rules/enip-keyword.html#enip-cip-extendedstatus";
    sigmatch_table[DETECT_ENIP_CIPEXTENDEDSTATUS].Match = NULL;
    sigmatch_table[DETECT_ENIP_CIPEXTENDEDSTATUS].AppLayerTxMatch =
            DetectEnipCipExtendedstatusMatch;
    sigmatch_table[DETECT_ENIP_CIPEXTENDEDSTATUS].Setup = DetectEnipCipExtendedstatusSetup;
    sigmatch_table[DETECT_ENIP_CIPEXTENDEDSTATUS].Free = DetectEnipCipExtendedstatusFree;

    DetectAppLayerInspectEngineRegister("enip.cip_extendedstatus", ALPROTO_ENIP, SIG_FLAG_TOSERVER,
            0, DetectEngineInspectGenericList, NULL);
    DetectAppLayerInspectEngineRegister("enip.cip_extendedstatus", ALPROTO_ENIP, SIG_FLAG_TOCLIENT,
            0, DetectEngineInspectGenericList, NULL);

    g_enip_cip_extendedstatus_id = DetectBufferTypeGetByName("enip.cip_extendedstatus");
}
