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
 * Set up ENIP Status rule parsing and entry point for matching
 */

#include "suricata-common.h"
#include "detect-parse.h"
#include "detect-engine.h"
#include "detect-engine-uint.h"
#include "rust.h"

#include "detect-enip-status.h"

static int g_enip_status_id = 0;

/**
 * \brief this function will free memory associated
 *
 * \param ptr pointer to u16
 */
static void DetectEnipStatusFree(DetectEngineCtx *de_ctx, void *ptr)
{
    rs_detect_u32_free(ptr);
}

/**
 * \brief this function is used by enipcmdd to parse enip_status data into the current signature
 *
 * \param de_ctx pointer to the Detection Engine Context
 * \param s pointer to the Current Signature
 * \param rulestr pointer to the user provided enip status options
 *
 * \retval 0 on Success
 * \retval -1 on Failure
 */
static int DetectEnipStatusSetup(DetectEngineCtx *de_ctx, Signature *s, const char *rulestr)
{
    if (DetectSignatureSetAppProto(s, ALPROTO_ENIP) != 0)
        return -1;

    DetectU32Data *du32 = SCEnipParseStatus(rulestr);
    if (du32 == NULL) {
        return -1;
    }

    if (SigMatchAppendSMToList(
                de_ctx, s, DETECT_ENIPSTATUS, (SigMatchCtx *)du32, g_enip_status_id) == NULL) {
        DetectEnipStatusFree(de_ctx, du32);
        SCReturnInt(-1);
    }
    SCReturnInt(0);
}

/**
 * \brief This function is used to match enip status type rule option on a transaction with those
 * passed via enip_status:
 *
 * \retval 0 no match
 * \retval 1 match
 */
static int DetectEnipStatusMatch(DetectEngineThreadCtx *det_ctx, Flow *f, uint8_t flags,
        void *state, void *txv, const Signature *s, const SigMatchCtx *ctx)

{
    uint32_t status;
    if (!SCEnipTxGetStatus(txv, flags, &status))
        SCReturnInt(0);
    const DetectU32Data *du32 = (const DetectU32Data *)ctx;
    return DetectU32Match(status, du32);
}

/**
 * \brief Registration function for enip_status: keyword
 */
void DetectEnipStatusRegister(void)
{
    sigmatch_table[DETECT_ENIPSTATUS].name = "enip.status"; // rule keyword
    sigmatch_table[DETECT_ENIPSTATUS].desc = "rules for detecting EtherNet/IP status";
    sigmatch_table[DETECT_ENIPSTATUS].url = "/rules/enip-keyword.html#enip-status";
    sigmatch_table[DETECT_ENIPSTATUS].Match = NULL;
    sigmatch_table[DETECT_ENIPSTATUS].AppLayerTxMatch = DetectEnipStatusMatch;
    sigmatch_table[DETECT_ENIPSTATUS].Setup = DetectEnipStatusSetup;
    sigmatch_table[DETECT_ENIPSTATUS].Free = DetectEnipStatusFree;

    DetectAppLayerInspectEngineRegister("enip.status", ALPROTO_ENIP, SIG_FLAG_TOSERVER, 0,
            DetectEngineInspectGenericList, NULL);
    DetectAppLayerInspectEngineRegister("enip.status", ALPROTO_ENIP, SIG_FLAG_TOCLIENT, 0,
            DetectEngineInspectGenericList, NULL);

    g_enip_status_id = DetectBufferTypeGetByName("enip.status");
}
