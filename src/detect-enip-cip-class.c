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
 * Set up ENIP cip class keyword
 */

#include "suricata-common.h"
#include "detect-parse.h"
#include "detect-engine.h"
#include "detect-engine-uint.h"
#include "rust.h"

#include "detect-enip-cip-class.h"

static int g_enip_cip_class_id = 0;

static void DetectEnipCipClassFree(DetectEngineCtx *de_ctx, void *ptr)
{
    rs_detect_u32_free(ptr);
}

/**
 * \brief this function is used to parse enip_cip_class data into the current signature
 *
 * \param de_ctx pointer to the Detection Engine Context
 * \param s pointer to the Current Signature
 * \param rulestr pointer to the user provided enip cip_class options
 *
 * \retval 0 on Success
 * \retval -1 on Failure
 */
static int DetectEnipCipClassSetup(DetectEngineCtx *de_ctx, Signature *s, const char *rulestr)
{
    if (DetectSignatureSetAppProto(s, ALPROTO_ENIP) != 0)
        SCReturnInt(-1);

    DetectU32Data *du32 = DetectU32Parse(rulestr);
    if (du32 == NULL)
        SCReturnInt(-1);

    if (SigMatchAppendSMToList(de_ctx, s, DETECT_ENIP_CIPCLASS, (SigMatchCtx *)du32,
                g_enip_cip_class_id) == NULL) {
        DetectEnipCipClassFree(de_ctx, du32);
        SCReturnInt(-1);
    }
    SCReturnInt(0);
}

/**
 * \brief This function is used to match enip cip_class type rule option on a transaction
 * with those passed via enip_cip_class:
 *
 * \retval 0 no match
 * \retval 1 match
 */
static int DetectEnipCipClassMatch(DetectEngineThreadCtx *det_ctx, Flow *f, uint8_t flags,
        void *state, void *txv, const Signature *s, const SigMatchCtx *ctx)

{
    return SCEnipTxHasCipClass(txv, ctx);
}

/**
 * \brief Registration function for enip_cip_class: keyword
 */
void DetectEnipCipClassRegister(void)
{
    sigmatch_table[DETECT_ENIP_CIPCLASS].name = "enip.cip_class"; // rule keyword
    sigmatch_table[DETECT_ENIP_CIPCLASS].desc = "rules for detecting EtherNet/IP cip_class";
    sigmatch_table[DETECT_ENIP_CIPCLASS].url = "/rules/enip-keyword.html#enip-cip-class";
    sigmatch_table[DETECT_ENIP_CIPCLASS].Match = NULL;
    sigmatch_table[DETECT_ENIP_CIPCLASS].AppLayerTxMatch = DetectEnipCipClassMatch;
    sigmatch_table[DETECT_ENIP_CIPCLASS].Setup = DetectEnipCipClassSetup;
    sigmatch_table[DETECT_ENIP_CIPCLASS].Free = DetectEnipCipClassFree;

    DetectAppLayerInspectEngineRegister("enip.cip_class", ALPROTO_ENIP, SIG_FLAG_TOSERVER, 0,
            DetectEngineInspectGenericList, NULL);
    DetectAppLayerInspectEngineRegister("enip.cip_class", ALPROTO_ENIP, SIG_FLAG_TOCLIENT, 0,
            DetectEngineInspectGenericList, NULL);

    g_enip_cip_class_id = DetectBufferTypeGetByName("enip.cip_class");
}
