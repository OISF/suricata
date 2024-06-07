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
 * Set up ENIP vendor id keyword
 */

#include "suricata-common.h"
#include "detect-parse.h"
#include "detect-engine.h"
#include "detect-engine-uint.h"
#include "rust.h"

#include "detect-enip-vendor-id.h"

static int g_enip_vendor_id_id = 0;

static void DetectEnipVendorIdFree(DetectEngineCtx *de_ctx, void *ptr)
{
    rs_detect_u16_free(ptr);
}

/**
 * \brief this function is used to parse enip_vendor_id data into the current signature
 *
 * \param de_ctx pointer to the Detection Engine Context
 * \param s pointer to the Current Signature
 * \param rulestr pointer to the user provided enip vendor_id options
 *
 * \retval 0 on Success
 * \retval -1 on Failure
 */
static int DetectEnipVendorIdSetup(DetectEngineCtx *de_ctx, Signature *s, const char *rulestr)
{
    if (DetectSignatureSetAppProto(s, ALPROTO_ENIP) != 0)
        return -1;

    DetectU16Data *du16 = DetectU16Parse(rulestr);
    if (du16 == NULL) {
        return -1;
    }

    if (SigMatchAppendSMToList(de_ctx, s, DETECT_ENIP_VENDORID, (SigMatchCtx *)du16,
                g_enip_vendor_id_id) == NULL) {
        DetectEnipVendorIdFree(de_ctx, du16);
        SCReturnInt(-1);
    }
    SCReturnInt(0);
}

/**
 * \brief This function is used to match enip vendor_id type rule option on a transaction with those
 * passed via enip_vendor_id:
 *
 * \retval 0 no match
 * \retval 1 match
 */
static int DetectEnipVendorIdMatch(DetectEngineThreadCtx *det_ctx, Flow *f, uint8_t flags,
        void *state, void *txv, const Signature *s, const SigMatchCtx *ctx)

{
    uint16_t value;
    if (!SCEnipTxGetVendorId(txv, &value))
        SCReturnInt(0);
    const DetectU16Data *du16 = (const DetectU16Data *)ctx;
    return DetectU16Match(value, du16);
}

/**
 * \brief Registration function for enip_vendor_id: keyword
 */
void DetectEnipVendorIdRegister(void)
{
    sigmatch_table[DETECT_ENIP_VENDORID].name = "enip.vendor_id"; // rule keyword
    sigmatch_table[DETECT_ENIP_VENDORID].desc = "rules for detecting EtherNet/IP vendor_id";
    sigmatch_table[DETECT_ENIP_VENDORID].url = "/rules/enip-keyword.html#enip-vendor-id";
    sigmatch_table[DETECT_ENIP_VENDORID].Match = NULL;
    sigmatch_table[DETECT_ENIP_VENDORID].AppLayerTxMatch = DetectEnipVendorIdMatch;
    sigmatch_table[DETECT_ENIP_VENDORID].Setup = DetectEnipVendorIdSetup;
    sigmatch_table[DETECT_ENIP_VENDORID].Free = DetectEnipVendorIdFree;

    DetectAppLayerInspectEngineRegister("enip.vendor_id", ALPROTO_ENIP, SIG_FLAG_TOSERVER, 0,
            DetectEngineInspectGenericList, NULL);
    DetectAppLayerInspectEngineRegister("enip.vendor_id", ALPROTO_ENIP, SIG_FLAG_TOCLIENT, 0,
            DetectEngineInspectGenericList, NULL);

    g_enip_vendor_id_id = DetectBufferTypeGetByName("enip.vendor_id");
}
