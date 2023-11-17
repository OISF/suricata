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
 * Set up ENIP serial keyword
 */

#include "suricata-common.h"
#include "detect-parse.h"
#include "detect-engine.h"
#include "detect-engine-uint.h"
#include "rust.h"

#include "detect-enip-serial.h"

static int g_enip_serial_id = 0;

static void DetectEnipSerialFree(DetectEngineCtx *de_ctx, void *ptr)
{
    rs_detect_u32_free(ptr);
}

/**
 * \brief this function is used to parse enip_serial data into the current signature
 *
 * \param de_ctx pointer to the Detection Engine Context
 * \param s pointer to the Current Signature
 * \param rulestr pointer to the user provided enip serial options
 *
 * \retval 0 on Success
 * \retval -1 on Failure
 */
static int DetectEnipSerialSetup(DetectEngineCtx *de_ctx, Signature *s, const char *rulestr)
{
    if (DetectSignatureSetAppProto(s, ALPROTO_ENIP) != 0)
        return -1;

    DetectU32Data *du32 = DetectU32Parse(rulestr);
    if (du32 == NULL) {
        return -1;
    }

    if (SigMatchAppendSMToList(
                de_ctx, s, DETECT_ENIP_SERIAL, (SigMatchCtx *)du32, g_enip_serial_id) == NULL) {
        DetectEnipSerialFree(de_ctx, du32);
        SCReturnInt(-1);
    }
    SCReturnInt(0);
}

/**
 * \brief This function is used to match enip serial type rule option on a transaction with those
 * passed via enip_serial:
 *
 * \retval 0 no match
 * \retval 1 match
 */
static int DetectEnipSerialMatch(DetectEngineThreadCtx *det_ctx, Flow *f, uint8_t flags,
        void *state, void *txv, const Signature *s, const SigMatchCtx *ctx)

{
    uint32_t value;
    if (!ScEnipTxGetSerial(txv, &value))
        SCReturnInt(0);
    const DetectU32Data *du32 = (const DetectU32Data *)ctx;
    return DetectU32Match(value, du32);
}

/**
 * \brief Registration function for enip_serial: keyword
 */
void DetectEnipSerialRegister(void)
{
    sigmatch_table[DETECT_ENIP_SERIAL].name = "enip.serial"; // rule keyword
    sigmatch_table[DETECT_ENIP_SERIAL].desc = "rules for detecting EtherNet/IP serial";
    sigmatch_table[DETECT_ENIP_SERIAL].url = "/rules/enip-keyword.html#enip-serial";
    sigmatch_table[DETECT_ENIP_SERIAL].Match = NULL;
    sigmatch_table[DETECT_ENIP_SERIAL].AppLayerTxMatch = DetectEnipSerialMatch;
    sigmatch_table[DETECT_ENIP_SERIAL].Setup = DetectEnipSerialSetup;
    sigmatch_table[DETECT_ENIP_SERIAL].Free = DetectEnipSerialFree;

    DetectAppLayerInspectEngineRegister("enip.serial", ALPROTO_ENIP, SIG_FLAG_TOSERVER, 0,
            DetectEngineInspectGenericList, NULL);
    DetectAppLayerInspectEngineRegister("enip.serial", ALPROTO_ENIP, SIG_FLAG_TOCLIENT, 0,
            DetectEngineInspectGenericList, NULL);

    g_enip_serial_id = DetectBufferTypeGetByName("enip.serial");
}
