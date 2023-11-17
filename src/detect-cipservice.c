/* Copyright (C) 2015 Open Information Security Foundation
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
 * \author Kevin Wong <kwong@solananetworks.com>
 *
 * Set up ENIP Command and CIP Service rule parsing and entry point for matching
 */

#include "suricata-common.h"
#include "detect-parse.h"
#include "detect-engine.h"
#include "rust.h"

#include "detect-cipservice.h"

/*
 * CIP SERVICE CODE
 */

static int g_cip_buffer_id = 0;

/**
 * \brief this function will free memory associated with DetectCipServiceData
 *
 * \param ptr pointer to DetectCipServiceData
 */
static void DetectCipServiceFree(DetectEngineCtx *de_ctx, void *ptr)
{
    rs_enip_cip_service_free(ptr);
}

/**
 * \brief this function is used to a cipserviced the parsed cip_service data into the current signature
 *
 * \param de_ctx pointer to the Detection Engine Context
 * \param s pointer to the Current Signature
 * \param rulestr pointer to the user provided cip_service options
 *
 * \retval 0 on Success
 * \retval -1 on Failure
 */
static int DetectCipServiceSetup(DetectEngineCtx *de_ctx, Signature *s,
        const char *rulestr)
{
    SCEnter();

    if (DetectSignatureSetAppProto(s, ALPROTO_ENIP) != 0)
        return -1;

    void *cipserviced = rs_enip_parse_cip_service(rulestr);
    if (cipserviced == NULL)
        return -1;

    if (SigMatchAppendSMToList(de_ctx, s, DETECT_CIPSERVICE, (SigMatchCtx *)cipserviced,
                g_cip_buffer_id) == NULL) {
        DetectCipServiceFree(de_ctx, cipserviced);
        SCReturnInt(-1);
    }
    SCReturnInt(0);
}

/**
 * \brief This function is used to match enip command type rule option on a transaction with those
 * passed via enip_command:
 *
 * \retval 0 no match
 * \retval 1 match
 */
static int DetectCipServiceMatch(DetectEngineThreadCtx *det_ctx, Flow *f, uint8_t flags,
        void *state, void *txv, const Signature *s, const SigMatchCtx *ctx)

{
    return rs_enip_tx_has_cip_service(txv, flags, ctx);
}

/**
 * \brief Registration function for cip_service: keyword
 */
void DetectCipServiceRegister(void)
{
    SCEnter();
    sigmatch_table[DETECT_CIPSERVICE].name = "cip_service"; // rule keyword
    sigmatch_table[DETECT_CIPSERVICE].desc =
            "match on CIP Service, and optionnally class and attribute";
    sigmatch_table[DETECT_CIPSERVICE].url = "/rules/enip-keyword.html#cip_service";
    sigmatch_table[DETECT_CIPSERVICE].Match = NULL;
    sigmatch_table[DETECT_CIPSERVICE].AppLayerTxMatch = DetectCipServiceMatch;
    sigmatch_table[DETECT_CIPSERVICE].Setup = DetectCipServiceSetup;
    sigmatch_table[DETECT_CIPSERVICE].Free = DetectCipServiceFree;

    DetectAppLayerInspectEngineRegister(
            "cip", ALPROTO_ENIP, SIG_FLAG_TOSERVER, 0, DetectEngineInspectGenericList, NULL);
    DetectAppLayerInspectEngineRegister(
            "cip", ALPROTO_ENIP, SIG_FLAG_TOCLIENT, 0, DetectEngineInspectGenericList, NULL);

    g_cip_buffer_id = DetectBufferTypeGetByName("cip");

    SCReturn;
}
