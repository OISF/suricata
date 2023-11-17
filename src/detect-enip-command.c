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
 * Set up ENIP Command rule parsing and entry point for matching
 */

#include "suricata-common.h"
#include "detect-parse.h"
#include "detect-engine.h"
#include "rust.h"

#include "detect-enip-command.h"

static int g_enip_buffer_id = 0;


/**
 * \brief this function will free memory associated
 *
 * \param ptr pointer to u16
 */
static void DetectEnipCommandFree(DetectEngineCtx *de_ctx, void *ptr)
{
    SCFree(ptr);
}

/**
 * \brief this function is used by enipcmdd to parse enip_command data into the current signature
 *
 * \param de_ctx pointer to the Detection Engine Context
 * \param s pointer to the Current Signature
 * \param rulestr pointer to the user provided enip command options
 *
 * \retval 0 on Success
 * \retval -1 on Failure
 */
static int DetectEnipCommandSetup(DetectEngineCtx *de_ctx, Signature *s,
        const char *rulestr)
{
    SigMatch *sm = NULL;
    uint16_t cmdparsed;

    if (DetectSignatureSetAppProto(s, ALPROTO_ENIP) != 0)
        return -1;

    if (!rs_enip_parse_command(rulestr, &cmdparsed)) {
        SCLogWarning("rule %u has invalid value for enip_command %s", s->id, rulestr);
        return -1;
    }

    uint16_t *enipcmdd = SCCalloc(1, sizeof(uint16_t));
    if (enipcmdd == NULL)
        return -1;
    *enipcmdd = cmdparsed;

    sm = SigMatchAlloc();
    if (sm == NULL) {
        DetectEnipCommandFree(de_ctx, enipcmdd);
        SCReturnInt(-1);
    }

    sm->type = DETECT_ENIPCOMMAND;
    sm->ctx = (void *) enipcmdd;

    SigMatchAppendSMToList(s, sm, g_enip_buffer_id);
    SCReturnInt(0);
}

/**
 * \brief This function is used to match enip command type rule option on a transaction with those passed via enip_command:
 *
 * \retval 0 no match
 * \retval 1 match
 */
static int DetectEnipCommandMatch(DetectEngineThreadCtx *det_ctx,
                               Flow *f, uint8_t flags, void *state, void *txv, const Signature *s,
                               const SigMatchCtx *ctx)

{
    uint16_t *cmd = (uint16_t *)ctx;
    return rs_enip_tx_is_cmd(txv, flags, *cmd);
}

/**
 * \brief Registration function for enip_command: keyword
 */
void DetectEnipCommandRegister(void)
{
    sigmatch_table[DETECT_ENIPCOMMAND].name = "enip_command"; //rule keyword
    sigmatch_table[DETECT_ENIPCOMMAND].desc
            = "rules for detecting EtherNet/IP command";
    sigmatch_table[DETECT_ENIPCOMMAND].url = "/rules/enip-keyword.html#enip_command";
    sigmatch_table[DETECT_ENIPCOMMAND].Match = NULL;
    sigmatch_table[DETECT_ENIPCOMMAND].AppLayerTxMatch = DetectEnipCommandMatch;
    sigmatch_table[DETECT_ENIPCOMMAND].Setup = DetectEnipCommandSetup;
    sigmatch_table[DETECT_ENIPCOMMAND].Free = DetectEnipCommandFree;

    DetectAppLayerInspectEngineRegister2(
            "enip", ALPROTO_ENIP, SIG_FLAG_TOSERVER, 0, DetectEngineInspectGenericList, NULL);
    DetectAppLayerInspectEngineRegister2(
            "enip", ALPROTO_ENIP, SIG_FLAG_TOCLIENT, 0, DetectEngineInspectGenericList, NULL);

    g_enip_buffer_id = DetectBufferTypeGetByName("enip");
}
