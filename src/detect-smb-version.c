/* Copyright (C) 2022-2023 Open Information Security Foundation
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
 * \author Eloy Pérez
 * \author Jason Taylor
 *
 * Implements the smb.version keyword
 */

#include "suricata-common.h"

#include "detect.h"
#include "detect-parse.h"

#include "detect-engine.h"
#include "detect-engine-mpm.h"
#include "detect-engine-state.h"
#include "detect-engine-prefilter.h"
#include "detect-engine-content-inspection.h"

#include "detect-smb-version.h"
#include "rust.h"

#define BUFFER_NAME  "smb_version"
#define KEYWORD_NAME "smb.version"

static int g_smb_version_list_id = 0;

static void DetectSmbVersionFree(DetectEngineCtx *de_ctx, void *ptr)
{

    SCLogDebug("smb_version: DetectSmbVersionFree");
    rs_smb_version_free(ptr);
}

/**
 * \brief Creates a SigMatch for the "smb.version" keyword being sent as argument,
 *        and appends it to the rs_smb_version_match Signature(s).
 *
 * \param de_ctx Pointer to the detection engine context.
 * \param s      Pointer to signature for the current Signature being parsed
 *               from the rules.
 * \param arg    Pointer to the string holding the keyword value.
 *
 * \retval 0 on success, -1 on failure
 */

static int DetectSmbVersionSetup(DetectEngineCtx *de_ctx, Signature *s, const char *arg)
{
    SCLogDebug("smb_version: DetectSmbVersionSetup");

    if (DetectSignatureSetAppProto(s, ALPROTO_SMB) < 0)
        return -1;

    if (arg == NULL) {
        SCLogError("Error parsing smb.version option in signature, it needs a value");
        return -1;
    }

    if (DetectGetLastSMFromLists(s, DETECT_SMB_VERSION, -1)) {
        SCLogError("Can't use 2 or more smb.version declarations in "
                   "the same sig. Invalidating signature.");
        return -1;
    }

    void *dod = rs_smb_version_parse(arg);

    if (dod == NULL) {
        SCLogError("Error parsing smb.version option in signature");
        return -1;
    }

    if (SigMatchAppendSMToList(
                de_ctx, s, DETECT_SMB_VERSION, (SigMatchCtx *)dod, g_smb_version_list_id) == NULL) {
        DetectSmbVersionFree(de_ctx, dod);
        return -1;
    }

    return 0;
}

/**
 * \brief App layer match function for the "smb.version" keyword.
 *
 * \param t       Pointer to the ThreadVars instance.
 * \param det_ctx Pointer to the DetectEngineThreadCtx.
 * \param f       Pointer to the flow.
 * \param flags   Pointer to the flags indicating the flow direction.
 * \param state   Pointer to the app layer state data.
 * \param s       Pointer to the Signature instance.
 * \param m       Pointer to the SigMatch.
 *
 * \retval 1 On Match.
 * \retval 0 On no match.
 */

static int DetectSmbVersionMatchRust(DetectEngineThreadCtx *det_ctx, Flow *f, uint8_t flags,
        void *state, void *txv, const Signature *s, const SigMatchCtx *m)
{

    SCLogDebug("smb_version: DetectSmbVersionMatchRust");

    int matchvalue = rs_smb_version_match(txv, (void *)m);

    if (matchvalue != 1) {
        SCLogDebug("rs_smb_version_match: didn't match");
        SCReturnInt(0);
    } else {
        SCLogDebug("rs_smb_version_match: matched!");
        return matchvalue;
    }
}

/**
 * \brief Registers the keyword handlers for the "smb_version" keyword.
 */

void DetectSmbVersionRegister(void)
{
    sigmatch_table[DETECT_SMB_VERSION].name = KEYWORD_NAME;
    sigmatch_table[DETECT_SMB_VERSION].Setup = DetectSmbVersionSetup;
    sigmatch_table[DETECT_SMB_VERSION].Match = NULL;
    sigmatch_table[DETECT_SMB_VERSION].AppLayerTxMatch = DetectSmbVersionMatchRust;
    sigmatch_table[DETECT_SMB_VERSION].Free = DetectSmbVersionFree;
    sigmatch_table[DETECT_SMB_VERSION].desc = "smb keyword to match on SMB version";
    sigmatch_table[DETECT_FLOW_AGE].url = "/rules/smb-keywords.html#smb-version";

    DetectAppLayerInspectEngineRegister(
            BUFFER_NAME, ALPROTO_SMB, SIG_FLAG_TOSERVER, 0, DetectEngineInspectGenericList, NULL);

    DetectAppLayerInspectEngineRegister(
            BUFFER_NAME, ALPROTO_SMB, SIG_FLAG_TOCLIENT, 0, DetectEngineInspectGenericList, NULL);

    g_smb_version_list_id = DetectBufferTypeRegister(BUFFER_NAME);

    SCLogDebug("registering " BUFFER_NAME " rule option");
}
