/* Copyright (C) 2022 Open Information Security Foundation
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
 * Keyword to match SMB version, which can be 1 or 2.
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

static int g_smb_version_list_id = 0;

static void DetectSmbVersionFree(DetectEngineCtx *de_ctx, void *ptr)
{
    SCEnter();

    SCLogDebug("smb_version: DetectSmbVersionFree");

    if (ptr != NULL) {
        rs_smb_version_free(ptr);
    }
    SCReturn;
}

static int DetectSmbVersionSetup(DetectEngineCtx *de_ctx, Signature *s, const char *arg)
{
    SCLogDebug("smb_version: DetectSmbVersionSetup");

    if (DetectSignatureSetAppProto(s, ALPROTO_SMB) < 0)
        return -1;

    if (arg == NULL) {
        SCLogError(SC_ERR_INVALID_SIGNATURE, "Error parsing smb_version option in "
                                             "signature, it needs a value");
        return -1;
    }

    void *dod = rs_smb_version_parse(arg);
    if (dod == NULL) {
        SCLogError(SC_ERR_INVALID_SIGNATURE, "Error parsing smb_version option in "
                                             "signature");
        return -1;
    }

    SigMatch *sm = SigMatchAlloc();
    if (sm == NULL) {
        DetectSmbVersionFree(de_ctx, dod);
        return -1;
    }

    sm->type = DETECT_SMB_VERSION;
    sm->ctx = dod;

    SigMatchAppendSMToList(s, sm, g_smb_version_list_id);
    return 0;
}

static int DetectSmbVersionMatchRust(DetectEngineThreadCtx *det_ctx, Flow *f, uint8_t flags,
        void *state, void *txv, const Signature *s, const SigMatchCtx *m)
{
    SCEnter();

    SCLogDebug("smb_version: DetectSmbVersionMatchRust");

    if (rs_smb_version_match(txv, (void *)m) != 1)
        SCReturnInt(0);

    SCReturnInt(1);
}

static int DetectEngineInspectSmbVersion(DetectEngineCtx *de_ctx, DetectEngineThreadCtx *det_ctx,
        const struct DetectEngineAppInspectionEngine_ *engine, const Signature *s, Flow *f,
        uint8_t flags, void *alstate, void *txv, uint64_t tx_id)
{
    return DetectEngineInspectGenericList(
            de_ctx, det_ctx, s, engine->smd, f, flags, alstate, txv, tx_id);
}

void DetectSmbVersionRegister(void)
{
    sigmatch_table[DETECT_SMB_VERSION].name = "smb.version";
    sigmatch_table[DETECT_SMB_VERSION].alias = "smb_version";

    sigmatch_table[DETECT_SMB_VERSION].desc = "match SMB message type";
    sigmatch_table[DETECT_SMB_VERSION].Setup = DetectSmbVersionSetup;
    sigmatch_table[DETECT_SMB_VERSION].Match = NULL;
    sigmatch_table[DETECT_SMB_VERSION].AppLayerTxMatch = DetectSmbVersionMatchRust;
    sigmatch_table[DETECT_SMB_VERSION].Free = DetectSmbVersionFree;

    DetectAppLayerInspectEngineRegister2(
            "smb_version", ALPROTO_SMB, SIG_FLAG_TOSERVER, 0, DetectEngineInspectSmbVersion, NULL);

    DetectAppLayerInspectEngineRegister2(
            "smb_version", ALPROTO_SMB, SIG_FLAG_TOCLIENT, 0, DetectEngineInspectSmbVersion, NULL);

    g_smb_version_list_id = DetectBufferTypeRegister("smb_version");
}
