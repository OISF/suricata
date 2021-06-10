/* Copyright (C) 2021 Open Information Security Foundation
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

#include "suricata-common.h"

#include "detect-parse.h"
#include "detect-engine.h"
#include "detect-smb-fp.h"

#include "rust.h"

static void DetectSMBfingerprintFree(DetectEngineCtx *de_ctx, void *ptr)
{
    SCFree(ptr);
}

typedef struct DetectSMB_Fingerprint {
    char md5[SC_MD5_LEN];
} DetectSMB_Fingerprint;

const uint8_t SC_hexvalue[256] = {
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0,
    1,
    2,
    3,
    4,
    5,
    6,
    7,
    8,
    9,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    10,
    11,
    12,
    13,
    14,
    15,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    10,
    11,
    12,
    13,
    14,
    15,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
    0xFF,
};

static int smb_fingerprint_id = 0;

/**
 * \brief this function is used to attach the parsed smb.fingerprint data into the current signature
 *
 * \param de_ctx pointer to the Detection Engine Context
 * \param s pointer to the Current Signature
 * \param str pointer to the user provided smb.fingerprint
 *
 * \retval 0 on Success
 * \retval -1 on Failure
 */
static int DetectSMBfingerprintSetup(DetectEngineCtx *de_ctx, Signature *s, const char *str)
{
    if (DetectSignatureSetAppProto(s, ALPROTO_SMB) != 0)
        return -1;

    if (strlen(str) != SC_MD5_HEX_LEN) {
        SCLogError(SC_ERR_INVALID_VALUE,
                "rule %u smb.fingerprint needs a valid MD5 with 32 characters", s->id);
        return -1;
    }

    DetectSMB_Fingerprint *smbfp = SCMalloc(sizeof(DetectSMB_Fingerprint));
    if (smbfp == NULL)
        return -1;

    for (uint8_t i = 0; i < SC_MD5_LEN; i++) {
        if (SC_hexvalue[(uint8_t)str[2 * i]] == 0xFF ||
                SC_hexvalue[(uint8_t)str[2 * i + 1]] == 0xFF) {
            SCLogError(SC_ERR_INVALID_VALUE,
                    "rule %u smb.fingerprint needs a valid MD5 with hexadecimal characters only",
                    s->id);
            DetectSMBfingerprintFree(NULL, smbfp);
            return -1;
        }
        smbfp->md5[i] =
                (SC_hexvalue[(uint8_t)str[2 * i]] << 4) | SC_hexvalue[(uint8_t)str[2 * i + 1]];
    }

    SigMatch *sm = SigMatchAlloc();
    if (sm == NULL) {
        DetectSMBfingerprintFree(NULL, smbfp);
        return -1;
    }

    sm->type = DETECT_SMB_FINGERPRINT;
    sm->ctx = (SigMatchCtx *)smbfp;

    SigMatchAppendSMToList(s, sm, smb_fingerprint_id);

    return 0;
}

static int DetectSMBfingerprintMatch(DetectEngineThreadCtx *det_ctx, Flow *f, uint8_t flags,
        void *state, void *txv, const Signature *s, const SigMatchCtx *ctx)

{
    uint8_t hash[SC_MD5_LEN];
    DetectSMB_Fingerprint *detect = (DetectSMB_Fingerprint *)ctx;

    if (rs_smb_get_fingerprint(state, txv, &hash) == 0) {
        if (memcmp(hash, detect->md5, SC_MD5_LEN) == 0) {
            return 1;
        }
    }

    // no match by default
    return 0;
}

static int InspectSMBGeneric(DetectEngineCtx *de_ctx, DetectEngineThreadCtx *det_ctx,
        const struct DetectEngineAppInspectionEngine_ *engine, const Signature *s, Flow *f,
        uint8_t flags, void *alstate, void *txv, uint64_t tx_id)
{
    return DetectEngineInspectGenericList(
            de_ctx, det_ctx, s, engine->smd, f, flags, alstate, txv, tx_id);
}

#ifdef UNITTESTS
void DetectSMBfingerprintRegisterTests(void);
#endif

void DetectSmbFingerprintRegister(void)
{
    sigmatch_table[DETECT_SMB_FINGERPRINT].name = "smb.fingerprint";
    sigmatch_table[DETECT_SMB_FINGERPRINT].alias = "smb.fingerprint-client";
    sigmatch_table[DETECT_SMB_FINGERPRINT].desc = "match on SMB client fingerprint";
    sigmatch_table[DETECT_SMB_FINGERPRINT].url = "/rules/smb-keywords.html#fingerprint";
    sigmatch_table[DETECT_SMB_FINGERPRINT].Match = NULL;
    sigmatch_table[DETECT_SMB_FINGERPRINT].AppLayerTxMatch = DetectSMBfingerprintMatch;
    sigmatch_table[DETECT_SMB_FINGERPRINT].Setup = DetectSMBfingerprintSetup;
    sigmatch_table[DETECT_SMB_FINGERPRINT].Free = DetectSMBfingerprintFree;
#ifdef UNITTESTS
    sigmatch_table[DETECT_SMB_FINGERPRINT].RegisterTests = DetectSMBfingerprintRegisterTests;
#endif

    DetectAppLayerInspectEngineRegister2(
            "smb.fingerprint", ALPROTO_SMB, SIG_FLAG_TOSERVER, 0, InspectSMBGeneric, NULL);
    smb_fingerprint_id = DetectBufferTypeRegister("smb.fingerprint");
}

#ifdef UNITTESTS
#include "tests/detect-smb-fp.c"
#endif
