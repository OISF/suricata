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

#include "../suricata-common.h"

#include "../detect-engine.h"

#include "../detect-smb-fp.h"

#include "../util-unittest.h"

/**
 * \test signature with a valid fingerprint value.
 */

static int DetectSMBfingerprintParseTest01(void)
{
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);

    Signature *sig = DetectEngineAppendSig(de_ctx,
            "alert smb any any -> any any "
            "(smb.fingerprint:f0b90f9e6480edfb78cc14bb75a89480; sid:1; rev:1;)");
    FAIL_IF_NULL(sig);

    DetectEngineCtxFree(de_ctx);
    PASS;
}

/**
 * \test signature with a too short fingerprint value.
 */

static int DetectSMBfingerprintParseTest02(void)
{
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);

    Signature *sig = DetectEngineAppendSig(de_ctx,
            "alert smb any any -> any any "
            "(smb.fingerprint:z0b90f9e6480edfb78cc14bb75a8948Z; sid:1; rev:1;)");
    FAIL_IF_NOT_NULL(sig);

    DetectEngineCtxFree(de_ctx);
    PASS;
}

/**
 * \test signature with an invalid fingerprint value.
 */

static int DetectSMBfingerprintParseTest03(void)
{
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);

    Signature *sig = DetectEngineAppendSig(
            de_ctx, "alert smb any any -> any any (smb.fingerprint:f0b9; sid:1; rev:1;)");
    FAIL_IF_NOT_NULL(sig);

    DetectEngineCtxFree(de_ctx);
    PASS;
}

/**
 * \brief this function registers unit tests for SMB fingerprint
 */
void DetectSMBfingerprintRegisterTests(void)
{
    UtRegisterTest("DetectSMBfingerprintParseTest01", DetectSMBfingerprintParseTest01);
    UtRegisterTest("DetectSMBfingerprintParseTest02", DetectSMBfingerprintParseTest02);
    UtRegisterTest("DetectSMBfingerprintParseTest03", DetectSMBfingerprintParseTest03);
}
