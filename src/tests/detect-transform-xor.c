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

#include "../detect-transform-xor.h"

#include "../util-unittest.h"

/**
 * \test signature with an invalid xor value.
 */

static int DetectTransformXorParseTest01(void)
{
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);

    Signature *sig = DetectEngineAppendSig(de_ctx, "alert tcp any any <> any 1 xor:\"nohexa\";");
    FAIL_IF_NOT_NULL(sig);

    DetectEngineCtxFree(de_ctx);
    PASS;
}

/**
 * \test signature with a valid xor value.
 */

static int DetectTransformXorParseTest02(void)
{
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);

    Signature *sig = DetectEngineAppendSig(de_ctx,
            "alert http any any -> any any (msg:\"HTTP with xor\"; http.request_line; "
            "xor:\"0a0DC8ff\"; content:\"/z4d4kWk.jpg\"; sid:1;)");
    FAIL_IF_NULL(sig);

    DetectEngineCtxFree(de_ctx);
    PASS;
}

/**
 * \brief this function registers unit tests for DetectTransformXor
 */
void DetectTransformXorRegisterTests(void)
{
    UtRegisterTest("DetectTransformXorParseTest01", DetectTransformXorParseTest01);
    UtRegisterTest("DetectTransformXorParseTest02", DetectTransformXorParseTest02);
}
