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

#include "../suricata-common.h"

#include "../detect-engine.h"

#include "../detect-transform-dropbytes.h"

#include "../util-unittest.h"

/**
 * \test signature with an invalid dropbytes value.
 */

static int DetectTransformDropbytesParseTest01(void)
{
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);

    Signature *sig = DetectEngineAppendSig(de_ctx, "alert tcp any any <> any 1 dropbytes:\"^|00\";");
    FAIL_IF_NOT_NULL(sig);

    DetectEngineCtxFree(de_ctx);
    PASS;
}

/**
 * \test signature with a valid dropbytes value.
 */

static int DetectTransformDropbytesParseTest02(void)
{
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);

    Signature *sig = DetectEngineAppendSig(de_ctx,
            "alert http any any -> any any (msg:\"HTTP with dropbytes\"; http.request_line; "
            "dropbytes:\"^|00|\"; content:\"/z4d4kWk.jpg\"; sid:1;)");
    FAIL_IF_NULL(sig);

    DetectEngineCtxFree(de_ctx);
    PASS;
}

/**
 * \test signature with an invalid dropbytes flag.
 */

static int DetectTransformDropbytesParseTest03(void)
{
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);

    Signature *sig = DetectEngineAppendSig(de_ctx, "alert tcp any any <> any 1 dropbytes:\"x,^\";");
    FAIL_IF_NOT_NULL(sig);

    DetectEngineCtxFree(de_ctx);
    PASS;
}

/**
 * \test signature with a valid dropbytes flag and value.
 */

static int DetectTransformDropbytesParseTest04(void)
{
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);

    Signature *sig = DetectEngineAppendSig(de_ctx,
            "alert http any any -> any any (msg:\"HTTP with dropbytes\"; http.request_line; "
            "dropbytes:\"c,^\"; content:\"/z4d4kWk.jpg\"; sid:1;)");
    FAIL_IF_NULL(sig);

    DetectEngineCtxFree(de_ctx);
    PASS;
}

/**
 * \test signature with a valid dropbytes flag without value.
 */

static int DetectTransformDropbytesParseTest05(void)
{
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);

    Signature *sig = DetectEngineAppendSig(de_ctx, "alert tcp any any <> any 1 dropbytes:\"c,\";");
    FAIL_IF_NOT_NULL(sig);

    DetectEngineCtxFree(de_ctx);
    PASS;
}

/**
 * \test signature without dropbytes flag (but comma present) and value.
 */

static int DetectTransformDropbytesParseTest06(void)
{
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);

    Signature *sig = DetectEngineAppendSig(de_ctx,
            "alert http any any -> any any (msg:\"HTTP with dropbytes\"; http.request_line; "
            "dropbytes:\",^\"; content:\"/z4d4kWk.jpg\"; sid:1;)");
    FAIL_IF_NULL(sig);

    DetectEngineCtxFree(de_ctx);
    PASS;
}

/**
 * \brief this function registers unit tests for DetectTransformDropbytes
 */
void DetectTransformDropbytesRegisterTests(void)
{
    UtRegisterTest("DetectTransformDropbytesParseTest01", DetectTransformDropbytesParseTest01);
    UtRegisterTest("DetectTransformDropbytesParseTest02", DetectTransformDropbytesParseTest02);
    UtRegisterTest("DetectTransformDropbytesParseTest03", DetectTransformDropbytesParseTest03);
    UtRegisterTest("DetectTransformDropbytesParseTest04", DetectTransformDropbytesParseTest04);
    UtRegisterTest("DetectTransformDropbytesParseTest05", DetectTransformDropbytesParseTest05);
    UtRegisterTest("DetectTransformDropbytesParseTest06", DetectTransformDropbytesParseTest06);
}
