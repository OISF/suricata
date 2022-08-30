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

#include "../detect-http2.h"

#include "../util-unittest.h"

/**
 * \test signature with a valid http2.frametype value.
 */

static int DetectHTTP2frameTypeParseTest01 (void)
{
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);

    Signature *sig = DetectEngineAppendSig(de_ctx,
                                           "alert http2 any any -> any any (http2.frametype:GOAWAY; sid:1; rev:1;)");
    FAIL_IF_NULL(sig);

    DetectEngineCtxFree(de_ctx);
    PASS;
}

/**
 * \brief this function registers unit tests for DetectHTTP2frameType
 */
void DetectHTTP2frameTypeRegisterTests(void)
{
    UtRegisterTest("DetectHTTP2frameTypeParseTest01", DetectHTTP2frameTypeParseTest01);
}

/**
 * \test signature with a valid http2.errorcode value.
 */

static int DetectHTTP2errorCodeParseTest01 (void)
{
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);

    Signature *sig = DetectEngineAppendSig(de_ctx,
                                           "alert http2 any any -> any any (http2.errorcode:NO_ERROR; sid:1; rev:1;)");
    FAIL_IF_NULL(sig);

    DetectEngineCtxFree(de_ctx);
    PASS;
}

void DetectHTTP2errorCodeRegisterTests(void)
{
    UtRegisterTest("DetectHTTP2errorCodeParseTest01", DetectHTTP2errorCodeParseTest01);
}

/**
 * \test signature with a valid http2.priority value.
 */

static int DetectHTTP2priorityParseTest01 (void)
{
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);

    Signature *sig = DetectEngineAppendSig(de_ctx,
                                           "alert http2 any any -> any any (http2.priority:>100; sid:1; rev:1;)");
    FAIL_IF_NULL(sig);

    DetectEngineCtxFree(de_ctx);
    PASS;
}

void DetectHTTP2priorityRegisterTests(void)
{
    UtRegisterTest("DetectHTTP2priorityParseTest01", DetectHTTP2priorityParseTest01);
}

/**
 * \test signature with a valid http2.window value.
 */

static int DetectHTTP2windowParseTest01 (void)
{
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);

    Signature *sig = DetectEngineAppendSig(de_ctx,
                                           "alert http2 any any -> any any (http2.window:<42; sid:1; rev:1;)");
    FAIL_IF_NULL(sig);

    DetectEngineCtxFree(de_ctx);
    PASS;
}

void DetectHTTP2windowRegisterTests(void)
{
    UtRegisterTest("DetectHTTP2windowParseTest01", DetectHTTP2windowParseTest01);
}


/**
 * \test signature with a valid http2.settings value.
 */

static int DetectHTTP2settingsParseTest01 (void)
{
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);

    Signature *sig = DetectEngineAppendSig(de_ctx,
                                           "alert http2 any any -> any any (http2.settings:SETTINGS_MAX_HEADER_LIST_SIZE >1024; sid:1; rev:1;)");
    FAIL_IF_NULL(sig);

    DetectEngineCtxFree(de_ctx);
    PASS;
}

void DetectHTTP2settingsRegisterTests(void)
{
    UtRegisterTest("DetectHTTP2settingsParseTest01", DetectHTTP2settingsParseTest01);
}


/**
* \test signature with a valid http2.size_update value.
*/

static int DetectHTTP2sizeUpdateParseTest01 (void)
{
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);

    Signature *sig = DetectEngineAppendSig(de_ctx,
                                           "alert http2 any any -> any any (http2.size_update:>4096; sid:1; rev:1;)");
    FAIL_IF_NULL(sig);

    DetectEngineCtxFree(de_ctx);
    PASS;
}

void DetectHTTP2sizeUpdateRegisterTests(void)
{
    UtRegisterTest("DetectHTTP2sizeUpdateParseTest01", DetectHTTP2sizeUpdateParseTest01);
}
