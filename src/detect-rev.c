/* Copyright (C) 2007-2010 Open Information Security Foundation
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
 * \author Victor Julien <victor@inliniac.net>
 *
 * Implements the rev keyword
 */

#include "suricata-common.h"
#include "detect.h"
#include "detect-engine.h"
#include "detect-parse.h"
#include "detect-rev.h"
#include "util-byte.h"
#include "util-debug.h"
#include "util-error.h"
#include "util-unittest.h"

static int DetectRevSetup (DetectEngineCtx *, Signature *, const char *);
#ifdef UNITTESTS
static void DetectRevRegisterTests(void);
#endif

void DetectRevRegister (void)
{
    sigmatch_table[DETECT_REV].name = "rev";
    sigmatch_table[DETECT_REV].desc = "set version of the rule";
    sigmatch_table[DETECT_REV].url = "/rules/meta.html#rev-revision";
    sigmatch_table[DETECT_REV].Setup = DetectRevSetup;
#ifdef UNITTESTS
    sigmatch_table[DETECT_REV].RegisterTests = DetectRevRegisterTests;
#endif
}

static int DetectRevSetup (DetectEngineCtx *de_ctx, Signature *s, const char *rawstr)
{
    uint32_t rev = 0;
    if (ByteExtractStringUint32(&rev, 10, strlen(rawstr), rawstr) <= 0) {
        SCLogError("invalid input as arg to rev keyword");
        goto error;
    }
    if (rev == 0) {
        SCLogError("rev value 0 is invalid");
        goto error;
    }
    if (s->rev > 0) {
        SCLogError("duplicated 'rev' keyword detected");
        goto error;
    }

    s->rev = rev;
    return 0;

error:
    return -1;
}

#ifdef UNITTESTS
/**
 * \test RevTestParse01 is a test for a valid rev value
 */
static int RevTestParse01(void)
{
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);

    Signature *s =
            DetectEngineAppendSig(de_ctx, "alert tcp 1.2.3.4 any -> any any (sid:1; rev:1;)");

    FAIL_IF_NULL(s);
    FAIL_IF(s->rev != 1);

    DetectEngineCtxFree(de_ctx);
    PASS;
}

/**
 * \test RevTestParse02 is a test for an invalid rev value
 */
static int RevTestParse02(void)
{
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);

    FAIL_IF_NOT_NULL(
            DetectEngineAppendSig(de_ctx, "alert tcp 1.2.3.4 any -> any any (sid:1; rev:a;)"));

    DetectEngineCtxFree(de_ctx);
    PASS;
}

/**
 * \test RevTestParse03 is a test for a rev containing of a single quote.
 */
static int RevTestParse03(void)
{
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);

    FAIL_IF_NOT_NULL(DetectEngineAppendSig(
            de_ctx, "alert tcp any any -> any any (content:\"ABC\"; rev:\";)"));

    DetectEngineCtxFree(de_ctx);
    PASS;
}

/**
 * \test RevTestParse04 is a test for a rev value of 0
 */
static int RevTestParse04(void)
{
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);

    FAIL_IF_NOT_NULL(DetectEngineAppendSig(
            de_ctx, "alert tcp any any -> any any (content:\"ABC\"; rev:0;)"));

    DetectEngineCtxFree(de_ctx);
    PASS;
}

/**
 * \brief this function registers unit tests for Rev
 */
static void DetectRevRegisterTests(void)
{
    UtRegisterTest("RevTestParse01", RevTestParse01);
    UtRegisterTest("RevTestParse02", RevTestParse02);
    UtRegisterTest("RevTestParse03", RevTestParse03);
    UtRegisterTest("RevTestParse04", RevTestParse04);
}
#endif /* UNITTESTS */
