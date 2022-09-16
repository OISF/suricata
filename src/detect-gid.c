/* Copyright (C) 2007-2021 Open Information Security Foundation
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
 * \author Breno Silva <breno.silva@gmail.com>
 *
 * Implements the gid keyword
 */

#include "suricata-common.h"
#ifdef UNITTESTS
#include "util-unittest.h"
#include "detect-parse.h"
#include "detect-engine.h"
#endif

#include "detect-gid.h"

static int DetectGidSetup (DetectEngineCtx *, Signature *, const char *);
#ifdef UNITTESTS
static void GidRegisterTests(void);
#endif

/**
 * \brief Registration function for gid: keyword
 */

void DetectGidRegister (void)
{
    sigmatch_table[DETECT_GID].name = "gid";
    sigmatch_table[DETECT_GID].desc = "give different groups of signatures another id value";
    sigmatch_table[DETECT_GID].url = "/rules/meta.html#gid-group-id";
    sigmatch_table[DETECT_GID].Match = NULL;
    sigmatch_table[DETECT_GID].Setup = DetectGidSetup;
    sigmatch_table[DETECT_GID].Free  = NULL;
#ifdef UNITTESTS
    sigmatch_table[DETECT_GID].RegisterTests = GidRegisterTests;
#endif
}

/**
 * \internal
 * \brief this function is used to add the parsed gid into the current signature
 *
 * \param de_ctx pointer to the Detection Engine Context
 * \param s pointer to the Current Signature
 * \param rawstr pointer to the user provided gid options
 *
 * \retval 0 on Success
 * \retval -1 on Failure
 */
static int DetectGidSetup (DetectEngineCtx *de_ctx, Signature *s, const char *rawstr)
{
    unsigned long gid = 0;
    char *endptr = NULL;
    gid = strtoul(rawstr, &endptr, 10);
    if (endptr == NULL || *endptr != '\0') {
        SCLogError(SC_ERR_INVALID_SIGNATURE, "invalid character as arg "
                   "to gid keyword");
        goto error;
    }
    if (gid >= UINT_MAX) {
        SCLogError(SC_ERR_INVALID_NUMERIC_VALUE, "gid value to high, max %u", UINT_MAX);
        goto error;
    }

    s->gid = (uint32_t)gid;

    return 0;

 error:
    return -1;
}

/*
 * ONLY TESTS BELOW THIS COMMENT
 */

#ifdef UNITTESTS
/**
 * \test GidTestParse01 is a test for a  valid gid value
 */
static int GidTestParse01 (void)
{
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);

    Signature *s =
            DetectEngineAppendSig(de_ctx, "alert tcp 1.2.3.4 any -> any any (sid:1; gid:1;)");

    FAIL_IF_NULL(s);
    FAIL_IF(s->gid != 1);

    DetectEngineCtxFree(de_ctx);
    PASS;
}

/**
 * \test GidTestParse02 is a test for an invalid gid value
 */
static int GidTestParse02 (void)
{
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);

    FAIL_IF_NOT_NULL(
            DetectEngineAppendSig(de_ctx, "alert tcp 1.2.3.4 any -> any any (sid:1; gid:a;)"));

    DetectEngineCtxFree(de_ctx);
    PASS;
}

/**
 * \test Test a gid consisting of a single quote.
 */
static int GidTestParse03 (void)
{
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);

    FAIL_IF_NOT_NULL(DetectEngineAppendSig(
            de_ctx, "alert tcp any any -> any any (content:\"ABC\"; gid:\";)"));

    DetectEngineCtxFree(de_ctx);
    PASS;
}

/**
 * \brief this function registers unit tests for Gid
 */
static void GidRegisterTests(void)
{
    UtRegisterTest("GidTestParse01", GidTestParse01);
    UtRegisterTest("GidTestParse02", GidTestParse02);
    UtRegisterTest("GidTestParse03", GidTestParse03);
}
#endif /* UNITTESTS */