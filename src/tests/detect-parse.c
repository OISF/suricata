/* Copyright (C) 2007-2022 Open Information Security Foundation
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

#include "../detect.h"
#include "../detect-parse.h"
#include "../detect-engine-port.h"
#include "../util-unittest.h"
#include "util-debug.h"
#include "util-error.h"

/**
 * \test DetectParseTest01 is a regression test against a memory leak
 * in the case of multiple signatures with different revisions
 * Leak happened in function DetectEngineSignatureIsDuplicate
 */

static int DetectParseTest01 (void)
{
    DetectEngineCtx * de_ctx = DetectEngineCtxInit();
    FAIL_IF(DetectEngineAppendSig(de_ctx, "alert http any any -> any any (msg:\"sid 1 version 0\"; content:\"dummy1\"; sid:1;)") == NULL);
    DetectEngineAppendSig(de_ctx, "alert http any any -> any any (msg:\"sid 2 version 0\"; content:\"dummy2\"; sid:2;)");
    DetectEngineAppendSig(de_ctx, "alert http any any -> any any (msg:\"sid 1 version 1\"; content:\"dummy1.1\"; sid:1; rev:1;)");
    DetectEngineAppendSig(de_ctx, "alert http any any -> any any (msg:\"sid 2 version 2\"; content:\"dummy2.1\"; sid:2; rev:1;)");
    FAIL_IF(de_ctx->sig_list->next == NULL);
    DetectEngineCtxFree(de_ctx);

    PASS;
}

/**
 * \test DetectParseTestNoOpt  is a regression test to make sure that we reject
 * any signature where a NOOPT rule option is given a value. This can hide rule
 * errors which make other options disappear, eg: foo: bar: baz; where "foo" is
 * the NOOPT option, we will end up with a signature which is missing "bar".
 */

static int DetectParseTestNoOpt(void)
{
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF(DetectEngineAppendSig(de_ctx,
                    "alert http any any -> any any (msg:\"sid 1 version 0\"; "
                    "content:\"dummy1\"; endswith: reference: ref; sid:1;)") != NULL);
    DetectEngineCtxFree(de_ctx);

    PASS;
}

static int SigParseTestNegationNoWhitespace(void)
{
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    Signature *s = DetectEngineAppendSig(de_ctx,
            "alert http any [30:50,!45] -> any [30:50,!45] (msg:\"sid 2 version 0\"; "
            "content:\"dummy2\"; sid:2;)");
    FAIL_IF_NULL(s);
    FAIL_IF_NULL(s->sp);
    FAIL_IF_NULL(s->dp);
    FAIL_IF_NOT(s->sp->port == 30);
    FAIL_IF_NOT(s->sp->port2 == 44);
    FAIL_IF_NULL(s->sp->next);
    FAIL_IF_NOT(s->sp->next->port == 46);
    FAIL_IF_NOT(s->sp->next->port2 == 50);
    FAIL_IF_NOT_NULL(s->sp->next->next);
    DetectEngineCtxFree(de_ctx);
    PASS;
}

// // Tests proper Signature is parsed from portstring length < 16 ie [30:50, !45]
static int SigParseTestWhitespaceLessThan14(void)
{
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    Signature *s = DetectEngineAppendSig(de_ctx,
            "alert http any [30:50, !45] -> any [30:50,!45] (msg:\"sid 2 version 0\"; "
            "content:\"dummy2\"; sid:2;)");
    FAIL_IF_NULL(s);
    FAIL_IF_NULL(s->sp);
    FAIL_IF_NULL(s->dp);
    FAIL_IF_NOT(s->sp->port == 30);
    FAIL_IF_NOT(s->sp->port2 == 44);
    FAIL_IF_NULL(s->sp->next);
    FAIL_IF_NOT(s->sp->next->port == 46);
    FAIL_IF_NOT(s->sp->next->port2 == 50);
    FAIL_IF_NOT_NULL(s->sp->next->next);
    DetectEngineCtxFree(de_ctx);
    PASS;
}

static int SigParseTestWhitespace14Spaces(void)
{
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    Signature *s = DetectEngineAppendSig(de_ctx,
            "alert http any [30:50,              !45] -> any [30:50,!45] (msg:\"sid 2 "
            "version 0\"; content:\"dummy2\"; sid:2;)");
    FAIL_IF_NULL(s);
    FAIL_IF_NULL(s->sp);
    FAIL_IF_NULL(s->dp);
    FAIL_IF_NOT(s->sp->port == 30);
    FAIL_IF_NOT(s->sp->port2 == 44);
    FAIL_IF_NULL(s->sp->next);
    FAIL_IF_NOT(s->sp->next->port == 46);
    FAIL_IF_NOT(s->sp->next->port2 == 50);
    FAIL_IF_NOT_NULL(s->sp->next->next);
    DetectEngineCtxFree(de_ctx);
    PASS;
}

static int SigParseTestWhitespaceMoreThan14(void)
{
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    Signature *s = DetectEngineAppendSig(de_ctx,
            "alert http any [30:50,                          !45] -> any [30:50,!45] "
            "(msg:\"sid 2 version 0\"; content:\"dummy2\"; sid:2;)");
    FAIL_IF_NULL(s);
    FAIL_IF_NULL(s->sp);
    FAIL_IF_NULL(s->dp);
    FAIL_IF_NOT(s->sp->port == 30);
    FAIL_IF_NOT(s->sp->port2 == 44);
    FAIL_IF_NULL(s->sp->next);
    FAIL_IF_NOT(s->sp->next->port == 46);
    FAIL_IF_NOT(s->sp->next->port2 == 50);
    FAIL_IF_NOT_NULL(s->sp->next->next);
    DetectEngineCtxFree(de_ctx);
    PASS;
}

/**
 * \brief this function registers unit tests for DetectParse
 */
void DetectParseRegisterTests(void)
{
    UtRegisterTest("DetectParseTest01", DetectParseTest01);
    UtRegisterTest("DetectParseTestNoOpt", DetectParseTestNoOpt);
    UtRegisterTest("SigParseTestNegationNoWhitespace", SigParseTestNegationNoWhitespace);
    UtRegisterTest("SigParseTestWhitespaceLessThan14", SigParseTestWhitespaceLessThan14);
    UtRegisterTest("SigParseTestWhitespace14Spaces", SigParseTestWhitespace14Spaces);
    UtRegisterTest("SigParseTestWhitespaceMoreThan14", SigParseTestWhitespaceMoreThan14);
}
