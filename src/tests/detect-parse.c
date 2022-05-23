
/* Copyright (C) 2007-2019 Open Information Security Foundation
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
#include "stdbool.h"
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

/**
 * @brief Convenience method for printing the details of a linked list of DetectPorts
 *
 * @param count Index in the linked list
 *
 * @param dp Pointer to a DetectPort
 */
static void DetectPortPrinter(DetectPort *dp)
{
    int count = 0;

    while (dp != NULL) {
        printf("\n  (DetectPort %d)  flags: %d", count, dp->flags);
        printf("\n  (DetectPort %d) port: %d", count, dp->port);
        printf("\n  (DetectPort %d) port2: %d", count, dp->port2);
        dp = dp->next;
        count++;
    }
}

/**
 * @brief Convenience method for printing the details of a linked list of Signatures
 *
 * @param s Pointer to a Signature
 */
static void SigPrinter(Signature *s)
{
    printf("\nPRINTING THE SIGNATURE");

    while (s != NULL) {
        printf("\nnum: %d", s->num);
        printf("\nflags: %d", s->flags);
        printf("\ndsize_low: %d", s->dsize_low);
        printf("\ndsize_high, %d", s->dsize_high);

        printf("\n/** inline -- action */");
        printf("\naction, %d", s->action);
        printf("\nfile_flags: %d", s->file_flags);

        printf("\n/** addresses, ports and proto this sig matches on */");
        printf("\nDetectProto->proto: %hhn", s->proto.proto);
        printf("\nDetectProto->flags: %d", s->proto.flags);

        printf("\n/** port settings for this signature */");
        printf("\nSignature->source_ports");
        DetectPortPrinter(s->sp);
        printf("\nSignature->destination_ports");
        DetectPortPrinter(s->dp);

        printf("\nNext Signature? : %s", s->next != NULL ? "true" : "false");
        if ((s = s->next) != NULL)
            printf("\nNext Signature...");
    }

    printf("\nDONE PRINTING\n\n");
}

// SigParseCleanup
static void SigParseCleanup(DetectEngineCtx *de_ctx, Signature *s)
{
    if (s != NULL)
        SigFree(de_ctx, s);

    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);
}

// InitializeSigParseTest
static int InitializeSigParseTest(DetectEngineCtx **de_ctx, Signature **s, const char *str)
{
    if (!de_ctx || !s) {
        SCLogError(SC_ERR_INVALID_ARGUMENT, "Error: invalid parameter");
        return 0;
    }

    *de_ctx = DetectEngineCtxInit();

    if (*de_ctx) {
        (*de_ctx)->flags |= DE_QUIET;
        *s = SigInit(*de_ctx, str);
        return 1;
    }

    return 0;
}

// Tests proper Signature is parsed from portstring length < 16 ie [30:50,!45]
static int SigParseTestNegatationNoWhitespace(void)
{
    int result = 0;
    DetectEngineCtx *de_ctx = NULL;
    Signature *s = NULL;
    const char *str = "alert http any [30:50,!45] -> any [30:50,!45] (msg:\"sid 2 version 0\"; "
                      "content:\"dummy2\"; sid:2;)";

    if (!InitializeSigParseTest(&de_ctx, &s, str)) {
        SCLogError(SC_ERR_INVALID_ARGUMENT, "Error");
        return 0;
    }

    SigPrinter(s);

    // Assertions
    if (s->sp->port == 30 && s->sp->port2 == 44 && s->sp->next->port == 46 &&
            s->sp->next->port2 == 50 && s->sp->next->next == NULL) {
        result = 1;
    }

    if (de_ctx && s)
        SigParseCleanup(de_ctx, s);

    return result;
}

// // Tests proper Signature is parsed from portstring length < 16 ie [30:50, !45]
static int SigParseTestWhitespaceLessThan14(void)
{
    int result = 0;
    DetectEngineCtx *de_ctx = NULL;
    Signature *s = NULL;
    const char *str = "alert http any [30:50, !45] -> any [30:50,!45] (msg:\"sid 2 version 0\"; "
                      "content:\"dummy2\"; sid:2;)";
    if (!InitializeSigParseTest(&de_ctx, &s, str)) {
        SCLogError(SC_ERR_INVALID_ARGUMENT, "Error");
        return 0;
    }
    SigPrinter(s);

    // Assertions
    if (s->sp->port == 30 && s->sp->port2 == 44 && s->sp->next->port == 46 &&
            s->sp->next->port2 == 50 && s->sp->next->next == NULL) {
        result = 1;
    }

    if (de_ctx && s) {
        SigParseCleanup(de_ctx, s);
    }
    return result;
}

// [30:50,              !45] (14 spaces) then you get traffic on ports 30-50 (incorrect)
static int SigParseTestWhitespace14Spaces(void)
{
    DetectEngineCtx *de_ctx = NULL;
    Signature *s = NULL;
    const char *str = "alert http any [30:50,              !45] -> any [30:50,!45] (msg:\"sid 2 "
                      "version 0\"; content:\"dummy2\"; sid:2;)";
    InitializeSigParseTest(&de_ctx, &s, str);
    FAIL_IF_NOT_NULL(s);
    if (de_ctx && s) {
        SigParseCleanup(de_ctx, s);
    }

    PASS;
}

// [30:50,               !45] (more than 14 spaces) you get a parse error failed to parse port " 45"
// (correct?)
static int SigParseTestWhitespaceMoreThan14(void)
{
    DetectEngineCtx *de_ctx = NULL;
    Signature *s = NULL;
    const char *str = "alert http any [30:50,                          !45] -> any [30:50,!45] "
                      "(msg:\"sid 2 version 0\"; content:\"dummy2\"; sid:2;)";

    InitializeSigParseTest(&de_ctx, &s, str);

    // Assertions
    FAIL_IF_NOT_NULL(s);
    if (de_ctx && s) {
        SigParseCleanup(de_ctx, s);
    }

    PASS;
}

/**
 * \brief this function registers unit tests for DetectParse
 */
void DetectParseRegisterTests(void)
{
    UtRegisterTest("DetectParseTest01", DetectParseTest01);
    UtRegisterTest("DetectParseTestNoOpt", DetectParseTestNoOpt);
    UtRegisterTest("SigParseTestNegatationNoWhitespace", SigParseTestNegatationNoWhitespace);
    UtRegisterTest("SigParseTestWhitespaceLessThan14", SigParseTestWhitespaceLessThan14);
    UtRegisterTest("SigParseTestWhitespace14Spaces", SigParseTestWhitespace14Spaces);
    UtRegisterTest("SigParseTestWhitespaceMoreThan14", SigParseTestWhitespaceMoreThan14);
}
