/* Copyright (C) 2007-2020 Open Information Security Foundation
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
 * \author Anoop Saldanha <anoopsaldanha@gmail.com>
 *
 * Implements the priority keyword
 */

#include "suricata-common.h"
#ifdef UNITTESTS
#include "util-unittest.h"
#include "detect-engine.h"
#endif
#include "detect-parse.h"
#include "detect-priority.h"

#define PARSE_REGEX "^\\s*(\\d+|\"\\d+\")\\s*$"

static DetectParseRegex parse_regex;

static int DetectPrioritySetup (DetectEngineCtx *, Signature *, const char *);
#ifdef UNITTESTS
static void PriorityRegisterTests(void);
#endif

/**
 * \brief Registers the handler functions for the "priority" keyword
 */
void DetectPriorityRegister (void)
{
    sigmatch_table[DETECT_PRIORITY].name = "priority";
    sigmatch_table[DETECT_PRIORITY].desc = "rules with a higher priority will be examined first";
    sigmatch_table[DETECT_PRIORITY].url = "/rules/meta.html#priority";
    sigmatch_table[DETECT_PRIORITY].Setup = DetectPrioritySetup;
#ifdef UNITTESTS
    sigmatch_table[DETECT_PRIORITY].RegisterTests = PriorityRegisterTests;
#endif
    DetectSetupParseRegexes(PARSE_REGEX, &parse_regex);
}

static int DetectPrioritySetup (DetectEngineCtx *de_ctx, Signature *s, const char *rawstr)
{
    char copy_str[128] = "";

    int ret = 0;
    size_t pcre2len;

    ret = DetectParsePcreExec(&parse_regex, rawstr, 0, 0);
    if (ret < 0) {
        SCLogError(SC_ERR_PCRE_MATCH, "Invalid Priority in Signature "
                     "- %s", rawstr);
        return -1;
    }

    pcre2len = sizeof(copy_str);
    ret = pcre2_substring_copy_bynumber(parse_regex.match, 1, (PCRE2_UCHAR8 *)copy_str, &pcre2len);
    if (ret < 0) {
        SCLogError(SC_ERR_PCRE_GET_SUBSTRING, "pcre2_substring_copy_bynumber failed");
        return -1;
    }

    long prio = 0;
    char *endptr = NULL;
    prio = strtol(copy_str, &endptr, 10);
    if (endptr == NULL || *endptr != '\0') {
        SCLogError(SC_ERR_INVALID_SIGNATURE, "Saw an invalid character as arg "
                   "to priority keyword");
        return -1;
    }

    if (s->init_data->init_flags & SIG_FLAG_INIT_PRIO_EXPLICT) {
        SCLogWarning(SC_ERR_CONFLICTING_RULE_KEYWORDS, "duplicate priority "
                "keyword. Using highest priority in the rule");
        s->prio = MIN(s->prio, prio);
    } else {
        s->prio = prio;
        s->init_data->init_flags |= SIG_FLAG_INIT_PRIO_EXPLICT;
    }
    return 0;
}

/*------------------------------Unittests-------------------------------------*/

#ifdef UNITTESTS

static int DetectPriorityTest01(void)
{
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);

    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(msg:\"Priority test\"; priority:2; sid:1;)");
    FAIL_IF_NULL(de_ctx->sig_list);

    FAIL_IF_NOT(de_ctx->sig_list->prio == 2);

    DetectEngineCtxFree(de_ctx);
    PASS;
}

static int DetectPriorityTest02(void)
{
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);

    Signature *sig = DetectEngineAppendSig(de_ctx, "alert tcp any any -> any any "
                  "(msg:\"Priority test\"; priority:1; sid:1;)");
    FAIL_IF_NULL(sig);
    FAIL_IF_NOT(sig->prio == 1);

    sig = DetectEngineAppendSig(de_ctx, "alert tcp any any -> any any "
                  "(msg:\"Priority test\"; priority:boo; sid:2;)");
    FAIL_IF_NOT_NULL(sig);

    sig = DetectEngineAppendSig(de_ctx, "alert tcp any any -> any any "
                  "(msg:\"Priority test\"; priority:10boo; sid:3;)");
    FAIL_IF_NOT_NULL(sig);

    sig = DetectEngineAppendSig(de_ctx, "alert tcp any any -> any any "
                  "(msg:\"Priority test\"; priority:b10oo; sid:4;)");
    FAIL_IF_NOT_NULL(sig);

    sig = DetectEngineAppendSig(de_ctx, "alert tcp any any -> any any "
                  "(msg:\"Priority test\"; priority:boo10; sid:5;)");
    FAIL_IF_NOT_NULL(sig);

    sig = DetectEngineAppendSig(de_ctx, "alert tcp any any -> any any "
                  "(msg:\"Priority test\"; priority:-1; sid:6;)");
    FAIL_IF_NOT_NULL(sig);

    sig = DetectEngineAppendSig(de_ctx, "alert tcp any any -> any any "
                  "(msg:\"Priority test\"; sid:7;)");
    FAIL_IF_NULL(sig);
    FAIL_IF_NOT(sig->prio == 3);

    sig = DetectEngineAppendSig(de_ctx, "alert tcp any any -> any any "
                  "(msg:\"Priority test\"; priority:5; priority:4; sid:8;)");
    FAIL_IF_NULL(sig);
    FAIL_IF_NOT(sig->prio == 4);

    sig = DetectEngineAppendSig(de_ctx, "alert tcp any any -> any any "
                  "(msg:\"Priority test\"; priority:5; priority:4; "
                  "priority:1; sid:9;)");
    FAIL_IF_NULL(sig);
    FAIL_IF_NOT(sig->prio == 1);

    DetectEngineCtxFree(de_ctx);
    PASS;
}

/**
 * \brief This function registers unit tests for Classification Config API.
 */
static void PriorityRegisterTests(void)
{
    UtRegisterTest("DetectPriorityTest01", DetectPriorityTest01);
    UtRegisterTest("DetectPriorityTest02", DetectPriorityTest02);
}
#endif /* UNITTESTS */
