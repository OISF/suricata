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
 * \author Anoop Saldanha <anoopsaldanha@gmail.com>
 * \author Victor Julien <victor@inliniac.net>
 *
 * Implements classtype keyword.
 */

#include "suricata-common.h"

#include "detect-parse.h"
#include "detect-classtype.h"
#include "util-classification-config.h"

#ifdef UNITTESTS
#include "util-unittest.h"
#include "util-debug.h"
#include "util-error.h"
#include "detect-engine.h"
#include "detect.h"
#include "decode.h"
#endif
#define PARSE_REGEX "^\\s*([a-zA-Z][a-zA-Z0-9-_]*)\\s*$"

static DetectParseRegex parse_regex;

static int DetectClasstypeSetup(DetectEngineCtx *, Signature *, const char *);
#ifdef UNITTESTS
static void DetectClasstypeRegisterTests(void);
#endif

/**
 * \brief Registers the handler functions for the "Classtype" keyword.
 */
void DetectClasstypeRegister(void)
{
    sigmatch_table[DETECT_CLASSTYPE].name = "classtype";
    sigmatch_table[DETECT_CLASSTYPE].desc = "information about the classification of rules and alerts";
    sigmatch_table[DETECT_CLASSTYPE].url = "/rules/meta.html#classtype";
    sigmatch_table[DETECT_CLASSTYPE].Setup = DetectClasstypeSetup;
#ifdef UNITTESTS
    sigmatch_table[DETECT_CLASSTYPE].RegisterTests = DetectClasstypeRegisterTests;
#endif
    DetectSetupParseRegexes(PARSE_REGEX, &parse_regex);
}

/**
 * \brief Parses the raw string supplied with the "Classtype" keyword.
 *
 * \param Pointer to the string to be parsed.
 *
 * \retval bool success or failure.
 */
static int DetectClasstypeParseRawString(const char *rawstr, char *out, size_t outsize)
{
    size_t pcre2len;

    const size_t esize = CLASSTYPE_NAME_MAX_LEN + 8;
    char e[esize];

    int ret = DetectParsePcreExec(&parse_regex, rawstr, 0, 0);
    if (ret < 0) {
        SCLogError(SC_ERR_PCRE_MATCH, "Invalid Classtype in Signature");
        return -1;
    }

    pcre2len = esize;
    ret = pcre2_substring_copy_bynumber(parse_regex.match, 1, (PCRE2_UCHAR8 *)e, &pcre2len);
    if (ret < 0) {
        SCLogError(SC_ERR_PCRE_GET_SUBSTRING, "pcre2_substring_copy_bynumber failed");
        return -1;
    }

    if (strlen(e) >= CLASSTYPE_NAME_MAX_LEN) {
        SCLogError(SC_ERR_INVALID_VALUE, "classtype '%s' is too big: max %d",
                rawstr, CLASSTYPE_NAME_MAX_LEN - 1);
        return -1;
    }
    (void)strlcpy(out, e, outsize);

    return 0;
}

/**
 * \brief The setup function that would be called when the Signature parsing
 *        module encounters the "Classtype" keyword.
 *
 * \param de_ctx Pointer to the Detection Engine Context.
 * \param s      Pointer the current Signature instance that is being parsed.
 * \param rawstr Pointer to the argument supplied to the classtype keyword.
 *
 * \retval  0 On success
 * \retval -1 On failure
 */
static int DetectClasstypeSetup(DetectEngineCtx *de_ctx, Signature *s, const char *rawstr)
{
    char parsed_ct_name[CLASSTYPE_NAME_MAX_LEN] = "";

    if ((s->class_id > 0) || (s->class_msg != NULL)) {
        if (SigMatchStrictEnabled(DETECT_CLASSTYPE)) {
            SCLogError(SC_ERR_CONFLICTING_RULE_KEYWORDS, "duplicated 'classtype' "
                    "keyword detected.");
            return -1;
        } else {
            SCLogWarning(SC_ERR_CONFLICTING_RULE_KEYWORDS, "duplicated 'classtype' "
                    "keyword detected. Using instance with highest priority");
        }
    }

    if (DetectClasstypeParseRawString(rawstr, parsed_ct_name, sizeof(parsed_ct_name)) < 0) {
        SCLogError(SC_ERR_PCRE_PARSE, "invalid value for classtype keyword: "
                "\"%s\"", rawstr);
        return -1;
    }

    bool real_ct = true;
    SCClassConfClasstype *ct = SCClassConfGetClasstype(parsed_ct_name, de_ctx);
    if (ct == NULL) {
        if (SigMatchStrictEnabled(DETECT_CLASSTYPE)) {
            SCLogError(SC_ERR_UNKNOWN_VALUE, "unknown classtype '%s'",
                    parsed_ct_name);
            return -1;
        }

        if (s->id > 0) {
            SCLogWarning(SC_ERR_UNKNOWN_VALUE, "signature sid:%u uses "
                    "unknown classtype: \"%s\", using default priority %d. "
                    "This message won't be shown again for this classtype",
                    s->id, parsed_ct_name, DETECT_DEFAULT_PRIO);
        } else if (de_ctx->rule_file != NULL) {
            SCLogWarning(SC_ERR_UNKNOWN_VALUE, "signature at %s:%u uses "
                    "unknown classtype: \"%s\", using default priority %d. "
                    "This message won't be shown again for this classtype",
                    de_ctx->rule_file, de_ctx->rule_line,
                    parsed_ct_name, DETECT_DEFAULT_PRIO);
        } else {
            SCLogWarning(SC_ERR_UNKNOWN_VALUE, "unknown classtype: \"%s\", "
                    "using default priority %d. "
                    "This message won't be shown again for this classtype",
                    parsed_ct_name, DETECT_DEFAULT_PRIO);
        }

        char str[256];
        snprintf(str, sizeof(str),
                "config classification: %s,Unknown Classtype,%d\n",
                parsed_ct_name, DETECT_DEFAULT_PRIO);

        if (SCClassConfAddClasstype(de_ctx, str, 0) < 0)
            return -1;
        ct = SCClassConfGetClasstype(parsed_ct_name, de_ctx);
        if (ct == NULL)
            return -1;
        real_ct = false;
    }

    /* set prio only if not already explicitly set by 'priority' keyword.
     * update classtype in sig, but only if it is 'real' (not undefined)
     * update sigs classtype if its prio is lower (but not undefined)
     */

    bool update_ct = false;
    if ((s->init_data->init_flags & SIG_FLAG_INIT_PRIO_EXPLICT) != 0) {
        /* don't touch Signature::prio */
        update_ct = true;
    } else if (s->prio == -1) {
        s->prio = ct->priority;
        update_ct = true;
    } else {
        if (ct->priority < s->prio) {
            s->prio = ct->priority;
            update_ct = true;
        }
    }

    if (real_ct && update_ct) {
        s->class_id = ct->classtype_id;
        s->class_msg = ct->classtype_desc;
    }
    return 0;
}

#ifdef UNITTESTS

/**
 * \test undefined classtype
 */
static int DetectClasstypeTest01(void)
{
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);

    FILE *fd = SCClassConfGenerateValidDummyClassConfigFD01();
    FAIL_IF_NULL(fd);
    SCClassConfLoadClassficationConfigFile(de_ctx, fd);
    Signature *s = DetectEngineAppendSig(de_ctx, "alert tcp any any -> any any "
                               "(msg:\"Classtype test\"; "
                               "Classtype:not_available; sid:1;)");
    FAIL_IF_NULL(s);
    FAIL_IF_NOT(s->prio == 3);

    DetectEngineCtxFree(de_ctx);
    PASS;
}

/**
 * \test Check that both valid and invalid classtypes in a rule are handled
 *       properly, with rules containing invalid classtypes being rejected
 *       and the ones containing valid classtypes parsed and returned.
 */
static int DetectClasstypeTest02(void)
{
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);

    FILE *fd = SCClassConfGenerateValidDummyClassConfigFD01();
    FAIL_IF_NULL(fd);
    SCClassConfLoadClassficationConfigFile(de_ctx, fd);

    Signature *sig = DetectEngineAppendSig(de_ctx, "alert tcp any any -> any any "
                  "(Classtype:bad-unknown; sid:1;)");
    FAIL_IF_NULL(sig);

    sig = DetectEngineAppendSig(de_ctx, "alert tcp any any -> any any "
                  "(Classtype:not-there; sid:2;)");
    FAIL_IF_NULL(sig);

    sig = DetectEngineAppendSig(de_ctx, "alert tcp any any -> any any "
                  "(Classtype:Bad-UnkNown; sid:3;)");
    FAIL_IF_NULL(sig);

    sig = DetectEngineAppendSig(de_ctx, "alert tcp any any -> any any "
                  "(Classtype:nothing-wrong; sid:4;)");
    FAIL_IF_NULL(sig);

    sig = DetectEngineAppendSig(de_ctx, "alert tcp any any -> any any "
                  "(Classtype:attempted_dos; Classtype:bad-unknown; sid:5;)");
    FAIL_IF_NULL(sig);
    FAIL_IF_NOT(sig->prio == 2);

    /* duplicate test */
    sig = DetectEngineAppendSig(de_ctx, "alert tcp any any -> any any "
                  "(Classtype:nothing-wrong; Classtype:Bad-UnkNown; sid:6;)");
    FAIL_IF_NULL(sig);
    FAIL_IF_NOT(sig->prio == 2);

    DetectEngineCtxFree(de_ctx);
    PASS;
}

/**
 * \test Check that the signatures are assigned priority based on classtype they
 *       are given.
 */
static int DetectClasstypeTest03(void)
{
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);

    FILE *fd = SCClassConfGenerateValidDummyClassConfigFD01();
    FAIL_IF_NULL(fd);
    SCClassConfLoadClassficationConfigFile(de_ctx, fd);

    Signature *sig = DetectEngineAppendSig(de_ctx, "alert tcp any any -> any any "
                  "(msg:\"Classtype test\"; Classtype:bad-unknown; priority:1; sid:1;)");
    FAIL_IF_NULL(sig);
    FAIL_IF_NOT(sig->prio == 1);

    sig = DetectEngineAppendSig(de_ctx, "alert tcp any any -> any any "
                  "(msg:\"Classtype test\"; Classtype:unKnoWn; "
                  "priority:3; sid:2;)");
    FAIL_IF_NULL(sig);
    FAIL_IF_NOT(sig->prio == 3);

    sig = DetectEngineAppendSig(de_ctx, "alert tcp any any -> any any (msg:\"Classtype test\"; "
                  "Classtype:nothing-wrong; priority:1; sid:3;)");
    FAIL_IF_NOT(sig->prio == 1);

    sig = DetectEngineAppendSig(de_ctx, "alert tcp any any -> any any "
                  "(msg:\"Classtype test\"; Classtype:bad-unknown; Classtype:undefined; "
                  "priority:5; sid:4;)");
    FAIL_IF_NULL(sig);
    FAIL_IF_NOT(sig->prio == 5);

    DetectEngineCtxFree(de_ctx);
    PASS;
}

/**
 * \brief This function registers unit tests for Classification Config API.
 */
static void DetectClasstypeRegisterTests(void)
{
    UtRegisterTest("DetectClasstypeTest01", DetectClasstypeTest01);
    UtRegisterTest("DetectClasstypeTest02", DetectClasstypeTest02);
    UtRegisterTest("DetectClasstypeTest03", DetectClasstypeTest03);
}
#endif /* UNITTESTS */
