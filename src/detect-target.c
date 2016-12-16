/* Copyright (C) 2017 Open Information Security Foundation
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
 * \author Eric Leblond <eric@regit.org>
 *
 * target keyword allow rules writer to specify information about target of the attack
 */

#include "suricata-common.h"
#include "util-unittest.h"

#include "detect-parse.h"
#include "detect-engine.h"

#include "detect-target.h"

/**
 * \brief Regex for parsing our keyword options
 */
#define PARSE_REGEX  "^\\s*(src_ip|dest_ip)\\s*$"

static pcre *parse_regex;
static pcre_extra *parse_regex_study;

/* Prototypes of functions registered in DetectTargetRegister below */
static int DetectTargetSetup (DetectEngineCtx *, Signature *, const char *);
static void DetectTargetRegisterTests (void);

/**
 * \brief Registration function for target keyword
 *
 */
void DetectTargetRegister(void) {
    /* keyword name: this is how the keyword is used in a rule */
    sigmatch_table[DETECT_TARGET].name = "target";
    /* description: listed in "suricata --list-keywords=all" */
    sigmatch_table[DETECT_TARGET].desc = "indicate to output module which side is the target of the attack";
    /* link to further documentation of the keyword. Normally on the Suricata redmine/wiki */
    sigmatch_table[DETECT_TARGET].url =  DOC_URL DOC_VERSION "/rules/meta.html#target";
    /* match function is called when the signature is inspected on a packet */
    sigmatch_table[DETECT_TARGET].Match = NULL;
    /* setup function is called during signature parsing, when the target
     * keyword is encountered in the rule */
    sigmatch_table[DETECT_TARGET].Setup = DetectTargetSetup;
    /* free function is called when the detect engine is freed. Normally at
     * shutdown, but also during rule reloads. */
    sigmatch_table[DETECT_TARGET].Free = NULL;
    /* registers unittests into the system */
    sigmatch_table[DETECT_TARGET].RegisterTests = DetectTargetRegisterTests;

    /* set up the PCRE for keyword parsing */
    DetectSetupParseRegexes(PARSE_REGEX, &parse_regex, &parse_regex_study);
}

/**
 * \brief This function is used to parse target options passed via target: keyword
 *
 * \param targetstr Pointer to the user provided target options
 *
 * \retval targetd pointer to DetectTargetData on success
 * \retval NULL on failure
 */
static int DetectTargetParse(Signature *s, const char *targetstr)
{
#define MAX_SUBSTRINGS 30
    int ret = 0, res = 0;
    int ov[MAX_SUBSTRINGS];
    char value[10];

    ret = pcre_exec(parse_regex, parse_regex_study,
                    targetstr, strlen(targetstr), 0, 0, ov, MAX_SUBSTRINGS);
    if (ret < 1) {
        SCLogError(SC_ERR_PCRE_MATCH, "pcre_exec parse error, ret %" PRId32 ", string %s", ret, targetstr);
        return -1;
    }

    res = pcre_copy_substring(targetstr, ov, MAX_SUBSTRINGS, 1,
                              value, sizeof(value));
    if (res < 0) {
        SCLogError(SC_ERR_PCRE_GET_SUBSTRING, "pcre_get_substring failed");
        return -1;
    }

    /* now check key value */
    if (!strcmp(value, "src_ip")) {
        if (s->flags & SIG_FLAG_DEST_IS_TARGET) {
            SCLogError(SC_ERR_CONFLICTING_RULE_KEYWORDS,
                       "Conflicting values of target keyword");
            return -1;
        }
        s->flags |= SIG_FLAG_SRC_IS_TARGET;
    } else if (!strcmp(value, "dest_ip")) {
        if (s->flags & SIG_FLAG_SRC_IS_TARGET) {
            SCLogError(SC_ERR_CONFLICTING_RULE_KEYWORDS,
                       "Conflicting values of target keyword");
            return -1;
        }
        s->flags |= SIG_FLAG_DEST_IS_TARGET;
    } else {
        SCLogError(SC_ERR_INVALID_VALUE, "only 'src_ip' and 'dest_ip' are supported as target value");
        return -1;
    }
    return 0;
}

/**
 * \brief parse the options from the 'target' keyword in the rule into
 *        the Signature data structure.
 *
 * \param de_ctx pointer to the Detection Engine Context
 * \param s pointer to the Current Signature
 * \param targetstr pointer to the user provided target options
 *
 * \retval 0 on Success
 * \retval -1 on Failure
 */
static int DetectTargetSetup(DetectEngineCtx *de_ctx, Signature *s, const char *targetstr)
{
    int ret = DetectTargetParse(s, targetstr);
    if (ret < 0)
        return -1;

    return 0;
}

#ifdef UNITTESTS

static int DetectTargetSignatureTest01(void)
{
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);

    Signature *sig = DetectEngineAppendSig(de_ctx, "alert ip any any -> any any (target: dest_ip; sid:1; rev:1;)");
    FAIL_IF_NULL(sig);

    DetectEngineCtxFree(de_ctx);
    PASS;
}

#endif /* UNITTESTS */

/**
 * \brief this function registers unit tests for DetectTarget
 */
void DetectTargetRegisterTests(void) {
#ifdef UNITTESTS
    UtRegisterTest("DetectTargetSignatureTest01",
                   DetectTargetSignatureTest01);
#endif /* UNITTESTS */
}
