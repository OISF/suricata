/* Copyright (C) 2015-2016 Open Information Security Foundation
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
 * \author XXX Yourname <youremail@yourdomain>
 *
 * XXX Short description of the purpose of this keyword
 */

#include "suricata-common.h"
#include "util-unittest.h"

#include "detect-parse.h"
#include "detect-engine.h"

#include "detect-template.h"

/**
 * \brief Regex for parsing our keyword options
 */
#define PARSE_REGEX  "^\\s*([0-9]+)?\\s*,s*([0-9]+)?\\s*$"
static pcre *parse_regex;
static pcre_extra *parse_regex_study;

/* Prototypes of functions registered in DetectTemplateRegister below */
static int DetectTemplateMatch (ThreadVars *, DetectEngineThreadCtx *,
        Packet *, const Signature *, const SigMatchCtx *);
static int DetectTemplateSetup (DetectEngineCtx *, Signature *, const char *);
static void DetectTemplateFree (void *);
static void DetectTemplateRegisterTests (void);

/**
 * \brief Registration function for template: keyword
 *
 * This function is called once in the 'lifetime' of the engine.
 */
void DetectTemplateRegister(void) {
    /* keyword name: this is how the keyword is used in a rule */
    sigmatch_table[DETECT_TEMPLATE].name = "template";
    /* description: listed in "suricata --list-keywords=all" */
    sigmatch_table[DETECT_TEMPLATE].desc = "give an introduction into how a detection module works";
    /* link to further documentation of the keyword. Normally on the Suricata redmine/wiki */
    sigmatch_table[DETECT_TEMPLATE].url = "https://redmine.openinfosecfoundation.org/projects/suricata/wiki/Suricata_Developers_Guide";
    /* match function is called when the signature is inspected on a packet */
    sigmatch_table[DETECT_TEMPLATE].Match = DetectTemplateMatch;
    /* setup function is called during signature parsing, when the template
     * keyword is encountered in the rule */
    sigmatch_table[DETECT_TEMPLATE].Setup = DetectTemplateSetup;
    /* free function is called when the detect engine is freed. Normally at
     * shutdown, but also during rule reloads. */
    sigmatch_table[DETECT_TEMPLATE].Free = DetectTemplateFree;
    /* registers unittests into the system */
    sigmatch_table[DETECT_TEMPLATE].RegisterTests = DetectTemplateRegisterTests;

    /* set up the PCRE for keyword parsing */
    DetectSetupParseRegexes(PARSE_REGEX, &parse_regex, &parse_regex_study);
}

/**
 * \brief This function is used to match TEMPLATE rule option on a packet
 *
 * \param t pointer to thread vars
 * \param det_ctx pointer to the pattern matcher thread
 * \param p pointer to the current packet
 * \param m pointer to the sigmatch with context that we will cast into DetectTemplateData
 *
 * \retval 0 no match
 * \retval 1 match
 */
static int DetectTemplateMatch (ThreadVars *t, DetectEngineThreadCtx *det_ctx, Packet *p,
                                const Signature *s, const SigMatchCtx *ctx)
{
    int ret = 0;
    const DetectTemplateData *templated = (const DetectTemplateData *) ctx;
#if 0
    if (PKT_IS_PSEUDOPKT(p)) {
        /* fake pkt */
    }

    if (PKT_IS_IPV4(p)) {
        /* ipv4 pkt */
    } else if (PKT_IS_IPV6(p)) {
        /* ipv6 pkt */
    } else {
        SCLogDebug("packet is of not IPv4 or IPv6");
        return ret;
    }
#endif
    /* packet payload access */
    if (p->payload != NULL && p->payload_len > 0) {
        if (templated->arg1 == p->payload[0] &&
            templated->arg2 == p->payload[p->payload_len - 1])
        {
            ret = 1;
        }
    }

    return ret;
}

/**
 * \brief This function is used to parse template options passed via template: keyword
 *
 * \param templatestr Pointer to the user provided template options
 *
 * \retval templated pointer to DetectTemplateData on success
 * \retval NULL on failure
 */
static DetectTemplateData *DetectTemplateParse (const char *templatestr)
{
    DetectTemplateData *templated = NULL;
    char arg1[4] = "";
    char arg2[4] = "";
#define MAX_SUBSTRINGS 30
    int ret = 0, res = 0;
    int ov[MAX_SUBSTRINGS];

    ret = pcre_exec(parse_regex, parse_regex_study,
                    templatestr, strlen(templatestr),
                    0, 0, ov, MAX_SUBSTRINGS);
    if (ret != 3) {
        SCLogError(SC_ERR_PCRE_MATCH, "parse error, ret %" PRId32 "", ret);
        goto error;
    }

    res = pcre_copy_substring((char *) templatestr, ov, MAX_SUBSTRINGS, 1, arg1, sizeof(arg1));
    if (res < 0) {
        SCLogError(SC_ERR_PCRE_GET_SUBSTRING, "pcre_copy_substring failed");
        goto error;
    }
    SCLogDebug("Arg1 \"%s\"", arg1);

    if (ret >= 3) {
        res = pcre_copy_substring((char *) templatestr, ov, MAX_SUBSTRINGS, 2, arg2, sizeof(arg2));
        if (res < 0) {
            SCLogError(SC_ERR_PCRE_GET_SUBSTRING, "pcre_copy_substring failed");
            goto error;
        }
        SCLogDebug("Arg2 \"%s\"", arg2);

    }

    templated = SCMalloc(sizeof (DetectTemplateData));
    if (unlikely(templated == NULL))
        goto error;
    templated->arg1 = (uint8_t)atoi(arg1);
    templated->arg2 = (uint8_t)atoi(arg2);

    return templated;

error:
    if (templated)
        SCFree(templated);
    return NULL;
}

/**
 * \brief parse the options from the 'template' keyword in the rule into
 *        the Signature data structure.
 *
 * \param de_ctx pointer to the Detection Engine Context
 * \param s pointer to the Current Signature
 * \param templatestr pointer to the user provided template options
 *
 * \retval 0 on Success
 * \retval -1 on Failure
 */
static int DetectTemplateSetup (DetectEngineCtx *de_ctx, Signature *s, const char *templatestr)
{
    DetectTemplateData *templated = NULL;
    SigMatch *sm = NULL;

    templated = DetectTemplateParse(templatestr);
    if (templated == NULL)
        goto error;

    sm = SigMatchAlloc();
    if (sm == NULL)
        goto error;

    sm->type = DETECT_TEMPLATE;
    sm->ctx = (void *)templated;

    SigMatchAppendSMToList(s, sm, DETECT_SM_LIST_MATCH);
    s->flags |= SIG_FLAG_REQUIRE_PACKET;

    return 0;

error:
    if (templated != NULL)
        DetectTemplateFree(templated);
    if (sm != NULL)
        SCFree(sm);
    return -1;
}

/**
 * \brief this function will free memory associated with DetectTemplateData
 *
 * \param ptr pointer to DetectTemplateData
 */
static void DetectTemplateFree(void *ptr) {
    DetectTemplateData *templated = (DetectTemplateData *)ptr;

    /* do more specific cleanup here, if needed */

    SCFree(templated);
}

#ifdef UNITTESTS

/**
 * \test description of the test
 */

static int DetectTemplateParseTest01 (void)
{
    DetectTemplateData *templated = DetectTemplateParse("1,10");
    FAIL_IF_NULL(templated);
    FAIL_IF(!(templated->arg1 == 1 && templated->arg2 == 10));
    DetectTemplateFree(templated);
    PASS;
}

static int DetectTemplateSignatureTest01 (void)
{
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);

    Signature *sig = DetectEngineAppendSig(de_ctx, "alert ip any any -> any any (template:1,10; sid:1; rev:1;)");
    FAIL_IF_NULL(sig);

    DetectEngineCtxFree(de_ctx);
    PASS;
}

#endif /* UNITTESTS */

/**
 * \brief this function registers unit tests for DetectTemplate
 */
void DetectTemplateRegisterTests(void) {
#ifdef UNITTESTS
    UtRegisterTest("DetectTemplateParseTest01", DetectTemplateParseTest01);
    UtRegisterTest("DetectTemplateSignatureTest01",
                   DetectTemplateSignatureTest01);
#endif /* UNITTESTS */
}
