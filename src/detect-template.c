/* Copyright (C) 2015-2020 Open Information Security Foundation
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
#include "util-byte.h"

#include "detect-parse.h"

#include "detect-template.h"

#ifdef UNITTESTS
#endif
/**
 * \brief Regex for parsing our keyword options
 */
#define PARSE_REGEX  "^\\s*([0-9]+)?\\s*,s*([0-9]+)?\\s*$"
static DetectParseRegex parse_regex;

/* Prototypes of functions registered in DetectTemplateRegister below */
static int DetectTemplateMatch (DetectEngineThreadCtx *,
        Packet *, const Signature *, const SigMatchCtx *);
static int DetectTemplateSetup (DetectEngineCtx *, Signature *, const char *);
static void DetectTemplateFree (DetectEngineCtx *, void *);
#ifdef UNITTESTS
static void DetectTemplateRegisterTests (void);
#endif

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
#ifdef UNITTESTS
    /* registers unittests into the system */
    sigmatch_table[DETECT_TEMPLATE].RegisterTests = DetectTemplateRegisterTests;
#endif
    /* set up the PCRE for keyword parsing */
    DetectSetupParseRegexes(PARSE_REGEX, &parse_regex);
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
static int DetectTemplateMatch (DetectEngineThreadCtx *det_ctx, Packet *p,
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
    char arg1[4] = "";
    char arg2[4] = "";
    size_t pcre2len;

    int ret = DetectParsePcreExec(&parse_regex, templatestr, 0, 0);
    if (ret != 3) {
        SCLogError(SC_ERR_PCRE_MATCH, "parse error, ret %" PRId32 "", ret);
        return NULL;
    }

    pcre2len = sizeof(arg1);
    ret = pcre2_substring_copy_bynumber(parse_regex.match, 1, (PCRE2_UCHAR8 *)arg1, &pcre2len);
    if (ret < 0) {
        SCLogError(SC_ERR_PCRE_GET_SUBSTRING, "pcre2_substring_copy_bynumber failed");
        return NULL;
    }
    SCLogDebug("Arg1 \"%s\"", arg1);

    pcre2len = sizeof(arg2);
    ret = pcre2_substring_copy_bynumber(parse_regex.match, 2, (PCRE2_UCHAR8 *)arg2, &pcre2len);
    if (ret < 0) {
        SCLogError(SC_ERR_PCRE_GET_SUBSTRING, "pcre2_substring_copy_bynumber failed");
        return NULL;
    }
    SCLogDebug("Arg2 \"%s\"", arg2);

    DetectTemplateData *templated = SCMalloc(sizeof (DetectTemplateData));
    if (unlikely(templated == NULL))
        return NULL;

    if (ByteExtractStringUint8(&templated->arg1, 10, 0, (const char *)arg1) < 0) {
        SCFree(templated);
        return NULL;
    }
    if (ByteExtractStringUint8(&templated->arg2, 10, 0, (const char *)arg2) < 0) {
        SCFree(templated);
        return NULL;
    }
    return templated;
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
    DetectTemplateData *templated = DetectTemplateParse(templatestr);
    if (templated == NULL)
        return -1;

    SigMatch *sm = SigMatchAlloc();
    if (sm == NULL) {
        DetectTemplateFree(de_ctx, templated);
        return -1;
    }

    sm->type = DETECT_TEMPLATE;
    sm->ctx = (void *)templated;

    SigMatchAppendSMToList(s, sm, DETECT_SM_LIST_MATCH);
    s->flags |= SIG_FLAG_REQUIRE_PACKET;

    return 0;
}

/**
 * \brief this function will free memory associated with DetectTemplateData
 *
 * \param ptr pointer to DetectTemplateData
 */
static void DetectTemplateFree(DetectEngineCtx *de_ctx, void *ptr)
{
    DetectTemplateData *templated = (DetectTemplateData *)ptr;

    /* do more specific cleanup here, if needed */

    SCFree(templated);
}

#ifdef UNITTESTS
#include "tests/detect-template.c"
#endif
