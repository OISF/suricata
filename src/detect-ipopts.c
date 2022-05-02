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
 * \author Breno Silva <breno.silva@gmail.com>
 *
 * Implements the ipopts keyword
 */

#include "suricata-common.h"
#include "suricata.h"
#include "decode.h"

#include "detect.h"
#include "detect-parse.h"

#include "flow-var.h"
#include "decode-events.h"

#include "util-debug.h"

#include "detect-ipopts.h"
#include "util-unittest.h"

#define PARSE_REGEX "\\S[A-z]"

static pcre *parse_regex;
static pcre_extra *parse_regex_study;

static int DetectIpOptsMatch (DetectEngineThreadCtx *, Packet *,
        const Signature *, const SigMatchCtx *);
static int DetectIpOptsSetup (DetectEngineCtx *, Signature *, const char *);
void IpOptsRegisterTests(void);
void DetectIpOptsFree(void *);

/**
 * \brief Registration function for ipopts: keyword
 */
void DetectIpOptsRegister (void)
{
    sigmatch_table[DETECT_IPOPTS].name = "ipopts";
    sigmatch_table[DETECT_IPOPTS].desc = "check if a specific IP option is set";
    sigmatch_table[DETECT_IPOPTS].url = "/rules/header-keywords.html#ipopts";
    sigmatch_table[DETECT_IPOPTS].Match = DetectIpOptsMatch;
    sigmatch_table[DETECT_IPOPTS].Setup = DetectIpOptsSetup;
    sigmatch_table[DETECT_IPOPTS].Free  = DetectIpOptsFree;
    sigmatch_table[DETECT_IPOPTS].RegisterTests = IpOptsRegisterTests;

    DetectSetupParseRegexes(PARSE_REGEX, &parse_regex, &parse_regex_study);
}

/**
 * \struct DetectIpOptss_
 * DetectIpOptss_ is used to store supported iptops values
 */

struct DetectIpOpts_ {
    const char *ipopt_name;   /**< ip option name */
    uint16_t code;   /**< ip option flag value */
} ipopts[] = {
    { "rr", IPV4_OPT_FLAG_RR, },
    { "lsrr", IPV4_OPT_FLAG_LSRR, },
    { "eol", IPV4_OPT_FLAG_EOL, },
    { "nop", IPV4_OPT_FLAG_NOP, },
    { "ts", IPV4_OPT_FLAG_TS, },
    { "sec", IPV4_OPT_FLAG_SEC, },
    { "ssrr", IPV4_OPT_FLAG_SSRR, },
    { "satid", IPV4_OPT_FLAG_SID, },
    { "any", 0xffff, },
    { NULL, 0 },
};

/**
 * \internal
 * \brief This function is used to match ip option on a packet with those passed via ipopts:
 *
 * \param t pointer to thread vars
 * \param det_ctx pointer to the pattern matcher thread
 * \param p pointer to the current packet
 * \param s pointer to the Signature
 * \param m pointer to the sigmatch
 *
 * \retval 0 no match
 * \retval 1 match
 */
static int DetectIpOptsMatch (DetectEngineThreadCtx *det_ctx, Packet *p,
        const Signature *s, const SigMatchCtx *ctx)
{
    const DetectIpOptsData *de = (const DetectIpOptsData *)ctx;

    if (!de || !PKT_IS_IPV4(p) || PKT_IS_PSEUDOPKT(p))
        return 0;

    if (p->ip4vars.opts_set & de->ipopt) {
        return 1;
    }

    return 0;
}

/**
 * \internal
 * \brief This function is used to parse ipopts options passed via ipopts: keyword
 *
 * \param rawstr Pointer to the user provided ipopts options
 *
 * \retval de pointer to DetectIpOptsData on success
 * \retval NULL on failure
 */
static DetectIpOptsData *DetectIpOptsParse (const char *rawstr)
{
    int i;
    DetectIpOptsData *de = NULL;
#define MAX_SUBSTRINGS 30
    int ret = 0, found = 0;
    int ov[MAX_SUBSTRINGS];

    ret = pcre_exec(parse_regex, parse_regex_study, rawstr, strlen(rawstr), 0, 0, ov, MAX_SUBSTRINGS);
    if (ret < 1) {
        SCLogError(SC_ERR_PCRE_MATCH, "pcre_exec parse error, ret %" PRId32 ", string %s", ret, rawstr);
        goto error;
    }

    for(i = 0; ipopts[i].ipopt_name != NULL; i++)  {
        if((strcasecmp(ipopts[i].ipopt_name,rawstr)) == 0) {
            found = 1;
            break;
        }
    }

    if(found == 0)
        goto error;

    de = SCMalloc(sizeof(DetectIpOptsData));
    if (unlikely(de == NULL))
        goto error;

    de->ipopt = ipopts[i].code;

    return de;

error:
    if (de) SCFree(de);
    return NULL;
}

/**
 * \internal
 * \brief this function is used to add the parsed ipopts into the current signature
 *
 * \param de_ctx pointer to the Detection Engine Context
 * \param s pointer to the Current Signature
 * \param rawstr pointer to the user provided ipopts options
 *
 * \retval 0 on Success
 * \retval -1 on Failure
 */
static int DetectIpOptsSetup (DetectEngineCtx *de_ctx, Signature *s, const char *rawstr)
{
    DetectIpOptsData *de = NULL;
    SigMatch *sm = NULL;

    de = DetectIpOptsParse(rawstr);
    if (de == NULL)
        goto error;

    sm = SigMatchAlloc();
    if (sm == NULL)
        goto error;

    sm->type = DETECT_IPOPTS;
    sm->ctx = (SigMatchCtx *)de;

    SigMatchAppendSMToList(s, sm, DETECT_SM_LIST_MATCH);
    s->flags |= SIG_FLAG_REQUIRE_PACKET;

    return 0;

error:
    if (de) SCFree(de);
    if (sm) SCFree(sm);
    return -1;
}

/**
 * \internal
 * \brief this function will free memory associated with DetectIpOptsData
 *
 * \param de pointer to DetectIpOptsData
 */
void DetectIpOptsFree(void *de_ptr)
{
    DetectIpOptsData *de = (DetectIpOptsData *)de_ptr;
    if(de) SCFree(de);
}

/*
 * ONLY TESTS BELOW THIS COMMENT
 */

#ifdef UNITTESTS
/**
 * \test IpOptsTestParse01 is a test for a  valid ipopts value
 *
 *  \retval 1 on succces
 *  \retval 0 on failure
 */
static int IpOptsTestParse01 (void)
{
    DetectIpOptsData *de = NULL;
    de = DetectIpOptsParse("lsrr");
    if (de) {
        DetectIpOptsFree(de);
        return 1;
    }

    return 0;
}

/**
 * \test IpOptsTestParse02 is a test for an invalid ipopts value
 *
 *  \retval 1 on succces
 *  \retval 0 on failure
 */
static int IpOptsTestParse02 (void)
{
    DetectIpOptsData *de = NULL;
    de = DetectIpOptsParse("invalidopt");
    if (de) {
        DetectIpOptsFree(de);
        return 0;
    }

    return 1;
}

/**
 * \test IpOptsTestParse03 test the match function on a packet that needs to match
 *
 *  \retval 1 on succces
 *  \retval 0 on failure
 */
static int IpOptsTestParse03 (void)
{
    Packet *p = PacketGetFromAlloc();
    if (unlikely(p == NULL))
        return 0;
    ThreadVars tv;
    int ret = 0;
    DetectIpOptsData *de = NULL;
    SigMatch *sm = NULL;
    IPV4Hdr ip4h;

    memset(&tv, 0, sizeof(ThreadVars));
    memset(&ip4h, 0, sizeof(IPV4Hdr));

    p->ip4h = &ip4h;
    p->ip4vars.opts_set = IPV4_OPT_FLAG_RR;

    de = DetectIpOptsParse("rr");

    if (de == NULL)
        goto error;

    sm = SigMatchAlloc();
    if (sm == NULL)
        goto error;

    sm->type = DETECT_IPOPTS;
    sm->ctx = (SigMatchCtx *)de;

    ret = DetectIpOptsMatch(NULL, p, NULL, sm->ctx);

    if(ret) {
        SCFree(p);
        return 1;
    }

error:
    if (de) SCFree(de);
    if (sm) SCFree(sm);
    SCFree(p);
    return 0;
}

/**
 * \test IpOptsTestParse04 test the match function on a packet that needs to not match
 *
 *  \retval 1 on succces
 *  \retval 0 on failure
 */
static int IpOptsTestParse04 (void)
{
    Packet *p = PacketGetFromAlloc();
    if (unlikely(p == NULL))
        return 0;
    ThreadVars tv;
    int ret = 0;
    DetectIpOptsData *de = NULL;
    SigMatch *sm = NULL;
    IPV4Hdr ip4h;

    memset(&tv, 0, sizeof(ThreadVars));
    memset(&ip4h, 0, sizeof(IPV4Hdr));

    p->ip4h = &ip4h;
    p->ip4vars.opts_set = IPV4_OPT_FLAG_RR;

    de = DetectIpOptsParse("lsrr");

    if (de == NULL)
        goto error;

    sm = SigMatchAlloc();
    if (sm == NULL)
        goto error;

    sm->type = DETECT_IPOPTS;
    sm->ctx = (SigMatchCtx *)de;

    ret = DetectIpOptsMatch(NULL, p, NULL, sm->ctx);

    if(ret) {
        SCFree(p);
        return 0;
    }

    /* Error expected. */
error:
    if (de) SCFree(de);
    if (sm) SCFree(sm);
    SCFree(p);
    return 1;
}
#endif /* UNITTESTS */

/**
 * \brief this function registers unit tests for IpOpts
 */
void IpOptsRegisterTests(void)
{
#ifdef UNITTESTS
    UtRegisterTest("IpOptsTestParse01", IpOptsTestParse01);
    UtRegisterTest("IpOptsTestParse02", IpOptsTestParse02);
    UtRegisterTest("IpOptsTestParse03", IpOptsTestParse03);
    UtRegisterTest("IpOptsTestParse04", IpOptsTestParse04);
#endif /* UNITTESTS */
}
