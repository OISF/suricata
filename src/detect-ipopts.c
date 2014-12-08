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

/* Need to get the DIpOpts[] array */
#define DETECT_EVENTS

#include "detect-ipopts.h"
#include "util-unittest.h"

#define PARSE_REGEX "\\S[A-z]"

static pcre *parse_regex;
static pcre_extra *parse_regex_study;

int DetectIpOptsMatch (ThreadVars *, DetectEngineThreadCtx *, Packet *, Signature *, const SigMatchCtx *);
static int DetectIpOptsSetup (DetectEngineCtx *, Signature *, char *);
void IpOptsRegisterTests(void);
void DetectIpOptsFree(void *);

/**
 * \brief Registration function for ipopts: keyword
 */
void DetectIpOptsRegister (void)
{
    sigmatch_table[DETECT_IPOPTS].name = "ipopts";
    sigmatch_table[DETECT_IPOPTS].desc = "check if a specific IP option is set";
    sigmatch_table[DETECT_IPOPTS].url = "https://redmine.openinfosecfoundation.org/projects/suricata/wiki/Header_keywords#Ipopts";
    sigmatch_table[DETECT_IPOPTS].Match = DetectIpOptsMatch;
    sigmatch_table[DETECT_IPOPTS].Setup = DetectIpOptsSetup;
    sigmatch_table[DETECT_IPOPTS].Free  = DetectIpOptsFree;
    sigmatch_table[DETECT_IPOPTS].RegisterTests = IpOptsRegisterTests;

    const char *eb;
    int eo;
    int opts = 0;

    parse_regex = pcre_compile(PARSE_REGEX, opts, &eb, &eo, NULL);
    if(parse_regex == NULL)
    {
        SCLogError(SC_ERR_PCRE_COMPILE, "pcre compile of \"%s\" failed at offset %" PRId32 ": %s", PARSE_REGEX, eo, eb);
        goto error;
    }

    parse_regex_study = pcre_study(parse_regex, 0, &eb);
    if(eb != NULL)
    {
        SCLogError(SC_ERR_PCRE_STUDY, "pcre study failed: %s", eb);
        goto error;
    }
    return;

error:
    return;

}

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
int DetectIpOptsMatch (ThreadVars *t, DetectEngineThreadCtx *det_ctx, Packet *p, Signature *s, const SigMatchCtx *ctx)
{
    int ret = 0;
    int ipopt = 0;
    const DetectIpOptsData *de = (const DetectIpOptsData *)ctx;

    if (!de || !PKT_IS_IPV4(p) || PKT_IS_PSEUDOPKT(p))
        return ret;

    /* IPV4_OPT_ANY matches on any options */

    if (p->IPV4_OPTS_CNT && (de->ipopt == IPV4_OPT_ANY)) {
        return 1;
    }

    /* Loop through instead of using o_xxx direct access fields so that
     * future options do not require any modification here.
     */

    while(ipopt < p->IPV4_OPTS_CNT) {
        if (p->IPV4_OPTS[ipopt].type == de->ipopt) {
            return 1;
        }
        ipopt++;
    }

    return ret;
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
DetectIpOptsData *DetectIpOptsParse (char *rawstr)
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

    for(i = 0; DIpOpts[i].ipopt_name != NULL; i++)  {
        if((strcasecmp(DIpOpts[i].ipopt_name,rawstr)) == 0) {
            found = 1;
            break;
        }
    }

    if(found == 0)
        goto error;

    de = SCMalloc(sizeof(DetectIpOptsData));
    if (unlikely(de == NULL))
        goto error;

    de->ipopt = DIpOpts[i].code;

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
static int DetectIpOptsSetup (DetectEngineCtx *de_ctx, Signature *s, char *rawstr)
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
int IpOptsTestParse01 (void)
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
int IpOptsTestParse02 (void)
{
    DetectIpOptsData *de = NULL;
    de = DetectIpOptsParse("invalidopt");
    if (de) {
        DetectIpOptsFree(de);
        return 1;
    }

    return 0;
}

/**
 * \test IpOptsTestParse03 test the match function on a packet that needs to match
 *
 *  \retval 1 on succces
 *  \retval 0 on failure
 */
int IpOptsTestParse03 (void)
{
    Packet *p = SCMalloc(SIZE_OF_PACKET);
    if (unlikely(p == NULL))
        return 0;
    ThreadVars tv;
    int ret = 0;
    DetectIpOptsData *de = NULL;
    SigMatch *sm = NULL;
    IPV4Hdr ip4h;

    memset(&tv, 0, sizeof(ThreadVars));
    memset(p, 0, SIZE_OF_PACKET);
    memset(&ip4h, 0, sizeof(IPV4Hdr));

    p->ip4h = &ip4h;
    p->IPV4_OPTS[0].type = IPV4_OPT_RR;

    p->IPV4_OPTS_CNT++;

    de = DetectIpOptsParse("rr");

    if (de == NULL)
        goto error;

    sm = SigMatchAlloc();
    if (sm == NULL)
        goto error;

    sm->type = DETECT_IPOPTS;
    sm->ctx = (SigMatchCtx *)de;

    ret = DetectIpOptsMatch(&tv, NULL, p, NULL, sm->ctx);

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
int IpOptsTestParse04 (void)
{
    Packet *p = SCMalloc(SIZE_OF_PACKET);
    if (unlikely(p == NULL))
        return 0;
    ThreadVars tv;
    int ret = 0;
    DetectIpOptsData *de = NULL;
    SigMatch *sm = NULL;
    IPV4Hdr ip4h;

    memset(&tv, 0, sizeof(ThreadVars));
    memset(p, 0, SIZE_OF_PACKET);
    memset(&ip4h, 0, sizeof(IPV4Hdr));

    p->ip4h = &ip4h;
    p->IPV4_OPTS[0].type = IPV4_OPT_RR;

    p->IPV4_OPTS_CNT++;

    de = DetectIpOptsParse("lsrr");

    if (de == NULL)
        goto error;

    sm = SigMatchAlloc();
    if (sm == NULL)
        goto error;

    sm->type = DETECT_IPOPTS;
    sm->ctx = (SigMatchCtx *)de;

    ret = DetectIpOptsMatch(&tv, NULL, p, NULL, sm->ctx);

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
#endif /* UNITTESTS */

/**
 * \brief this function registers unit tests for IpOpts
 */
void IpOptsRegisterTests(void)
{
#ifdef UNITTESTS
    UtRegisterTest("IpOptsTestParse01", IpOptsTestParse01, 1);
    UtRegisterTest("IpOptsTestParse02", IpOptsTestParse02, 0);
    UtRegisterTest("IpOptsTestParse03", IpOptsTestParse03, 1);
    UtRegisterTest("IpOptsTestParse04", IpOptsTestParse04, 0);
#endif /* UNITTESTS */
}
