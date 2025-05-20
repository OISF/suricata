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
 * Implements the ipopts keyword
 */

#include "suricata-common.h"
#include "suricata.h"

#include "detect.h"
#include "detect-parse.h"

#include "detect-ipopts.h"
#include "util-unittest.h"
#include "util-unittest-helper.h"

static int DetectIpOptsMatch (DetectEngineThreadCtx *, Packet *,
        const Signature *, const SigMatchCtx *);
static int DetectIpOptsSetup (DetectEngineCtx *, Signature *, const char *);
#ifdef UNITTESTS
static void IpOptsRegisterTests(void);
#endif
void DetectIpOptsFree(DetectEngineCtx *, void *);

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
#ifdef UNITTESTS
    sigmatch_table[DETECT_IPOPTS].RegisterTests = IpOptsRegisterTests;
#endif
}

/**
 * \struct DetectIpOptss_
 * DetectIpOptss_ is used to store supported iptops values
 */

struct DetectIpOpts_ {
    const char *ipopt_name;   /**< ip option name */
    uint16_t code;   /**< ip option flag value */
} ipopts[] = {
    {
            "rr",
            IPV4_OPT_FLAG_RR,
    },
    {
            "lsrr",
            IPV4_OPT_FLAG_LSRR,
    },
    {
            "eol",
            IPV4_OPT_FLAG_EOL,
    },
    {
            "nop",
            IPV4_OPT_FLAG_NOP,
    },
    {
            "ts",
            IPV4_OPT_FLAG_TS,
    },
    {
            "sec",
            IPV4_OPT_FLAG_SEC,
    },
    {
            "esec",
            IPV4_OPT_FLAG_ESEC,
    },
    {
            "ssrr",
            IPV4_OPT_FLAG_SSRR,
    },
    {
            "satid",
            IPV4_OPT_FLAG_SID,
    },
    {
            "any",
            0xffff,
    },
    { NULL, 0 },
};

/**
 * \brief Return human readable value for ipopts flag
 *
 * \param flag uint16_t DetectIpOptsData ipopts flag value
 */
const char *IpOptsFlagToString(uint16_t flag)
{
    switch (flag) {
        case IPV4_OPT_FLAG_RR:
            return "rr";
        case IPV4_OPT_FLAG_LSRR:
            return "lsrr";
        case IPV4_OPT_FLAG_EOL:
            return "eol";
        case IPV4_OPT_FLAG_NOP:
            return "nop";
        case IPV4_OPT_FLAG_TS:
            return "ts";
        case IPV4_OPT_FLAG_SEC:
            return "sec";
        case IPV4_OPT_FLAG_ESEC:
            return "esec";
        case IPV4_OPT_FLAG_SSRR:
            return "ssrr";
        case IPV4_OPT_FLAG_SID:
            return "satid";
        case 0xffff:
            return "any";
        default:
            return NULL;
    }
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
static int DetectIpOptsMatch (DetectEngineThreadCtx *det_ctx, Packet *p,
        const Signature *s, const SigMatchCtx *ctx)
{
    DEBUG_VALIDATE_BUG_ON(PKT_IS_PSEUDOPKT(p));

    const DetectIpOptsData *de = (const DetectIpOptsData *)ctx;

    if (!de || !PacketIsIPv4(p))
        return 0;

    return (p->l3.vars.ip4.opts_set & de->ipopt) == de->ipopt;
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
    if (rawstr == NULL || strlen(rawstr) == 0)
        return NULL;

    int i;
    bool found = false;
    for(i = 0; ipopts[i].ipopt_name != NULL; i++)  {
        if((strcasecmp(ipopts[i].ipopt_name,rawstr)) == 0) {
            found = true;
            break;
        }
    }

    if (!found) {
        SCLogError("unknown IP option specified \"%s\"", rawstr);
        return NULL;
    }

    DetectIpOptsData *de = SCMalloc(sizeof(DetectIpOptsData));
    if (unlikely(de == NULL))
        return NULL;

    de->ipopt = ipopts[i].code;

    return de;
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
    DetectIpOptsData *de = DetectIpOptsParse(rawstr);
    if (de == NULL)
        goto error;

    if (SCSigMatchAppendSMToList(
                de_ctx, s, DETECT_IPOPTS, (SigMatchCtx *)de, DETECT_SM_LIST_MATCH) == NULL) {
        goto error;
    }
    s->flags |= SIG_FLAG_REQUIRE_PACKET;

    return 0;

error:
    if (de)
        SCFree(de);
    return -1;
}

/**
 * \internal
 * \brief this function will free memory associated with DetectIpOptsData
 *
 * \param de pointer to DetectIpOptsData
 */
void DetectIpOptsFree(DetectEngineCtx *de_ctx, void *de_ptr)
{
    if (de_ptr) {
        SCFree(de_ptr);
    }
}

/*
 * ONLY TESTS BELOW THIS COMMENT
 */

#ifdef UNITTESTS
/**
 * \test IpOptsTestParse01 is a test for a  valid ipopts value
 */
static int IpOptsTestParse01 (void)
{
    DetectIpOptsData *de = DetectIpOptsParse("lsrr");

    FAIL_IF_NULL(de);

    DetectIpOptsFree(NULL, de);

    PASS;
}

/**
 * \test IpOptsTestParse02 is a test for an invalid ipopts value
 */
static int IpOptsTestParse02 (void)
{
    DetectIpOptsData *de = DetectIpOptsParse("invalidopt");

    FAIL_IF_NOT_NULL(de);

    DetectIpOptsFree(NULL, de);

    PASS;
}

/**
 * \test IpOptsTestParse03 test the match function on a packet that needs to match
 */
static int IpOptsTestParse03 (void)
{
    Packet *p = PacketGetFromAlloc();
    FAIL_IF_NULL(p);
    ThreadVars tv;
    IPV4Hdr ip4h;

    memset(&tv, 0, sizeof(ThreadVars));
    memset(&ip4h, 0, sizeof(IPV4Hdr));

    UTHSetIPV4Hdr(p, &ip4h);
    p->l3.vars.ip4.opts_set = IPV4_OPT_FLAG_RR;

    DetectIpOptsData *de = DetectIpOptsParse("rr");
    FAIL_IF_NULL(de);

    SigMatch *sm = SigMatchAlloc();
    FAIL_IF_NULL(sm);

    sm->type = DETECT_IPOPTS;
    sm->ctx = (SigMatchCtx *)de;

    FAIL_IF_NOT(DetectIpOptsMatch(NULL, p, NULL, sm->ctx));

    SCFree(de);
    SCFree(sm);
    SCFree(p);

    PASS;
}

/**
 * \test IpOptsTestParse04 test the match function on a packet that needs to not match
 */
static int IpOptsTestParse04 (void)
{
    Packet *p = PacketGetFromAlloc();
    FAIL_IF_NULL(p);
    ThreadVars tv;
    IPV4Hdr ip4h;

    memset(&tv, 0, sizeof(ThreadVars));
    memset(&ip4h, 0, sizeof(IPV4Hdr));

    UTHSetIPV4Hdr(p, &ip4h);
    p->l3.vars.ip4.opts_set = IPV4_OPT_FLAG_RR;

    DetectIpOptsData *de = DetectIpOptsParse("lsrr");
    FAIL_IF_NULL(de);

    SigMatch *sm = SigMatchAlloc();
    FAIL_IF_NULL(sm);

    sm->type = DETECT_IPOPTS;
    sm->ctx = (SigMatchCtx *)de;

    FAIL_IF(DetectIpOptsMatch(NULL, p, NULL, sm->ctx));

    SCFree(de);
    SCFree(sm);
    SCFree(p);

    PASS;
}

/**
 * \test IpOptsTestParse05 tests the NULL and empty string
 */
static int IpOptsTestParse05(void)
{
    DetectIpOptsData *de = DetectIpOptsParse("");
    FAIL_IF_NOT_NULL(de);

    de = DetectIpOptsParse(NULL);
    FAIL_IF_NOT_NULL(de);

    PASS;
}

/**
 * \brief this function registers unit tests for IpOpts
 */
void IpOptsRegisterTests(void)
{
    UtRegisterTest("IpOptsTestParse01", IpOptsTestParse01);
    UtRegisterTest("IpOptsTestParse02", IpOptsTestParse02);
    UtRegisterTest("IpOptsTestParse03", IpOptsTestParse03);
    UtRegisterTest("IpOptsTestParse04", IpOptsTestParse04);
    UtRegisterTest("IpOptsTestParse05", IpOptsTestParse05);
}
#endif /* UNITTESTS */
