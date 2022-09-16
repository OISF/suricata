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
 * \author Gerardo Iglesias <iglesiasg@gmail.com>
 *
 * Implements icode keyword support
 */

#include "suricata-common.h"
#ifdef UNITTESTS
#include "util-unittest-helper.h"
#include "util-unittest.h"
#include "detect-engine-build.h"
#endif

#include "detect-parse.h"
#include "detect-engine-uint.h"

#include "detect-icode.h"

/**
 *\brief Regex for parsing our icode options
 */

static int DetectICodeMatch(DetectEngineThreadCtx *, Packet *,
        const Signature *, const SigMatchCtx *);
static int DetectICodeSetup(DetectEngineCtx *, Signature *, const char *);
#ifdef UNITTESTS
static void DetectICodeRegisterTests(void);
#endif
void DetectICodeFree(DetectEngineCtx *, void *);

static int PrefilterSetupICode(DetectEngineCtx *de_ctx, SigGroupHead *sgh);
static bool PrefilterICodeIsPrefilterable(const Signature *s);

/**
 * \brief Registration function for icode: keyword
 */
void DetectICodeRegister (void)
{
    sigmatch_table[DETECT_ICODE].name = "icode";
    sigmatch_table[DETECT_ICODE].desc = "match on specific ICMP id-value";
    sigmatch_table[DETECT_ICODE].url = "/rules/header-keywords.html#icode";
    sigmatch_table[DETECT_ICODE].Match = DetectICodeMatch;
    sigmatch_table[DETECT_ICODE].Setup = DetectICodeSetup;
    sigmatch_table[DETECT_ICODE].Free = DetectICodeFree;
#ifdef UNITTESTS
    sigmatch_table[DETECT_ICODE].RegisterTests = DetectICodeRegisterTests;
#endif
    sigmatch_table[DETECT_ICODE].SupportsPrefilter = PrefilterICodeIsPrefilterable;
    sigmatch_table[DETECT_ICODE].SetupPrefilter = PrefilterSetupICode;
}

/**
 * \brief This function is used to match icode rule option set on a packet with those passed via
 * icode:
 *
 * \param t pointer to thread vars
 * \param det_ctx pointer to the pattern matcher thread
 * \param p pointer to the current packet
 * \param ctx pointer to the sigmatch that we will cast into DetectU8Data
 *
 * \retval 0 no match
 * \retval 1 match
 */
static int DetectICodeMatch (DetectEngineThreadCtx *det_ctx, Packet *p,
        const Signature *s, const SigMatchCtx *ctx)
{
    if (PKT_IS_PSEUDOPKT(p))
        return 0;

    uint8_t picode;
    if (PKT_IS_ICMPV4(p)) {
        picode = ICMPV4_GET_CODE(p);
    } else if (PKT_IS_ICMPV6(p)) {
        picode = ICMPV6_GET_CODE(p);
    } else {
        /* Packet not ICMPv4 nor ICMPv6 */
        return 0;
    }

    const DetectU8Data *icd = (const DetectU8Data *)ctx;
    return DetectU8Match(picode, icd);
}

/**
 * \brief this function is used to add the parsed icode data into the current signature
 *
 * \param de_ctx pointer to the Detection Engine Context
 * \param s pointer to the Current Signature
 * \param icodestr pointer to the user provided icode options
 *
 * \retval 0 on Success
 * \retval -1 on Failure
 */
static int DetectICodeSetup(DetectEngineCtx *de_ctx, Signature *s, const char *icodestr)
{

    DetectU8Data *icd = NULL;
    SigMatch *sm = NULL;

    icd = DetectU8Parse(icodestr);
    if (icd == NULL) goto error;

    sm = SigMatchAlloc();
    if (sm == NULL) goto error;

    sm->type = DETECT_ICODE;
    sm->ctx = (SigMatchCtx *)icd;

    SigMatchAppendSMToList(s, sm, DETECT_SM_LIST_MATCH);
    s->flags |= SIG_FLAG_REQUIRE_PACKET;

    return 0;

error:
    if (icd != NULL)
        rs_detect_u8_free(icd);
    if (sm != NULL) SCFree(sm);
    return -1;
}

/**
 * \brief this function will free memory associated with DetectU8Data
 *
 * \param ptr pointer to DetectU8Data
 */
void DetectICodeFree(DetectEngineCtx *de_ctx, void *ptr)
{
    rs_detect_u8_free(ptr);
}

/* prefilter code */

static void PrefilterPacketICodeMatch(DetectEngineThreadCtx *det_ctx,
        Packet *p, const void *pectx)
{
    if (PKT_IS_PSEUDOPKT(p)) {
        SCReturn;
    }

    uint8_t picode;
    if (PKT_IS_ICMPV4(p)) {
        picode = ICMPV4_GET_CODE(p);
    } else if (PKT_IS_ICMPV6(p)) {
        picode = ICMPV6_GET_CODE(p);
    } else {
        /* Packet not ICMPv4 nor ICMPv6 */
        return;
    }

    const PrefilterPacketU8HashCtx *h = pectx;
    const SigsArray *sa = h->array[picode];
    if (sa) {
        PrefilterAddSids(&det_ctx->pmq, sa->sigs, sa->cnt);
    }
}

static int PrefilterSetupICode(DetectEngineCtx *de_ctx, SigGroupHead *sgh)
{
    return PrefilterSetupPacketHeaderU8Hash(de_ctx, sgh, DETECT_ICODE, PrefilterPacketU8Set,
            PrefilterPacketU8Compare, PrefilterPacketICodeMatch);
}

static bool PrefilterICodeIsPrefilterable(const Signature *s)
{
    const SigMatch *sm;
    for (sm = s->init_data->smlists[DETECT_SM_LIST_MATCH] ; sm != NULL; sm = sm->next) {
        switch (sm->type) {
            case DETECT_ICODE:
                return true;
        }
    }
    return false;
}

#ifdef UNITTESTS
#include "detect-engine.h"

/**
 * \test DetectICodeParseTest01 is a test for setting a valid icode value
 */
static int DetectICodeParseTest01(void)
{
    DetectU8Data *icd = DetectU8Parse("8");
    FAIL_IF_NULL(icd);
    FAIL_IF_NOT(icd->arg1 == 8);
    FAIL_IF_NOT(icd->mode == DETECT_UINT_EQ);
    DetectICodeFree(NULL, icd);

    PASS;
}

/**
 * \test DetectICodeParseTest02 is a test for setting a valid icode value
 *       with ">" operator
 */
static int DetectICodeParseTest02(void)
{
    DetectU8Data *icd = DetectU8Parse(">8");
    FAIL_IF_NULL(icd);
    FAIL_IF_NOT(icd->arg1 == 8);
    FAIL_IF_NOT(icd->mode == DETECT_UINT_GT);
    DetectICodeFree(NULL, icd);

    PASS;
}

/**
 * \test DetectICodeParseTest03 is a test for setting a valid icode value
 *       with "<" operator
 */
static int DetectICodeParseTest03(void)
{
    DetectU8Data *icd = DetectU8Parse("<8");
    FAIL_IF_NULL(icd);
    FAIL_IF_NOT(icd->arg1 == 8);
    FAIL_IF_NOT(icd->mode == DETECT_UINT_LT);
    DetectICodeFree(NULL, icd);

    PASS;
}

/**
 * \test DetectICodeParseTest04 is a test for setting a valid icode value
 *       with "<>" operator
 */
static int DetectICodeParseTest04(void)
{
    DetectU8Data *icd = DetectU8Parse("8<>20");
    FAIL_IF_NULL(icd);
    FAIL_IF_NOT(icd->arg1 == 8);
    FAIL_IF_NOT(icd->arg2 == 20);
    FAIL_IF_NOT(icd->mode == DETECT_UINT_RA);
    DetectICodeFree(NULL, icd);

    PASS;
}

/**
 * \test DetectICodeParseTest05 is a test for setting a valid icode value
 *       with spaces all around
 */
static int DetectICodeParseTest05(void)
{
    DetectU8Data *icd = DetectU8Parse("  8 ");
    FAIL_IF_NULL(icd);
    FAIL_IF_NOT(icd->arg1 == 8);
    FAIL_IF_NOT(icd->mode == DETECT_UINT_EQ);
    DetectICodeFree(NULL, icd);

    PASS;
}

/**
 * \test DetectICodeParseTest06 is a test for setting a valid icode value
 *       with ">" operator and spaces all around
 */
static int DetectICodeParseTest06(void)
{
    DetectU8Data *icd = DetectU8Parse("  >  8 ");
    FAIL_IF_NULL(icd);
    FAIL_IF_NOT(icd->arg1 == 8);
    FAIL_IF_NOT(icd->mode == DETECT_UINT_GT);
    DetectICodeFree(NULL, icd);

    PASS;
}

/**
 * \test DetectICodeParseTest07 is a test for setting a valid icode value
 *       with "<>" operator and spaces all around
 */
static int DetectICodeParseTest07(void)
{
    DetectU8Data *icd = DetectU8Parse("  8  <>  20 ");
    FAIL_IF_NULL(icd);
    FAIL_IF_NOT(icd->arg1 == 8);
    FAIL_IF_NOT(icd->arg2 == 20);
    FAIL_IF_NOT(icd->mode == DETECT_UINT_RA);
    DetectICodeFree(NULL, icd);

    PASS;
}

/**
 * \test DetectICodeParseTest08 is a test for setting an invalid icode value
 */
static int DetectICodeParseTest08(void)
{
    DetectU8Data *icd = DetectU8Parse("> 8 <> 20");
    FAIL_IF_NOT_NULL(icd);

    DetectICodeFree(NULL, icd);
    PASS;
}

/**
 * \test DetectICodeParseTest09 is a test for setting an invalid icode value
 *       with "<<" operator
 */
static int DetectICodeParseTest09(void)
{
    DetectU8Data *icd = DetectU8Parse("8<<20");
    FAIL_IF_NOT_NULL(icd);

    DetectICodeFree(NULL, icd);
    PASS;
}

/**
 * \test DetectICodeMatchTest01 is a test for checking the working of icode
 *       keyword by creating 5 rules and matching a crafted packet against
 *       them. 4 out of 5 rules shall trigger.
 */
static int DetectICodeMatchTest01(void)
{

    Packet *p = NULL;
    Signature *s = NULL;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx;

    memset(&th_v, 0, sizeof(th_v));

    p = UTHBuildPacket(NULL, 0, IPPROTO_ICMP);

    p->icmpv4h->code = 10;

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);

    de_ctx->flags |= DE_QUIET;

    s = DetectEngineAppendSig(de_ctx, "alert icmp any any -> any any (icode:10; sid:1;)");
    FAIL_IF_NULL(s);

    s = DetectEngineAppendSig(de_ctx, "alert icmp any any -> any any (icode:<15; sid:2;)");
    FAIL_IF_NULL(s);

    s = DetectEngineAppendSig(de_ctx, "alert icmp any any -> any any (icode:>20; sid:3;)");
    FAIL_IF_NULL(s);

    s = DetectEngineAppendSig(de_ctx, "alert icmp any any -> any any (icode:8<>20; sid:4;)");
    FAIL_IF_NULL(s);

    s = DetectEngineAppendSig(de_ctx, "alert icmp any any -> any any (icode:20<>8; sid:5;)");
    FAIL_IF_NOT_NULL(s);

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);

    FAIL_IF(PacketAlertCheck(p, 1) == 0);
    FAIL_IF(PacketAlertCheck(p, 2) == 0);
    FAIL_IF(PacketAlertCheck(p, 3));
    FAIL_IF(PacketAlertCheck(p, 4) == 0);

    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);

    UTHFreePackets(&p, 1);

    PASS;
}

/**
 * \brief this function registers unit tests for DetectICode
 */
void DetectICodeRegisterTests(void)
{
    UtRegisterTest("DetectICodeParseTest01", DetectICodeParseTest01);
    UtRegisterTest("DetectICodeParseTest02", DetectICodeParseTest02);
    UtRegisterTest("DetectICodeParseTest03", DetectICodeParseTest03);
    UtRegisterTest("DetectICodeParseTest04", DetectICodeParseTest04);
    UtRegisterTest("DetectICodeParseTest05", DetectICodeParseTest05);
    UtRegisterTest("DetectICodeParseTest06", DetectICodeParseTest06);
    UtRegisterTest("DetectICodeParseTest07", DetectICodeParseTest07);
    UtRegisterTest("DetectICodeParseTest08", DetectICodeParseTest08);
    UtRegisterTest("DetectICodeParseTest09", DetectICodeParseTest09);
    UtRegisterTest("DetectICodeMatchTest01", DetectICodeMatchTest01);
}
#endif /* UNITTESTS */
