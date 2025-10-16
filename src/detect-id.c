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
 * \author Pablo Rincon Crespo <pablo.rincon.crespo@gmail.com>
 *
 * Implements the id keyword
 */

#include "suricata-common.h"
#include "decode.h"
#include "detect.h"

#include "detect-parse.h"
#include "detect-engine.h"
#include "detect-engine-mpm.h"
#include "detect-engine-prefilter-common.h"
#include "detect-engine-uint.h"

#include "detect-id.h"
#include "flow.h"
#include "flow-var.h"

#include "util-debug.h"
#include "util-byte.h"
#include "util-unittest.h"
#include "util-unittest-helper.h"

/**
 * \brief Regex for parsing "id" option, matching number or "number"
 */

static int DetectIdMatch (DetectEngineThreadCtx *, Packet *,
        const Signature *, const SigMatchCtx *);
static int DetectIdSetup (DetectEngineCtx *, Signature *, const char *);
#ifdef UNITTESTS
static void DetectIdRegisterTests(void);
#endif
void DetectIdFree(DetectEngineCtx *, void *);

static int PrefilterSetupId(DetectEngineCtx *de_ctx, SigGroupHead *sgh);
static bool PrefilterIdIsPrefilterable(const Signature *s);

/**
 * \brief Registration function for keyword: id
 */
void DetectIdRegister (void)
{
    sigmatch_table[DETECT_ID].name = "id";
    sigmatch_table[DETECT_ID].desc = "match on a specific IP ID value";
    sigmatch_table[DETECT_ID].url = "/rules/header-keywords.html#id";
    sigmatch_table[DETECT_ID].Match = DetectIdMatch;
    sigmatch_table[DETECT_ID].Setup = DetectIdSetup;
    sigmatch_table[DETECT_ID].Free  = DetectIdFree;
    sigmatch_table[DETECT_ID].flags = SIGMATCH_INFO_UINT16;
#ifdef UNITTESTS
    sigmatch_table[DETECT_ID].RegisterTests = DetectIdRegisterTests;
#endif
    sigmatch_table[DETECT_ID].SupportsPrefilter = PrefilterIdIsPrefilterable;
    sigmatch_table[DETECT_ID].SetupPrefilter = PrefilterSetupId;
}

/**
 * \brief This function is used to match the specified id on a packet
 *
 * \param t pointer to thread vars
 * \param det_ctx pointer to the pattern matcher thread
 * \param p pointer to the current packet
 * \param m pointer to the sigmatch that we will cast into DetectIdData
 *
 * \retval 0 no match
 * \retval 1 match
 */
static int DetectIdMatch (DetectEngineThreadCtx *det_ctx, Packet *p,
                          const Signature *s, const SigMatchCtx *ctx)
{
    DEBUG_VALIDATE_BUG_ON(PKT_IS_PSEUDOPKT(p));
    const DetectU16Data *id_d = (const DetectU16Data *)ctx;

    /**
     * To match a ipv4 packet with a "id" rule
     */
    if (!PacketIsIPv4(p)) {
        return 0;
    }

    const IPV4Hdr *ip4h = PacketGetIPv4(p);
    return DetectU16Match(IPV4_GET_RAW_IPID(ip4h), id_d);
}

/**
 * \brief this function is used to add the parsed "id" option
 * \brief into the current signature
 *
 * \param de_ctx pointer to the Detection Engine Context
 * \param s pointer to the Current Signature
 * \param idstr pointer to the user provided "id" option
 *
 * \retval 0 on Success
 * \retval -1 on Failure
 */
int DetectIdSetup (DetectEngineCtx *de_ctx, Signature *s, const char *idstr)
{
    DetectU16Data *id_d = SCDetectU16UnquoteParse(idstr);
    if (id_d == NULL)
        return -1;

    /* Okay so far so good, lets get this into a SigMatch
     * and put it in the Signature. */
    if (SCSigMatchAppendSMToList(de_ctx, s, DETECT_ID, (SigMatchCtx *)id_d, DETECT_SM_LIST_MATCH) ==
            NULL) {
        DetectIdFree(de_ctx, id_d);
        return -1;
    }
    s->flags |= SIG_FLAG_REQUIRE_PACKET;
    return 0;
}

/**
 * \brief this function will free memory associated with DetectIdData
 *
 * \param id_d pointer to DetectIdData
 */
void DetectIdFree(DetectEngineCtx *de_ctx, void *ptr)
{
    SCDetectU16Free(ptr);
}

/* prefilter code */

static void
PrefilterPacketIdMatch(DetectEngineThreadCtx *det_ctx, Packet *p, const void *pectx)
{
    DEBUG_VALIDATE_BUG_ON(PKT_IS_PSEUDOPKT(p));

    const PrefilterPacketHeaderCtx *ctx = pectx;

    if (!PacketIsIPv4(p)) {
        return;
    }

    if (!PrefilterPacketHeaderExtraMatch(ctx, p))
        return;

    const IPV4Hdr *ip4h = PacketGetIPv4(p);
    DetectU16Data du16;
    du16.mode = ctx->v1.u8[0];
    du16.arg1 = ctx->v1.u16[1];
    du16.arg2 = ctx->v1.u16[2];
    if (DetectU16Match(IPV4_GET_RAW_IPID(ip4h), &du16)) {
        SCLogDebug("packet matches IP id %u", ctx->v1.u16[0]);
        PrefilterAddSids(&det_ctx->pmq, ctx->sigs_array, ctx->sigs_cnt);
    }
}

static int PrefilterSetupId(DetectEngineCtx *de_ctx, SigGroupHead *sgh)
{
    return PrefilterSetupPacketHeader(de_ctx, sgh, DETECT_ID, SIG_MASK_REQUIRE_REAL_PKT,
            PrefilterPacketU16Set, PrefilterPacketU16Compare, PrefilterPacketIdMatch);
}

static bool PrefilterIdIsPrefilterable(const Signature *s)
{
    const SigMatch *sm;
    for (sm = s->init_data->smlists[DETECT_SM_LIST_MATCH] ; sm != NULL; sm = sm->next) {
        switch (sm->type) {
            case DETECT_ID:
                return true;
        }
    }
    return false;
}

#ifdef UNITTESTS /* UNITTESTS */

/**
 * \test DetectIdTestParse01 is a test to make sure that we parse the "id"
 *       option correctly when given valid id option
 */
static int DetectIdTestParse01 (void)
{
    DetectU16Data *id_d = SCDetectU16UnquoteParse(" 35402 ");

    FAIL_IF_NULL(id_d);
    FAIL_IF_NOT(id_d->arg1 == 35402);

    DetectIdFree(NULL, id_d);

    PASS;
}

/**
 * \test DetectIdTestParse02 is a test to make sure that we parse the "id"
 *       option correctly when given an invalid id option
 *       it should return id_d = NULL
 */
static int DetectIdTestParse02 (void)
{
    DetectU16Data *id_d = SCDetectU16UnquoteParse("65537");

    FAIL_IF_NOT_NULL(id_d);

    PASS;
}

/**
 * \test DetectIdTestParse03 is a test to make sure that we parse the "id"
 *       option correctly when given an invalid id option
 *       it should return id_d = NULL
 */
static int DetectIdTestParse03 (void)
{
    DetectU16Data *id_d = SCDetectU16UnquoteParse("12what?");

    FAIL_IF_NOT_NULL(id_d);

    PASS;
}

/**
 * \test DetectIdTestParse04 is a test to make sure that we parse the "id"
 *       option correctly when given valid id option but wrapped with "'s
 */
static int DetectIdTestParse04 (void)
{
    /* yep, look if we trim blank spaces correctly and ignore "'s */
    DetectU16Data *id_d = SCDetectU16UnquoteParse(" \"35402\" ");

    FAIL_IF_NULL(id_d);
    FAIL_IF_NOT(id_d->arg1 == 35402);

    DetectIdFree(NULL, id_d);

    PASS;
}

/**
 * \test DetectIdTestSig01
 * \brief Test to check "id" keyword with constructed packets
 */
static int DetectIdTestMatch01(void)
{
    uint8_t *buf = (uint8_t *)"Hi all!";
    uint16_t buflen = strlen((char *)buf);
    Packet *p[3];
    p[0] = UTHBuildPacket((uint8_t *)buf, buflen, IPPROTO_TCP);
    p[1] = UTHBuildPacket((uint8_t *)buf, buflen, IPPROTO_UDP);
    p[2] = UTHBuildPacket((uint8_t *)buf, buflen, IPPROTO_ICMP);

    FAIL_IF_NULL(p[0]);
    FAIL_IF_NULL(p[1]);
    FAIL_IF_NULL(p[2]);

    /* TCP IP id = 1234 */
    p[0]->l3.hdrs.ip4h->ip_id = htons(1234);

    /* UDP IP id = 5678 */
    p[1]->l3.hdrs.ip4h->ip_id = htons(5678);

    /* UDP IP id = 91011 */
    p[2]->l3.hdrs.ip4h->ip_id = htons(5101);

    const char *sigs[3];
    sigs[0]= "alert ip any any -> any any (msg:\"Testing id 1\"; id:1234; sid:1;)";
    sigs[1]= "alert ip any any -> any any (msg:\"Testing id 2\"; id:5678; sid:2;)";
    sigs[2]= "alert ip any any -> any any (msg:\"Testing id 3\"; id:5101; sid:3;)";

    uint32_t sid[3] = {1, 2, 3};

    uint32_t results[3][3] = {
                              /* packet 0 match sid 1 but should not match sid 2 */
                              {1, 0, 0},
                              /* packet 1 should not match */
                              {0, 1, 0},
                              /* packet 2 should not match */
                              {0, 0, 1} };

    FAIL_IF_NOT(UTHGenericTest(p, 3, sigs, sid, (uint32_t *)results, 3));

    UTHFreePackets(p, 3);

    PASS;
}

/**
 * \brief this function registers unit tests for DetectId
 */
void DetectIdRegisterTests(void)
{
    UtRegisterTest("DetectIdTestParse01", DetectIdTestParse01);
    UtRegisterTest("DetectIdTestParse02", DetectIdTestParse02);
    UtRegisterTest("DetectIdTestParse03", DetectIdTestParse03);
    UtRegisterTest("DetectIdTestParse04", DetectIdTestParse04);
    UtRegisterTest("DetectIdTestMatch01", DetectIdTestMatch01);

}
#endif /* UNITTESTS */
