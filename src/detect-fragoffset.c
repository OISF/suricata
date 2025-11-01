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
 * Implements fragoffset keyword
 */

#include "suricata-common.h"
#include "decode.h"
#include "decode-ipv4.h"
#include "decode-ipv6.h"

#include "detect.h"
#include "detect-parse.h"
#include "detect-engine-prefilter-common.h"
#include "detect-engine-build.h"
#include "detect-engine-uint.h"

#include "detect-fragoffset.h"

#include "util-byte.h"
#include "util-unittest.h"
#include "util-debug.h"

static int DetectFragOffsetMatch(DetectEngineThreadCtx *,
        Packet *, const Signature *, const SigMatchCtx *);
static int DetectFragOffsetSetup(DetectEngineCtx *, Signature *, const char *);
#ifdef UNITTESTS
void DetectFragOffsetRegisterTests(void);
#endif
void DetectFragOffsetFree(DetectEngineCtx *, void *);

static int PrefilterSetupFragOffset(DetectEngineCtx *de_ctx, SigGroupHead *sgh);
static bool PrefilterFragOffsetIsPrefilterable(const Signature *s);

/**
 * \brief Registration function for fragoffset
 */
void DetectFragOffsetRegister (void)
{
    sigmatch_table[DETECT_FRAGOFFSET].name = "fragoffset";
    sigmatch_table[DETECT_FRAGOFFSET].desc = "match on specific decimal values of the IP fragment offset field";
    sigmatch_table[DETECT_FRAGOFFSET].url = "/rules/header-keywords.html#fragoffset";
    sigmatch_table[DETECT_FRAGOFFSET].Match = DetectFragOffsetMatch;
    sigmatch_table[DETECT_FRAGOFFSET].Setup = DetectFragOffsetSetup;
    sigmatch_table[DETECT_FRAGOFFSET].Free = DetectFragOffsetFree;
    sigmatch_table[DETECT_FRAGOFFSET].flags = SIGMATCH_INFO_UINT16;
#ifdef UNITTESTS
    sigmatch_table[DETECT_FRAGOFFSET].RegisterTests = DetectFragOffsetRegisterTests;
#endif
    sigmatch_table[DETECT_FRAGOFFSET].SupportsPrefilter = PrefilterFragOffsetIsPrefilterable;
    sigmatch_table[DETECT_FRAGOFFSET].SetupPrefilter = PrefilterSetupFragOffset;
}

/**
 * \brief This function is used to match fragoffset rule option set on a packet
 *
 * \param t pointer to thread vars
 * \param det_ctx pointer to the pattern matcher thread
 * \param p pointer to the current packet
 * \param m pointer to the sigmatch that we will cast into DetectFragOffsetData
 *
 * \retval 0 no match or frag is not set
 * \retval 1 match
 *
 */
static int DetectFragOffsetMatch (DetectEngineThreadCtx *det_ctx,
        Packet *p, const Signature *s, const SigMatchCtx *ctx)
{
    uint16_t frag = 0;
    const DetectU16Data *fragoff = (const DetectU16Data *)ctx;

    DEBUG_VALIDATE_BUG_ON(PKT_IS_PSEUDOPKT(p));

    if (PacketIsIPv4(p)) {
        const IPV4Hdr *ip4h = PacketGetIPv4(p);
        frag = IPV4_GET_RAW_FRAGOFFSET(ip4h);
    } else if (PacketIsIPv6(p)) {
        if (IPV6_EXTHDR_ISSET_FH(p)) {
            frag = IPV6_EXTHDR_GET_FH_OFFSET(p);
        } else {
            return 0;
        }
    } else {
        SCLogDebug("No IPv4 or IPv6 packet");
        return 0;
    }

    return DetectU16Match(frag, fragoff);
}

/**
 * \brief this function is used to add the parsed fragoffset data into the current signature
 *
 * \param de_ctx pointer to the Detection Engine Context
 * \param s pointer to the Current Signature
 * \param fragoffsetstr pointer to the user provided fragoffset option
 *
 * \retval 0 on Success
 * \retval -1 on Failure
 */
static int DetectFragOffsetSetup (DetectEngineCtx *de_ctx, Signature *s, const char *fragoffsetstr)
{
    DetectU16Data *fragoff = SCDetectU16Parse(fragoffsetstr);
    if (fragoff == NULL)
        return -1;

    if (SCSigMatchAppendSMToList(de_ctx, s, DETECT_FRAGOFFSET, (SigMatchCtx *)fragoff,
                DETECT_SM_LIST_MATCH) == NULL) {
        goto error;
    }
    s->flags |= SIG_FLAG_REQUIRE_PACKET;

    return 0;

error:
    DetectFragOffsetFree(de_ctx, fragoff);
    return -1;

}

/**
 * \brief this function will free memory associated with DetectFragOffsetData
 *
 * \param ptr pointer to DetectFragOffsetData
 */
void DetectFragOffsetFree (DetectEngineCtx *de_ctx, void *ptr)
{
    SCDetectU16Free(ptr);
}

static void
PrefilterPacketFragOffsetMatch(DetectEngineThreadCtx *det_ctx, Packet *p, const void *pectx)
{
    DEBUG_VALIDATE_BUG_ON(PKT_IS_PSEUDOPKT(p));

    uint16_t frag;

    if (PacketIsIPv4(p)) {
        const IPV4Hdr *ip4h = PacketGetIPv4(p);
        frag = IPV4_GET_RAW_FRAGOFFSET(ip4h);
    } else if (PacketIsIPv6(p)) {
        if (IPV6_EXTHDR_ISSET_FH(p)) {
            frag = IPV6_EXTHDR_GET_FH_OFFSET(p);
        } else {
            return;
        }
    } else {
        SCLogDebug("No IPv4 or IPv6 packet");
        return;
    }

    const PrefilterPacketHeaderCtx *ctx = pectx;
    DetectU16Data du16;
    du16.mode = ctx->v1.u8[0];
    du16.arg1 = ctx->v1.u16[1];
    du16.arg2 = ctx->v1.u16[2];

    if (DetectU16Match(frag, &du16)) {
        PrefilterAddSids(&det_ctx->pmq, ctx->sigs_array, ctx->sigs_cnt);
    }
}

static int PrefilterSetupFragOffset(DetectEngineCtx *de_ctx, SigGroupHead *sgh)
{
    return PrefilterSetupPacketHeader(de_ctx, sgh, DETECT_FRAGOFFSET, SIG_MASK_REQUIRE_REAL_PKT,
            PrefilterPacketU16Set, PrefilterPacketU16Compare, PrefilterPacketFragOffsetMatch);
}

static bool PrefilterFragOffsetIsPrefilterable(const Signature *s)
{
    const SigMatch *sm;
    for (sm = s->init_data->smlists[DETECT_SM_LIST_MATCH] ; sm != NULL; sm = sm->next) {
        switch (sm->type) {
            case DETECT_FRAGOFFSET:
                return true;
        }
    }
    return false;
}

#ifdef UNITTESTS
#include "util-unittest-helper.h"
#include "detect-engine.h"
#include "detect-engine-alert.h"

/**
 * \test DetectFragOffsetParseTest01 is a test for setting a valid fragoffset value
 */
static int DetectFragOffsetParseTest01 (void)
{
    DetectU16Data *fragoff = SCDetectU16Parse("300");

    FAIL_IF_NULL(fragoff);
    FAIL_IF_NOT(fragoff->arg1 == 300);

    DetectFragOffsetFree(NULL, fragoff);

    PASS;
}

/**
 * \test DetectFragOffsetParseTest02 is a test for setting a valid fragoffset value
 *       with spaces all around
 */
static int DetectFragOffsetParseTest02 (void)
{
    DetectU16Data *fragoff = SCDetectU16Parse(">300");

    FAIL_IF_NULL(fragoff);
    FAIL_IF_NOT(fragoff->arg1 == 300);
    FAIL_IF_NOT(fragoff->mode == DetectUintModeGt);

    DetectFragOffsetFree(NULL, fragoff);

    PASS;
}

/**
 * \test DetectFragOffsetParseTest03 is a test for setting an invalid fragoffset value
 */
static int DetectFragOffsetParseTest03 (void)
{
    DetectU16Data *fragoff = SCDetectU16Parse("badc");

    FAIL_IF_NOT_NULL(fragoff);

    PASS;
}

/**
 * \test DetectFragOffsetMatchTest01 is a test for checking the working of
 *       fragoffset keyword by creating 2 rules and matching a crafted packet
 *       against them. Only the first one shall trigger.
 */
static int DetectFragOffsetMatchTest01 (void)
{
    Packet *p = PacketGetFromAlloc();

    FAIL_IF_NULL(p);
    Signature *s = NULL;
    DecodeThreadVars dtv;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx = NULL;
    IPV4Hdr ip4h;

    memset(&ip4h, 0, sizeof(IPV4Hdr));
    memset(&dtv, 0, sizeof(DecodeThreadVars));
    memset(&th_v, 0, sizeof(ThreadVars));

    FlowInitConfig(FLOW_QUIET);

    p->src.family = AF_INET;
    p->dst.family = AF_INET;
    p->src.addr_data32[0] = 0x01020304;
    p->dst.addr_data32[0] = 0x04030201;

    ip4h.s_ip_src.s_addr = p->src.addr_data32[0];
    ip4h.s_ip_dst.s_addr = p->dst.addr_data32[0];
    ip4h.ip_off = 0x2222;
    UTHSetIPV4Hdr(p, &ip4h);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);

    de_ctx->flags |= DE_QUIET;

    s = DetectEngineAppendSig(de_ctx, "alert ip any any -> any any (fragoffset:546; sid:1;)");
    FAIL_IF_NULL(s);

    s = DetectEngineAppendSig(de_ctx, "alert ip any any -> any any (fragoffset:5000; sid:2;)");
    FAIL_IF_NULL(s);

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);

    FAIL_IF(PacketAlertCheck(p, 1) == 0);
    FAIL_IF(PacketAlertCheck(p, 2));

    PacketFree(p);
    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);
    FlowShutdown();
    StatsThreadCleanup(&th_v);
    PASS;
}

void DetectFragOffsetRegisterTests (void)
{
    UtRegisterTest("DetectFragOffsetParseTest01", DetectFragOffsetParseTest01);
    UtRegisterTest("DetectFragOffsetParseTest02", DetectFragOffsetParseTest02);
    UtRegisterTest("DetectFragOffsetParseTest03", DetectFragOffsetParseTest03);
    UtRegisterTest("DetectFragOffsetMatchTest01", DetectFragOffsetMatchTest01);
}
#endif /* UNITTESTS */
