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
 * \author Victor Julien <victor@inliniac.net>
 *
 * Implements the dsize keyword
 */

#include "suricata-common.h"
#include "decode.h"

#include "detect.h"
#include "detect-parse.h"
#include "detect-engine-prefilter-common.h"
#include "detect-engine-build.h"

#include "flow-var.h"

#include "detect-content.h"
#include "detect-dsize.h"

#include "util-unittest.h"
#include "util-debug.h"
#include "util-byte.h"

#include "pkt-var.h"
#include "host.h"
#include "util-profiling.h"

static int DetectDsizeMatch (DetectEngineThreadCtx *, Packet *,
        const Signature *, const SigMatchCtx *);
static int DetectDsizeSetup (DetectEngineCtx *, Signature *s, const char *str);
#ifdef UNITTESTS
static void DsizeRegisterTests(void);
#endif
static void DetectDsizeFree(DetectEngineCtx *, void *);

static int PrefilterSetupDsize(DetectEngineCtx *de_ctx, SigGroupHead *sgh);
static bool PrefilterDsizeIsPrefilterable(const Signature *s);

/**
 * \brief Registration function for dsize: keyword
 */
void DetectDsizeRegister (void)
{
    sigmatch_table[DETECT_DSIZE].name = "dsize";
    sigmatch_table[DETECT_DSIZE].desc = "match on the size of the packet payload";
    sigmatch_table[DETECT_DSIZE].url = "/rules/payload-keywords.html#dsize";
    sigmatch_table[DETECT_DSIZE].Match = DetectDsizeMatch;
    sigmatch_table[DETECT_DSIZE].Setup = DetectDsizeSetup;
    sigmatch_table[DETECT_DSIZE].Free  = DetectDsizeFree;
#ifdef UNITTESTS
    sigmatch_table[DETECT_DSIZE].RegisterTests = DsizeRegisterTests;
#endif
    sigmatch_table[DETECT_DSIZE].SupportsPrefilter = PrefilterDsizeIsPrefilterable;
    sigmatch_table[DETECT_DSIZE].SetupPrefilter = PrefilterSetupDsize;
}

/**
 * \internal
 * \brief This function is used to match flags on a packet with those passed via dsize:
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
static int DetectDsizeMatch (DetectEngineThreadCtx *det_ctx, Packet *p,
    const Signature *s, const SigMatchCtx *ctx)
{
    SCEnter();
    int ret = 0;

    if (PKT_IS_PSEUDOPKT(p)) {
        SCReturnInt(0);
    }

    const DetectU16Data *dd = (const DetectU16Data *)ctx;

    SCLogDebug("p->payload_len %"PRIu16"", p->payload_len);

    ret = DetectU16Match(p->payload_len, dd);

    SCReturnInt(ret);
}

/**
 * \internal
 * \brief this function is used to add the parsed dsize into the current signature
 *
 * \param de_ctx pointer to the Detection Engine Context
 * \param s pointer to the Current Signature
 * \param rawstr pointer to the user provided flags options
 *
 * \retval 0 on Success
 * \retval -1 on Failure
 */
static int DetectDsizeSetup (DetectEngineCtx *de_ctx, Signature *s, const char *rawstr)
{
    DetectU16Data *dd = NULL;
    SigMatch *sm = NULL;

    if (DetectGetLastSMFromLists(s, DETECT_DSIZE, -1)) {
        SCLogError(SC_ERR_INVALID_SIGNATURE, "Can't use 2 or more dsizes in "
                   "the same sig.  Invalidating signature.");
        goto error;
    }

    SCLogDebug("\'%s\'", rawstr);

    dd = DetectU16Parse(rawstr);
    if (dd == NULL) {
        SCLogError(SC_ERR_INVALID_ARGUMENT,"Parsing \'%s\' failed", rawstr);
        goto error;
    }

    /* Okay so far so good, lets get this into a SigMatch
     * and put it in the Signature. */
    sm = SigMatchAlloc();
    if (sm == NULL){
        SCLogError(SC_ERR_MEM_ALLOC, "Failed to allocate memory for SigMatch");
        rs_detect_u16_free(dd);
        goto error;
    }

    sm->type = DETECT_DSIZE;
    sm->ctx = (SigMatchCtx *)dd;

    SigMatchAppendSMToList(s, sm, DETECT_SM_LIST_MATCH);

    SCLogDebug("dd->arg1 %" PRIu16 ", dd->arg2 %" PRIu16 ", dd->mode %" PRIu8 "", dd->arg1,
            dd->arg2, dd->mode);
    /* tell the sig it has a dsize to speed up engine init */
    s->flags |= SIG_FLAG_REQUIRE_PACKET;
    s->flags |= SIG_FLAG_DSIZE;

    if (s->init_data->dsize_sm == NULL) {
        s->init_data->dsize_sm = sm;
    }

    return 0;

error:
    return -1;
}

/**
 * \internal
 * \brief this function will free memory associated with DetectU16Data
 *
 * \param de pointer to DetectU16Data
 */
void DetectDsizeFree(DetectEngineCtx *de_ctx, void *de_ptr)
{
    rs_detect_u16_free(de_ptr);
}

/* prefilter code */

static void
PrefilterPacketDsizeMatch(DetectEngineThreadCtx *det_ctx, Packet *p, const void *pectx)
{
    if (PKT_IS_PSEUDOPKT(p)) {
        SCReturn;
    }

    const PrefilterPacketHeaderCtx *ctx = pectx;
    if (!PrefilterPacketHeaderExtraMatch(ctx, p))
        return;

    const uint16_t dsize = p->payload_len;
    DetectU16Data du16;
    du16.mode = ctx->v1.u8[0];
    du16.arg1 = ctx->v1.u16[1];
    du16.arg2 = ctx->v1.u16[2];

    if (DetectU16Match(dsize, &du16)) {
        SCLogDebug("packet matches dsize %u", dsize);
        PrefilterAddSids(&det_ctx->pmq, ctx->sigs_array, ctx->sigs_cnt);
    }
}

static int PrefilterSetupDsize(DetectEngineCtx *de_ctx, SigGroupHead *sgh)
{
    return PrefilterSetupPacketHeader(de_ctx, sgh, DETECT_DSIZE, PrefilterPacketU16Set,
            PrefilterPacketU16Compare, PrefilterPacketDsizeMatch);
}

static bool PrefilterDsizeIsPrefilterable(const Signature *s)
{
    const SigMatch *sm;
    for (sm = s->init_data->smlists[DETECT_SM_LIST_MATCH] ; sm != NULL; sm = sm->next) {
        switch (sm->type) {
            case DETECT_DSIZE:
                return true;
        }
    }
    return false;
}

/** \brief get max dsize "depth"
 *  \param s signature to get dsize value from
 *  \retval depth or negative value
 */
int SigParseGetMaxDsize(const Signature *s)
{
    if (s->flags & SIG_FLAG_DSIZE && s->init_data->dsize_sm != NULL) {
        const DetectU16Data *dd = (const DetectU16Data *)s->init_data->dsize_sm->ctx;

        switch (dd->mode) {
            case DETECT_UINT_LT:
            case DETECT_UINT_EQ:
            case DETECT_UINT_NE:
                return dd->arg1;
            case DETECT_UINT_RA:
                return dd->arg2;
            case DETECT_UINT_GT:
            default:
                SCReturnInt(-2);
        }
    }
    SCReturnInt(-1);
}

/** \brief set prefilter dsize pair
 *  \param s signature to get dsize value from
 */
void SigParseSetDsizePair(Signature *s)
{
    if (s->flags & SIG_FLAG_DSIZE && s->init_data->dsize_sm != NULL) {
        DetectU16Data *dd = (DetectU16Data *)s->init_data->dsize_sm->ctx;

        uint16_t low = 0;
        uint16_t high = 65535;

        switch (dd->mode) {
            case DETECT_UINT_LT:
                low = 0;
                high = dd->arg1;
                break;
            case DETECT_UINT_LTE:
                low = 0;
                high = dd->arg1 + 1;
                break;
            case DETECT_UINT_EQ:
            case DETECT_UINT_NE:
                low = dd->arg1;
                high = dd->arg1;
                break;
            case DETECT_UINT_RA:
                low = dd->arg1;
                high = dd->arg2;
                break;
            case DETECT_UINT_GT:
                low = dd->arg1;
                high = 65535;
                break;
            case DETECT_UINT_GTE:
                low = dd->arg1 - 1;
                high = 65535;
                break;
        }
        s->dsize_mode = dd->mode;
        s->dsize_low = low;
        s->dsize_high = high;

        SCLogDebug("low %u, high %u, mode %u", low, high, dd->mode);
    }
}

/**
 *  \brief Apply dsize as depth to content matches in the rule
 *  \param s signature to get dsize value from
 */
void SigParseApplyDsizeToContent(Signature *s)
{
    SCEnter();

    if (s->flags & SIG_FLAG_DSIZE) {
        SigParseSetDsizePair(s);

        int dsize = SigParseGetMaxDsize(s);
        if (dsize < 0) {
            /* nothing to do */
            return;
        }

        SigMatch *sm = s->init_data->smlists[DETECT_SM_LIST_PMATCH];
        for ( ; sm != NULL;  sm = sm->next) {
            if (sm->type != DETECT_CONTENT) {
                continue;
            }

            DetectContentData *cd = (DetectContentData *)sm->ctx;
            if (cd == NULL) {
                continue;
            }

            if (cd->depth == 0 || cd->depth >= dsize) {
                cd->flags |= DETECT_CONTENT_DEPTH;
                cd->depth = (uint16_t)dsize;
                SCLogDebug("updated %u, content %u to have depth %u "
                        "because of dsize.", s->id, cd->id, cd->depth);
            }
        }
    }
}

/*
 * ONLY TESTS BELOW THIS COMMENT
 */

#ifdef UNITTESTS
#include "detect-engine.h"

/**
 * \test this is a test for a valid dsize value 1
 *
 */
static int DsizeTestParse01(void)
{
    DetectU16Data *dd = DetectU16Parse("1");
    FAIL_IF_NULL(dd);
    FAIL_IF_NOT(dd->arg1 == 1);
    FAIL_IF_NOT(dd->arg2 == 0);

    DetectDsizeFree(NULL, dd);
    PASS;
}

/**
 * \test this is a test for a valid dsize value >10
 *
 */
static int DsizeTestParse02(void)
{
    DetectU16Data *dd = DetectU16Parse(">10");
    FAIL_IF_NULL(dd);
    FAIL_IF_NOT(dd->arg1 == 10);
    FAIL_IF_NOT(dd->mode == DETECT_UINT_GT);
    DetectDsizeFree(NULL, dd);
    PASS;
}

/**
 * \test this is a test for a valid dsize value <100
 *
 */
static int DsizeTestParse03(void)
{
    DetectU16Data *dd = DetectU16Parse("<100");
    FAIL_IF_NULL(dd);
    FAIL_IF_NOT(dd->arg1 == 100);
    FAIL_IF_NOT(dd->mode == DETECT_UINT_LT);

    DetectDsizeFree(NULL, dd);
    PASS;
}

/**
 * \test this is a test for a valid dsize value 1<>3
 *
 */
static int DsizeTestParse04(void)
{
    DetectU16Data *dd = DetectU16Parse("1<>3");
    FAIL_IF_NULL(dd);
    FAIL_IF_NOT(dd->arg1 == 1);
    FAIL_IF_NOT(dd->arg2 == 3);
    FAIL_IF_NOT(dd->mode == DETECT_UINT_RA);

    DetectDsizeFree(NULL, dd);
    PASS;
}

/**
 * \test this is a test for a valid dsize value 1 <> 3
 *
 */
static int DsizeTestParse05(void)
{
    DetectU16Data *dd = DetectU16Parse(" 1 <> 3 ");
    FAIL_IF_NULL(dd);
    FAIL_IF_NOT(dd->arg1 == 1);
    FAIL_IF_NOT(dd->arg2 == 3);
    FAIL_IF_NOT(dd->mode == DETECT_UINT_RA);

    DetectDsizeFree(NULL, dd);
    PASS;
}

/**
 * \test this is test for a valid dsize value > 2
 *
 */
static int DsizeTestParse06(void)
{
    DetectU16Data *dd = DetectU16Parse("> 2 ");
    FAIL_IF_NULL(dd);
    FAIL_IF_NOT(dd->arg1 == 2);
    FAIL_IF_NOT(dd->mode == DETECT_UINT_GT);

    DetectDsizeFree(NULL, dd);
    PASS;
}

/**
 * \test test for a valid dsize value <   12
 *
 */
static int DsizeTestParse07(void)
{
    DetectU16Data *dd = DetectU16Parse("<   12 ");
    FAIL_IF_NULL(dd);
    FAIL_IF_NOT(dd->arg1 == 12);
    FAIL_IF_NOT(dd->mode == DETECT_UINT_LT);

    DetectDsizeFree(NULL, dd);
    PASS;
}

/**
 * \test test for a valid dsize value    12
 *
 */
static int DsizeTestParse08(void)
{
    DetectU16Data *dd = DetectU16Parse("   12 ");
    FAIL_IF_NULL(dd);
    FAIL_IF_NOT(dd->arg1 == 12);
    FAIL_IF_NOT(dd->mode == DETECT_UINT_EQ);

    DetectDsizeFree(NULL, dd);
    PASS;
}

/**
 * \test this is a test for a valid dsize value !1
 *
 */
static int DsizeTestParse09(void)
{
    DetectU16Data *dd = DetectU16Parse("!1");
    FAIL_IF_NULL(dd);
    DetectDsizeFree(NULL, dd);
    PASS;
}

/**
 * \test this is a test for a valid dsize value ! 1
 *
 */
static int DsizeTestParse10(void)
{
    DetectU16Data *dd = DetectU16Parse("! 1");
    FAIL_IF_NULL(dd);
    DetectDsizeFree(NULL, dd);
    PASS;
}

/**
 * \test this is a test for invalid dsize values
 * A, >10<>10, <>10, 1<>, "", " ", 2<>1, 1!
 *
 */
static int DsizeTestParse11(void)
{
    const char *strings[] = { "A", ">10<>10", "<>10", "1<>", "", " ", "2<>1", "1!", NULL };
    for (int i = 0; strings[i]; i++) {
        DetectU16Data *dd = DetectU16Parse(strings[i]);
        FAIL_IF_NOT_NULL(dd);
    }

    PASS;
}

/**
 * \test this is a test for positive ! dsize matching
 *
 */
static int DsizeTestMatch01(void)
{
    uint16_t psize = 1;
    uint16_t dsizelow = 2;
    uint16_t dsizehigh = 0;
    DetectU16Data du16;
    du16.mode = DETECT_UINT_NE;
    du16.arg1 = dsizelow;
    du16.arg2 = dsizehigh;
    FAIL_IF_NOT(DetectU16Match(psize, &du16));

    PASS;
}

/**
 * \test this is a test for negative ! dsize matching
 *
 */
static int DsizeTestMatch02(void)
{
    uint16_t psize = 1;
    uint16_t dsizelow = 1;
    uint16_t dsizehigh = 0;
    DetectU16Data du16;
    du16.mode = DETECT_UINT_NE;
    du16.arg1 = dsizelow;
    du16.arg2 = dsizehigh;
    FAIL_IF(DetectU16Match(psize, &du16));

    PASS;
}

/**
 * \test DetectDsizeIcmpv6Test01 is a test for checking the working of
 *       dsize keyword by creating 2 rules and matching a crafted packet
 *       against them. Only the first one shall trigger.
 */
static int DetectDsizeIcmpv6Test01(void)
{
    static uint8_t raw_icmpv6[] = {
        0x60, 0x00, 0x00, 0x00, 0x00, 0x30, 0x3a, 0xff,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        0x01, 0x00, 0x7b, 0x85, 0x00, 0x00, 0x00, 0x00,
        0x60, 0x4b, 0xe8, 0xbd, 0x00, 0x00, 0x3b, 0xff,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 };

    Packet *p = PacketGetFromAlloc();
    FAIL_IF_NULL(p);

    IPV6Hdr ip6h;
    ThreadVars tv;
    DecodeThreadVars dtv;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx = NULL;

    memset(&tv, 0, sizeof(ThreadVars));
    memset(&dtv, 0, sizeof(DecodeThreadVars));
    memset(&ip6h, 0, sizeof(IPV6Hdr));
    memset(&th_v, 0, sizeof(ThreadVars));

    FlowInitConfig(FLOW_QUIET);
    p->src.family = AF_INET6;
    p->dst.family = AF_INET6;
    p->ip6h = &ip6h;

    DecodeIPV6(&tv, &dtv, p, raw_icmpv6, sizeof(raw_icmpv6));

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);

    de_ctx->flags |= DE_QUIET;

    Signature *s = DetectEngineAppendSig(de_ctx,
            "alert icmp any any -> any any "
            "(msg:\"ICMP Large ICMP Packet\"; dsize:>8; sid:1; rev:4;)");
    FAIL_IF_NULL(s);

    s = DetectEngineAppendSig(de_ctx,
            "alert icmp any any -> any any "
            "(msg:\"ICMP Large ICMP Packet\"; dsize:>800; sid:2; rev:4;)");
    FAIL_IF_NULL(s);

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    FAIL_IF(PacketAlertCheck(p, 1) == 0);
    FAIL_IF(PacketAlertCheck(p, 2));

    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);

    PACKET_RECYCLE(p);
    FlowShutdown();
    SCFree(p);

    PASS;
}

/**
 * \brief this function registers unit tests for dsize
 */
static void DsizeRegisterTests(void)
{
    UtRegisterTest("DsizeTestParse01", DsizeTestParse01);
    UtRegisterTest("DsizeTestParse02", DsizeTestParse02);
    UtRegisterTest("DsizeTestParse03", DsizeTestParse03);
    UtRegisterTest("DsizeTestParse04", DsizeTestParse04);
    UtRegisterTest("DsizeTestParse05", DsizeTestParse05);
    UtRegisterTest("DsizeTestParse06", DsizeTestParse06);
    UtRegisterTest("DsizeTestParse07", DsizeTestParse07);
    UtRegisterTest("DsizeTestParse08", DsizeTestParse08);
    UtRegisterTest("DsizeTestParse09", DsizeTestParse09);
    UtRegisterTest("DsizeTestParse10", DsizeTestParse10);
    UtRegisterTest("DsizeTestParse11", DsizeTestParse11);
    UtRegisterTest("DsizeTestMatch01", DsizeTestMatch01);
    UtRegisterTest("DsizeTestMatch02", DsizeTestMatch02);

    UtRegisterTest("DetectDsizeIcmpv6Test01", DetectDsizeIcmpv6Test01);
}
#endif /* UNITTESTS */
