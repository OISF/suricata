/* Copyright (C) 2007-2020 Open Information Security Foundation
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
 * Implements the flags keyword
 */

#include "suricata-common.h"
#include "suricata.h"
#include "decode.h"
#include "rust.h"

#include "detect.h"
#include "detect-parse.h"
#include "detect-engine-prefilter.h"
#include "detect-engine-prefilter-common.h"
#include "detect-engine-uint.h"

#include "flow-var.h"
#include "decode-events.h"

#include "detect-tcp-flags.h"
#include "util-unittest.h"
#include "util-unittest-helper.h"

#include "util-debug.h"

static int DetectFlagsMatch (DetectEngineThreadCtx *, Packet *,
        const Signature *, const SigMatchCtx *);
static int DetectFlagsSetup (DetectEngineCtx *, Signature *, const char *);
static void DetectFlagsFree(DetectEngineCtx *, void *);

static bool PrefilterTcpFlagsIsPrefilterable(const Signature *s);
static int PrefilterSetupTcpFlags(DetectEngineCtx *de_ctx, SigGroupHead *sgh);
#ifdef UNITTESTS
static void FlagsRegisterTests(void);
#endif

/**
 * \brief Registration function for flags: keyword
 */

void DetectFlagsRegister (void)
{
    sigmatch_table[DETECT_FLAGS].name = "tcp.flags";
    sigmatch_table[DETECT_FLAGS].alias = "flags";
    sigmatch_table[DETECT_FLAGS].desc = "detect which flags are set in the TCP header";
    sigmatch_table[DETECT_FLAGS].url = "/rules/header-keywords.html#tcp-flags";
    sigmatch_table[DETECT_FLAGS].Match = DetectFlagsMatch;
    sigmatch_table[DETECT_FLAGS].Setup = DetectFlagsSetup;
    sigmatch_table[DETECT_FLAGS].Free  = DetectFlagsFree;
    sigmatch_table[DETECT_FLAGS].flags = SIGMATCH_SUPPORT_FIREWALL;
#ifdef UNITTESTS
    sigmatch_table[DETECT_FLAGS].RegisterTests = FlagsRegisterTests;
#endif
    sigmatch_table[DETECT_FLAGS].SupportsPrefilter = PrefilterTcpFlagsIsPrefilterable;
    sigmatch_table[DETECT_FLAGS].SetupPrefilter = PrefilterSetupTcpFlags;
    sigmatch_table[DETECT_FLAGS].flags = SIGMATCH_INFO_UINT8 | SIGMATCH_INFO_BITFLAGS_UINT;
    ;
}

/**
 * \internal
 * \brief This function is used to match flags on a packet with those passed via flags:
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
static int DetectFlagsMatch (DetectEngineThreadCtx *det_ctx, Packet *p,
        const Signature *s, const SigMatchCtx *ctx)
{
    SCEnter();

    DEBUG_VALIDATE_BUG_ON(PKT_IS_PSEUDOPKT(p));
    if (!(PacketIsTCP(p))) {
        SCReturnInt(0);
    }

    const TCPHdr *tcph = PacketGetTCP(p);
    const uint8_t flags = tcph->th_flags;
    DetectU8Data *du8 = (DetectU8Data *)ctx;
    return DetectU8Match(flags, du8);
}

/**
 * \internal
 * \brief this function is used to add the parsed flags into the current signature
 *
 * \param de_ctx pointer to the Detection Engine Context
 * \param s pointer to the Current Signature
 * \param m pointer to the Current SigMatch
 * \param rawstr pointer to the user provided flags options
 *
 * \retval 0 on Success
 * \retval -1 on Failure
 */
static int DetectFlagsSetup (DetectEngineCtx *de_ctx, Signature *s, const char *rawstr)
{
    DetectU8Data *du8 = SCDetectTcpFlagsParse(rawstr);
    if (du8 == NULL)
        goto error;

    if (SCSigMatchAppendSMToList(
                de_ctx, s, DETECT_FLAGS, (SigMatchCtx *)du8, DETECT_SM_LIST_MATCH) == NULL) {
        goto error;
    }
    s->flags |= SIG_FLAG_REQUIRE_PACKET;

    return 0;

error:
    if (du8)
        DetectFlagsFree(NULL, du8);
    return -1;
}

/**
 * \internal
 * \brief this function will free memory associated with DetectU8Data
 *
 * \param de pointer to DetectU8Data
 */
static void DetectFlagsFree(DetectEngineCtx *de_ctx, void *de_ptr)
{
    SCDetectU8Free(de_ptr);
}

int DetectFlagsSignatureNeedsSynPackets(const Signature *s)
{
    const SigMatch *sm;
    for (sm = s->init_data->smlists[DETECT_SM_LIST_MATCH] ; sm != NULL; sm = sm->next) {
        switch (sm->type) {
            case DETECT_FLAGS:
            {
                const DetectU8Data *fl = (const DetectU8Data *)sm->ctx;

                if (DetectU8Match(TH_SYN, fl)) {
                    return 1;
                }
                break;
            }
        }
    }
    return 0;
}

int DetectFlagsSignatureNeedsSynOnlyPackets(const Signature *s)
{
    const SigMatch *sm;
    for (sm = s->init_data->smlists[DETECT_SM_LIST_MATCH] ; sm != NULL; sm = sm->next) {
        switch (sm->type) {
            case DETECT_FLAGS:
            {
                const DetectU8Data *fl = (const DetectU8Data *)sm->ctx;

                if (!(fl->mode == DetectUintModeNegBitmask) && (fl->arg1 == TH_SYN)) {
                    return 1;
                }
                break;
            }
        }
    }
    return 0;
}

static void
PrefilterPacketFlagsMatch(DetectEngineThreadCtx *det_ctx, Packet *p, const void *pectx)
{
    DEBUG_VALIDATE_BUG_ON(PKT_IS_PSEUDOPKT(p));
    if (!(PacketIsTCP(p))) {
        SCReturn;
    }

    const PrefilterPacketHeaderCtx *ctx = pectx;
    if (!PrefilterPacketHeaderExtraMatch(ctx, p))
        return;

    const TCPHdr *tcph = PacketGetTCP(p);
    const uint8_t flags = tcph->th_flags;
    DetectU8Data du8;
    du8.mode = ctx->v1.u8[0];
    du8.arg1 = ctx->v1.u8[1];
    du8.arg2 = ctx->v1.u8[2];
    if (DetectU8Match(flags, &du8)) {
        SCLogDebug("packet matches TCP flags %02x", ctx->v1.u8[1]);
        PrefilterAddSids(&det_ctx->pmq, ctx->sigs_array, ctx->sigs_cnt);
    }
}

static void
PrefilterPacketFlagsSet(PrefilterPacketHeaderValue *v, void *smctx)
{
    const DetectU8Data *a = smctx;
    v->u8[0] = a->mode;
    v->u8[1] = a->arg1;
    v->u8[2] = a->arg2;
    SCLogDebug("v->u8[0] = %02x", v->u8[0]);
}

static bool
PrefilterPacketFlagsCompare(PrefilterPacketHeaderValue v, void *smctx)
{
    const DetectU8Data *a = smctx;
    if (v.u8[0] == a->mode && v.u8[1] == a->arg1 && v.u8[2] == a->arg2)
        return true;
    return false;
}

static int PrefilterSetupTcpFlags(DetectEngineCtx *de_ctx, SigGroupHead *sgh)
{
    return PrefilterSetupPacketHeader(de_ctx, sgh, DETECT_FLAGS, SIG_MASK_REQUIRE_REAL_PKT,
            PrefilterPacketFlagsSet, PrefilterPacketFlagsCompare, PrefilterPacketFlagsMatch);
}

static bool PrefilterTcpFlagsIsPrefilterable(const Signature *s)
{
    const SigMatch *sm;
    for (sm = s->init_data->smlists[DETECT_SM_LIST_MATCH] ; sm != NULL; sm = sm->next) {
        switch (sm->type) {
            case DETECT_FLAGS:
                return true;
        }
    }
    return false;
}

/*
 * ONLY TESTS BELOW THIS COMMENT
 */

#ifdef UNITTESTS
/**
 * \test FlagsTestParse03 test if ACK and PUSH are set. Must return success
 *
 *  \retval 1 on success
 *  \retval 0 on failure
 */
static int FlagsTestParse03 (void)
{
    ThreadVars tv;
    IPV4Hdr ipv4h;
    TCPHdr tcph;

    memset(&tv, 0, sizeof(ThreadVars));
    memset(&ipv4h, 0, sizeof(IPV4Hdr));
    memset(&tcph, 0, sizeof(TCPHdr));

    Packet *p = PacketGetFromAlloc();
    FAIL_IF_NULL(p);
    UTHSetIPV4Hdr(p, &ipv4h);
    tcph.th_flags = TH_ACK | TH_PUSH | TH_SYN | TH_RST;
    UTHSetTCPHdr(p, &tcph);

    DetectU8Data *de = SCDetectTcpFlagsParse("AP+");
    FAIL_IF_NULL(de);
    FAIL_IF(de->mode != DetectUintModeBitmask);
    FAIL_IF(de->arg1 != (TH_ACK | TH_PUSH));
    FAIL_IF(de->arg2 != (TH_ACK | TH_PUSH));

    SigMatch *sm = SigMatchAlloc();
    FAIL_IF_NULL(sm);
    sm->type = DETECT_FLAGS;
    sm->ctx = (SigMatchCtx *)de;

    int ret = DetectFlagsMatch(NULL, p, NULL, sm->ctx);
    FAIL_IF_NOT(ret == 1);

    SigMatchFree(NULL, sm);
    PacketFree(p);
    PASS;
}

/**
 * \test FlagsTestParse04 check if ACK bit is set. Must fails.
 *
 *  \retval 1 on success
 *  \retval 0 on failure
 */
static int FlagsTestParse04 (void)
{
    ThreadVars tv;
    IPV4Hdr ipv4h;
    TCPHdr tcph;

    memset(&tv, 0, sizeof(ThreadVars));
    memset(&ipv4h, 0, sizeof(IPV4Hdr));
    memset(&tcph, 0, sizeof(TCPHdr));

    Packet *p = PacketGetFromAlloc();
    FAIL_IF_NULL(p);
    UTHSetIPV4Hdr(p, &ipv4h);
    tcph.th_flags = TH_SYN;
    UTHSetTCPHdr(p, &tcph);

    DetectU8Data *de = SCDetectTcpFlagsParse("A");
    FAIL_IF_NULL(de);
    FAIL_IF(de->mode != DetectUintModeBitmask);
    FAIL_IF(de->arg1 != 0xFF);
    FAIL_IF(de->arg2 != TH_ACK);

    SigMatch *sm = SigMatchAlloc();
    FAIL_IF_NULL(sm);
    sm->type = DETECT_FLAGS;
    sm->ctx = (SigMatchCtx *)de;

    int ret = DetectFlagsMatch(NULL, p, NULL, sm->ctx);
    FAIL_IF_NOT(ret == 0);

    SigMatchFree(NULL, sm);
    PacketFree(p);
    PASS;
}

/**
 * \test FlagsTestParse05 test if ACK+PUSH and no other flags are set. Ignore SYN and RST bits.
 *  \retval 1 on success
 *  \retval 0 on failure
 */
static int FlagsTestParse05 (void)
{
    ThreadVars tv;
    IPV4Hdr ipv4h;
    TCPHdr tcph;

    memset(&tv, 0, sizeof(ThreadVars));
    memset(&ipv4h, 0, sizeof(IPV4Hdr));
    memset(&tcph, 0, sizeof(TCPHdr));

    Packet *p = PacketGetFromAlloc();
    FAIL_IF_NULL(p);
    UTHSetIPV4Hdr(p, &ipv4h);
    tcph.th_flags = TH_ACK | TH_PUSH | TH_SYN | TH_RST;
    UTHSetTCPHdr(p, &tcph);

    DetectU8Data *de = SCDetectTcpFlagsParse("AP,SR");
    FAIL_IF_NULL(de);
    FAIL_IF(de->mode != DetectUintModeBitmask);
    FAIL_IF(de->arg1 != (uint8_t) ~(TH_SYN | TH_RST));
    FAIL_IF(de->arg2 != (TH_ACK | TH_PUSH));

    SigMatch *sm = SigMatchAlloc();
    FAIL_IF_NULL(sm);
    sm->type = DETECT_FLAGS;
    sm->ctx = (SigMatchCtx *)de;

    int ret = DetectFlagsMatch(NULL, p, NULL, sm->ctx);
    FAIL_IF_NOT(ret == 1);

    SigMatchFree(NULL, sm);
    PacketFree(p);
    PASS;
}

/**
 * \test FlagsTestParse06 test if ACK+PUSH and no other flags are set. Ignore URG and RST bits.
 *       Must fail as TH_SYN is also set
 *  \retval 1 on success
 *  \retval 0 on failure
 */
static int FlagsTestParse06 (void)
{
    ThreadVars tv;
    IPV4Hdr ipv4h;
    TCPHdr tcph;

    memset(&tv, 0, sizeof(ThreadVars));
    memset(&ipv4h, 0, sizeof(IPV4Hdr));
    memset(&tcph, 0, sizeof(TCPHdr));

    Packet *p = PacketGetFromAlloc();
    FAIL_IF_NULL(p);
    UTHSetIPV4Hdr(p, &ipv4h);
    tcph.th_flags = TH_ACK | TH_PUSH | TH_SYN | TH_RST;
    UTHSetTCPHdr(p, &tcph);

    DetectU8Data *de = SCDetectTcpFlagsParse("AP,UR");
    FAIL_IF_NULL(de);
    FAIL_IF(de->mode != DetectUintModeBitmask);
    FAIL_IF(de->arg1 != (uint8_t) ~(TH_URG | TH_RST));
    FAIL_IF(de->arg2 != (TH_ACK | TH_PUSH));

    SigMatch *sm = SigMatchAlloc();
    FAIL_IF_NULL(sm);
    sm->type = DETECT_FLAGS;
    sm->ctx = (SigMatchCtx *)de;

    int ret = DetectFlagsMatch(NULL, p, NULL, sm->ctx);
    FAIL_IF_NOT(ret == 0);

    SigMatchFree(NULL, sm);
    PacketFree(p);
    PASS;
}

/**
 * \test FlagsTestParse07 test if SYN or RST are set. Must fails.
 *
 *  \retval 1 on success
 *  \retval 0 on failure
 */
static int FlagsTestParse07 (void)
{
    ThreadVars tv;
    IPV4Hdr ipv4h;
    TCPHdr tcph;

    memset(&tv, 0, sizeof(ThreadVars));
    memset(&ipv4h, 0, sizeof(IPV4Hdr));
    memset(&tcph, 0, sizeof(TCPHdr));

    Packet *p = PacketGetFromAlloc();
    FAIL_IF_NULL(p);
    UTHSetIPV4Hdr(p, &ipv4h);
    tcph.th_flags = TH_SYN | TH_RST;
    UTHSetTCPHdr(p, &tcph);

    DetectU8Data *de = SCDetectTcpFlagsParse("*AP");
    FAIL_IF_NULL(de);
    FAIL_IF(de->mode != DetectUintModeNegBitmask);
    FAIL_IF(de->arg1 != (TH_ACK | TH_PUSH));
    FAIL_IF(de->arg2 != 0);

    SigMatch *sm = SigMatchAlloc();
    FAIL_IF_NULL(sm);
    sm->type = DETECT_FLAGS;
    sm->ctx = (SigMatchCtx *)de;

    int ret = DetectFlagsMatch(NULL, p, NULL, sm->ctx);
    FAIL_IF_NOT(ret == 0);

    SigMatchFree(NULL, sm);
    PacketFree(p);
    PASS;
}

/**
 * \test FlagsTestParse08 test if SYN or RST are set. Must return success.
 *
 *  \retval 1 on success
 *  \retval 0 on failure
 */
static int FlagsTestParse08 (void)
{
    ThreadVars tv;
    IPV4Hdr ipv4h;
    TCPHdr tcph;

    memset(&tv, 0, sizeof(ThreadVars));
    memset(&ipv4h, 0, sizeof(IPV4Hdr));
    memset(&tcph, 0, sizeof(TCPHdr));

    Packet *p = PacketGetFromAlloc();
    FAIL_IF_NULL(p);
    UTHSetIPV4Hdr(p, &ipv4h);
    tcph.th_flags = TH_SYN | TH_RST;
    UTHSetTCPHdr(p, &tcph);

    DetectU8Data *de = SCDetectTcpFlagsParse("*SA");
    FAIL_IF_NULL(de);
    FAIL_IF(de->mode != DetectUintModeNegBitmask);
    FAIL_IF(de->arg1 != (TH_ACK | TH_SYN));

    SigMatch *sm = SigMatchAlloc();
    FAIL_IF_NULL(sm);
    sm->type = DETECT_FLAGS;
    sm->ctx = (SigMatchCtx *)de;

    int ret = DetectFlagsMatch(NULL, p, NULL, sm->ctx);
    FAIL_IF_NOT(ret == 1);

    SigMatchFree(NULL, sm);
    PacketFree(p);
    PASS;
}

/**
 * \test FlagsTestParse09 test if SYN and RST are not set. Must fails.
 *
 *  \retval 1 on success
 *  \retval 0 on failure
 */
static int FlagsTestParse09 (void)
{
    ThreadVars tv;
    IPV4Hdr ipv4h;
    TCPHdr tcph;

    memset(&tv, 0, sizeof(ThreadVars));
    memset(&ipv4h, 0, sizeof(IPV4Hdr));
    memset(&tcph, 0, sizeof(TCPHdr));

    Packet *p = PacketGetFromAlloc();
    FAIL_IF_NULL(p);
    UTHSetIPV4Hdr(p, &ipv4h);
    tcph.th_flags = TH_SYN | TH_RST;
    UTHSetTCPHdr(p, &tcph);

    DetectU8Data *de = SCDetectTcpFlagsParse("!PA");
    FAIL_IF_NULL(de);
    FAIL_IF(de->mode != DetectUintModeNegBitmask);
    FAIL_IF(de->arg1 != (TH_ACK | TH_PUSH));
    FAIL_IF(de->arg2 != (TH_ACK | TH_PUSH));

    SigMatch *sm = SigMatchAlloc();
    FAIL_IF_NULL(sm);
    sm->type = DETECT_FLAGS;
    sm->ctx = (SigMatchCtx *)de;

    int ret = DetectFlagsMatch(NULL, p, NULL, sm->ctx);
    FAIL_IF_NOT(ret == 1);

    SigMatchFree(NULL, sm);
    PacketFree(p);
    PASS;
}

/**
 * \test FlagsTestParse10 test if ACK and PUSH are not set. Must return success.
 *
 *  \retval 1 on success
 *  \retval 0 on failure
 */
static int FlagsTestParse10 (void)
{
    ThreadVars tv;
    IPV4Hdr ipv4h;
    TCPHdr tcph;

    memset(&tv, 0, sizeof(ThreadVars));
    memset(&ipv4h, 0, sizeof(IPV4Hdr));
    memset(&tcph, 0, sizeof(TCPHdr));

    Packet *p = PacketGetFromAlloc();
    FAIL_IF_NULL(p);
    UTHSetIPV4Hdr(p, &ipv4h);
    tcph.th_flags = TH_SYN | TH_RST;
    UTHSetTCPHdr(p, &tcph);

    DetectU8Data *de = SCDetectTcpFlagsParse("!AP");
    FAIL_IF_NULL(de);

    FAIL_IF(de->mode != DetectUintModeNegBitmask);
    FAIL_IF(de->arg1 != (TH_ACK | TH_PUSH));

    SigMatch *sm = SigMatchAlloc();
    FAIL_IF_NULL(sm);
    sm->type = DETECT_FLAGS;
    sm->ctx = (SigMatchCtx *)de;

    int ret = DetectFlagsMatch(NULL, p, NULL, sm->ctx);
    FAIL_IF_NOT(ret == 1);

    SigMatchFree(NULL, sm);
    PacketFree(p);
    PASS;
}

/**
 * \test FlagsTestParse11 test if flags are ACK and PUSH. Ignore SYN and RST.
 *
 *  \retval 1 on success
 *  \retval 0 on failure
 */
static int FlagsTestParse11 (void)
{
    ThreadVars tv;
    IPV4Hdr ipv4h;
    TCPHdr tcph;

    memset(&tv, 0, sizeof(ThreadVars));
    memset(&ipv4h, 0, sizeof(IPV4Hdr));
    memset(&tcph, 0, sizeof(TCPHdr));

    Packet *p = PacketGetFromAlloc();
    FAIL_IF_NULL(p);
    UTHSetIPV4Hdr(p, &ipv4h);
    tcph.th_flags = TH_SYN | TH_RST | TH_URG;
    UTHSetTCPHdr(p, &tcph);

    DetectU8Data *de = SCDetectTcpFlagsParse("AP,SR");
    FAIL_IF_NULL(de);
    FAIL_IF(de->mode != DetectUintModeBitmask);
    FAIL_IF(de->arg1 != (uint8_t) ~(TH_SYN | TH_RST));
    FAIL_IF(de->arg2 != (TH_ACK | TH_PUSH));

    SigMatch *sm = SigMatchAlloc();
    FAIL_IF_NULL(de);
    sm->type = DETECT_FLAGS;
    sm->ctx = (SigMatchCtx *)de;

    int ret = DetectFlagsMatch(NULL, p, NULL, sm->ctx);
    FAIL_IF_NOT(ret == 0);

    SigMatchFree(NULL, sm);
    PacketFree(p);
    PASS;
}

/**
 * \test FlagsTestParse12 check if no flags are set. Must fail.
 *
 *  \retval 1 on success
 *  \retval 0 on failure
 */
static int FlagsTestParse12 (void)
{
    ThreadVars tv;
    IPV4Hdr ipv4h;
    TCPHdr tcph;

    memset(&tv, 0, sizeof(ThreadVars));
    memset(&ipv4h, 0, sizeof(IPV4Hdr));
    memset(&tcph, 0, sizeof(TCPHdr));

    Packet *p = PacketGetFromAlloc();
    FAIL_IF_NULL(p);
    UTHSetIPV4Hdr(p, &ipv4h);
    tcph.th_flags = TH_SYN;
    UTHSetTCPHdr(p, &tcph);

    DetectU8Data *de = SCDetectTcpFlagsParse("0");
    FAIL_IF_NULL(de);
    FAIL_IF_NOT(de->mode == DetectUintModeEqual);
    FAIL_IF_NOT(de->arg1 == 0);

    SigMatch *sm = SigMatchAlloc();
    FAIL_IF_NULL(sm);
    sm->type = DETECT_FLAGS;
    sm->ctx = (SigMatchCtx *)de;

    int ret = DetectFlagsMatch(NULL, p, NULL, sm->ctx);
    FAIL_IF_NOT(ret == 0);

    SigMatchFree(NULL, sm);
    PacketFree(p);
    PASS;
}

static int FlagsTestParse15(void)
{
    ThreadVars tv;
    IPV4Hdr ipv4h;
    TCPHdr tcph;

    memset(&tv, 0, sizeof(ThreadVars));
    memset(&ipv4h, 0, sizeof(IPV4Hdr));
    memset(&tcph, 0, sizeof(TCPHdr));

    Packet *p = PacketGetFromAlloc();
    FAIL_IF_NULL(p);
    UTHSetIPV4Hdr(p, &ipv4h);
    tcph.th_flags = TH_ECN | TH_CWR | TH_SYN | TH_RST;
    UTHSetTCPHdr(p, &tcph);

    DetectU8Data *de = SCDetectTcpFlagsParse("EC+");
    FAIL_IF_NULL(de);
    FAIL_IF_NOT(de->mode == DetectUintModeBitmask);
    FAIL_IF_NOT(de->arg1 == (TH_ECN | TH_CWR));
    FAIL_IF_NOT(de->arg2 == (TH_ECN | TH_CWR));

    SigMatch *sm = SigMatchAlloc();
    FAIL_IF_NULL(sm);
    sm->type = DETECT_FLAGS;
    sm->ctx = (SigMatchCtx *)de;

    int ret = DetectFlagsMatch(NULL, p, NULL, sm->ctx);
    FAIL_IF_NOT(ret == 1);

    SigMatchFree(NULL, sm);
    PacketFree(p);
    PASS;
}

static int FlagsTestParse16(void)
{
    ThreadVars tv;
    IPV4Hdr ipv4h;
    TCPHdr tcph;

    memset(&tv, 0, sizeof(ThreadVars));
    memset(&ipv4h, 0, sizeof(IPV4Hdr));
    memset(&tcph, 0, sizeof(TCPHdr));

    Packet *p = PacketGetFromAlloc();
    FAIL_IF_NULL(p);
    UTHSetIPV4Hdr(p, &ipv4h);
    tcph.th_flags = TH_ECN | TH_SYN | TH_RST;
    UTHSetTCPHdr(p, &tcph);

    DetectU8Data *de = SCDetectTcpFlagsParse("EC*");
    FAIL_IF_NULL(de);
    FAIL_IF_NOT(de->mode == DetectUintModeNegBitmask);
    FAIL_IF_NOT(de->arg1 == (TH_ECN | TH_CWR));
    FAIL_IF_NOT(de->arg2 == 0);

    SigMatch *sm = SigMatchAlloc();
    FAIL_IF_NULL(sm);
    sm->type = DETECT_FLAGS;
    sm->ctx = (SigMatchCtx *)de;

    int ret = DetectFlagsMatch(NULL, p, NULL, sm->ctx);

    FAIL_IF_NOT(ret == 1);

    SigMatchFree(NULL, sm);
    PacketFree(p);
    PASS;
}

/**
 * \test Negative test.
 */
static int FlagsTestParse17(void)
{
    ThreadVars tv;
    IPV4Hdr ipv4h;
    TCPHdr tcph;

    memset(&tv, 0, sizeof(ThreadVars));
    memset(&ipv4h, 0, sizeof(IPV4Hdr));
    memset(&tcph, 0, sizeof(TCPHdr));

    Packet *p = PacketGetFromAlloc();
    FAIL_IF_NULL(p);
    UTHSetIPV4Hdr(p, &ipv4h);
    tcph.th_flags = TH_ECN | TH_SYN | TH_RST;
    UTHSetTCPHdr(p, &tcph);

    DetectU8Data *de = SCDetectTcpFlagsParse("EC+");
    FAIL_IF_NULL(de);
    FAIL_IF_NOT(de->mode == DetectUintModeBitmask);
    FAIL_IF_NOT(de->arg1 == (TH_ECN | TH_CWR));
    FAIL_IF_NOT(de->arg2 == (TH_ECN | TH_CWR));

    SigMatch *sm = SigMatchAlloc();
    FAIL_IF_NULL(sm);
    sm->type = DETECT_FLAGS;
    sm->ctx = (SigMatchCtx *)de;

    int ret = DetectFlagsMatch(NULL, p, NULL, sm->ctx);
    FAIL_IF_NOT(ret == 0);

    SigMatchFree(NULL, sm);
    PacketFree(p);
    PASS;
}

/**
 * \brief this function registers unit tests for Flags
 */
static void FlagsRegisterTests(void)
{
    UtRegisterTest("FlagsTestParse03", FlagsTestParse03);
    UtRegisterTest("FlagsTestParse04", FlagsTestParse04);
    UtRegisterTest("FlagsTestParse05", FlagsTestParse05);
    UtRegisterTest("FlagsTestParse06", FlagsTestParse06);
    UtRegisterTest("FlagsTestParse07", FlagsTestParse07);
    UtRegisterTest("FlagsTestParse08", FlagsTestParse08);
    UtRegisterTest("FlagsTestParse09", FlagsTestParse09);
    UtRegisterTest("FlagsTestParse10", FlagsTestParse10);
    UtRegisterTest("FlagsTestParse11", FlagsTestParse11);
    UtRegisterTest("FlagsTestParse12", FlagsTestParse12);
    UtRegisterTest("FlagsTestParse15", FlagsTestParse15);
    UtRegisterTest("FlagsTestParse16", FlagsTestParse16);
    UtRegisterTest("FlagsTestParse17", FlagsTestParse17);
}
#endif /* UNITTESTS */
