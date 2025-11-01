/* Copyright (C) 2007-2022 Open Information Security Foundation
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
 * Implements the icmp_seq keyword
 */

#include "suricata-common.h"
#include "decode.h"

#include "detect.h"
#include "detect-parse.h"
#include "detect-engine-prefilter-common.h"
#include "detect-engine-build.h"
#include "detect-engine-uint.h"

#include "detect-icmp-seq.h"

#include "util-byte.h"
#include "util-unittest.h"
#include "util-unittest-helper.h"
#include "util-debug.h"

static int DetectIcmpSeqMatch(DetectEngineThreadCtx *, Packet *,
        const Signature *, const SigMatchCtx *);
static int DetectIcmpSeqSetup(DetectEngineCtx *, Signature *, const char *);
#ifdef UNITTESTS
static void DetectIcmpSeqRegisterTests(void);
#endif
void DetectIcmpSeqFree(DetectEngineCtx *, void *);
static int PrefilterSetupIcmpSeq(DetectEngineCtx *de_ctx, SigGroupHead *sgh);
static bool PrefilterIcmpSeqIsPrefilterable(const Signature *s);

/**
 * \brief Registration function for icmp_seq
 */
void DetectIcmpSeqRegister (void)
{
    sigmatch_table[DETECT_ICMP_SEQ].name = "icmp_seq";
    sigmatch_table[DETECT_ICMP_SEQ].desc = "check for a ICMP sequence number";
    sigmatch_table[DETECT_ICMP_SEQ].url = "/rules/header-keywords.html#icmp-seq";
    sigmatch_table[DETECT_ICMP_SEQ].Match = DetectIcmpSeqMatch;
    sigmatch_table[DETECT_ICMP_SEQ].Setup = DetectIcmpSeqSetup;
    sigmatch_table[DETECT_ICMP_SEQ].Free = DetectIcmpSeqFree;
    sigmatch_table[DETECT_ICMP_SEQ].flags = SIGMATCH_INFO_UINT16;
#ifdef UNITTESTS
    sigmatch_table[DETECT_ICMP_SEQ].RegisterTests = DetectIcmpSeqRegisterTests;
#endif
    sigmatch_table[DETECT_ICMP_SEQ].SupportsPrefilter = PrefilterIcmpSeqIsPrefilterable;
    sigmatch_table[DETECT_ICMP_SEQ].SetupPrefilter = PrefilterSetupIcmpSeq;
}

static inline bool GetIcmpSeq(Packet *p, uint16_t *seq)
{
    uint16_t seqn;

    if (PacketIsICMPv4(p)) {
        switch (p->icmp_s.type) {
            case ICMP_ECHOREPLY:
            case ICMP_ECHO:
            case ICMP_TIMESTAMP:
            case ICMP_TIMESTAMPREPLY:
            case ICMP_INFO_REQUEST:
            case ICMP_INFO_REPLY:
            case ICMP_ADDRESS:
            case ICMP_ADDRESSREPLY:
                SCLogDebug("ICMPV4_GET_SEQ(p) %"PRIu16" (network byte order), "
                        "%"PRIu16" (host byte order)", ICMPV4_GET_SEQ(p),
                        SCNtohs(ICMPV4_GET_SEQ(p)));

                seqn = ICMPV4_GET_SEQ(p);
                break;
            default:
                SCLogDebug("Packet has no seq field");
                return false;
        }
    } else if (PacketIsICMPv6(p)) {
        switch (ICMPV6_GET_TYPE(PacketGetICMPv6(p))) {
            case ICMP6_ECHO_REQUEST:
            case ICMP6_ECHO_REPLY:
                SCLogDebug("ICMPV6_GET_SEQ(p) %"PRIu16" (network byte order), "
                        "%"PRIu16" (host byte order)", ICMPV6_GET_SEQ(p),
                        SCNtohs(ICMPV6_GET_SEQ(p)));

                seqn = ICMPV6_GET_SEQ(p);
                break;
            default:
                SCLogDebug("Packet has no seq field");
                return false;
        }
    } else {
        SCLogDebug("Packet not ICMPV4 nor ICMPV6");
        return false;
    }

    *seq = SCNtohs(seqn);
    return true;
}

/**
 * \brief This function is used to match icmp_seq rule option set on a packet
 *
 * \param t pointer to thread vars
 * \param det_ctx pointer to the pattern matcher thread
 * \param p pointer to the current packet
 * \param m pointer to the sigmatch that we will cast into DetectU16Data
 *
 * \retval 0 no match
 * \retval 1 match
 */
static int DetectIcmpSeqMatch (DetectEngineThreadCtx *det_ctx, Packet *p,
        const Signature *s, const SigMatchCtx *ctx)
{
    DEBUG_VALIDATE_BUG_ON(PKT_IS_PSEUDOPKT(p));
    uint16_t seqn;

    if (!GetIcmpSeq(p, &seqn))
        return 0;

    const DetectU16Data *iseq = (const DetectU16Data *)ctx;
    return DetectU16Match(seqn, iseq);
}

/**
 * \brief this function is used to add the parsed icmp_seq data into the current signature
 *
 * \param de_ctx pointer to the Detection Engine Context
 * \param s pointer to the Current Signature
 * \param icmpseqstr pointer to the user provided icmp_seq option
 *
 * \retval 0 on Success
 * \retval -1 on Failure
 */
static int DetectIcmpSeqSetup (DetectEngineCtx *de_ctx, Signature *s, const char *icmpseqstr)
{
    DetectU16Data *iseq = SCDetectU16UnquoteParse(icmpseqstr);
    if (iseq == NULL)
        return -1;

    if (SCSigMatchAppendSMToList(
                de_ctx, s, DETECT_ICMP_SEQ, (SigMatchCtx *)iseq, DETECT_SM_LIST_MATCH) == NULL) {
        goto error;
    }
    s->flags |= SIG_FLAG_REQUIRE_PACKET;

    return 0;

error:
    DetectIcmpSeqFree(de_ctx, iseq);
    return -1;

}

/**
 * \brief this function will free memory associated with DetectU16Data
 *
 * \param ptr pointer to DetectU16Data
 */
void DetectIcmpSeqFree (DetectEngineCtx *de_ctx, void *ptr)
{
    SCDetectU16Free(ptr);
}

/* prefilter code */

static void
PrefilterPacketIcmpSeqMatch(DetectEngineThreadCtx *det_ctx, Packet *p, const void *pectx)
{
    DEBUG_VALIDATE_BUG_ON(PKT_IS_PSEUDOPKT(p));

    const PrefilterPacketHeaderCtx *ctx = pectx;
    uint16_t seqn;

    if (!GetIcmpSeq(p, &seqn))
        return;

    DetectU16Data du16;
    du16.mode = ctx->v1.u8[0];
    du16.arg1 = ctx->v1.u16[1];
    du16.arg2 = ctx->v1.u16[2];
    if (DetectU16Match(seqn, &du16)) {
        SCLogDebug("packet matches ICMP SEQ %u", ctx->v1.u16[0]);
        PrefilterAddSids(&det_ctx->pmq, ctx->sigs_array, ctx->sigs_cnt);
    }
}

static int PrefilterSetupIcmpSeq(DetectEngineCtx *de_ctx, SigGroupHead *sgh)
{
    return PrefilterSetupPacketHeader(de_ctx, sgh, DETECT_ICMP_SEQ, SIG_MASK_REQUIRE_REAL_PKT,
            PrefilterPacketU16Set, PrefilterPacketU16Compare, PrefilterPacketIcmpSeqMatch);
}

static bool PrefilterIcmpSeqIsPrefilterable(const Signature *s)
{
    const SigMatch *sm;
    for (sm = s->init_data->smlists[DETECT_SM_LIST_MATCH] ; sm != NULL; sm = sm->next) {
        switch (sm->type) {
            case DETECT_ICMP_SEQ:
                return true;
        }
    }
    return false;
}

#ifdef UNITTESTS
#include "detect-engine.h"
#include "detect-engine-mpm.h"
#include "detect-engine-alert.h"

/**
 * \test DetectIcmpSeqParseTest01 is a test for setting a valid icmp_seq value
 */
static int DetectIcmpSeqParseTest01 (void)
{
    DetectU16Data *iseq = NULL;
    iseq = SCDetectU16UnquoteParse("300");
    FAIL_IF_NULL(iseq);
    FAIL_IF_NOT(iseq->arg1 == 300);
    DetectIcmpSeqFree(NULL, iseq);
    PASS;
}

/**
 * \test DetectIcmpSeqParseTest02 is a test for setting a valid icmp_seq value
 *       with spaces all around
 */
static int DetectIcmpSeqParseTest02 (void)
{
    DetectU16Data *iseq = NULL;
    iseq = SCDetectU16UnquoteParse("  300  ");
    FAIL_IF_NULL(iseq);
    FAIL_IF_NOT(iseq->arg1 == 300);
    DetectIcmpSeqFree(NULL, iseq);
    PASS;
}

/**
 * \test DetectIcmpSeqParseTest03 is a test for setting an invalid icmp_seq value
 */
static int DetectIcmpSeqParseTest03 (void)
{
    DetectU16Data *iseq = SCDetectU16UnquoteParse("badc");
    FAIL_IF_NOT_NULL(iseq);
    PASS;
}

static void DetectIcmpSeqRegisterTests (void)
{
    UtRegisterTest("DetectIcmpSeqParseTest01", DetectIcmpSeqParseTest01);
    UtRegisterTest("DetectIcmpSeqParseTest02", DetectIcmpSeqParseTest02);
    UtRegisterTest("DetectIcmpSeqParseTest03", DetectIcmpSeqParseTest03);
}
#endif /* UNITTESTS */
