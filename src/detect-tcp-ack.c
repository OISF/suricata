/* Copyright (C) 2007-2016 Open Information Security Foundation
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
 * \author Brian Rectanus <brectanu@gmail.com>
 * \author Victor Julien <victor@inliniac.net>
 *
 * Implements the "ack" keyword.
 */

#include "suricata-common.h"
#include "decode.h"
#include "detect.h"

#include "detect-parse.h"
#include "detect-engine.h"
#include "detect-engine-mpm.h"
#include "detect-engine-prefilter.h"
#include "detect-engine-prefilter-common.h"
#include "detect-engine-build.h"
#include "detect-engine-uint.h"

#include "detect-tcp-ack.h"

#include "util-byte.h"
#include "util-unittest.h"
#include "util-unittest-helper.h"
#include "util-debug.h"

/* prototypes */
static int DetectAckSetup(DetectEngineCtx *, Signature *, const char *);
static int DetectAckMatch(DetectEngineThreadCtx *,
                          Packet *, const Signature *, const SigMatchCtx *);
#ifdef UNITTESTS
static void DetectAckRegisterTests(void);
#endif
static void DetectAckFree(DetectEngineCtx *, void *);
static int PrefilterSetupTcpAck(DetectEngineCtx *de_ctx, SigGroupHead *sgh);
static bool PrefilterTcpAckIsPrefilterable(const Signature *s);

void DetectAckRegister(void)
{
    sigmatch_table[DETECT_ACK].name = "tcp.ack";
    sigmatch_table[DETECT_ACK].alias = "ack";
    sigmatch_table[DETECT_ACK].desc = "check for a specific TCP acknowledgement number";
    sigmatch_table[DETECT_ACK].url = "/rules/header-keywords.html#ack";
    sigmatch_table[DETECT_ACK].Match = DetectAckMatch;
    sigmatch_table[DETECT_ACK].Setup = DetectAckSetup;
    sigmatch_table[DETECT_ACK].Free = DetectAckFree;
    sigmatch_table[DETECT_ACK].flags = SIGMATCH_INFO_UINT32;

    sigmatch_table[DETECT_ACK].SupportsPrefilter = PrefilterTcpAckIsPrefilterable;
    sigmatch_table[DETECT_ACK].SetupPrefilter = PrefilterSetupTcpAck;
#ifdef UNITTESTS
    sigmatch_table[DETECT_ACK].RegisterTests = DetectAckRegisterTests;
#endif
}

/**
 * \internal
 * \brief This function is used to match packets with a given Ack number
 *
 * \param t pointer to thread vars
 * \param det_ctx pointer to the pattern matcher thread
 * \param p pointer to the current packet
 * \param m pointer to the sigmatch that we will cast into DetectAckData
 *
 * \retval 0 no match
 * \retval 1 match
 */
static int DetectAckMatch(DetectEngineThreadCtx *det_ctx,
                          Packet *p, const Signature *s, const SigMatchCtx *ctx)
{
    DEBUG_VALIDATE_BUG_ON(PKT_IS_PSEUDOPKT(p));
    const DetectU32Data *data = (const DetectU32Data *)ctx;

    /* This is only needed on TCP packets */
    if (!(PacketIsTCP(p))) {
        return 0;
    }

    return DetectU32Match(TCP_GET_RAW_ACK(PacketGetTCP(p)), data);
}

/**
 * \internal
 * \brief this function is used to add the ack option into the signature
 *
 * \param de_ctx pointer to the Detection Engine Context
 * \param s pointer to the Current Signature
 * \param m pointer to the Current SigMatch
 * \param optstr pointer to the user provided options
 *
 * \retval 0 on Success
 * \retval -1 on Failure
 */
static int DetectAckSetup(DetectEngineCtx *de_ctx, Signature *s, const char *optstr)
{
    DetectU32Data *data = SCDetectU32Parse(optstr);
    if (data == NULL)
        return -1;

    if (SCSigMatchAppendSMToList(
                de_ctx, s, DETECT_ACK, (SigMatchCtx *)data, DETECT_SM_LIST_MATCH) == NULL) {
        DetectAckFree(de_ctx, data);
        return -1;
    }
    s->flags |= SIG_FLAG_REQUIRE_PACKET;
    return 0;
}

/**
 * \internal
 * \brief this function will free memory associated with ack option
 *
 * \param data pointer to ack configuration data
 */
static void DetectAckFree(DetectEngineCtx *de_ctx, void *ptr)
{
    SCDetectU32Free(ptr);
}

/* prefilter code */

static void
PrefilterPacketAckMatch(DetectEngineThreadCtx *det_ctx, Packet *p, const void *pectx)
{
    DEBUG_VALIDATE_BUG_ON(PKT_IS_PSEUDOPKT(p));
    const PrefilterPacketHeaderCtx *ctx = pectx;

    if (!PrefilterPacketHeaderExtraMatch(ctx, p))
        return;

    if (p->proto == IPPROTO_TCP && PacketIsTCP(p)) {
        DetectU32Data du32;
        du32.mode = ctx->v1.u8[0];
        du32.arg1 = ctx->v1.u32[1];
        du32.arg2 = ctx->v1.u32[2];
        if (DetectU32Match(TCP_GET_RAW_ACK(PacketGetTCP(p)), &du32)) {
            SCLogDebug("packet matches TCP ack %u", ctx->v1.u32[0]);
            PrefilterAddSids(&det_ctx->pmq, ctx->sigs_array, ctx->sigs_cnt);
        }
    }
}

static int PrefilterSetupTcpAck(DetectEngineCtx *de_ctx, SigGroupHead *sgh)
{
    return PrefilterSetupPacketHeader(de_ctx, sgh, DETECT_ACK, SIG_MASK_REQUIRE_REAL_PKT,
            PrefilterPacketU32Set, PrefilterPacketU32Compare, PrefilterPacketAckMatch);
}

static bool PrefilterTcpAckIsPrefilterable(const Signature *s)
{
    const SigMatch *sm;
    for (sm = s->init_data->smlists[DETECT_SM_LIST_MATCH] ; sm != NULL; sm = sm->next) {
        switch (sm->type) {
            case DETECT_ACK:
                return true;
        }
    }
    return false;
}

#ifdef UNITTESTS
#include "detect-engine-alert.h"
/**
 * \internal
 * \brief This test tests sameip success and failure.
 */
static int DetectAckSigTest01(void)
{
    ThreadVars th_v;
    memset(&th_v, 0, sizeof(th_v));
    DetectEngineThreadCtx *det_ctx = NULL;

    /* TCP w/ack=42 */
    Packet *p1 = UTHBuildPacket(NULL, 0, IPPROTO_TCP);
    p1->l4.hdrs.tcph->th_ack = htonl(42);

    /* TCP w/ack=100 */
    Packet *p2 = UTHBuildPacket(NULL, 0, IPPROTO_TCP);
    p2->l4.hdrs.tcph->th_ack = htonl(100);

    /* ICMP */
    Packet *p3 = UTHBuildPacket(NULL, 0, IPPROTO_ICMP);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    de_ctx->flags |= DE_QUIET;

    /* These three are crammed in here as there is no Parse */
    Signature *s = DetectEngineAppendSig(de_ctx, "alert tcp any any -> any any "
                                                 "(msg:\"Testing ack\";ack:foo;sid:1;)");
    FAIL_IF_NOT_NULL(s);
    s = DetectEngineAppendSig(de_ctx, "alert tcp any any -> any any "
                                      "(msg:\"Testing ack\";ack:9999999999;sid:1;)");
    FAIL_IF_NOT_NULL(s);
    s = DetectEngineAppendSig(de_ctx, "alert tcp any any -> any any "
                                      "(msg:\"Testing ack\";ack:-100;sid:1;)");
    FAIL_IF_NOT_NULL(s);

    s = DetectEngineAppendSig(de_ctx, "alert tcp any any -> any any "
                                      "(msg:\"Testing ack\";ack:41;sid:1;)");
    FAIL_IF_NULL(s);
    s = DetectEngineAppendSig(de_ctx, "alert tcp any any -> any any "
                                      "(msg:\"Testing ack\";ack:42;sid:2;)");
    FAIL_IF_NULL(s);

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p1);
    FAIL_IF(PacketAlertCheck(p1, 1));
    FAIL_IF_NOT(PacketAlertCheck(p1, 2));

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p2);
    FAIL_IF(PacketAlertCheck(p2, 1));
    FAIL_IF(PacketAlertCheck(p2, 2));

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p3);
    FAIL_IF(PacketAlertCheck(p3, 1));
    FAIL_IF(PacketAlertCheck(p3, 2));

    UTHFreePacket(p1);
    UTHFreePacket(p2);
    UTHFreePacket(p3);

    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);
    StatsThreadCleanup(&th_v);
    PASS;
}

/**
 * \internal
 * \brief This function registers unit tests for DetectAck
 */
static void DetectAckRegisterTests(void)
{
    UtRegisterTest("DetectAckSigTest01", DetectAckSigTest01);
}
#endif /* UNITTESTS */
