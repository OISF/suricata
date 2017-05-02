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
#include "debug.h"
#include "decode.h"
#include "detect.h"

#include "detect-parse.h"
#include "detect-engine.h"
#include "detect-engine-mpm.h"
#include "detect-engine-prefilter.h"
#include "detect-engine-prefilter-common.h"

#include "detect-ack.h"

#include "util-byte.h"
#include "util-unittest.h"
#include "util-unittest-helper.h"
#include "util-debug.h"

/* prototypes */
static int DetectAckSetup(DetectEngineCtx *, Signature *, const char *);
static int DetectAckMatch(ThreadVars *, DetectEngineThreadCtx *,
                          Packet *, const Signature *, const SigMatchCtx *);
static void DetectAckRegisterTests(void);
static void DetectAckFree(void *);
static int PrefilterSetupTcpAck(SigGroupHead *sgh);
static _Bool PrefilterTcpAckIsPrefilterable(const Signature *s);

void DetectAckRegister(void)
{
    sigmatch_table[DETECT_ACK].name = "ack";
    sigmatch_table[DETECT_ACK].desc = "check for a specific TCP acknowledgement number";
    sigmatch_table[DETECT_ACK].url = DOC_URL DOC_VERSION "/rules/header-keywords.html#ack";
    sigmatch_table[DETECT_ACK].Match = DetectAckMatch;
    sigmatch_table[DETECT_ACK].Setup = DetectAckSetup;
    sigmatch_table[DETECT_ACK].Free = DetectAckFree;

    sigmatch_table[DETECT_ACK].SupportsPrefilter = PrefilterTcpAckIsPrefilterable;
    sigmatch_table[DETECT_ACK].SetupPrefilter = PrefilterSetupTcpAck;

    sigmatch_table[DETECT_ACK].RegisterTests = DetectAckRegisterTests;
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
static int DetectAckMatch(ThreadVars *t, DetectEngineThreadCtx *det_ctx,
                          Packet *p, const Signature *s, const SigMatchCtx *ctx)
{
    const DetectAckData *data = (const DetectAckData *)ctx;

    /* This is only needed on TCP packets */
    if (!(PKT_IS_TCP(p)) || PKT_IS_PSEUDOPKT(p)) {
        return 0;
    }

    return (data->ack == TCP_GET_ACK(p)) ? 1 : 0;
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
    DetectAckData *data = NULL;
    SigMatch *sm = NULL;

    data = SCMalloc(sizeof(DetectAckData));
    if (unlikely(data == NULL))
        goto error;

    sm = SigMatchAlloc();
    if (sm == NULL)
        goto error;

    sm->type = DETECT_ACK;

    if (-1 == ByteExtractStringUint32(&data->ack, 10, 0, optstr)) {
        goto error;
    }
    sm->ctx = (SigMatchCtx*)data;

    SigMatchAppendSMToList(s, sm, DETECT_SM_LIST_MATCH);
    s->flags |= SIG_FLAG_REQUIRE_PACKET;

    return 0;

error:
    if (data)
        SCFree(data);
    if (sm)
        SigMatchFree(sm);
    return -1;

}

/**
 * \internal
 * \brief this function will free memory associated with ack option
 *
 * \param data pointer to ack configuration data
 */
static void DetectAckFree(void *ptr)
{
    DetectAckData *data = (DetectAckData *)ptr;
    SCFree(data);
}

/* prefilter code */

static void
PrefilterPacketAckMatch(DetectEngineThreadCtx *det_ctx, Packet *p, const void *pectx)
{
    const PrefilterPacketHeaderCtx *ctx = pectx;

    if (PrefilterPacketHeaderExtraMatch(ctx, p) == FALSE)
        return;

    if ((p->proto) == IPPROTO_TCP && !(PKT_IS_PSEUDOPKT(p)) &&
        (p->tcph != NULL) && (TCP_GET_ACK(p) == ctx->v1.u32[0]))
    {
        SCLogDebug("packet matches TCP ack %u", ctx->v1.u32[0]);
        PrefilterAddSids(&det_ctx->pmq, ctx->sigs_array, ctx->sigs_cnt);
    }
}

static void
PrefilterPacketAckSet(PrefilterPacketHeaderValue *v, void *smctx)
{
    const DetectAckData *a = smctx;
    v->u32[0] = a->ack;
}

static _Bool
PrefilterPacketAckCompare(PrefilterPacketHeaderValue v, void *smctx)
{
    const DetectAckData *a = smctx;
    if (v.u32[0] == a->ack)
        return TRUE;
    return FALSE;
}

static int PrefilterSetupTcpAck(SigGroupHead *sgh)
{
    return PrefilterSetupPacketHeader(sgh, DETECT_ACK,
        PrefilterPacketAckSet,
        PrefilterPacketAckCompare,
        PrefilterPacketAckMatch);
}

static _Bool PrefilterTcpAckIsPrefilterable(const Signature *s)
{
    const SigMatch *sm;
    for (sm = s->init_data->smlists[DETECT_SM_LIST_MATCH] ; sm != NULL; sm = sm->next) {
        switch (sm->type) {
            case DETECT_ACK:
                return TRUE;
        }
    }
    return FALSE;
}

#ifdef UNITTESTS
/**
 * \internal
 * \brief This test tests sameip success and failure.
 */
static int DetectAckSigTest01(void)
{
    Packet *p1 = NULL;
    Packet *p2 = NULL;
    Packet *p3 = NULL;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx;
    int result = 0;

    memset(&th_v, 0, sizeof(th_v));

    /* TCP w/ack=42 */
    p1 = UTHBuildPacket(NULL, 0, IPPROTO_TCP);
    p1->tcph->th_ack = htonl(42);

    /* TCP w/ack=100 */
    p2 = UTHBuildPacket(NULL, 0, IPPROTO_TCP);
    p2->tcph->th_ack = htonl(100);

    /* ICMP */
    p3 = UTHBuildPacket(NULL, 0, IPPROTO_ICMP);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }

    de_ctx->flags |= DE_QUIET;

    /* These three are crammed in here as there is no Parse */
    if (SigInit(de_ctx,
                "alert tcp any any -> any any "
                "(msg:\"Testing ack\";ack:foo;sid:1;)") != NULL)
    {
        printf("invalid ack accepted: ");
        goto cleanup_engine;
    }
    if (SigInit(de_ctx,
                "alert tcp any any -> any any "
                "(msg:\"Testing ack\";ack:9999999999;sid:1;)") != NULL)
    {
        printf("overflowing ack accepted: ");
        goto cleanup_engine;
    }
    if (SigInit(de_ctx,
                "alert tcp any any -> any any "
                "(msg:\"Testing ack\";ack:-100;sid:1;)") != NULL)
    {
        printf("negative ack accepted: ");
        goto cleanup_engine;
    }

    de_ctx->sig_list = SigInit(de_ctx,
                               "alert tcp any any -> any any "
                               "(msg:\"Testing ack\";ack:41;sid:1;)");
    if (de_ctx->sig_list == NULL) {
        goto cleanup_engine;
    }

    de_ctx->sig_list->next = SigInit(de_ctx,
                                     "alert tcp any any -> any any "
                                     "(msg:\"Testing ack\";ack:42;sid:2;)");
    if (de_ctx->sig_list->next == NULL) {
        goto cleanup_engine;
    }

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p1);
    if (PacketAlertCheck(p1, 1) != 0) {
        printf("sid 1 alerted, but should not have: ");
        goto cleanup;
    }
    if (PacketAlertCheck(p1, 2) == 0) {
        printf("sid 2 did not alert, but should have: ");
        goto cleanup;
    }

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p2);
    if (PacketAlertCheck(p2, 1) != 0) {
        printf("sid 1 alerted, but should not have: ");
        goto cleanup;
    }
    if (PacketAlertCheck(p2, 2) != 0) {
        printf("sid 2 alerted, but should not have: ");
        goto cleanup;
    }

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p3);
    if (PacketAlertCheck(p3, 1) != 0) {
        printf("sid 1 alerted, but should not have: ");
        goto cleanup;
    }
    if (PacketAlertCheck(p3, 2) != 0) {
        printf("sid 2 alerted, but should not have: ");
        goto cleanup;
    }

    result = 1;

cleanup:
    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);

    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);

cleanup_engine:
    DetectEngineCtxFree(de_ctx);

end:
    return result;
}

#endif /* UNITTESTS */

/**
 * \internal
 * \brief This function registers unit tests for DetectAck
 */
static void DetectAckRegisterTests(void)
{
#ifdef UNITTESTS
    UtRegisterTest("DetectAckSigTest01", DetectAckSigTest01);
#endif /* UNITTESTS */
}

