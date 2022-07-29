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
 * \author Brian Rectanus <brectanu@gmail.com>
 *
 * Implements the seq keyword.
 */

#include "suricata-common.h"

#include "detect-parse.h"
#include "detect-engine.h"
#include "detect-engine-prefilter-common.h"
#include "detect-engine-build.h"

#include "detect-tcp-seq.h"

#include "util-byte.h"
#include "util-unittest.h"
#include "util-unittest-helper.h"

static int DetectSeqSetup(DetectEngineCtx *, Signature *, const char *);
static int DetectSeqMatch(DetectEngineThreadCtx *,
                          Packet *, const Signature *, const SigMatchCtx *);
#ifdef UNITTESTS
static void DetectSeqRegisterTests(void);
#endif
static void DetectSeqFree(DetectEngineCtx *, void *);
static int PrefilterSetupTcpSeq(DetectEngineCtx *de_ctx, SigGroupHead *sgh);
static bool PrefilterTcpSeqIsPrefilterable(const Signature *s);

void DetectSeqRegister(void)
{
    sigmatch_table[DETECT_SEQ].name = "tcp.seq";
    sigmatch_table[DETECT_SEQ].alias = "seq";
    sigmatch_table[DETECT_SEQ].desc = "check for a specific TCP sequence number";
    sigmatch_table[DETECT_SEQ].url = "/rules/header-keywords.html#seq";
    sigmatch_table[DETECT_SEQ].Match = DetectSeqMatch;
    sigmatch_table[DETECT_SEQ].Setup = DetectSeqSetup;
    sigmatch_table[DETECT_SEQ].Free = DetectSeqFree;
#ifdef UNITTESTS
    sigmatch_table[DETECT_SEQ].RegisterTests = DetectSeqRegisterTests;
#endif
    sigmatch_table[DETECT_SEQ].SupportsPrefilter = PrefilterTcpSeqIsPrefilterable;
    sigmatch_table[DETECT_SEQ].SetupPrefilter = PrefilterSetupTcpSeq;
}

/**
 * \internal
 * \brief This function is used to match packets with a given Seq number
 *
 * \param t pointer to thread vars
 * \param det_ctx pointer to the pattern matcher thread
 * \param p pointer to the current packet
 * \param m pointer to the sigmatch that we will cast into DetectSeqData
 *
 * \retval 0 no match
 * \retval 1 match
 */
static int DetectSeqMatch(DetectEngineThreadCtx *det_ctx,
                          Packet *p, const Signature *s, const SigMatchCtx *ctx)
{
    const DetectSeqData *data = (const DetectSeqData *)ctx;

    /* This is only needed on TCP packets */
    if (!(PKT_IS_TCP(p)) || PKT_IS_PSEUDOPKT(p)) {
        return 0;
    }

    return (data->seq == TCP_GET_SEQ(p)) ? 1 : 0;
}

/**
 * \internal
 * \brief this function is used to add the seq option into the signature
 *
 * \param de_ctx pointer to the Detection Engine Context
 * \param s pointer to the Current Signature
 * \param optstr pointer to the user provided options
 *
 * \retval 0 on Success
 * \retval -1 on Failure
 */
static int DetectSeqSetup (DetectEngineCtx *de_ctx, Signature *s, const char *optstr)
{
    DetectSeqData *data = NULL;
    SigMatch *sm = NULL;

    data = SCMalloc(sizeof(DetectSeqData));
    if (unlikely(data == NULL))
        goto error;

    sm = SigMatchAlloc();
    if (sm == NULL)
        goto error;

    sm->type = DETECT_SEQ;

    if (StringParseUint32(&data->seq, 10, 0, optstr) < 0) {
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
        SigMatchFree(de_ctx, sm);
    return -1;

}

/**
 * \internal
 * \brief this function will free memory associated with seq option
 *
 * \param data pointer to seq configuration data
 */
static void DetectSeqFree(DetectEngineCtx *de_ctx, void *ptr)
{
    DetectSeqData *data = (DetectSeqData *)ptr;
    SCFree(data);
}

/* prefilter code */

static void
PrefilterPacketSeqMatch(DetectEngineThreadCtx *det_ctx, Packet *p, const void *pectx)
{
    const PrefilterPacketHeaderCtx *ctx = pectx;

    if (!PrefilterPacketHeaderExtraMatch(ctx, p))
        return;

    if ((p->proto) == IPPROTO_TCP && !(PKT_IS_PSEUDOPKT(p)) &&
        (p->tcph != NULL) && (TCP_GET_SEQ(p) == ctx->v1.u32[0]))
    {
        SCLogDebug("packet matches TCP seq %u", ctx->v1.u32[0]);
        PrefilterAddSids(&det_ctx->pmq, ctx->sigs_array, ctx->sigs_cnt);
    }
}

static void
PrefilterPacketSeqSet(PrefilterPacketHeaderValue *v, void *smctx)
{
    const DetectSeqData *a = smctx;
    v->u32[0] = a->seq;
}

static bool
PrefilterPacketSeqCompare(PrefilterPacketHeaderValue v, void *smctx)
{
    const DetectSeqData *a = smctx;
    if (v.u32[0] == a->seq)
        return true;
    return false;
}

static int PrefilterSetupTcpSeq(DetectEngineCtx *de_ctx, SigGroupHead *sgh)
{
    return PrefilterSetupPacketHeader(de_ctx, sgh, DETECT_SEQ,
        PrefilterPacketSeqSet,
        PrefilterPacketSeqCompare,
        PrefilterPacketSeqMatch);
}

static bool PrefilterTcpSeqIsPrefilterable(const Signature *s)
{
    const SigMatch *sm;
    for (sm = s->init_data->smlists[DETECT_SM_LIST_MATCH] ; sm != NULL; sm = sm->next) {
        switch (sm->type) {
            case DETECT_SEQ:
                return true;
        }
    }
    return false;
}


#ifdef UNITTESTS

/**
 * \test DetectSeqSigTest01 tests parses
 */
static int DetectSeqSigTest01(void)
{
    int result = 0;
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    /* These three are crammed in here as there is no Parse */
    if (SigInit(de_ctx,
                "alert tcp any any -> any any "
                "(msg:\"Testing seq\";seq:foo;sid:1;)") != NULL)
    {
        printf("invalid seq accepted: ");
        goto cleanup;
    }
    if (SigInit(de_ctx,
                "alert tcp any any -> any any "
                "(msg:\"Testing seq\";seq:9999999999;sid:1;)") != NULL)
    {
        printf("overflowing seq accepted: ");
        goto cleanup;
    }
    if (SigInit(de_ctx,
                "alert tcp any any -> any any "
                "(msg:\"Testing seq\";seq:-100;sid:1;)") != NULL)
    {
        printf("negative seq accepted: ");
        goto cleanup;
    }
    result = 1;

cleanup:
    if (de_ctx) {
        SigGroupCleanup(de_ctx);
        SigCleanSignatures(de_ctx);
        DetectEngineCtxFree(de_ctx);
    }
end:
    return result;
}

/**
 * \test DetectSeqSigTest02 tests seq keyword
 */
static int DetectSeqSigTest02(void)
{
    int result = 0;
    uint8_t *buf = (uint8_t *)"Hi all!";
    uint16_t buflen = strlen((char *)buf);
    Packet *p[3];
    p[0] = UTHBuildPacket((uint8_t *)buf, buflen, IPPROTO_TCP);
    p[1] = UTHBuildPacket((uint8_t *)buf, buflen, IPPROTO_TCP);
    p[2] = UTHBuildPacket((uint8_t *)buf, buflen, IPPROTO_ICMP);
    if (p[0] == NULL || p[1] == NULL ||p[2] == NULL)
        goto end;

    /* TCP w/seq=42 */
    p[0]->tcph->th_seq = htonl(42);

    /* TCP w/seq=100 */
    p[1]->tcph->th_seq = htonl(100);

    const char *sigs[2];
    sigs[0]= "alert tcp any any -> any any (msg:\"Testing seq\"; seq:41; sid:1;)";
    sigs[1]= "alert tcp any any -> any any (msg:\"Testing seq\"; seq:42; sid:2;)";

    uint32_t sid[2] = {1, 2};

    uint32_t results[3][2] = {
                              /* packet 0 match sid 1 but should not match sid 2 */
                              {0, 1},
                              /* packet 1 should not match */
                              {0, 0},
                              /* packet 2 should not match */
                              {0, 0} };

    result = UTHGenericTest(p, 3, sigs, sid, (uint32_t *) results, 2);
    UTHFreePackets(p, 3);
end:
    return result;
}

/**
 * \internal
 * \brief This function registers unit tests for DetectSeq
 */
static void DetectSeqRegisterTests(void)
{
    UtRegisterTest("DetectSeqSigTest01", DetectSeqSigTest01);
    UtRegisterTest("DetectSeqSigTest02", DetectSeqSigTest02);
}
#endif /* UNITTESTS */
