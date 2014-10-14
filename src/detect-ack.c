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
 * Implements the "ack" keyword.
 */

#include "suricata-common.h"
#include "debug.h"
#include "decode.h"
#include "detect.h"

#include "detect-parse.h"
#include "detect-engine.h"
#include "detect-engine-mpm.h"

#include "detect-ack.h"

#include "util-byte.h"
#include "util-unittest.h"
#include "util-unittest-helper.h"
#include "util-debug.h"

/* prototypes */
static int DetectAckSetup(DetectEngineCtx *, Signature *, char *);
static int DetectAckMatch(ThreadVars *, DetectEngineThreadCtx *,
                          Packet *, Signature *, const SigMatchCtx *);
static void DetectAckRegisterTests(void);
static void DetectAckFree(void *);

void DetectAckRegister(void)
{
    sigmatch_table[DETECT_ACK].name = "ack";
    sigmatch_table[DETECT_ACK].desc = "check for a specific TCP acknowledgement number";
    sigmatch_table[DETECT_ACK].url = "https://redmine.openinfosecfoundation.org/projects/suricata/wiki/Header_keywords#ack";
    sigmatch_table[DETECT_ACK].Match = DetectAckMatch;
    sigmatch_table[DETECT_ACK].Setup = DetectAckSetup;
    sigmatch_table[DETECT_ACK].Free = DetectAckFree;
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
                          Packet *p, Signature *s, const SigMatchCtx *ctx)
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
static int DetectAckSetup(DetectEngineCtx *de_ctx, Signature *s, char *optstr)
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


#ifdef UNITTESTS
/**
 * \internal
 * \brief This test tests sameip success and failure.
 */
static int DetectAckSigTest01Real(int mpm_type)
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

    de_ctx->mpm_matcher = mpm_type;
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

/**
 * \test DetectAckSigTest01B2g tests sameip under B2g MPM
 */
static int DetectAckSigTest01B2g(void)
{
    return DetectAckSigTest01Real(MPM_B2G);
}

/**
 * \test DetectAckSigTest01B2g tests sameip under B3g MPM
 */
static int DetectAckSigTest01B3g(void)
{
    return DetectAckSigTest01Real(MPM_B3G);
}

/**
 * \test DetectAckSigTest01B2g tests sameip under WuManber MPM
 */
static int DetectAckSigTest01Wm(void)
{
    return DetectAckSigTest01Real(MPM_WUMANBER);
}

#endif /* UNITTESTS */

/**
 * \internal
 * \brief This function registers unit tests for DetectAck
 */
static void DetectAckRegisterTests(void)
{
#ifdef UNITTESTS
    UtRegisterTest("DetectAckSigTest01B2g", DetectAckSigTest01B2g, 1);
    UtRegisterTest("DetectAckSigTest01B3g", DetectAckSigTest01B3g, 1);
    UtRegisterTest("DetectAckSigTest01Wm", DetectAckSigTest01Wm, 1);
#endif /* UNITTESTS */
}

