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
#include "debug.h"
#include "decode.h"
#include "detect.h"

#include "detect-parse.h"
#include "detect-engine.h"
#include "detect-engine-mpm.h"

#include "detect-seq.h"

#include "util-byte.h"
#include "util-unittest.h"
#include "util-unittest-helper.h"
#include "util-debug.h"

static int DetectSeqSetup(DetectEngineCtx *, Signature *, char *);
static int DetectSeqMatch(ThreadVars *, DetectEngineThreadCtx *,
                          Packet *, Signature *, const SigMatchCtx *);
static void DetectSeqRegisterTests(void);
static void DetectSeqFree(void *);


void DetectSeqRegister(void)
{
    sigmatch_table[DETECT_SEQ].name = "seq";
    sigmatch_table[DETECT_SEQ].desc = "check for a specific TCP sequence number";
    sigmatch_table[DETECT_SEQ].url = "https://redmine.openinfosecfoundation.org/projects/suricata/wiki/Header_keywords#seq";
    sigmatch_table[DETECT_SEQ].Match = DetectSeqMatch;
    sigmatch_table[DETECT_SEQ].Setup = DetectSeqSetup;
    sigmatch_table[DETECT_SEQ].Free = DetectSeqFree;
    sigmatch_table[DETECT_SEQ].RegisterTests = DetectSeqRegisterTests;
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
static int DetectSeqMatch(ThreadVars *t, DetectEngineThreadCtx *det_ctx,
                          Packet *p, Signature *s, const SigMatchCtx *ctx)
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
static int DetectSeqSetup (DetectEngineCtx *de_ctx, Signature *s, char *optstr)
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

    if (-1 == ByteExtractStringUint32(&data->seq, 10, 0, optstr)) {
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
 * \brief this function will free memory associated with seq option
 *
 * \param data pointer to seq configuration data
 */
static void DetectSeqFree(void *ptr)
{
    DetectSeqData *data = (DetectSeqData *)ptr;
    SCFree(data);
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

    char *sigs[2];
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

#endif /* UNITTESTS */

/**
 * \internal
 * \brief This function registers unit tests for DetectSeq
 */
static void DetectSeqRegisterTests(void)
{
#ifdef UNITTESTS
    UtRegisterTest("DetectSeqSigTest01", DetectSeqSigTest01, 1);
    UtRegisterTest("DetectSeqSigTest02", DetectSeqSigTest02, 1);
#endif /* UNITTESTS */
}

