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
 * \author Brian Rectanus <brectanu@gmail.com>
 *
 * Implements the sameip keyword.
 */

#include "suricata-common.h"
#include "decode.h"
#include "detect.h"

#include "detect-parse.h"
#include "detect-engine.h"
#include "detect-engine-mpm.h"
#include "detect-engine-build.h"

#include "detect-sameip.h"

#include "util-unittest.h"
#include "util-unittest-helper.h"

static int DetectSameipMatch(DetectEngineThreadCtx *, Packet *,
                             const Signature *, const SigMatchCtx *);
static int DetectSameipSetup(DetectEngineCtx *, Signature *, const char *);
#ifdef UNITTESTS
static void DetectSameipRegisterTests(void);
#endif

/**
 * \brief Registration function for sameip: keyword
 * \todo add support for no_stream and stream_only
 */
void DetectSameipRegister(void)
{
    sigmatch_table[DETECT_SAMEIP].name = "sameip";
    sigmatch_table[DETECT_SAMEIP].desc = "check if the IP address of the source is the same as the IP address of the destination";
    sigmatch_table[DETECT_SAMEIP].url = "/rules/header-keywords.html#sameip";
    sigmatch_table[DETECT_SAMEIP].Match = DetectSameipMatch;
    sigmatch_table[DETECT_SAMEIP].Setup = DetectSameipSetup;
#ifdef UNITTESTS
    sigmatch_table[DETECT_SAMEIP].RegisterTests = DetectSameipRegisterTests;
#endif
    sigmatch_table[DETECT_SAMEIP].flags = SIGMATCH_NOOPT;
}

/**
 * \internal
 * \brief This function is used to match packets with same src/dst IPs
 *
 * \param t pointer to thread vars
 * \param det_ctx pointer to the pattern matcher thread
 * \param p pointer to the current packet
 * \param m pointer to the sigmatch that we will cast into DetectSameipData
 *
 * \retval 0 no match
 * \retval 1 match
 */
static int DetectSameipMatch(DetectEngineThreadCtx *det_ctx,
                             Packet *p, const Signature *s, const SigMatchCtx *ctx)
{
    return CMP_ADDR(&p->src, &p->dst) ? 1 : 0;
}

/**
 * \internal
 * \brief this function is used to add the sameip option into the signature
 *
 * \param de_ctx pointer to the Detection Engine Context
 * \param s pointer to the Current Signature
 * \param optstr pointer to the user provided options
 *
 * \retval 0 on Success
 * \retval -1 on Failure
 */
static int DetectSameipSetup(DetectEngineCtx *de_ctx, Signature *s, const char *optstr)
{
    SigMatch *sm = NULL;

    /* Get this into a SigMatch and put it in the Signature. */
    sm = SigMatchAlloc();
    if (sm == NULL)
        goto error;

    sm->type = DETECT_SAMEIP;
    sm->ctx = NULL;

    SigMatchAppendSMToList(s, sm, DETECT_SM_LIST_MATCH);
    s->flags |= SIG_FLAG_REQUIRE_PACKET;

    return 0;

error:
    if (sm != NULL)
        SCFree(sm);
    return -1;

}

#ifdef UNITTESTS

/* NOTE: No parameters, so no parse tests */

/**
 * \internal
 * \brief This test tests sameip success and failure.
 */
static int DetectSameipSigTest01(void)
{
    uint8_t *buf = (uint8_t *)
                    "GET / HTTP/1.0\r\n"
                    "\r\n";
    uint16_t buflen = strlen((char *)buf);
    Packet *p1 = NULL;
    Packet *p2 = NULL;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx;

    memset(&th_v, 0, sizeof(th_v));

    /* First packet has same IPs */
    p1 = UTHBuildPacketSrcDst(buf, buflen, IPPROTO_TCP, "1.2.3.4", "1.2.3.4");

    /* Second packet does not have same IPs */
    p2 = UTHBuildPacketSrcDst(buf, buflen, IPPROTO_TCP, "1.2.3.4", "4.3.2.1");

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,
                                     "alert tcp any any -> any any "
                                     "(msg:\"Testing sameip\"; sameip; sid:1;)");
    FAIL_IF_NULL(de_ctx->sig_list);

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p1);
    FAIL_IF(PacketAlertCheck(p1, 1) == 0);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p2);
    FAIL_IF(PacketAlertCheck(p2, 1) != 0);

    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);

    PASS;
}

/**
 * \internal
 * \brief This function registers unit tests for DetectSameip
 */
static void DetectSameipRegisterTests(void)
{
    UtRegisterTest("DetectSameipSigTest01", DetectSameipSigTest01);
}
#endif /* UNITTESTS */
