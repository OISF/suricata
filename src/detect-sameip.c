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
 * Implements the sameip keyword.
 */

#include "suricata-common.h"
#include "debug.h"
#include "decode.h"
#include "detect.h"

#include "detect-parse.h"
#include "detect-engine.h"
#include "detect-engine-mpm.h"

#include "detect-sameip.h"

#include "util-unittest.h"

static int DetectSameipMatch(ThreadVars *, DetectEngineThreadCtx *, Packet *,
                             Signature *, SigMatch *);
static int DetectSameipSetup(DetectEngineCtx *, Signature *, char *);
static void DetectSameipRegisterTests(void);

/**
 * \brief Registration function for sameip: keyword
 * \todo add support for no_stream and stream_only
 */
void DetectSameipRegister(void)
{
    sigmatch_table[DETECT_SAMEIP].name = "sameip";
    sigmatch_table[DETECT_SAMEIP].Match = DetectSameipMatch;
    sigmatch_table[DETECT_SAMEIP].Setup = DetectSameipSetup;
    sigmatch_table[DETECT_SAMEIP].Free = NULL;
    sigmatch_table[DETECT_SAMEIP].RegisterTests = DetectSameipRegisterTests;
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
static int DetectSameipMatch(ThreadVars *t, DetectEngineThreadCtx *det_ctx,
                             Packet *p, Signature *s, SigMatch *m)
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
static int DetectSameipSetup(DetectEngineCtx *de_ctx, Signature *s, char *optstr)
{
    SigMatch *sm = NULL;

    /* Get this into a SigMatch and put it in the Signature. */
    sm = SigMatchAlloc();
    if (sm == NULL)
        goto error;

    sm->type = DETECT_SAMEIP;
    sm->ctx = NULL;

    SigMatchAppendPacket(s, sm);

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
static int DetectSameipSigTest01Real(int mpm_type)
{
    uint8_t *buf = (uint8_t *)
                    "GET / HTTP/1.0\r\n"
                    "\r\n";
    uint16_t buflen = strlen((char *)buf);
    Packet p[2];
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx;
    int result = 0;

    memset(&th_v, 0, sizeof(th_v));

    /* First packet has same IPs */
    memset(&p[0], 0, sizeof(p[0]));
    p[0].src.family = AF_INET;
    p[0].dst.family = AF_INET;
    p[0].src.addr_data32[0] = 0x01020304;
    p[0].dst.addr_data32[0] = 0x01020304;
    p[0].payload = buf;
    p[0].payload_len = buflen;
    p[0].proto = IPPROTO_TCP;

    /* Second packet does not have same IPs */
    memset(&p[1], 0, sizeof(p[1]));
    p[1].src.family = AF_INET;
    p[1].dst.family = AF_INET;
    p[1].src.addr_data32[0] = 0x01020304;
    p[1].dst.addr_data32[0] = 0x04030201;
    p[1].payload = buf;
    p[1].payload_len = buflen;
    p[1].proto = IPPROTO_TCP;

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }

    de_ctx->mpm_matcher = mpm_type;
    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,
                                     "alert tcp any any -> any any "
                                     "(msg:\"Testing sameip\"; sameip; sid:1;)");
    if (de_ctx->sig_list == NULL) {
        goto end;
    }

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, &p[0]);
    if (PacketAlertCheck(&p[0], 1) == 0) {
        printf("sid 2 did not alert, but should have: ");
        goto cleanup;
    }

    SigMatchSignatures(&th_v, de_ctx, det_ctx, &p[1]);
    if (PacketAlertCheck(&p[1], 1) != 0) {
        printf("sid 2 alerted, but should not have: ");
        goto cleanup;
    }

    result = 1;

cleanup:
    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);

    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);

end:
    return result;
}

/**
 * \test DetectSameipSigTest01B2g tests sameip under B2g MPM
 */
static int DetectSameipSigTest01B2g(void)
{
    return DetectSameipSigTest01Real(MPM_B2G);
}

/**
 * \test DetectSameipSigTest01B2g tests sameip under B3g MPM
 */
static int DetectSameipSigTest01B3g(void)
{
    return DetectSameipSigTest01Real(MPM_B3G);
}

/**
 * \test DetectSameipSigTest01B2g tests sameip under WuManber MPM
 */
static int DetectSameipSigTest01Wm(void)
{
    return DetectSameipSigTest01Real(MPM_WUMANBER);
}

#endif /* UNITTESTS */

/**
 * \internal
 * \brief This function registers unit tests for DetectSameip
 */
static void DetectSameipRegisterTests(void)
{
#ifdef UNITTESTS
    UtRegisterTest("DetectSameipSigTest01B2g", DetectSameipSigTest01B2g, 1);
    UtRegisterTest("DetectSameipSigTest01B3g", DetectSameipSigTest01B3g, 1);
    UtRegisterTest("DetectSameipSigTest01Wm", DetectSameipSigTest01Wm, 1);
#endif /* UNITTESTS */
}
