
/* Copyright (C) 2007-2018 Open Information Security Foundation
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

#include "../detect-engine.h"
#include "../util-unittest.h"

/**
 * \test DetectTtlParseTest01 is a test for setting up an valid ttl value.
 */

static int DetectTtlParseTest01 (void)
{
    DetectTtlData *ttld = DetectTtlParse("10");
    FAIL_IF_NULL(ttld);
    FAIL_IF_NOT(ttld->ttl1 == 10);
    FAIL_IF_NOT(ttld->mode == DETECT_TTL_EQ);
    DetectTtlFree(ttld);
    PASS;
}

/**
 * \test DetectTtlParseTest02 is a test for setting up an valid ttl value with
 *       "<" operator.
 */

static int DetectTtlParseTest02 (void)
{
    DetectTtlData *ttld = DetectTtlParse("<10");
    FAIL_IF_NULL(ttld);
    FAIL_IF_NOT(ttld->ttl1 == 10);
    FAIL_IF_NOT(ttld->mode == DETECT_TTL_LT);
    DetectTtlFree(ttld);
    PASS;
}

/**
 * \test DetectTtlParseTest03 is a test for setting up an valid ttl values with
 *       "-" operator.
 */

static int DetectTtlParseTest03 (void)
{
    DetectTtlData *ttld = DetectTtlParse("1-2");
    FAIL_IF_NULL(ttld);
    FAIL_IF_NOT(ttld->ttl1 == 1);
    FAIL_IF_NOT(ttld->ttl2 == 2);
    FAIL_IF_NOT(ttld->mode == DETECT_TTL_RA);
    DetectTtlFree(ttld);
    PASS;
}

/**
 * \test DetectTtlParseTest04 is a test for setting up an valid ttl value with
 *       ">" operator and include spaces arround the given values.
 */

static int DetectTtlParseTest04 (void)
{
    DetectTtlData *ttld = DetectTtlParse(" > 10 ");
    FAIL_IF_NULL(ttld);
    FAIL_IF_NOT(ttld->ttl1 == 10);
    FAIL_IF_NOT(ttld->mode == DETECT_TTL_GT);
    DetectTtlFree(ttld);
    PASS;
}

/**
 * \test DetectTtlParseTest05 is a test for setting up an valid ttl values with
 *       "-" operator and include spaces arround the given values.
 */

static int DetectTtlParseTest05 (void)
{
    DetectTtlData *ttld = DetectTtlParse(" 1 - 2 ");
    FAIL_IF_NULL(ttld);
    FAIL_IF_NOT(ttld->ttl1 == 1);
    FAIL_IF_NOT(ttld->ttl2 == 2);
    FAIL_IF_NOT(ttld->mode == DETECT_TTL_RA);
    DetectTtlFree(ttld);
    PASS;
}

/**
 * \test DetectTtlParseTest06 is a test for setting up an valid ttl values with
 *       invalid "=" operator and include spaces arround the given values.
 */

static int DetectTtlParseTest06 (void)
{
    DetectTtlData *ttld = DetectTtlParse(" 1 = 2 ");
    FAIL_IF_NOT_NULL(ttld);
    PASS;
}

/**
 * \test DetectTtlParseTest07 is a test for setting up an valid ttl values with
 *       invalid "<>" operator and include spaces arround the given values.
 */

static int DetectTtlParseTest07 (void)
{
    DetectTtlData *ttld = DetectTtlParse(" 1<>2 ");
    FAIL_IF_NOT_NULL(ttld);
    PASS;
}

/**
 * \test DetectTtlSetupTest01 is a test for setting up an valid ttl values with
 *       valid "-" operator and include spaces arround the given values. In the
 *       test the values are setup with initializing the detection engine context
 *       setting up the signature itself.
 */

static int DetectTtlSetupTest01(void)
{
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    de_ctx->flags |= DE_QUIET;

    Signature *s = DetectEngineAppendSig(de_ctx,
            "alert ip any any -> any any (msg:\"with in ttl limit\"; ttl:1 - 2; sid:1;)");
    FAIL_IF_NULL(s);
    SigGroupBuild(de_ctx);
    FAIL_IF_NULL(s->sm_arrays[DETECT_SM_LIST_MATCH]);
    FAIL_IF_NULL(s->sm_arrays[DETECT_SM_LIST_MATCH]->ctx);
    DetectTtlData *ttld = (DetectTtlData *)s->sm_arrays[DETECT_SM_LIST_MATCH]->ctx;

    FAIL_IF_NOT(ttld->ttl1 == 1);
    FAIL_IF_NOT(ttld->ttl2 == 2);
    FAIL_IF_NOT(ttld->mode == DETECT_TTL_RA);
    DetectEngineCtxFree(de_ctx);
    PASS;
}

/**
 * \test DetectTtlTestSig01 is a test for checking the working of ttl keyword
 *       by setting up the signature and later testing its working by matching
 *       the received packet against the sig.
 */

static int DetectTtlTestSig1(void)
{
    Packet *p = PacketGetFromAlloc();
    FAIL_IF_NULL(p);
    Signature *s = NULL;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx;
    IPV4Hdr ip4h;

    memset(&th_v, 0, sizeof(th_v));
    memset(&ip4h, 0, sizeof(ip4h));

    p->src.family = AF_INET;
    p->dst.family = AF_INET;
    p->proto = IPPROTO_TCP;
    ip4h.ip_ttl = 15;
    p->ip4h = &ip4h;

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    de_ctx->flags |= DE_QUIET;

    s = DetectEngineAppendSig(de_ctx,"alert ip any any -> any any (msg:\"with in ttl limit\"; ttl: >16; sid:1;)");
    FAIL_IF_NULL(s);

    s = DetectEngineAppendSig(de_ctx,"alert ip any any -> any any (msg:\"Less than 17\"; ttl: <17; sid:2;)");
    FAIL_IF_NULL(s);

    s = DetectEngineAppendSig(de_ctx,"alert ip any any -> any any (msg:\"Greater than 5\"; ttl:15; sid:3;)");
    FAIL_IF_NULL(s);

    s = DetectEngineAppendSig(de_ctx,"alert ip any any -> any any (msg:\"Equals tcp\"; ttl: 1-30; sid:4;)");
    FAIL_IF_NULL(s);

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    FAIL_IF(PacketAlertCheck(p, 1));
    FAIL_IF_NOT(PacketAlertCheck(p, 2));
    FAIL_IF_NOT(PacketAlertCheck(p, 3));
    FAIL_IF_NOT(PacketAlertCheck(p, 4));

    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);

    SCFree(p);
    PASS;
}

/**
 * \brief this function registers unit tests for DetectTtl
 */
void DetectTtlRegisterTests(void)
{
    UtRegisterTest("DetectTtlParseTest01", DetectTtlParseTest01);
    UtRegisterTest("DetectTtlParseTest02", DetectTtlParseTest02);
    UtRegisterTest("DetectTtlParseTest03", DetectTtlParseTest03);
    UtRegisterTest("DetectTtlParseTest04", DetectTtlParseTest04);
    UtRegisterTest("DetectTtlParseTest05", DetectTtlParseTest05);
    UtRegisterTest("DetectTtlParseTest06", DetectTtlParseTest06);
    UtRegisterTest("DetectTtlParseTest07", DetectTtlParseTest07);
    UtRegisterTest("DetectTtlSetupTest01", DetectTtlSetupTest01);
    UtRegisterTest("DetectTtlTestSig1", DetectTtlTestSig1);
}
