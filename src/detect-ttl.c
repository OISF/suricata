/* Copyright (C) 2007-2013 Open Information Security Foundation
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
 * \author Gurvinder Singh <gurvindersighdahiya@gmail.com>
 *
 * Implements the ttl keyword
 */

#include "suricata-common.h"
#include "stream-tcp.h"
#include "util-unittest.h"

#include "detect.h"
#include "detect-parse.h"
#include "detect-engine-prefilter-common.h"

#include "detect-ttl.h"
#include "util-debug.h"

/**
 * \brief Regex for parsing our flow options
 */
#define PARSE_REGEX  "^\\s*([0-9]*)?\\s*([<>=-]+)?\\s*([0-9]+)?\\s*$"

static pcre *parse_regex;
static pcre_extra *parse_regex_study;

/*prototypes*/
static int DetectTtlMatch (ThreadVars *, DetectEngineThreadCtx *, Packet *,
        const Signature *, const SigMatchCtx *);
static int DetectTtlSetup (DetectEngineCtx *, Signature *, const char *);
void DetectTtlFree (void *);
void DetectTtlRegisterTests (void);

static int PrefilterSetupTtl(SigGroupHead *sgh);
static _Bool PrefilterTtlIsPrefilterable(const Signature *s);

/**
 * \brief Registration function for ttl: keyword
 */

void DetectTtlRegister(void)
{
    sigmatch_table[DETECT_TTL].name = "ttl";
    sigmatch_table[DETECT_TTL].desc = "check for a specific IP time-to-live value";
    sigmatch_table[DETECT_TTL].url = DOC_URL DOC_VERSION "/rules/header-keywords.html#ttl";
    sigmatch_table[DETECT_TTL].Match = DetectTtlMatch;
    sigmatch_table[DETECT_TTL].Setup = DetectTtlSetup;
    sigmatch_table[DETECT_TTL].Free = DetectTtlFree;
    sigmatch_table[DETECT_TTL].RegisterTests = DetectTtlRegisterTests;

    sigmatch_table[DETECT_TTL].SupportsPrefilter = PrefilterTtlIsPrefilterable;
    sigmatch_table[DETECT_TTL].SetupPrefilter = PrefilterSetupTtl;

    DetectSetupParseRegexes(PARSE_REGEX, &parse_regex, &parse_regex_study);
    return;
}

static inline int TtlMatch(const uint8_t pttl, const uint8_t mode,
                           const uint8_t dttl1, const uint8_t dttl2)
{
    if (mode == DETECT_TTL_EQ && pttl == dttl1)
        return 1;
    else if (mode == DETECT_TTL_LT && pttl < dttl1)
        return 1;
    else if (mode == DETECT_TTL_GT && pttl > dttl1)
        return 1;
    else if (mode == DETECT_TTL_RA && (pttl > dttl1 && pttl < dttl2))
        return 1;

    return 0;

}

/**
 * \brief This function is used to match TTL rule option on a packet with those passed via ttl:
 *
 * \param t pointer to thread vars
 * \param det_ctx pointer to the pattern matcher thread
 * \param p pointer to the current packet
 * \param m pointer to the sigmatch that we will cast into DetectTtlData
 *
 * \retval 0 no match
 * \retval 1 match
 */
static int DetectTtlMatch (ThreadVars *t, DetectEngineThreadCtx *det_ctx, Packet *p,
        const Signature *s, const SigMatchCtx *ctx)
{

    if (PKT_IS_PSEUDOPKT(p))
        return 0;

    uint8_t pttl;
    if (PKT_IS_IPV4(p)) {
        pttl = IPV4_GET_IPTTL(p);
    } else if (PKT_IS_IPV6(p)) {
        pttl = IPV6_GET_HLIM(p);
    } else {
        SCLogDebug("Packet is of not IPv4 or IPv6");
        return 0;
    }

    const DetectTtlData *ttld = (const DetectTtlData *)ctx;
    return TtlMatch(pttl, ttld->mode, ttld->ttl1, ttld->ttl2);
}

/**
 * \brief This function is used to parse ttl options passed via ttl: keyword
 *
 * \param ttlstr Pointer to the user provided ttl options
 *
 * \retval ttld pointer to DetectTtlData on success
 * \retval NULL on failure
 */

static DetectTtlData *DetectTtlParse (const char *ttlstr)
{
    DetectTtlData *ttld = NULL;
    char *arg1 = NULL;
    char *arg2 = NULL;
    char *arg3 = NULL;
#define MAX_SUBSTRINGS 30
    int ret = 0, res = 0;
    int ov[MAX_SUBSTRINGS];

    ret = pcre_exec(parse_regex, parse_regex_study, ttlstr, strlen(ttlstr), 0, 0, ov, MAX_SUBSTRINGS);
    if (ret < 2 || ret > 4) {
        SCLogError(SC_ERR_PCRE_MATCH, "parse error, ret %" PRId32 "", ret);
        goto error;
    }
    const char *str_ptr;

    res = pcre_get_substring((char *) ttlstr, ov, MAX_SUBSTRINGS, 1, &str_ptr);
    if (res < 0) {
        SCLogError(SC_ERR_PCRE_GET_SUBSTRING, "pcre_get_substring failed");
        goto error;
    }
    arg1 = (char *) str_ptr;
    SCLogDebug("Arg1 \"%s\"", arg1);

    if (ret >= 3) {
        res = pcre_get_substring((char *) ttlstr, ov, MAX_SUBSTRINGS, 2, &str_ptr);
        if (res < 0) {
            SCLogError(SC_ERR_PCRE_GET_SUBSTRING, "pcre_get_substring failed");
            goto error;
        }
        arg2 = (char *) str_ptr;
        SCLogDebug("Arg2 \"%s\"", arg2);

        if (ret >= 4) {
            res = pcre_get_substring((char *) ttlstr, ov, MAX_SUBSTRINGS, 3, &str_ptr);
            if (res < 0) {
                SCLogError(SC_ERR_PCRE_GET_SUBSTRING, "pcre_get_substring failed");
                goto error;
            }
            arg3 = (char *) str_ptr;
            SCLogDebug("Arg3 \"%s\"", arg3);
        }
    }

    ttld = SCMalloc(sizeof (DetectTtlData));
    if (unlikely(ttld == NULL))
        goto error;
    ttld->ttl1 = 0;
    ttld->ttl2 = 0;

    if (arg2 != NULL) {
        /*set the values*/
        switch(arg2[0]) {
            case '<':
                if (arg3 == NULL)
                    goto error;

                ttld->mode = DETECT_TTL_LT;
                ttld->ttl1 = (uint8_t) atoi(arg3);

                SCLogDebug("ttl is %"PRIu8"",ttld->ttl1);
                if (strlen(arg1) > 0)
                    goto error;

                break;
            case '>':
                if (arg3 == NULL)
                    goto error;

                ttld->mode = DETECT_TTL_GT;
                ttld->ttl1 = (uint8_t) atoi(arg3);

                SCLogDebug("ttl is %"PRIu8"",ttld->ttl1);
                if (strlen(arg1) > 0)
                    goto error;

                break;
            case '-':
                if (arg1 == NULL || strlen(arg1)== 0)
                    goto error;
                if (arg3 == NULL || strlen(arg3)== 0)
                    goto error;

                ttld->mode = DETECT_TTL_RA;
                ttld->ttl1 = (uint8_t) atoi(arg1);

                ttld->ttl2 = (uint8_t) atoi(arg3);
                SCLogDebug("ttl is %"PRIu8" to %"PRIu8"",ttld->ttl1, ttld->ttl2);
                if (ttld->ttl1 >= ttld->ttl2) {
                    SCLogError(SC_ERR_INVALID_SIGNATURE, "Invalid ttl range. ");
                    goto error;
                }
                break;
            default:
                ttld->mode = DETECT_TTL_EQ;

                if ((arg2 != NULL && strlen(arg2) > 0) ||
                    (arg3 != NULL && strlen(arg3) > 0) ||
                    (arg1 == NULL ||strlen(arg1) == 0))
                    goto error;

                ttld->ttl1 = (uint8_t) atoi(arg1);
                break;
        }
    } else {
        ttld->mode = DETECT_TTL_EQ;

        if ((arg3 != NULL && strlen(arg3) > 0) ||
            (arg1 == NULL ||strlen(arg1) == 0))
            goto error;

        ttld->ttl1 = (uint8_t) atoi(arg1);
    }

    SCFree(arg1);
    SCFree(arg2);
    SCFree(arg3);
    return ttld;

error:
    if (ttld)
        SCFree(ttld);
    if (arg1)
        SCFree(arg1);
    if (arg2)
        SCFree(arg2);
    if (arg3)
        SCFree(arg3);
    return NULL;
}

/**
 * \brief this function is used to attld the parsed ttl data into the current signature
 *
 * \param de_ctx pointer to the Detection Engine Context
 * \param s pointer to the Current Signature
 * \param ttlstr pointer to the user provided ttl options
 *
 * \retval 0 on Success
 * \retval -1 on Failure
 */
static int DetectTtlSetup (DetectEngineCtx *de_ctx, Signature *s, const char *ttlstr)
{
    DetectTtlData *ttld = NULL;
    SigMatch *sm = NULL;

    ttld = DetectTtlParse(ttlstr);
    if (ttld == NULL)
        goto error;

    sm = SigMatchAlloc();
    if (sm == NULL)
        goto error;

    sm->type = DETECT_TTL;
    sm->ctx = (SigMatchCtx *)ttld;

    SigMatchAppendSMToList(s, sm, DETECT_SM_LIST_MATCH);
    s->flags |= SIG_FLAG_REQUIRE_PACKET;

    return 0;

error:
    if (ttld != NULL) DetectTtlFree(ttld);
    if (sm != NULL) SCFree(sm);
    return -1;
}

/**
 * \brief this function will free memory associated with DetectTtlData
 *
 * \param ptr pointer to DetectTtlData
 */
void DetectTtlFree(void *ptr)
{
    DetectTtlData *ttld = (DetectTtlData *)ptr;
    SCFree(ttld);
}

/* prefilter code */

static void
PrefilterPacketTtlMatch(DetectEngineThreadCtx *det_ctx, Packet *p, const void *pectx)
{
    if (PKT_IS_PSEUDOPKT(p)) {
        SCReturn;
    }

    uint8_t pttl;
    if (PKT_IS_IPV4(p)) {
        pttl = IPV4_GET_IPTTL(p);
    } else if (PKT_IS_IPV6(p)) {
        pttl = IPV6_GET_HLIM(p);
    } else {
        SCLogDebug("Packet is of not IPv4 or IPv6");
        return;
    }

    const PrefilterPacketHeaderCtx *ctx = pectx;
    if (PrefilterPacketHeaderExtraMatch(ctx, p) == FALSE)
        return;

    if (TtlMatch(pttl, ctx->v1.u8[0], ctx->v1.u8[1], ctx->v1.u8[2]))
    {
        SCLogDebug("packet matches ttl/hl %u", pttl);
        PrefilterAddSids(&det_ctx->pmq, ctx->sigs_array, ctx->sigs_cnt);
    }
}

static void
PrefilterPacketTtlSet(PrefilterPacketHeaderValue *v, void *smctx)
{
    const DetectTtlData *a = smctx;
    v->u8[0] = a->mode;
    v->u8[1] = a->ttl1;
    v->u8[2] = a->ttl2;
}

static _Bool
PrefilterPacketTtlCompare(PrefilterPacketHeaderValue v, void *smctx)
{
    const DetectTtlData *a = smctx;
    if (v.u8[0] == a->mode &&
        v.u8[1] == a->ttl1 &&
        v.u8[2] == a->ttl2)
        return TRUE;
    return FALSE;
}

static int PrefilterSetupTtl(SigGroupHead *sgh)
{
    return PrefilterSetupPacketHeader(sgh, DETECT_TTL,
            PrefilterPacketTtlSet,
            PrefilterPacketTtlCompare,
            PrefilterPacketTtlMatch);
}

static _Bool PrefilterTtlIsPrefilterable(const Signature *s)
{
    const SigMatch *sm;
    for (sm = s->init_data->smlists[DETECT_SM_LIST_MATCH] ; sm != NULL; sm = sm->next) {
        switch (sm->type) {
            case DETECT_TTL:
                return TRUE;
        }
    }
    return FALSE;
}

#ifdef UNITTESTS
#include "detect-engine.h"
#include "detect-engine-mpm.h"

/**
 * \brief this function is used to initialize the detection engine context and
 *        setup the signature with passed values.
 *
 */

static int DetectTtlInitTest(DetectEngineCtx **de_ctx, Signature **sig, DetectTtlData **ttld, const char *str)
{
    char fullstr[1024];
    int result = 0;

    *de_ctx = NULL;
    *sig = NULL;

    if (snprintf(fullstr, 1024, "alert ip any any -> any any (msg:\"Ttl test\"; ttl:%s; sid:1;)", str) >= 1024) {
        goto end;
    }

    *de_ctx = DetectEngineCtxInit();
    if (*de_ctx == NULL) {
        goto end;
    }

    (*de_ctx)->flags |= DE_QUIET;

    (*de_ctx)->sig_list = SigInit(*de_ctx, fullstr);
    if ((*de_ctx)->sig_list == NULL) {
        goto end;
    }

    *sig = (*de_ctx)->sig_list;

    *ttld = DetectTtlParse(str);

    result = 1;

end:
    return result;
}

/**
 * \test DetectTtlParseTest01 is a test for setting up an valid ttl value.
 */

static int DetectTtlParseTest01 (void)
{
    DetectTtlData *ttld = NULL;
    uint8_t res = 0;

    ttld = DetectTtlParse("10");
    if (ttld != NULL) {
        if (ttld->ttl1 == 10 && ttld->mode == DETECT_TTL_EQ)
            res = 1;

        DetectTtlFree(ttld);
    }

    return res;
}

/**
 * \test DetectTtlParseTest02 is a test for setting up an valid ttl value with
 *       "<" operator.
 */

static int DetectTtlParseTest02 (void)
{
    DetectTtlData *ttld = NULL;
    uint8_t res = 0;
    ttld = DetectTtlParse("<10");
    if (ttld != NULL) {
        if (ttld->ttl1 == 10 && ttld->mode == DETECT_TTL_LT)
            res = 1;
        DetectTtlFree(ttld);
    }

    return res;
}

/**
 * \test DetectTtlParseTest03 is a test for setting up an valid ttl values with
 *       "-" operator.
 */

static int DetectTtlParseTest03 (void)
{
    DetectTtlData *ttld = NULL;
    uint8_t res = 0;
    ttld = DetectTtlParse("1-2");
    if (ttld != NULL) {
        if (ttld->ttl1 == 1 && ttld->ttl2 == 2 && ttld->mode == DETECT_TTL_RA)
            res = 1;
        DetectTtlFree(ttld);
    }

    return res;
}

/**
 * \test DetectTtlParseTest04 is a test for setting up an valid ttl value with
 *       ">" operator and include spaces arround the given values.
 */

static int DetectTtlParseTest04 (void)
{
    DetectTtlData *ttld = NULL;
    uint8_t res = 0;

    ttld = DetectTtlParse(" > 10 ");
    if (ttld != NULL) {
        if (ttld->ttl1 == 10 && ttld->mode == DETECT_TTL_GT)
            res = 1;

        DetectTtlFree(ttld);
    }

    return res;
}

/**
 * \test DetectTtlParseTest05 is a test for setting up an valid ttl values with
 *       "-" operator and include spaces arround the given values.
 */

static int DetectTtlParseTest05 (void)
{
    DetectTtlData *ttld = NULL;
    uint8_t res = 0;

    ttld = DetectTtlParse(" 1 - 2 ");
    if (ttld != NULL) {
        if (ttld->ttl1 == 1 && ttld->ttl2 == 2 && ttld->mode == DETECT_TTL_RA)
            res = 1;
        DetectTtlFree(ttld);
    }

    return res;
}

/**
 * \test DetectTtlParseTest06 is a test for setting up an valid ttl values with
 *       invalid "=" operator and include spaces arround the given values.
 */

static int DetectTtlParseTest06 (void)
{
    DetectTtlData *ttld = NULL;
    uint8_t res = 0;

    ttld = DetectTtlParse(" 1 = 2 ");
    if (ttld == NULL)
        res = 1;
    if (ttld) SCFree(ttld);

    return res;
}

/**
 * \test DetectTtlParseTest07 is a test for setting up an valid ttl values with
 *       invalid "<>" operator and include spaces arround the given values.
 */

static int DetectTtlParseTest07 (void)
{
    DetectTtlData *ttld = NULL;
    uint8_t res = 0;

    ttld = DetectTtlParse(" 1<>2 ");
    if (ttld == NULL)
        res = 1;

    if (ttld) SCFree(ttld);

    return res;
}

/**
 * \test DetectTtlSetpTest01 is a test for setting up an valid ttl values with
 *       valid "-" operator and include spaces arround the given values. In the
 *       test the values are setup with initializing the detection engine context
 *       setting up the signature itself.
 */

static int DetectTtlSetpTest01(void)
{

    DetectTtlData *ttld = NULL;
    uint8_t res = 0;
    Signature *sig = NULL;
    DetectEngineCtx *de_ctx = NULL;

    res = DetectTtlInitTest(&de_ctx, &sig, &ttld, "1 - 2 ");
    if (res == 0) {
        goto end;
    }

    if(ttld == NULL)
        goto cleanup;

    if (ttld != NULL) {
        if (ttld->ttl1 == 1 && ttld->ttl2 == 2 && ttld->mode == DETECT_TTL_RA)
            res = 1;
    }

cleanup:
    if (ttld) SCFree(ttld);
    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
end:
    return res;
}

/**
 * \test DetectTtlTestSig01 is a test for checking the working of ttl keyword
 *       by setting up the signature and later testing its working by matching
 *       the received packet against the sig.
 */

static int DetectTtlTestSig1(void)
{

    Packet *p = PacketGetFromAlloc();
    if (unlikely(p == NULL))
        return 0;
    Signature *s = NULL;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx;
    int result = 0;
    IPV4Hdr ip4h;

    memset(&th_v, 0, sizeof(th_v));
    memset(&ip4h, 0, sizeof(ip4h));

    p->src.family = AF_INET;
    p->dst.family = AF_INET;
    p->proto = IPPROTO_TCP;
    ip4h.ip_ttl = 15;
    p->ip4h = &ip4h;

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }

    de_ctx->flags |= DE_QUIET;

    s = de_ctx->sig_list = SigInit(de_ctx,"alert ip any any -> any any (msg:\"with in ttl limit\"; ttl: >16; sid:1;)");
    if (s == NULL) {
        goto end;
    }

    s = s->next = SigInit(de_ctx,"alert ip any any -> any any (msg:\"Less than 17\"; ttl: <17; sid:2;)");
    if (s == NULL) {
        goto end;
    }

    s = s->next = SigInit(de_ctx,"alert ip any any -> any any (msg:\"Greater than 5\"; ttl:15; sid:3;)");
    if (s == NULL) {
        goto end;
    }

    s = s->next = SigInit(de_ctx,"alert ip any any -> any any (msg:\"Equals tcp\"; ttl: 1-30; sid:4;)");
    if (s == NULL) {
        goto end;
    }

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    if (PacketAlertCheck(p, 1)) {
        printf("sid 1 alerted, but should not have: ");
        goto cleanup;
    } else if (PacketAlertCheck(p, 2) == 0) {
        printf("sid 2 did not alert, but should have: ");
        goto cleanup;
    } else if (PacketAlertCheck(p, 3) == 0) {
        printf("sid 3 did not alert, but should have: ");
        goto cleanup;
    } else if (PacketAlertCheck(p, 4) == 0) {
        printf("sid 4 did not alert, but should have: ");
        goto cleanup;
    }

    result = 1;

cleanup:
    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);

    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);

end:
    SCFree(p);
    return result;
}

#endif /* UNITTESTS */

/**
 * \brief this function registers unit tests for DetectTtl
 */
void DetectTtlRegisterTests(void)
{
#ifdef UNITTESTS
    UtRegisterTest("DetectTtlParseTest01", DetectTtlParseTest01);
    UtRegisterTest("DetectTtlParseTest02", DetectTtlParseTest02);
    UtRegisterTest("DetectTtlParseTest03", DetectTtlParseTest03);
    UtRegisterTest("DetectTtlParseTest04", DetectTtlParseTest04);
    UtRegisterTest("DetectTtlParseTest05", DetectTtlParseTest05);
    UtRegisterTest("DetectTtlParseTest06", DetectTtlParseTest06);
    UtRegisterTest("DetectTtlParseTest07", DetectTtlParseTest07);
    UtRegisterTest("DetectTtlSetpTest01", DetectTtlSetpTest01);
    UtRegisterTest("DetectTtlTestSig1", DetectTtlTestSig1);
#endif /* UNITTESTS */
}
