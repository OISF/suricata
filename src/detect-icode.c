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
 * \author Gerardo Iglesias <iglesiasg@gmail.com>
 *
 * Implements icode keyword support
 */

#include "suricata-common.h"
#include "debug.h"
#include "decode.h"

#include "detect.h"
#include "detect-parse.h"
#include "detect-engine-prefilter-common.h"

#include "detect-icode.h"

#include "util-byte.h"
#include "util-unittest.h"
#include "util-unittest-helper.h"
#include "util-debug.h"

/**
 *\brief Regex for parsing our icode options
 */
#define PARSE_REGEX "^\\s*(<|>)?\\s*([0-9]+)\\s*(?:<>\\s*([0-9]+))?\\s*$"

static pcre *parse_regex;
static pcre_extra *parse_regex_study;

static int DetectICodeMatch(ThreadVars *, DetectEngineThreadCtx *, Packet *,
        const Signature *, const SigMatchCtx *);
static int DetectICodeSetup(DetectEngineCtx *, Signature *, const char *);
void DetectICodeRegisterTests(void);
void DetectICodeFree(void *);

static int PrefilterSetupICode(SigGroupHead *sgh);
static _Bool PrefilterICodeIsPrefilterable(const Signature *s);

/**
 * \brief Registration function for icode: keyword
 */
void DetectICodeRegister (void)
{
    sigmatch_table[DETECT_ICODE].name = "icode";
    sigmatch_table[DETECT_ICODE].desc = "match on specific ICMP id-value";
    sigmatch_table[DETECT_ICODE].url = DOC_URL DOC_VERSION "/rules/header-keywords.html#icode";
    sigmatch_table[DETECT_ICODE].Match = DetectICodeMatch;
    sigmatch_table[DETECT_ICODE].Setup = DetectICodeSetup;
    sigmatch_table[DETECT_ICODE].Free = DetectICodeFree;
    sigmatch_table[DETECT_ICODE].RegisterTests = DetectICodeRegisterTests;

    sigmatch_table[DETECT_ICODE].SupportsPrefilter = PrefilterICodeIsPrefilterable;
    sigmatch_table[DETECT_ICODE].SetupPrefilter = PrefilterSetupICode;

    DetectSetupParseRegexes(PARSE_REGEX, &parse_regex, &parse_regex_study);
}

#define DETECT_ICODE_EQ   PREFILTER_U8HASH_MODE_EQ   /**< "equal" operator */
#define DETECT_ICODE_LT   PREFILTER_U8HASH_MODE_LT   /**< "less than" operator */
#define DETECT_ICODE_GT   PREFILTER_U8HASH_MODE_GT   /**< "greater than" operator */
#define DETECT_ICODE_RN   PREFILTER_U8HASH_MODE_RA   /**< "range" operator */

typedef struct DetectICodeData_ {
    uint8_t code1;
    uint8_t code2;

    uint8_t mode;
} DetectICodeData;

static inline int ICodeMatch(const uint8_t pcode, const uint8_t mode,
                             const uint8_t dcode1, const uint8_t dcode2)
{
    switch (mode) {
        case DETECT_ICODE_EQ:
            return (pcode == dcode1) ? 1 : 0;

        case DETECT_ICODE_LT:
            return (pcode < dcode1) ? 1 : 0;

        case DETECT_ICODE_GT:
            return (pcode > dcode1) ? 1 : 0;

        case DETECT_ICODE_RN:
            return (pcode > dcode1 && pcode < dcode2) ? 1 : 0;
    }
    return 0;
}

/**
 * \brief This function is used to match icode rule option set on a packet with those passed via icode:
 *
 * \param t pointer to thread vars
 * \param det_ctx pointer to the pattern matcher thread
 * \param p pointer to the current packet
 * \param m pointer to the sigmatch that we will cast into DetectICodeData
 *
 * \retval 0 no match
 * \retval 1 match
 */
static int DetectICodeMatch (ThreadVars *t, DetectEngineThreadCtx *det_ctx, Packet *p,
        const Signature *s, const SigMatchCtx *ctx)
{
    if (PKT_IS_PSEUDOPKT(p))
        return 0;

    uint8_t picode;
    if (PKT_IS_ICMPV4(p)) {
        picode = ICMPV4_GET_CODE(p);
    } else if (PKT_IS_ICMPV6(p)) {
        picode = ICMPV6_GET_CODE(p);
    } else {
        /* Packet not ICMPv4 nor ICMPv6 */
        return 0;
    }

    const DetectICodeData *icd = (const DetectICodeData *)ctx;
    return ICodeMatch(picode, icd->mode, icd->code1, icd->code2);
}

/**
 * \brief This function is used to parse icode options passed via icode: keyword
 *
 * \param icodestr Pointer to the user provided icode options
 *
 * \retval icd pointer to DetectICodeData on success
 * \retval NULL on failure
 */
static DetectICodeData *DetectICodeParse(const char *icodestr)
{
    DetectICodeData *icd = NULL;
    char *args[3] = {NULL, NULL, NULL};
#define MAX_SUBSTRINGS 30
    int ret = 0, res = 0;
    int ov[MAX_SUBSTRINGS];

    ret = pcre_exec(parse_regex, parse_regex_study, icodestr, strlen(icodestr), 0, 0, ov, MAX_SUBSTRINGS);
    if (ret < 1 || ret > 4) {
        SCLogError(SC_ERR_PCRE_MATCH, "pcre_exec parse error, ret %" PRId32 ", string %s", ret, icodestr);
        goto error;
    }

    int i;
    const char *str_ptr;
    for (i = 1; i < ret; i++) {
        res = pcre_get_substring((char *)icodestr, ov, MAX_SUBSTRINGS, i, &str_ptr);
        if (res < 0) {
            SCLogError(SC_ERR_PCRE_GET_SUBSTRING, "pcre_get_substring failed");
            goto error;
        }
        args[i-1] = (char *)str_ptr;
    }

    icd = SCMalloc(sizeof(DetectICodeData));
    if (unlikely(icd == NULL))
        goto error;
    icd->code1 = 0;
    icd->code2 = 0;
    icd->mode = 0;

    /* we have either "<" or ">" */
    if (args[0] != NULL && strlen(args[0]) != 0) {
        /* we have a third part ("<> y"), therefore it's invalid */
        if (args[2] != NULL) {
            SCLogError(SC_ERR_INVALID_VALUE, "icode: invalid value");
            goto error;
        }
        /* we have only a comparison ("<", ">") */
        if (ByteExtractStringUint8(&icd->code1, 10, 0, args[1]) < 0) {
            SCLogError(SC_ERR_INVALID_ARGUMENT, "specified icmp code %s is not "
                                        "valid", args[1]);
            goto error;
        }
        if ((strcmp(args[0], ">")) == 0) icd->mode = DETECT_ICODE_GT;
        else icd->mode = DETECT_ICODE_LT;
    } else { /* no "<", ">" */
        /* we have a range ("<>") */
        if (args[2] != NULL) {
            icd->mode = (uint8_t) DETECT_ICODE_RN;
            if (ByteExtractStringUint8(&icd->code1, 10, 0, args[1]) < 0) {
                SCLogError(SC_ERR_INVALID_ARGUMENT, "specified icmp code %s is not "
                                            "valid", args[1]);
                goto error;
            }
            if (ByteExtractStringUint8(&icd->code2, 10, 0, args[2]) < 0) {
                SCLogError(SC_ERR_INVALID_ARGUMENT, "specified icmp code %s is not "
                                            "valid", args[2]);
                goto error;
            }
            /* we check that the first given value in the range is less than
               the second, otherwise we swap them */
            if (icd->code1 > icd->code2) {
                uint8_t temp = icd->code1;
                icd->code1 = icd->code2;
                icd->code2 = temp;
            }
        } else { /* we have an equality */
            icd->mode = DETECT_ICODE_EQ;
            if (ByteExtractStringUint8(&icd->code1, 10, 0, args[1]) < 0) {
                SCLogError(SC_ERR_INVALID_ARGUMENT, "specified icmp code %s is not "
                                                    "valid", args[1]);
                goto error;
            }
        }
    }

    for (i = 0; i < (ret-1); i++) {
        if (args[i] != NULL)
            SCFree(args[i]);
    }
    return icd;

error:
    for (i = 0; i < (ret-1) && i < 3; i++) {
        if (args[i] != NULL)
            SCFree(args[i]);
    }
    if (icd != NULL)
        DetectICodeFree(icd);
    return NULL;
}

/**
 * \brief this function is used to add the parsed icode data into the current signature
 *
 * \param de_ctx pointer to the Detection Engine Context
 * \param s pointer to the Current Signature
 * \param icodestr pointer to the user provided icode options
 *
 * \retval 0 on Success
 * \retval -1 on Failure
 */
static int DetectICodeSetup(DetectEngineCtx *de_ctx, Signature *s, const char *icodestr)
{

    DetectICodeData *icd = NULL;
    SigMatch *sm = NULL;

    icd = DetectICodeParse(icodestr);
    if (icd == NULL) goto error;

    sm = SigMatchAlloc();
    if (sm == NULL) goto error;

    sm->type = DETECT_ICODE;
    sm->ctx = (SigMatchCtx *)icd;

    SigMatchAppendSMToList(s, sm, DETECT_SM_LIST_MATCH);
    s->flags |= SIG_FLAG_REQUIRE_PACKET;

    return 0;

error:
    if (icd != NULL) DetectICodeFree(icd);
    if (sm != NULL) SCFree(sm);
    return -1;
}

/**
 * \brief this function will free memory associated with DetectICodeData
 *
 * \param ptr pointer to DetectICodeData
 */
void DetectICodeFree(void *ptr)
{
    DetectICodeData *icd = (DetectICodeData *)ptr;
    SCFree(icd);
}

/* prefilter code */

static void PrefilterPacketICodeMatch(DetectEngineThreadCtx *det_ctx,
        Packet *p, const void *pectx)
{
    if (PKT_IS_PSEUDOPKT(p)) {
        SCReturn;
    }

    uint8_t picode;
    if (PKT_IS_ICMPV4(p)) {
        picode = ICMPV4_GET_CODE(p);
    } else if (PKT_IS_ICMPV6(p)) {
        picode = ICMPV6_GET_CODE(p);
    } else {
        /* Packet not ICMPv4 nor ICMPv6 */
        return;
    }

    const PrefilterPacketU8HashCtx *h = pectx;
    const SigsArray *sa = h->array[picode];
    if (sa) {
        PrefilterAddSids(&det_ctx->pmq, sa->sigs, sa->cnt);
    }
}

static void
PrefilterPacketICodeSet(PrefilterPacketHeaderValue *v, void *smctx)
{
    const DetectICodeData *a = smctx;
    v->u8[0] = a->mode;
    v->u8[1] = a->code1;
    v->u8[2] = a->code2;
}

static _Bool
PrefilterPacketICodeCompare(PrefilterPacketHeaderValue v, void *smctx)
{
    const DetectICodeData *a = smctx;
    if (v.u8[0] == a->mode &&
        v.u8[1] == a->code1 &&
        v.u8[2] == a->code2)
        return TRUE;
    return FALSE;
}

static int PrefilterSetupICode(SigGroupHead *sgh)
{
    return PrefilterSetupPacketHeaderU8Hash(sgh, DETECT_ICODE,
            PrefilterPacketICodeSet,
            PrefilterPacketICodeCompare,
            PrefilterPacketICodeMatch);
}

static _Bool PrefilterICodeIsPrefilterable(const Signature *s)
{
    const SigMatch *sm;
    for (sm = s->init_data->smlists[DETECT_SM_LIST_MATCH] ; sm != NULL; sm = sm->next) {
        switch (sm->type) {
            case DETECT_ICODE:
                return TRUE;
        }
    }
    return FALSE;
}

#ifdef UNITTESTS
#include "detect-engine.h"
#include "detect-engine-mpm.h"

/**
 * \test DetectICodeParseTest01 is a test for setting a valid icode value
 */
static int DetectICodeParseTest01(void)
{
    DetectICodeData *icd = NULL;
    int result = 0;
    icd = DetectICodeParse("8");
    if (icd != NULL) {
        if (icd->code1 == 8 && icd->mode == DETECT_ICODE_EQ)
            result = 1;
        DetectICodeFree(icd);
    }
    return result;
}

/**
 * \test DetectICodeParseTest02 is a test for setting a valid icode value
 *       with ">" operator
 */
static int DetectICodeParseTest02(void)
{
    DetectICodeData *icd = NULL;
    int result = 0;
    icd = DetectICodeParse(">8");
    if (icd != NULL) {
        if (icd->code1 == 8 && icd->mode == DETECT_ICODE_GT)
            result = 1;
        DetectICodeFree(icd);
    }
    return result;
}

/**
 * \test DetectICodeParseTest03 is a test for setting a valid icode value
 *       with "<" operator
 */
static int DetectICodeParseTest03(void)
{
    DetectICodeData *icd = NULL;
    int result = 0;
    icd = DetectICodeParse("<8");
    if (icd != NULL) {
        if (icd->code1 == 8 && icd->mode == DETECT_ICODE_LT)
            result = 1;
        DetectICodeFree(icd);
    }
    return result;
}

/**
 * \test DetectICodeParseTest04 is a test for setting a valid icode value
 *       with "<>" operator
 */
static int DetectICodeParseTest04(void)
{
    DetectICodeData *icd = NULL;
    int result = 0;
    icd = DetectICodeParse("8<>20");
    if (icd != NULL) {
        if (icd->code1 == 8 && icd->code2 == 20 && icd->mode == DETECT_ICODE_RN)
            result = 1;
        DetectICodeFree(icd);
    }
    return result;
}

/**
 * \test DetectICodeParseTest05 is a test for setting a valid icode value
 *       with spaces all around
 */
static int DetectICodeParseTest05(void)
{
    DetectICodeData *icd = NULL;
    int result = 0;
    icd = DetectICodeParse("  8 ");
    if (icd != NULL) {
        if (icd->code1 == 8 && icd->mode == DETECT_ICODE_EQ)
            result = 1;
        DetectICodeFree(icd);
    }
    return result;
}

/**
 * \test DetectICodeParseTest06 is a test for setting a valid icode value
 *       with ">" operator and spaces all around
 */
static int DetectICodeParseTest06(void)
{
    DetectICodeData *icd = NULL;
    int result = 0;
    icd = DetectICodeParse("  >  8 ");
    if (icd != NULL) {
        if (icd->code1 == 8 && icd->mode == DETECT_ICODE_GT)
            result = 1;
        DetectICodeFree(icd);
    }
    return result;
}

/**
 * \test DetectICodeParseTest07 is a test for setting a valid icode value
 *       with "<>" operator and spaces all around
 */
static int DetectICodeParseTest07(void)
{
    DetectICodeData *icd = NULL;
    int result = 0;
    icd = DetectICodeParse("  8  <>  20 ");
    if (icd != NULL) {
        if (icd->code1 == 8 && icd->code2 == 20 && icd->mode == DETECT_ICODE_RN)
            result = 1;
        DetectICodeFree(icd);
    }
    return result;
}

/**
 * \test DetectICodeParseTest08 is a test for setting an invalid icode value
 */
static int DetectICodeParseTest08(void)
{
    DetectICodeData *icd = NULL;
    icd = DetectICodeParse("> 8 <> 20");
    if (icd == NULL)
        return 1;
    DetectICodeFree(icd);
    return 0;
}

/**
 * \test DetectICodeMatchTest01 is a test for checking the working of icode
 *       keyword by creating 5 rules and matching a crafted packet against
 *       them. 4 out of 5 rules shall trigger.
 */
static int DetectICodeMatchTest01(void)
{

    Packet *p = NULL;
    Signature *s = NULL;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx;
    int result = 0;

    memset(&th_v, 0, sizeof(th_v));

    p = UTHBuildPacket(NULL, 0, IPPROTO_ICMP);

    p->icmpv4h->code = 10;

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }

    de_ctx->flags |= DE_QUIET;

    s = de_ctx->sig_list = SigInit(de_ctx,"alert icmp any any -> any any (icode:10; sid:1;)");
    if (s == NULL) {
        goto end;
    }

    s = s->next = SigInit(de_ctx,"alert icmp any any -> any any (icode:<15; sid:2;)");
    if (s == NULL) {
        goto end;
    }

    s = s->next = SigInit(de_ctx,"alert icmp any any -> any any (icode:>20; sid:3;)");
    if (s == NULL) {
        goto end;
    }

    s = s->next = SigInit(de_ctx,"alert icmp any any -> any any (icode:8<>20; sid:4;)");
    if (s == NULL) {
        goto end;
    }

    s = s->next = SigInit(de_ctx,"alert icmp any any -> any any (icode:20<>8; sid:5;)");
    if (s == NULL) {
        goto end;
    }

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    if (PacketAlertCheck(p, 1) == 0) {
        SCLogDebug("sid 1 did not alert, but should have");
        goto cleanup;
    } else if (PacketAlertCheck(p, 2) == 0) {
        SCLogDebug("sid 2 did not alert, but should have");
        goto cleanup;
    } else if (PacketAlertCheck(p, 3)) {
        SCLogDebug("sid 3 alerted, but should not have");
        goto cleanup;
    } else if (PacketAlertCheck(p, 4) == 0) {
        SCLogDebug("sid 4 did not alert, but should have");
        goto cleanup;
    } else if (PacketAlertCheck(p, 5) == 0) {
        SCLogDebug("sid 5 did not alert, but should have");
        goto cleanup;
    }

    result = 1;

cleanup:
    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);

    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);

    UTHFreePackets(&p, 1);
end:
    return result;
}

#endif /* UNITTESTS */

/**
 * \brief this function registers unit tests for DetectICode
 */
void DetectICodeRegisterTests(void)
{
#ifdef UNITTESTS
    UtRegisterTest("DetectICodeParseTest01", DetectICodeParseTest01);
    UtRegisterTest("DetectICodeParseTest02", DetectICodeParseTest02);
    UtRegisterTest("DetectICodeParseTest03", DetectICodeParseTest03);
    UtRegisterTest("DetectICodeParseTest04", DetectICodeParseTest04);
    UtRegisterTest("DetectICodeParseTest05", DetectICodeParseTest05);
    UtRegisterTest("DetectICodeParseTest06", DetectICodeParseTest06);
    UtRegisterTest("DetectICodeParseTest07", DetectICodeParseTest07);
    UtRegisterTest("DetectICodeParseTest08", DetectICodeParseTest08);
    UtRegisterTest("DetectICodeMatchTest01", DetectICodeMatchTest01);
#endif /* UNITTESTS */
}
