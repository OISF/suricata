/* Copyright (C) 2007-2020 Open Information Security Foundation
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
 * Implements itype keyword support
 */

#include "suricata-common.h"
#include "debug.h"
#include "decode.h"

#include "detect.h"
#include "detect-parse.h"
#include "detect-engine-prefilter-common.h"
#include "detect-engine-build.h"

#include "detect-itype.h"

#include "util-byte.h"
#include "util-unittest.h"
#include "util-unittest-helper.h"
#include "util-debug.h"

/**
 *\brief Regex for parsing our itype options
 */
#define PARSE_REGEX "^\\s*(<|>)?\\s*([0-9]+)\\s*(?:<>\\s*([0-9]+))?\\s*$"

static DetectParseRegex parse_regex;

static int DetectITypeMatch(DetectEngineThreadCtx *, Packet *,
        const Signature *, const SigMatchCtx *);
static int DetectITypeSetup(DetectEngineCtx *, Signature *, const char *);
#ifdef UNITTESTS
static void DetectITypeRegisterTests(void);
#endif
void DetectITypeFree(DetectEngineCtx *, void *);

static int PrefilterSetupIType(DetectEngineCtx *de_ctx, SigGroupHead *sgh);
static bool PrefilterITypeIsPrefilterable(const Signature *s);

/**
 * \brief Registration function for itype: keyword
 */
void DetectITypeRegister (void)
{
    sigmatch_table[DETECT_ITYPE].name = "itype";
    sigmatch_table[DETECT_ITYPE].desc = "match on a specific ICMP type";
    sigmatch_table[DETECT_ITYPE].url = "/rules/header-keywords.html#itype";
    sigmatch_table[DETECT_ITYPE].Match = DetectITypeMatch;
    sigmatch_table[DETECT_ITYPE].Setup = DetectITypeSetup;
    sigmatch_table[DETECT_ITYPE].Free = DetectITypeFree;
#ifdef UNITTESTS
    sigmatch_table[DETECT_ITYPE].RegisterTests = DetectITypeRegisterTests;
#endif
    sigmatch_table[DETECT_ITYPE].SupportsPrefilter = PrefilterITypeIsPrefilterable;
    sigmatch_table[DETECT_ITYPE].SetupPrefilter = PrefilterSetupIType;

    DetectSetupParseRegexes(PARSE_REGEX, &parse_regex);
}

#define DETECT_ITYPE_EQ   PREFILTER_U8HASH_MODE_EQ   /**< "equal" operator */
#define DETECT_ITYPE_LT   PREFILTER_U8HASH_MODE_LT   /**< "less than" operator */
#define DETECT_ITYPE_GT   PREFILTER_U8HASH_MODE_GT   /**< "greater than" operator */
#define DETECT_ITYPE_RN   PREFILTER_U8HASH_MODE_RA   /**< "range" operator */

typedef struct DetectITypeData_ {
    uint8_t type1;
    uint8_t type2;

    uint8_t mode;
} DetectITypeData;

static inline int ITypeMatch(const uint8_t ptype, const uint8_t mode,
                             const uint8_t dtype1, const uint8_t dtype2)
{
    switch (mode) {
        case DETECT_ITYPE_EQ:
            return (ptype == dtype1) ? 1 : 0;

        case DETECT_ITYPE_LT:
            return (ptype < dtype1) ? 1 : 0;

        case DETECT_ITYPE_GT:
            return (ptype > dtype1) ? 1 : 0;

        case DETECT_ITYPE_RN:
            return (ptype > dtype1 && ptype < dtype2) ? 1 : 0;
    }
    return 0;
}

/**
 * \brief This function is used to match itype rule option set on a packet with those passed via itype:
 *
 * \param t pointer to thread vars
 * \param det_ctx pointer to the pattern matcher thread
 * \param p pointer to the current packet
 * \param m pointer to the sigmatch that we will cast into DetectITypeData
 *
 * \retval 0 no match
 * \retval 1 match
 */
static int DetectITypeMatch (DetectEngineThreadCtx *det_ctx, Packet *p,
        const Signature *s, const SigMatchCtx *ctx)
{
    if (PKT_IS_PSEUDOPKT(p))
        return 0;

    uint8_t pitype;
    if (PKT_IS_ICMPV4(p)) {
        pitype = ICMPV4_GET_TYPE(p);
    } else if (PKT_IS_ICMPV6(p)) {
        pitype = ICMPV6_GET_TYPE(p);
    } else {
        /* Packet not ICMPv4 nor ICMPv6 */
        return 0;
    }

    const DetectITypeData *itd = (const DetectITypeData *)ctx;
    return ITypeMatch(pitype, itd->mode, itd->type1, itd->type2);
}

/**
 * \brief This function is used to parse itype options passed via itype: keyword
 *
 * \param de_ctx Pointer to the detection engine context
 * \param itypestr Pointer to the user provided itype options
 *
 * \retval itd pointer to DetectITypeData on success
 * \retval NULL on failure
 */
static DetectITypeData *DetectITypeParse(DetectEngineCtx *de_ctx, const char *itypestr)
{
    DetectITypeData *itd = NULL;
    char *args[3] = {NULL, NULL, NULL};
    int ret = 0, res = 0;
    size_t pcre2_len;

    ret = DetectParsePcreExec(&parse_regex, itypestr, 0, 0);
    if (ret < 1 || ret > 4) {
        SCLogError(SC_ERR_PCRE_MATCH, "pcre_exec parse error, ret %" PRId32 ", string %s", ret, itypestr);
        goto error;
    }

    int i;
    const char *str_ptr;
    for (i = 1; i < ret; i++) {
        res = SC_Pcre2SubstringGet(parse_regex.match, i, (PCRE2_UCHAR8 **)&str_ptr, &pcre2_len);
        if (res < 0) {
            SCLogError(SC_ERR_PCRE_GET_SUBSTRING, "pcre2_substring_get_bynumber failed");
            goto error;
        }
        args[i-1] = (char *)str_ptr;
    }

    itd = SCMalloc(sizeof(DetectITypeData));
    if (unlikely(itd == NULL))
        goto error;
    itd->type1 = 0;
    itd->type2 = 0;
    itd->mode = 0;

    /* we have either "<" or ">" */
    if (args[0] != NULL && strlen(args[0]) != 0) {
        /* we have a third part ("<> y"), therefore it's invalid */
        if (args[2] != NULL) {
            SCLogError(SC_ERR_INVALID_VALUE, "itype: invalid value");
            goto error;
        }
        /* we have only a comparison ("<", ">") */
        if (StringParseUint8(&itd->type1, 10, 0, args[1]) < 0) {
            SCLogError(SC_ERR_INVALID_ARGUMENT, "specified icmp type %s is not "
                                                "valid", args[1]);
            goto error;
        }
        if ((strcmp(args[0], ">")) == 0) {
            if (itd->type1 == 255) {
                SCLogError(SC_ERR_INVALID_ARGUMENT,
                        "specified icmp type >%s is not "
                        "valid",
                        args[1]);
                goto error;
            }
            itd->mode = DETECT_ITYPE_GT;
        } else {
            if (itd->type1 == 0) {
                SCLogError(SC_ERR_INVALID_ARGUMENT,
                        "specified icmp type <%s is not "
                        "valid",
                        args[1]);
                goto error;
            }
            itd->mode = DETECT_ITYPE_LT;
        }
    } else { /* no "<", ">" */
        /* we have a range ("<>") */
        if (args[2] != NULL) {
            itd->mode = (uint8_t) DETECT_ITYPE_RN;
            if (StringParseUint8(&itd->type1, 10, 0, args[1]) < 0) {
                SCLogError(SC_ERR_INVALID_ARGUMENT, "specified icmp type %s is not "
                                                    "valid", args[1]);
                goto error;
            }
            if (StringParseUint8(&itd->type2, 10, 0, args[2]) < 0) {
                SCLogError(SC_ERR_INVALID_ARGUMENT, "specified icmp type %s is not "
                                                    "valid", args[2]);
                goto error;
            }
            /* we check that the first given value in the range is less than
               the second, otherwise we swap them */
            if (itd->type1 > itd->type2) {
                uint8_t temp = itd->type1;
                itd->type1 = itd->type2;
                itd->type2 = temp;
            }
        } else { /* we have an equality */
            itd->mode = DETECT_ITYPE_EQ;
            if (StringParseUint8(&itd->type1, 10, 0, args[1]) < 0) {
                SCLogError(SC_ERR_INVALID_ARGUMENT, "specified icmp type %s is not "
                                                    "valid", args[1]);
                goto error;
            }
        }
    }

    for (i = 0; i < (ret-1); i++) {
        if (args[i] != NULL)
            pcre2_substring_free((PCRE2_UCHAR8 *)args[i]);
    }
    return itd;

error:
    for (i = 0; i < (ret-1) && i < 3; i++) {
        if (args[i] != NULL)
            pcre2_substring_free((PCRE2_UCHAR8 *)args[i]);
    }
    if (itd != NULL)
        DetectITypeFree(de_ctx, itd);
    return NULL;
}

/**
 * \brief this function is used to add the parsed itype data into the current signature
 *
 * \param de_ctx pointer to the Detection Engine Context
 * \param s pointer to the Current Signature
 * \param itypestr pointer to the user provided itype options
 *
 * \retval 0 on Success
 * \retval -1 on Failure
 */
static int DetectITypeSetup(DetectEngineCtx *de_ctx, Signature *s, const char *itypestr)
{

    DetectITypeData *itd = NULL;
    SigMatch *sm = NULL;

    itd = DetectITypeParse(de_ctx, itypestr);
    if (itd == NULL) goto error;

    sm = SigMatchAlloc();
    if (sm == NULL) goto error;

    sm->type = DETECT_ITYPE;
    sm->ctx = (SigMatchCtx *)itd;

    SigMatchAppendSMToList(s, sm, DETECT_SM_LIST_MATCH);
    s->flags |= SIG_FLAG_REQUIRE_PACKET;

    return 0;

error:
    if (itd != NULL) DetectITypeFree(de_ctx, itd);
    if (sm != NULL) SCFree(sm);
    return -1;
}

/**
 * \brief this function will free memory associated with DetectITypeData
 *
 * \param ptr pointer to DetectITypeData
 */
void DetectITypeFree(DetectEngineCtx *de_ctx, void *ptr)
{
    DetectITypeData *itd = (DetectITypeData *)ptr;
    SCFree(itd);
}

/* prefilter code
 *
 * Prefilter uses the U8Hash logic, where we setup a 256 entry array
 * for each ICMP type. Each array element has the list of signatures
 * that need to be inspected. */

static void PrefilterPacketITypeMatch(DetectEngineThreadCtx *det_ctx,
        Packet *p, const void *pectx)
{
    if (PKT_IS_PSEUDOPKT(p)) {
        SCReturn;
    }

    uint8_t pitype;
    if (PKT_IS_ICMPV4(p)) {
        pitype = ICMPV4_GET_TYPE(p);
    } else if (PKT_IS_ICMPV6(p)) {
        pitype = ICMPV6_GET_TYPE(p);
    } else {
        /* Packet not ICMPv4 nor ICMPv6 */
        return;
    }

    const PrefilterPacketU8HashCtx *h = pectx;
    const SigsArray *sa = h->array[pitype];
    if (sa) {
        PrefilterAddSids(&det_ctx->pmq, sa->sigs, sa->cnt);
    }
}

static void
PrefilterPacketITypeSet(PrefilterPacketHeaderValue *v, void *smctx)
{
    const DetectITypeData *a = smctx;
    v->u8[0] = a->mode;
    v->u8[1] = a->type1;
    v->u8[2] = a->type2;
}

static bool
PrefilterPacketITypeCompare(PrefilterPacketHeaderValue v, void *smctx)
{
    const DetectITypeData *a = smctx;
    if (v.u8[0] == a->mode &&
        v.u8[1] == a->type1 &&
        v.u8[2] == a->type2)
        return true;
    return false;
}

static int PrefilterSetupIType(DetectEngineCtx *de_ctx, SigGroupHead *sgh)
{
    return PrefilterSetupPacketHeaderU8Hash(de_ctx, sgh, DETECT_ITYPE,
            PrefilterPacketITypeSet,
            PrefilterPacketITypeCompare,
            PrefilterPacketITypeMatch);
}

static bool PrefilterITypeIsPrefilterable(const Signature *s)
{
    const SigMatch *sm;
    for (sm = s->init_data->smlists[DETECT_SM_LIST_MATCH] ; sm != NULL; sm = sm->next) {
        switch (sm->type) {
            case DETECT_ITYPE:
                return true;
        }
    }
    return false;
}

#ifdef UNITTESTS

#include "detect-engine.h"
#include "detect-engine-mpm.h"

/**
 * \test DetectITypeParseTest01 is a test for setting a valid itype value
 */
static int DetectITypeParseTest01(void)
{
    DetectITypeData *itd = NULL;
    int result = 0;
    itd = DetectITypeParse(NULL, "8");
    if (itd != NULL) {
        if (itd->type1 == 8 && itd->mode == DETECT_ITYPE_EQ)
            result = 1;
        DetectITypeFree(NULL, itd);
    }
    return result;
}

/**
 * \test DetectITypeParseTest02 is a test for setting a valid itype value
 *       with ">" operator
 */
static int DetectITypeParseTest02(void)
{
DetectITypeData *itd = NULL;
    int result = 0;
    itd = DetectITypeParse(NULL, ">8");
    if (itd != NULL) {
        if (itd->type1 == 8 && itd->mode == DETECT_ITYPE_GT)
            result = 1;
        DetectITypeFree(NULL, itd);
    }
    return result;
}

/**
 * \test DetectITypeParseTest03 is a test for setting a valid itype value
 *       with "<" operator
 */
static int DetectITypeParseTest03(void)
{
    DetectITypeData *itd = NULL;
    int result = 0;
    itd = DetectITypeParse(NULL, "<8");
    if (itd != NULL) {
        if (itd->type1 == 8 && itd->mode == DETECT_ITYPE_LT)
            result = 1;
        DetectITypeFree(NULL, itd);
    }
    return result;
}

/**
 * \test DetectITypeParseTest04 is a test for setting a valid itype value
 *       with "<>" operator
 */
static int DetectITypeParseTest04(void)
{
DetectITypeData *itd = NULL;
    int result = 0;
    itd = DetectITypeParse(NULL, "8<>20");
    if (itd != NULL) {
        if (itd->type1 == 8 && itd->type2 == 20 && itd->mode == DETECT_ITYPE_RN)
            result = 1;
        DetectITypeFree(NULL, itd);
    }
    return result;
}

/**
 * \test DetectITypeParseTest05 is a test for setting a valid itype value
 *       with spaces all around
 */
static int DetectITypeParseTest05(void)
{
DetectITypeData *itd = NULL;
    int result = 0;
    itd = DetectITypeParse(NULL, "   8 ");
    if (itd != NULL) {
        if (itd->type1 == 8 && itd->mode == DETECT_ITYPE_EQ)
            result = 1;
        DetectITypeFree(NULL, itd);
    }
    return result;
}

/**
 * \test DetectITypeParseTest06 is a test for setting a valid itype value
 *       with ">" operator and spaces all around
 */
static int DetectITypeParseTest06(void)
{
DetectITypeData *itd = NULL;
    int result = 0;
    itd = DetectITypeParse(NULL, "  >  8  ");
    if (itd != NULL) {
        if (itd->type1 == 8 && itd->mode == DETECT_ITYPE_GT)
            result = 1;
        DetectITypeFree(NULL, itd);
    }
    return result;
}

/**
 * \test DetectITypeParseTest07 is a test for setting a valid itype value
 *       with "<>" operator and spaces all around
 */
static int DetectITypeParseTest07(void)
{
DetectITypeData *itd = NULL;
    int result = 0;
    itd = DetectITypeParse(NULL, "  8  <> 20  ");
    if (itd != NULL) {
        if (itd->type1 == 8 && itd->type2 == 20 && itd->mode == DETECT_ITYPE_RN)
            result = 1;
        DetectITypeFree(NULL, itd);
    }
    return result;
}

/**
 * \test DetectITypeParseTest08 is a test for setting an invalid itype value
 */
static int DetectITypeParseTest08(void)
{
    DetectITypeData *itd = NULL;
    itd = DetectITypeParse(NULL, "> 8 <> 20");
    if (itd == NULL)
        return 1;
    DetectITypeFree(NULL, itd);
    return 0;
}

/**
 * \test DetectITypeMatchTest01 is a test for checking the working of itype
 *       keyword by creating 5 rules and matching a crafted packet against
 *       them. 4 out of 5 rules shall trigger.
 */
static int DetectITypeMatchTest01(void)
{

    Packet *p = NULL;
    Signature *s = NULL;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx;
    int result = 0;

    memset(&th_v, 0, sizeof(th_v));

    p = UTHBuildPacket(NULL, 0, IPPROTO_ICMP);
    p->icmpv4h->type = 10;

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }

    de_ctx->flags |= DE_QUIET;

    s = de_ctx->sig_list = SigInit(de_ctx,"alert icmp any any -> any any (itype:10; sid:1;)");
    if (s == NULL) {
        goto end;
    }

    s = s->next = SigInit(de_ctx,"alert icmp any any -> any any (itype:<15; sid:2;)");
    if (s == NULL) {
        goto end;
    }

    s = s->next = SigInit(de_ctx,"alert icmp any any -> any any (itype:>20; sid:3;)");
    if (s == NULL) {
        goto end;
    }

    s = s->next = SigInit(de_ctx,"alert icmp any any -> any any (itype:8<>20; sid:4;)");
    if (s == NULL) {
        goto end;
    }

    s = s->next = SigInit(de_ctx,"alert icmp any any -> any any (itype:20<>8; sid:5;)");
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

/**
 * \brief this function registers unit tests for DetectIType
 */
void DetectITypeRegisterTests(void)
{
    UtRegisterTest("DetectITypeParseTest01", DetectITypeParseTest01);
    UtRegisterTest("DetectITypeParseTest02", DetectITypeParseTest02);
    UtRegisterTest("DetectITypeParseTest03", DetectITypeParseTest03);
    UtRegisterTest("DetectITypeParseTest04", DetectITypeParseTest04);
    UtRegisterTest("DetectITypeParseTest05", DetectITypeParseTest05);
    UtRegisterTest("DetectITypeParseTest06", DetectITypeParseTest06);
    UtRegisterTest("DetectITypeParseTest07", DetectITypeParseTest07);
    UtRegisterTest("DetectITypeParseTest08", DetectITypeParseTest08);
    UtRegisterTest("DetectITypeMatchTest01", DetectITypeMatchTest01);
}
#endif /* UNITTESTS */
