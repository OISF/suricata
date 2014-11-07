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
 * \author Gerardo Iglesias <iglesiasg@gmail.com>
 *
 * Implements itype keyword support
 */

#include "suricata-common.h"
#include "debug.h"
#include "decode.h"

#include "detect.h"
#include "detect-parse.h"

#include "detect-itype.h"

#include "util-byte.h"
#include "util-unittest.h"
#include "util-unittest-helper.h"
#include "util-debug.h"

/**
 *\brief Regex for parsing our itype options
 */
#define PARSE_REGEX "^\\s*(<|>)?\\s*([0-9]+)\\s*(?:<>\\s*([0-9]+))?\\s*$"

static pcre *parse_regex;
static pcre_extra *parse_regex_study;

int DetectITypeMatch(ThreadVars *, DetectEngineThreadCtx *, Packet *, Signature *, const SigMatchCtx *);
static int DetectITypeSetup(DetectEngineCtx *, Signature *, char *);
void DetectITypeRegisterTests(void);
void DetectITypeFree(void *);


/**
 * \brief Registration function for itype: keyword
 */
void DetectITypeRegister (void)
{
    sigmatch_table[DETECT_ITYPE].name = "itype";
    sigmatch_table[DETECT_ITYPE].desc = "matching on a specific ICMP type";
    sigmatch_table[DETECT_ITYPE].url = "https://redmine.openinfosecfoundation.org/projects/suricata/wiki/Header_keywords#itype";
    sigmatch_table[DETECT_ITYPE].Match = DetectITypeMatch;
    sigmatch_table[DETECT_ITYPE].Setup = DetectITypeSetup;
    sigmatch_table[DETECT_ITYPE].Free = DetectITypeFree;
    sigmatch_table[DETECT_ITYPE].RegisterTests = DetectITypeRegisterTests;

    const char *eb;
    int eo;
    int opts = 0;

    parse_regex = pcre_compile(PARSE_REGEX, opts, &eb, &eo, NULL);
    if(parse_regex == NULL)
    {
        SCLogError(SC_ERR_PCRE_COMPILE, "pcre compile of \"%s\" failed at offset %" PRId32 ": %s", PARSE_REGEX, eo, eb);
        goto error;
    }

    parse_regex_study = pcre_study(parse_regex, 0, &eb);
    if(eb != NULL)
    {
        SCLogError(SC_ERR_PCRE_STUDY, "pcre study failed: %s", eb);
        goto error;
    }
    return;

error:
    return;
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
int DetectITypeMatch (ThreadVars *t, DetectEngineThreadCtx *det_ctx, Packet *p, Signature *s, const SigMatchCtx *ctx)
{
    int ret = 0;
    uint8_t pitype;
    const DetectITypeData *itd = (const DetectITypeData *)ctx;

    if (PKT_IS_PSEUDOPKT(p))
        return 0;

    if (PKT_IS_ICMPV4(p)) {
        pitype = ICMPV4_GET_TYPE(p);
    } else if (PKT_IS_ICMPV6(p)) {
        pitype = ICMPV6_GET_TYPE(p);
    } else {
        /* Packet not ICMPv4 nor ICMPv6 */
        return ret;
    }

    switch(itd->mode) {
        case DETECT_ITYPE_EQ:
            ret = (pitype == itd->type1) ? 1 : 0;
            break;
        case DETECT_ITYPE_LT:
            ret = (pitype < itd->type1) ? 1 : 0;
            break;
        case DETECT_ITYPE_GT:
            ret = (pitype > itd->type1) ? 1 : 0;
            break;
        case DETECT_ITYPE_RN:
            ret = (pitype > itd->type1 && pitype < itd->type2) ? 1 : 0;
            break;
    }

    return ret;
}

/**
 * \brief This function is used to parse itype options passed via itype: keyword
 *
 * \param itypestr Pointer to the user provided itype options
 *
 * \retval itd pointer to DetectITypeData on success
 * \retval NULL on failure
 */
DetectITypeData *DetectITypeParse(char *itypestr)
{
    DetectITypeData *itd = NULL;
    char *args[3] = {NULL, NULL, NULL};
#define MAX_SUBSTRINGS 30
    int ret = 0, res = 0;
    int ov[MAX_SUBSTRINGS];

    ret = pcre_exec(parse_regex, parse_regex_study, itypestr, strlen(itypestr), 0, 0, ov, MAX_SUBSTRINGS);
    if (ret < 1 || ret > 4) {
        SCLogError(SC_ERR_PCRE_MATCH, "pcre_exec parse error, ret %" PRId32 ", string %s", ret, itypestr);
        goto error;
    }

    int i;
    const char *str_ptr;
    for (i = 1; i < ret; i++) {
        res = pcre_get_substring((char *)itypestr, ov, MAX_SUBSTRINGS, i, &str_ptr);
        if (res < 0) {
            SCLogError(SC_ERR_PCRE_GET_SUBSTRING, "pcre_get_substring failed");
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
        if (ByteExtractStringUint8(&itd->type1, 10, 0, args[1]) < 0) {
            SCLogError(SC_ERR_INVALID_ARGUMENT, "specified icmp type %s is not "
                                                "valid", args[1]);
            goto error;
        }
        if ((strcmp(args[0], ">")) == 0) itd->mode = DETECT_ITYPE_GT;
        else itd->mode = DETECT_ITYPE_LT;
    } else { /* no "<", ">" */
        /* we have a range ("<>") */
        if (args[2] != NULL) {
            itd->mode = (uint8_t) DETECT_ITYPE_RN;
            if (ByteExtractStringUint8(&itd->type1, 10, 0, args[1]) < 0) {
                SCLogError(SC_ERR_INVALID_ARGUMENT, "specified icmp type %s is not "
                                                    "valid", args[1]);
                goto error;
            }
            if (ByteExtractStringUint8(&itd->type2, 10, 0, args[2]) < 0) {
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
            if (ByteExtractStringUint8(&itd->type1, 10, 0, args[1]) < 0) {
                SCLogError(SC_ERR_INVALID_ARGUMENT, "specified icmp type %s is not "
                                                    "valid", args[1]);
                goto error;
            }
        }
    }

    for (i = 0; i < (ret-1); i++) {
        if (args[i] != NULL)
            SCFree(args[i]);
    }
    return itd;

error:
    for (i = 0; i < (ret-1) && i < 3; i++) {
        if (args[i] != NULL)
            SCFree(args[i]);
    }
    if (itd != NULL)
        DetectITypeFree(itd);
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
static int DetectITypeSetup(DetectEngineCtx *de_ctx, Signature *s, char *itypestr)
{

    DetectITypeData *itd = NULL;
    SigMatch *sm = NULL;

    itd = DetectITypeParse(itypestr);
    if (itd == NULL) goto error;

    sm = SigMatchAlloc();
    if (sm == NULL) goto error;

    sm->type = DETECT_ITYPE;
    sm->ctx = (SigMatchCtx *)itd;

    SigMatchAppendSMToList(s, sm, DETECT_SM_LIST_MATCH);
    s->flags |= SIG_FLAG_REQUIRE_PACKET;

    return 0;

error:
    if (itd != NULL) DetectITypeFree(itd);
    if (sm != NULL) SCFree(sm);
    return -1;
}

/**
 * \brief this function will free memory associated with DetectITypeData
 *
 * \param ptr pointer to DetectITypeData
 */
void DetectITypeFree(void *ptr)
{
    DetectITypeData *itd = (DetectITypeData *)ptr;
    SCFree(itd);
}

#ifdef UNITTESTS

#include "detect-parse.h"
#include "detect-engine.h"
#include "detect-engine-mpm.h"

/**
 * \test DetectITypeParseTest01 is a test for setting a valid itype value
 */
int DetectITypeParseTest01(void)
{
    DetectITypeData *itd = NULL;
    int result = 0;
    itd = DetectITypeParse("8");
    if (itd != NULL) {
        if (itd->type1 == 8 && itd->mode == DETECT_ITYPE_EQ)
            result = 1;
        DetectITypeFree(itd);
    }
    return result;
}

/**
 * \test DetectITypeParseTest02 is a test for setting a valid itype value
 *       with ">" operator
 */
int DetectITypeParseTest02(void)
{
DetectITypeData *itd = NULL;
    int result = 0;
    itd = DetectITypeParse(">8");
    if (itd != NULL) {
        if (itd->type1 == 8 && itd->mode == DETECT_ITYPE_GT)
            result = 1;
        DetectITypeFree(itd);
    }
    return result;
}

/**
 * \test DetectITypeParseTest03 is a test for setting a valid itype value
 *       with "<" operator
 */
int DetectITypeParseTest03(void)
{
    DetectITypeData *itd = NULL;
    int result = 0;
    itd = DetectITypeParse("<8");
    if (itd != NULL) {
        if (itd->type1 == 8 && itd->mode == DETECT_ITYPE_LT)
            result = 1;
        DetectITypeFree(itd);
    }
    return result;
}

/**
 * \test DetectITypeParseTest04 is a test for setting a valid itype value
 *       with "<>" operator
 */
int DetectITypeParseTest04(void)
{
DetectITypeData *itd = NULL;
    int result = 0;
    itd = DetectITypeParse("8<>20");
    if (itd != NULL) {
        if (itd->type1 == 8 && itd->type2 == 20 && itd->mode == DETECT_ITYPE_RN)
            result = 1;
        DetectITypeFree(itd);
    }
    return result;
}

/**
 * \test DetectITypeParseTest05 is a test for setting a valid itype value
 *       with spaces all around
 */
int DetectITypeParseTest05(void)
{
DetectITypeData *itd = NULL;
    int result = 0;
    itd = DetectITypeParse("   8 ");
    if (itd != NULL) {
        if (itd->type1 == 8 && itd->mode == DETECT_ITYPE_EQ)
            result = 1;
        DetectITypeFree(itd);
    }
    return result;
}

/**
 * \test DetectITypeParseTest06 is a test for setting a valid itype value
 *       with ">" operator and spaces all around
 */
int DetectITypeParseTest06(void)
{
DetectITypeData *itd = NULL;
    int result = 0;
    itd = DetectITypeParse("  >  8  ");
    if (itd != NULL) {
        if (itd->type1 == 8 && itd->mode == DETECT_ITYPE_GT)
            result = 1;
        DetectITypeFree(itd);
    }
    return result;
}

/**
 * \test DetectITypeParseTest07 is a test for setting a valid itype value
 *       with "<>" operator and spaces all around
 */
int DetectITypeParseTest07(void)
{
DetectITypeData *itd = NULL;
    int result = 0;
    itd = DetectITypeParse("  8  <> 20  ");
    if (itd != NULL) {
        if (itd->type1 == 8 && itd->type2 == 20 && itd->mode == DETECT_ITYPE_RN)
            result = 1;
        DetectITypeFree(itd);
    }
    return result;
}

/**
 * \test DetectITypeParseTest08 is a test for setting an invalid itype value
 */
int DetectITypeParseTest08(void)
{
    DetectITypeData *itd = NULL;
    itd = DetectITypeParse("> 8 <> 20");
    if (itd == NULL)
        return 1;
    DetectITypeFree(itd);
    return 0;
}

/**
 * \test DetectITypeMatchTest01 is a test for checking the working of itype
 *       keyword by creating 5 rules and matching a crafted packet against
 *       them. 4 out of 5 rules shall trigger.
 */
int DetectITypeMatchTest01(void)
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


#endif /* UNITTESTS */

/**
 * \brief this function registers unit tests for DetectIType
 */
void DetectITypeRegisterTests(void)
{
#ifdef UNITTESTS
    UtRegisterTest("DetectITypeParseTest01", DetectITypeParseTest01, 1);
    UtRegisterTest("DetectITypeParseTest02", DetectITypeParseTest02, 1);
    UtRegisterTest("DetectITypeParseTest03", DetectITypeParseTest03, 1);
    UtRegisterTest("DetectITypeParseTest04", DetectITypeParseTest04, 1);
    UtRegisterTest("DetectITypeParseTest05", DetectITypeParseTest05, 1);
    UtRegisterTest("DetectITypeParseTest06", DetectITypeParseTest06, 1);
    UtRegisterTest("DetectITypeParseTest07", DetectITypeParseTest07, 1);
    UtRegisterTest("DetectITypeParseTest08", DetectITypeParseTest08, 1);
    UtRegisterTest("DetectITypeMatchTest01", DetectITypeMatchTest01, 1);
#endif /* UNITTESTS */
}
