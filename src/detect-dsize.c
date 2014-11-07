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
 * \author Victor Julien <victor@inliniac.net>
 *
 * Implements the dsize keyword
 */

#include "suricata-common.h"
#include "decode.h"

#include "detect.h"
#include "detect-parse.h"

#include "flow-var.h"

#include "detect-dsize.h"

#include "util-unittest.h"
#include "util-debug.h"
#include "util-byte.h"

#include "pkt-var.h"
#include "host.h"
#include "util-profiling.h"

/**
 *  dsize:[<>]<0-65535>[<><0-65535>];
 */
#define PARSE_REGEX "^\\s*(<|>)?\\s*([0-9]{1,5})\\s*(?:(<>)\\s*([0-9]{1,5}))?\\s*$"
static pcre *parse_regex;
static pcre_extra *parse_regex_study;

int DetectDsizeMatch (ThreadVars *, DetectEngineThreadCtx *, Packet *, Signature *, const SigMatchCtx *);
static int DetectDsizeSetup (DetectEngineCtx *, Signature *s, char *str);
void DsizeRegisterTests(void);
static void DetectDsizeFree(void *);

/**
 * \brief Registration function for dsize: keyword
 */
void DetectDsizeRegister (void)
{
    sigmatch_table[DETECT_DSIZE].name = "dsize";
    sigmatch_table[DETECT_DSIZE].desc = "match on the size of the packet payload";
    sigmatch_table[DETECT_DSIZE].url = "https://redmine.openinfosecfoundation.org/projects/suricata/wiki/Payload_keywords#Dsize";
    sigmatch_table[DETECT_DSIZE].Match = DetectDsizeMatch;
    sigmatch_table[DETECT_DSIZE].Setup = DetectDsizeSetup;
    sigmatch_table[DETECT_DSIZE].Free  = DetectDsizeFree;
    sigmatch_table[DETECT_DSIZE].RegisterTests = DsizeRegisterTests;

    const char *eb;
    int eo;
    int opts = 0;

    parse_regex = pcre_compile(PARSE_REGEX, opts, &eb, &eo, NULL);
    if(parse_regex == NULL)
    {
        SCLogError(SC_ERR_PCRE_COMPILE,"pcre compile of \"%s\" failed at offset %" PRId32 ": %s", PARSE_REGEX, eo, eb);
        goto error;
    }

    parse_regex_study = pcre_study(parse_regex, 0, &eb);
    if(eb != NULL)
    {
        SCLogError(SC_ERR_PCRE_STUDY,"pcre study failed: %s", eb);
        goto error;
    }
    return;

error:
    /* XXX */
    return;
}

/**
 * \internal
 * \brief This function is used to match flags on a packet with those passed via dsize:
 *
 * \param t pointer to thread vars
 * \param det_ctx pointer to the pattern matcher thread
 * \param p pointer to the current packet
 * \param s pointer to the Signature
 * \param m pointer to the sigmatch
 *
 * \retval 0 no match
 * \retval 1 match
 */
int DetectDsizeMatch (ThreadVars *t, DetectEngineThreadCtx *det_ctx, Packet *p, Signature *s, const SigMatchCtx *ctx)
{
    SCEnter();
    int ret = 0;

    if (PKT_IS_PSEUDOPKT(p)) {
        SCReturnInt(0);
    }

    const DetectDsizeData *dd = (const DetectDsizeData *)ctx;

    SCLogDebug("p->payload_len %"PRIu16"", p->payload_len);

    if (dd->mode == DETECTDSIZE_EQ && dd->dsize == p->payload_len)
        ret = 1;
    else if (dd->mode == DETECTDSIZE_LT && p->payload_len < dd->dsize)
        ret = 1;
    else if (dd->mode == DETECTDSIZE_GT && p->payload_len > dd->dsize)
        ret = 1;
    else if (dd->mode == DETECTDSIZE_RA && p->payload_len > dd->dsize && p->payload_len < dd->dsize2)
        ret = 1;

    SCReturnInt(ret);
}

/**
 * \internal
 * \brief This function is used to parse dsize options passed via dsize: keyword
 *
 * \param rawstr Pointer to the user provided dsize options
 *
 * \retval dd pointer to DetectDsizeData on success
 * \retval NULL on failure
 */
DetectDsizeData *DetectDsizeParse (char *rawstr)
{
    DetectDsizeData *dd = NULL;
#define MAX_SUBSTRINGS 30
    int ret = 0, res = 0;
    int ov[MAX_SUBSTRINGS];
    char mode[2] = "";
    char value1[6] = "";
    char value2[6] = "";
    char range[3] = "";

    ret = pcre_exec(parse_regex, parse_regex_study, rawstr, strlen(rawstr), 0, 0, ov, MAX_SUBSTRINGS);
    if (ret < 3 || ret > 5) {
        SCLogError(SC_ERR_PCRE_MATCH,"Parse error %s", rawstr);
        goto error;
    }

    res = pcre_copy_substring((char *)rawstr, ov, MAX_SUBSTRINGS, 1, mode, sizeof(mode));
    if (res < 0) {
        SCLogError(SC_ERR_PCRE_GET_SUBSTRING,"pcre_copy_substring failed");
        goto error;
    }
    SCLogDebug("mode \"%s\"", mode);

    res = pcre_copy_substring((char *)rawstr, ov, MAX_SUBSTRINGS, 2, value1, sizeof(value1));
    if (res < 0) {
        SCLogError(SC_ERR_PCRE_GET_SUBSTRING,"pcre_copy_substring failed");
        goto error;
    }
    SCLogDebug("value1 \"%s\"", value1);

    if (ret > 3) {
        res = pcre_copy_substring((char *)rawstr, ov, MAX_SUBSTRINGS, 3, range, sizeof(range));
        if (res < 0) {
            SCLogError(SC_ERR_PCRE_GET_SUBSTRING,"pcre_copy_substring failed");
            goto error;
        }
        SCLogDebug("range \"%s\"", range);

        if (ret > 4) {
            res = pcre_copy_substring((char *)rawstr, ov, MAX_SUBSTRINGS, 4, value2, sizeof(value2));
            if (res < 0) {
                SCLogError(SC_ERR_PCRE_GET_SUBSTRING,"pcre_copy_substring failed");
                goto error;
            }
            SCLogDebug("value2 \"%s\"", value2);
        }
    }

    dd = SCMalloc(sizeof(DetectDsizeData));
    if (unlikely(dd == NULL))
        goto error;
    dd->dsize = 0;
    dd->dsize2 = 0;
    dd->mode = DETECTDSIZE_EQ; // default

    if (strlen(mode) > 0) {
        if (mode[0] == '<')
            dd->mode = DETECTDSIZE_LT;
        else if (mode[0] == '>')
            dd->mode = DETECTDSIZE_GT;
        else
            dd->mode = DETECTDSIZE_EQ;
    }

    if (strcmp("<>", range) == 0) {
        if (strlen(mode) != 0) {
            SCLogError(SC_ERR_INVALID_ARGUMENT,"Range specified but mode also set");
            goto error;
        }
        dd->mode = DETECTDSIZE_RA;
    }

    /** set the first dsize value */
    if (ByteExtractStringUint16(&dd->dsize,10,strlen(value1),value1) <= 0) {
        SCLogError(SC_ERR_INVALID_ARGUMENT, "Invalid size value1:\"%s\"", value1);
        goto error;
    }

    /** set the second dsize value if specified */
    if (strlen(value2) > 0) {
        if (dd->mode != DETECTDSIZE_RA) {
            SCLogError(SC_ERR_INVALID_ARGUMENT,"Multiple dsize values specified but mode is not range");
            goto error;
        }

        if (ByteExtractStringUint16(&dd->dsize2,10,strlen(value2),value2) <= 0) {
            SCLogError(SC_ERR_INVALID_ARGUMENT,"Invalid size value2:\"%s\"",value2);
            goto error;
        }

        if (dd->dsize2 <= dd->dsize) {
            SCLogError(SC_ERR_INVALID_ARGUMENT,"dsize2:%"PRIu16" <= dsize:%"PRIu16"",dd->dsize2,dd->dsize);
            goto error;
        }
    }

    SCLogDebug("dsize parsed successfully dsize: %"PRIu16" dsize2: %"PRIu16"",dd->dsize,dd->dsize2);
    return dd;

error:
    if (dd)
        SCFree(dd);
    return NULL;
}

/**
 * \internal
 * \brief this function is used to add the parsed dsize into the current signature
 *
 * \param de_ctx pointer to the Detection Engine Context
 * \param s pointer to the Current Signature
 * \param rawstr pointer to the user provided flags options
 *
 * \retval 0 on Success
 * \retval -1 on Failure
 */
static int DetectDsizeSetup (DetectEngineCtx *de_ctx, Signature *s, char *rawstr)
{
    DetectDsizeData *dd = NULL;
    SigMatch *sm = NULL;

    if (SigMatchGetLastSMFromLists(s, 2,
                                   DETECT_DSIZE,
                                   s->sm_lists_tail[DETECT_SM_LIST_MATCH]) != NULL) {
        SCLogError(SC_ERR_INVALID_SIGNATURE, "Can't use 2 or more dsizes in "
                   "the same sig.  Invalidating signature.");
        goto error;
    }

    SCLogDebug("\'%s\'", rawstr);

    dd = DetectDsizeParse(rawstr);
    if (dd == NULL) {
        SCLogError(SC_ERR_INVALID_ARGUMENT,"Parsing \'%s\' failed", rawstr);
        goto error;
    }

    /* Okay so far so good, lets get this into a SigMatch
     * and put it in the Signature. */
    sm = SigMatchAlloc();
    if (sm == NULL){
        SCLogError(SC_ERR_MEM_ALLOC, "Failed to allocate memory for SigMatch");
        SCFree(dd);
        goto error;
    }

    sm->type = DETECT_DSIZE;
    sm->ctx = (SigMatchCtx *)dd;

    SigMatchAppendSMToList(s, sm, DETECT_SM_LIST_MATCH);

    SCLogDebug("dd->dsize %"PRIu16", dd->dsize2 %"PRIu16", dd->mode %"PRIu8"",
            dd->dsize, dd->dsize2, dd->mode);
    /* tell the sig it has a dsize to speed up engine init */
    s->flags |= SIG_FLAG_REQUIRE_PACKET;
    s->flags |= SIG_FLAG_DSIZE;

    if (s->dsize_sm == NULL) {
        s->dsize_sm = sm;
    }

    return 0;

error:
    return -1;
}

/**
 * \internal
 * \brief this function will free memory associated with DetectDsizeData
 *
 * \param de pointer to DetectDsizeData
 */
void DetectDsizeFree(void *de_ptr)
{
    DetectDsizeData *dd = (DetectDsizeData *)de_ptr;
    if(dd) SCFree(dd);
}

/*
 * ONLY TESTS BELOW THIS COMMENT
 */

#ifdef UNITTESTS
#include "detect.h"
#include "detect-engine.h"
/**
 * \test this is a test for a valid dsize value 1
 *
 *  \retval 1 on succces
 *  \retval 0 on failure
 */
int DsizeTestParse01 (void)
{
    DetectDsizeData *dd = NULL;
    dd = DetectDsizeParse("1");
    if (dd) {
        DetectDsizeFree(dd);
        return 1;
    }

    return 0;
}

/**
 * \test this is a test for a valid dsize value >10
 *
 *  \retval 1 on succces
 *  \retval 0 on failure
 */
int DsizeTestParse02 (void)
{
    DetectDsizeData *dd = NULL;
    dd = DetectDsizeParse(">10");
    if (dd) {
        DetectDsizeFree(dd);
        return 1;
    }

    return 0;
}

/**
 * \test this is a test for a valid dsize value <100
 *
 *  \retval 1 on succces
 *  \retval 0 on failure
 */
int DsizeTestParse03 (void)
{
    DetectDsizeData *dd = NULL;
    dd = DetectDsizeParse("<100");
    if (dd) {
        DetectDsizeFree(dd);
        return 1;
    }

    return 0;
}

/**
 * \test this is a test for a valid dsize value 1<>2
 *
 *  \retval 1 on succces
 *  \retval 0 on failure
 */
int DsizeTestParse04 (void)
{
    DetectDsizeData *dd = NULL;
    dd = DetectDsizeParse("1<>2");
    if (dd) {
        DetectDsizeFree(dd);
        return 1;
    }

    return 0;
}

/**
 * \test this is a test for a valid dsize value 1
 *
 *  \retval 1 on succces
 *  \retval 0 on failure
 */
int DsizeTestParse05 (void)
{
    int result = 0;
    DetectDsizeData *dd = NULL;
    dd = DetectDsizeParse("1");
    if (dd) {
        if (dd->dsize == 1)
            result = 1;

        DetectDsizeFree(dd);
    }

    return result;
}

/**
 * \test this is a test for a valid dsize value >10
 *
 *  \retval 1 on succces
 *  \retval 0 on failure
 */
int DsizeTestParse06 (void)
{
    int result = 0;
    DetectDsizeData *dd = NULL;
    dd = DetectDsizeParse(">10");
    if (dd) {
        if (dd->dsize == 10 && dd->mode == DETECTDSIZE_GT)
            result = 1;

        DetectDsizeFree(dd);
    }

    return result;
}

/**
 * \test this is a test for a valid dsize value <100
 *
 *  \retval 1 on succces
 *  \retval 0 on failure
 */
int DsizeTestParse07 (void)
{
    int result = 0;
    DetectDsizeData *dd = NULL;
    dd = DetectDsizeParse("<100");
    if (dd) {
        if (dd->dsize == 100 && dd->mode == DETECTDSIZE_LT)
            result = 1;

        DetectDsizeFree(dd);
    }

    return result;
}

/**
 * \test this is a test for a valid dsize value 1<>2
 *
 *  \retval 1 on succces
 *  \retval 0 on failure
 */
int DsizeTestParse08 (void)
{
    int result = 0;
    DetectDsizeData *dd = NULL;
    dd = DetectDsizeParse("1<>2");
    if (dd) {
        if (dd->dsize == 1 && dd->dsize2 == 2 && dd->mode == DETECTDSIZE_RA)
            result = 1;

        DetectDsizeFree(dd);
    }

    return result;
}

/**
 * \test this is a test for a invalid dsize value A
 *
 *  \retval 1 on succces
 *  \retval 0 on failure
 */
int DsizeTestParse09 (void)
{
    DetectDsizeData *dd = NULL;
    dd = DetectDsizeParse("A");
    if (dd) {
        DetectDsizeFree(dd);
        return 0;
    }

    return 1;
}

/**
 * \test this is a test for a invalid dsize value >10<>10
 *
 *  \retval 1 on succces
 *  \retval 0 on failure
 */
int DsizeTestParse10 (void)
{
    DetectDsizeData *dd = NULL;
    dd = DetectDsizeParse(">10<>10");
    if (dd) {
        DetectDsizeFree(dd);
        return 0;
    }

    return 1;
}

/**
 * \test this is a test for a invalid dsize value <>10
 *
 *  \retval 1 on succces
 *  \retval 0 on failure
 */
int DsizeTestParse11 (void)
{
    DetectDsizeData *dd = NULL;
    dd = DetectDsizeParse("<>10");
    if (dd) {
        DetectDsizeFree(dd);
        return 0;
    }

    return 1;
}

/**
 * \test this is a test for a invalid dsize value 1<>
 *
 *  \retval 1 on succces
 *  \retval 0 on failure
 */
int DsizeTestParse12 (void)
{
    DetectDsizeData *dd = NULL;
    dd = DetectDsizeParse("1<>");
    if (dd) {
        DetectDsizeFree(dd);
        return 0;
    }

    return 1;
}

/**
 * \test this is a test for a valid dsize value 1
 *
 *  \retval 1 on succces
 *  \retval 0 on failure
 */
int DsizeTestParse13 (void)
{
    int result = 0;
    DetectDsizeData *dd = NULL;
    dd = DetectDsizeParse("1");
    if (dd) {
        if (dd->dsize2 == 0)
            result = 1;

        DetectDsizeFree(dd);
    }

    return result;
}

/**
 * \test this is a test for a invalid dsize value ""
 *
 *  \retval 1 on succces
 *  \retval 0 on failure
 */
int DsizeTestParse14 (void)
{
    DetectDsizeData *dd = NULL;
    dd = DetectDsizeParse("");
    if (dd) {
        DetectDsizeFree(dd);
        return 0;
    }

    return 1;
}

/**
 * \test this is a test for a invalid dsize value " "
 *
 *  \retval 1 on succces
 *  \retval 0 on failure
 */
int DsizeTestParse15 (void)
{
    DetectDsizeData *dd = NULL;
    dd = DetectDsizeParse(" ");
    if (dd) {
        DetectDsizeFree(dd);
        return 0;
    }

    return 1;
}

/**
 * \test this is a test for a invalid dsize value 2<>1
 *
 *  \retval 1 on succces
 *  \retval 0 on failure
 */
int DsizeTestParse16 (void)
{
    DetectDsizeData *dd = NULL;
    dd = DetectDsizeParse("2<>1");
    if (dd) {
        DetectDsizeFree(dd);
        return 0;
    }

    return 1;
}

/**
 * \test this is a test for a valid dsize value 1 <> 2
 *
 *  \retval 1 on succces
 *  \retval 0 on failure
 */
int DsizeTestParse17 (void)
{
    int result = 0;
    DetectDsizeData *dd = NULL;
    dd = DetectDsizeParse(" 1 <> 2 ");
    if (dd) {
        if (dd->dsize == 1 && dd->dsize2 == 2 && dd->mode == DETECTDSIZE_RA)
            result = 1;

        DetectDsizeFree(dd);
    }

    return result;
}

/**
 * \test this is test for a valid dsize value > 2
 *
 *  \retval 1 on succces
 *  \retval 0 on failure
 */
int DsizeTestParse18 (void)
{
    int result = 0;
    DetectDsizeData *dd = NULL;
    dd = DetectDsizeParse("> 2 ");
    if (dd) {
        if (dd->dsize == 2 && dd->mode == DETECTDSIZE_GT)
            result = 1;

        DetectDsizeFree(dd);
    }

    return result;
}

/**
 * \test test for a valid dsize value <   12
 *
 *  \retval 1 on succces
 *  \retval 0 on failure
 */
int DsizeTestParse19 (void)
{
    int result = 0;
    DetectDsizeData *dd = NULL;
    dd = DetectDsizeParse("<   12 ");
    if (dd) {
        if (dd->dsize == 12 && dd->mode == DETECTDSIZE_LT)
            result = 1;

        DetectDsizeFree(dd);
    }

    return result;
}

/**
 * \test test for a valid dsize value    12
 *
 *  \retval 1 on succces
 *  \retval 0 on failure
 */
int DsizeTestParse20 (void)
{
    int result = 0;
    DetectDsizeData *dd = NULL;
    dd = DetectDsizeParse("   12 ");
    if (dd) {
        if (dd->dsize == 12 && dd->mode == DETECTDSIZE_EQ)
            result = 1;

        DetectDsizeFree(dd);
    }

    return result;
}

/**
 * \test DetectDsizeIcmpv6Test01 is a test for checking the working of
 *       dsize keyword by creating 2 rules and matching a crafted packet
 *       against them. Only the first one shall trigger.
 */
int DetectDsizeIcmpv6Test01 (void)
{
    int result = 0;

    static uint8_t raw_icmpv6[] = {
        0x60, 0x00, 0x00, 0x00, 0x00, 0x30, 0x3a, 0xff,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        0x01, 0x00, 0x7b, 0x85, 0x00, 0x00, 0x00, 0x00,
        0x60, 0x4b, 0xe8, 0xbd, 0x00, 0x00, 0x3b, 0xff,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 };

    Packet *p = SCMalloc(SIZE_OF_PACKET);
    if (unlikely(p == NULL))
        return 0;
    IPV6Hdr ip6h;
    ThreadVars tv;
    DecodeThreadVars dtv;
    Signature *s = NULL;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx = NULL;

    memset(&tv, 0, sizeof(ThreadVars));
    memset(p, 0, SIZE_OF_PACKET);
    memset(&dtv, 0, sizeof(DecodeThreadVars));
    memset(&ip6h, 0, sizeof(IPV6Hdr));
    memset(&th_v, 0, sizeof(ThreadVars));

    FlowInitConfig(FLOW_QUIET);
    p->src.family = AF_INET6;
    p->dst.family = AF_INET6;
    p->ip6h = &ip6h;

    DecodeIPV6(&tv, &dtv, p, raw_icmpv6, sizeof(raw_icmpv6), NULL);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }

    de_ctx->flags |= DE_QUIET;

    s = de_ctx->sig_list = SigInit(de_ctx, "alert icmp any any -> any any "
            "(msg:\"ICMP Large ICMP Packet\"; dsize:>8; sid:1; rev:4;)");
    if (s == NULL) {
        goto end;
    }

    s = s->next = SigInit(de_ctx, "alert icmp any any -> any any "
            "(msg:\"ICMP Large ICMP Packet\"; dsize:>800; sid:2; rev:4;)");
    if (s == NULL) {
        goto end;
    }

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    if (PacketAlertCheck(p, 1) == 0) {
        printf("sid 1 did not alert, but should have: ");
        goto cleanup;
    } else if (PacketAlertCheck(p, 2)) {
        printf("sid 2 alerted, but should not have: ");
        goto cleanup;
    }

    result = 1;

cleanup:
    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);

    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);

    PACKET_RECYCLE(p);
    FlowShutdown();
end:
    SCFree(p);
    return result;

}
#endif /* UNITTESTS */

/**
 * \brief this function registers unit tests for dsize
 */
void DsizeRegisterTests(void)
{
#ifdef UNITTESTS
    UtRegisterTest("DsizeTestParse01", DsizeTestParse01, 1);
    UtRegisterTest("DsizeTestParse02", DsizeTestParse02, 1);
    UtRegisterTest("DsizeTestParse03", DsizeTestParse03, 1);
    UtRegisterTest("DsizeTestParse04", DsizeTestParse04, 1);
    UtRegisterTest("DsizeTestParse05", DsizeTestParse05, 1);
    UtRegisterTest("DsizeTestParse06", DsizeTestParse06, 1);
    UtRegisterTest("DsizeTestParse07", DsizeTestParse07, 1);
    UtRegisterTest("DsizeTestParse08", DsizeTestParse08, 1);
    UtRegisterTest("DsizeTestParse09", DsizeTestParse09, 1);
    UtRegisterTest("DsizeTestParse10", DsizeTestParse10, 1);
    UtRegisterTest("DsizeTestParse11", DsizeTestParse11, 1);
    UtRegisterTest("DsizeTestParse12", DsizeTestParse12, 1);
    UtRegisterTest("DsizeTestParse13", DsizeTestParse13, 1);
    UtRegisterTest("DsizeTestParse14", DsizeTestParse14, 1);
    UtRegisterTest("DsizeTestParse15", DsizeTestParse15, 1);
    UtRegisterTest("DsizeTestParse16", DsizeTestParse16, 1);
    UtRegisterTest("DsizeTestParse17", DsizeTestParse17, 1);
    UtRegisterTest("DsizeTestParse18", DsizeTestParse18, 1);
    UtRegisterTest("DsizeTestParse19", DsizeTestParse19, 1);
    UtRegisterTest("DsizeTestParse20", DsizeTestParse20, 1);

    UtRegisterTest("DetectDsizeIcmpv6Test01", DetectDsizeIcmpv6Test01, 1);
#endif /* UNITTESTS */
}

