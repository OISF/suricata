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
 * \author Breno Silva <breno.silva@gmail.com>
 *
 * Implements fragbits keyword
 */

#include "suricata-common.h"
#include "suricata.h"
#include "decode.h"

#include "detect.h"
#include "detect-parse.h"

#include "flow-var.h"
#include "decode-events.h"
#include "app-layer.h"
#include "app-layer-detect-proto.h"

#include "detect-fragbits.h"
#include "util-unittest.h"
#include "util-debug.h"

#include "pkt-var.h"
#include "host.h"
#include "util-profiling.h"

/**
 *  Regex
 *  fragbits: [!+*](MDR)
 */
#define PARSE_REGEX "^\\s*(?:([\\+\\*!]))?\\s*([MDR]+)"

/**
 * FragBits args[0] *(3) +(2) !(1)
 *
 */

#define MODIFIER_NOT  1
#define MODIFIER_PLUS 2
#define MODIFIER_ANY  3

#define FRAGBITS_HAVE_MF    0x01
#define FRAGBITS_HAVE_DF    0x02
#define FRAGBITS_HAVE_RF    0x04

static pcre *parse_regex;
static pcre_extra *parse_regex_study;

static int DetectFragBitsMatch (ThreadVars *, DetectEngineThreadCtx *, Packet *, Signature *, const SigMatchCtx *);
static int DetectFragBitsSetup (DetectEngineCtx *, Signature *, char *);
static void DetectFragBitsFree(void *);

/**
 * \brief Registration function for fragbits: keyword
 */

void DetectFragBitsRegister (void)
{
    sigmatch_table[DETECT_FRAGBITS].name = "fragbits";
    sigmatch_table[DETECT_FRAGBITS].desc = "check if the fragmentation and reserved bits are set in the IP header";
    sigmatch_table[DETECT_FRAGBITS].url = "https://redmine.openinfosecfoundation.org/projects/suricata/wiki/Header_keywords#Fragbits";
    sigmatch_table[DETECT_FRAGBITS].Match = DetectFragBitsMatch;
    sigmatch_table[DETECT_FRAGBITS].Setup = DetectFragBitsSetup;
    sigmatch_table[DETECT_FRAGBITS].Free  = DetectFragBitsFree;
    sigmatch_table[DETECT_FRAGBITS].RegisterTests = FragBitsRegisterTests;

    const char *eb;
    int opts = 0;
    int eo;

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

error:
    return;

}

/**
 * \internal
 * \brief This function is used to match fragbits on a packet with those passed via fragbits:
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
static int DetectFragBitsMatch (ThreadVars *t, DetectEngineThreadCtx *det_ctx, Packet *p, Signature *s, const SigMatchCtx *ctx)
{
    int ret = 0;
    uint16_t fragbits = 0;
    const DetectFragBitsData *de = (const DetectFragBitsData *)ctx;

    if (!de || !PKT_IS_IPV4(p) || !p || PKT_IS_PSEUDOPKT(p))
        return ret;

    if(IPV4_GET_MF(p))
        fragbits |= FRAGBITS_HAVE_MF;
    if(IPV4_GET_DF(p))
        fragbits |= FRAGBITS_HAVE_DF;
    if(IPV4_GET_RF(p))
        fragbits |= FRAGBITS_HAVE_RF;

    switch(de->modifier)    {
        case MODIFIER_ANY:
            if((fragbits & de->fragbits) > 0)
                return 1;
            return ret;
        case MODIFIER_PLUS:
            if(((fragbits & de->fragbits) == de->fragbits) && (((fragbits - de->fragbits) > 0)))
                return 1;
            return ret;
        case MODIFIER_NOT:
            if((fragbits & de->fragbits) != de->fragbits)
                return 1;
            return ret;
        default:
            if(fragbits == de->fragbits)
                return 1;
    }

    return ret;
}

/**
 * \internal
 * \brief This function is used to parse fragbits options passed via fragbits: keyword
 *
 * \param rawstr Pointer to the user provided fragbits options
 *
 * \retval de pointer to DetectFragBitsData on success
 * \retval NULL on failure
 */
static DetectFragBitsData *DetectFragBitsParse (char *rawstr)
{
    DetectFragBitsData *de = NULL;
#define MAX_SUBSTRINGS 30
    int ret = 0, found = 0, res = 0;
    int ov[MAX_SUBSTRINGS];
    const char *str_ptr = NULL;
    char *args[2] = { NULL, NULL};
    char *ptr;
    int i;

    ret = pcre_exec(parse_regex, parse_regex_study, rawstr, strlen(rawstr), 0, 0, ov, MAX_SUBSTRINGS);

    if (ret < 1) {
        SCLogError(SC_ERR_PCRE_MATCH, "pcre_exec parse error, ret %" PRId32 ", string %s", ret, rawstr);
        goto error;
    }

    for (i = 0; i < (ret - 1); i++) {

        res = pcre_get_substring((char *)rawstr, ov, MAX_SUBSTRINGS,i + 1, &str_ptr);

        if (res < 0) {
            SCLogError(SC_ERR_PCRE_GET_SUBSTRING, "pcre_get_substring failed");
            goto error;
        }

        args[i] = (char *)str_ptr;
    }

    if(args[1] == NULL) {
        SCLogError(SC_ERR_INVALID_VALUE, "invalid value");
        goto error;
    }

    de = SCMalloc(sizeof(DetectFragBitsData));
    if (unlikely(de == NULL))
        goto error;

    memset(de,0,sizeof(DetectFragBitsData));

    /** First parse args[0] */

    if(args[0])   {

        ptr = args[0];

        while (*ptr != '\0') {
            switch (*ptr) {
                case '!':
                    de->modifier = MODIFIER_NOT;
                    break;
                case '+':
                    de->modifier = MODIFIER_PLUS;
                    break;
                case '*':
                    de->modifier = MODIFIER_ANY;
                    break;
            }
            ptr++;
        }

    }

    /** Second parse first set of fragbits */

    ptr = args[1];

    while (*ptr != '\0') {
        switch (*ptr) {
            case 'M':
            case 'm':
                de->fragbits |= FRAGBITS_HAVE_MF;
                found++;
                break;
            case 'D':
            case 'd':
                de->fragbits |= FRAGBITS_HAVE_DF;
                found++;
                break;
            case 'R':
            case 'r':
                de->fragbits |= FRAGBITS_HAVE_RF;
                found++;
                break;
            default:
                found = 0;
                break;
        }
        ptr++;
    }

    if(found == 0)
        goto error;

    for (i = 0; i < 2; i++) {
        if (args[i] != NULL)
            SCFree(args[i]);
    }
    return de;

error:
    for (i = 0; i < 2; i++) {
        if (args[i] != NULL)
            SCFree(args[i]);
    }
    if (de != NULL)
        SCFree(de);
    return NULL;
}

/**
 * \internal
 * \brief this function is used to add the parsed fragbits into the current signature
 *
 * \param de_ctx pointer to the Detection Engine Context
 * \param s pointer to the Current Signature
 * \param m pointer to the Current SigMatch
 * \param rawstr pointer to the user provided fragbits options
 *
 * \retval 0 on Success
 * \retval -1 on Failure
 */
static int DetectFragBitsSetup (DetectEngineCtx *de_ctx, Signature *s, char *rawstr)
{
    DetectFragBitsData *de = NULL;
    SigMatch *sm = NULL;

    de = DetectFragBitsParse(rawstr);
    if (de == NULL)
        goto error;

    sm = SigMatchAlloc();
    if (sm == NULL)
        goto error;

    sm->type = DETECT_FRAGBITS;
    sm->ctx = (SigMatchCtx *)de;

    SigMatchAppendSMToList(s, sm, DETECT_SM_LIST_MATCH);
    s->flags |= SIG_FLAG_REQUIRE_PACKET;

    return 0;

error:
    if (de) SCFree(de);
    if (sm) SCFree(sm);
    return -1;
}

/**
 * \internal
 * \brief this function will free memory associated with DetectFragBitsData
 *
 * \param de pointer to DetectFragBitsData
 */
static void DetectFragBitsFree(void *de_ptr)
{
    DetectFragBitsData *de = (DetectFragBitsData *)de_ptr;
    if(de) SCFree(de);
}

/*
 * ONLY TESTS BELOW THIS COMMENT
 */

#ifdef UNITTESTS
/**
 * \test FragBitsTestParse01 is a test for a  valid fragbits value
 *
 *  \retval 1 on succces
 *  \retval 0 on failure
 */
static int FragBitsTestParse01 (void)
{
    DetectFragBitsData *de = NULL;
    de = DetectFragBitsParse("M");
    if (de && (de->fragbits == FRAGBITS_HAVE_MF) ) {
        DetectFragBitsFree(de);
        return 1;
    }

    return 0;
}

/**
 * \test FragBitsTestParse02 is a test for an invalid fragbits value
 *
 *  \retval 1 on succces
 *  \retval 0 on failure
 */
static int FragBitsTestParse02 (void)
{
    DetectFragBitsData *de = NULL;
    de = DetectFragBitsParse("G");
    if (de) {
        DetectFragBitsFree(de);
        return 1;
    }

    return 0;
}

/**
 * \test FragBitsTestParse03 test if DONT FRAG is set. Must return success
 *
 *  \retval 1 on success
 *  \retval 0 on failure
 */
static int FragBitsTestParse03 (void)
{
    uint8_t raw_eth[] = {
        0x00 ,0x40 ,0x33 ,0xd9 ,0x7c ,0xfd ,0x00 ,0x00,
        0x39 ,0xcf ,0xd9 ,0xcd ,0x08 ,0x00 ,0x45 ,0x00,
        0x01 ,0x13 ,0x9c ,0x5d ,0x40 ,0x00 ,0xf6 ,0x11,
        0x44 ,0xca ,0x97 ,0xa4 ,0x01 ,0x08 ,0x0a ,0x00,
        0x00 ,0x06 ,0x00 ,0x35 ,0x04 ,0x0b ,0x00 ,0xff,
        0x3c ,0x87 ,0x7d ,0x9e ,0x85 ,0x80 ,0x00 ,0x01,
        0x00 ,0x01 ,0x00 ,0x05 ,0x00 ,0x05 ,0x06 ,0x70,
        0x69 ,0x63 ,0x61 ,0x72 ,0x64 ,0x07 ,0x75 ,0x74,
        0x68 ,0x73 ,0x63 ,0x73 ,0x61 ,0x03 ,0x65 ,0x64,
        0x75 ,0x00 ,0x00 ,0x01 ,0x00 ,0x01 ,0xc0 ,0x0c,
        0x00 ,0x01 ,0x00 ,0x01 ,0x00 ,0x00 ,0x0e ,0x10,
        0x00 ,0x04 ,0x81 ,0x6f ,0x1e ,0x1b ,0x07 ,0x75,
        0x74 ,0x68 ,0x73 ,0x63 ,0x73 ,0x61 ,0x03 ,0x65,
        0x64 ,0x75 ,0x00 ,0x00 ,0x02 ,0x00 ,0x01 ,0x00,
        0x00 ,0x0e ,0x10 ,0x00 ,0x09 ,0x06 ,0x6b ,0x65,
        0x6e ,0x6f ,0x62 ,0x69 ,0xc0 ,0x34 ,0xc0 ,0x34,
        0x00 ,0x02 ,0x00 ,0x01 ,0x00 ,0x00 ,0x0e ,0x10,
        0x00 ,0x07 ,0x04 ,0x6a ,0x69 ,0x6e ,0x6e ,0xc0,
        0x34 ,0xc0 ,0x34 ,0x00 ,0x02 ,0x00 ,0x01 ,0x00,
        0x00 ,0x0e ,0x10 ,0x00 ,0x0c ,0x04 ,0x64 ,0x6e,
        0x73 ,0x31 ,0x04 ,0x6e ,0x6a ,0x69 ,0x74 ,0xc0,
        0x3c ,0xc0 ,0x34 ,0x00 ,0x02 ,0x00 ,0x01 ,0x00,
        0x00 ,0x0e ,0x10 ,0x00 ,0x08 ,0x05 ,0x65 ,0x6c,
        0x7a ,0x69 ,0x70 ,0xc0 ,0x34 ,0xc0 ,0x34 ,0x00,
        0x02 ,0x00 ,0x01 ,0x00 ,0x00 ,0x0e ,0x10 ,0x00,
        0x08 ,0x05 ,0x61 ,0x72 ,0x77 ,0x65 ,0x6e ,0xc0,
        0x34 ,0xc0 ,0x4b ,0x00 ,0x01 ,0x00 ,0x01 ,0x00,
        0x00 ,0x0e ,0x10 ,0x00 ,0x04 ,0x81 ,0x6f ,0x1a,
        0x06 ,0xc0 ,0x60 ,0x00 ,0x01 ,0x00 ,0x01 ,0x00,
        0x00 ,0x0e ,0x10 ,0x00 ,0x04 ,0x81 ,0x6f ,0x1a,
        0x07 ,0xc0 ,0x73 ,0x00 ,0x01 ,0x00 ,0x01 ,0x00,
        0x01 ,0x03 ,0x82 ,0x00 ,0x04 ,0x80 ,0xeb ,0xfb,
        0x0a ,0xc0 ,0x8b ,0x00 ,0x01 ,0x00 ,0x01 ,0x00,
        0x00 ,0x0e ,0x10 ,0x00 ,0x04 ,0x81 ,0x6f ,0x01,
        0x0b ,0xc0 ,0x9f ,0x00 ,0x01 ,0x00 ,0x01 ,0x00,
        0x00 ,0x0e ,0x10 ,0x00 ,0x04 ,0x81 ,0x6f ,0x0b,
        0x51};
    Packet *p = SCMalloc(SIZE_OF_PACKET);
    if (unlikely(p == NULL))
        return 0;
    ThreadVars tv;
    DecodeThreadVars dtv;
    IPV4Hdr ipv4h;
    int ret = 0;
    DetectFragBitsData *de = NULL;
    SigMatch *sm = NULL;

    memset(&tv, 0, sizeof(ThreadVars));
    memset(p, 0, SIZE_OF_PACKET);
    memset(&dtv, 0, sizeof(DecodeThreadVars));
    memset(&ipv4h, 0, sizeof(IPV4Hdr));
    dtv.app_tctx = AppLayerGetCtxThread(&tv);

    p->ip4h = &ipv4h;

    FlowInitConfig(FLOW_QUIET);

    DecodeEthernet(&tv, &dtv, p, raw_eth, sizeof(raw_eth), NULL);

    de = DetectFragBitsParse("D");

    if (de == NULL || (de->fragbits != FRAGBITS_HAVE_DF))
        goto error;

    sm = SigMatchAlloc();
    if (sm == NULL)
        goto error;

    sm->type = DETECT_FRAGBITS;
    sm->ctx = (SigMatchCtx *)de;

    ret = DetectFragBitsMatch(&tv, NULL, p, NULL, sm->ctx);

    if(ret) {
        if (de) SCFree(de);
        if (sm) SCFree(sm);
        SCFree(p);
        return 1;
    }

error:
    FlowShutdown();
    if (de) SCFree(de);
    if (sm) SCFree(sm);
    SCFree(p);
    return 0;
}

/**
 * \test FragBitsTestParse04 test if DONT FRAG is not set. Must fails.
 *
 *  \retval 1 on success
 *  \retval 0 on failure
 */
static int FragBitsTestParse04 (void)
{
    uint8_t raw_eth[] = {
        0x00 ,0x40 ,0x33 ,0xd9 ,0x7c ,0xfd ,0x00 ,0x00,
        0x39 ,0xcf ,0xd9 ,0xcd ,0x08 ,0x00 ,0x45 ,0x00,
        0x01 ,0x13 ,0x9c ,0x5d ,0x40 ,0x00 ,0xf6 ,0x11,
        0x44 ,0xca ,0x97 ,0xa4 ,0x01 ,0x08 ,0x0a ,0x00,
        0x00 ,0x06 ,0x00 ,0x35 ,0x04 ,0x0b ,0x00 ,0xff,
        0x3c ,0x87 ,0x7d ,0x9e ,0x85 ,0x80 ,0x00 ,0x01,
        0x00 ,0x01 ,0x00 ,0x05 ,0x00 ,0x05 ,0x06 ,0x70,
        0x69 ,0x63 ,0x61 ,0x72 ,0x64 ,0x07 ,0x75 ,0x74,
        0x68 ,0x73 ,0x63 ,0x73 ,0x61 ,0x03 ,0x65 ,0x64,
        0x75 ,0x00 ,0x00 ,0x01 ,0x00 ,0x01 ,0xc0 ,0x0c,
        0x00 ,0x01 ,0x00 ,0x01 ,0x00 ,0x00 ,0x0e ,0x10,
        0x00 ,0x04 ,0x81 ,0x6f ,0x1e ,0x1b ,0x07 ,0x75,
        0x74 ,0x68 ,0x73 ,0x63 ,0x73 ,0x61 ,0x03 ,0x65,
        0x64 ,0x75 ,0x00 ,0x00 ,0x02 ,0x00 ,0x01 ,0x00,
        0x00 ,0x0e ,0x10 ,0x00 ,0x09 ,0x06 ,0x6b ,0x65,
        0x6e ,0x6f ,0x62 ,0x69 ,0xc0 ,0x34 ,0xc0 ,0x34,
        0x00 ,0x02 ,0x00 ,0x01 ,0x00 ,0x00 ,0x0e ,0x10,
        0x00 ,0x07 ,0x04 ,0x6a ,0x69 ,0x6e ,0x6e ,0xc0,
        0x34 ,0xc0 ,0x34 ,0x00 ,0x02 ,0x00 ,0x01 ,0x00,
        0x00 ,0x0e ,0x10 ,0x00 ,0x0c ,0x04 ,0x64 ,0x6e,
        0x73 ,0x31 ,0x04 ,0x6e ,0x6a ,0x69 ,0x74 ,0xc0,
        0x3c ,0xc0 ,0x34 ,0x00 ,0x02 ,0x00 ,0x01 ,0x00,
        0x00 ,0x0e ,0x10 ,0x00 ,0x08 ,0x05 ,0x65 ,0x6c,
        0x7a ,0x69 ,0x70 ,0xc0 ,0x34 ,0xc0 ,0x34 ,0x00,
        0x02 ,0x00 ,0x01 ,0x00 ,0x00 ,0x0e ,0x10 ,0x00,
        0x08 ,0x05 ,0x61 ,0x72 ,0x77 ,0x65 ,0x6e ,0xc0,
        0x34 ,0xc0 ,0x4b ,0x00 ,0x01 ,0x00 ,0x01 ,0x00,
        0x00 ,0x0e ,0x10 ,0x00 ,0x04 ,0x81 ,0x6f ,0x1a,
        0x06 ,0xc0 ,0x60 ,0x00 ,0x01 ,0x00 ,0x01 ,0x00,
        0x00 ,0x0e ,0x10 ,0x00 ,0x04 ,0x81 ,0x6f ,0x1a,
        0x07 ,0xc0 ,0x73 ,0x00 ,0x01 ,0x00 ,0x01 ,0x00,
        0x01 ,0x03 ,0x82 ,0x00 ,0x04 ,0x80 ,0xeb ,0xfb,
        0x0a ,0xc0 ,0x8b ,0x00 ,0x01 ,0x00 ,0x01 ,0x00,
        0x00 ,0x0e ,0x10 ,0x00 ,0x04 ,0x81 ,0x6f ,0x01,
        0x0b ,0xc0 ,0x9f ,0x00 ,0x01 ,0x00 ,0x01 ,0x00,
        0x00 ,0x0e ,0x10 ,0x00 ,0x04 ,0x81 ,0x6f ,0x0b,
        0x51};
    Packet *p = SCMalloc(SIZE_OF_PACKET);
    if (unlikely(p == NULL))
        return 0;
    ThreadVars tv;
    DecodeThreadVars dtv;
    IPV4Hdr ipv4h;
    int ret = 0;
    DetectFragBitsData *de = NULL;
    SigMatch *sm = NULL;

    memset(&tv, 0, sizeof(ThreadVars));
    memset(p, 0, SIZE_OF_PACKET);
    memset(&dtv, 0, sizeof(DecodeThreadVars));
    memset(&ipv4h, 0, sizeof(IPV4Hdr));
    dtv.app_tctx = AppLayerGetCtxThread(&tv);

    p->ip4h = &ipv4h;

    FlowInitConfig(FLOW_QUIET);

    DecodeEthernet(&tv, &dtv, p, raw_eth, sizeof(raw_eth), NULL);


    de = DetectFragBitsParse("!D");

    if (de == NULL || (de->fragbits != FRAGBITS_HAVE_DF) || (de->modifier != MODIFIER_NOT))
        goto error;

    sm = SigMatchAlloc();
    if (sm == NULL)
        goto error;

    sm->type = DETECT_FRAGBITS;
    sm->ctx = (SigMatchCtx *)de;

    ret = DetectFragBitsMatch(&tv, NULL, p, NULL, sm->ctx);

    if(ret) {
        if (de) SCFree(de);
        if (sm) SCFree(sm);
        PACKET_RECYCLE(p);
        FlowShutdown();
        SCFree(p);
        return 1;
    }

error:
    if (de) SCFree(de);
    if (sm) SCFree(sm);
    PACKET_RECYCLE(p);
    FlowShutdown();
    SCFree(p);
    return 0;
}
#endif /* UNITTESTS */

/**
 * \brief this function registers unit tests for FragBits
 */
void FragBitsRegisterTests(void)
{
#ifdef UNITTESTS
    UtRegisterTest("FragBitsTestParse01", FragBitsTestParse01, 1);
    UtRegisterTest("FragBitsTestParse02", FragBitsTestParse02, 0);
    UtRegisterTest("FragBitsTestParse03", FragBitsTestParse03, 1);
    UtRegisterTest("FragBitsTestParse04", FragBitsTestParse04, 0);
#endif /* UNITTESTS */
}
