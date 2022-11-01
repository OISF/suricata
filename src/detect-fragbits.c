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
 * \author Breno Silva <breno.silva@gmail.com>
 * \author Victor Julien <victor@inliniac.net>
 *
 * Implements fragbits keyword
 */

#include "suricata-common.h"
#include "suricata.h"
#include "decode.h"

#include "detect.h"
#include "detect-parse.h"
#include "detect-engine-prefilter.h"
#include "detect-engine-prefilter-common.h"

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
#define PARSE_REGEX "^(?:([\\+\\*!]))?\\s*([MDR]+)"

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

static DetectParseRegex parse_regex;

static int DetectFragBitsMatch (DetectEngineThreadCtx *, Packet *,
        const Signature *, const SigMatchCtx *);
static int DetectFragBitsSetup (DetectEngineCtx *, Signature *, const char *);
static void DetectFragBitsFree(DetectEngineCtx *, void *);

static int PrefilterSetupFragBits(DetectEngineCtx *de_ctx, SigGroupHead *sgh);
static bool PrefilterFragBitsIsPrefilterable(const Signature *s);
#ifdef UNITTESTS
static void FragBitsRegisterTests(void);
#endif

/**
 * \brief Registration function for fragbits: keyword
 */

void DetectFragBitsRegister (void)
{
    sigmatch_table[DETECT_FRAGBITS].name = "fragbits";
    sigmatch_table[DETECT_FRAGBITS].desc = "check if the fragmentation and reserved bits are set in the IP header";
    sigmatch_table[DETECT_FRAGBITS].url = "/rules/header-keywords.html#fragbits-ip-fragmentation";
    sigmatch_table[DETECT_FRAGBITS].Match = DetectFragBitsMatch;
    sigmatch_table[DETECT_FRAGBITS].Setup = DetectFragBitsSetup;
    sigmatch_table[DETECT_FRAGBITS].Free  = DetectFragBitsFree;
#ifdef UNITTESTS
    sigmatch_table[DETECT_FRAGBITS].RegisterTests = FragBitsRegisterTests;
#endif
    sigmatch_table[DETECT_FRAGBITS].SetupPrefilter = PrefilterSetupFragBits;
    sigmatch_table[DETECT_FRAGBITS].SupportsPrefilter = PrefilterFragBitsIsPrefilterable;

    DetectSetupParseRegexes(PARSE_REGEX, &parse_regex);
}

static inline int
FragBitsMatch(const uint8_t pbits, const uint8_t modifier,
              const uint8_t dbits)
{
    switch (modifier) {
        case MODIFIER_ANY:
            if ((pbits & dbits) > 0)
                return 1;
            return 0;

        case MODIFIER_PLUS:
            if (((pbits & dbits) == dbits) && (((pbits - dbits) > 0)))
                return 1;
            return 0;

        case MODIFIER_NOT:
            if ((pbits & dbits) != dbits)
                return 1;
            return 0;

        default:
            if (pbits == dbits)
                return 1;
    }
    return 0;
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
static int DetectFragBitsMatch (DetectEngineThreadCtx *det_ctx,
        Packet *p, const Signature *s, const SigMatchCtx *ctx)
{
    if (!ctx || !PKT_IS_IPV4(p) || PKT_IS_PSEUDOPKT(p))
        return 0;

    uint8_t fragbits = 0;
    const DetectFragBitsData *de = (const DetectFragBitsData *)ctx;
    if(IPV4_GET_MF(p))
        fragbits |= FRAGBITS_HAVE_MF;
    if(IPV4_GET_DF(p))
        fragbits |= FRAGBITS_HAVE_DF;
    if(IPV4_GET_RF(p))
        fragbits |= FRAGBITS_HAVE_RF;

    return FragBitsMatch(fragbits, de->modifier, de->fragbits);
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
static DetectFragBitsData *DetectFragBitsParse (const char *rawstr)
{
    DetectFragBitsData *de = NULL;
    int ret = 0, found = 0, res = 0;
    size_t pcre2_len;
    const char *str_ptr = NULL;
    char *args[2] = { NULL, NULL};
    char *ptr;
    int i;

    ret = DetectParsePcreExec(&parse_regex, rawstr, 0, 0);
    if (ret < 1) {
        SCLogError(SC_ERR_PCRE_MATCH, "pcre_exec parse error, ret %" PRId32 ", string %s", ret, rawstr);
        goto error;
    }

    for (i = 0; i < (ret - 1); i++) {
        res = SC_Pcre2SubstringGet(parse_regex.match, i + 1, (PCRE2_UCHAR8 **)&str_ptr, &pcre2_len);
        if (res < 0) {
            SCLogError(SC_ERR_PCRE_GET_SUBSTRING, "pcre2_substring_get_bynumber failed %d", res);
            goto error;
        }

        args[i] = (char *)str_ptr;
    }

    if (args[1] == NULL) {
        SCLogError(SC_ERR_INVALID_VALUE, "invalid value");
        goto error;
    }

    de = SCMalloc(sizeof(DetectFragBitsData));
    if (unlikely(de == NULL))
        goto error;

    memset(de,0,sizeof(DetectFragBitsData));

    /** First parse args[0] */

    if (args[0] && strlen(args[0])) {
        ptr = args[0];
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
            pcre2_substring_free((PCRE2_UCHAR8 *)args[i]);
    }
    return de;

error:
    for (i = 0; i < 2; i++) {
        if (args[i] != NULL)
            pcre2_substring_free((PCRE2_UCHAR8 *)args[i]);
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
static int DetectFragBitsSetup (DetectEngineCtx *de_ctx, Signature *s, const char *rawstr)
{
    DetectFragBitsData *de = NULL;
    SigMatch *sm = NULL;

    de = DetectFragBitsParse(rawstr);
    if (de == NULL)
        return -1;

    sm = SigMatchAlloc();
    if (sm == NULL)
        goto error;

    sm->type = DETECT_FRAGBITS;
    sm->ctx = (SigMatchCtx *)de;

    SigMatchAppendSMToList(s, sm, DETECT_SM_LIST_MATCH);
    s->flags |= SIG_FLAG_REQUIRE_PACKET;

    return 0;

error:
    if (de)
        SCFree(de);
    return -1;
}

/**
 * \internal
 * \brief this function will free memory associated with DetectFragBitsData
 *
 * \param de pointer to DetectFragBitsData
 */
static void DetectFragBitsFree(DetectEngineCtx *de_ctx, void *de_ptr)
{
    DetectFragBitsData *de = (DetectFragBitsData *)de_ptr;
    if(de) SCFree(de);
}

static void
PrefilterPacketFragBitsMatch(DetectEngineThreadCtx *det_ctx, Packet *p, const void *pectx)
{
    const PrefilterPacketHeaderCtx *ctx = pectx;

    if (!PKT_IS_IPV4(p) || PKT_IS_PSEUDOPKT(p))
        return;

    uint8_t fragbits = 0;
    if (IPV4_GET_MF(p))
        fragbits |= FRAGBITS_HAVE_MF;
    if (IPV4_GET_DF(p))
        fragbits |= FRAGBITS_HAVE_DF;
    if (IPV4_GET_RF(p))
        fragbits |= FRAGBITS_HAVE_RF;

    if (FragBitsMatch(fragbits, ctx->v1.u8[0], ctx->v1.u8[1]))
    {
        PrefilterAddSids(&det_ctx->pmq, ctx->sigs_array, ctx->sigs_cnt);
    }
}

static void
PrefilterPacketFragBitsSet(PrefilterPacketHeaderValue *v, void *smctx)
{
    const DetectFragBitsData *fb = smctx;
    v->u8[0] = fb->modifier;
    v->u8[1] = fb->fragbits;
}

static bool
PrefilterPacketFragBitsCompare(PrefilterPacketHeaderValue v, void *smctx)
{
    const DetectFragBitsData *fb = smctx;
    if (v.u8[0] == fb->modifier &&
        v.u8[1] == fb->fragbits)
    {
        return true;
    }
    return false;
}

static int PrefilterSetupFragBits(DetectEngineCtx *de_ctx, SigGroupHead *sgh)
{
    return PrefilterSetupPacketHeader(de_ctx, sgh, DETECT_FRAGBITS,
        PrefilterPacketFragBitsSet,
        PrefilterPacketFragBitsCompare,
        PrefilterPacketFragBitsMatch);
}

static bool PrefilterFragBitsIsPrefilterable(const Signature *s)
{
    const SigMatch *sm;
    for (sm = s->init_data->smlists[DETECT_SM_LIST_MATCH] ; sm != NULL; sm = sm->next) {
        switch (sm->type) {
            case DETECT_FRAGBITS:
                return true;
        }
    }
    return false;
}

/*
 * ONLY TESTS BELOW THIS COMMENT
 */

#ifdef UNITTESTS
#include "util-unittest-helper.h"
#include "packet.h"

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
        DetectFragBitsFree(NULL, de);
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
        DetectFragBitsFree(NULL, de);
        return 0;
    }

    return 1;
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
    Packet *p = PacketGetFromAlloc();
    FAIL_IF(unlikely(p == NULL));
    ThreadVars tv;
    DecodeThreadVars dtv;
    IPV4Hdr ipv4h;
    int ret = 0;
    DetectFragBitsData *de = NULL;
    SigMatch *sm = NULL;

    memset(&tv, 0, sizeof(ThreadVars));
    memset(&dtv, 0, sizeof(DecodeThreadVars));
    memset(&ipv4h, 0, sizeof(IPV4Hdr));
    dtv.app_tctx = AppLayerGetCtxThread(&tv);

    p->ip4h = &ipv4h;

    FlowInitConfig(FLOW_QUIET);

    DecodeEthernet(&tv, &dtv, p, raw_eth, sizeof(raw_eth));

    de = DetectFragBitsParse("D");

    FAIL_IF(de == NULL || (de->fragbits != FRAGBITS_HAVE_DF));

    sm = SigMatchAlloc();
    FAIL_IF(sm == NULL);

    sm->type = DETECT_FRAGBITS;
    sm->ctx = (SigMatchCtx *)de;

    ret = DetectFragBitsMatch(NULL, p, NULL, sm->ctx);
    FAIL_IF(ret == 0);

    FlowShutdown();
    SCFree(de);
    SCFree(sm);
    SCFree(p);
    PASS;
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
    Packet *p = PacketGetFromAlloc();
    FAIL_IF(unlikely(p == NULL));
    ThreadVars tv;
    DecodeThreadVars dtv;
    IPV4Hdr ipv4h;
    int ret = 0;
    DetectFragBitsData *de = NULL;
    SigMatch *sm = NULL;

    memset(&tv, 0, sizeof(ThreadVars));
    memset(&dtv, 0, sizeof(DecodeThreadVars));
    memset(&ipv4h, 0, sizeof(IPV4Hdr));
    dtv.app_tctx = AppLayerGetCtxThread(&tv);

    p->ip4h = &ipv4h;

    FlowInitConfig(FLOW_QUIET);

    DecodeEthernet(&tv, &dtv, p, raw_eth, sizeof(raw_eth));


    de = DetectFragBitsParse("!D");

    FAIL_IF(de == NULL);
    FAIL_IF(de->fragbits != FRAGBITS_HAVE_DF);
    FAIL_IF(de->modifier != MODIFIER_NOT);

    sm = SigMatchAlloc();
    FAIL_IF(sm == NULL);

    sm->type = DETECT_FRAGBITS;
    sm->ctx = (SigMatchCtx *)de;

    ret = DetectFragBitsMatch(NULL, p, NULL, sm->ctx);
    FAIL_IF(ret);
    SCFree(de);
    SCFree(sm);
    PacketRecycle(p);
    FlowShutdown();
    SCFree(p);
    PASS;
}

/**
 * \brief this function registers unit tests for FragBits
 */
static void FragBitsRegisterTests(void)
{
    UtRegisterTest("FragBitsTestParse01", FragBitsTestParse01);
    UtRegisterTest("FragBitsTestParse02", FragBitsTestParse02);
    UtRegisterTest("FragBitsTestParse03", FragBitsTestParse03);
    UtRegisterTest("FragBitsTestParse04", FragBitsTestParse04);
}
#endif /* UNITTESTS */
