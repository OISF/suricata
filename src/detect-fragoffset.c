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
 * \author Breno Silva <breno.silva@gmail.com>
 *
 * Implements fragoffset keyword
 */

#include "suricata-common.h"
#include "decode.h"
#include "decode-ipv4.h"
#include "decode-ipv6.h"

#include "detect.h"
#include "detect-parse.h"
#include "detect-engine-prefilter-common.h"
#include "detect-engine-build.h"

#include "detect-fragoffset.h"

#include "util-byte.h"
#include "util-unittest.h"
#include "util-debug.h"

#define PARSE_REGEX "^\\s*(?:(<|>))?\\s*([0-9]+)"

static DetectParseRegex parse_regex;

static int DetectFragOffsetMatch(DetectEngineThreadCtx *,
        Packet *, const Signature *, const SigMatchCtx *);
static int DetectFragOffsetSetup(DetectEngineCtx *, Signature *, const char *);
#ifdef UNITTESTS
void DetectFragOffsetRegisterTests(void);
#endif
void DetectFragOffsetFree(DetectEngineCtx *, void *);

static int PrefilterSetupFragOffset(DetectEngineCtx *de_ctx, SigGroupHead *sgh);
static bool PrefilterFragOffsetIsPrefilterable(const Signature *s);

/**
 * \brief Registration function for fragoffset
 */
void DetectFragOffsetRegister (void)
{
    sigmatch_table[DETECT_FRAGOFFSET].name = "fragoffset";
    sigmatch_table[DETECT_FRAGOFFSET].desc = "match on specific decimal values of the IP fragment offset field";
    sigmatch_table[DETECT_FRAGOFFSET].url = "/rules/header-keywords.html#fragoffset";
    sigmatch_table[DETECT_FRAGOFFSET].Match = DetectFragOffsetMatch;
    sigmatch_table[DETECT_FRAGOFFSET].Setup = DetectFragOffsetSetup;
    sigmatch_table[DETECT_FRAGOFFSET].Free = DetectFragOffsetFree;
#ifdef UNITTESTS
    sigmatch_table[DETECT_FRAGOFFSET].RegisterTests = DetectFragOffsetRegisterTests;
#endif
    sigmatch_table[DETECT_FRAGOFFSET].SupportsPrefilter = PrefilterFragOffsetIsPrefilterable;
    sigmatch_table[DETECT_FRAGOFFSET].SetupPrefilter = PrefilterSetupFragOffset;

    DetectSetupParseRegexes(PARSE_REGEX, &parse_regex);
}

static inline int FragOffsetMatch(const uint16_t poffset, const uint8_t mode,
                                  const uint16_t doffset)
{
    switch (mode)  {
        case FRAG_LESS:
            if (poffset < doffset)
                return 1;
            break;
        case FRAG_MORE:
            if (poffset > doffset)
                return 1;
            break;
        default:
            if (poffset == doffset)
                return 1;
    }
    return 0;
}

/**
 * \brief This function is used to match fragoffset rule option set on a packet
 *
 * \param t pointer to thread vars
 * \param det_ctx pointer to the pattern matcher thread
 * \param p pointer to the current packet
 * \param m pointer to the sigmatch that we will cast into DetectFragOffsetData
 *
 * \retval 0 no match or frag is not set
 * \retval 1 match
 *
 */
static int DetectFragOffsetMatch (DetectEngineThreadCtx *det_ctx,
        Packet *p, const Signature *s, const SigMatchCtx *ctx)
{
    uint16_t frag = 0;
    const DetectFragOffsetData *fragoff = (const DetectFragOffsetData *)ctx;

    if (PKT_IS_PSEUDOPKT(p))
        return 0;

    if (PKT_IS_IPV4(p)) {
        frag = IPV4_GET_IPOFFSET(p);
    } else if (PKT_IS_IPV6(p)) {
        if (IPV6_EXTHDR_ISSET_FH(p)) {
            frag = IPV6_EXTHDR_GET_FH_OFFSET(p);
        } else {
            return 0;
        }
    } else {
        SCLogDebug("No IPv4 or IPv6 packet");
        return 0;
    }

    return FragOffsetMatch(frag, fragoff->mode, fragoff->frag_off);;
}

/**
 * \brief This function is used to parse fragoffset option passed via fragoffset: keyword
 *
 * \param de_ctx Pointer to the detection engine context
 * \param fragoffsetstr Pointer to the user provided fragoffset options
 *
 * \retval fragoff pointer to DetectFragOffsetData on success
 * \retval NULL on failure
 */
static DetectFragOffsetData *DetectFragOffsetParse (DetectEngineCtx *de_ctx, const char *fragoffsetstr)
{
    DetectFragOffsetData *fragoff = NULL;
    char *substr[3] = {NULL, NULL, NULL};
    int ret = 0, res = 0;
    size_t pcre2_len;
    int i;
    const char *str_ptr;
    char *mode = NULL;

    ret = DetectParsePcreExec(&parse_regex, fragoffsetstr, 0, 0);
    if (ret < 1 || ret > 4) {
        SCLogError(SC_ERR_PCRE_MATCH,"Parse error %s", fragoffsetstr);
        goto error;
    }

    for (i = 1; i < ret; i++) {
        res = SC_Pcre2SubstringGet(parse_regex.match, i, (PCRE2_UCHAR8 **)&str_ptr, &pcre2_len);
        if (res < 0) {
            SCLogError(SC_ERR_PCRE_GET_SUBSTRING, "pcre2_substring_get_bynumber failed");
            goto error;
        }
        substr[i-1] = (char *)str_ptr;
    }

    fragoff = SCMalloc(sizeof(DetectFragOffsetData));
    if (unlikely(fragoff == NULL))
        goto error;

    fragoff->frag_off = 0;
    fragoff->mode = 0;

    mode = substr[0];

    if(mode != NULL)    {

        while(*mode != '\0')    {
            switch(*mode)   {
                case '>':
                    fragoff->mode = FRAG_MORE;
                    break;
                case '<':
                    fragoff->mode = FRAG_LESS;
                    break;
            }
            mode++;
        }
    }

    if (StringParseUint16(&fragoff->frag_off, 10, 0, substr[1]) < 0) {
        SCLogError(SC_ERR_INVALID_ARGUMENT, "specified frag offset %s is not "
                                        "valid", substr[1]);
        goto error;
    }

    for (i = 0; i < 3; i++) {
        if (substr[i] != NULL)
            pcre2_substring_free((PCRE2_UCHAR8 *)substr[i]);
    }

    return fragoff;

error:
    for (i = 0; i < 3; i++) {
        if (substr[i] != NULL)
            pcre2_substring_free((PCRE2_UCHAR8 *)substr[i]);
    }
    if (fragoff != NULL) DetectFragOffsetFree(de_ctx, fragoff);
    return NULL;

}

/**
 * \brief this function is used to add the parsed fragoffset data into the current signature
 *
 * \param de_ctx pointer to the Detection Engine Context
 * \param s pointer to the Current Signature
 * \param fragoffsetstr pointer to the user provided fragoffset option
 *
 * \retval 0 on Success
 * \retval -1 on Failure
 */
static int DetectFragOffsetSetup (DetectEngineCtx *de_ctx, Signature *s, const char *fragoffsetstr)
{
    DetectFragOffsetData *fragoff = NULL;
    SigMatch *sm = NULL;

    fragoff = DetectFragOffsetParse(de_ctx, fragoffsetstr);
    if (fragoff == NULL) goto error;

    sm = SigMatchAlloc();
    if (sm == NULL) goto error;

    sm->type = DETECT_FRAGOFFSET;
    sm->ctx = (SigMatchCtx *)fragoff;

    SigMatchAppendSMToList(s, sm, DETECT_SM_LIST_MATCH);
    s->flags |= SIG_FLAG_REQUIRE_PACKET;

    return 0;

error:
    if (fragoff != NULL) DetectFragOffsetFree(de_ctx, fragoff);
    if (sm != NULL) SCFree(sm);
    return -1;

}

/**
 * \brief this function will free memory associated with DetectFragOffsetData
 *
 * \param ptr pointer to DetectFragOffsetData
 */
void DetectFragOffsetFree (DetectEngineCtx *de_ctx, void *ptr)
{
    DetectFragOffsetData *fragoff = (DetectFragOffsetData *)ptr;
    SCFree(fragoff);
}

static void
PrefilterPacketFragOffsetMatch(DetectEngineThreadCtx *det_ctx, Packet *p, const void *pectx)
{
    if (PKT_IS_PSEUDOPKT(p))
        return;

    uint16_t frag;

    if (PKT_IS_IPV4(p)) {
        frag = IPV4_GET_IPOFFSET(p);
    } else if (PKT_IS_IPV6(p)) {
        if (IPV6_EXTHDR_ISSET_FH(p)) {
            frag = IPV6_EXTHDR_GET_FH_OFFSET(p);
        } else {
            return;
        }
    } else {
        SCLogDebug("No IPv4 or IPv6 packet");
        return;
    }

    const PrefilterPacketHeaderCtx *ctx = pectx;
    if (FragOffsetMatch(frag, ctx->v1.u8[0], ctx->v1.u16[1]))
    {
        PrefilterAddSids(&det_ctx->pmq, ctx->sigs_array, ctx->sigs_cnt);
    }
}

static void
PrefilterPacketFragOffsetSet(PrefilterPacketHeaderValue *v, void *smctx)
{
    const DetectFragOffsetData *fb = smctx;
    v->u8[0] = fb->mode;
    v->u16[1] = fb->frag_off;
}

static bool
PrefilterPacketFragOffsetCompare(PrefilterPacketHeaderValue v, void *smctx)
{
    const DetectFragOffsetData *fb = smctx;
    if (v.u8[0] == fb->mode &&
        v.u16[1] == fb->frag_off)
    {
        return true;
    }
    return false;
}

static int PrefilterSetupFragOffset(DetectEngineCtx *de_ctx, SigGroupHead *sgh)
{
    return PrefilterSetupPacketHeader(de_ctx, sgh, DETECT_FRAGOFFSET,
        PrefilterPacketFragOffsetSet,
        PrefilterPacketFragOffsetCompare,
        PrefilterPacketFragOffsetMatch);
}

static bool PrefilterFragOffsetIsPrefilterable(const Signature *s)
{
    const SigMatch *sm;
    for (sm = s->init_data->smlists[DETECT_SM_LIST_MATCH] ; sm != NULL; sm = sm->next) {
        switch (sm->type) {
            case DETECT_FRAGOFFSET:
                return true;
        }
    }
    return false;
}

#ifdef UNITTESTS
#include "util-unittest-helper.h"

/**
 * \test DetectFragOffsetParseTest01 is a test for setting a valid fragoffset value
 */
static int DetectFragOffsetParseTest01 (void)
{
    DetectFragOffsetData *fragoff = DetectFragOffsetParse(NULL, "300");

    FAIL_IF_NULL(fragoff);
    FAIL_IF_NOT(fragoff->frag_off == 300);

    DetectFragOffsetFree(NULL, fragoff);

    PASS;
}

/**
 * \test DetectFragOffsetParseTest02 is a test for setting a valid fragoffset value
 *       with spaces all around
 */
static int DetectFragOffsetParseTest02 (void)
{
    DetectFragOffsetData *fragoff = DetectFragOffsetParse(NULL, ">300");

    FAIL_IF_NULL(fragoff);
    FAIL_IF_NOT(fragoff->frag_off == 300);
    FAIL_IF_NOT(fragoff->mode == FRAG_MORE);

    DetectFragOffsetFree(NULL, fragoff);

    PASS;
}

/**
 * \test DetectFragOffsetParseTest03 is a test for setting an invalid fragoffset value
 */
static int DetectFragOffsetParseTest03 (void)
{
    DetectFragOffsetData *fragoff = DetectFragOffsetParse(NULL, "badc");

    FAIL_IF_NOT_NULL(fragoff);

    PASS;
}

/**
 * \test DetectFragOffsetMatchTest01 is a test for checking the working of
 *       fragoffset keyword by creating 2 rules and matching a crafted packet
 *       against them. Only the first one shall trigger.
 */
static int DetectFragOffsetMatchTest01 (void)
{
    Packet *p = PacketGetFromAlloc();

    FAIL_IF_NULL(p);
    Signature *s = NULL;
    DecodeThreadVars dtv;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx = NULL;
    IPV4Hdr ip4h;

    memset(&ip4h, 0, sizeof(IPV4Hdr));
    memset(&dtv, 0, sizeof(DecodeThreadVars));
    memset(&th_v, 0, sizeof(ThreadVars));

    FlowInitConfig(FLOW_QUIET);

    p->src.family = AF_INET;
    p->dst.family = AF_INET;
    p->src.addr_data32[0] = 0x01020304;
    p->dst.addr_data32[0] = 0x04030201;

    ip4h.s_ip_src.s_addr = p->src.addr_data32[0];
    ip4h.s_ip_dst.s_addr = p->dst.addr_data32[0];
    ip4h.ip_off = 0x2222;
    p->ip4h = &ip4h;

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);

    de_ctx->flags |= DE_QUIET;

    s = DetectEngineAppendSig(de_ctx, "alert ip any any -> any any (fragoffset:546; sid:1;)");
    FAIL_IF_NULL(s);

    s = DetectEngineAppendSig(de_ctx, "alert ip any any -> any any (fragoffset:5000; sid:2;)");
    FAIL_IF_NULL(s);

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);

    FAIL_IF(PacketAlertCheck(p, 1) == 0);
    FAIL_IF(PacketAlertCheck(p, 2));

    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);

    FlowShutdown();

    SCFree(p);
    PASS;
}

void DetectFragOffsetRegisterTests (void)
{
    UtRegisterTest("DetectFragOffsetParseTest01", DetectFragOffsetParseTest01);
    UtRegisterTest("DetectFragOffsetParseTest02", DetectFragOffsetParseTest02);
    UtRegisterTest("DetectFragOffsetParseTest03", DetectFragOffsetParseTest03);
    UtRegisterTest("DetectFragOffsetMatchTest01", DetectFragOffsetMatchTest01);
}
#endif /* UNITTESTS */
