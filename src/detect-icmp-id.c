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
 * \author Gerardo Iglesias Galvan <iglesiasg@gmail.com>
 *
 * Implements the icmp_id keyword
 */

#include "suricata-common.h"
#include "decode.h"

#include "detect.h"
#include "detect-parse.h"
#include "detect-engine-prefilter-common.h"
#include "detect-engine-build.h"

#include "detect-icmp-id.h"

#include "util-byte.h"
#include "util-unittest.h"
#include "util-unittest-helper.h"
#include "util-debug.h"

#define PARSE_REGEX "^\\s*(\"\\s*)?([0-9]+)(\\s*\")?\\s*$"

static DetectParseRegex parse_regex;

static int DetectIcmpIdMatch(DetectEngineThreadCtx *, Packet *,
        const Signature *, const SigMatchCtx *);
static int DetectIcmpIdSetup(DetectEngineCtx *, Signature *, const char *);
#ifdef UNITTESTS
static void DetectIcmpIdRegisterTests(void);
#endif
void DetectIcmpIdFree(DetectEngineCtx *, void *);
static int PrefilterSetupIcmpId(DetectEngineCtx *de_ctx, SigGroupHead *sgh);
static bool PrefilterIcmpIdIsPrefilterable(const Signature *s);

/**
 * \brief Registration function for icode: icmp_id
 */
void DetectIcmpIdRegister (void)
{
    sigmatch_table[DETECT_ICMP_ID].name = "icmp_id";
    sigmatch_table[DETECT_ICMP_ID].desc = "check for a ICMP ID";
    sigmatch_table[DETECT_ICMP_ID].url = "/rules/header-keywords.html#icmp-id";
    sigmatch_table[DETECT_ICMP_ID].Match = DetectIcmpIdMatch;
    sigmatch_table[DETECT_ICMP_ID].Setup = DetectIcmpIdSetup;
    sigmatch_table[DETECT_ICMP_ID].Free = DetectIcmpIdFree;
#ifdef UNITTESTS
    sigmatch_table[DETECT_ICMP_ID].RegisterTests = DetectIcmpIdRegisterTests;
#endif
    sigmatch_table[DETECT_ICMP_ID].SupportsPrefilter = PrefilterIcmpIdIsPrefilterable;
    sigmatch_table[DETECT_ICMP_ID].SetupPrefilter = PrefilterSetupIcmpId;

    DetectSetupParseRegexes(PARSE_REGEX, &parse_regex);
}

static inline bool GetIcmpId(Packet *p, uint16_t *id)
{
    if (PKT_IS_PSEUDOPKT(p))
        return false;

    uint16_t pid;
    if (PKT_IS_ICMPV4(p)) {
        switch (ICMPV4_GET_TYPE(p)){
            case ICMP_ECHOREPLY:
            case ICMP_ECHO:
            case ICMP_TIMESTAMP:
            case ICMP_TIMESTAMPREPLY:
            case ICMP_INFO_REQUEST:
            case ICMP_INFO_REPLY:
            case ICMP_ADDRESS:
            case ICMP_ADDRESSREPLY:
                SCLogDebug("ICMPV4_GET_ID(p) %"PRIu16" (network byte order), "
                        "%"PRIu16" (host byte order)", ICMPV4_GET_ID(p),
                        SCNtohs(ICMPV4_GET_ID(p)));

                pid = ICMPV4_GET_ID(p);
                break;
            default:
                SCLogDebug("Packet has no id field");
                return false;
        }
    } else if (PKT_IS_ICMPV6(p)) {
        switch (ICMPV6_GET_TYPE(p)) {
            case ICMP6_ECHO_REQUEST:
            case ICMP6_ECHO_REPLY:
                SCLogDebug("ICMPV6_GET_ID(p) %"PRIu16" (network byte order), "
                        "%"PRIu16" (host byte order)", ICMPV6_GET_ID(p),
                        SCNtohs(ICMPV6_GET_ID(p)));

                pid = ICMPV6_GET_ID(p);
                break;
            default:
                SCLogDebug("Packet has no id field");
                return false;
        }
    } else {
        SCLogDebug("Packet not ICMPV4 nor ICMPV6");
        return false;
    }

    *id = pid;
    return true;
}

/**
 * \brief This function is used to match icmp_id rule option set on a packet
 *
 * \param t pointer to thread vars
 * \param det_ctx pointer to the pattern matcher thread
 * \param p pointer to the current packet
 * \param m pointer to the sigmatch that we will cast into DetectIcmpIdData
 *
 * \retval 0 no match
 * \retval 1 match
 */
static int DetectIcmpIdMatch (DetectEngineThreadCtx *det_ctx, Packet *p,
        const Signature *s, const SigMatchCtx *ctx)
{
    uint16_t pid;

    if (!GetIcmpId(p, &pid))
        return 0;

    const DetectIcmpIdData *iid = (const DetectIcmpIdData *)ctx;
    if (pid == iid->id)
        return 1;

    return 0;
}

/**
 * \brief This function is used to parse icmp_id option passed via icmp_id: keyword
 *
 * \param de_ctx Pointer to the detection engine context
 * \param icmpidstr Pointer to the user provided icmp_id options
 *
 * \retval iid pointer to DetectIcmpIdData on success
 * \retval NULL on failure
 */
static DetectIcmpIdData *DetectIcmpIdParse (DetectEngineCtx *de_ctx, const char *icmpidstr)
{
    DetectIcmpIdData *iid = NULL;
    char *substr[3] = {NULL, NULL, NULL};
    int ret = 0, res = 0;
    size_t pcre2_len;

    ret = DetectParsePcreExec(&parse_regex, icmpidstr, 0, 0);
    if (ret < 1 || ret > 4) {
        SCLogError(SC_ERR_PCRE_MATCH, "Parse error %s", icmpidstr);
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
        substr[i-1] = (char *)str_ptr;
    }

    iid = SCMalloc(sizeof(DetectIcmpIdData));
    if (unlikely(iid == NULL))
        goto error;
    iid->id = 0;

    if (substr[0]!= NULL && strlen(substr[0]) != 0) {
        if (substr[2] == NULL) {
            SCLogError(SC_ERR_INVALID_ARGUMENT, "Missing close quote in input");
            goto error;
        }
    } else {
        if (substr[2] != NULL) {
            SCLogError(SC_ERR_INVALID_ARGUMENT, "Missing open quote in input");
            goto error;
        }
    }

    uint16_t id = 0;
    if (StringParseUint16(&id, 10, 0, substr[1]) < 0) {
        SCLogError(SC_ERR_INVALID_ARGUMENT, "specified icmp id %s is not "
                                        "valid", substr[1]);
        goto error;
    }
    iid->id = htons(id);

    for (i = 0; i < 3; i++) {
        if (substr[i] != NULL)
            pcre2_substring_free((PCRE2_UCHAR8 *)substr[i]);
    }
    return iid;

error:
    for (i = 0; i < 3; i++) {
        if (substr[i] != NULL)
            pcre2_substring_free((PCRE2_UCHAR8 *)substr[i]);
    }
    if (iid != NULL) DetectIcmpIdFree(de_ctx, iid);
    return NULL;

}

/**
 * \brief this function is used to add the parsed icmp_id data into the current signature
 *
 * \param de_ctx pointer to the Detection Engine Context
 * \param s pointer to the Current Signature
 * \param icmpidstr pointer to the user provided icmp_id option
 *
 * \retval 0 on Success
 * \retval -1 on Failure
 */
static int DetectIcmpIdSetup (DetectEngineCtx *de_ctx, Signature *s, const char *icmpidstr)
{
    DetectIcmpIdData *iid = NULL;
    SigMatch *sm = NULL;

    iid = DetectIcmpIdParse(de_ctx, icmpidstr);
    if (iid == NULL) goto error;

    sm = SigMatchAlloc();
    if (sm == NULL) goto error;

    sm->type = DETECT_ICMP_ID;
    sm->ctx = (SigMatchCtx *)iid;

    SigMatchAppendSMToList(s, sm, DETECT_SM_LIST_MATCH);
    s->flags |= SIG_FLAG_REQUIRE_PACKET;

    return 0;

error:
    if (iid != NULL) DetectIcmpIdFree(de_ctx, iid);
    if (sm != NULL) SCFree(sm);
    return -1;

}

/**
 * \brief this function will free memory associated with DetectIcmpIdData
 *
 * \param ptr pointer to DetectIcmpIdData
 */
void DetectIcmpIdFree (DetectEngineCtx *de_ctx, void *ptr)
{
    DetectIcmpIdData *iid = (DetectIcmpIdData *)ptr;
    SCFree(iid);
}

/* prefilter code */

static void
PrefilterPacketIcmpIdMatch(DetectEngineThreadCtx *det_ctx, Packet *p, const void *pectx)
{
    const PrefilterPacketHeaderCtx *ctx = pectx;

    uint16_t pid;
    if (!GetIcmpId(p, &pid))
        return;

    if (pid == ctx->v1.u16[0])
    {
        SCLogDebug("packet matches ICMP ID %u", ctx->v1.u16[0]);
        PrefilterAddSids(&det_ctx->pmq, ctx->sigs_array, ctx->sigs_cnt);
    }
}

static void
PrefilterPacketIcmpIdSet(PrefilterPacketHeaderValue *v, void *smctx)
{
    const DetectIcmpIdData *a = smctx;
    v->u16[0] = a->id;
}

static bool
PrefilterPacketIcmpIdCompare(PrefilterPacketHeaderValue v, void *smctx)
{
    const DetectIcmpIdData *a = smctx;
    if (v.u16[0] == a->id)
        return true;
    return false;
}

static int PrefilterSetupIcmpId(DetectEngineCtx *de_ctx, SigGroupHead *sgh)
{
    return PrefilterSetupPacketHeader(de_ctx, sgh, DETECT_ICMP_ID,
        PrefilterPacketIcmpIdSet,
        PrefilterPacketIcmpIdCompare,
        PrefilterPacketIcmpIdMatch);
}

static bool PrefilterIcmpIdIsPrefilterable(const Signature *s)
{
    const SigMatch *sm;
    for (sm = s->init_data->smlists[DETECT_SM_LIST_MATCH] ; sm != NULL; sm = sm->next) {
        switch (sm->type) {
            case DETECT_ICMP_ID:
                return true;
        }
    }
    return false;
}

#ifdef UNITTESTS
#include "detect-engine.h"
#include "detect-engine-mpm.h"

/**
 * \test DetectIcmpIdParseTest01 is a test for setting a valid icmp_id value
 */
static int DetectIcmpIdParseTest01 (void)
{
    DetectIcmpIdData *iid = DetectIcmpIdParse(NULL, "300");
    FAIL_IF_NULL(iid);
    FAIL_IF_NOT(iid->id == htons(300));
    DetectIcmpIdFree(NULL, iid);
    PASS;
}

/**
 * \test DetectIcmpIdParseTest02 is a test for setting a valid icmp_id value
 *       with spaces all around
 */
static int DetectIcmpIdParseTest02 (void)
{
    DetectIcmpIdData *iid = DetectIcmpIdParse(NULL, "  300  ");
    FAIL_IF_NULL(iid);
    FAIL_IF_NOT(iid->id == htons(300));
    DetectIcmpIdFree(NULL, iid);
    PASS;
}

/**
 * \test DetectIcmpIdParseTest03 is a test for setting a valid icmp_id value
 *       with quotation marks
 */
static int DetectIcmpIdParseTest03 (void)
{
    DetectIcmpIdData *iid = DetectIcmpIdParse(NULL, "\"300\"");
    FAIL_IF_NULL(iid);
    FAIL_IF_NOT(iid->id == htons(300));
    DetectIcmpIdFree(NULL, iid);
    PASS;
}

/**
 * \test DetectIcmpIdParseTest04 is a test for setting a valid icmp_id value
 *       with quotation marks and spaces all around
 */
static int DetectIcmpIdParseTest04 (void)
{
    DetectIcmpIdData *iid = DetectIcmpIdParse(NULL, "   \"   300 \"");
    FAIL_IF_NULL(iid);
    FAIL_IF_NOT(iid->id == htons(300));
    DetectIcmpIdFree(NULL, iid);
    PASS;
}

/**
 * \test DetectIcmpIdParseTest05 is a test for setting an invalid icmp_id
 *       value with missing quotation marks
 */
static int DetectIcmpIdParseTest05 (void)
{
    DetectIcmpIdData *iid = DetectIcmpIdParse(NULL, "\"300");
    FAIL_IF_NOT_NULL(iid);
    PASS;
}

/**
 * \test DetectIcmpIdMatchTest01 is a test for checking the working of
 *       icmp_id keyword by creating 2 rules and matching a crafted packet
 *       against them. Only the first one shall trigger.
 */
static int DetectIcmpIdMatchTest01 (void)
{
    int result = 0;
    Packet *p = NULL;
    Signature *s = NULL;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx = NULL;

    memset(&th_v, 0, sizeof(ThreadVars));

    p = UTHBuildPacket(NULL, 0, IPPROTO_ICMP);
    p->icmpv4vars.id = htons(21781);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }

    de_ctx->flags |= DE_QUIET;

    s = de_ctx->sig_list = SigInit(de_ctx, "alert icmp any any -> any any (icmp_id:21781; sid:1;)");
    if (s == NULL) {
        goto end;
    }

    s = s->next = SigInit(de_ctx, "alert icmp any any -> any any (icmp_id:21782; sid:2;)");
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

    UTHFreePackets(&p, 1);
end:
    return result;

}

/**
 * \test DetectIcmpIdMatchTest02 is a test for checking the working of
 *       icmp_id keyword by creating 1 rule and matching a crafted packet
 *       against them. The packet is an ICMP packet with no "id" field,
 *       therefore the rule should not trigger.
 */
static int DetectIcmpIdMatchTest02 (void)
{
    int result = 0;

    uint8_t raw_icmpv4[] = {
        0x0b, 0x00, 0x8a, 0xdf, 0x00, 0x00, 0x00, 0x00,
        0x45, 0x00, 0x00, 0x14, 0x25, 0x0c, 0x00, 0x00,
        0xff, 0x11, 0x00, 0x00, 0x85, 0x64, 0xea, 0x5b,
        0x51, 0xa6, 0xbb, 0x35, 0x59, 0x8a, 0x5a, 0xe2,
        0x00, 0x14, 0x00, 0x00 };

    Packet *p = PacketGetFromAlloc();
    if (unlikely(p == NULL))
        return 0;
    Signature *s = NULL;
    DecodeThreadVars dtv;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx = NULL;
    IPV4Hdr ip4h;

    memset(&ip4h, 0, sizeof(IPV4Hdr));
    memset(&dtv, 0, sizeof(DecodeThreadVars));
    memset(&th_v, 0, sizeof(ThreadVars));

    FlowInitConfig(FLOW_QUIET);

    p->src.addr_data32[0] = 0x01020304;
    p->dst.addr_data32[0] = 0x04030201;

    ip4h.s_ip_src.s_addr = p->src.addr_data32[0];
    ip4h.s_ip_dst.s_addr = p->dst.addr_data32[0];
    p->ip4h = &ip4h;

    DecodeICMPV4(&th_v, &dtv, p, raw_icmpv4, sizeof(raw_icmpv4));

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }

    de_ctx->flags |= DE_QUIET;

    s = de_ctx->sig_list = SigInit(de_ctx, "alert icmp any any -> any any (icmp_id:0; sid:1;)");
    if (s == NULL) {
        goto end;
    }

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    if (PacketAlertCheck(p, 1)) {
        printf("sid 1 alerted, but should not have: ");
        goto cleanup;
    }

    result = 1;

cleanup:
    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);

    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);

    FlowShutdown();
end:
    SCFree(p);
    return result;
}

static void DetectIcmpIdRegisterTests (void)
{
    UtRegisterTest("DetectIcmpIdParseTest01", DetectIcmpIdParseTest01);
    UtRegisterTest("DetectIcmpIdParseTest02", DetectIcmpIdParseTest02);
    UtRegisterTest("DetectIcmpIdParseTest03", DetectIcmpIdParseTest03);
    UtRegisterTest("DetectIcmpIdParseTest04", DetectIcmpIdParseTest04);
    UtRegisterTest("DetectIcmpIdParseTest05", DetectIcmpIdParseTest05);
    UtRegisterTest("DetectIcmpIdMatchTest01", DetectIcmpIdMatchTest01);
    UtRegisterTest("DetectIcmpIdMatchTest02", DetectIcmpIdMatchTest02);
}
#endif /* UNITTESTS */
