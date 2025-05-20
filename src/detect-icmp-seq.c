/* Copyright (C) 2007-2022 Open Information Security Foundation
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
 * Implements the icmp_seq keyword
 */

#include "suricata-common.h"
#include "decode.h"

#include "detect.h"
#include "detect-parse.h"
#include "detect-engine-prefilter-common.h"
#include "detect-engine-build.h"

#include "detect-icmp-seq.h"

#include "util-byte.h"
#include "util-unittest.h"
#include "util-unittest-helper.h"
#include "util-debug.h"

#define PARSE_REGEX "^\\s*(\"\\s*)?([0-9]+)(\\s*\")?\\s*$"

static DetectParseRegex parse_regex;

static int DetectIcmpSeqMatch(DetectEngineThreadCtx *, Packet *,
        const Signature *, const SigMatchCtx *);
static int DetectIcmpSeqSetup(DetectEngineCtx *, Signature *, const char *);
#ifdef UNITTESTS
static void DetectIcmpSeqRegisterTests(void);
#endif
void DetectIcmpSeqFree(DetectEngineCtx *, void *);
static int PrefilterSetupIcmpSeq(DetectEngineCtx *de_ctx, SigGroupHead *sgh);
static bool PrefilterIcmpSeqIsPrefilterable(const Signature *s);

/**
 * \brief Registration function for icmp_seq
 */
void DetectIcmpSeqRegister (void)
{
    sigmatch_table[DETECT_ICMP_SEQ].name = "icmp_seq";
    sigmatch_table[DETECT_ICMP_SEQ].desc = "check for a ICMP sequence number";
    sigmatch_table[DETECT_ICMP_SEQ].url = "/rules/header-keywords.html#icmp-seq";
    sigmatch_table[DETECT_ICMP_SEQ].Match = DetectIcmpSeqMatch;
    sigmatch_table[DETECT_ICMP_SEQ].Setup = DetectIcmpSeqSetup;
    sigmatch_table[DETECT_ICMP_SEQ].Free = DetectIcmpSeqFree;
#ifdef UNITTESTS
    sigmatch_table[DETECT_ICMP_SEQ].RegisterTests = DetectIcmpSeqRegisterTests;
#endif
    sigmatch_table[DETECT_ICMP_SEQ].SupportsPrefilter = PrefilterIcmpSeqIsPrefilterable;
    sigmatch_table[DETECT_ICMP_SEQ].SetupPrefilter = PrefilterSetupIcmpSeq;

    DetectSetupParseRegexes(PARSE_REGEX, &parse_regex);
}

static inline bool GetIcmpSeq(Packet *p, uint16_t *seq)
{
    uint16_t seqn;

    if (PacketIsICMPv4(p)) {
        switch (p->icmp_s.type) {
            case ICMP_ECHOREPLY:
            case ICMP_ECHO:
            case ICMP_TIMESTAMP:
            case ICMP_TIMESTAMPREPLY:
            case ICMP_INFO_REQUEST:
            case ICMP_INFO_REPLY:
            case ICMP_ADDRESS:
            case ICMP_ADDRESSREPLY:
                SCLogDebug("ICMPV4_GET_SEQ(p) %"PRIu16" (network byte order), "
                        "%"PRIu16" (host byte order)", ICMPV4_GET_SEQ(p),
                        SCNtohs(ICMPV4_GET_SEQ(p)));

                seqn = ICMPV4_GET_SEQ(p);
                break;
            default:
                SCLogDebug("Packet has no seq field");
                return false;
        }
    } else if (PacketIsICMPv6(p)) {
        switch (ICMPV6_GET_TYPE(PacketGetICMPv6(p))) {
            case ICMP6_ECHO_REQUEST:
            case ICMP6_ECHO_REPLY:
                SCLogDebug("ICMPV6_GET_SEQ(p) %"PRIu16" (network byte order), "
                        "%"PRIu16" (host byte order)", ICMPV6_GET_SEQ(p),
                        SCNtohs(ICMPV6_GET_SEQ(p)));

                seqn = ICMPV6_GET_SEQ(p);
                break;
            default:
                SCLogDebug("Packet has no seq field");
                return false;
        }
    } else {
        SCLogDebug("Packet not ICMPV4 nor ICMPV6");
        return false;
    }

    *seq = seqn;
    return true;
}

/**
 * \brief This function is used to match icmp_seq rule option set on a packet
 *
 * \param t pointer to thread vars
 * \param det_ctx pointer to the pattern matcher thread
 * \param p pointer to the current packet
 * \param m pointer to the sigmatch that we will cast into DetectIcmpSeqData
 *
 * \retval 0 no match
 * \retval 1 match
 */
static int DetectIcmpSeqMatch (DetectEngineThreadCtx *det_ctx, Packet *p,
        const Signature *s, const SigMatchCtx *ctx)
{
    DEBUG_VALIDATE_BUG_ON(PKT_IS_PSEUDOPKT(p));
    uint16_t seqn;

    if (!GetIcmpSeq(p, &seqn))
        return 0;

    const DetectIcmpSeqData *iseq = (const DetectIcmpSeqData *)ctx;
    if (seqn == iseq->seq)
        return 1;

    return 0;
}

/**
 * \brief This function is used to parse icmp_seq option passed via icmp_seq: keyword
 *
 * \param de_ctx Pointer to the detection engine context
 * \param icmpseqstr Pointer to the user provided icmp_seq options
 *
 * \retval iseq pointer to DetectIcmpSeqData on success
 * \retval NULL on failure
 */
static DetectIcmpSeqData *DetectIcmpSeqParse (DetectEngineCtx *de_ctx, const char *icmpseqstr)
{
    DetectIcmpSeqData *iseq = NULL;
    char *substr[3] = {NULL, NULL, NULL};
    int res = 0;
    size_t pcre2_len;
    int i;
    const char *str_ptr;

    pcre2_match_data *match = NULL;
    int ret = DetectParsePcreExec(&parse_regex, &match, icmpseqstr, 0, 0);
    if (ret < 1 || ret > 4) {
        SCLogError("Parse error %s", icmpseqstr);
        goto error;
    }

    for (i = 1; i < ret; i++) {
        res = SC_Pcre2SubstringGet(match, i, (PCRE2_UCHAR8 **)&str_ptr, &pcre2_len);
        if (res < 0) {
            SCLogError("pcre2_substring_get_bynumber failed");
            goto error;
        }
        substr[i-1] = (char *)str_ptr;
    }

    iseq = SCMalloc(sizeof(DetectIcmpSeqData));
    if (unlikely(iseq == NULL))
        goto error;

    iseq->seq = 0;

    if (substr[0] != NULL && strlen(substr[0]) != 0) {
        if (substr[2] == NULL) {
            SCLogError("Missing quote in input");
            goto error;
        }
    } else {
        if (substr[2] != NULL) {
            SCLogError("Missing quote in input");
            goto error;
        }
    }

    uint16_t seq = 0;
    if (StringParseUint16(&seq, 10, 0, substr[1]) < 0) {
        SCLogError("specified icmp seq %s is not "
                   "valid",
                substr[1]);
        goto error;
    }
    iseq->seq = htons(seq);

    for (i = 0; i < 3; i++) {
        if (substr[i] != NULL)
            pcre2_substring_free((PCRE2_UCHAR8 *)substr[i]);
    }

    pcre2_match_data_free(match);
    return iseq;

error:
    if (match) {
        pcre2_match_data_free(match);
    }
    for (i = 0; i < 3; i++) {
        if (substr[i] != NULL)
            pcre2_substring_free((PCRE2_UCHAR8 *)substr[i]);
    }
    if (iseq != NULL) DetectIcmpSeqFree(de_ctx, iseq);
    return NULL;

}

/**
 * \brief this function is used to add the parsed icmp_seq data into the current signature
 *
 * \param de_ctx pointer to the Detection Engine Context
 * \param s pointer to the Current Signature
 * \param icmpseqstr pointer to the user provided icmp_seq option
 *
 * \retval 0 on Success
 * \retval -1 on Failure
 */
static int DetectIcmpSeqSetup (DetectEngineCtx *de_ctx, Signature *s, const char *icmpseqstr)
{
    DetectIcmpSeqData *iseq = NULL;

    iseq = DetectIcmpSeqParse(de_ctx, icmpseqstr);
    if (iseq == NULL) goto error;

    if (SCSigMatchAppendSMToList(
                de_ctx, s, DETECT_ICMP_SEQ, (SigMatchCtx *)iseq, DETECT_SM_LIST_MATCH) == NULL) {
        goto error;
    }
    s->flags |= SIG_FLAG_REQUIRE_PACKET;

    return 0;

error:
    if (iseq != NULL)
        DetectIcmpSeqFree(de_ctx, iseq);
    return -1;

}

/**
 * \brief this function will free memory associated with DetectIcmpSeqData
 *
 * \param ptr pointer to DetectIcmpSeqData
 */
void DetectIcmpSeqFree (DetectEngineCtx *de_ctx, void *ptr)
{
    DetectIcmpSeqData *iseq = (DetectIcmpSeqData *)ptr;
    SCFree(iseq);
}

/* prefilter code */

static void
PrefilterPacketIcmpSeqMatch(DetectEngineThreadCtx *det_ctx, Packet *p, const void *pectx)
{
    DEBUG_VALIDATE_BUG_ON(PKT_IS_PSEUDOPKT(p));

    const PrefilterPacketHeaderCtx *ctx = pectx;
    uint16_t seqn;

    if (!GetIcmpSeq(p, &seqn))
        return;

    if (seqn == ctx->v1.u16[0])
    {
        SCLogDebug("packet matches ICMP SEQ %u", ctx->v1.u16[0]);
        PrefilterAddSids(&det_ctx->pmq, ctx->sigs_array, ctx->sigs_cnt);
    }
}

static void
PrefilterPacketIcmpSeqSet(PrefilterPacketHeaderValue *v, void *smctx)
{
    const DetectIcmpSeqData *a = smctx;
    v->u16[0] = a->seq;
}

static bool
PrefilterPacketIcmpSeqCompare(PrefilterPacketHeaderValue v, void *smctx)
{
    const DetectIcmpSeqData *a = smctx;
    if (v.u16[0] == a->seq)
        return true;
    return false;
}

static int PrefilterSetupIcmpSeq(DetectEngineCtx *de_ctx, SigGroupHead *sgh)
{
    return PrefilterSetupPacketHeader(de_ctx, sgh, DETECT_ICMP_SEQ, SIG_MASK_REQUIRE_REAL_PKT,
            PrefilterPacketIcmpSeqSet, PrefilterPacketIcmpSeqCompare, PrefilterPacketIcmpSeqMatch);
}

static bool PrefilterIcmpSeqIsPrefilterable(const Signature *s)
{
    const SigMatch *sm;
    for (sm = s->init_data->smlists[DETECT_SM_LIST_MATCH] ; sm != NULL; sm = sm->next) {
        switch (sm->type) {
            case DETECT_ICMP_SEQ:
                return true;
        }
    }
    return false;
}

#ifdef UNITTESTS
#include "detect-engine.h"
#include "detect-engine-mpm.h"
#include "detect-engine-alert.h"

/**
 * \test DetectIcmpSeqParseTest01 is a test for setting a valid icmp_seq value
 */
static int DetectIcmpSeqParseTest01 (void)
{
    DetectIcmpSeqData *iseq = NULL;
    iseq = DetectIcmpSeqParse(NULL, "300");
    FAIL_IF_NULL(iseq);
    FAIL_IF_NOT(htons(iseq->seq) == 300);
    DetectIcmpSeqFree(NULL, iseq);
    PASS;
}

/**
 * \test DetectIcmpSeqParseTest02 is a test for setting a valid icmp_seq value
 *       with spaces all around
 */
static int DetectIcmpSeqParseTest02 (void)
{
    DetectIcmpSeqData *iseq = NULL;
    iseq = DetectIcmpSeqParse(NULL, "  300  ");
    FAIL_IF_NULL(iseq);
    FAIL_IF_NOT(htons(iseq->seq) == 300);
    DetectIcmpSeqFree(NULL, iseq);
    PASS;
}

/**
 * \test DetectIcmpSeqParseTest03 is a test for setting an invalid icmp_seq value
 */
static int DetectIcmpSeqParseTest03 (void)
{
    DetectIcmpSeqData *iseq = DetectIcmpSeqParse(NULL, "badc");
    FAIL_IF_NOT_NULL(iseq);
    PASS;
}

static void DetectIcmpSeqRegisterTests (void)
{
    UtRegisterTest("DetectIcmpSeqParseTest01", DetectIcmpSeqParseTest01);
    UtRegisterTest("DetectIcmpSeqParseTest02", DetectIcmpSeqParseTest02);
    UtRegisterTest("DetectIcmpSeqParseTest03", DetectIcmpSeqParseTest03);
}
#endif /* UNITTESTS */
