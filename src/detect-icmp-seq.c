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
 * Implements the icmp_seq keyword
 */

#include "suricata-common.h"
#include "debug.h"
#include "decode.h"

#include "detect.h"
#include "detect-parse.h"

#include "detect-icmp-seq.h"

#include "util-byte.h"
#include "util-unittest.h"
#include "util-unittest-helper.h"
#include "util-debug.h"

#define PARSE_REGEX "^\\s*(\"\\s*)?([0-9]+)(\\s*\")?\\s*$"

static pcre *parse_regex;
static pcre_extra *parse_regex_study;

int DetectIcmpSeqMatch(ThreadVars *, DetectEngineThreadCtx *, Packet *, Signature *, const SigMatchCtx *);
static int DetectIcmpSeqSetup(DetectEngineCtx *, Signature *, char *);
void DetectIcmpSeqRegisterTests(void);
void DetectIcmpSeqFree(void *);

/**
 * \brief Registration function for icmp_seq
 */
void DetectIcmpSeqRegister (void)
{
    sigmatch_table[DETECT_ICMP_SEQ].name = "icmp_seq";
    sigmatch_table[DETECT_ICMP_SEQ].desc = "check for a ICMP sequence number";
    sigmatch_table[DETECT_ICMP_SEQ].url = "https://redmine.openinfosecfoundation.org/projects/suricata/wiki/Header_keywords#icmp_seq";
    sigmatch_table[DETECT_ICMP_SEQ].Match = DetectIcmpSeqMatch;
    sigmatch_table[DETECT_ICMP_SEQ].Setup = DetectIcmpSeqSetup;
    sigmatch_table[DETECT_ICMP_SEQ].Free = DetectIcmpSeqFree;
    sigmatch_table[DETECT_ICMP_SEQ].RegisterTests = DetectIcmpSeqRegisterTests;

    const char *eb;
    int eo;
    int opts = 0;

    parse_regex = pcre_compile(PARSE_REGEX, opts, &eb, &eo, NULL);
    if (parse_regex == NULL) {
        SCLogError(SC_ERR_PCRE_COMPILE,"pcre compile of \"%s\" failed at offset %" PRId32 ": %s", PARSE_REGEX, eo, eb);
        goto error;
    }

    parse_regex_study = pcre_study(parse_regex, 0, &eb);
    if (eb != NULL) {
        SCLogError(SC_ERR_PCRE_STUDY,"pcre study failed: %s", eb);
        goto error;
    }
    return;

error:
    return;
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
int DetectIcmpSeqMatch (ThreadVars *t, DetectEngineThreadCtx *det_ctx, Packet *p, Signature *s, const SigMatchCtx *ctx)
{
    uint16_t seqn;
    const DetectIcmpSeqData *iseq = (const DetectIcmpSeqData *)ctx;

    if (PKT_IS_PSEUDOPKT(p))
        return 0;

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
                SCLogDebug("ICMPV4_GET_SEQ(p) %"PRIu16" (network byte order), "
                        "%"PRIu16" (host byte order)", ICMPV4_GET_SEQ(p),
                        ntohs(ICMPV4_GET_SEQ(p)));

                seqn = ICMPV4_GET_SEQ(p);
                break;
            default:
                SCLogDebug("Packet has no seq field");
                return 0;
        }
    } else if (PKT_IS_ICMPV6(p)) {

        switch (ICMPV6_GET_TYPE(p)) {
            case ICMP6_ECHO_REQUEST:
            case ICMP6_ECHO_REPLY:
                SCLogDebug("ICMPV6_GET_SEQ(p) %"PRIu16" (network byte order), "
                        "%"PRIu16" (host byte order)", ICMPV6_GET_SEQ(p),
                        ntohs(ICMPV6_GET_SEQ(p)));

                seqn = ICMPV6_GET_SEQ(p);
                break;
            default:
                SCLogDebug("Packet has no seq field");
                return 0;
        }
    } else {
        SCLogDebug("Packet not ICMPV4 nor ICMPV6");
        return 0;
    }

    if (seqn == iseq->seq)
        return 1;

    return 0;
}

/**
 * \brief This function is used to parse icmp_seq option passed via icmp_seq: keyword
 *
 * \param icmpseqstr Pointer to the user provided icmp_seq options
 *
 * \retval iseq pointer to DetectIcmpSeqData on success
 * \retval NULL on failure
 */
DetectIcmpSeqData *DetectIcmpSeqParse (char *icmpseqstr)
{
    DetectIcmpSeqData *iseq = NULL;
    char *substr[3] = {NULL, NULL, NULL};
#define MAX_SUBSTRINGS 30
    int ret = 0, res = 0;
    int ov[MAX_SUBSTRINGS];
    int i;
    const char *str_ptr;

    ret = pcre_exec(parse_regex, parse_regex_study, icmpseqstr, strlen(icmpseqstr), 0, 0, ov, MAX_SUBSTRINGS);
    if (ret < 1 || ret > 4) {
        SCLogError(SC_ERR_PCRE_MATCH,"Parse error %s", icmpseqstr);
        goto error;
    }

    for (i = 1; i < ret; i++) {
        res = pcre_get_substring((char *)icmpseqstr, ov, MAX_SUBSTRINGS, i, &str_ptr);
        if (res < 0) {
            SCLogError(SC_ERR_PCRE_GET_SUBSTRING,"pcre_get_substring failed");
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
            SCLogError(SC_ERR_MISSING_QUOTE,"Missing quote in input");
            goto error;
        }
    } else {
        if (substr[2] != NULL) {
            SCLogError(SC_ERR_MISSING_QUOTE,"Missing quote in input");
            goto error;
        }
    }

    uint16_t seq = 0;
    if (ByteExtractStringUint16(&seq, 10, 0, substr[1]) < 0) {
        SCLogError(SC_ERR_INVALID_ARGUMENT, "specified icmp seq %s is not "
                                        "valid", substr[1]);
        goto error;
    }
    iseq->seq = htons(seq);

    for (i = 0; i < 3; i++) {
        if (substr[i] != NULL) SCFree(substr[i]);
    }

    return iseq;

error:
    for (i = 0; i < 3; i++) {
        if (substr[i] != NULL) SCFree(substr[i]);
    }
    if (iseq != NULL) DetectIcmpSeqFree(iseq);
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
static int DetectIcmpSeqSetup (DetectEngineCtx *de_ctx, Signature *s, char *icmpseqstr)
{
    DetectIcmpSeqData *iseq = NULL;
    SigMatch *sm = NULL;

    iseq = DetectIcmpSeqParse(icmpseqstr);
    if (iseq == NULL) goto error;

    sm = SigMatchAlloc();
    if (sm == NULL) goto error;

    sm->type = DETECT_ICMP_SEQ;
    sm->ctx = (SigMatchCtx *)iseq;

    SigMatchAppendSMToList(s, sm, DETECT_SM_LIST_MATCH);

    return 0;

error:
    if (iseq != NULL) DetectIcmpSeqFree(iseq);
    if (sm != NULL) SCFree(sm);
    return -1;

}

/**
 * \brief this function will free memory associated with DetectIcmpSeqData
 *
 * \param ptr pointer to DetectIcmpSeqData
 */
void DetectIcmpSeqFree (void *ptr)
{
    DetectIcmpSeqData *iseq = (DetectIcmpSeqData *)ptr;
    SCFree(iseq);
}

#ifdef UNITTESTS

#include "detect-parse.h"
#include "detect-engine.h"
#include "detect-engine-mpm.h"

/**
 * \test DetectIcmpSeqParseTest01 is a test for setting a valid icmp_seq value
 */
int DetectIcmpSeqParseTest01 (void)
{
    DetectIcmpSeqData *iseq = NULL;
    iseq = DetectIcmpSeqParse("300");
    if (iseq != NULL && htons(iseq->seq) == 300) {
        DetectIcmpSeqFree(iseq);
        return 1;
    }
    return 0;
}

/**
 * \test DetectIcmpSeqParseTest02 is a test for setting a valid icmp_seq value
 *       with spaces all around
 */
int DetectIcmpSeqParseTest02 (void)
{
    DetectIcmpSeqData *iseq = NULL;
    iseq = DetectIcmpSeqParse("  300  ");
    if (iseq != NULL && htons(iseq->seq) == 300) {
        DetectIcmpSeqFree(iseq);
        return 1;
    }
    return 0;
}

/**
 * \test DetectIcmpSeqParseTest03 is a test for setting an invalid icmp_seq value
 */
int DetectIcmpSeqParseTest03 (void)
{
    DetectIcmpSeqData *iseq = NULL;
    iseq = DetectIcmpSeqParse("badc");
    if (iseq != NULL) {
        DetectIcmpSeqFree(iseq);
        return 1;
    }
    return 0;
}

/**
 * \test DetectIcmpSeqMatchTest01 is a test for checking the working of
 *       icmp_seq keyword by creating 2 rules and matching a crafted packet
 *       against them. Only the first one shall trigger.
 */
int DetectIcmpSeqMatchTest01 (void)
{
    int result = 0;
    Packet *p = NULL;
    Signature *s = NULL;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx = NULL;

    memset(&th_v, 0, sizeof(th_v));

    p = UTHBuildPacket(NULL, 0, IPPROTO_ICMP);
    p->icmpv4vars.seq = htons(2216);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }

    de_ctx->flags |= DE_QUIET;

    s = de_ctx->sig_list = SigInit(de_ctx, "alert icmp any any -> any any (icmp_seq:2216; sid:1;)");
    if (s == NULL) {
        goto end;
    }

    s = s->next = SigInit(de_ctx, "alert icmp any any -> any any (icmp_seq:5000; sid:2;)");
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
#endif /* UNITTESTS */

void DetectIcmpSeqRegisterTests (void)
{
#ifdef UNITTESTS
    UtRegisterTest("DetectIcmpSeqParseTest01", DetectIcmpSeqParseTest01, 1);
    UtRegisterTest("DetectIcmpSeqParseTest02", DetectIcmpSeqParseTest02, 1);
    UtRegisterTest("DetectIcmpSeqParseTest03", DetectIcmpSeqParseTest03, 0);
    UtRegisterTest("DetectIcmpSeqMatchTest01", DetectIcmpSeqMatchTest01, 1);
#endif /* UNITTESTS */
}

