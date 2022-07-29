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
 * \ingroup threshold
 * @{
 */

/**
 * \file
 *
 * \author Breno Silva <breno.silva@gmail.com>
 * \author Victor Julien <victor@inliniac.net>
 *
 * Implements the threshold keyword.
 *
 * The feature depends on what is provided
 * by detect-engine-threshold.c and util-threshold-config.c
 */

#include "suricata-common.h"

#include "detect-parse.h"

#include "detect-threshold.h"
#include "detect-engine-threshold.h"
#include "detect-engine-address.h"
#include "detect-engine-build.h"

#include "util-unittest.h"
#include "util-unittest-helper.h"
#include "util-byte.h"

#ifdef UNITTESTS
#include "util-cpu.h"
#endif

#define PARSE_REGEX "^\\s*(track|type|count|seconds)\\s+(limit|both|threshold|by_dst|by_src|by_both|by_rule|\\d+)\\s*,\\s*(track|type|count|seconds)\\s+(limit|both|threshold|by_dst|by_src|by_both|by_rule|\\d+)\\s*,\\s*(track|type|count|seconds)\\s+(limit|both|threshold|by_dst|by_src|by_both|by_rule|\\d+)\\s*,\\s*(track|type|count|seconds)\\s+(limit|both|threshold|by_dst|by_src|by_both|by_rule|\\d+)\\s*"

static DetectParseRegex parse_regex;

static int DetectThresholdMatch(DetectEngineThreadCtx *, Packet *,
        const Signature *, const SigMatchCtx *);
static int DetectThresholdSetup(DetectEngineCtx *, Signature *, const char *);
static void DetectThresholdFree(DetectEngineCtx *, void *);
#ifdef UNITTESTS
static void ThresholdRegisterTests(void);
#endif

/**
 * \brief Registration function for threshold: keyword
 */

void DetectThresholdRegister(void)
{
    sigmatch_table[DETECT_THRESHOLD].name = "threshold";
    sigmatch_table[DETECT_THRESHOLD].desc = "control the rule's alert frequency";
    sigmatch_table[DETECT_THRESHOLD].url = "/rules/thresholding.html#threshold";
    sigmatch_table[DETECT_THRESHOLD].Match = DetectThresholdMatch;
    sigmatch_table[DETECT_THRESHOLD].Setup = DetectThresholdSetup;
    sigmatch_table[DETECT_THRESHOLD].Free  = DetectThresholdFree;
#ifdef UNITTESTS
    sigmatch_table[DETECT_THRESHOLD].RegisterTests = ThresholdRegisterTests;
#endif
    /* this is compatible to ip-only signatures */
    sigmatch_table[DETECT_THRESHOLD].flags |= SIGMATCH_IPONLY_COMPAT;

    DetectSetupParseRegexes(PARSE_REGEX, &parse_regex);
}

static int DetectThresholdMatch(DetectEngineThreadCtx *det_ctx, Packet *p,
        const Signature *s, const SigMatchCtx *ctx)
{
    return 1;
}

/**
 * \internal
 * \brief This function is used to parse threshold options passed via threshold: keyword
 *
 * \param rawstr Pointer to the user provided threshold options
 *
 * \retval de pointer to DetectThresholdData on success
 * \retval NULL on failure
 */
static DetectThresholdData *DetectThresholdParse(const char *rawstr)
{
    DetectThresholdData *de = NULL;
    int ret = 0, res = 0;
    size_t pcre2_len;
    const char *str_ptr = NULL;
    char *args[9] = { NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL };
    char *copy_str = NULL, *threshold_opt = NULL;
    int second_found = 0, count_found = 0;
    int type_found = 0, track_found = 0;
    int second_pos = 0, count_pos = 0;
    size_t pos = 0;
    int i = 0;

    copy_str = SCStrdup(rawstr);
    if (unlikely(copy_str == NULL)) {
        goto error;
    }

    char *saveptr = NULL;
    for (pos = 0, threshold_opt = strtok_r(copy_str,",", &saveptr);
         pos < strlen(copy_str) && threshold_opt != NULL;
         pos++, threshold_opt = strtok_r(NULL,"," , &saveptr))
    {
        if(strstr(threshold_opt,"count"))
            count_found++;
        if(strstr(threshold_opt,"second"))
            second_found++;
        if(strstr(threshold_opt,"type"))
            type_found++;
        if(strstr(threshold_opt,"track"))
            track_found++;
    }
    SCFree(copy_str);
    copy_str = NULL;

    if(count_found != 1 || second_found != 1 || type_found != 1 || track_found != 1)
        goto error;

    ret = DetectParsePcreExec(&parse_regex, rawstr, 0, 0);
    if (ret < 5) {
        SCLogError(SC_ERR_PCRE_MATCH, "pcre_exec parse error, ret %" PRId32 ", string %s", ret, rawstr);
        goto error;
    }

    de = SCMalloc(sizeof(DetectThresholdData));
    if (unlikely(de == NULL))
        goto error;

    memset(de,0,sizeof(DetectThresholdData));

    for (i = 0; i < (ret - 1); i++) {

        res = pcre2_substring_get_bynumber(
                parse_regex.match, i + 1, (PCRE2_UCHAR8 **)&str_ptr, &pcre2_len);

        if (res < 0) {
            SCLogError(SC_ERR_PCRE_GET_SUBSTRING, "pcre2_substring_get_bynumber failed");
            goto error;
        }

        args[i] = (char *)str_ptr;

        if (strncasecmp(args[i],"limit",strlen("limit")) == 0)
            de->type = TYPE_LIMIT;
        if (strncasecmp(args[i],"both",strlen("both")) == 0)
            de->type = TYPE_BOTH;
        if (strncasecmp(args[i],"threshold",strlen("threshold")) == 0)
            de->type = TYPE_THRESHOLD;
        if (strncasecmp(args[i],"by_dst",strlen("by_dst")) == 0)
            de->track = TRACK_DST;
        if (strncasecmp(args[i],"by_src",strlen("by_src")) == 0)
            de->track = TRACK_SRC;
        if (strncasecmp(args[i],"by_both",strlen("by_both")) == 0)
            de->track = TRACK_BOTH;
        if (strncasecmp(args[i],"by_rule",strlen("by_rule")) == 0)
            de->track = TRACK_RULE;
        if (strncasecmp(args[i],"count",strlen("count")) == 0)
            count_pos = i+1;
        if (strncasecmp(args[i],"seconds",strlen("seconds")) == 0)
            second_pos = i+1;
    }

    if (args[count_pos] == NULL || args[second_pos] == NULL) {
        goto error;
    }

    if (StringParseUint32(&de->count, 10, strlen(args[count_pos]),
                args[count_pos]) <= 0) {
        goto error;
    }

    if (StringParseUint32(&de->seconds, 10, strlen(args[second_pos]),
                args[second_pos]) <= 0) {
        goto error;
    }

    for (i = 0; i < (ret - 1); i++){
        if (args[i] != NULL)
            pcre2_substring_free((PCRE2_UCHAR8 *)args[i]);
    }
    return de;

error:
    for (i = 0; i < (ret - 1); i++){
        if (args[i] != NULL)
            pcre2_substring_free((PCRE2_UCHAR8 *)args[i]);
    }
    if (de != NULL)
        SCFree(de);
    return NULL;
}

/**
 * \internal
 * \brief this function is used to add the parsed threshold into the current signature
 *
 * \param de_ctx pointer to the Detection Engine Context
 * \param s pointer to the Current Signature
 * \param rawstr pointer to the user provided threshold options
 *
 * \retval 0 on Success
 * \retval -1 on Failure
 */
static int DetectThresholdSetup(DetectEngineCtx *de_ctx, Signature *s, const char *rawstr)
{
    DetectThresholdData *de = NULL;
    SigMatch *sm = NULL;
    SigMatch *tmpm = NULL;

    /* checks if there is a previous instance of detection_filter */
    tmpm = DetectGetLastSMFromLists(s, DETECT_THRESHOLD, DETECT_DETECTION_FILTER, -1);
    if (tmpm != NULL) {
        if (tmpm->type == DETECT_DETECTION_FILTER) {
            SCLogError(SC_ERR_INVALID_SIGNATURE, "\"detection_filter\" and "
                    "\"threshold\" are not allowed in the same rule");
        } else {
            SCLogError(SC_ERR_INVALID_SIGNATURE, "multiple \"threshold\" "
                    "options are not allowed in the same rule");
        }
        SCReturnInt(-1);
    }

    de = DetectThresholdParse(rawstr);
    if (de == NULL)
        goto error;

    sm = SigMatchAlloc();
    if (sm == NULL)
        goto error;

    sm->type = DETECT_THRESHOLD;
    sm->ctx = (SigMatchCtx *)de;

    SigMatchAppendSMToList(s, sm, DETECT_SM_LIST_THRESHOLD);

    return 0;

error:
    if (de) SCFree(de);
    if (sm) SCFree(sm);
    return -1;
}

/**
 * \internal
 * \brief this function will free memory associated with DetectThresholdData
 *
 * \param de pointer to DetectThresholdData
 */
static void DetectThresholdFree(DetectEngineCtx *de_ctx, void *de_ptr)
{
    DetectThresholdData *de = (DetectThresholdData *)de_ptr;
    if (de) {
        DetectAddressHeadCleanup(&de->addrs);
        SCFree(de);
    }
}

/**
 * \brief Make a deep-copy of an extant DetectTHresholdData object.
 *
 * \param de pointer to DetectThresholdData
 */
DetectThresholdData *DetectThresholdDataCopy(DetectThresholdData *de)
{
    DetectThresholdData *new_de = SCCalloc(1, sizeof(DetectThresholdData));
    if (unlikely(new_de == NULL))
        return NULL;

    *new_de = *de;
    new_de->addrs.ipv4_head = NULL;
    new_de->addrs.ipv6_head = NULL;

    for (DetectAddress *last = NULL, *tmp_ad = de->addrs.ipv4_head; tmp_ad; tmp_ad = tmp_ad->next) {
        DetectAddress *n_addr = DetectAddressCopy(tmp_ad);
        if (n_addr == NULL)
            goto error;
        if (last == NULL) {
            new_de->addrs.ipv4_head = n_addr;
        } else {
            last->next = n_addr;
            n_addr->prev = last;
        }
        last = n_addr;
    }
    for (DetectAddress *last = NULL, *tmp_ad = de->addrs.ipv6_head; tmp_ad; tmp_ad = tmp_ad->next) {
        DetectAddress *n_addr = DetectAddressCopy(tmp_ad);
        if (n_addr == NULL)
            goto error;
        if (last == NULL) {
            new_de->addrs.ipv6_head = n_addr;
        } else {
            last->next = n_addr;
            n_addr->prev = last;
        }
        last = n_addr;
    }

    return new_de;

error:
    DetectThresholdFree(NULL, new_de);
    return NULL;
}

/*
 * ONLY TESTS BELOW THIS COMMENT
 */
#ifdef UNITTESTS
#include "detect-engine.h"
#include "util-time.h"

/**
 * \test ThresholdTestParse01 is a test for a valid threshold options
 *
 *  \retval 1 on success
 *  \retval 0 on failure
 */
static int ThresholdTestParse01(void)
{
    DetectThresholdData *de = NULL;
    de = DetectThresholdParse("type limit,track by_dst,count 10,seconds 60");
    if (de && (de->type == TYPE_LIMIT) && (de->track == TRACK_DST) && (de->count == 10) && (de->seconds == 60)) {
        DetectThresholdFree(NULL, de);
        return 1;
    }

    return 0;
}

/**
 * \test ThresholdTestParse02 is a test for a invalid threshold options
 *
 *  \retval 1 on success
 *  \retval 0 on failure
 */
static int ThresholdTestParse02(void)
{
    DetectThresholdData *de = NULL;
    de = DetectThresholdParse("type any,track by_dst,count 10,seconds 60");
    if (de && (de->type == TYPE_LIMIT) && (de->track == TRACK_DST) && (de->count == 10) && (de->seconds == 60)) {
        DetectThresholdFree(NULL, de);
        return 0;
    }

    return 1;
}

/**
 * \test ThresholdTestParse03 is a test for a valid threshold options in any order
 *
 *  \retval 1 on success
 *  \retval 0 on failure
 */
static int ThresholdTestParse03(void)
{
    DetectThresholdData *de = NULL;
    de = DetectThresholdParse("track by_dst, type limit, seconds 60, count 10");
    if (de && (de->type == TYPE_LIMIT) && (de->track == TRACK_DST) && (de->count == 10) && (de->seconds == 60)) {
        DetectThresholdFree(NULL, de);
        return 1;
    }

    return 0;
}


/**
 * \test ThresholdTestParse04 is a test for an invalid threshold options in any order
 *
 *  \retval 1 on success
 *  \retval 0 on failure
 */
static int ThresholdTestParse04(void)
{
    DetectThresholdData *de = NULL;
    de = DetectThresholdParse("count 10, track by_dst, seconds 60, type both, count 10");
    if (de && (de->type == TYPE_BOTH) && (de->track == TRACK_DST) && (de->count == 10) && (de->seconds == 60)) {
        DetectThresholdFree(NULL, de);
        return 0;
    }

    return 1;
}

/**
 * \test ThresholdTestParse05 is a test for a valid threshold options in any order
 *
 *  \retval 1 on success
 *  \retval 0 on failure
 */
static int ThresholdTestParse05(void)
{
    DetectThresholdData *de = NULL;
    de = DetectThresholdParse("count 10, track by_dst, seconds 60, type both");
    if (de && (de->type == TYPE_BOTH) && (de->track == TRACK_DST) && (de->count == 10) && (de->seconds == 60)) {
        DetectThresholdFree(NULL, de);
        return 1;
    }

    return 0;
}

/**
 * \test ThresholdTestParse06 is a test for thresholding by_both
 *
 *  \retval 1 on success
 *  \retval 0 on failure
 */
static int ThresholdTestParse06(void)
{
    DetectThresholdData *de = NULL;
    de = DetectThresholdParse("count 10, track by_both, seconds 60, type limit");
    FAIL_IF_NULL(de);
    FAIL_IF_NOT(de->type == TYPE_LIMIT);
    FAIL_IF_NOT(de->track == TRACK_BOTH);
    FAIL_IF_NOT(de->count == 10);
    FAIL_IF_NOT(de->seconds == 60);
    DetectThresholdFree(NULL, de);
    PASS;
}

/**
 * \test ThresholdTestParse07 is a test for thresholding by_rule
 *
 *  \retval 1 on success
 *  \retval 0 on failure
 */
static int ThresholdTestParse07(void)
{
    DetectThresholdData *de = NULL;
    de = DetectThresholdParse("count 10, track by_rule, seconds 60, type limit");
    FAIL_IF_NULL(de);
    FAIL_IF_NOT(de->type == TYPE_LIMIT);
    FAIL_IF_NOT(de->track == TRACK_RULE);
    FAIL_IF_NOT(de->count == 10);
    FAIL_IF_NOT(de->seconds == 60);
    DetectThresholdFree(NULL, de);
    PASS;
}

/**
 * \test DetectThresholdTestSig1 is a test for checking the working of limit keyword
 *       by setting up the signature and later testing its working by matching
 *       the received packet against the sig.
 *
 *  \retval 1 on success
 *  \retval 0 on failure
 */

static int DetectThresholdTestSig1(void)
{
    Packet *p = NULL;
    Signature *s = NULL;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx;
    int result = 0;
    int alerts = 0;

    HostInitConfig(HOST_QUIET);

    memset(&th_v, 0, sizeof(th_v));

    p = UTHBuildPacketReal((uint8_t *)"A",1,IPPROTO_TCP, "1.1.1.1", "2.2.2.2", 1024, 80);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }

    de_ctx->flags |= DE_QUIET;

    s = de_ctx->sig_list = SigInit(de_ctx,"alert tcp any any -> any 80 (msg:\"Threshold limit\"; content:\"A\"; threshold: type limit, track by_dst, count 5, seconds 60; sid:1;)");
    if (s == NULL) {
        goto end;
    }

    SigGroupBuild(de_ctx);

    if (s->flags & SIG_FLAG_IPONLY) {
        printf("signature is ip-only: ");
        goto end;
    }

    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    alerts = PacketAlertCheck(p, 1);
    if (alerts != 1) {
        printf("alerts %"PRIi32", expected 1: ", alerts);
    }
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    alerts += PacketAlertCheck(p, 1);
    if (alerts != 2) {
        printf("alerts %"PRIi32", expected 2: ", alerts);
    }
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    alerts += PacketAlertCheck(p, 1);
    if (alerts != 3) {
        printf("alerts %"PRIi32", expected 3: ", alerts);
    }
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    alerts += PacketAlertCheck(p, 1);
    if (alerts != 4) {
        printf("alerts %"PRIi32", expected 4: ", alerts);
    }
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    alerts += PacketAlertCheck(p, 1);
    if (alerts != 5) {
        printf("alerts %"PRIi32", expected 5: ", alerts);
    }
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    alerts += PacketAlertCheck(p, 1);
    if (alerts != 5) {
        printf("alerts %"PRIi32", expected 5: ", alerts);
    }
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    alerts += PacketAlertCheck(p, 1);
    if (alerts != 5) {
        printf("alerts %"PRIi32", expected 5: ", alerts);
    }
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    alerts += PacketAlertCheck(p, 1);
    if (alerts != 5) {
        printf("alerts %"PRIi32", expected 5: ", alerts);
    }

    if(alerts == 5)
        result = 1;
    else
        printf("alerts %"PRIi32", expected 5: ", alerts);

    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);

    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);

    UTHFreePackets(&p, 1);

    HostShutdown();
end:
    return result;
}

/**
 * \test DetectThresholdTestSig2 is a test for checking the working of threshold keyword
 *       by setting up the signature and later testing its working by matching
 *       the received packet against the sig.
 *
 *  \retval 1 on success
 *  \retval 0 on failure
 */

static int DetectThresholdTestSig2(void)
{
    Packet *p = NULL;
    Signature *s = NULL;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx;
    int result = 0;
    int alerts = 0;

    HostInitConfig(HOST_QUIET);

    memset(&th_v, 0, sizeof(th_v));

    p = UTHBuildPacketReal((uint8_t *)"A",1,IPPROTO_TCP, "1.1.1.1", "2.2.2.2", 1024, 80);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }

    de_ctx->flags |= DE_QUIET;

    s = de_ctx->sig_list = SigInit(de_ctx,"alert tcp any any -> any 80 (msg:\"Threshold\"; threshold: type threshold, track by_dst, count 5, seconds 60; sid:1;)");
    if (s == NULL) {
        goto end;
    }

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    alerts = PacketAlertCheck(p, 1);
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    alerts += PacketAlertCheck(p, 1);
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    alerts += PacketAlertCheck(p, 1);
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    alerts += PacketAlertCheck(p, 1);
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    alerts += PacketAlertCheck(p, 1);
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    alerts += PacketAlertCheck(p, 1);
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    alerts += PacketAlertCheck(p, 1);
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    alerts += PacketAlertCheck(p, 1);
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    alerts += PacketAlertCheck(p, 1);
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    alerts += PacketAlertCheck(p, 1);

    if (alerts == 2)
        result = 1;
    else
        goto cleanup;

cleanup:
    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);

    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);

end:
    UTHFreePackets(&p, 1);
    HostShutdown();
    return result;
}

/**
 * \test DetectThresholdTestSig3 is a test for checking the working of limit keyword
 *       by setting up the signature and later testing its working by matching
 *       the received packet against the sig.
 *
 *  \retval 1 on success
 *  \retval 0 on failure
 */

static int DetectThresholdTestSig3(void)
{
    Packet *p = NULL;
    Signature *s = NULL;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx;
    int result = 0;
    int alerts = 0;
    struct timeval ts;
    DetectThresholdEntry *lookup_tsh = NULL;

    HostInitConfig(HOST_QUIET);

    memset (&ts, 0, sizeof(struct timeval));
    TimeGet(&ts);

    memset(&th_v, 0, sizeof(th_v));

    p = UTHBuildPacketReal((uint8_t *)"A",1,IPPROTO_TCP, "1.1.1.1", "2.2.2.2", 1024, 80);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }

    de_ctx->flags |= DE_QUIET;

    s = de_ctx->sig_list = SigInit(de_ctx,"alert tcp any any -> any 80 (msg:\"Threshold limit\"; threshold: type limit, track by_dst, count 5, seconds 60; sid:10;)");
    if (s == NULL) {
        goto end;
    }

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    TimeGet(&p->ts);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);

    Host *host = HostLookupHostFromHash(&p->dst);
    if (host == NULL) {
        printf("host not found: ");
        goto cleanup;
    }

    if (!(ThresholdHostHasThreshold(host))) {
        HostRelease(host);
        printf("host has no threshold: ");
        goto cleanup;
    }
    HostRelease(host);

    TimeSetIncrementTime(200);
    TimeGet(&p->ts);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);

    host = HostLookupHostFromHash(&p->dst);
    if (host == NULL) {
        printf("host not found: ");
        goto cleanup;
    }
    HostRelease(host);

    lookup_tsh = HostGetStorageById(host, ThresholdHostStorageId());
    if (lookup_tsh == NULL) {
        HostRelease(host);
        printf("lookup_tsh is NULL: ");
        goto cleanup;
    }

    alerts = lookup_tsh->current_count;

    if (alerts == 3)
        result = 1;
    else {
        printf("alerts %u != 3: ", alerts);
        goto cleanup;
    }

cleanup:
    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);

    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);
end:
    UTHFreePackets(&p, 1);
    HostShutdown();
    return result;
}

/**
 * \test DetectThresholdTestSig4 is a test for checking the working of both keyword
 *       by setting up the signature and later testing its working by matching
 *       the received packet against the sig.
 *
 *  \retval 1 on success
 *  \retval 0 on failure
 */

static int DetectThresholdTestSig4(void)
{
    Packet *p = NULL;
    Signature *s = NULL;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx;
    int result = 0;
    int alerts = 0;
    struct timeval ts;

    HostInitConfig(HOST_QUIET);

    memset (&ts, 0, sizeof(struct timeval));
    TimeGet(&ts);

    memset(&th_v, 0, sizeof(th_v));

    p = UTHBuildPacketReal((uint8_t *)"A",1,IPPROTO_TCP, "1.1.1.1", "2.2.2.2", 1024, 80);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }

    de_ctx->flags |= DE_QUIET;

    s = de_ctx->sig_list = SigInit(de_ctx,"alert tcp any any -> any 80 (msg:\"Threshold both\"; threshold: type both, track by_dst, count 2, seconds 60; sid:10;)");
    if (s == NULL) {
        goto end;
    }

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    TimeGet(&p->ts);
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    alerts = PacketAlertCheck(p, 10);
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    alerts += PacketAlertCheck(p, 10);
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    alerts += PacketAlertCheck(p, 10);

    TimeSetIncrementTime(200);
    TimeGet(&p->ts);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    alerts += PacketAlertCheck(p, 10);
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    alerts += PacketAlertCheck(p, 10);
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    alerts += PacketAlertCheck(p, 10);

    if (alerts == 2)
        result = 1;
    else
        goto cleanup;

cleanup:
    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);

    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);
end:
    UTHFreePackets(&p, 1);
    HostShutdown();
    return result;
}

/**
 * \test DetectThresholdTestSig5 is a test for checking the working of limit keyword
 *       by setting up the signature and later testing its working by matching
 *       the received packet against the sig.
 *
 *  \retval 1 on success
 *  \retval 0 on failure
 */

static int DetectThresholdTestSig5(void)
{
    Packet *p = NULL;
    Signature *s = NULL;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx;
    int result = 0;
    int alerts = 0;

    HostInitConfig(HOST_QUIET);

    memset(&th_v, 0, sizeof(th_v));
    p = UTHBuildPacketReal((uint8_t *)"A",1,IPPROTO_TCP, "1.1.1.1", "2.2.2.2", 1024, 80);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }

    de_ctx->flags |= DE_QUIET;

    s = de_ctx->sig_list = SigInit(de_ctx,"alert tcp any any -> any 80 (msg:\"Threshold limit sid 1\"; threshold: type limit, track by_dst, count 5, seconds 60; sid:1;)");
    if (s == NULL) {
        goto end;
    }

    s = s->next = SigInit(de_ctx,"alert tcp any any -> any 80 (msg:\"Threshold limit sid 1000\"; threshold: type limit, track by_dst, count 5, seconds 60; sid:1000;)");
    if (s == NULL) {
        goto end;
    }

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    alerts = PacketAlertCheck(p, 1);
    alerts += PacketAlertCheck(p, 1000);
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    alerts += PacketAlertCheck(p, 1);
    alerts += PacketAlertCheck(p, 1000);
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    alerts += PacketAlertCheck(p, 1);
    alerts += PacketAlertCheck(p, 1000);
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    alerts += PacketAlertCheck(p, 1);
    alerts += PacketAlertCheck(p, 1000);
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    alerts += PacketAlertCheck(p, 1);
    alerts += PacketAlertCheck(p, 1000);
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    alerts += PacketAlertCheck(p, 1);
    alerts += PacketAlertCheck(p, 1000);
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    alerts += PacketAlertCheck(p, 1);
    alerts += PacketAlertCheck(p, 1000);
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    alerts += PacketAlertCheck(p, 1);
    alerts += PacketAlertCheck(p, 1000);

    if(alerts == 10)
        result = 1;
    else {
        printf("alerts %d != 10: ", alerts);
        goto cleanup;
    }

cleanup:
    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);

    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);

end:
    UTHFreePackets(&p, 1);
    HostShutdown();
    return result;
}

static int DetectThresholdTestSig6Ticks(void)
{
    Packet *p = NULL;
    Signature *s = NULL;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx;
    int result = 0;
    int alerts = 0;

    HostInitConfig(HOST_QUIET);

    memset(&th_v, 0, sizeof(th_v));
    p = UTHBuildPacketReal((uint8_t *)"A",1,IPPROTO_TCP, "1.1.1.1", "2.2.2.2", 1024, 80);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }

    de_ctx->flags |= DE_QUIET;

    s = de_ctx->sig_list = SigInit(de_ctx,"alert tcp any any -> any 80 (msg:\"Threshold limit sid 1\"; threshold: type limit, track by_dst, count 5, seconds 60; sid:1;)");
    if (s == NULL) {
        goto end;
    }

    s = s->next = SigInit(de_ctx,"alert tcp any any -> any 80 (msg:\"Threshold limit sid 1000\"; threshold: type limit, track by_dst, count 5, seconds 60; sid:1000;)");
    if (s == NULL) {
        goto end;
    }

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    uint64_t ticks_start = 0;
    uint64_t ticks_end = 0;

    ticks_start = UtilCpuGetTicks();
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    alerts = PacketAlertCheck(p, 1);
    alerts += PacketAlertCheck(p, 1000);
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    alerts += PacketAlertCheck(p, 1);
    alerts += PacketAlertCheck(p, 1000);
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    alerts += PacketAlertCheck(p, 1);
    alerts += PacketAlertCheck(p, 1000);
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    alerts += PacketAlertCheck(p, 1);
    alerts += PacketAlertCheck(p, 1000);
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    alerts += PacketAlertCheck(p, 1);
    alerts += PacketAlertCheck(p, 1000);
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    alerts += PacketAlertCheck(p, 1);
    alerts += PacketAlertCheck(p, 1000);
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    alerts += PacketAlertCheck(p, 1);
    alerts += PacketAlertCheck(p, 1000);
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    alerts += PacketAlertCheck(p, 1);
    alerts += PacketAlertCheck(p, 1000);
    ticks_end = UtilCpuGetTicks();
    printf("test run %"PRIu64"\n", (ticks_end - ticks_start));

    if(alerts == 10)
        result = 1;
    else
        goto cleanup;

cleanup:
    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);

    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);

end:
    UTHFreePackets(&p, 1);
    HostShutdown();
    return result;
}

/**
 * \test Test drop action being set even if thresholded
 */
static int DetectThresholdTestSig7(void)
{
    Packet *p = NULL;
    Signature *s = NULL;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx;
    int result = 0;
    int alerts = 0;
    int drops = 0;
    struct timeval ts;

    HostInitConfig(HOST_QUIET);

    memset (&ts, 0, sizeof(struct timeval));
    TimeGet(&ts);

    memset(&th_v, 0, sizeof(th_v));

    p = UTHBuildPacketReal((uint8_t *)"A",1,IPPROTO_TCP, "1.1.1.1", "2.2.2.2", 1024, 80);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }

    de_ctx->flags |= DE_QUIET;

    s = de_ctx->sig_list = SigInit(de_ctx,"drop tcp any any -> any 80 (threshold: type limit, track by_src, count 1, seconds 300; sid:10;)");
    if (s == NULL) {
        goto end;
    }

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    TimeGet(&p->ts);
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    alerts = PacketAlertCheck(p, 10);
    drops += ((PacketTestAction(p, ACTION_DROP)) ? 1 : 0);
    p->action = 0;

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    alerts += PacketAlertCheck(p, 10);
    drops += ((PacketTestAction(p, ACTION_DROP)) ? 1 : 0);
    p->action = 0;

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    alerts += PacketAlertCheck(p, 10);
    drops += ((PacketTestAction(p, ACTION_DROP)) ? 1 : 0);
    p->action = 0;

    TimeSetIncrementTime(200);
    TimeGet(&p->ts);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    alerts += PacketAlertCheck(p, 10);
    drops += ((PacketTestAction(p, ACTION_DROP)) ? 1 : 0);
    p->action = 0;

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    alerts += PacketAlertCheck(p, 10);
    drops += ((PacketTestAction(p, ACTION_DROP)) ? 1 : 0);
    p->action = 0;

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    alerts += PacketAlertCheck(p, 10);
    drops += ((PacketTestAction(p, ACTION_DROP)) ? 1 : 0);
    p->action = 0;

    if (alerts == 1 && drops == 6)
        result = 1;
    else {
        if (alerts != 1)
            printf("alerts: %d != 1: ", alerts);
        if (drops != 6)
            printf("drops: %d != 6: ", drops);
        goto cleanup;
    }

cleanup:
    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);

    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);
end:
    UTHFreePackets(&p, 1);
    HostShutdown();
    return result;
}

/**
 * \test Test drop action being set even if thresholded
 */
static int DetectThresholdTestSig8(void)
{
    Packet *p = NULL;
    Signature *s = NULL;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx;
    int result = 0;
    int alerts = 0;
    int drops = 0;
    struct timeval ts;

    HostInitConfig(HOST_QUIET);

    memset (&ts, 0, sizeof(struct timeval));
    TimeGet(&ts);

    memset(&th_v, 0, sizeof(th_v));

    p = UTHBuildPacketReal((uint8_t *)"A",1,IPPROTO_TCP, "1.1.1.1", "2.2.2.2", 1024, 80);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }

    de_ctx->flags |= DE_QUIET;

    s = de_ctx->sig_list = SigInit(de_ctx,"drop tcp any any -> any 80 (threshold: type limit, track by_src, count 2, seconds 300; sid:10;)");
    if (s == NULL) {
        goto end;
    }

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    TimeGet(&p->ts);
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    alerts = PacketAlertCheck(p, 10);
    drops += ((PacketTestAction(p, ACTION_DROP)) ? 1 : 0);
    p->action = 0;

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    alerts += PacketAlertCheck(p, 10);
    drops += ((PacketTestAction(p, ACTION_DROP)) ? 1 : 0);
    p->action = 0;

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    alerts += PacketAlertCheck(p, 10);
    drops += ((PacketTestAction(p, ACTION_DROP)) ? 1 : 0);
    p->action = 0;

    TimeSetIncrementTime(200);
    TimeGet(&p->ts);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    alerts += PacketAlertCheck(p, 10);
    drops += ((PacketTestAction(p, ACTION_DROP)) ? 1 : 0);
    p->action = 0;

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    alerts += PacketAlertCheck(p, 10);
    drops += ((PacketTestAction(p, ACTION_DROP)) ? 1 : 0);
    p->action = 0;

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    alerts += PacketAlertCheck(p, 10);
    drops += ((PacketTestAction(p, ACTION_DROP)) ? 1 : 0);
    p->action = 0;

    if (alerts == 2 && drops == 6)
        result = 1;
    else {
        if (alerts != 1)
            printf("alerts: %d != 1: ", alerts);
        if (drops != 6)
            printf("drops: %d != 6: ", drops);
        goto cleanup;
    }

cleanup:
    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);

    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);
end:
    UTHFreePackets(&p, 1);
    HostShutdown();
    return result;
}

/**
 * \test Test drop action being set even if thresholded
 */
static int DetectThresholdTestSig9(void)
{
    Packet *p = NULL;
    Signature *s = NULL;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx;
    int result = 0;
    int alerts = 0;
    int drops = 0;
    struct timeval ts;

    HostInitConfig(HOST_QUIET);

    memset (&ts, 0, sizeof(struct timeval));
    TimeGet(&ts);

    memset(&th_v, 0, sizeof(th_v));

    p = UTHBuildPacketReal((uint8_t *)"A",1,IPPROTO_TCP, "1.1.1.1", "2.2.2.2", 1024, 80);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }

    de_ctx->flags |= DE_QUIET;

    s = de_ctx->sig_list = SigInit(de_ctx,"drop tcp any any -> any 80 (threshold: type threshold, track by_src, count 3, seconds 100; sid:10;)");
    if (s == NULL) {
        goto end;
    }

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    TimeGet(&p->ts);
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    alerts = PacketAlertCheck(p, 10);
    drops += ((PacketTestAction(p, ACTION_DROP)) ? 1 : 0);
    p->action = 0;

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    alerts += PacketAlertCheck(p, 10);
    drops += ((PacketTestAction(p, ACTION_DROP)) ? 1 : 0);
    p->action = 0;

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    alerts += PacketAlertCheck(p, 10);
    drops += ((PacketTestAction(p, ACTION_DROP)) ? 1 : 0);
    p->action = 0;

    TimeSetIncrementTime(200);
    TimeGet(&p->ts);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    alerts += PacketAlertCheck(p, 10);
    drops += ((PacketTestAction(p, ACTION_DROP)) ? 1 : 0);
    p->action = 0;

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    alerts += PacketAlertCheck(p, 10);
    drops += ((PacketTestAction(p, ACTION_DROP)) ? 1 : 0);
    p->action = 0;

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    alerts += PacketAlertCheck(p, 10);
    drops += ((PacketTestAction(p, ACTION_DROP)) ? 1 : 0);
    p->action = 0;

    if (alerts == 2 && drops == 2)
        result = 1;
    else {
        if (alerts != 2)
            printf("alerts: %d != 2: ", alerts);
        if (drops != 2)
            printf("drops: %d != 2: ", drops);
        goto cleanup;
    }

cleanup:
    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);

    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);
end:
    UTHFreePackets(&p, 1);
    HostShutdown();
    return result;
}

/**
 * \test Test drop action being set even if thresholded
 */
static int DetectThresholdTestSig10(void)
{
    Packet *p = NULL;
    Signature *s = NULL;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx;
    int result = 0;
    int alerts = 0;
    int drops = 0;
    struct timeval ts;

    HostInitConfig(HOST_QUIET);

    memset (&ts, 0, sizeof(struct timeval));
    TimeGet(&ts);

    memset(&th_v, 0, sizeof(th_v));

    p = UTHBuildPacketReal((uint8_t *)"A",1,IPPROTO_TCP, "1.1.1.1", "2.2.2.2", 1024, 80);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }

    de_ctx->flags |= DE_QUIET;

    s = de_ctx->sig_list = SigInit(de_ctx,"drop tcp any any -> any 80 (threshold: type threshold, track by_src, count 5, seconds 300; sid:10;)");
    if (s == NULL) {
        goto end;
    }

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    TimeGet(&p->ts);
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    alerts = PacketAlertCheck(p, 10);
    drops += ((PacketTestAction(p, ACTION_DROP)) ? 1 : 0);
    p->action = 0;

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    alerts += PacketAlertCheck(p, 10);
    drops += ((PacketTestAction(p, ACTION_DROP)) ? 1 : 0);
    p->action = 0;

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    alerts += PacketAlertCheck(p, 10);
    drops += ((PacketTestAction(p, ACTION_DROP)) ? 1 : 0);
    p->action = 0;

    TimeSetIncrementTime(200);
    TimeGet(&p->ts);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    alerts += PacketAlertCheck(p, 10);
    drops += ((PacketTestAction(p, ACTION_DROP)) ? 1 : 0);
    p->action = 0;

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    alerts += PacketAlertCheck(p, 10);
    drops += ((PacketTestAction(p, ACTION_DROP)) ? 1 : 0);
    p->action = 0;

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    alerts += PacketAlertCheck(p, 10);
    drops += ((PacketTestAction(p, ACTION_DROP)) ? 1 : 0);
    p->action = 0;

    if (alerts == 1 && drops == 1)
        result = 1;
    else {
        if (alerts != 1)
            printf("alerts: %d != 1: ", alerts);
        if (drops != 1)
            printf("drops: %d != 1: ", drops);
        goto cleanup;
    }

cleanup:
    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);

    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);
end:
    UTHFreePackets(&p, 1);
    HostShutdown();
    return result;
}

/**
 * \test Test drop action being set even if thresholded
 */
static int DetectThresholdTestSig11(void)
{
    Packet *p = NULL;
    Signature *s = NULL;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx;
    int result = 0;
    int alerts = 0;
    int drops = 0;
    struct timeval ts;

    HostInitConfig(HOST_QUIET);

    memset (&ts, 0, sizeof(struct timeval));
    TimeGet(&ts);

    memset(&th_v, 0, sizeof(th_v));

    p = UTHBuildPacketReal((uint8_t *)"A",1,IPPROTO_TCP, "1.1.1.1", "2.2.2.2", 1024, 80);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }

    de_ctx->flags |= DE_QUIET;

    s = de_ctx->sig_list = SigInit(de_ctx,"drop tcp any any -> any 80 (threshold: type both, track by_src, count 3, seconds 300; sid:10;)");
    if (s == NULL) {
        goto end;
    }

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    TimeGet(&p->ts);
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    alerts = PacketAlertCheck(p, 10);
    drops += ((PacketTestAction(p, ACTION_DROP)) ? 1 : 0);
    p->action = 0;

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    alerts += PacketAlertCheck(p, 10);
    drops += ((PacketTestAction(p, ACTION_DROP)) ? 1 : 0);
    p->action = 0;

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    alerts += PacketAlertCheck(p, 10);
    drops += ((PacketTestAction(p, ACTION_DROP)) ? 1 : 0);
    p->action = 0;

    TimeSetIncrementTime(200);
    TimeGet(&p->ts);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    alerts += PacketAlertCheck(p, 10);
    drops += ((PacketTestAction(p, ACTION_DROP)) ? 1 : 0);
    p->action = 0;

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    alerts += PacketAlertCheck(p, 10);
    drops += ((PacketTestAction(p, ACTION_DROP)) ? 1 : 0);
    p->action = 0;

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    alerts += PacketAlertCheck(p, 10);
    drops += ((PacketTestAction(p, ACTION_DROP)) ? 1 : 0);
    p->action = 0;

    if (alerts == 1 && drops == 4)
        result = 1;
    else {
        if (alerts != 1)
            printf("alerts: %d != 1: ", alerts);
        if (drops != 4)
            printf("drops: %d != 4: ", drops);
        goto cleanup;
    }

cleanup:
    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);

    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);
end:
    UTHFreePackets(&p, 1);
    HostShutdown();
    return result;
}

/**
 * \test Test drop action being set even if thresholded
 */
static int DetectThresholdTestSig12(void)
{
    Packet *p = NULL;
    Signature *s = NULL;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx;
    int result = 0;
    int alerts = 0;
    int drops = 0;
    struct timeval ts;

    HostInitConfig(HOST_QUIET);

    memset (&ts, 0, sizeof(struct timeval));
    TimeGet(&ts);

    memset(&th_v, 0, sizeof(th_v));

    p = UTHBuildPacketReal((uint8_t *)"A",1,IPPROTO_TCP, "1.1.1.1", "2.2.2.2", 1024, 80);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }

    de_ctx->flags |= DE_QUIET;

    s = de_ctx->sig_list = SigInit(de_ctx,"drop tcp any any -> any 80 (threshold: type both, track by_src, count 5, seconds 300; sid:10;)");
    if (s == NULL) {
        goto end;
    }

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    TimeGet(&p->ts);
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    alerts = PacketAlertCheck(p, 10);
    drops += ((PacketTestAction(p, ACTION_DROP)) ? 1 : 0);
    p->action = 0;

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    alerts += PacketAlertCheck(p, 10);
    drops += ((PacketTestAction(p, ACTION_DROP)) ? 1 : 0);
    p->action = 0;

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    alerts += PacketAlertCheck(p, 10);
    drops += ((PacketTestAction(p, ACTION_DROP)) ? 1 : 0);
    p->action = 0;

    TimeSetIncrementTime(200);
    TimeGet(&p->ts);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    alerts += PacketAlertCheck(p, 10);
    drops += ((PacketTestAction(p, ACTION_DROP)) ? 1 : 0);
    p->action = 0;

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    alerts += PacketAlertCheck(p, 10);
    drops += ((PacketTestAction(p, ACTION_DROP)) ? 1 : 0);
    p->action = 0;

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    alerts += PacketAlertCheck(p, 10);
    drops += ((PacketTestAction(p, ACTION_DROP)) ? 1 : 0);
    p->action = 0;

    if (alerts == 1 && drops == 2)
        result = 1;
    else {
        if (alerts != 1)
            printf("alerts: %d != 1: ", alerts);
        if (drops != 2)
            printf("drops: %d != 2: ", drops);
        goto cleanup;
    }

cleanup:
    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);

    DetectEngineThreadCtxDeinit(&th_v, (void*)det_ctx);
    DetectEngineCtxFree(de_ctx);
end:
    UTHFreePackets(&p, 1);
    HostShutdown();
    return result;
}

/**
 * \test DetectThresholdTestSig13 is a test for checking the working by_rule limits
 *       by setting up the signature and later testing its working by matching
 *       received packets against the sig.
 *
 *  \retval 1 on success
 *  \retval 0 on failure
 */

static int DetectThresholdTestSig13(void)
{
    Packet *p = NULL;
    Signature *s = NULL;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx;
    int alerts = 0;

    HostInitConfig(HOST_QUIET);

    memset(&th_v, 0, sizeof(th_v));
    p = UTHBuildPacketReal((uint8_t *)"A",1,IPPROTO_TCP, "1.1.1.1", "2.2.2.2", 1024, 80);
    FAIL_IF_NULL(p);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);

    de_ctx->flags |= DE_QUIET;

    s = de_ctx->sig_list = SigInit(de_ctx,"alert tcp any any -> any 80 (msg:\"Threshold limit sid 1\"; threshold: type limit, track by_rule, count 2, seconds 60; sid:1;)");
    FAIL_IF_NULL(s);

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    /* should alert twice */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    alerts += PacketAlertCheck(p, 1);
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    alerts += PacketAlertCheck(p, 1);
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    alerts += PacketAlertCheck(p, 1);
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    alerts += PacketAlertCheck(p, 1);

    FAIL_IF(alerts != 2);

    TimeSetIncrementTime(70);
    TimeGet(&p->ts);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    alerts += PacketAlertCheck(p, 1);
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    alerts += PacketAlertCheck(p, 1);
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    alerts += PacketAlertCheck(p, 1);
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    alerts += PacketAlertCheck(p, 1);

    FAIL_IF(alerts != 4);

    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);
    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);
    UTHFreePackets(&p, 1);
    HostShutdown();
    PASS;
}

/**
 * \test DetectThresholdTestSig14 is a test for checking the working by_both limits
 *       by setting up the signature and later testing its working by matching
 *       received packets against the sig.
 *
 *  \retval 1 on success
 *  \retval 0 on failure
 */

static int DetectThresholdTestSig14(void)
{
    Packet *p1 = NULL;
    Packet *p2 = NULL;
    Signature *s = NULL;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx;
    int alerts1 = 0;
    int alerts2 = 0;

    HostInitConfig(HOST_QUIET);
    IPPairInitConfig(IPPAIR_QUIET);

    memset(&th_v, 0, sizeof(th_v));
    p1 = UTHBuildPacketReal((uint8_t *)"A",1,IPPROTO_TCP, "1.1.1.1", "2.2.2.2", 1024, 80);
    p2 = UTHBuildPacketReal((uint8_t *)"A",1,IPPROTO_TCP, "1.1.1.1", "3.3.3.3", 1024, 80);
    FAIL_IF_NULL(p1);
    FAIL_IF_NULL(p2);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);

    de_ctx->flags |= DE_QUIET;

    s = de_ctx->sig_list = SigInit(de_ctx,"alert tcp any any -> any 80 (msg:\"Threshold limit sid 1\"; threshold: type limit, track by_both, count 2, seconds 60; sid:1;)");
    FAIL_IF_NULL(s);

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    /* Both p1 and p2 should alert twice */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p1);
    alerts1 += PacketAlertCheck(p1, 1);
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p1);
    alerts1 += PacketAlertCheck(p1, 1);
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p1);
    alerts1 += PacketAlertCheck(p1, 1);
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p1);
    alerts1 += PacketAlertCheck(p1, 1);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p2);
    alerts2 += PacketAlertCheck(p2, 1);
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p2);
    alerts2 += PacketAlertCheck(p2, 1);
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p2);
    alerts2 += PacketAlertCheck(p2, 1);
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p2);
    alerts2 += PacketAlertCheck(p2, 1);

    FAIL_IF(alerts1 != 2);
    FAIL_IF(alerts2 != 2);

    TimeSetIncrementTime(70);
    TimeGet(&p1->ts);
    TimeGet(&p2->ts);

    /* Now they should both alert again after previous alerts expire */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p1);
    alerts1 += PacketAlertCheck(p1, 1);
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p2);
    alerts2 += PacketAlertCheck(p2, 1);

    FAIL_IF(alerts1 != 3);
    FAIL_IF(alerts2 != 3);

    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);
    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);
    UTHFreePackets(&p1, 1);
    UTHFreePackets(&p2, 1);
    HostShutdown();
    PASS;
}

static void ThresholdRegisterTests(void)
{
    UtRegisterTest("ThresholdTestParse01", ThresholdTestParse01);
    UtRegisterTest("ThresholdTestParse02", ThresholdTestParse02);
    UtRegisterTest("ThresholdTestParse03", ThresholdTestParse03);
    UtRegisterTest("ThresholdTestParse04", ThresholdTestParse04);
    UtRegisterTest("ThresholdTestParse05", ThresholdTestParse05);
    UtRegisterTest("ThresholdTestParse06", ThresholdTestParse06);
    UtRegisterTest("ThresholdTestParse07", ThresholdTestParse07);
    UtRegisterTest("DetectThresholdTestSig1", DetectThresholdTestSig1);
    UtRegisterTest("DetectThresholdTestSig2", DetectThresholdTestSig2);
    UtRegisterTest("DetectThresholdTestSig3", DetectThresholdTestSig3);
    UtRegisterTest("DetectThresholdTestSig4", DetectThresholdTestSig4);
    UtRegisterTest("DetectThresholdTestSig5", DetectThresholdTestSig5);
    UtRegisterTest("DetectThresholdTestSig6Ticks",
                   DetectThresholdTestSig6Ticks);
    UtRegisterTest("DetectThresholdTestSig7", DetectThresholdTestSig7);
    UtRegisterTest("DetectThresholdTestSig8", DetectThresholdTestSig8);
    UtRegisterTest("DetectThresholdTestSig9", DetectThresholdTestSig9);
    UtRegisterTest("DetectThresholdTestSig10", DetectThresholdTestSig10);
    UtRegisterTest("DetectThresholdTestSig11", DetectThresholdTestSig11);
    UtRegisterTest("DetectThresholdTestSig12", DetectThresholdTestSig12);
    UtRegisterTest("DetectThresholdTestSig13", DetectThresholdTestSig13);
    UtRegisterTest("DetectThresholdTestSig14", DetectThresholdTestSig14);
}
#endif /* UNITTESTS */

/**
 * @}
 */
