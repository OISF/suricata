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
 * Implements the detection_filter keyword
 */

#include "suricata-common.h"
#include "suricata.h"
#include "decode.h"
#include "detect.h"

#include "host.h"

#include "detect-detection-filter.h"
#include "detect-threshold.h"
#include "detect-parse.h"

#include "util-byte.h"
#include "util-unittest.h"
#include "util-unittest-helper.h"
#include "util-debug.h"
#include "detect-engine-build.h"

#define TRACK_DST      1
#define TRACK_SRC      2

/**
 *\brief Regex for parsing our detection_filter options
 */
#define PARSE_REGEX "^\\s*(track|count|seconds)\\s+(by_src|by_dst|\\d+)\\s*,\\s*(track|count|seconds)\\s+(by_src|by_dst|\\d+)\\s*,\\s*(track|count|seconds)\\s+(by_src|by_dst|\\d+)\\s*$"

static DetectParseRegex parse_regex;

static int DetectDetectionFilterMatch(DetectEngineThreadCtx *,
        Packet *, const Signature *, const SigMatchCtx *);
static int DetectDetectionFilterSetup(DetectEngineCtx *, Signature *, const char *);
#ifdef UNITTESTS
static void DetectDetectionFilterRegisterTests(void);
#endif
static void DetectDetectionFilterFree(DetectEngineCtx *, void *);

/**
 * \brief Registration function for detection_filter: keyword
 */
void DetectDetectionFilterRegister (void)
{
    sigmatch_table[DETECT_DETECTION_FILTER].name = "detection_filter";
    sigmatch_table[DETECT_DETECTION_FILTER].desc = "alert on every match after a threshold has been reached";
    sigmatch_table[DETECT_DETECTION_FILTER].url = "/rules/thresholding.html#detection-filter";
    sigmatch_table[DETECT_DETECTION_FILTER].Match = DetectDetectionFilterMatch;
    sigmatch_table[DETECT_DETECTION_FILTER].Setup = DetectDetectionFilterSetup;
    sigmatch_table[DETECT_DETECTION_FILTER].Free = DetectDetectionFilterFree;
#ifdef UNITTESTS
    sigmatch_table[DETECT_DETECTION_FILTER].RegisterTests = DetectDetectionFilterRegisterTests;
#endif
    /* this is compatible to ip-only signatures */
    sigmatch_table[DETECT_DETECTION_FILTER].flags |= SIGMATCH_IPONLY_COMPAT;

    DetectSetupParseRegexes(PARSE_REGEX, &parse_regex);
}

static int DetectDetectionFilterMatch (DetectEngineThreadCtx *det_ctx,
        Packet *p, const Signature *s, const SigMatchCtx *ctx)
{
    return 1;
}

/**
 * \internal
 * \brief This function is used to parse detection_filter options passed via detection_filter: keyword
 *
 * \param rawstr Pointer to the user provided detection_filter options
 *
 * \retval df pointer to DetectThresholdData on success
 * \retval NULL on failure
 */
static DetectThresholdData *DetectDetectionFilterParse (const char *rawstr)
{
    DetectThresholdData *df = NULL;
    int ret = 0, res = 0;
    size_t pcre2_len;
    const char *str_ptr = NULL;
    char *args[6] = { NULL, NULL, NULL, NULL, NULL, NULL};
    char *copy_str = NULL, *df_opt = NULL;
    int seconds_found = 0, count_found = 0, track_found = 0;
    int seconds_pos = 0, count_pos = 0;
    size_t pos = 0;
    int i = 0;
    char *saveptr = NULL;

    copy_str = SCStrdup(rawstr);
    if (unlikely(copy_str == NULL)) {
        goto error;
    }

    for (pos = 0, df_opt = strtok_r(copy_str,",", &saveptr);
         pos < strlen(copy_str) && df_opt != NULL;
         pos++, df_opt = strtok_r(NULL,",", &saveptr))
    {
        if(strstr(df_opt,"count"))
            count_found++;
        if(strstr(df_opt,"second"))
            seconds_found++;
        if(strstr(df_opt,"track"))
            track_found++;
    }
    SCFree(copy_str);
    copy_str = NULL;

    if (count_found != 1 || seconds_found != 1 || track_found != 1)
        goto error;

    ret = DetectParsePcreExec(&parse_regex, rawstr, 0, 0);
    if (ret < 5) {
        SCLogError(SC_ERR_PCRE_MATCH, "pcre_exec parse error, ret %" PRId32 ", string %s", ret, rawstr);
        goto error;
    }

    df = SCMalloc(sizeof(DetectThresholdData));
    if (unlikely(df == NULL))
        goto error;

    memset(df,0,sizeof(DetectThresholdData));

    df->type = TYPE_DETECTION;

    for (i = 0; i < (ret - 1); i++) {
        res = pcre2_substring_get_bynumber(
                parse_regex.match, i + 1, (PCRE2_UCHAR8 **)&str_ptr, &pcre2_len);
        if (res < 0) {
            SCLogError(SC_ERR_PCRE_GET_SUBSTRING, "pcre2_substring_get_bynumber failed");
            goto error;
        }

        args[i] = (char *)str_ptr;

        if (strncasecmp(args[i],"by_dst",strlen("by_dst")) == 0)
            df->track = TRACK_DST;
        if (strncasecmp(args[i],"by_src",strlen("by_src")) == 0)
            df->track = TRACK_SRC;
        if (strncasecmp(args[i],"count",strlen("count")) == 0)
            count_pos = i+1;
        if (strncasecmp(args[i],"seconds",strlen("seconds")) == 0)
            seconds_pos = i+1;
    }

    if (args[count_pos] == NULL || args[seconds_pos] == NULL) {
        goto error;
    }

    if (StringParseUint32(&df->count, 10, strlen(args[count_pos]),
                args[count_pos]) <= 0) {
        goto error;
    }

    if (StringParseUint32(&df->seconds, 10, strlen(args[seconds_pos]),
                args[seconds_pos]) <= 0) {
        goto error;
    }

    if (df->count == 0 || df->seconds == 0) {
        SCLogError(SC_EINVAL, "found an invalid value");
        goto error;
    }

    for (i = 0; i < 6; i++){
        if (args[i] != NULL)
            pcre2_substring_free((PCRE2_UCHAR *)args[i]);
    }
    return df;

error:
    for (i = 0; i < 6; i++){
        if (args[i] != NULL)
            pcre2_substring_free((PCRE2_UCHAR *)args[i]);
    }
    if (df != NULL)
        SCFree(df);
    return NULL;
}

/**
 * \internal
 * \brief this function is used to add the parsed detection_filter into the current signature
 *
 * \param de_ctx pointer to the Detection Engine Context
 * \param s pointer to the Current Signature
 * \param m pointer to the Current SigMatch
 * \param rawstr pointer to the user provided detection_filter options
 *
 * \retval 0 on Success
 * \retval -1 on Failure
 */
static int DetectDetectionFilterSetup (DetectEngineCtx *de_ctx, Signature *s, const char *rawstr)
{
    SCEnter();
    DetectThresholdData *df = NULL;
    SigMatch *sm = NULL;
    SigMatch *tmpm = NULL;

    /* checks if there's a previous instance of threshold */
    tmpm = DetectGetLastSMFromLists(s, DETECT_THRESHOLD, -1);
    if (tmpm != NULL) {
        SCLogError(SC_ERR_INVALID_SIGNATURE, "\"detection_filter\" and \"threshold\" are not allowed in the same rule");
        SCReturnInt(-1);
    }
    /* checks there's no previous instance of detection_filter */
    tmpm = DetectGetLastSMFromLists(s, DETECT_DETECTION_FILTER, -1);
    if (tmpm != NULL) {
        SCLogError(SC_ERR_INVALID_SIGNATURE, "At most one \"detection_filter\" is allowed per rule");
        SCReturnInt(-1);
    }

    df = DetectDetectionFilterParse(rawstr);
    if (df == NULL)
        goto error;

    sm = SigMatchAlloc();
    if (sm == NULL)
        goto error;

    sm->type = DETECT_DETECTION_FILTER;
    sm->ctx = (SigMatchCtx *)df;

    SigMatchAppendSMToList(s, sm, DETECT_SM_LIST_THRESHOLD);

    return 0;

error:
    if (df)
        SCFree(df);
    if (sm)
        SCFree(sm);
    return -1;
}

/**
 * \internal
 * \brief this function will free memory associated with DetectThresholdData
 *
 * \param df_ptr pointer to DetectDetectionFilterData
 */
static void DetectDetectionFilterFree(DetectEngineCtx *de_ctx, void *df_ptr)
{
    DetectThresholdData *df = (DetectThresholdData *)df_ptr;
    if (df)
        SCFree(df);
}

/*
 * ONLY TESTS BELOW THIS COMMENT
 */
#ifdef UNITTESTS
#include "detect-engine.h"
#include "detect-engine-mpm.h"
#include "detect-engine-threshold.h"
#include "util-time.h"
#include "util-hashlist.h"

/**
 * \test DetectDetectionFilterTestParse01 is a test for a valid detection_filter options
 *
 *  \retval 1 on succces
 *  \retval 0 on failure
 */
static int DetectDetectionFilterTestParse01 (void)
{
    DetectThresholdData *df = NULL;
    df = DetectDetectionFilterParse("track by_dst,count 10,seconds 60");
    if (df && (df->track == TRACK_DST) && (df->count == 10) && (df->seconds == 60)) {
        DetectDetectionFilterFree(NULL, df);
        return 1;
    }

    return 0;
}

/**
 * \test DetectDetectionFilterTestParse02 is a test for a invalid detection_filter options
 *
 *  \retval 1 on succces
 *  \retval 0 on failure
 */
static int DetectDetectionFilterTestParse02 (void)
{
    DetectThresholdData *df = NULL;
    df = DetectDetectionFilterParse("track both,count 10,seconds 60");
    if (df && (df->track == TRACK_DST || df->track == TRACK_SRC) && (df->count == 10) && (df->seconds == 60)) {
        DetectDetectionFilterFree(NULL, df);
        return 0;
    }

    return 1;
}

/**
 * \test DetectDetectionfilterTestParse03 is a test for a valid detection_filter options in any order
 *
 *  \retval 1 on succces
 *  \retval 0 on failure
 */
static int DetectDetectionFilterTestParse03 (void)
{
    DetectThresholdData *df = NULL;
    df = DetectDetectionFilterParse("track by_dst, seconds 60, count 10");
    if (df && (df->track == TRACK_DST) && (df->count == 10) && (df->seconds == 60)) {
        DetectDetectionFilterFree(NULL, df);
        return 1;
    }

    return 0;
}


/**
 * \test DetectDetectionFilterTestParse04 is a test for an invalid detection_filter options in any order
 *
 *  \retval 1 on succces
 *  \retval 0 on failure
 */
static int DetectDetectionFilterTestParse04 (void)
{
    DetectThresholdData *df = NULL;
    df = DetectDetectionFilterParse("count 10, track by_dst, seconds 60, count 10");
    if (df && (df->track == TRACK_DST) && (df->count == 10) && (df->seconds == 60)) {
        DetectDetectionFilterFree(NULL, df);
        return 0;
    }

    return 1;
}

/**
 * \test DetectDetectionFilterTestParse05 is a test for a valid detection_filter options in any order
 *
 *  \retval 1 on succces
 *  \retval 0 on failure
 */
static int DetectDetectionFilterTestParse05 (void)
{
    DetectThresholdData *df = NULL;
    df = DetectDetectionFilterParse("count 10, track by_dst, seconds 60");
    if (df && (df->track == TRACK_DST) && (df->count == 10) && (df->seconds == 60)) {
        DetectDetectionFilterFree(NULL, df);
        return 1;
    }

    return 0;
}

/**
 * \test DetectDetectionFilterTestParse06 is a test for an invalid value in detection_filter
 *
 *  \retval 1 on succces
 *  \retval 0 on failure
 */
static int DetectDetectionFilterTestParse06 (void)
{
    DetectThresholdData *df = NULL;
    df = DetectDetectionFilterParse("count 10, track by_dst, seconds 0");
    if (df && (df->track == TRACK_DST) && (df->count == 10) && (df->seconds == 0)) {
        DetectDetectionFilterFree(NULL, df);
        return 0;
    }

    return 1;
}

/**
 * \test DetectDetectionFilterTestSig1 is a test for checking the working of detection_filter keyword
 *       by setting up the signature and later testing its working by matching
 *       the received packet against the sig.
 *
 *  \retval 1 on succces
 *  \retval 0 on failure
 */
static int DetectDetectionFilterTestSig1(void)
{
    Packet *p = NULL;
    Signature *s = NULL;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx;
    int result = 0;
    int alerts = 0;

    HostInitConfig(HOST_QUIET);

    memset(&th_v, 0, sizeof(th_v));

    p = UTHBuildPacketReal(NULL, 0, IPPROTO_TCP, "1.1.1.1", "2.2.2.2", 1024, 80);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }

    de_ctx->flags |= DE_QUIET;

    s = de_ctx->sig_list = SigInit(de_ctx,"alert tcp any any -> any 80 (msg:\"detection_filter Test\"; detection_filter: track by_dst, count 4, seconds 60; sid:1;)");
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

    if(alerts == 4)
        result = 1;

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
 * \test DetectDetectionFilterTestSig2 is a test for checking the working of detection_filter keyword
 *       by setting up the signature and later testing its working by matching
 *       the received packet against the sig.
 *
 *  \retval 1 on succces
 *  \retval 0 on failure
 */

static int DetectDetectionFilterTestSig2(void)
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

    p = UTHBuildPacketReal(NULL, 0, IPPROTO_TCP, "1.1.1.1", "2.2.2.2", 1024, 80);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }

    de_ctx->flags |= DE_QUIET;

    s = de_ctx->sig_list = SigInit(de_ctx,"alert tcp any any -> any 80 (msg:\"detection_filter Test 2\"; detection_filter: track by_dst, count 4, seconds 60; sid:10;)");
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
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    alerts += PacketAlertCheck(p, 10);

    if (alerts == 0)
        result = 1;

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
 *  \test drops
 */
static int DetectDetectionFilterTestSig3(void)
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

    p = UTHBuildPacketReal(NULL, 0, IPPROTO_TCP, "1.1.1.1", "2.2.2.2", 1024, 80);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }

    de_ctx->flags |= DE_QUIET;

    s = de_ctx->sig_list = SigInit(de_ctx,"drop tcp any any -> any 80 (msg:\"detection_filter Test 2\"; detection_filter: track by_dst, count 2, seconds 60; sid:10;)");
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

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    alerts += PacketAlertCheck(p, 10);
    drops += ((PacketTestAction(p, ACTION_DROP)) ? 1 : 0);
    p->action = 0;

    if (alerts == 3 && drops == 3)
        result = 1;
    else {
        if (alerts != 3)
            printf("alerts: %d != 3: ", alerts);
        if (drops != 3)
            printf("drops: %d != 3: ", drops);
    }

    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);

    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);
end:
    UTHFreePackets(&p, 1);
    HostShutdown();
    return result;
}

static void DetectDetectionFilterRegisterTests(void)
{
    UtRegisterTest("DetectDetectionFilterTestParse01",
                   DetectDetectionFilterTestParse01);
    UtRegisterTest("DetectDetectionFilterTestParse02",
                   DetectDetectionFilterTestParse02);
    UtRegisterTest("DetectDetectionFilterTestParse03",
                   DetectDetectionFilterTestParse03);
    UtRegisterTest("DetectDetectionFilterTestParse04",
                   DetectDetectionFilterTestParse04);
    UtRegisterTest("DetectDetectionFilterTestParse05",
                   DetectDetectionFilterTestParse05);
    UtRegisterTest("DetectDetectionFilterTestParse06",
                   DetectDetectionFilterTestParse06);
    UtRegisterTest("DetectDetectionFilterTestSig1",
                   DetectDetectionFilterTestSig1);
    UtRegisterTest("DetectDetectionFilterTestSig2",
                   DetectDetectionFilterTestSig2);
    UtRegisterTest("DetectDetectionFilterTestSig3",
                   DetectDetectionFilterTestSig3);
}
#endif /* UNITTESTS */
