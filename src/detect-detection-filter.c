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
#include "detect-engine-proto.h"

#define TRACK_DST 1
#define TRACK_SRC 2

/**
 *\brief Regex for parsing our detection_filter options
 */
#define PARSE_REGEX                                                                                \
    "^\\s*(track|count|seconds)\\s+(by_src|by_dst|by_flow|\\d+)\\s*,\\s*(track|count|seconds)\\s+" \
    "(by_src|"                                                                                     \
    "by_dst|by_flow|\\d+)\\s*,\\s*(track|count|seconds)\\s+(by_src|by_dst|by_flow|\\d+)"           \
    "(?:\\s*,\\s*unique_on\\s+(src_port|dst_port))?\\s*$"

/* minimum number of PCRE submatches expected for detection_filter parse */
#define DF_PARSE_MIN_SUBMATCHES 5

static DetectParseRegex parse_regex;

static int DetectDetectionFilterMatch(
        DetectEngineThreadCtx *, Packet *, const Signature *, const SigMatchCtx *);
static int DetectDetectionFilterSetup(DetectEngineCtx *, Signature *, const char *);
#ifdef UNITTESTS
static void DetectDetectionFilterRegisterTests(void);
#endif
static void DetectDetectionFilterFree(DetectEngineCtx *, void *);

/**
 * \brief Registration function for detection_filter: keyword
 */
void DetectDetectionFilterRegister(void)
{
    sigmatch_table[DETECT_DETECTION_FILTER].name = "detection_filter";
    sigmatch_table[DETECT_DETECTION_FILTER].desc =
            "alert on every match after a threshold has been reached";
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

static int DetectDetectionFilterMatch(
        DetectEngineThreadCtx *det_ctx, Packet *p, const Signature *s, const SigMatchCtx *ctx)
{
    return 1;
}

/**
 * \internal
 * \brief This function is used to parse detection_filter options passed via detection_filter:
 * keyword
 *
 * \param rawstr Pointer to the user provided detection_filter options
 *
 * \retval df pointer to DetectThresholdData on success
 * \retval NULL on failure
 */
static DetectThresholdData *DetectDetectionFilterParse(const char *rawstr)
{
    DetectThresholdData *df = NULL;
    int res = 0;
    size_t pcre2_len;
    const char *str_ptr = NULL;
    char *args[8] = { NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL };
    char *copy_str = NULL, *df_opt = NULL;
    int seconds_found = 0, count_found = 0, track_found = 0;
    int seconds_pos = 0, count_pos = 0;
    size_t pos = 0;
    int i = 0;
    int parsed_count = 0;
    int ret = 0;
    char *saveptr = NULL;
    pcre2_match_data *match = NULL;

    copy_str = SCStrdup(rawstr);
    if (unlikely(copy_str == NULL)) {
        goto error;
    }

    for (pos = 0, df_opt = strtok_r(copy_str, ",", &saveptr);
            pos < strlen(copy_str) && df_opt != NULL;
            pos++, df_opt = strtok_r(NULL, ",", &saveptr)) {
        if (strstr(df_opt, "count"))
            count_found++;
        if (strstr(df_opt, "second"))
            seconds_found++;
        if (strstr(df_opt, "track"))
            track_found++;
    }
    SCFree(copy_str);
    copy_str = NULL;

    if (count_found != 1 || seconds_found != 1 || track_found != 1)
        goto error;

    ret = DetectParsePcreExec(&parse_regex, &match, rawstr, 0, 0);
    if (ret < DF_PARSE_MIN_SUBMATCHES) {
        SCLogError("pcre_exec parse error, ret %" PRId32 ", string %s", ret, rawstr);
        goto error;
    }

    df = SCCalloc(1, sizeof(DetectThresholdData));
    if (unlikely(df == NULL))
        goto error;

    df->type = TYPE_DETECTION;

    for (i = 0; i < (ret - 1); i++) {
        res = pcre2_substring_get_bynumber(match, i + 1, (PCRE2_UCHAR8 **)&str_ptr, &pcre2_len);
        if (res < 0) {
            SCLogError("pcre2_substring_get_bynumber failed");
            goto error;
        }

        args[i] = (char *)str_ptr;
        parsed_count++;

        if (strncasecmp(args[i], "by_dst", strlen("by_dst")) == 0)
            df->track = TRACK_DST;
        if (strncasecmp(args[i], "by_src", strlen("by_src")) == 0)
            df->track = TRACK_SRC;
        if (strncasecmp(args[i], "by_flow", strlen("by_flow")) == 0)
            df->track = TRACK_FLOW;
        if (strncasecmp(args[i], "count", strlen("count")) == 0)
            count_pos = i + 1;
        if (strncasecmp(args[i], "seconds", strlen("seconds")) == 0)
            seconds_pos = i + 1;
        if (strcasecmp(args[i], "src_port") == 0)
            df->unique_on = DF_UNIQUE_SRC_PORT;
        if (strcasecmp(args[i], "dst_port") == 0)
            df->unique_on = DF_UNIQUE_DST_PORT;
    }

    if (args[count_pos] == NULL || args[seconds_pos] == NULL) {
        goto error;
    }

    if (StringParseUint32(&df->count, 10, strlen(args[count_pos]), args[count_pos]) <= 0) {
        goto error;
    }

    if (StringParseUint32(&df->seconds, 10, strlen(args[seconds_pos]), args[seconds_pos]) <= 0) {
        goto error;
    }

    if (df->count == 0 || df->seconds == 0) {
        SCLogError("found an invalid value");
        goto error;
    }

    for (i = 0; i < parsed_count; i++) {
        if (args[i] != NULL)
            pcre2_substring_free((PCRE2_UCHAR *)args[i]);
    }

    pcre2_match_data_free(match);
    return df;

error:
    for (i = 0; i < parsed_count; i++) {
        if (args[i] != NULL)
            pcre2_substring_free((PCRE2_UCHAR *)args[i]);
    }
    if (df != NULL)
        SCFree(df);
    if (match) {
        pcre2_match_data_free(match);
    }
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
static int DetectDetectionFilterSetup(DetectEngineCtx *de_ctx, Signature *s, const char *rawstr)
{
    SCEnter();
    DetectThresholdData *df = NULL;
    SigMatch *tmpm = NULL;

    /* checks if there's a previous instance of threshold */
    tmpm = DetectGetLastSMFromLists(s, DETECT_THRESHOLD, -1);
    if (tmpm != NULL) {
        SCLogError("\"detection_filter\" and \"threshold\" are not allowed in the same rule");
        SCReturnInt(-1);
    }
    /* checks there's no previous instance of detection_filter */
    tmpm = DetectGetLastSMFromLists(s, DETECT_DETECTION_FILTER, -1);
    if (tmpm != NULL) {
        SCLogError("At most one \"detection_filter\" is allowed per rule");
        SCReturnInt(-1);
    }

    df = DetectDetectionFilterParse(rawstr);
    if (df == NULL)
        goto error;

    /* unique_on requires a ported L4 protocol: tcp/udp/sctp */
    if (df->unique_on != DF_UNIQUE_NONE) {
        const int has_tcp = DetectProtoContainsProto(&s->proto, IPPROTO_TCP);
        const int has_udp = DetectProtoContainsProto(&s->proto, IPPROTO_UDP);
        const int has_sctp = DetectProtoContainsProto(&s->proto, IPPROTO_SCTP);
        if (!(has_tcp || has_udp || has_sctp) || (s->proto.flags & DETECT_PROTO_ANY)) {
            SCLogError("detection_filter unique_on requires protocol tcp/udp/sctp");
            goto error;
        }
    }

    if (SCSigMatchAppendSMToList(de_ctx, s, DETECT_DETECTION_FILTER, (SigMatchCtx *)df,
                DETECT_SM_LIST_THRESHOLD) == NULL) {
        goto error;
    }

    return 0;

error:
    if (df)
        SCFree(df);
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
#include "detect-engine-alert.h"
#include "util-time.h"
#include "util-hashlist.h"
#include "action-globals.h"
#include "packet.h"

/* test seams from detect-engine-threshold.c */
void ThresholdForceAllocFail(int);
uint64_t ThresholdGetBitmapMemuse(void);
uint64_t ThresholdGetBitmapAllocFail(void);

/**
 * \test DetectDetectionFilterTestParse01 is a test for a valid detection_filter options
 *
 */
static int DetectDetectionFilterTestParse01(void)
{
    DetectThresholdData *df = DetectDetectionFilterParse("track by_dst,count 10,seconds 60");
    FAIL_IF_NULL(df);
    FAIL_IF_NOT(df->track == TRACK_DST);
    FAIL_IF_NOT(df->count == 10);
    FAIL_IF_NOT(df->seconds == 60);
    DetectDetectionFilterFree(NULL, df);

    PASS;
}

/**
 * \test DetectDetectionFilterTestParse02 is a test for a invalid detection_filter options
 *
 */
static int DetectDetectionFilterTestParse02(void)
{
    DetectThresholdData *df = DetectDetectionFilterParse("track both,count 10,seconds 60");
    FAIL_IF_NOT_NULL(df);

    PASS;
}

/**
 * \test DetectDetectionfilterTestParse03 is a test for a valid detection_filter options in any
 * order
 *
 */
static int DetectDetectionFilterTestParse03(void)
{
    DetectThresholdData *df = DetectDetectionFilterParse("track by_dst, seconds 60, count 10");
    FAIL_IF_NULL(df);
    FAIL_IF_NOT(df->track == TRACK_DST);
    FAIL_IF_NOT(df->count == 10);
    FAIL_IF_NOT(df->seconds == 60);
    DetectDetectionFilterFree(NULL, df);

    PASS;
}

/**
 * \test DetectDetectionFilterTestParse04 is a test for an invalid detection_filter options in any
 * order
 *
 */
static int DetectDetectionFilterTestParse04(void)
{
    DetectThresholdData *df =
            DetectDetectionFilterParse("count 10, track by_dst, seconds 60, count 10");
    FAIL_IF_NOT_NULL(df);

    PASS;
}

/**
 * \test DetectDetectionFilterTestParse05 is a test for a valid detection_filter options in any
 * order
 *
 */
static int DetectDetectionFilterTestParse05(void)
{
    DetectThresholdData *df = DetectDetectionFilterParse("count 10, track by_dst, seconds 60");
    FAIL_IF_NULL(df);
    FAIL_IF_NOT(df->track == TRACK_DST);
    FAIL_IF_NOT(df->count == 10);
    FAIL_IF_NOT(df->seconds == 60);
    DetectDetectionFilterFree(NULL, df);

    PASS;
}

/**
 * \test DetectDetectionFilterTestParse06 is a test for an invalid value in detection_filter
 *
 */
static int DetectDetectionFilterTestParse06(void)
{
    DetectThresholdData *df = DetectDetectionFilterParse("count 10, track by_dst, seconds 0");
    FAIL_IF_NOT_NULL(df);

    PASS;
}
/**
 * \test unique_on requires tcp/udp/sctp protocol; alert ip should fail
 */
static int DetectDetectionFilterUniqueOnProtoValidationFail(void)
{
    ThresholdInit();

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    de_ctx->flags |= DE_QUIET;

    Signature *s = DetectEngineAppendSig(de_ctx,
            "alert ip any any -> any any (msg:\"DF proto validation\"; "
            "detection_filter: track by_dst, count 2, seconds 60, unique_on dst_port; sid:29;)");
    /* setup should fail, append returns NULL */
    FAIL_IF_NOT_NULL(s);

    DetectEngineCtxFree(de_ctx);
    ThresholdDestroy();
    PASS;
}

/**
 * \test DetectDetectionFilterTestParseUnique01 tests parsing unique_on dst_port
 */
static int DetectDetectionFilterTestParseUnique01(void)
{
    DetectThresholdData *df =
            DetectDetectionFilterParse("track by_dst, count 10, seconds 60, unique_on dst_port");
    FAIL_IF_NULL(df);
    FAIL_IF_NOT(df->track == TRACK_DST);
    FAIL_IF_NOT(df->count == 10);
    FAIL_IF_NOT(df->seconds == 60);
    FAIL_IF_NOT(df->unique_on == DF_UNIQUE_DST_PORT);
    DetectDetectionFilterFree(NULL, df);
    PASS;
}

/**
 * \test Distinct boundary: exactly 'count' distinct should not alert
 */
static int DetectDetectionFilterDistinctBoundaryNoAlert(void)
{
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx;

    ThresholdInit();
    memset(&th_v, 0, sizeof(th_v));
    StatsThreadInit(&th_v.stats);

    Packet *p1 = UTHBuildPacketReal(NULL, 0, IPPROTO_TCP, "1.1.1.1", "2.2.2.2", 1024, 80);
    Packet *p2 = UTHBuildPacketReal(NULL, 0, IPPROTO_TCP, "1.1.1.1", "2.2.2.2", 1024, 81);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    de_ctx->flags |= DE_QUIET;

    Signature *s = DetectEngineAppendSig(de_ctx,
            "alert tcp any any -> any any (msg:\"DF distinct boundary no alert\"; "
            "detection_filter: track by_dst, count 2, seconds 60, unique_on dst_port; sid:24;)");
    FAIL_IF_NULL(s);

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p1);
    FAIL_IF(PacketAlertCheck(p1, 24));
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p2);
    FAIL_IF(PacketAlertCheck(p2, 24));

    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);
    UTHFreePackets(&p1, 1);
    UTHFreePackets(&p2, 1);
    ThresholdDestroy();
    StatsThreadCleanup(&th_v.stats);
    PASS;
}

/**
 * \test Distinct window reset: expire and re-trigger after seconds
 */
static int DetectDetectionFilterDistinctWindowReset(void)
{
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx;

    ThresholdInit();
    memset(&th_v, 0, sizeof(th_v));
    StatsThreadInit(&th_v.stats);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    de_ctx->flags |= DE_QUIET;

    Signature *s = DetectEngineAppendSig(de_ctx,
            "alert tcp any any -> any any (msg:\"DF distinct window reset\"; "
            "detection_filter: track by_dst, count 2, seconds 2, unique_on dst_port; sid:25;)");
    FAIL_IF_NULL(s);

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    Packet *p1 = UTHBuildPacketReal(NULL, 0, IPPROTO_TCP, "1.1.1.1", "2.2.2.2", 1024, 80);
    p1->ts = TimeGet();
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p1);
    FAIL_IF(PacketAlertCheck(p1, 25));

    Packet *p2 = UTHBuildPacketReal(NULL, 0, IPPROTO_TCP, "1.1.1.1", "2.2.2.2", 1024, 81);
    p2->ts = TimeGet();
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p2);
    FAIL_IF(PacketAlertCheck(p2, 25));

    Packet *p3 = UTHBuildPacketReal(NULL, 0, IPPROTO_TCP, "1.1.1.1", "2.2.2.2", 1024, 82);
    p3->ts = TimeGet();
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p3);
    FAIL_IF_NOT(PacketAlertCheck(p3, 25));

    /* advance time beyond window to force expiration */
    TimeSetIncrementTime(3);

    Packet *p4 = UTHBuildPacketReal(NULL, 0, IPPROTO_TCP, "1.1.1.1", "2.2.2.2", 1024, 80);
    p4->ts = TimeGet();
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p4);
    FAIL_IF(PacketAlertCheck(p4, 25));

    Packet *p5 = UTHBuildPacketReal(NULL, 0, IPPROTO_TCP, "1.1.1.1", "2.2.2.2", 1024, 81);
    p5->ts = TimeGet();
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p5);
    FAIL_IF(PacketAlertCheck(p5, 25));

    Packet *p6 = UTHBuildPacketReal(NULL, 0, IPPROTO_TCP, "1.1.1.1", "2.2.2.2", 1024, 82);
    p6->ts = TimeGet();
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p6);
    FAIL_IF_NOT(PacketAlertCheck(p6, 25));

    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);
    UTHFreePackets(&p1, 1);
    UTHFreePackets(&p2, 1);
    UTHFreePackets(&p3, 1);
    UTHFreePackets(&p4, 1);
    UTHFreePackets(&p5, 1);
    UTHFreePackets(&p6, 1);
    ThresholdDestroy();
    StatsThreadCleanup(&th_v.stats);
    PASS;
}

/**
 * \test When bitmap alloc fails, unique_on falls back to classic counting (> count)
 */
static int DetectDetectionFilterDistinctAllocFailFallback(void)
{
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx;

    ThresholdInit();
    memset(&th_v, 0, sizeof(th_v));
    StatsThreadInit(&th_v.stats);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    de_ctx->flags |= DE_QUIET;

    /* Force allocation failure for distinct bitmap */
    ThresholdForceAllocFail(1);

    Signature *s = DetectEngineAppendSig(de_ctx,
            "alert tcp any any -> any any (msg:\"DF alloc fail fallback\"; "
            "detection_filter: track by_dst, count 2, seconds 60, unique_on dst_port; sid:27;)");
    FAIL_IF_NULL(s);

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    Packet *p1 = UTHBuildPacketReal(NULL, 0, IPPROTO_TCP, "1.1.1.1", "2.2.2.2", 1024, 80);
    Packet *p2 = UTHBuildPacketReal(NULL, 0, IPPROTO_TCP, "1.1.1.1", "2.2.2.2", 1024, 80);
    Packet *p3 = UTHBuildPacketReal(NULL, 0, IPPROTO_TCP, "1.1.1.1", "2.2.2.2", 1024, 80);

    int result = 0;

    /* Classic detection_filter alerts when current_count > count (i.e., 3rd packet) */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p1);
    if (PacketAlertCheck(p1, 27))
        goto end;
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p2);
    if (PacketAlertCheck(p2, 27))
        goto end;
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p3);
    if (!PacketAlertCheck(p3, 27))
        goto end;

    result = 1;

end:
    /* cleanup and restore hook */
    ThresholdForceAllocFail(0);
    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);
    UTHFreePackets(&p1, 1);
    UTHFreePackets(&p2, 1);
    UTHFreePackets(&p3, 1);
    ThresholdDestroy();
    StatsThreadCleanup(&th_v.stats);
    return result;
}

/**
 * \test DetectDetectionFilterTestSig1 is a test for checking the working of detection_filter
 * keyword by setting up the signature and later testing its working by matching the received packet
 * against the sig.
 *
 */
static int DetectDetectionFilterTestSig1(void)
{
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx;

    ThresholdInit();

    memset(&th_v, 0, sizeof(th_v));
    StatsThreadInit(&th_v.stats);

    Packet *p = UTHBuildPacketReal(NULL, 0, IPPROTO_TCP, "1.1.1.1", "2.2.2.2", 1024, 80);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);

    de_ctx->flags |= DE_QUIET;

    Signature *s = DetectEngineAppendSig(de_ctx,
            "alert tcp any any -> any 80 (msg:\"detection_filter Test\"; detection_filter: "
            "track by_dst, count 4, seconds 60; sid:1;)");
    FAIL_IF_NULL(s);

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    FAIL_IF(PacketAlertCheck(p, 1));
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    FAIL_IF(PacketAlertCheck(p, 1));
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    FAIL_IF(PacketAlertCheck(p, 1));
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    FAIL_IF(PacketAlertCheck(p, 1));
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    FAIL_IF_NOT(PacketAlertCheck(p, 1));
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    FAIL_IF_NOT(PacketAlertCheck(p, 1));
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    FAIL_IF_NOT(PacketAlertCheck(p, 1));
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    FAIL_IF_NOT(PacketAlertCheck(p, 1));

    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);

    UTHFreePackets(&p, 1);
    ThresholdDestroy();
    StatsThreadCleanup(&th_v.stats);
    PASS;
}

/**
 * \test DetectDetectionFilterTestSig2 is a test for checking the working of detection_filter
 * keyword by setting up the signature and later testing its working by matching the received packet
 * against the sig.
 *
 */

static int DetectDetectionFilterTestSig2(void)
{
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx;

    ThresholdInit();

    memset(&th_v, 0, sizeof(th_v));
    StatsThreadInit(&th_v.stats);

    Packet *p = UTHBuildPacketReal(NULL, 0, IPPROTO_TCP, "1.1.1.1", "2.2.2.2", 1024, 80);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();

    FAIL_IF_NULL(de_ctx);

    de_ctx->flags |= DE_QUIET;

    Signature *s = DetectEngineAppendSig(de_ctx,
            "alert tcp any any -> any 80 (msg:\"detection_filter Test 2\"; "
            "detection_filter: track by_dst, count 4, seconds 60; sid:10;)");
    FAIL_IF_NULL(s);

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    p->ts = TimeGet();

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    FAIL_IF(PacketAlertCheck(p, 10));
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    FAIL_IF(PacketAlertCheck(p, 10));
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    FAIL_IF(PacketAlertCheck(p, 10));

    TimeSetIncrementTime(200);
    p->ts = TimeGet();

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    FAIL_IF(PacketAlertCheck(p, 10));
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    FAIL_IF(PacketAlertCheck(p, 10));
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    FAIL_IF(PacketAlertCheck(p, 10));
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    FAIL_IF(PacketAlertCheck(p, 10));

    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);

    UTHFreePackets(&p, 1);
    ThresholdDestroy();
    StatsThreadCleanup(&th_v.stats);
    PASS;
}

/**
 *  \test drops
 */
static int DetectDetectionFilterTestSig3(void)
{
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx;

    ThresholdInit();

    memset(&th_v, 0, sizeof(th_v));
    StatsThreadInit(&th_v.stats);

    Packet *p = UTHBuildPacketReal(NULL, 0, IPPROTO_TCP, "1.1.1.1", "2.2.2.2", 1024, 80);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);

    de_ctx->flags |= DE_QUIET;

    Signature *s = DetectEngineAppendSig(de_ctx,
            "drop tcp any any -> any 80 (msg:\"detection_filter Test 2\"; "
            "detection_filter: track by_dst, count 2, seconds 60; sid:10;)");
    FAIL_IF_NULL(s);

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    p->ts = TimeGet();

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    FAIL_IF(PacketAlertCheck(p, 10));
    FAIL_IF(PacketTestAction(p, ACTION_DROP));
    p->action = 0;

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    FAIL_IF(PacketAlertCheck(p, 10));
    FAIL_IF(PacketTestAction(p, ACTION_DROP));
    p->action = 0;

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    FAIL_IF_NOT(PacketAlertCheck(p, 10));
    FAIL_IF_NOT(PacketTestAction(p, ACTION_DROP));
    p->action = 0;

    TimeSetIncrementTime(200);
    p->ts = TimeGet();

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    FAIL_IF(PacketAlertCheck(p, 10));
    FAIL_IF(PacketTestAction(p, ACTION_DROP));
    p->action = 0;

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    FAIL_IF(PacketAlertCheck(p, 10));
    FAIL_IF(PacketTestAction(p, ACTION_DROP));
    p->action = 0;

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    FAIL_IF_NOT(PacketAlertCheck(p, 10));
    FAIL_IF_NOT(PacketTestAction(p, ACTION_DROP));
    p->action = 0;

    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);

    UTHFreePackets(&p, 1);
    ThresholdDestroy();
    StatsThreadCleanup(&th_v.stats);
    PASS;
}

/**
 * \test Verify bitmap memory is tracked in bitmap_memuse counter
 */
static int DetectDetectionFilterDistinctBitmapMemuseTracking(void)
{
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx;

    ThresholdInit();
    memset(&th_v, 0, sizeof(th_v));
    StatsThreadInit(&th_v.stats);

    /* Record baseline memuse */
    uint64_t baseline_memuse = ThresholdGetBitmapMemuse();

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    de_ctx->flags |= DE_QUIET;

    Signature *s = DetectEngineAppendSig(de_ctx,
            "alert tcp any any -> any any (msg:\"DF memuse tracking\"; "
            "detection_filter: track by_dst, count 2, seconds 60, unique_on dst_port; sid:30;)");
    FAIL_IF_NULL(s);

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    /* Send a packet to trigger threshold entry creation with bitmap */
    Packet *p1 = UTHBuildPacketReal(NULL, 0, IPPROTO_TCP, "1.1.1.1", "2.2.2.2", 1024, 80);
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p1);

    /* Verify bitmap_memuse increased by 8192 bytes (65536/8) */
    uint64_t after_memuse = ThresholdGetBitmapMemuse();
    FAIL_IF_NOT(after_memuse == baseline_memuse + 8192);

    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);
    UTHFreePackets(&p1, 1);
    ThresholdDestroy();

    /* After destroy, bitmap_memuse should return to baseline */
    uint64_t final_memuse = ThresholdGetBitmapMemuse();
    FAIL_IF_NOT(final_memuse == baseline_memuse);

    StatsThreadCleanup(&th_v.stats);
    PASS;
}

/**
 * \test Verify bitmap_alloc_fail counter increments on forced failure
 */
static int DetectDetectionFilterDistinctAllocFailCounter(void)
{
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx;

    ThresholdInit();
    memset(&th_v, 0, sizeof(th_v));
    StatsThreadInit(&th_v.stats);

    /* Record baseline alloc fail count */
    uint64_t baseline_fail = ThresholdGetBitmapAllocFail();

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    de_ctx->flags |= DE_QUIET;

    /* Force allocation failure */
    ThresholdForceAllocFail(1);

    Signature *s = DetectEngineAppendSig(de_ctx,
            "alert tcp any any -> any any (msg:\"DF alloc fail counter\"; "
            "detection_filter: track by_dst, count 2, seconds 60, unique_on dst_port; sid:31;)");
    FAIL_IF_NULL(s);

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    /* Send packet to trigger threshold entry creation (bitmap alloc will fail) */
    Packet *p1 = UTHBuildPacketReal(NULL, 0, IPPROTO_TCP, "1.1.1.1", "2.2.2.2", 1024, 80);
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p1);

    /* Verify alloc_fail counter increased */
    uint64_t after_fail = ThresholdGetBitmapAllocFail();
    FAIL_IF_NOT(after_fail == baseline_fail + 1);

    /* bitmap_memuse should NOT have increased since alloc failed */
    uint64_t memuse = ThresholdGetBitmapMemuse();
    FAIL_IF_NOT(memuse == 0);

    /* cleanup */
    ThresholdForceAllocFail(0);
    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);
    UTHFreePackets(&p1, 1);
    ThresholdDestroy();
    StatsThreadCleanup(&th_v.stats);
    PASS;
}

/**
 * \test Multiple distinct trackers should accumulate bitmap memory
 */
static int DetectDetectionFilterDistinctMultipleTrackers(void)
{
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx;

    ThresholdInit();
    memset(&th_v, 0, sizeof(th_v));
    StatsThreadInit(&th_v.stats);

    uint64_t baseline_memuse = ThresholdGetBitmapMemuse();

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    de_ctx->flags |= DE_QUIET;

    Signature *s = DetectEngineAppendSig(de_ctx,
            "alert tcp any any -> any any (msg:\"DF multi tracker\"; "
            "detection_filter: track by_dst, count 2, seconds 60, unique_on dst_port; sid:32;)");
    FAIL_IF_NULL(s);

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    /* Create packets to different destinations - each will create a new threshold entry */
    Packet *p1 = UTHBuildPacketReal(NULL, 0, IPPROTO_TCP, "1.1.1.1", "2.2.2.2", 1024, 80);
    Packet *p2 = UTHBuildPacketReal(NULL, 0, IPPROTO_TCP, "1.1.1.1", "3.3.3.3", 1024, 80);
    Packet *p3 = UTHBuildPacketReal(NULL, 0, IPPROTO_TCP, "1.1.1.1", "4.4.4.4", 1024, 80);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p1);
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p2);
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p3);

    /* Verify 3 bitmaps allocated = 3 * 8192 = 24576 bytes */
    uint64_t after_memuse = ThresholdGetBitmapMemuse();
    FAIL_IF_NOT(after_memuse == baseline_memuse + (3 * 8192));

    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);
    UTHFreePackets(&p1, 1);
    UTHFreePackets(&p2, 1);
    UTHFreePackets(&p3, 1);
    ThresholdDestroy();

    /* After destroy, should return to baseline */
    uint64_t final_memuse = ThresholdGetBitmapMemuse();
    FAIL_IF_NOT(final_memuse == baseline_memuse);

    StatsThreadCleanup(&th_v.stats);
    PASS;
}

/**
 * \test Bitmap memory is freed when threshold entry expires
 */
static int DetectDetectionFilterDistinctBitmapExpiry(void)
{
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx;

    ThresholdInit();
    memset(&th_v, 0, sizeof(th_v));
    StatsThreadInit(&th_v.stats);

    uint64_t baseline_memuse = ThresholdGetBitmapMemuse();

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    de_ctx->flags |= DE_QUIET;

    /* Use short timeout (2 seconds) */
    Signature *s = DetectEngineAppendSig(de_ctx,
            "alert tcp any any -> any any (msg:\"DF bitmap expiry\"; "
            "detection_filter: track by_dst, count 2, seconds 2, unique_on dst_port; sid:33;)");
    FAIL_IF_NULL(s);

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    Packet *p1 = UTHBuildPacketReal(NULL, 0, IPPROTO_TCP, "1.1.1.1", "2.2.2.2", 1024, 80);
    p1->ts = TimeGet();
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p1);

    /* Verify bitmap allocated */
    uint64_t after_alloc = ThresholdGetBitmapMemuse();
    FAIL_IF_NOT(after_alloc == baseline_memuse + 8192);

    /* Advance time beyond the timeout to expire the entry */
    TimeSetIncrementTime(5);

    /* Trigger expiration by calling ThresholdsExpire */
    SCTime_t now = TimeGet();
    ThresholdsExpire(now);

    /* After expiry, bitmap memory should be freed */
    uint64_t after_expiry = ThresholdGetBitmapMemuse();
    FAIL_IF_NOT(after_expiry == baseline_memuse);

    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);
    UTHFreePackets(&p1, 1);
    ThresholdDestroy();
    StatsThreadCleanup(&th_v.stats);
    PASS;
}

static void DetectDetectionFilterRegisterTests(void)
{
    UtRegisterTest("DetectDetectionFilterTestParse01", DetectDetectionFilterTestParse01);
    UtRegisterTest("DetectDetectionFilterTestParse02", DetectDetectionFilterTestParse02);
    UtRegisterTest("DetectDetectionFilterTestParse03", DetectDetectionFilterTestParse03);
    UtRegisterTest("DetectDetectionFilterTestParse04", DetectDetectionFilterTestParse04);
    UtRegisterTest("DetectDetectionFilterTestParse05", DetectDetectionFilterTestParse05);
    UtRegisterTest("DetectDetectionFilterTestParse06", DetectDetectionFilterTestParse06);
    UtRegisterTest(
            "DetectDetectionFilterTestParseUnique01", DetectDetectionFilterTestParseUnique01);
    UtRegisterTest("DetectDetectionFilterTestSig1", DetectDetectionFilterTestSig1);
    UtRegisterTest("DetectDetectionFilterTestSig2", DetectDetectionFilterTestSig2);
    UtRegisterTest("DetectDetectionFilterTestSig3", DetectDetectionFilterTestSig3);
    UtRegisterTest("DetectDetectionFilterDistinctBoundaryNoAlert",
            DetectDetectionFilterDistinctBoundaryNoAlert);
    UtRegisterTest(
            "DetectDetectionFilterDistinctWindowReset", DetectDetectionFilterDistinctWindowReset);
    UtRegisterTest("DetectDetectionFilterDistinctAllocFailFallback",
            DetectDetectionFilterDistinctAllocFailFallback);
    UtRegisterTest("DetectDetectionFilterUniqueOnProtoValidationFail",
            DetectDetectionFilterUniqueOnProtoValidationFail);
    UtRegisterTest("DetectDetectionFilterDistinctBitmapMemuseTracking",
            DetectDetectionFilterDistinctBitmapMemuseTracking);
    UtRegisterTest("DetectDetectionFilterDistinctAllocFailCounter",
            DetectDetectionFilterDistinctAllocFailCounter);
    UtRegisterTest("DetectDetectionFilterDistinctMultipleTrackers",
            DetectDetectionFilterDistinctMultipleTrackers);
    UtRegisterTest(
            "DetectDetectionFilterDistinctBitmapExpiry", DetectDetectionFilterDistinctBitmapExpiry);
}
#endif /* UNITTESTS */
