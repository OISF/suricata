/* Copyright (C) 2024 Open Information Security Foundation
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

/** \file
 *
 * Benchmark Suricata's content inspection code and the closely related
 * SPM (single pattern matcher) code.
 */

#include "suricata.h"
#include "detect.h"
#include "detect-parse.h"
#include "detect-engine.h"
#include "detect-engine-build.h"
#include "detect-engine-content-inspection.h"
#include "util-conf.h"
#include "util-spm.h"

char csv[8192] = "";
char csvh[8192] = "";

/* Signatures should have a short message w/o comma's as they are used as header in the csv output.
 */
const char *sigs1[] = {
    "alert ip any any -> any any (content:\"abcdef\"; sid:1; msg:\"floating pattern start\";)",
    "alert ip any any -> any any (content:\"uvwxyz\"; sid:2; msg:\"floating pattern end\";)",
    "alert ip any any -> any any (content:\"lmnopqrstuvwxyz\"; sid:3; msg:\"floating pattern end "
    "long\";)",
    "alert ip any any -> any any (content:\"xxxxxxxxxxxxxxxxxxxxxxxxxlmnopqrstuvwxyz\"; sid:4; "
    "msg:\"floating pattern end longer\";)",
    "alert ip any any -> any any (content:\"abc\"; depth:3; sid:5; msg:\"anchor depth == "
    "pattern\";)",
    "alert ip any any -> any any (content:\"abc\"; startswith; sid:6; msg:\"startswith\";)",
    "alert ip any any -> any any (content:\"xyz\"; endswith; sid:7; msg:\"endswith\";)",
    "alert ip any any -> any any (content:\"abc\"; content:\"def\"; distance:0; within:3; sid:8; "
    "msg:\"split floating pattern\";)",
    "alert ip any any -> any any (content:\"abc\"; content:\"xyz\"; distance:0; sid:9; "
    "msg:\"pattern1 followed by pattern2\";)",
    "alert ip any any -> any any (content:\"abcdef\"; content:\"xyz\"; distance:0; sid:10; "
    "msg:\"longer pattern1 followed by pattern2\";)",
    "alert ip any any -> any any (content:\"abc\"; content:\"def\"; distance:0; within:3; "
    "content:\"xyz\"; distance:0; sid:11; msg:\"split pattern followed by pattern3\";)",
    "alert ip any any -> any any (content:\"def\"; offset:3; depth:3; sid:12; msg:\"single "
    "anchored pattern\";)",
    "alert ip any any -> any any (pcre:\"/^abc/\"; sid:13; msg:\"pcre anchored\";)",
    "alert ip any any -> any any (content:\"abc\"; depth:3; pcre:\"/^abc/\"; sid:14; msg:\"pattern "
    "anchored pcre anchored\";)",
    "alert ip any any -> any any (pcre:\"/^abc.*xyz/\"; sid:15; msg:\"pcre anchored pat1 -> "
    "pat2\";)",
    "alert ip any any -> any any (pcre:\"/^abc.*xyz$/\"; sid:16; msg:\"pcre anchored pat1 -> "
    "anchored pat2\";)",
    "alert ip any any -> any any (pcre:\"/^abc/\"; pcre:\"/xyz$/R\"; sid:17; msg:\"anchored pat1 "
    "-> pcre anchored pat2\";)",
    "alert ip any any -> any any (content:\"abc\"; depth:3; content:\"xyz\"; endswith; sid:18; "
    "msg:\"anchored pat1 -> anchored pat2\";)",
    "alert ip any any -> any any (content:\"abc\"; depth:3; content:\"xyz\"; endswith; "
    "pcre:\"/^abc.*xyz/\"; sid:19; msg:\"anchored pat1 -> anchored pat2 repeat for pcre\";)",
    "alert ip any any -> any any (content:\"abc\"; depth:3; content:\"xyz\"; endswith; "
    "pcre:\"/^abc.*xyz$/\"; sid:20; msg:\"anchored pat1 -> anchored pat2 repeat for pcre "
    "anchored\";)",
    "alert ip any any -> any any (content:\"abc\"; isdataat:!1000,relative; sid:21; msg:\"floating "
    "pattern followed by !isdataat\";)",
    "alert ip any any -> any any (content:!\"xyz\"; startswith; sid:22; msg:\"negated "
    "startswith\";)",
    "alert ip any any -> any any (content:!\"abc\"; endswith; sid:23; msg:\"negated endswith\";)",
    "alert ip any any -> any any (content:!\"abcdefxyz\"; sid:24; msg:\"negated floating "
    "pattern\";)",
    "alert ip any any -> any any (byte_test:1,=,97,0; byte_jump:1,1; byte_test:1,!=,97,0,relative; "
    "sid:25; msg:\"byte: test>jump>test\";)",
    "alert ip any any -> any any (content:\"abc\"; content:\"xxl\"; distance:0; content:\"xyz\"; "
    "distance:0; sid:26; msg:\"pat1>pat2>pat3\";)",
    "alert ip any any -> any any (pcre:\"/abc.*xxl.*xyz/\"; sid:27; msg:\"pat1>pat2>pat3(pcre)\";)",
    "alert ip any any -> any any (content:\"abc\"; nocase; content:\"xxl\"; distance:0; nocase; "
    "content:\"xyz\"; distance:0; nocase; sid:28; msg:\"pat1>pat2>pat3 nocase\";)",
    "alert ip any any -> any any (pcre:\"/abc.*xxl.*xyz/i\"; sid:29; "
    "msg:\"pat1>pat2>pat3(pcre/i)\";)",
    "alert ip any any -> any any (content:\"XXLMNOPQRSTUVWXYZ\"; nocase; sid:30; msg:\"pat1 "
    "nocase\";)",
    "alert ip any any -> any any (content:\"ABC\"; nocase; startswith; content:\"GHI\"; nocase; "
    "distance:3; within:3; sid:31; msg:\"anchored implicit nocase\";)",
    NULL,
};

const char *sigs2[] = {
    "alert ip any any -> any any (content:\"a\"; content:\"b\"; within:1; distance:0; "
    "content:\"l\"; within:1; distance:0; sid:10001;)",
    "alert ip any any -> any any (content:\"a\"; depth:1; content:\"b\"; within:1; distance:0; "
    "content:\"l\"; within:1; distance:0; sid:10002;)",
    "alert ip any any -> any any (content:\"ab\"; content:\"l\"; within:1; distance:0; sid:1;)",
    "alert ip any any -> any any (content:\"abl\"; sid:10003;)",
    "alert ip any any -> any any (content:\"A\"; nocase; content:\"B\"; nocase; within:1; "
    "distance:0; "
    "content:\"L\"; nocase; within:1; distance:0; sid:10004;)",
    NULL,
};

const char *bufs[] = { "a",
    "abcdefghijkxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxlmnopqrstuvwxyz",
    "abcdefghijkabababababababababababababababababababababababababababababababababababababababx"
    "ababababababababababababababababababababababababababababababababababababababababababababab"
    "ababababababababababababababababababababababababababababababababababababababababababababab"
    "ababababababababababababababababababababababababababababababababababababababababababababab"
    "ababababababababababababababababababababababababababababababababababababababababababababab"
    "ababababababababababababababababababababababababababababababababababababababababababababab"
    "ababababababababababababababababababababababababababababababababababababababababababababab"
    "ababababababababababababababababababababababababababababababababababababababababababababab"
    "ababababababababababababababababababababababababababababababxlmnopqrstuvwxyz",
    "abcdefghijkxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxlmnopqrstuvwxyz",
    "ABCDEFGHIJKXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
    "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
    "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
    "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
    "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
    "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
    "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
    "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
    "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXLMNOPQRSTUVWXYZ",
    NULL };

// based on: https://www.gnu.org/software/libc/manual/html_node/Calculating-Elapsed-Time.html
int timespec_subtract(struct timespec *result, struct timespec *x, struct timespec *y)
{
    /* Perform the carry for the later subtraction by updating y. */
    if (x->tv_nsec < y->tv_nsec) {
        int64_t nsec = (y->tv_nsec - x->tv_nsec) / 1000000000LL + 1;
        y->tv_nsec -= 1000000000LL * nsec;
        y->tv_sec += nsec;
    }
    if (x->tv_nsec - y->tv_nsec > 1000000000LL) {
        int64_t nsec = (x->tv_nsec - y->tv_nsec) / 1000000000LL;
        y->tv_nsec += 1000000000LL * nsec;
        y->tv_sec -= nsec;
    }

    /* Compute the time remaining to wait.
       tv_usec is certainly positive. */
    result->tv_sec = x->tv_sec - y->tv_sec;
    result->tv_nsec = x->tv_nsec - y->tv_nsec;

    /* Return 1 if result is negative. */
    return x->tv_sec < y->tv_sec;
}

/* strstr is not usable as spm, since it is for strings, not byte arrays. Test it anyway to get a
 * sense for what is possible wrt optimizations. */
static void StrstrBaselinePattern(const char *needles[])
{
    const char *buf = bufs[1];
    char csv_line[8192] = "";
    uint64_t total_nsecs = 0;
    uint64_t total_evals = 0;
    snprintf(csv_line, sizeof(csv_line), "%s,", "strstr");

    int i = 0;
    do {
        const char *needle = needles[i];
        struct timespec tps, tpe;
        clock_gettime(CLOCK_REALTIME, &tps);

        uint64_t cnt = 0;
        uint64_t matches = 0;

        uint32_t volatile x = 0;
        for (; x < 1000000; x++) {
            cc_barrier();
            cnt++;
            char *found = strstr((const char *)buf, needle);
            matches = (found != NULL);
        }

        clock_gettime(CLOCK_REALTIME, &tpe);
        struct timespec diff;
        int r = timespec_subtract(&diff, &tpe, &tps);
        BUG_ON(r != 0);

        BUG_ON(matches != 0 && matches != 1000000 && x != 1000000);

        uint64_t nsecs = diff.tv_sec * 1000000000ULL + diff.tv_nsec;
        uint64_t nsecs_avg = nsecs / cnt;
        total_nsecs += nsecs_avg;
        total_evals++;

        char value[32] = "";
        snprintf(value, sizeof(value), "%" PRIu64 ",", nsecs_avg);
        strlcat(csv_line, value, sizeof(csv_line));

        i++;
    } while (needles[i] != NULL);

    char value[32] = "";
    snprintf(value, sizeof(value), "%" PRIu64 "\n", total_nsecs / total_evals);
    strlcat(csv_line, value, sizeof(csv_line));
    printf("%s", csv_line);
}

static void MemmemBaselinePattern(const char *needles[])
{
    const char *buf = bufs[1];
    const size_t buf_size = strlen(buf);
    char csv_line[8192] = "";
    uint64_t total_nsecs = 0;
    uint64_t total_evals = 0;
    snprintf(csv_line, sizeof(csv_line), "%s,", "memmem");

    int i = 0;
    do {
        const char *needle = needles[i];
        const size_t needle_len = strlen(needle);
        struct timespec tps, tpe;
        clock_gettime(CLOCK_REALTIME, &tps);

        uint64_t cnt = 0;
        uint64_t matches = 0;

        uint32_t volatile x = 0;
        for (; x < 1000000; x++) {
            cc_barrier();
            cnt++;
            void *found = memmem(buf, buf_size, needle, needle_len);
            matches = (found != NULL);
        }

        clock_gettime(CLOCK_REALTIME, &tpe);
        struct timespec diff;
        int r = timespec_subtract(&diff, &tpe, &tps);
        BUG_ON(r != 0);

        BUG_ON(matches != 0 && matches != 1000000 && x != 1000000);

        uint64_t nsecs = diff.tv_sec * 1000000000ULL + diff.tv_nsec;
        uint64_t nsecs_avg = nsecs / cnt;
        total_nsecs += nsecs_avg;
        total_evals++;

        char value[32] = "";
        snprintf(value, sizeof(value), "%" PRIu64 ",", nsecs_avg);
        strlcat(csv_line, value, sizeof(csv_line));

        i++;
    } while (needles[i] != NULL);

    char value[32] = "";
    snprintf(value, sizeof(value), "%" PRIu64 "\n", total_nsecs / total_evals);
    strlcat(csv_line, value, sizeof(csv_line));
    printf("%s", csv_line);
}

static void BasicSearchBaselinePattern(const char *needles[])
{
    const char *buf = bufs[1];
    const size_t buf_size = strlen(buf);
    char csv_line[8192] = "";
    uint64_t total_nsecs = 0;
    uint64_t total_evals = 0;
    snprintf(csv_line, sizeof(csv_line), "%s,", "bs");

    int i = 0;
    do {
        const char *needle = needles[i];
        const size_t needle_len = strlen(needle);
        struct timespec tps, tpe;
        clock_gettime(CLOCK_REALTIME, &tps);

        uint64_t cnt = 0;
        uint64_t matches = 0;

        uint32_t volatile x = 0;
        for (; x < 100000; x++) {
            cc_barrier();
            cnt++;
            uint8_t *found = BasicSearch(
                    (const uint8_t *)buf, buf_size, (const uint8_t *)needle, needle_len);
            matches = (found != NULL);
        }

        clock_gettime(CLOCK_REALTIME, &tpe);
        struct timespec diff;
        int r = timespec_subtract(&diff, &tpe, &tps);
        BUG_ON(r != 0);

        BUG_ON(matches != 0 && matches != 100000 && x != 100000);

        uint64_t nsecs = diff.tv_sec * 1000000000ULL + diff.tv_nsec;
        uint64_t nsecs_avg = nsecs / cnt;
        total_nsecs += nsecs_avg;
        total_evals++;

        char value[32] = "";
        snprintf(value, sizeof(value), "%" PRIu64 ",", nsecs_avg);
        strlcat(csv_line, value, sizeof(csv_line));

        i++;
    } while (needles[i] != NULL);

    char value[32] = "";
    snprintf(value, sizeof(value), "%" PRIu64 "\n", total_nsecs / total_evals);
    strlcat(csv_line, value, sizeof(csv_line));
    printf("%s", csv_line);
}

static void SpmBaselinePatterns(const char *needles[], const uint8_t matcher)
{
    const char *buf = bufs[1];
    size_t buf_size = strlen(buf);
    char csv_line[8192] = "";
    uint64_t total_nsecs = 0;
    uint64_t total_evals = 0;
    int i = 0;
    snprintf(csv_line, sizeof(csv_line), "%s,", spm_table[matcher].name);
    do {
        const char *needle = needles[i];

        SpmGlobalThreadCtx *g_thread_ctx = SpmInitGlobalThreadCtx(matcher);
        BUG_ON(g_thread_ctx == NULL);

        SpmCtx *spm_ctx = SpmInitCtx((const uint8_t *)needle, strlen(needle), 0, g_thread_ctx);
        BUG_ON(!spm_ctx);
        SpmThreadCtx *thread_ctx = SpmMakeThreadCtx(g_thread_ctx);
        BUG_ON(thread_ctx == NULL);

        struct timespec tps, tpe;
        clock_gettime(CLOCK_REALTIME, &tps);

        uint64_t cnt = 0;
        uint64_t matches = 0;

        uint32_t volatile x = 0;
        for (; x < 1000000; x++) {
            cc_barrier();
            cnt++;
            SpmScan(spm_ctx, thread_ctx, (const uint8_t *)buf, buf_size);
        }

        clock_gettime(CLOCK_REALTIME, &tpe);
        struct timespec diff;
        int r = timespec_subtract(&diff, &tpe, &tps);
        BUG_ON(r != 0);
        uint64_t nsecs = diff.tv_sec * 1000000000ULL + diff.tv_nsec;
        uint64_t nsecs_avg = nsecs / cnt;
        total_nsecs += nsecs_avg;
        total_evals++;

        BUG_ON(matches != 0 && matches != 1000000 && x != 1000000);

        SpmDestroyThreadCtx(thread_ctx);
        SpmDestroyGlobalThreadCtx(g_thread_ctx);
        SpmDestroyCtx(spm_ctx);

        char value[32] = "";
        snprintf(value, sizeof(value), "%" PRIu64 ",", nsecs_avg);
        strlcat(csv_line, value, sizeof(csv_line));

        i++;
    } while (needles[i] != NULL);

    char value[32] = "";
    snprintf(value, sizeof(value), "%" PRIu64 "\n", total_nsecs / total_evals);
    strlcat(csv_line, value, sizeof(csv_line));
    printf("%s", csv_line);
}

const char *patterns[] = {
    "a",
    "z",
    "abc",
    "abcdef",
    "xyz",
    "uvwxyz",
    "abcdefxyz",
    "xxxxxxxxxxxxxxxx",
    NULL,
};

static void SpmBaseline(void)
{
    printf("spm,");
    int i = 0;
    do {
        const char *needle = patterns[i];
        printf("%s,", needle);
        i++;
    } while (patterns[i] != NULL);
    printf("avg,\n");

    MemmemBaselinePattern(patterns);
    StrstrBaselinePattern(patterns);
    BasicSearchBaselinePattern(patterns);

    for (i = 0; i < SPM_TABLE_SIZE; i++) {
        if (spm_table[i].name == NULL)
            continue;
        SpmBaselinePatterns(patterns, i);
    }
}

static void Run(ThreadVars *tv, const char *sigs[], const uint32_t loops, const char *test,
        const char *prefix)
{
    char filename[PATH_MAX];
    snprintf(filename, sizeof(filename), "%s-%s.csv", prefix, test);
    FILE *fp = fopen(filename, "w");
    BUG_ON(fp == NULL);
    bool once = false;

    for (uint8_t m = 0; m < SPM_TABLE_SIZE; m++) {
        if (spm_table[m].name == NULL)
            continue;
        const char *spm = spm_table[m].name;
        ConfSet("spm-algo", spm_table[m].name);
        printf("SPM matcher %s\tTest %s:\t", spm_table[m].name, test);

        snprintf(csvh, sizeof(csvh), "spm,");
        snprintf(csv, sizeof(csv), "%s,", spm);

        uint64_t total_nsecs = 0;
        uint64_t total_evals = 0;

        int i = 0;
        do {
            char sidstr[64];
            const char *sig = sigs[i];
            DetectEngineThreadCtx *det_ctx = NULL;
            DetectEngineCtx *de_ctx = DetectEngineCtxInit();
            if (de_ctx == NULL) {
                exit(EXIT_FAILURE);
            }
            de_ctx->flags |= DE_QUIET;
            DetectEngineAddToMaster(de_ctx);

            Signature *s = DetectEngineAppendSig(de_ctx, sig);
            if (s == NULL)
                goto error;
            SigGroupBuild(de_ctx);

            if (s->msg) {
                snprintf(sidstr, sizeof(sidstr), "sid:%u-%s", s->id, s->msg);
            } else {
                snprintf(sidstr, sizeof(sidstr), "sid:%u", s->id);
            }

            SigMatchData *smd = s->sm_arrays[1];
            BUG_ON(smd == NULL);

            BUG_ON(DetectEngineThreadCtxInit(tv, (void *)de_ctx, (void *)&det_ctx) != TM_ECODE_OK);

            uint64_t sig_nsecs = 0;

            int b = 0;
            do {
                const size_t buf_size = strlen(bufs[b]);
                struct timespec tps, tpe;
                clock_gettime(CLOCK_REALTIME, &tps);

                uint64_t cnt = 0;
                for (uint32_t x = 0; x < loops; x++) {
                    cnt++;

                    (void)DetectEngineContentInspection(de_ctx, det_ctx, s, smd, NULL, NULL,
                            (const uint8_t *)bufs[b], buf_size, 0, DETECT_CI_FLAGS_SINGLE,
                            DETECT_ENGINE_CONTENT_INSPECTION_MODE_PAYLOAD);
                }
                clock_gettime(CLOCK_REALTIME, &tpe);
                struct timespec diff;
                int r = timespec_subtract(&diff, &tpe, &tps);
                BUG_ON(r != 0);
                uint64_t nsecs = diff.tv_sec * 1000000000ULL + diff.tv_nsec;
                sig_nsecs += (nsecs / cnt);
                total_nsecs += sig_nsecs;
                total_evals++;

                b++;
            } while (bufs[b] != NULL);

            char csve[128] = "";
            snprintf(csve, sizeof(csve), "%s,", sidstr);
            strlcat(csvh, csve, sizeof(csvh));
            char csvv[64] = "";
            snprintf(csvv, sizeof(csvv), "%" PRIu64 ",", sig_nsecs / b);
            strlcat(csv, csvv, sizeof(csv));

            DetectEngineThreadCtxDeinit(tv, (void *)det_ctx);
            DetectEngineMoveToFreeList(de_ctx);
            DetectEnginePruneFreeList();
            DetectEngineBumpVersion();

            i++;
        } while (sigs[i] != NULL);

        /* print csv header once */
        if (!once) {
            fprintf(fp, "%s\n", csvh);
            once = true;
        }
        fprintf(fp, "%s\n", csv);
        printf("%" PRIu64 "\n", total_nsecs / total_evals);
    }

    fclose(fp);
    return;
error:
    fclose(fp);
    exit(EXIT_FAILURE);
}

int main(int argc, char **argv)
{
    SCInstance instance;
    ThreadVars th_v;
    SuricataPreInit(argv[0]);
    memset(&th_v, 0, sizeof(th_v));
    memset(&instance, 0, sizeof(instance));

    if (argc <= 1) {
        SCLogError("call with '%s <filename prefix>'. E.g. '%s master'", argv[0], argv[0]);
        exit(EXIT_FAILURE);
    }

    setenv("SC_LOG_LEVEL", "Error", 1);
    InitGlobal();
    GlobalsInitPreConfig();
    ConfigSetLogDirectory("/tmp/");
    PostConfLoadedSetup(&instance);
    PostConfLoadedDetectSetup(&instance);

    SpmBaseline();

    Run(&th_v, sigs1, 10000, "common", argv[1]);
    Run(&th_v, sigs2, 10000, "edge", argv[1]);

    GlobalsDestroy();
    return EXIT_SUCCESS;
}
