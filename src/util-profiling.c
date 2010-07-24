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
 * \author Endace Technology Limited.
 *
 * An API for profiling operations.
 *
 * Really just a wrapper around the existing perf counters.
 */

#include "suricata-common.h"
#include "detect.h"
#include "counters.h"
#include "conf.h"
#include "util-unittest.h"
#include "util-byte.h"
#include "util-profiling.h"

#ifdef PROFILING

#define MIN(a, b) (((a) < (b)) ? (a) : (b))

/**
 * Sort orders for dumping profiled rules.
 */
enum {
    SC_PROFILING_RULES_SORT_BY_TICKS = 0,
    SC_PROFILING_RULES_SORT_BY_AVG_TICKS,
    SC_PROFILING_RULES_SORT_BY_CHECKS,
    SC_PROFILING_RULES_SORT_BY_MATCHES,
};
static int profiling_rules_sort_order = SC_PROFILING_RULES_SORT_BY_TICKS;

/**
 * Maximum number of rules to dump.
 */
static uint32_t profiling_rules_limit = UINT32_MAX;

static SCPerfContext rules_ctx;
static SCPerfCounterArray *rules_pca;

/**
 * Extra data for rule profiling.
 */
typedef struct SCProfileData_ {
    uint64_t matches;
} SCProfileData;
SCProfileData rules_profile_data[0xffff];

/**
 * Used for generating the summary data to print.
 */
typedef struct SCProfileSummary_ {
    char *name;
    uint64_t ticks;
    double avgticks;
    uint64_t checks;
    uint64_t matches;
} SCProfileSummary;

int profiling_rules_enabled = 0;

/**
 * Used as a check so we don't double enter a profiling run.
 */
__thread int profiling_entered = 0;

/**
 * \brief Initialize profiling.
 */
void
SCProfilingInit(void)
{
    ConfNode *conf;
    const char *val;

    conf = ConfGetNode("profiling.rules");
    if (conf == NULL) {
        return;
    }
    if (ConfNodeChildValueIsTrue(conf, "enabled")) {
        memset(rules_profile_data, 0, sizeof(rules_profile_data));
        memset(&rules_ctx, 0, sizeof(rules_ctx));
        rules_pca = SCPerfGetAllCountersArray(NULL);
        if (SCMutexInit(&rules_ctx.m, NULL) != 0) {
            SCLogError(SC_ERR_MEM_ALLOC,
                "Failed to initialize hash table mutex.");
            exit(EXIT_FAILURE);
        }
        profiling_rules_enabled = 1;

        val = ConfNodeLookupChildValue(conf, "sort");
        if (val != NULL) {
            if (strcmp(val, "ticks") == 0) {
                profiling_rules_sort_order =
                    SC_PROFILING_RULES_SORT_BY_TICKS;
            }
            else if (strcmp(val, "avgticks") == 0) {
                profiling_rules_sort_order =
                    SC_PROFILING_RULES_SORT_BY_AVG_TICKS;
            }
            else if (strcmp(val, "checks") == 0) {
                profiling_rules_sort_order =
                    SC_PROFILING_RULES_SORT_BY_CHECKS;
            }
            else if (strcmp(val, "matches") == 0) {
                profiling_rules_sort_order =
                    SC_PROFILING_RULES_SORT_BY_MATCHES;
            }
        }

        val = ConfNodeLookupChildValue(conf, "limit");
        if (val != NULL) {
            if (ByteExtractStringUint32(&profiling_rules_limit, 10,
                    (uint16_t)strlen(val), val) <= 0) {
                SCLogError(SC_ERR_INVALID_ARGUMENT, "Invalid limit: %s", val);
                exit(EXIT_FAILURE);
            }
        }
    }
}

/**
 * \brief Free resources used by profiling.
 */
void
SCProfilingDestroy(void)
{
    if (profiling_rules_enabled) {
        SCPerfReleasePerfCounterS(rules_ctx.head);
        SCPerfReleasePCA(rules_pca);
    }
}

/**
 * \brief Qsort comparison function to sort by ticks.
 */
static int
SCProfileSummarySortByTicks(const void *a, const void *b)
{
    const SCProfileSummary *s0 = a;
    const SCProfileSummary *s1 = b;
    return s1->ticks - s0->ticks;
}

/**
 * \brief Qsort comparison function to sort by average ticks.
 */
static int
SCProfileSummarySortByAvgTicks(const void *a, const void *b)
{
    const SCProfileSummary *s0 = a;
    const SCProfileSummary *s1 = b;
    return s1->avgticks - s0->avgticks;
}

/**
 * \brief Qsort comparison function to sort by checks.
 */
static int
SCProfileSummarySortByChecks(const void *a, const void *b)
{
    const SCProfileSummary *s0 = a;
    const SCProfileSummary *s1 = b;
    return s1->checks - s0->checks;
}

/**
 * \brief Qsort comparison function to sort by matches.
 */
static int
SCProfileSummarySortByMatches(const void *a, const void *b)
{
    const SCProfileSummary *s0 = a;
    const SCProfileSummary *s1 = b;
    return s1->matches - s0->matches;
}

void
SCProfilingDump(FILE *output)
{
    uint32_t i;

    if (rules_pca == NULL) {
        SCLogDebug("No rules specified to provide a profiling summary");
        return;
    }

    SCProfileSummary *summary = SCMalloc(sizeof(SCProfileSummary) * rules_pca->size);
    if (summary == NULL) {
        SCLogError(SC_ERR_MEM_ALLOC, "Error allocating memory for profiling summary");
        return;
    }

    uint32_t count = rules_pca->size;
    uint64_t total_ticks = 0;

    SCLogInfo("Dumping profiling data.");

    memset(summary, 0, sizeof(summary));
    for (i = 1; i < count + 1; i++) {
        summary[i - 1].name = rules_pca->head[i].pc->name->cname;
        summary[i - 1].ticks =  rules_pca->head[i].ui64_cnt;
        if (rules_pca->head[i].ui64_cnt)
            summary[i - 1].avgticks = (long double)rules_pca->head[i].ui64_cnt /
                (long double)rules_pca->head[i].syncs;
        summary[i - 1].checks = rules_pca->head[i].syncs;
        summary[i - 1].matches = rules_profile_data[i].matches;
        total_ticks += summary[i - 1].ticks;
    }

    switch (profiling_rules_sort_order) {
    case SC_PROFILING_RULES_SORT_BY_TICKS:
        qsort(summary, count, sizeof(SCProfileSummary),
            SCProfileSummarySortByTicks);
        break;
    case SC_PROFILING_RULES_SORT_BY_AVG_TICKS:
        qsort(summary, count, sizeof(SCProfileSummary),
            SCProfileSummarySortByAvgTicks);
        break;
    case SC_PROFILING_RULES_SORT_BY_CHECKS:
        qsort(summary, count, sizeof(SCProfileSummary),
            SCProfileSummarySortByChecks);
        break;
    case SC_PROFILING_RULES_SORT_BY_MATCHES:
        qsort(summary, count, sizeof(SCProfileSummary),
            SCProfileSummarySortByMatches);
        break;
    }

    fprintf(output, "  %-12s %-12s %-6s %-8s %-8s %-11s\n", "Rule", "Ticks", "%", "Checks", "Matches", "Avg Ticks");
    fprintf(output, "  ------------ "
        "------------ "
        "------ "
        "-------- "
        "-------- "
        "----------- "
        "\n");
    for (i = 0; i < MIN(count, profiling_rules_limit); i++) {
        double percent = (long double)summary[i].ticks /
            (long double)total_ticks * 100;
        fprintf(output,
            "  %-12s %-12"PRIu64" %-6.2f %-8"PRIu64" %-8"PRIu64" %-8.2f\n",
            summary[i].name,
            summary[i].ticks,
            percent,
            summary[i].checks,
            summary[i].matches,
            summary[i].avgticks);
    }

    SCLogInfo("Done dumping profiling data.");
}

/**
 * \brief Register a rule profiling counter.
 *
 * \param gid The GID of the rule.
 * \param sid The SID of the rule.
 *
 * \retval Returns the ID of the counter on success, 0 on failure.
 */
static uint16_t
SCProfilingRegisterRuleCounter(Signature *sig)
{
    char name[12];
    uint16_t id;

    /* Don't use GID right now... */
    //snprintf(name, sizeof(name), "%"PRIu32":%"PRIu32, gid, sid);
    snprintf(name, sizeof(name), "%"PRIu32, sig->id);

    id = SCPerfRegisterCounter(name, "profiler", SC_PERF_TYPE_UINT64, NULL,
        &rules_ctx);
    return id;
}

/**
 * \brief Register the rule profiling counters.
 *
 * \param de_ctx The active DetectEngineCtx, used to get at the loaded rules.
 */
void
SCProfilingInitRuleCounters(DetectEngineCtx *de_ctx)
{
    Signature *sig = de_ctx->sig_list;
    uint32_t count = 0;
    while (sig != NULL) {
        sig->profiling_id = SCProfilingRegisterRuleCounter(sig);
        sig = sig->next;
        count++;
    }
    rules_pca = SCPerfGetAllCountersArray(&rules_ctx);
    SCLogInfo("Registered %"PRIu32" rule profiling counters.\n", count);
}

/**
 * \brief Add a uint64_t value to the current value of the rule
 *     counter ID.
 *
 * \param id The ID of the rule profiling counter.
 * \paral val The value to add to the counter.
 */
void
SCProfilingCounterAddUI64(uint16_t id, uint64_t val)
{
    SCPerfCounterAddUI64(id, rules_pca, val);
}

/**
 * \brief Update a rule counter.
 *
 * \param id The ID of this counter.
 * \param ticks Number of CPU ticks for this rule.
 * \param match Did the rule match?
 */
void
SCProfilingUpdateRuleCounter(uint16_t id, uint64_t ticks, int match)
{
    SCMutexLock(&rules_ctx.m);
    SCProfilingCounterAddUI64(id, ticks);
    rules_profile_data[id].matches += match;
    SCMutexUnlock(&rules_ctx.m);
}

#ifdef UNITTESTS

static int
ProfilingTest01(void)
{
    uint16_t counter1;

    Signature sig;
    sig.gid = 1;
    sig.id = 1;

    SCProfilingInit();
    counter1 = SCProfilingRegisterRuleCounter(&sig);
    if (counter1 == 0)
        return 0;
    rules_pca = SCPerfGetAllCountersArray(&rules_ctx);
    if (rules_pca == NULL)
        return 0;
    SCProfilingCounterAddUI64(counter1, 64);
    if (rules_pca->head[counter1].ui64_cnt != 64)
        return 0;
    if (rules_pca->head[counter1].syncs != 1)
        return 0;
    SCProfilingCounterAddUI64(counter1, 64);
    if (rules_pca->head[counter1].ui64_cnt != 128)
        return 0;
    if (rules_pca->head[counter1].syncs != 2)
        return 0;
    if (rules_pca->head[counter1].wrapped_syncs != 0)
        return 0;

    SCProfilingDump(stdout);

    SCProfilingDestroy();

    return 1;
}

static int
ProfilingGenericTicksTest01(void) {
#define TEST_RUNS 1024
    uint64_t ticks_start = 0;
    uint64_t ticks_end = 0;
    void *ptr[TEST_RUNS];
    int i;

    ticks_start = UtilCpuGetTicks();
    for (i = 0; i < TEST_RUNS; i++) {
        ptr[i] = malloc(1024);
    }
    ticks_end = UtilCpuGetTicks();
    printf("malloc(1024) %"PRIu64"\n", (ticks_end - ticks_start)/TEST_RUNS);

    ticks_start = UtilCpuGetTicks();
    for (i = 0; i < TEST_RUNS; i++) {
        free(ptr[i]);
    }
    ticks_end = UtilCpuGetTicks();
    printf("free(1024) %"PRIu64"\n", (ticks_end - ticks_start)/TEST_RUNS);

    SCMutex m[TEST_RUNS];

    ticks_start = UtilCpuGetTicks();
    for (i = 0; i < TEST_RUNS; i++) {
        SCMutexInit(&m[i], NULL);
    }
    ticks_end = UtilCpuGetTicks();
    printf("SCMutexInit() %"PRIu64"\n", (ticks_end - ticks_start)/TEST_RUNS);

    ticks_start = UtilCpuGetTicks();
    for (i = 0; i < TEST_RUNS; i++) {
        SCMutexLock(&m[i]);
    }
    ticks_end = UtilCpuGetTicks();
    printf("SCMutexLock() %"PRIu64"\n", (ticks_end - ticks_start)/TEST_RUNS);

    ticks_start = UtilCpuGetTicks();
    for (i = 0; i < TEST_RUNS; i++) {
        SCMutexUnlock(&m[i]);
    }
    ticks_end = UtilCpuGetTicks();
    printf("SCMutexUnlock() %"PRIu64"\n", (ticks_end - ticks_start)/TEST_RUNS);

    ticks_start = UtilCpuGetTicks();
    for (i = 0; i < TEST_RUNS; i++) {
        SCMutexDestroy(&m[i]);
    }
    ticks_end = UtilCpuGetTicks();
    printf("SCMutexDestroy() %"PRIu64"\n", (ticks_end - ticks_start)/TEST_RUNS);

    SCSpinlock s[TEST_RUNS];

    ticks_start = UtilCpuGetTicks();
    for (i = 0; i < TEST_RUNS; i++) {
        SCSpinInit(&s[i], 0);
    }
    ticks_end = UtilCpuGetTicks();
    printf("SCSpinInit() %"PRIu64"\n", (ticks_end - ticks_start)/TEST_RUNS);

    ticks_start = UtilCpuGetTicks();
    for (i = 0; i < TEST_RUNS; i++) {
        SCSpinLock(&s[i]);
    }
    ticks_end = UtilCpuGetTicks();
    printf("SCSpinLock() %"PRIu64"\n", (ticks_end - ticks_start)/TEST_RUNS);

    ticks_start = UtilCpuGetTicks();
    for (i = 0; i < TEST_RUNS; i++) {
        SCSpinUnlock(&s[i]);
    }
    ticks_end = UtilCpuGetTicks();
    printf("SCSpinUnlock() %"PRIu64"\n", (ticks_end - ticks_start)/TEST_RUNS);

    ticks_start = UtilCpuGetTicks();
    for (i = 0; i < TEST_RUNS; i++) {
        SCSpinDestroy(&s[i]);
    }
    ticks_end = UtilCpuGetTicks();
    printf("SCSpinDestroy() %"PRIu64"\n", (ticks_end - ticks_start)/TEST_RUNS);

    return 1;
}

#endif /* UNITTESTS */

void
SCProfilingRegisterTests(void)
{
#ifdef UNITTESTS
    UtRegisterTest("ProfilingTest01", ProfilingTest01, 1);
    UtRegisterTest("ProfilingGenericTicksTest01", ProfilingGenericTicksTest01, 1);
#endif /* UNITTESTS */
}

#endif /* PROFILING */
