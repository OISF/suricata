/* Copyright (C) 2007-2012 Open Information Security Foundation
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
 * \author Victor Julien <victor@inliniac.net>
 *
 * An API for rule profiling operations.
 */

#include "suricata-common.h"
#include "decode.h"
#include "detect.h"
#include "conf.h"

#include "tm-threads.h"

#include "util-unittest.h"
#include "util-byte.h"
#include "util-profiling.h"
#include "util-profiling-locks.h"

#ifdef PROFILING

#ifndef MIN
#define MIN(a, b) (((a) < (b)) ? (a) : (b))
#endif

/**
 * Extra data for rule profiling.
 */
typedef struct SCProfileData_ {
    uint32_t sid;
    uint32_t gid;
    uint32_t rev;
    uint64_t checks;
    uint64_t matches;
    uint64_t max;
    uint64_t ticks_match;
    uint64_t ticks_no_match;
} SCProfileData;

typedef struct SCProfileDetectCtx_ {
    uint32_t size;
    uint32_t id;
    SCProfileData *data;
    pthread_mutex_t data_m;
} SCProfileDetectCtx;

/**
 * Used for generating the summary data to print.
 */
typedef struct SCProfileSummary_ {
    uint32_t sid;
    uint32_t gid;
    uint32_t rev;
    uint64_t ticks;
    double avgticks;
    double avgticks_match;
    double avgticks_no_match;
    uint64_t checks;
    uint64_t matches;
    uint64_t max;
    uint64_t ticks_match;
    uint64_t ticks_no_match;
} SCProfileSummary;

extern int profiling_output_to_file;
int profiling_rules_enabled = 0;
static char *profiling_file_name = "";
static const char *profiling_file_mode = "a";

/**
 * Sort orders for dumping profiled rules.
 */
enum {
    SC_PROFILING_RULES_SORT_BY_TICKS = 0,
    SC_PROFILING_RULES_SORT_BY_AVG_TICKS,
    SC_PROFILING_RULES_SORT_BY_CHECKS,
    SC_PROFILING_RULES_SORT_BY_MATCHES,
    SC_PROFILING_RULES_SORT_BY_MAX_TICKS,
    SC_PROFILING_RULES_SORT_BY_AVG_TICKS_MATCH,
    SC_PROFILING_RULES_SORT_BY_AVG_TICKS_NO_MATCH,
};
static int profiling_rules_sort_order = SC_PROFILING_RULES_SORT_BY_TICKS;

/**
 * Maximum number of rules to dump.
 */
static uint32_t profiling_rules_limit = UINT32_MAX;

void SCProfilingRulesGlobalInit(void)
{
    ConfNode *conf;
    const char *val;

    conf = ConfGetNode("profiling.rules");
    if (conf != NULL) {
        if (ConfNodeChildValueIsTrue(conf, "enabled")) {
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
                else if (strcmp(val, "avgticks_match") == 0) {
                    profiling_rules_sort_order =
                        SC_PROFILING_RULES_SORT_BY_AVG_TICKS_MATCH;
                }
                else if (strcmp(val, "avgticks_no_match") == 0) {
                    profiling_rules_sort_order =
                        SC_PROFILING_RULES_SORT_BY_AVG_TICKS_NO_MATCH;
                }
                else if (strcmp(val, "checks") == 0) {
                    profiling_rules_sort_order =
                        SC_PROFILING_RULES_SORT_BY_CHECKS;
                }
                else if (strcmp(val, "matches") == 0) {
                    profiling_rules_sort_order =
                        SC_PROFILING_RULES_SORT_BY_MATCHES;
                }
                else if (strcmp(val, "maxticks") == 0) {
                    profiling_rules_sort_order =
                        SC_PROFILING_RULES_SORT_BY_MAX_TICKS;
                }
                else {
                    SCLogError(SC_ERR_INVALID_ARGUMENT,
                            "Invalid profiling sort order: %s", val);
                    exit(EXIT_FAILURE);
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
            const char *filename = ConfNodeLookupChildValue(conf, "filename");
            if (filename != NULL) {

                char *log_dir;
                log_dir = ConfigGetLogDirectory();

                profiling_file_name = SCMalloc(PATH_MAX);
                if (unlikely(profiling_file_name == NULL)) {
                    SCLogError(SC_ERR_MEM_ALLOC, "can't duplicate file name");
                    exit(EXIT_FAILURE);
                }
                snprintf(profiling_file_name, PATH_MAX, "%s/%s", log_dir, filename);

                const char *v = ConfNodeLookupChildValue(conf, "append");
                if (v == NULL || ConfValIsTrue(v)) {
                    profiling_file_mode = "a";
                } else {
                    profiling_file_mode = "w";
                }

                profiling_output_to_file = 1;
            }
        }
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
 * \brief Qsort comparison function to sort by average ticks per match.
 */
static int
SCProfileSummarySortByAvgTicksMatch(const void *a, const void *b)
{
    const SCProfileSummary *s0 = a;
    const SCProfileSummary *s1 = b;
    return s1->avgticks_match - s0->avgticks_match;
}

/**
 * \brief Qsort comparison function to sort by average ticks per non match.
 */
static int
SCProfileSummarySortByAvgTicksNoMatch(const void *a, const void *b)
{
    const SCProfileSummary *s0 = a;
    const SCProfileSummary *s1 = b;
    return s1->avgticks_no_match - s0->avgticks_no_match;
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

/**
 * \brief Qsort comparison function to sort by max ticks.
 */
static int
SCProfileSummarySortByMaxTicks(const void *a, const void *b)
{
    const SCProfileSummary *s0 = a;
    const SCProfileSummary *s1 = b;
    return s1->max - s0->max;
}

/**
 * \brief Dump rule profiling information to file
 *
 * \param de_ctx The active DetectEngineCtx, used to get at the loaded rules.
 */
void
SCProfilingRuleDump(SCProfileDetectCtx *rules_ctx)
{
    uint32_t i;
    FILE *fp;

    if (rules_ctx == NULL)
        return;

    struct timeval tval;
    struct tm *tms;
    if (profiling_output_to_file == 1) {
        fp = fopen(profiling_file_name, profiling_file_mode);

        if (fp == NULL) {
            SCLogError(SC_ERR_FOPEN, "failed to open %s: %s", profiling_file_name,
                    strerror(errno));
            return;
        }
    } else {
       fp = stdout;
    }

    int summary_size = sizeof(SCProfileSummary) * rules_ctx->size;
    SCProfileSummary *summary = SCMalloc(summary_size);
    if (unlikely(summary == NULL)) {
        SCLogError(SC_ERR_MEM_ALLOC, "Error allocating memory for profiling summary");
        return;
    }

    uint32_t count = rules_ctx->size;
    uint64_t total_ticks = 0;

    SCLogInfo("Dumping profiling data for %u rules.", count);

    memset(summary, 0, summary_size);
    for (i = 0; i < count; i++) {
        summary[i].sid = rules_ctx->data[i].sid;
        summary[i].rev = rules_ctx->data[i].rev;
        summary[i].gid = rules_ctx->data[i].gid;

        summary[i].ticks = rules_ctx->data[i].ticks_match + rules_ctx->data[i].ticks_no_match;
        summary[i].checks = rules_ctx->data[i].checks;

        if (summary[i].ticks > 0) {
            summary[i].avgticks = (long double)summary[i].ticks / (long double)summary[i].checks;
        }

        summary[i].matches = rules_ctx->data[i].matches;
        summary[i].max = rules_ctx->data[i].max;
        summary[i].ticks_match = rules_ctx->data[i].ticks_match;
        summary[i].ticks_no_match = rules_ctx->data[i].ticks_no_match;
        if (summary[i].ticks_match > 0) {
            summary[i].avgticks_match = (long double)summary[i].ticks_match /
                (long double)summary[i].matches;
        }

        if (summary[i].ticks_no_match > 0) {
            summary[i].avgticks_no_match = (long double)summary[i].ticks_no_match /
                ((long double)summary[i].checks - (long double)summary[i].matches);
        }
        total_ticks += summary[i].ticks;
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
        case SC_PROFILING_RULES_SORT_BY_MAX_TICKS:
            qsort(summary, count, sizeof(SCProfileSummary),
                    SCProfileSummarySortByMaxTicks);
            break;
        case SC_PROFILING_RULES_SORT_BY_AVG_TICKS_MATCH:
            qsort(summary, count, sizeof(SCProfileSummary),
                    SCProfileSummarySortByAvgTicksMatch);
            break;
        case SC_PROFILING_RULES_SORT_BY_AVG_TICKS_NO_MATCH:
            qsort(summary, count, sizeof(SCProfileSummary),
                    SCProfileSummarySortByAvgTicksNoMatch);
            break;
    }

    gettimeofday(&tval, NULL);
    struct tm local_tm;
    tms = SCLocalTime(tval.tv_sec, &local_tm);

    fprintf(fp, "  ----------------------------------------------"
            "----------------------------\n");
    fprintf(fp, "  Date: %" PRId32 "/%" PRId32 "/%04d -- "
            "%02d:%02d:%02d\n", tms->tm_mon + 1, tms->tm_mday, tms->tm_year + 1900,
            tms->tm_hour,tms->tm_min, tms->tm_sec);
    fprintf(fp, "  ----------------------------------------------"
            "----------------------------\n");
    fprintf(fp, "   %-8s %-12s %-8s %-8s %-12s %-6s %-8s %-8s %-11s %-11s %-11s %-11s\n", "Num", "Rule", "Gid", "Rev", "Ticks", "%", "Checks", "Matches", "Max Ticks", "Avg Ticks", "Avg Match", "Avg No Match");
    fprintf(fp, "  -------- "
        "------------ "
        "-------- "
        "-------- "
        "------------ "
        "------ "
        "-------- "
        "-------- "
        "----------- "
        "----------- "
        "----------- "
        "-------------- "
        "\n");
    for (i = 0; i < MIN(count, profiling_rules_limit); i++) {

        /* Stop dumping when we hit our first rule with 0 checks.  Due
         * to sorting this will be the beginning of all the rules with
         * 0 checks. */
        if (summary[i].checks == 0)
            break;

        double percent = (long double)summary[i].ticks /
            (long double)total_ticks * 100;
        fprintf(fp,
            "  %-8"PRIu32" %-12u %-8"PRIu32" %-8"PRIu32" %-12"PRIu64" %-6.2f %-8"PRIu64" %-8"PRIu64" %-11"PRIu64" %-11.2f %-11.2f %-11.2f\n",
            i + 1,
            summary[i].sid,
            summary[i].gid,
            summary[i].rev,
            summary[i].ticks,
            percent,
            summary[i].checks,
            summary[i].matches,
            summary[i].max,
            summary[i].avgticks,
            summary[i].avgticks_match,
            summary[i].avgticks_no_match);
    }

    fprintf(fp,"\n");
    if (fp != stdout)
        fclose(fp);
    SCFree(summary);
    SCLogInfo("Done dumping profiling data.");
}

/**
 * \brief Register a rule profiling counter.
 *
 * \retval Returns the ID of the counter on success, 0 on failure.
 */
static uint16_t
SCProfilingRegisterRuleCounter(SCProfileDetectCtx *ctx)
{
    ctx->size++;
    return ctx->id++;
}

/**
 * \brief Update a rule counter.
 *
 * \param id The ID of this counter.
 * \param ticks Number of CPU ticks for this rule.
 * \param match Did the rule match?
 */
void
SCProfilingRuleUpdateCounter(DetectEngineThreadCtx *det_ctx, uint16_t id, uint64_t ticks, int match)
{
    if (det_ctx != NULL && det_ctx->rule_perf_data != NULL && det_ctx->rule_perf_data_size > id) {
        SCProfileData *p = &det_ctx->rule_perf_data[id];

        p->checks++;
        p->matches += match;
        if (ticks > p->max)
            p->max = ticks;
        if (match == 1)
            p->ticks_match += ticks;
        else
            p->ticks_no_match += ticks;
    }
}

SCProfileDetectCtx *SCProfilingRuleInitCtx(void)
{
    SCProfileDetectCtx *ctx = SCMalloc(sizeof(SCProfileDetectCtx));
    if (ctx != NULL) {
        memset(ctx, 0x00, sizeof(SCProfileDetectCtx));

        if (pthread_mutex_init(&ctx->data_m, NULL) != 0) {
            SCLogError(SC_ERR_MUTEX,
                    "Failed to initialize hash table mutex.");
            exit(EXIT_FAILURE);
        }
    }

    return ctx;
}

void SCProfilingRuleDestroyCtx(SCProfileDetectCtx *ctx)
{
    if (ctx != NULL) {
        SCProfilingRuleDump(ctx);
        if (ctx->data != NULL)
            SCFree(ctx->data);
        pthread_mutex_destroy(&ctx->data_m);
        SCFree(ctx);
    }
}

void SCProfilingRuleThreadSetup(SCProfileDetectCtx *ctx, DetectEngineThreadCtx *det_ctx)
{
    if (ctx == NULL|| ctx->size == 0)
        return;

    SCProfileData *a = SCMalloc(sizeof(SCProfileData) * ctx->size);
    if (a != NULL) {
        memset(a, 0x00, sizeof(SCProfileData) * ctx->size);

        det_ctx->rule_perf_data = a;
        det_ctx->rule_perf_data_size = ctx->size;
    }
}

static void SCProfilingRuleThreadMerge(DetectEngineCtx *de_ctx, DetectEngineThreadCtx *det_ctx)
{
    if (de_ctx == NULL || de_ctx->profile_ctx == NULL || de_ctx->profile_ctx->data == NULL ||
        det_ctx == NULL || det_ctx->rule_perf_data == NULL)
        return;

    int i;
    for (i = 0; i < det_ctx->rule_perf_data_size; i++) {
        de_ctx->profile_ctx->data[i].checks += det_ctx->rule_perf_data[i].checks;
        de_ctx->profile_ctx->data[i].matches += det_ctx->rule_perf_data[i].matches;
        de_ctx->profile_ctx->data[i].ticks_match += det_ctx->rule_perf_data[i].ticks_match;
        de_ctx->profile_ctx->data[i].ticks_no_match += det_ctx->rule_perf_data[i].ticks_no_match;
        if (det_ctx->rule_perf_data[i].max > de_ctx->profile_ctx->data[i].max)
            de_ctx->profile_ctx->data[i].max = det_ctx->rule_perf_data[i].max;
    }
}

void SCProfilingRuleThreadCleanup(DetectEngineThreadCtx *det_ctx)
{
    if (det_ctx == NULL || det_ctx->de_ctx == NULL || det_ctx->rule_perf_data == NULL)
        return;

    pthread_mutex_lock(&det_ctx->de_ctx->profile_ctx->data_m);
    SCProfilingRuleThreadMerge(det_ctx->de_ctx, det_ctx);
    pthread_mutex_unlock(&det_ctx->de_ctx->profile_ctx->data_m);

    SCFree(det_ctx->rule_perf_data);
    det_ctx->rule_perf_data = NULL;
    det_ctx->rule_perf_data_size = 0;
}

/**
 * \brief Register the rule profiling counters.
 *
 * \param de_ctx The active DetectEngineCtx, used to get at the loaded rules.
 */
void
SCProfilingRuleInitCounters(DetectEngineCtx *de_ctx)
{
    if (profiling_rules_enabled == 0)
        return;

    de_ctx->profile_ctx = SCProfilingRuleInitCtx();
    BUG_ON(de_ctx->profile_ctx == NULL);

    Signature *sig = de_ctx->sig_list;
    uint32_t count = 0;
    while (sig != NULL) {
        sig->profiling_id = SCProfilingRegisterRuleCounter(de_ctx->profile_ctx);
        sig = sig->next;
        count++;
    }

    if (count > 0) {
        de_ctx->profile_ctx->data = SCMalloc(sizeof(SCProfileData) * de_ctx->profile_ctx->size);
        BUG_ON(de_ctx->profile_ctx->data == NULL);
        memset(de_ctx->profile_ctx->data, 0x00, sizeof(SCProfileData) * de_ctx->profile_ctx->size);

        sig = de_ctx->sig_list;
        while (sig != NULL) {
            de_ctx->profile_ctx->data[sig->profiling_id].sid = sig->id;
            de_ctx->profile_ctx->data[sig->profiling_id].gid = sig->gid;
            de_ctx->profile_ctx->data[sig->profiling_id].rev = sig->rev;
            sig = sig->next;
        }
    }

    SCLogInfo("Registered %"PRIu32" rule profiling counters.", count);
}

#endif /* PROFILING */

