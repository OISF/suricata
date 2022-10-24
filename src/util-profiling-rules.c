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
#include "util-profiling.h"

#ifdef PROFILING
#include "util-byte.h"
#include "util-conf.h"
#include "util-time.h"

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
    uint16_t id;
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
static char profiling_file_name[PATH_MAX] = "";
static const char *profiling_file_mode = "a";
static int profiling_rule_json = 0;

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

static int profiling_rules_sort_orders[8] = {
    SC_PROFILING_RULES_SORT_BY_TICKS,
    SC_PROFILING_RULES_SORT_BY_AVG_TICKS,
    SC_PROFILING_RULES_SORT_BY_AVG_TICKS_MATCH,
    SC_PROFILING_RULES_SORT_BY_AVG_TICKS_NO_MATCH,
    SC_PROFILING_RULES_SORT_BY_CHECKS,
    SC_PROFILING_RULES_SORT_BY_MATCHES,
    SC_PROFILING_RULES_SORT_BY_MAX_TICKS,
    -1 };

/**
 * Maximum number of rules to dump.
 */
static uint32_t profiling_rules_limit = UINT32_MAX;

void SCProfilingRulesGlobalInit(void)
{
#define SET_ONE(x) { \
        profiling_rules_sort_orders[0] = (x); \
        profiling_rules_sort_orders[1] = -1;  \
    }

    ConfNode *conf;
    const char *val;

    conf = ConfGetNode("profiling.rules");
    if (conf != NULL) {
        if (ConfNodeChildValueIsTrue(conf, "enabled")) {
            profiling_rules_enabled = 1;

            val = ConfNodeLookupChildValue(conf, "sort");
            if (val != NULL) {
                if (strcmp(val, "ticks") == 0) {
                    SET_ONE(SC_PROFILING_RULES_SORT_BY_TICKS);
                }
                else if (strcmp(val, "avgticks") == 0) {
                    SET_ONE(SC_PROFILING_RULES_SORT_BY_AVG_TICKS);
                }
                else if (strcmp(val, "avgticks_match") == 0) {
                    SET_ONE(SC_PROFILING_RULES_SORT_BY_AVG_TICKS_MATCH);
                }
                else if (strcmp(val, "avgticks_no_match") == 0) {
                    SET_ONE(SC_PROFILING_RULES_SORT_BY_AVG_TICKS_NO_MATCH);
                }
                else if (strcmp(val, "checks") == 0) {
                    SET_ONE(SC_PROFILING_RULES_SORT_BY_CHECKS);
                }
                else if (strcmp(val, "matches") == 0) {
                    SET_ONE(SC_PROFILING_RULES_SORT_BY_MATCHES);
                }
                else if (strcmp(val, "maxticks") == 0) {
                    SET_ONE(SC_PROFILING_RULES_SORT_BY_MAX_TICKS);
                }
                else {
                    SCLogError(SC_ERR_INVALID_ARGUMENT,
                            "Invalid profiling sort order: %s", val);
                    exit(EXIT_FAILURE);
                }
            }

            val = ConfNodeLookupChildValue(conf, "limit");
            if (val != NULL) {
                if (StringParseUint32(&profiling_rules_limit, 10,
                            (uint16_t)strlen(val), val) <= 0) {
                    SCLogError(SC_ERR_INVALID_ARGUMENT, "Invalid limit: %s", val);
                    exit(EXIT_FAILURE);
                }
            }
            const char *filename = ConfNodeLookupChildValue(conf, "filename");
            if (filename != NULL) {

                const char *log_dir;
                log_dir = ConfigGetLogDirectory();

                snprintf(profiling_file_name, sizeof(profiling_file_name),
                        "%s/%s", log_dir, filename);

                const char *v = ConfNodeLookupChildValue(conf, "append");
                if (v == NULL || ConfValIsTrue(v)) {
                    profiling_file_mode = "a";
                } else {
                    profiling_file_mode = "w";
                }

                profiling_output_to_file = 1;
            }
            if (ConfNodeChildValueIsTrue(conf, "json")) {
                profiling_rule_json = 1;
            }
        }
    }
#undef SET_ONE
}

/**
 * \brief Qsort comparison function to sort by ticks.
 */
static int
SCProfileSummarySortByTicks(const void *a, const void *b)
{
    const SCProfileSummary *s0 = a;
    const SCProfileSummary *s1 = b;
    if (s1->ticks == s0->ticks)
        return 0;
    else
        return s0->ticks > s1->ticks ? -1 : 1;
}

/**
 * \brief Qsort comparison function to sort by average ticks per match.
 */
static int
SCProfileSummarySortByAvgTicksMatch(const void *a, const void *b)
{
    const SCProfileSummary *s0 = a;
    const SCProfileSummary *s1 = b;
    if (s1->avgticks_match == s0->avgticks_match)
        return 0;
    else
        return s0->avgticks_match > s1->avgticks_match ? -1 : 1;
}

/**
 * \brief Qsort comparison function to sort by average ticks per non match.
 */
static int
SCProfileSummarySortByAvgTicksNoMatch(const void *a, const void *b)
{
    const SCProfileSummary *s0 = a;
    const SCProfileSummary *s1 = b;
    if (s1->avgticks_no_match == s0->avgticks_no_match)
        return 0;
    else
        return s0->avgticks_no_match > s1->avgticks_no_match ? -1 : 1;
}

/**
 * \brief Qsort comparison function to sort by average ticks.
 */
static int
SCProfileSummarySortByAvgTicks(const void *a, const void *b)
{
    const SCProfileSummary *s0 = a;
    const SCProfileSummary *s1 = b;
    if (s1->avgticks == s0->avgticks)
        return 0;
    else
        return s0->avgticks > s1->avgticks ? -1 : 1;
}

/**
 * \brief Qsort comparison function to sort by checks.
 */
static int
SCProfileSummarySortByChecks(const void *a, const void *b)
{
    const SCProfileSummary *s0 = a;
    const SCProfileSummary *s1 = b;
    if (s1->checks == s0->checks)
        return 0;
    else
        return s0->checks > s1->checks ? -1 : 1;
}

/**
 * \brief Qsort comparison function to sort by matches.
 */
static int
SCProfileSummarySortByMatches(const void *a, const void *b)
{
    const SCProfileSummary *s0 = a;
    const SCProfileSummary *s1 = b;
    if (s1->matches == s0->matches)
        return 0;
    else
        return s0->matches > s1->matches ? -1 : 1;
}

/**
 * \brief Qsort comparison function to sort by max ticks.
 */
static int
SCProfileSummarySortByMaxTicks(const void *a, const void *b)
{
    const SCProfileSummary *s0 = a;
    const SCProfileSummary *s1 = b;
    if (s1->max == s0->max)
        return 0;
    else
        return s0->max > s1->max ? -1 : 1;
}

static void DumpJson(FILE *fp, SCProfileSummary *summary,
        uint32_t count, uint64_t total_ticks,
        const char *sort_desc)
{
    char timebuf[64];
    uint32_t i;
    struct timeval tval;

    json_t *js = json_object();
    if (js == NULL)
        return;
    json_t *jsa = json_array();
    if (jsa == NULL) {
        json_decref(js);
        return;
    }

    gettimeofday(&tval, NULL);
    CreateIsoTimeString(&tval, timebuf, sizeof(timebuf));
    json_object_set_new(js, "timestamp", json_string(timebuf));
    json_object_set_new(js, "sort", json_string(sort_desc));

    for (i = 0; i < MIN(count, profiling_rules_limit); i++) {
        /* Stop dumping when we hit our first rule with 0 checks.  Due
         * to sorting this will be the beginning of all the rules with
         * 0 checks. */
        if (summary[i].checks == 0)
            break;

        json_t *jsm = json_object();
        if (jsm) {
            json_object_set_new(jsm, "signature_id", json_integer(summary[i].sid));
            json_object_set_new(jsm, "gid", json_integer(summary[i].gid));
            json_object_set_new(jsm, "rev", json_integer(summary[i].rev));

            json_object_set_new(jsm, "checks", json_integer(summary[i].checks));
            json_object_set_new(jsm, "matches", json_integer(summary[i].matches));

            json_object_set_new(jsm, "ticks_total", json_integer(summary[i].ticks));
            json_object_set_new(jsm, "ticks_max", json_integer(summary[i].max));
            json_object_set_new(jsm, "ticks_avg", json_integer(summary[i].avgticks));
            json_object_set_new(jsm, "ticks_avg_match", json_integer(summary[i].avgticks_match));
            json_object_set_new(jsm, "ticks_avg_nomatch", json_integer(summary[i].avgticks_no_match));

            double percent = (long double)summary[i].ticks /
                (long double)total_ticks * 100;
            json_object_set_new(jsm, "percent", json_integer(percent));
            json_array_append_new(jsa, jsm);
        }
    }
    json_object_set_new(js, "rules", jsa);

    char *js_s = json_dumps(js,
            JSON_PRESERVE_ORDER|JSON_COMPACT|JSON_ENSURE_ASCII|
            JSON_ESCAPE_SLASH);

    if (unlikely(js_s == NULL))
        return;
    fprintf(fp, "%s", js_s);
    free(js_s);
    json_decref(js);
}

static void DumpText(FILE *fp, SCProfileSummary *summary,
        uint32_t count, uint64_t total_ticks,
        const char *sort_desc)
{
    uint32_t i;
    struct timeval tval;
    struct tm *tms;
    gettimeofday(&tval, NULL);
    struct tm local_tm;
    tms = SCLocalTime(tval.tv_sec, &local_tm);

    fprintf(fp, "  ----------------------------------------------"
            "----------------------------\n");
    fprintf(fp, "  Date: %" PRId32 "/%" PRId32 "/%04d -- "
            "%02d:%02d:%02d.", tms->tm_mon + 1, tms->tm_mday, tms->tm_year + 1900,
            tms->tm_hour,tms->tm_min, tms->tm_sec);
    fprintf(fp, " Sorted by: %s.\n", sort_desc);
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
}

/**
 * \brief Dump rule profiling information to file
 *
 * \param de_ctx The active DetectEngineCtx, used to get at the loaded rules.
 */
static void
SCProfilingRuleDump(SCProfileDetectCtx *rules_ctx)
{
    uint32_t i;
    FILE *fp;

    if (rules_ctx == NULL)
        return;

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
        SCLogError(SC_ENOMEM, "Error allocating memory for profiling summary");
        return;
    }

    uint32_t count = rules_ctx->size;
    uint64_t total_ticks = 0;

    SCLogPerf("Dumping profiling data for %u rules.", count);

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

    int *order = profiling_rules_sort_orders;
    while (*order != -1) {
        const char *sort_desc = NULL;
        switch (*order) {
            case SC_PROFILING_RULES_SORT_BY_TICKS:
                qsort(summary, count, sizeof(SCProfileSummary),
                        SCProfileSummarySortByTicks);
                sort_desc = "ticks";
                break;
            case SC_PROFILING_RULES_SORT_BY_AVG_TICKS:
                qsort(summary, count, sizeof(SCProfileSummary),
                        SCProfileSummarySortByAvgTicks);
                sort_desc = "average ticks";
                break;
            case SC_PROFILING_RULES_SORT_BY_CHECKS:
                qsort(summary, count, sizeof(SCProfileSummary),
                        SCProfileSummarySortByChecks);
                sort_desc = "number of checks";
                break;
            case SC_PROFILING_RULES_SORT_BY_MATCHES:
                qsort(summary, count, sizeof(SCProfileSummary),
                        SCProfileSummarySortByMatches);
                sort_desc = "number of matches";
                break;
            case SC_PROFILING_RULES_SORT_BY_MAX_TICKS:
                qsort(summary, count, sizeof(SCProfileSummary),
                        SCProfileSummarySortByMaxTicks);
                sort_desc = "max ticks";
                break;
            case SC_PROFILING_RULES_SORT_BY_AVG_TICKS_MATCH:
                qsort(summary, count, sizeof(SCProfileSummary),
                        SCProfileSummarySortByAvgTicksMatch);
                sort_desc = "average ticks (match)";
                break;
            case SC_PROFILING_RULES_SORT_BY_AVG_TICKS_NO_MATCH:
                qsort(summary, count, sizeof(SCProfileSummary),
                        SCProfileSummarySortByAvgTicksNoMatch);
                sort_desc = "average ticks (no match)";
                break;
        }
        if (profiling_rule_json) {
            DumpJson(fp, summary, count, total_ticks, sort_desc);
        } else {
            DumpText(fp, summary, count, total_ticks, sort_desc);
        }
        order++;
    }

    if (fp != stdout)
        fclose(fp);
    SCFree(summary);
    SCLogPerf("Done dumping profiling data.");
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

static SCProfileDetectCtx *SCProfilingRuleInitCtx(void)
{
    SCProfileDetectCtx *ctx = SCMalloc(sizeof(SCProfileDetectCtx));
    if (ctx != NULL) {
        memset(ctx, 0x00, sizeof(SCProfileDetectCtx));

        if (pthread_mutex_init(&ctx->data_m, NULL) != 0) {
                    FatalError(SC_ERR_FATAL,
                               "Failed to initialize hash table mutex.");
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

    SCLogPerf("Registered %"PRIu32" rule profiling counters.", count);
}

#endif /* PROFILING */

