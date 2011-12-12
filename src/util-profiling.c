/* Copyright (C) 2007-2011 Open Information Security Foundation
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
 * An API for profiling operations.
 *
 * Really just a wrapper around the existing perf counters.
 */

#include "suricata-common.h"

#include "detect.h"
#include "counters.h"
#include "conf.h"

#include "tm-threads.h"

#include "util-unittest.h"
#include "util-byte.h"
#include "util-profiling.h"

#ifdef PROFILING

#define MIN(a, b) (((a) < (b)) ? (a) : (b))
#define DEFAULT_LOG_FILENAME "profile.log"
#define DEFAULT_LOG_MODE_APPEND "yes"

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

static SCPerfContext rules_ctx;
static SCPerfCounterArray *rules_pca;

static SCMutex packet_profile_lock;
static FILE *packet_profile_csv_fp = NULL;

/**
 * Extra data for rule profiling.
 */
typedef struct SCProfileData_ {
    uint32_t gid;
    uint8_t rev;
    uint64_t matches;
    uint64_t max;
    uint64_t ticks_match;
    uint64_t ticks_no_match;
} SCProfileData;
SCProfileData rules_profile_data[0xffff];

typedef struct SCProfilePacketData_ {
    uint64_t min;
    uint64_t max;
    uint64_t tot;
    uint64_t cnt;
} SCProfilePacketData;
SCProfilePacketData packet_profile_data4[257]; /**< all proto's + tunnel */
SCProfilePacketData packet_profile_data6[257]; /**< all proto's + tunnel */

/* each module, each proto */
SCProfilePacketData packet_profile_tmm_data4[TMM_SIZE][257];
SCProfilePacketData packet_profile_tmm_data6[TMM_SIZE][257];

SCProfilePacketData packet_profile_app_data4[TMM_SIZE][257];
SCProfilePacketData packet_profile_app_data6[TMM_SIZE][257];

SCProfilePacketData packet_profile_app_pd_data4[257];
SCProfilePacketData packet_profile_app_pd_data6[257];

SCProfilePacketData packet_profile_detect_data4[PROF_DETECT_SIZE][257];
SCProfilePacketData packet_profile_detect_data6[PROF_DETECT_SIZE][257];

/**
 * Used for generating the summary data to print.
 */
typedef struct SCProfileSummary_ {
    char *name;
    uint32_t gid;
    uint8_t rev;
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

int profiling_rules_enabled = 0;
int profiling_packets_enabled = 0;
int profiling_packets_csv_enabled = 0;

int profiling_output_to_file = 0;
int profiling_packets_output_to_file = 0;
char *profiling_file_name;
char *profiling_packets_file_name;
char *profiling_csv_file_name;
const char *profiling_file_mode;
const char *profiling_packets_file_mode;

/**
 * Used as a check so we don't double enter a profiling run.
 */
__thread int profiling_rules_entered = 0;

void SCProfilingDumpPacketStats(void);
const char * PacketProfileDetectIdToString(PacketProfileDetectId id);

/**
 * \brief Initialize profiling.
 */
void
SCProfilingInit(void)
{
    ConfNode *conf;
    const char *val;

    conf = ConfGetNode("profiling.rules");
    if (conf != NULL) {
        if (ConfNodeChildValueIsTrue(conf, "enabled")) {
            memset(rules_profile_data, 0, sizeof(rules_profile_data));
            memset(&rules_ctx, 0, sizeof(rules_ctx));
            rules_pca = SCPerfGetAllCountersArray(NULL);
            if (SCMutexInit(&rules_ctx.m, NULL) != 0) {
                SCLogError(SC_ERR_MUTEX,
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
                if (ConfGet("default-log-dir", &log_dir) != 1)
                    log_dir = DEFAULT_LOG_DIR;

                profiling_file_name = SCMalloc(PATH_MAX);
                snprintf(profiling_file_name, PATH_MAX, "%s/%s", log_dir, filename);

                profiling_file_mode = ConfNodeLookupChildValue(conf, "append");
                if (profiling_file_mode == NULL)
                    profiling_file_mode = DEFAULT_LOG_MODE_APPEND;

                profiling_output_to_file = 1;
            }
        }
    }

    conf = ConfGetNode("profiling.packets");
    if (conf != NULL) {
        if (ConfNodeChildValueIsTrue(conf, "enabled")) {
            profiling_packets_enabled = 1;

            if (SCMutexInit(&packet_profile_lock, NULL) != 0) {
                SCLogError(SC_ERR_MUTEX,
                        "Failed to initialize packet profiling mutex.");
                exit(EXIT_FAILURE);
            }
            memset(&packet_profile_data4, 0, sizeof(packet_profile_data4));
            memset(&packet_profile_data6, 0, sizeof(packet_profile_data6));
            memset(&packet_profile_tmm_data4, 0, sizeof(packet_profile_tmm_data4));
            memset(&packet_profile_tmm_data6, 0, sizeof(packet_profile_tmm_data6));
            memset(&packet_profile_app_data4, 0, sizeof(packet_profile_app_data4));
            memset(&packet_profile_app_data6, 0, sizeof(packet_profile_app_data6));
            memset(&packet_profile_app_pd_data4, 0, sizeof(packet_profile_app_pd_data4));
            memset(&packet_profile_app_pd_data6, 0, sizeof(packet_profile_app_pd_data6));
            memset(&packet_profile_detect_data4, 0, sizeof(packet_profile_detect_data4));
            memset(&packet_profile_detect_data6, 0, sizeof(packet_profile_detect_data6));

            const char *filename = ConfNodeLookupChildValue(conf, "filename");
            if (filename != NULL) {

                char *log_dir;
                if (ConfGet("default-log-dir", &log_dir) != 1)
                    log_dir = DEFAULT_LOG_DIR;

                profiling_packets_file_name = SCMalloc(PATH_MAX);
                snprintf(profiling_packets_file_name, PATH_MAX, "%s/%s", log_dir, filename);

                profiling_packets_file_mode = ConfNodeLookupChildValue(conf, "append");
                if (profiling_packets_file_mode == NULL)
                    profiling_packets_file_mode = DEFAULT_LOG_MODE_APPEND;

                profiling_packets_output_to_file = 1;
            }
        }

        conf = ConfGetNode("profiling.packets.csv");
        if (conf != NULL) {
            if (ConfNodeChildValueIsTrue(conf, "enabled")) {

                const char *filename = ConfNodeLookupChildValue(conf, "filename");
                if (filename == NULL) {
                    filename = "packet_profile.csv";
                }

                char *log_dir;
                if (ConfGet("default-log-dir", &log_dir) != 1)
                    log_dir = DEFAULT_LOG_DIR;

                profiling_csv_file_name = SCMalloc(PATH_MAX);
                if (profiling_csv_file_name == NULL) {
                    SCLogError(SC_ERR_MEM_ALLOC, "out of memory");
                    exit(EXIT_FAILURE);
                }
                snprintf(profiling_csv_file_name, PATH_MAX, "%s/%s", log_dir, filename);

                packet_profile_csv_fp = fopen(profiling_csv_file_name, "w");
                if (packet_profile_csv_fp == NULL) {
                    return;
                }
                fprintf(packet_profile_csv_fp, "pcap_cnt,ipver,ipproto,total,");
                int i;
                for (i = 0; i < TMM_SIZE; i++) {
                    fprintf(packet_profile_csv_fp, "%s,", TmModuleTmmIdToString(i));
                }
                fprintf(packet_profile_csv_fp, "threading,");
                for (i = 0; i < ALPROTO_MAX; i++) {
                    fprintf(packet_profile_csv_fp, "%s,", TmModuleAlprotoToString(i));
                }
                fprintf(packet_profile_csv_fp, "STREAM (no app),proto detect,");
                for (i = 0; i < PROF_DETECT_SIZE; i++) {
                    fprintf(packet_profile_csv_fp, "%s,", PacketProfileDetectIdToString(i));
                }
                fprintf(packet_profile_csv_fp, "\n");

                profiling_packets_csv_enabled = 1;
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
        SCMutexDestroy(&rules_ctx.m);
    }

    if (profiling_packets_enabled) {
        SCMutexDestroy(&packet_profile_lock);
    }

    if (profiling_packets_csv_enabled) {
        if (packet_profile_csv_fp != NULL)
            fclose(packet_profile_csv_fp);
    }

    if (profiling_csv_file_name != NULL)
        SCFree(profiling_csv_file_name);

    if (profiling_file_name != NULL)
        SCFree(profiling_file_name);
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

void
SCProfilingDump(void)
{
    uint32_t i;
    FILE *fp;

    SCProfilingDumpPacketStats();

    struct timeval tval;
    struct tm *tms;
    if (profiling_output_to_file == 1) {
        if (ConfValIsTrue(profiling_file_mode)) {
            fp = fopen(profiling_file_name, "a");
        } else {
            fp = fopen(profiling_file_name, "w");
        }

        if (fp == NULL) {
            SCLogError(SC_ERR_FOPEN, "failed to open %s: %s", profiling_file_name,
                    strerror(errno));
            return;
        }
    } else {
       fp = stdout;
    }

    if (rules_pca == NULL) {
        SCLogDebug("No rules specified to provide a profiling summary");
        return;
    }

    int summary_size = sizeof(SCProfileSummary) * rules_pca->size;
    SCProfileSummary *summary = SCMalloc(summary_size);
    if (summary == NULL) {
        SCLogError(SC_ERR_MEM_ALLOC, "Error allocating memory for profiling summary");
        return;
    }

    uint32_t count = rules_pca->size;
    uint64_t total_ticks = 0;

    SCLogInfo("Dumping profiling data.");

    memset(summary, 0, summary_size);
    for (i = 1; i < count + 1; i++) {
        summary[i - 1].name = rules_pca->head[i].pc->name->cname;
        summary[i - 1].rev = rules_profile_data[i].rev;
        summary[i - 1].gid = rules_profile_data[i].gid;
        summary[i - 1].ticks =  rules_pca->head[i].ui64_cnt;
        if (rules_pca->head[i].ui64_cnt) {
            summary[i - 1].avgticks = (long double)rules_pca->head[i].ui64_cnt /
                (long double)rules_pca->head[i].syncs;
        }
        summary[i - 1].checks = rules_pca->head[i].syncs;
        summary[i - 1].matches = rules_profile_data[i].matches;
        summary[i - 1].max = rules_profile_data[i].max;
        summary[i - 1].ticks_match = rules_profile_data[i].ticks_match;
        summary[i - 1].ticks_no_match = rules_profile_data[i].ticks_no_match;
        if (rules_profile_data[i].ticks_match > 0) {
            summary[i - 1].avgticks_match = (long double)rules_profile_data[i].ticks_match /
                (long double)rules_profile_data[i].matches;
        }

        if (rules_profile_data[i].ticks_no_match > 0) {
            summary[i - 1].avgticks_no_match = (long double)rules_profile_data[i].ticks_no_match /
                ((long double)rules_pca->head[i].syncs - (long double)rules_profile_data[i].matches);
        }
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
    tms = (struct tm *)localtime_r(&tval.tv_sec, &local_tm);

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
            "  %-8"PRIu32" %-12s %-8"PRIu32" %-8"PRIu32" %-12"PRIu64" %-6.2f %-8"PRIu64" %-8"PRIu64" %-11"PRIu64" %-11.2f %-11.2f %-11.2f\n",
            i + 1,
            summary[i].name,
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
        rules_profile_data[sig->profiling_id].rev = sig->rev;
        rules_profile_data[sig->profiling_id].gid = sig->gid;
        sig = sig->next;
        count++;
    }
    rules_pca = SCPerfGetAllCountersArray(&rules_ctx);
    SCLogInfo("Registered %"PRIu32" rule profiling counters.", count);
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
    if (ticks > rules_profile_data[id].max)
        rules_profile_data[id].max = ticks;
    if (match == 1)
        rules_profile_data[id].ticks_match += ticks;
    else
        rules_profile_data[id].ticks_no_match += ticks;

    SCMutexUnlock(&rules_ctx.m);
}

void SCProfilingDumpPacketStats(void) {
    int i;
    FILE *fp;

    if (profiling_packets_enabled == 0)
        return;

    if (profiling_packets_output_to_file == 1) {
        if (strcasecmp(profiling_packets_file_mode, "yes") == 0) {
            fp = fopen(profiling_packets_file_name, "a");
        } else {
            fp = fopen(profiling_packets_file_name, "w");
        }

        if (fp == NULL) {
            SCLogError(SC_ERR_FOPEN, "failed to open %s: %s",
                    profiling_packets_file_name, strerror(errno));
            return;
        }
    } else {
       fp = stdout;
    }

    fprintf(fp, "\n\nPacket profile dump:\n");

    fprintf(fp, "\n%-6s   %-5s   %-12s   %-12s   %-12s   %-12s\n",
            "IP ver", "Proto", "cnt", "min", "max", "avg");
    fprintf(fp, "%-6s   %-5s   %-12s   %-12s   %-12s   %-12s\n",
            "------", "-----", "----------", "------------", "------------", "-----------");

    for (i = 0; i < 257; i++) {
        SCProfilePacketData *pd = &packet_profile_data4[i];

        if (pd->cnt == 0) {
            continue;
        }

        fprintf(fp, " IPv4     %3d  %12"PRIu64"     %12"PRIu64"   %12"PRIu64"  %12"PRIu64"\n", i, pd->cnt,
            pd->min, pd->max, (uint64_t)(pd->tot / pd->cnt));
    }

    for (i = 0; i < 257; i++) {
        SCProfilePacketData *pd = &packet_profile_data6[i];

        if (pd->cnt == 0) {
            continue;
        }

        fprintf(fp, " IPv6     %3d  %12"PRIu64"     %12"PRIu64"   %12"PRIu64"  %12"PRIu64"\n", i, pd->cnt,
            pd->min, pd->max, (uint64_t)(pd->tot / pd->cnt));
    }
    fprintf(fp, "Note: Protocol 256 tracks pseudo/tunnel packets.\n");

    fprintf(fp, "\nPer Thread module stats:\n");

    fprintf(fp, "\n%-24s   %-6s   %-5s   %-12s   %-12s   %-12s   %-12s\n",
            "Thread Module", "IP ver", "Proto", "cnt", "min", "max", "avg");
    fprintf(fp, "%-24s   %-6s   %-5s   %-12s   %-12s   %-12s   %-12s\n",
            "------------------------", "------", "-----", "----------", "------------", "------------", "-----------");
    int m;
    for (m = 0; m < TMM_SIZE; m++) {
        int p;
        for (p = 0; p < 257; p++) {
            SCProfilePacketData *pd = &packet_profile_tmm_data4[m][p];

            if (pd->cnt == 0) {
                continue;
            }

            fprintf(fp, "%-24s    IPv4     %3d  %12"PRIu64"     %12"PRIu64"   %12"PRIu64"  %12"PRIu64"\n",
                    TmModuleTmmIdToString(m), p, pd->cnt, pd->min, pd->max, (uint64_t)(pd->tot / pd->cnt));
        }
    }

    for (m = 0; m < TMM_SIZE; m++) {
        int p;
        for (p = 0; p < 257; p++) {
            SCProfilePacketData *pd = &packet_profile_tmm_data6[m][p];

            if (pd->cnt == 0) {
                continue;
            }

            fprintf(fp, "%-24s    IPv6     %3d  %12"PRIu64"     %12"PRIu64"   %12"PRIu64"  %12"PRIu64"\n",
                    TmModuleTmmIdToString(m), p, pd->cnt, pd->min, pd->max, (uint64_t)(pd->tot / pd->cnt));
        }
    }
    fprintf(fp, "Note: TMM_STREAMTCP includes TCP app layer parsers, see below.\n");

    fprintf(fp, "\nPer App layer parser stats:\n");

    fprintf(fp, "\n%-20s   %-6s   %-5s   %-12s   %-12s   %-12s   %-12s\n",
            "App Layer", "IP ver", "Proto", "cnt", "min", "max", "avg");
    fprintf(fp, "%-20s   %-6s   %-5s   %-12s   %-12s   %-12s   %-12s\n",
            "--------------------", "------", "-----", "----------", "------------", "------------", "-----------");
    for (m = 0; m < ALPROTO_MAX; m++) {
        int p;
        for (p = 0; p < 257; p++) {
            SCProfilePacketData *pd = &packet_profile_app_data4[m][p];

            if (pd->cnt == 0) {
                continue;
            }

            fprintf(fp, "%-20s    IPv4     %3d  %12"PRIu64"     %12"PRIu64"   %12"PRIu64"  %12"PRIu64"\n",
                    TmModuleAlprotoToString(m), p, pd->cnt, pd->min, pd->max, (uint64_t)(pd->tot / pd->cnt));
        }
    }

    for (m = 0; m < ALPROTO_MAX; m++) {
        int p;
        for (p = 0; p < 257; p++) {
            SCProfilePacketData *pd = &packet_profile_app_data6[m][p];

            if (pd->cnt == 0) {
                continue;
            }

            fprintf(fp, "%-20s    IPv6     %3d  %12"PRIu64"     %12"PRIu64"   %12"PRIu64"  %12"PRIu64"\n",
                    TmModuleAlprotoToString(m), p, pd->cnt, pd->min, pd->max, (uint64_t)(pd->tot / pd->cnt));
        }
    }

    /* proto detect output */
    {
        int p;
        for (p = 0; p < 257; p++) {
            SCProfilePacketData *pd = &packet_profile_app_pd_data4[p];

            if (pd->cnt == 0) {
                continue;
            }

            fprintf(fp, "%-20s    IPv4     %3d  %12"PRIu64"     %12"PRIu64"   %12"PRIu64"  %12"PRIu64"\n",
                    "Proto detect", p, pd->cnt, pd->min, pd->max, (uint64_t)(pd->tot / pd->cnt));
        }

        for (p = 0; p < 257; p++) {
            SCProfilePacketData *pd = &packet_profile_app_pd_data6[p];

            if (pd->cnt == 0) {
                continue;
            }

            fprintf(fp, "%-20s    IPv6     %3d  %12"PRIu64"     %12"PRIu64"   %12"PRIu64"  %12"PRIu64"\n",
                    "Proto detect", p, pd->cnt, pd->min, pd->max, (uint64_t)(pd->tot / pd->cnt));
        }
    }

    fprintf(fp, "\nGeneral detection engine stats:\n");

    fprintf(fp, "\n%-24s   %-6s   %-5s   %-12s   %-12s   %-12s   %-12s\n",
            "Detection phase", "IP ver", "Proto", "cnt", "min", "max", "avg");
    fprintf(fp, "%-24s   %-6s   %-5s   %-12s   %-12s   %-12s   %-12s\n",
            "------------------------", "------", "-----", "----------", "------------", "------------", "-----------");
    for (m = 0; m < PROF_DETECT_SIZE; m++) {
        int p;
        for (p = 0; p < 257; p++) {
            SCProfilePacketData *pd = &packet_profile_detect_data4[m][p];

            if (pd->cnt == 0) {
                continue;
            }

            fprintf(fp, "%-24s    IPv4     %3d  %12"PRIu64"     %12"PRIu64"   %12"PRIu64"  %12"PRIu64"\n",
                    PacketProfileDetectIdToString(m), p, pd->cnt, pd->min, pd->max, (uint64_t)(pd->tot / pd->cnt));
        }
    }
    for (m = 0; m < PROF_DETECT_SIZE; m++) {
        int p;
        for (p = 0; p < 257; p++) {
            SCProfilePacketData *pd = &packet_profile_detect_data6[m][p];

            if (pd->cnt == 0) {
                continue;
            }

            fprintf(fp, "%-24s    IPv6     %3d  %12"PRIu64"     %12"PRIu64"   %12"PRIu64"  %12"PRIu64"\n",
                    PacketProfileDetectIdToString(m), p, pd->cnt, pd->min, pd->max, (uint64_t)(pd->tot / pd->cnt));
        }
    }
    fclose(fp);
}

void SCProfilingPrintPacketProfile(Packet *p) {
    if (profiling_packets_csv_enabled == 0 || p == NULL || packet_profile_csv_fp == NULL) {
        return;
    }

    uint64_t delta = p->profile.ticks_end - p->profile.ticks_start;

    fprintf(packet_profile_csv_fp, "%"PRIu64",%c,%"PRIu8",%"PRIu64",",
            p->pcap_cnt, PKT_IS_IPV4(p) ? '4' : (PKT_IS_IPV6(p) ? '6' : '?'), p->proto,
            delta);

    int i;
    uint64_t tmm_total = 0;
    uint64_t tmm_streamtcp_tcp = 0;

    for (i = 0; i < TMM_SIZE; i++) {
        PktProfilingTmmData *pdt = &p->profile.tmm[i];

        uint64_t tmm_delta = pdt->ticks_end - pdt->ticks_start;
        fprintf(packet_profile_csv_fp, "%"PRIu64",", tmm_delta);
        tmm_total += tmm_delta;

        if (p->proto == IPPROTO_TCP && i == TMM_STREAMTCP) {
            tmm_streamtcp_tcp = tmm_delta;
        }
    }

    fprintf(packet_profile_csv_fp, "%"PRIu64",", delta - tmm_total);

    uint64_t app_total = 0;
    for (i = 0; i < ALPROTO_MAX; i++) {
        PktProfilingAppData *pdt = &p->profile.app[i];

        fprintf(packet_profile_csv_fp,"%"PRIu64",", pdt->ticks_spent);

        if (p->proto == IPPROTO_TCP) {
            app_total += pdt->ticks_spent;
        }
    }

    uint64_t real_tcp = 0;
    if (tmm_streamtcp_tcp > app_total)
        real_tcp = tmm_streamtcp_tcp - app_total;
    fprintf(packet_profile_csv_fp, "%"PRIu64",", real_tcp);

    fprintf(packet_profile_csv_fp, "%"PRIu64",", p->profile.proto_detect);

    for (i = 0; i < PROF_DETECT_SIZE; i++) {
        PktProfilingDetectData *pdt = &p->profile.detect[i];

        fprintf(packet_profile_csv_fp,"%"PRIu64",", pdt->ticks_spent);
    }
    fprintf(packet_profile_csv_fp,"\n");
}

static void SCProfilingUpdatePacketDetectRecord(PacketProfileDetectId id, uint8_t ipproto, PktProfilingDetectData *pdt, int ipver) {
    if (pdt == NULL) {
        return;
    }

    SCProfilePacketData *pd;
    if (ipver == 4)
        pd = &packet_profile_detect_data4[id][ipproto];
    else
        pd = &packet_profile_detect_data6[id][ipproto];

    if (pd->min == 0 || pdt->ticks_spent < pd->min) {
        pd->min = pdt->ticks_spent;
    }
    if (pd->max < pdt->ticks_spent) {
        pd->max = pdt->ticks_spent;
    }

    pd->tot += pdt->ticks_spent;
    pd->cnt ++;
}

void SCProfilingUpdatePacketDetectRecords(Packet *p) {
    PacketProfileDetectId i;
    for (i = 0; i < PROF_DETECT_SIZE; i++) {
        PktProfilingDetectData *pdt = &p->profile.detect[i];

        if (pdt->ticks_spent > 0) {
            if (PKT_IS_IPV4(p)) {
                SCProfilingUpdatePacketDetectRecord(i, p->proto, pdt, 4);
            } else {
                SCProfilingUpdatePacketDetectRecord(i, p->proto, pdt, 6);
            }
        }
    }
}

static void SCProfilingUpdatePacketAppPdRecord(uint8_t ipproto, uint32_t ticks_spent, int ipver) {
    SCProfilePacketData *pd;
    if (ipver == 4)
        pd = &packet_profile_app_pd_data4[ipproto];
    else
        pd = &packet_profile_app_pd_data6[ipproto];

    if (pd->min == 0 || ticks_spent < pd->min) {
        pd->min = ticks_spent;
    }
    if (pd->max < ticks_spent) {
        pd->max = ticks_spent;
    }

    pd->tot += ticks_spent;
    pd->cnt ++;
}

static void SCProfilingUpdatePacketAppRecord(int alproto, uint8_t ipproto, PktProfilingAppData *pdt, int ipver) {
    if (pdt == NULL) {
        return;
    }

    SCProfilePacketData *pd;
    if (ipver == 4)
        pd = &packet_profile_app_data4[alproto][ipproto];
    else
        pd = &packet_profile_app_data6[alproto][ipproto];

    if (pd->min == 0 || pdt->ticks_spent < pd->min) {
        pd->min = pdt->ticks_spent;
    }
    if (pd->max < pdt->ticks_spent) {
        pd->max = pdt->ticks_spent;
    }

    pd->tot += pdt->ticks_spent;
    pd->cnt ++;
}

void SCProfilingUpdatePacketAppRecords(Packet *p) {
    int i;
    for (i = 0; i < ALPROTO_MAX; i++) {
        PktProfilingAppData *pdt = &p->profile.app[i];

        if (pdt->ticks_spent > 0) {
            if (PKT_IS_IPV4(p)) {
                SCProfilingUpdatePacketAppRecord(i, p->proto, pdt, 4);
            } else {
                SCProfilingUpdatePacketAppRecord(i, p->proto, pdt, 6);
            }
        }
    }

    if (p->profile.proto_detect > 0) {
        if (PKT_IS_IPV4(p)) {
            SCProfilingUpdatePacketAppPdRecord(p->proto, p->profile.proto_detect, 4);
        } else {
            SCProfilingUpdatePacketAppPdRecord(p->proto, p->profile.proto_detect, 6);
        }
    }
}

void SCProfilingUpdatePacketTmmRecord(int module, uint8_t proto, PktProfilingTmmData *pdt, int ipver) {
    if (pdt == NULL) {
        return;
    }

    SCProfilePacketData *pd;
    if (ipver == 4)
        pd = &packet_profile_tmm_data4[module][proto];
    else
        pd = &packet_profile_tmm_data6[module][proto];

    uint32_t delta = (uint32_t)pdt->ticks_end - pdt->ticks_start;
    if (pd->min == 0 || delta < pd->min) {
        pd->min = delta;
    }
    if (pd->max < delta) {
        pd->max = delta;
    }

    pd->tot += (uint64_t)delta;
    pd->cnt ++;
}

void SCProfilingUpdatePacketTmmRecords(Packet *p) {
    int i;
    for (i = 0; i < TMM_SIZE; i++) {
        PktProfilingTmmData *pdt = &p->profile.tmm[i];

        if (pdt->ticks_start == 0 || pdt->ticks_end == 0 || pdt->ticks_start > pdt->ticks_end) {
            continue;
        }

        if (PKT_IS_IPV4(p)) {
            SCProfilingUpdatePacketTmmRecord(i, p->proto, pdt, 4);
        } else {
            SCProfilingUpdatePacketTmmRecord(i, p->proto, pdt, 6);
        }
    }
}

void SCProfilingAddPacket(Packet *p) {
    if (p->profile.ticks_start == 0 || p->profile.ticks_end == 0 || p->profile.ticks_start > p->profile.ticks_end)
        return;

    SCMutexLock(&packet_profile_lock);
    {

        if (profiling_packets_csv_enabled)
            SCProfilingPrintPacketProfile(p);

        if (PKT_IS_IPV4(p)) {
            SCProfilePacketData *pd = &packet_profile_data4[p->proto];

            uint64_t delta = p->profile.ticks_end - p->profile.ticks_start;
            if (pd->min == 0 || delta < pd->min) {
                pd->min = delta;
            }
            if (pd->max < delta) {
                pd->max = delta;
            }

            pd->tot += delta;
            pd->cnt ++;

            if (IS_TUNNEL_PKT(p)) {
                pd = &packet_profile_data4[256];

                if (pd->min == 0 || delta < pd->min) {
                    pd->min = delta;
                }
                if (pd->max < delta) {
                    pd->max = delta;
                }

                pd->tot += delta;
                pd->cnt ++;
            }

            SCProfilingUpdatePacketTmmRecords(p);
            SCProfilingUpdatePacketAppRecords(p);
            SCProfilingUpdatePacketDetectRecords(p);

        } else if (PKT_IS_IPV6(p)) {
            SCProfilePacketData *pd = &packet_profile_data6[p->proto];

            uint64_t delta = p->profile.ticks_end - p->profile.ticks_start;
            if (pd->min == 0 || delta < pd->min) {
                pd->min = delta;
            }
            if (pd->max < delta) {
                pd->max = delta;
            }

            pd->tot += delta;
            pd->cnt ++;

            if (IS_TUNNEL_PKT(p)) {
                pd = &packet_profile_data6[256];

                if (pd->min == 0 || delta < pd->min) {
                    pd->min = delta;
                }
                if (pd->max < delta) {
                    pd->max = delta;
                }

                pd->tot += delta;
                pd->cnt ++;
            }

            SCProfilingUpdatePacketTmmRecords(p);
            SCProfilingUpdatePacketAppRecords(p);
            SCProfilingUpdatePacketDetectRecords(p);
        }
    }
    SCMutexUnlock(&packet_profile_lock);
}

#define CASE_CODE(E)  case E: return #E

/**
 * \brief Maps the PacketProfileDetectId, to its string equivalent
 *
 * \param id PacketProfileDetectId id
 *
 * \retval string equivalent for the PacketProfileDetectId id
 */
const char * PacketProfileDetectIdToString(PacketProfileDetectId id)
{
    switch (id) {
        CASE_CODE (PROF_DETECT_MPM);
        CASE_CODE (PROF_DETECT_MPM_PACKET);
        CASE_CODE (PROF_DETECT_MPM_PKT_STREAM);
        CASE_CODE (PROF_DETECT_MPM_STREAM);
        CASE_CODE (PROF_DETECT_MPM_URI);
        CASE_CODE (PROF_DETECT_MPM_HCBD);
        CASE_CODE (PROF_DETECT_MPM_HSBD);
        CASE_CODE (PROF_DETECT_MPM_HHD);
        CASE_CODE (PROF_DETECT_MPM_HRHD);
        CASE_CODE (PROF_DETECT_MPM_HMD);
        CASE_CODE (PROF_DETECT_MPM_HCD);
        CASE_CODE (PROF_DETECT_MPM_HRUD);
        CASE_CODE (PROF_DETECT_IPONLY);
        CASE_CODE (PROF_DETECT_RULES);
        CASE_CODE (PROF_DETECT_PREFILTER);
        CASE_CODE (PROF_DETECT_STATEFUL);
        CASE_CODE (PROF_DETECT_ALERT);
        CASE_CODE (PROF_DETECT_CLEANUP);
        CASE_CODE (PROF_DETECT_GETSGH);

        default:
            return "UNKNOWN";
    }
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

    SCProfilingDump();

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
        ptr[i] = SCMalloc(1024);
    }
    ticks_end = UtilCpuGetTicks();
    printf("malloc(1024) %"PRIu64"\n", (ticks_end - ticks_start)/TEST_RUNS);

    ticks_start = UtilCpuGetTicks();
    for (i = 0; i < TEST_RUNS; i++) {
        SCFree(ptr[i]);
    }
    ticks_end = UtilCpuGetTicks();
    printf("SCFree(1024) %"PRIu64"\n", (ticks_end - ticks_start)/TEST_RUNS);

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
