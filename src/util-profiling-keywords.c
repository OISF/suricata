/* Copyright (C) 2007-2013 Open Information Security Foundation
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
#ifdef PROFILING
#include "util-time.h"
#include "util-profiling-locks.h"
#include "util-profiling.h"
#include "util-byte.h"
#include "util-unittest.h"
#include "tm-threads.h"
#include "conf.h"
#include "detect-engine.h"
#include "detect.h"
#include "decode.h"
#endif

#ifdef PROFILING

#ifndef MIN
#define MIN(a, b) (((a) < (b)) ? (a) : (b))
#endif

/**
 * Extra data for rule profiling.
 */
typedef struct SCProfileKeywordData_ {
    uint64_t checks;
    uint64_t matches;
    uint64_t max;
    uint64_t ticks_match;
    uint64_t ticks_no_match;
} SCProfileKeywordData;

typedef struct SCProfileKeywordDetectCtx_ {
    uint32_t id;
    SCProfileKeywordData *data;
    pthread_mutex_t data_m;
} SCProfileKeywordDetectCtx;

static int profiling_keywords_output_to_file = 0;
int profiling_keyword_enabled = 0;
thread_local int profiling_keyword_entered = 0;
static char profiling_file_name[PATH_MAX];
static const char *profiling_file_mode = "a";

void SCProfilingKeywordsGlobalInit(void)
{
    ConfNode *conf;

    conf = ConfGetNode("profiling.keywords");
    if (conf != NULL) {
        if (ConfNodeChildValueIsTrue(conf, "enabled")) {
            profiling_keyword_enabled = 1;
            const char *filename = ConfNodeLookupChildValue(conf, "filename");
            if (filename != NULL) {
                const char *log_dir;
                log_dir = ConfigGetLogDirectory();

                snprintf(profiling_file_name, sizeof(profiling_file_name), "%s/%s",
                        log_dir, filename);

                const char *v = ConfNodeLookupChildValue(conf, "append");
                if (v == NULL || ConfValIsTrue(v)) {
                    profiling_file_mode = "a";
                } else {
                    profiling_file_mode = "w";
                }

                profiling_keywords_output_to_file = 1;
            }
        }
    }
}

static void DoDump(SCProfileKeywordDetectCtx *rules_ctx, FILE *fp, const char *name)
{
    int i;
    fprintf(fp, "  ----------------------------------------------"
            "------------------------------------------------------"
            "----------------------------\n");
    fprintf(fp, "  Stats for: %s\n", name);
    fprintf(fp, "  ----------------------------------------------"
            "------------------------------------------------------"
            "----------------------------\n");
    fprintf(fp, "  %-16s %-15s %-15s %-15s %-15s %-15s %-15s %-15s\n", "Keyword", "Ticks", "Checks", "Matches", "Max Ticks", "Avg", "Avg Match", "Avg No Match");
    fprintf(fp, "  ---------------- "
                "--------------- "
                "--------------- "
                "--------------- "
                "--------------- "
                "--------------- "
                "--------------- "
                "--------------- "
        "\n");
    for (i = 0; i < DETECT_TBLSIZE; i++) {
        SCProfileKeywordData *d = &rules_ctx->data[i];
        if (d == NULL || d->checks == 0)
            continue;

        uint64_t ticks = d->ticks_match + d->ticks_no_match;
        double avgticks = 0;
        double avgticks_match = 0;
        double avgticks_no_match = 0;
        if (ticks && d->checks) {
            avgticks = (double)(ticks / d->checks);

            if (d->ticks_match && d->matches)
                avgticks_match = (double)(d->ticks_match / d->matches);
            if (d->ticks_no_match && (d->checks - d->matches) != 0)
                avgticks_no_match = (double)(d->ticks_no_match / (d->checks - d->matches));
        }

        fprintf(fp,
            "  %-16s %-15"PRIu64" %-15"PRIu64" %-15"PRIu64" %-15"PRIu64" %-15.2f %-15.2f %-15.2f\n",
            sigmatch_table[i].name,
            ticks,
            d->checks,
            d->matches,
            d->max,
            avgticks,
            avgticks_match,
            avgticks_no_match);
    }
}

static void
SCProfilingKeywordDump(DetectEngineCtx *de_ctx)
{
    int i;
    FILE *fp;
    struct timeval tval;
    struct tm *tms;
    struct tm local_tm;

    if (profiling_keyword_enabled == 0)
        return;

    const int nlists = de_ctx->buffer_type_id;
    gettimeofday(&tval, NULL);
    tms = SCLocalTime(tval.tv_sec, &local_tm);

    if (profiling_keywords_output_to_file == 1) {
        SCLogDebug("file %s mode %s", profiling_file_name, profiling_file_mode);

        fp = fopen(profiling_file_name, profiling_file_mode);

        if (fp == NULL) {
            SCLogError(SC_ERR_FOPEN, "failed to open %s: %s", profiling_file_name,
                    strerror(errno));
            return;
        }
    } else {
       fp = stdout;
    }

    fprintf(fp, "  ----------------------------------------------"
            "------------------------------------------------------"
            "----------------------------\n");
    fprintf(fp, "  Date: %" PRId32 "/%" PRId32 "/%04d -- "
            "%02d:%02d:%02d\n", tms->tm_mon + 1, tms->tm_mday, tms->tm_year + 1900,
            tms->tm_hour,tms->tm_min, tms->tm_sec);

    /* global stats first */
    DoDump(de_ctx->profile_keyword_ctx, fp, "total");
    /* per buffer stats next, but only if there are stats to print */
    for (i = 0; i < nlists; i++) {
        int j;
        uint64_t checks = 0;
        for (j = 0; j < DETECT_TBLSIZE; j++) {
            checks += de_ctx->profile_keyword_ctx_per_list[i]->data[j].checks;
        }

        if (checks) {
            const char *name = NULL;
            if (i < DETECT_SM_LIST_DYNAMIC_START) {
                name = DetectSigmatchListEnumToString(i);
            } else {
                name = DetectEngineBufferTypeGetNameById(de_ctx, i);
            }

            DoDump(de_ctx->profile_keyword_ctx_per_list[i], fp, name);
        }
    }

    fprintf(fp,"\n");
    if (fp != stdout)
        fclose(fp);

    SCLogPerf("Done dumping keyword profiling data.");
}

/**
 * \brief Update a rule counter.
 *
 * \param id The ID of this counter.
 * \param ticks Number of CPU ticks for this rule.
 * \param match Did the rule match?
 */
void
SCProfilingKeywordUpdateCounter(DetectEngineThreadCtx *det_ctx, int id, uint64_t ticks, int match)
{
    if (det_ctx != NULL && det_ctx->keyword_perf_data != NULL && id < DETECT_TBLSIZE) {
        SCProfileKeywordData *p = &det_ctx->keyword_perf_data[id];

        p->checks++;
        p->matches += match;
        if (ticks > p->max)
            p->max = ticks;
        if (match == 1)
            p->ticks_match += ticks;
        else
            p->ticks_no_match += ticks;

        /* store per list (buffer type) as well */
        if (det_ctx->keyword_perf_list >= 0) {// && det_ctx->keyword_perf_list < DETECT_SM_LIST_MAX) {
            p = &det_ctx->keyword_perf_data_per_list[det_ctx->keyword_perf_list][id];
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
}

static SCProfileKeywordDetectCtx *SCProfilingKeywordInitCtx(void)
{
    SCProfileKeywordDetectCtx *ctx = SCMalloc(sizeof(SCProfileKeywordDetectCtx));
    if (ctx != NULL) {
        memset(ctx, 0x00, sizeof(SCProfileKeywordDetectCtx));

        if (pthread_mutex_init(&ctx->data_m, NULL) != 0) {
                    FatalError(SC_ERR_FATAL,
                               "Failed to initialize hash table mutex.");
        }
    }

    return ctx;
}

static void DetroyCtx(SCProfileKeywordDetectCtx *ctx)
{
    if (ctx) {
        if (ctx->data != NULL)
            SCFree(ctx->data);
        pthread_mutex_destroy(&ctx->data_m);
        SCFree(ctx);
    }
}

void SCProfilingKeywordDestroyCtx(DetectEngineCtx *de_ctx)
{
    if (de_ctx != NULL) {
        SCProfilingKeywordDump(de_ctx);

        DetroyCtx(de_ctx->profile_keyword_ctx);

        const int nlists = de_ctx->buffer_type_id;
        int i;
        for (i = 0; i < nlists; i++) {
            DetroyCtx(de_ctx->profile_keyword_ctx_per_list[i]);
        }
        SCFree(de_ctx->profile_keyword_ctx_per_list);
    }
}

void SCProfilingKeywordThreadSetup(SCProfileKeywordDetectCtx *ctx, DetectEngineThreadCtx *det_ctx)
{
    if (ctx == NULL)
        return;

    SCProfileKeywordData *a = SCMalloc(sizeof(SCProfileKeywordData) * DETECT_TBLSIZE);
    if (a != NULL) {
        memset(a, 0x00, sizeof(SCProfileKeywordData) * DETECT_TBLSIZE);
        det_ctx->keyword_perf_data = a;
    }

    const int nlists = det_ctx->de_ctx->buffer_type_id;
    det_ctx->keyword_perf_data_per_list = SCCalloc(nlists, sizeof(SCProfileKeywordData *));
    BUG_ON(det_ctx->keyword_perf_data_per_list == NULL);

    int i;
    for (i = 0; i < nlists; i++) {
        SCProfileKeywordData *b = SCMalloc(sizeof(SCProfileKeywordData) * DETECT_TBLSIZE);
        if (b != NULL) {
            memset(b, 0x00, sizeof(SCProfileKeywordData) * DETECT_TBLSIZE);
            det_ctx->keyword_perf_data_per_list[i] = b;
        }

    }
}

static void SCProfilingKeywordThreadMerge(DetectEngineCtx *de_ctx, DetectEngineThreadCtx *det_ctx)
{
    if (de_ctx == NULL || de_ctx->profile_keyword_ctx == NULL ||
        de_ctx->profile_keyword_ctx->data == NULL || det_ctx == NULL ||
        det_ctx->keyword_perf_data == NULL)
        return;

    int i;
    for (i = 0; i < DETECT_TBLSIZE; i++) {
        de_ctx->profile_keyword_ctx->data[i].checks += det_ctx->keyword_perf_data[i].checks;
        de_ctx->profile_keyword_ctx->data[i].matches += det_ctx->keyword_perf_data[i].matches;
        de_ctx->profile_keyword_ctx->data[i].ticks_match += det_ctx->keyword_perf_data[i].ticks_match;
        de_ctx->profile_keyword_ctx->data[i].ticks_no_match += det_ctx->keyword_perf_data[i].ticks_no_match;
        if (det_ctx->keyword_perf_data[i].max > de_ctx->profile_keyword_ctx->data[i].max)
            de_ctx->profile_keyword_ctx->data[i].max = det_ctx->keyword_perf_data[i].max;
    }

    const int nlists = det_ctx->de_ctx->buffer_type_id;
    int j;
    for (j = 0; j < nlists; j++) {
        for (i = 0; i < DETECT_TBLSIZE; i++) {
            de_ctx->profile_keyword_ctx_per_list[j]->data[i].checks += det_ctx->keyword_perf_data_per_list[j][i].checks;
            de_ctx->profile_keyword_ctx_per_list[j]->data[i].matches += det_ctx->keyword_perf_data_per_list[j][i].matches;
            de_ctx->profile_keyword_ctx_per_list[j]->data[i].ticks_match += det_ctx->keyword_perf_data_per_list[j][i].ticks_match;
            de_ctx->profile_keyword_ctx_per_list[j]->data[i].ticks_no_match += det_ctx->keyword_perf_data_per_list[j][i].ticks_no_match;
            if (det_ctx->keyword_perf_data_per_list[j][i].max > de_ctx->profile_keyword_ctx_per_list[j]->data[i].max)
                de_ctx->profile_keyword_ctx_per_list[j]->data[i].max = det_ctx->keyword_perf_data_per_list[j][i].max;
        }
    }
}

void SCProfilingKeywordThreadCleanup(DetectEngineThreadCtx *det_ctx)
{
    if (det_ctx == NULL || det_ctx->de_ctx == NULL || det_ctx->keyword_perf_data == NULL)
        return;

    pthread_mutex_lock(&det_ctx->de_ctx->profile_keyword_ctx->data_m);
    SCProfilingKeywordThreadMerge(det_ctx->de_ctx, det_ctx);
    pthread_mutex_unlock(&det_ctx->de_ctx->profile_keyword_ctx->data_m);

    SCFree(det_ctx->keyword_perf_data);
    det_ctx->keyword_perf_data = NULL;

    const int nlists = det_ctx->de_ctx->buffer_type_id;
    int i;
    for (i = 0; i < nlists; i++) {
        SCFree(det_ctx->keyword_perf_data_per_list[i]);
        det_ctx->keyword_perf_data_per_list[i] = NULL;
    }
    SCFree(det_ctx->keyword_perf_data_per_list);
}

/**
 * \brief Register the keyword profiling counters.
 *
 * \param de_ctx The active DetectEngineCtx, used to get at the loaded rules.
 */
void
SCProfilingKeywordInitCounters(DetectEngineCtx *de_ctx)
{
    if (profiling_keyword_enabled == 0)
        return;

    const int nlists = de_ctx->buffer_type_id;

    de_ctx->profile_keyword_ctx = SCProfilingKeywordInitCtx();
    BUG_ON(de_ctx->profile_keyword_ctx == NULL);

    de_ctx->profile_keyword_ctx->data = SCMalloc(sizeof(SCProfileKeywordData) * DETECT_TBLSIZE);
    BUG_ON(de_ctx->profile_keyword_ctx->data == NULL);
    memset(de_ctx->profile_keyword_ctx->data, 0x00, sizeof(SCProfileKeywordData) * DETECT_TBLSIZE);

    de_ctx->profile_keyword_ctx_per_list = SCCalloc(nlists, sizeof(SCProfileKeywordDetectCtx *));
    BUG_ON(de_ctx->profile_keyword_ctx_per_list == NULL);

    int i;
    for (i = 0; i < nlists; i++) {
        de_ctx->profile_keyword_ctx_per_list[i] = SCProfilingKeywordInitCtx();
        BUG_ON(de_ctx->profile_keyword_ctx_per_list[i] == NULL);
        de_ctx->profile_keyword_ctx_per_list[i]->data = SCMalloc(sizeof(SCProfileKeywordData) * DETECT_TBLSIZE);
        BUG_ON(de_ctx->profile_keyword_ctx_per_list[i]->data == NULL);
        memset(de_ctx->profile_keyword_ctx_per_list[i]->data, 0x00, sizeof(SCProfileKeywordData) * DETECT_TBLSIZE);
    }

    SCLogPerf("Registered %"PRIu32" keyword profiling counters.", DETECT_TBLSIZE);
}

#endif /* PROFILING */
