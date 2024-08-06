/* Copyright (C) 2007-2022 Open Information Security Foundation
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
#include "detect-engine-prefilter.h"
#include "util-conf.h"
#include "util-path.h"
#include "util-time.h"

typedef struct SCProfilePrefilterData_ {
    uint64_t called;
    uint64_t total;
    uint64_t max;
    uint64_t total_bytes;
    uint64_t max_bytes;
    uint64_t bytes_called; /**< number of times total_bytes was updated. Differs from `called` as a
                              prefilter engine may skip mpm if the smallest pattern is bigger than
                              the buffer to inspect. */
    const char *name;
} SCProfilePrefilterData;

typedef struct SCProfilePrefilterDetectCtx_ {
    uint32_t id;
    uint32_t size;                  /**< size in elements */
    SCProfilePrefilterData *data;
    SCProfilePrefilterData **sgh_data;
    uint32_t sgh_data_cnt;
    pthread_mutex_t data_m;
} SCProfilePrefilterDetectCtx;

static int profiling_prefilter_output_to_file = 0;
int profiling_prefilter_enabled = 0;
int profiling_prefilter_per_group_enabled = 0;
thread_local int profiling_prefilter_entered = 0;
static char profiling_file_name[PATH_MAX];
static const char *profiling_file_mode = "a";

void SCProfilingPrefilterGlobalInit(void)
{
    ConfNode *conf;

    conf = ConfGetNode("profiling.prefilter");
    if (conf != NULL) {
        if (ConfNodeChildValueIsTrue(conf, "rulegroup")) {
            profiling_prefilter_per_group_enabled = 1;
        }
        if (ConfNodeChildValueIsTrue(conf, "enabled")) {
            profiling_prefilter_enabled = 1;
            const char *filename = ConfNodeLookupChildValue(conf, "filename");
            if (filename != NULL) {
                if (PathIsAbsolute(filename)) {
                    strlcpy(profiling_file_name, filename, sizeof(profiling_file_name));
                } else {
                    const char *log_dir = ConfigGetLogDirectory();
                    snprintf(profiling_file_name, sizeof(profiling_file_name), "%s/%s", log_dir,
                            filename);
                }

                const char *v = ConfNodeLookupChildValue(conf, "append");
                if (v == NULL || ConfValIsTrue(v)) {
                    profiling_file_mode = "a";
                } else {
                    profiling_file_mode = "w";
                }

                profiling_prefilter_output_to_file = 1;
            }
        }
    }
}

//static void DoDump(SCProfilePrefilterDetectCtx *rules_ctx, FILE *fp, const char *name)
static void DoDump(int prefilter_ctx_size, SCProfilePrefilterData * data, FILE *fp, const char *name)
{
    int i;
    fprintf(fp, "  ----------------------------------------------"
            "------------------------------------------------------"
            "----------------------------\n");
    fprintf(fp, "  Stats for: %s\n", name);
    fprintf(fp, "  ----------------------------------------------"
            "------------------------------------------------------"
            "----------------------------\n");
    fprintf(fp, "  %-32s %-15s %-15s %-15s %-15s %-15s %-15s %-15s %-15s %-15s\n", "Prefilter",
            "Ticks", "Called", "Max Ticks", "Avg", "Bytes", "Called", "Max Bytes", "Avg Bytes",
            "Ticks/Byte");
    fprintf(fp, "  -------------------------------- "
                "--------------- "
                "--------------- "
                "--------------- "
                "--------------- "
                "--------------- "
                "--------------- "
                "--------------- "
                "--------------- "
                "--------------- "
                "\n");
    for (i = 0; i < prefilter_ctx_size; i++) {
        SCProfilePrefilterData *d = &data[i];
        if (d == NULL || d->called== 0)
            continue;

        uint64_t ticks = d->total;
        double avgticks = 0;
        if (ticks && d->called) {
            avgticks = (double)(ticks / d->called);
        }
        double avgbytes = 0;
        if (d->total_bytes && d->bytes_called) {
            avgbytes = (double)(d->total_bytes / d->bytes_called);
        }
        double ticks_per_byte = 0;
        if (ticks && d->total_bytes) {
            ticks_per_byte = (double)(ticks / d->total_bytes);
        }

        fprintf(fp,
                "  %-32s %-15" PRIu64 " %-15" PRIu64 " %-15" PRIu64 " %-15.2f %-15" PRIu64
                " %-15" PRIu64 " %-15" PRIu64 " %-15.2f %-15.2f\n",
                d->name, ticks, d->called, d->max, avgticks, d->total_bytes, d->bytes_called,
                d->max_bytes, avgbytes, ticks_per_byte);
    }
}

static void
SCProfilingPrefilterDump(DetectEngineCtx *de_ctx)
{
    FILE *fp;
    struct timeval tval;
    struct tm *tms;
    struct tm local_tm;

    if (profiling_prefilter_enabled == 0 || de_ctx->profile_prefilter_ctx == NULL)
        return;

    gettimeofday(&tval, NULL);
    tms = SCLocalTime(tval.tv_sec, &local_tm);

    if (profiling_prefilter_output_to_file == 1) {
        SCLogDebug("file %s mode %s", profiling_file_name, profiling_file_mode);

        fp = fopen(profiling_file_name, profiling_file_mode);

        if (fp == NULL) {
            SCLogError("failed to open %s: %s", profiling_file_name, strerror(errno));
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
    DoDump(de_ctx->profile_prefilter_ctx->size, de_ctx->profile_prefilter_ctx->data, fp, "total");



    SCLogPerf("Done dumping prefilter profiling data.");
    char name[32];
    for (uint32_t i = 0; i < de_ctx->sgh_array_cnt; i++) {
        snprintf(name, sizeof(name), "Signature group %"PRIu32, i);
        DoDump(de_ctx->profile_prefilter_ctx->size, de_ctx->profile_prefilter_ctx->sgh_data[i], fp, name);
    }

    fprintf(fp,"\n");
    if (fp != stdout)
        fclose(fp);
}

/**
 * \brief Update a rule counter.
 *
 * \param id The ID of this counter.
 * \param ticks Number of CPU ticks for this rule.
 * \param match Did the rule match?
 */
void SCProfilingPrefilterUpdateCounter(DetectEngineThreadCtx *det_ctx, int id, uint64_t ticks,
        uint64_t bytes, uint64_t bytes_called)
{
    if (det_ctx != NULL && det_ctx->prefilter_perf_data != NULL &&
            id < (int)det_ctx->de_ctx->prefilter_id)
    {
        SCProfilePrefilterData *p = &det_ctx->prefilter_perf_data[id];

        p->called++;
        if (ticks > p->max)
            p->max = ticks;
        p->total += ticks;

        p->bytes_called += bytes_called;
        if (bytes > p->max_bytes)
            p->max_bytes = bytes;
        p->total_bytes += bytes;
    }

}
/**
 * \brief Update a rule counter.
 *
 * \param id The ID of this counter.
 * \param sgh the current Signature group head being prefiltered
 * \param ticks Number of CPU ticks for this rule.
 * \param match Did the rule match?
 */
void 
SCProfilingSGHPrefilterUpdateCounter(
    DetectEngineThreadCtx *det_ctx, int id, const SigGroupHead * sgh, uint64_t ticks,
    uint64_t bytes, uint64_t bytes_called
) {
    if (profiling_prefilter_per_group_enabled && det_ctx != NULL && det_ctx->sgh_prefilter_perf_data != NULL && id < (int)det_ctx->de_ctx->prefilter_id) {
        SCProfilePrefilterData *p = &det_ctx->sgh_prefilter_perf_data[sgh->id][id];
        p->called++;
        if (ticks > p->max)
            p->max = ticks;
        p->total += ticks;

        p->bytes_called += bytes_called;
        if (bytes > p->max_bytes)
            p->max_bytes = bytes;
        p->total_bytes += bytes;
    }

}
static SCProfilePrefilterDetectCtx *SCProfilingPrefilterInitCtx(void)
{
    SCProfilePrefilterDetectCtx *ctx = SCCalloc(1, sizeof(SCProfilePrefilterDetectCtx));
    if (ctx != NULL) {
        if (pthread_mutex_init(&ctx->data_m, NULL) != 0) {
            FatalError("Failed to initialize hash table mutex.");
        }
    }

    return ctx;
}

static void DetroyCtx(SCProfilePrefilterDetectCtx *ctx)
{
    if (ctx) {
        if (ctx->data != NULL)
            SCFree(ctx->data);
        if (profiling_prefilter_per_group_enabled && ctx->sgh_data != NULL) {
            for (uint32_t i = 0; i < ctx->sgh_data_cnt; i++) {
                SCFree(ctx->sgh_data[i]);
            }
            SCFree(ctx->sgh_data);
        }
        pthread_mutex_destroy(&ctx->data_m);
        SCFree(ctx);
    }
}

void SCProfilingPrefilterDestroyCtx(DetectEngineCtx *de_ctx)
{
    if (de_ctx != NULL) {
        SCProfilingPrefilterDump(de_ctx);

        DetroyCtx(de_ctx->profile_prefilter_ctx);
    }
}

void SCProfilingPrefilterThreadSetup(SCProfilePrefilterDetectCtx *ctx, DetectEngineThreadCtx *det_ctx)
{
    if (ctx == NULL)
        return;

    const uint32_t size = det_ctx->de_ctx->prefilter_id;

    SCProfilePrefilterData *a = SCCalloc(1, sizeof(SCProfilePrefilterData) * size);
    if (a != NULL) {
        det_ctx->prefilter_perf_data = a;
    }


    //Per sgh logic TODO: Make it configurable
    if (!profiling_prefilter_per_group_enabled) {
        det_ctx->sgh_prefilter_perf_data_cnt = 0;
        return;
    }
    uint32_t n_sgh = det_ctx->de_ctx->sgh_array_cnt;
    BUG_ON(n_sgh == 0);
    SCProfilePrefilterData ** sgh_pf_perf_arr = 
        SCCalloc(n_sgh, sizeof(SCProfilePrefilterData *));
    if (sgh_pf_perf_arr != NULL) {
        for (uint32_t i = 0; i < n_sgh; i++) {
            SCProfilePrefilterData *b = SCCalloc(1, sizeof(SCProfilePrefilterData) * size);
            if (b != NULL) {
                sgh_pf_perf_arr[i] = b;
            } else {
                for (uint32_t j = 0; j < i; j++) {
                    SCFree(sgh_pf_perf_arr[j]);
                }
                SCFree(sgh_pf_perf_arr);
                sgh_pf_perf_arr = NULL;
                return;
            }
        }
    } else {
        return;
    }
    det_ctx->sgh_prefilter_perf_data = sgh_pf_perf_arr;
    det_ctx->sgh_prefilter_perf_data_cnt = n_sgh;

}

static void SCProfilingPrefilterThreadMerge(DetectEngineCtx *de_ctx, DetectEngineThreadCtx *det_ctx)
{
    if (de_ctx == NULL || de_ctx->profile_prefilter_ctx == NULL ||
        de_ctx->profile_prefilter_ctx->data == NULL || det_ctx == NULL ||
        det_ctx->prefilter_perf_data == NULL || det_ctx->sgh_prefilter_perf_data == NULL)
        return;

    for (uint32_t i = 0; i < de_ctx->prefilter_id; i++) {
        de_ctx->profile_prefilter_ctx->data[i].called += det_ctx->prefilter_perf_data[i].called;
        de_ctx->profile_prefilter_ctx->data[i].total += det_ctx->prefilter_perf_data[i].total;
        if (det_ctx->prefilter_perf_data[i].max > de_ctx->profile_prefilter_ctx->data[i].max)
            de_ctx->profile_prefilter_ctx->data[i].max = det_ctx->prefilter_perf_data[i].max;
        de_ctx->profile_prefilter_ctx->data[i].total_bytes +=
                det_ctx->prefilter_perf_data[i].total_bytes;
        if (det_ctx->prefilter_perf_data[i].max_bytes >
                de_ctx->profile_prefilter_ctx->data[i].max_bytes)
            de_ctx->profile_prefilter_ctx->data[i].max_bytes =
                    det_ctx->prefilter_perf_data[i].max_bytes;
        de_ctx->profile_prefilter_ctx->data[i].bytes_called +=
                det_ctx->prefilter_perf_data[i].bytes_called;
    }
    if (!profiling_prefilter_per_group_enabled)
        return;

    for (uint32_t sgh_idx = 0; sgh_idx < det_ctx->sgh_prefilter_perf_data_cnt; sgh_idx++) {
        for (uint32_t i = 0; i < de_ctx->prefilter_id; i++) {
            de_ctx->profile_prefilter_ctx->sgh_data[sgh_idx][i].called +=
                    det_ctx->sgh_prefilter_perf_data[sgh_idx][i].called;
            de_ctx->profile_prefilter_ctx->sgh_data[sgh_idx][i].total +=
                    det_ctx->sgh_prefilter_perf_data[sgh_idx][i].total;
            if (det_ctx->sgh_prefilter_perf_data[sgh_idx][i].max >
                    de_ctx->profile_prefilter_ctx->sgh_data[sgh_idx][i].max)
                de_ctx->profile_prefilter_ctx->sgh_data[sgh_idx][i].max =
                        det_ctx->sgh_prefilter_perf_data[sgh_idx][i].max;
            de_ctx->profile_prefilter_ctx->sgh_data[sgh_idx][i].total_bytes +=
                    det_ctx->sgh_prefilter_perf_data[sgh_idx][i].total_bytes;
            if (det_ctx->sgh_prefilter_perf_data[sgh_idx][i].max_bytes >
                    de_ctx->profile_prefilter_ctx->sgh_data[sgh_idx][i].max_bytes)
                de_ctx->profile_prefilter_ctx->sgh_data[sgh_idx][i].max_bytes =
                        det_ctx->sgh_prefilter_perf_data[sgh_idx][i].max_bytes;
            de_ctx->profile_prefilter_ctx->sgh_data[sgh_idx][i].bytes_called +=
                    det_ctx->sgh_prefilter_perf_data[sgh_idx][i].bytes_called;
        }
    }

}

void SCProfilingPrefilterThreadCleanup(DetectEngineThreadCtx *det_ctx)
{
    if (
        det_ctx == NULL || det_ctx->de_ctx == NULL ||
        det_ctx->prefilter_perf_data == NULL || det_ctx->sgh_prefilter_perf_data == NULL 
    )
        return;

    pthread_mutex_lock(&det_ctx->de_ctx->profile_prefilter_ctx->data_m);
    SCProfilingPrefilterThreadMerge(det_ctx->de_ctx, det_ctx);
    pthread_mutex_unlock(&det_ctx->de_ctx->profile_prefilter_ctx->data_m);

    SCFree(det_ctx->prefilter_perf_data);
    det_ctx->prefilter_perf_data = NULL;
    if (!profiling_prefilter_per_group_enabled)
        return;
    for (uint32_t i = 0; i < det_ctx->sgh_prefilter_perf_data_cnt; i++) {
        SCFree(det_ctx->sgh_prefilter_perf_data[i]);
    }
    SCFree(det_ctx->sgh_prefilter_perf_data);
    det_ctx->sgh_prefilter_perf_data = NULL;
}

/**
 * \brief Register the prefilter profiling counters.
 *
 * \param de_ctx The active DetectEngineCtx, used to get at the loaded rules.
 */
void
SCProfilingPrefilterInitCounters(DetectEngineCtx *de_ctx)
{
    if (profiling_prefilter_enabled == 0)
        return;

    const uint32_t size = de_ctx->prefilter_id;
    if (size == 0)
        return;

    de_ctx->profile_prefilter_ctx = SCProfilingPrefilterInitCtx();
    BUG_ON(de_ctx->profile_prefilter_ctx == NULL);
    de_ctx->profile_prefilter_ctx->size = size;

    de_ctx->profile_prefilter_ctx->data = SCCalloc(1, sizeof(SCProfilePrefilterData) * size);
    BUG_ON(de_ctx->profile_prefilter_ctx->data == NULL);

    HashListTableBucket *hb = HashListTableGetListHead(de_ctx->prefilter_hash_table);
    for ( ; hb != NULL; hb = HashListTableGetListNext(hb)) {
        PrefilterStore *ctx = HashListTableGetListData(hb);
        de_ctx->profile_prefilter_ctx->data[ctx->id].name = ctx->name;
        SCLogDebug("prefilter %s set up", de_ctx->profile_prefilter_ctx->data[ctx->id].name);
    }
    SCLogDebug("size alloc'd %u", (uint32_t)size * (uint32_t)sizeof(SCProfilePrefilterData));

    SCLogPerf("Registered %"PRIu32" prefilter profiling counters.", size);
    if (!profiling_prefilter_per_group_enabled)
        return;
    //Per sgh logic
    uint32_t n_sgh = de_ctx->sgh_array_cnt;
    BUG_ON(n_sgh == 0);
    SCProfilePrefilterData ** sgh_pf_perf_arr = 
        SCCalloc(n_sgh, sizeof(SCProfilePrefilterData *));
    BUG_ON(sgh_pf_perf_arr == NULL);
    for (uint32_t i = 0; i < n_sgh; i++) {
        SCProfilePrefilterData *b = SCCalloc(1, sizeof(SCProfilePrefilterData) * size);
        BUG_ON(b == NULL);
        sgh_pf_perf_arr[i] = b;
    }

    SCLogPerf("Registered %"PRIu32" per rule group prefilter profiling counters.", size * n_sgh);
    de_ctx->profile_prefilter_ctx->sgh_data = sgh_pf_perf_arr;

    for (uint32_t i = 0; i < n_sgh; i++) {
        for (uint32_t j = 0; j < size; j++) {
            de_ctx->profile_prefilter_ctx->sgh_data[i][j].name = de_ctx->profile_prefilter_ctx->data[j].name;
        }
    }
    hb = HashListTableGetListHead(de_ctx->prefilter_hash_table);
}

#endif /* PROFILING */
