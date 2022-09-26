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

#ifdef PROFILING
#include "util-time.h"
#include "util-profiling-locks.h"
#include "util-profiling.h"
#include "util-byte.h"
#include "util-unittest.h"
#include "tm-threads.h"
#include "conf.h"
#include "detect-engine-prefilter.h"
#include "detect-engine.h"
#include "detect.h"
#include "decode.h"
#endif
#ifdef PROFILING

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
    pthread_mutex_t data_m;
} SCProfilePrefilterDetectCtx;

static int profiling_prefilter_output_to_file = 0;
int profiling_prefilter_enabled = 0;
thread_local int profiling_prefilter_entered = 0;
static char profiling_file_name[PATH_MAX];
static const char *profiling_file_mode = "a";

void SCProfilingPrefilterGlobalInit(void)
{
    ConfNode *conf;

    conf = ConfGetNode("profiling.prefilter");
    if (conf != NULL) {
        if (ConfNodeChildValueIsTrue(conf, "enabled")) {
            profiling_prefilter_enabled = 1;
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

                profiling_prefilter_output_to_file = 1;
            }
        }
    }
}

static void DoDump(SCProfilePrefilterDetectCtx *rules_ctx, FILE *fp, const char *name)
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
    for (i = 0; i < (int)rules_ctx->size; i++) {
        SCProfilePrefilterData *d = &rules_ctx->data[i];
        if (d == NULL || d->called== 0)
            continue;

        uint64_t ticks = d->total;
        double avgticks = 0;
        if (ticks && d->called) {
            avgticks = (double)(ticks / d->called);
        }
        double avgbytes = 0;
        if (d->total_bytes && d->called) {
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
    DoDump(de_ctx->profile_prefilter_ctx, fp, "total");

    fprintf(fp,"\n");
    if (fp != stdout)
        fclose(fp);

    SCLogPerf("Done dumping prefilter profiling data.");
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

static SCProfilePrefilterDetectCtx *SCProfilingPrefilterInitCtx(void)
{
    SCProfilePrefilterDetectCtx *ctx = SCMalloc(sizeof(SCProfilePrefilterDetectCtx));
    if (ctx != NULL) {
        memset(ctx, 0x00, sizeof(SCProfilePrefilterDetectCtx));

        if (pthread_mutex_init(&ctx->data_m, NULL) != 0) {
                    FatalError(SC_ERR_FATAL,
                               "Failed to initialize hash table mutex.");
        }
    }

    return ctx;
}

static void DetroyCtx(SCProfilePrefilterDetectCtx *ctx)
{
    if (ctx) {
        if (ctx->data != NULL)
            SCFree(ctx->data);
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

    SCProfilePrefilterData *a = SCMalloc(sizeof(SCProfilePrefilterData) * size);
    if (a != NULL) {
        memset(a, 0x00, sizeof(SCProfilePrefilterData) * size);
        det_ctx->prefilter_perf_data = a;
    }
}

static void SCProfilingPrefilterThreadMerge(DetectEngineCtx *de_ctx, DetectEngineThreadCtx *det_ctx)
{
    if (de_ctx == NULL || de_ctx->profile_prefilter_ctx == NULL ||
        de_ctx->profile_prefilter_ctx->data == NULL || det_ctx == NULL ||
        det_ctx->prefilter_perf_data == NULL)
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
}

void SCProfilingPrefilterThreadCleanup(DetectEngineThreadCtx *det_ctx)
{
    if (det_ctx == NULL || det_ctx->de_ctx == NULL || det_ctx->prefilter_perf_data == NULL)
        return;

    pthread_mutex_lock(&det_ctx->de_ctx->profile_prefilter_ctx->data_m);
    SCProfilingPrefilterThreadMerge(det_ctx->de_ctx, det_ctx);
    pthread_mutex_unlock(&det_ctx->de_ctx->profile_prefilter_ctx->data_m);

    SCFree(det_ctx->prefilter_perf_data);
    det_ctx->prefilter_perf_data = NULL;
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

    de_ctx->profile_prefilter_ctx->data = SCMalloc(sizeof(SCProfilePrefilterData) * size);
    BUG_ON(de_ctx->profile_prefilter_ctx->data == NULL);
    memset(de_ctx->profile_prefilter_ctx->data, 0x00, sizeof(SCProfilePrefilterData) * size);

    HashListTableBucket *hb = HashListTableGetListHead(de_ctx->prefilter_hash_table);
    for ( ; hb != NULL; hb = HashListTableGetListNext(hb)) {
        PrefilterStore *ctx = HashListTableGetListData(hb);
        de_ctx->profile_prefilter_ctx->data[ctx->id].name = ctx->name;
        SCLogDebug("prefilter %s set up", de_ctx->profile_prefilter_ctx->data[ctx->id].name);
    }
    SCLogDebug("size alloc'd %u", (uint32_t)size * (uint32_t)sizeof(SCProfilePrefilterData));

    SCLogPerf("Registered %"PRIu32" prefilter profiling counters.", size);
}

#endif /* PROFILING */
