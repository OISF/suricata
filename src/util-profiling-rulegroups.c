/* Copyright (C) 2007-2015 Open Information Security Foundation
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

#include "conf.h"
#include "detect.h"
#include "suricata-common.h"
#include "util-profiling.h"
#include <stdint.h>
#include <stdlib.h>

#ifdef PROFILING
#include "util-conf.h"
#include "util-path.h"
#include "util-time.h"

typedef struct SCProfileSghDataSizeDist_ {
    uint64_t bin_size;
    uint64_t max_size;
    int bin_cnt;
    uint64_t *bins;
    uint64_t out_of_range_cnt;
} SCProfileSghDataSizeDist;
/**
 * Extra data for rule profiling.
 */
typedef struct SCProfileSghData_ {
    uint64_t checks;
    
    uint64_t non_mpm_generic;
    uint64_t non_mpm_syn;

    uint64_t post_prefilter_sigs_total;
    uint64_t post_prefilter_sigs_max;
    
    uint64_t mpm_checks;
    uint64_t mpm_match_cnt_total;
    uint64_t mpm_match_cnt_max;
    SCProfileSghDataSizeDist * size_dist;

} SCProfileSghData;

typedef struct SCProfileSghDetectCtx_ {
    uint32_t cnt;
    SCProfileSghData *data;
    pthread_mutex_t data_m;
} SCProfileSghDetectCtx;

static int profiling_sghs_output_to_file = 0;
int profiling_sghs_enabled = 0;
static char profiling_file_name[PATH_MAX];
static const char *profiling_file_mode = "a";
static int profiling_rulegroup_json = 0;
static int profiling_size_dist = 0; 
static uint64_t profiling_size_dist_bin_size = 1024;
static uint64_t profiling_size_dist_n_bins = 20;
void SCProfilingSghsGlobalInit(void)
{
    ConfNode *conf;

    conf = ConfGetNode("profiling.rulegroups");
    if (conf != NULL) {
        if (ConfNodeChildValueIsTrue(conf, "enabled")) {
            profiling_sghs_enabled = 1;
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

                profiling_sghs_output_to_file = 1;
            }
            if (ConfNodeChildValueIsTrue(conf, "json")) {
                profiling_rulegroup_json = 1;
                if (ConfNodeChildValueIsTrue(conf, "size_dist")) {
                    profiling_size_dist = 1;
                    int ret = ConfGetChildValueIntWithDefault(
                            conf, "size_dist_bin_size", &profiling_size_dist_bin_size);
                    if (!ret) {
                        profiling_size_dist_bin_size = 1024;
                    }
                    ret = ConfGetChildValueIntWithDefault(
                            conf, "size_dist_n_bins", &profiling_size_dist_n_bins);
                    if (!ret) {
                        profiling_size_dist_n_bins = 20;
                    }
                    
                }
            }
        }
    }
}

static void DoDumpJSON(SCProfileSghDetectCtx *rules_ctx, FILE *fp, const char *name)
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
    CreateIsoTimeString(SCTIME_FROM_TIMEVAL(&tval), timebuf, sizeof(timebuf));
    json_object_set_new(js, "timestamp", json_string(timebuf));

    for (i = 0; i < rules_ctx->cnt; i++) {
        SCProfileSghData *d = &rules_ctx->data[i];
        if (d == NULL || d->checks == 0)
            continue;

        double avgsigs = 0;
        double avgmpms = 0;

        if (d->post_prefilter_sigs_total && d->checks) {
            avgsigs = (double)((double)d->post_prefilter_sigs_total / (double)d->checks);
        }
        if (d->mpm_match_cnt_total && d->checks) {
            avgmpms = (double)((double)d->mpm_match_cnt_total / (double)d->checks);
        }

        json_t *jsm = json_object();
        if (jsm) {
            json_object_set_new(jsm, "id", json_integer(i));
            json_object_set_new(jsm, "checks", json_integer(d->checks));
            json_object_set_new(jsm, "non_mpm_generic", json_integer(d->non_mpm_generic));
            json_object_set_new(jsm, "non_mpm_syn", json_integer(d->non_mpm_syn));
            json_object_set_new(jsm, "avgmpms", json_real(avgmpms));
            json_object_set_new(jsm, "mpm_match_cnt_max", json_integer(d->mpm_match_cnt_max));
            json_object_set_new(jsm, "avgsigs", json_real(avgsigs));
            json_object_set_new(jsm, "post_prefilter_sigs_max", json_integer(d->post_prefilter_sigs_max));
            json_object_set_new(jsm, "mpm_checks", json_integer(d->mpm_checks));
            json_array_append_new(jsa, jsm);
        }
    }
    json_object_set_new(js, "rule_groups", jsa);

    char *js_s = json_dumps(js,
            JSON_PRESERVE_ORDER|JSON_COMPACT|JSON_ENSURE_ASCII|
            JSON_ESCAPE_SLASH);
    if (likely(js_s != NULL)) {
        fprintf(fp, "%s", js_s);
        free(js_s);
    }
    json_decref(js);
}

static void DoDump(SCProfileSghDetectCtx *rules_ctx, FILE *fp, const char *name)
{
    uint32_t i;
    struct timeval tval;
    struct tm *tms;
    struct tm local_tm;

    gettimeofday(&tval, NULL);
    tms = SCLocalTime(tval.tv_sec, &local_tm);

    fprintf(fp, "  ----------------------------------------------"
            "------------------------------------------------------"
            "----------------------------\n");
    fprintf(fp, "  Date: %" PRId32 "/%" PRId32 "/%04d -- "
            "%02d:%02d:%02d\n", tms->tm_mon + 1, tms->tm_mday, tms->tm_year + 1900,
            tms->tm_hour,tms->tm_min, tms->tm_sec);

    fprintf(fp, "  ----------------------------------------------"
            "------------------------------------------------------"
            "----------------------------\n");
    fprintf(fp, "  Stats for: %s %u\n", name, rules_ctx->cnt);
    fprintf(fp, "  ----------------------------------------------"
            "------------------------------------------------------"
            "----------------------------\n");
    fprintf(fp, "  %-16s %-18s %-18s %-18s %-18s %-18s %-18s %-18s %-18s\n", "Sgh", "Checks", "Non-MPM(gen)", "Non-Mpm(syn)", "MPM Matches", "MPM Match Max", "Post-Filter", "Post-Filter Max", "MPM Checks (HS)");
    fprintf(fp, "  ---------------- "
                "------------------ "
                "------------------ "
                "------------------ "
                "------------------ "
                "------------------ "
                "------------------ "
                "------------------ "
                "------------------ "
        "\n");
    for (i = 0; i < rules_ctx->cnt; i++) {
        SCProfileSghData *d = &rules_ctx->data[i];
        if (d == NULL || d->checks == 0)
            continue;

        double avgsigs = 0;
        double avgmpms = 0;

        if (d->post_prefilter_sigs_total && d->checks) {
            avgsigs = (double)((double)d->post_prefilter_sigs_total / (double)d->checks);
        }
        if (d->mpm_match_cnt_total && d->checks) {
            avgmpms = (double)((double)d->mpm_match_cnt_total / (double)d->checks);
        }

        fprintf(fp,
            "  %-16u %-18"PRIu64" %-18"PRIu64" %-18"PRIu64" %-18.2f %-18"PRIu64" %-18.2f %-18"PRIu64" %-18"PRIu64"\n",
            i,
            d->checks,
            d->non_mpm_generic,
            d->non_mpm_syn,
            avgmpms,
            d->mpm_match_cnt_max,
            avgsigs,
            d->post_prefilter_sigs_max,
            d->mpm_checks);
    }
    fprintf(fp,"\n");
}

static void
SCProfilingSghDump(DetectEngineCtx *de_ctx)
{
    FILE *fp;

    if (profiling_sghs_enabled == 0)
        return;

    if (profiling_sghs_output_to_file == 1) {
        SCLogDebug("file %s mode %s", profiling_file_name, profiling_file_mode);

        fp = fopen(profiling_file_name, profiling_file_mode);

        if (fp == NULL) {
            SCLogError("failed to open %s: %s", profiling_file_name, strerror(errno));
            return;
        }
    } else {
       fp = stdout;
    }

    if (profiling_rulegroup_json) {
        DoDumpJSON(de_ctx->profile_sgh_ctx, fp, "rule groups");
    } else {
        DoDump(de_ctx->profile_sgh_ctx, fp, "rule groups");
    }

    if (fp != stdout)
        fclose(fp);

    SCLogPerf("Done dumping rulegroup profiling data.");
}

/**
 * \brief Update a rule counter.
 *
 * \param id The ID of this counter.
 * \param ticks Number of CPU ticks for this rule.
 * \param match Did the rule match?
 */
void
SCProfilingSghUpdateCounter(DetectEngineThreadCtx *det_ctx, const SigGroupHead *sgh)
{
    if (det_ctx != NULL && det_ctx->sgh_perf_data != NULL && sgh->id < det_ctx->de_ctx->sgh_array_cnt) {
        SCProfileSghData *p = &det_ctx->sgh_perf_data[sgh->id];
        p->checks++;

        if (det_ctx->non_pf_store_cnt > 0) {
            if (det_ctx->non_pf_store_ptr == sgh->non_pf_syn_store_array)
                p->non_mpm_syn++;
            else
                p->non_mpm_generic++;
        }
        p->post_prefilter_sigs_total += det_ctx->match_array_cnt;
        if (det_ctx->match_array_cnt > p->post_prefilter_sigs_max)
            p->post_prefilter_sigs_max = det_ctx->match_array_cnt;
        p->mpm_match_cnt_total += det_ctx->pmq.rule_id_array_cnt;
        if (det_ctx->pmq.rule_id_array_cnt > p->mpm_match_cnt_max)
            p->mpm_match_cnt_max = det_ctx->pmq.rule_id_array_cnt;
    }
}
/**
 * \brief Update the prefilter MPM stats for a specific SigGroupHead 
 * \param det_ctx the current thread context
 * \param sgh pointer to the specific group head
 * \param mpm_checks the number of mpm checks to add
 */
void
SCProfilingSghUpdateMPMCounters(DetectEngineThreadCtx *det_ctx, const SigGroupHead * sgh) {
    det_ctx->sgh_perf_data[sgh->id].mpm_checks += det_ctx->mtc.mpm_checks;
}
/**
 * \brief Update the prefilter size distribution statistics for a specific SigGroupHead
 * \param det_ctx the current thread context
 * \param sgh pointer to the specific group head
 * \param size the size of the seen buffer
 */
void
SCProfilingSghUpdateSizeDist(DetectEngineThreadCtx *det_ctx, const SigGroupHead * sgh, uint64_t size) {
    if (!profiling_size_dist)
        return;
    SCProfileSghDataSizeDist * dist = det_ctx->sgh_perf_data[sgh->id].size_dist;
    if (size > dist->max_size) {
        dist->out_of_range_cnt++;
    } else {
        dist->bins[size / (dist->bin_size)]++;
    }
}

static SCProfileSghDetectCtx *SCProfilingSghInitCtx(void)
{
    SCProfileSghDetectCtx *ctx = SCCalloc(1, sizeof(SCProfileSghDetectCtx));
    if (ctx != NULL) {
        if (pthread_mutex_init(&ctx->data_m, NULL) != 0) {
            FatalError("Failed to initialize mutex.");
        }
    }

    return ctx;
}

static void DetroyCtx(SCProfileSghDetectCtx *ctx)
{
    if (ctx) {
        if (ctx->data != NULL)
            SCFree(ctx->data);
        pthread_mutex_destroy(&ctx->data_m);
        SCFree(ctx);
    }
}

void SCProfilingSghDestroyCtx(DetectEngineCtx *de_ctx)
{
    if (de_ctx != NULL) {
        SCProfilingSghDump(de_ctx);

        DetroyCtx(de_ctx->profile_sgh_ctx);
    }
}
/**
 * \brief For a given rule group, initialize the size_distribution_counter
 * \param sgh_prof_data The current sgh prof data structure
 */
void 
SCProfilingSghDistInit(SCProfileSghData * sgh_prof_data) {
    SCProfileSghDataSizeDist * size_dist = 
        SCCalloc(1, sizeof(SCProfileSghDataSizeDist));
    BUG_ON(size_dist == NULL);
    size_dist->bin_size = profiling_size_dist_bin_size;
    size_dist->max_size = profiling_size_dist_n_bins * profiling_size_dist_bin_size;
    size_dist->bin_cnt = profiling_size_dist_n_bins;
    size_dist->bins = SCCalloc(profiling_size_dist_n_bins, sizeof(uint64_t));
    BUG_ON(size_dist->bins == NULL);
    sgh_prof_data->size_dist = size_dist;

}
void SCProfilingSghThreadSetup(SCProfileSghDetectCtx *ctx, DetectEngineThreadCtx *det_ctx)
{
    if (ctx == NULL)
        return;

    uint32_t array_size = det_ctx->de_ctx->sgh_array_cnt;

    SCProfileSghData *a = SCCalloc(array_size, sizeof(SCProfileSghData));
    if (a != NULL) {
        det_ctx->sgh_perf_data = a;
    }
    if (profiling_size_dist) {
        for (int i = 0; i < array_size; i++) {
            SCProfilingSghDistInit(&a[i]);
        }
    }
}

static void SCProfilingSghThreadMerge(DetectEngineCtx *de_ctx, const DetectEngineThreadCtx *det_ctx)
{
    if (de_ctx == NULL || de_ctx->profile_sgh_ctx == NULL ||
        de_ctx->profile_sgh_ctx->data == NULL || det_ctx == NULL ||
        det_ctx->sgh_perf_data == NULL)
        return;

#define ADD(name) de_ctx->profile_sgh_ctx->data[i].name += det_ctx->sgh_perf_data[i].name
    uint32_t i;
    for (i = 0; i < de_ctx->sgh_array_cnt; i++) {
        ADD(checks);
        ADD(non_mpm_generic);
        ADD(non_mpm_syn);
        ADD(post_prefilter_sigs_total);
        ADD(mpm_match_cnt_total);
        ADD(mpm_checks);

        if (det_ctx->sgh_perf_data[i].mpm_match_cnt_max > de_ctx->profile_sgh_ctx->data[i].mpm_match_cnt_max)
            de_ctx->profile_sgh_ctx->data[i].mpm_match_cnt_max = det_ctx->sgh_perf_data[i].mpm_match_cnt_max;
        if (det_ctx->sgh_perf_data[i].post_prefilter_sigs_max > de_ctx->profile_sgh_ctx->data[i].post_prefilter_sigs_max)
            de_ctx->profile_sgh_ctx->data[i].post_prefilter_sigs_max = det_ctx->sgh_perf_data[i].post_prefilter_sigs_max;
        SCProfileSghDataSizeDist * sgh_profile_dist = 
            de_ctx->profile_sgh_ctx->data[i].size_dist;
        for (int j = 0; j < sgh_profile_dist->bin_cnt; j++) {
            sgh_profile_dist->bins[j] += det_ctx->sgh_perf_data[i].size_dist->bins[j];
        }
    }
#undef ADD
}

void SCProfilingSghThreadCleanup(DetectEngineThreadCtx *det_ctx)
{
    if (det_ctx == NULL || det_ctx->de_ctx == NULL || det_ctx->sgh_perf_data == NULL)
        return;

    pthread_mutex_lock(&det_ctx->de_ctx->profile_sgh_ctx->data_m);
    SCProfilingSghThreadMerge(det_ctx->de_ctx, det_ctx);
    pthread_mutex_unlock(&det_ctx->de_ctx->profile_sgh_ctx->data_m);
    if (profiling_size_dist) {
        for (int i = 0; i < det_ctx->de_ctx->sgh_array_cnt; i++) {
            SCProfileSghDataSizeDist * sgh_profile_dist = det_ctx->sgh_perf_data[i].size_dist;
            SCFree(sgh_profile_dist->bins);
            SCFree(sgh_profile_dist);
        }
    }
    SCFree(det_ctx->sgh_perf_data);
    det_ctx->sgh_perf_data = NULL;

}

/**
 * \brief Initialize the size distribution counters per rule group.
 * \param de_ctx The active DetectEngineCtx, used to get at the loaded rules.
 */
void 
SCPRofilingSghSizeDistInit(DetectEngineCtx * de_ctx) {
    if (profiling_size_dist == 0)
        return;
    SCProfileSghData * profile_data_arr = de_ctx->profile_sgh_ctx->data;
    int n_sgh = de_ctx->sgh_array_cnt;
    for (int i = 0; i < n_sgh; i++) {
        SCProfilingSghDistInit(&profile_data_arr[i]);
    }
} 

/**
 * \brief Register the keyword profiling counters.
 *
 * \param de_ctx The active DetectEngineCtx, used to get at the loaded rules.
 */
void
SCProfilingSghInitCounters(DetectEngineCtx *de_ctx)
{
    if (profiling_sghs_enabled == 0)
        return;

    de_ctx->profile_sgh_ctx = SCProfilingSghInitCtx();
    BUG_ON(de_ctx->profile_sgh_ctx == NULL);

    de_ctx->profile_sgh_ctx->data = SCCalloc(de_ctx->sgh_array_cnt, sizeof(SCProfileSghData));
    BUG_ON(de_ctx->profile_sgh_ctx->data == NULL);

    de_ctx->profile_sgh_ctx->cnt = de_ctx->sgh_array_cnt;
    SCPRofilingSghSizeDistInit(de_ctx);

    SCLogPerf("Registered %"PRIu32" rulegroup profiling counters.", de_ctx->sgh_array_cnt);
}

#endif /* PROFILING */
