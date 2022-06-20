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

#include "suricata-common.h"
#include "decode.h"
#include "detect.h"
#include "detect-engine.h"
#include "conf.h"

#include "tm-threads.h"

#include "util-unittest.h"
#include "util-byte.h"
#include "util-profiling.h"
#include "util-profiling-locks.h"
#include "util-time.h"

#ifdef PROFILING

/**
 * Extra data for rule profiling.
 */
typedef struct SCProfileSghData_ {
    uint64_t checks;

    uint64_t non_mpm_generic;
    uint64_t non_mpm_syn;

    uint64_t post_prefilter_sigs_total;
    uint64_t post_prefilter_sigs_max;

    uint64_t mpm_match_cnt_total;
    uint64_t mpm_match_cnt_max;

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

void SCProfilingSghsGlobalInit(void)
{
    ConfNode *conf;

    conf = ConfGetNode("profiling.rulegroups");
    if (conf != NULL) {
        if (ConfNodeChildValueIsTrue(conf, "enabled")) {
            profiling_sghs_enabled = 1;
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

                profiling_sghs_output_to_file = 1;
            }
            if (ConfNodeChildValueIsTrue(conf, "json")) {
                profiling_rulegroup_json = 1;
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
    CreateIsoTimeString(&tval, timebuf, sizeof(timebuf));
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
    fprintf(fp, "  %-16s %-15s %-15s %-15s %-15s %-15s %-15s %-15s\n", "Sgh", "Checks", "Non-MPM(gen)", "Non-Mpm(syn)", "MPM Matches", "MPM Match Max", "Post-Filter", "Post-Filter Max");
    fprintf(fp, "  ---------------- "
                "--------------- "
                "--------------- "
                "--------------- "
                "--------------- "
                "--------------- "
                "--------------- "
                "--------------- "
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
            "  %-16u %-15"PRIu64" %-15"PRIu64" %-15"PRIu64" %-15.2f %-15"PRIu64" %-15.2f %-15"PRIu64"\n",
            i,
            d->checks,
            d->non_mpm_generic,
            d->non_mpm_syn,
            avgmpms,
            d->mpm_match_cnt_max,
            avgsigs,
            d->post_prefilter_sigs_max);
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
            SCLogError(SC_ERR_FOPEN, "failed to open %s: %s", profiling_file_name,
                    strerror(errno));
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

static SCProfileSghDetectCtx *SCProfilingSghInitCtx(void)
{
    SCProfileSghDetectCtx *ctx = SCCalloc(1, sizeof(SCProfileSghDetectCtx));
    if (ctx != NULL) {
        if (pthread_mutex_init(&ctx->data_m, NULL) != 0) {
                    FatalError(SC_ERR_FATAL, "Failed to initialize mutex.");
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

void SCProfilingSghThreadSetup(SCProfileSghDetectCtx *ctx, DetectEngineThreadCtx *det_ctx)
{
    if (ctx == NULL)
        return;

    uint32_t array_size = det_ctx->de_ctx->sgh_array_cnt;

    SCProfileSghData *a = SCCalloc(array_size, sizeof(SCProfileSghData));
    if (a != NULL) {
        det_ctx->sgh_perf_data = a;
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

        if (det_ctx->sgh_perf_data[i].mpm_match_cnt_max > de_ctx->profile_sgh_ctx->data[i].mpm_match_cnt_max)
            de_ctx->profile_sgh_ctx->data[i].mpm_match_cnt_max = det_ctx->sgh_perf_data[i].mpm_match_cnt_max;
        if (det_ctx->sgh_perf_data[i].post_prefilter_sigs_max > de_ctx->profile_sgh_ctx->data[i].post_prefilter_sigs_max)
            de_ctx->profile_sgh_ctx->data[i].post_prefilter_sigs_max = det_ctx->sgh_perf_data[i].post_prefilter_sigs_max;
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

    SCFree(det_ctx->sgh_perf_data);
    det_ctx->sgh_perf_data = NULL;
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

    SCLogPerf("Registered %"PRIu32" rulegroup profiling counters.", de_ctx->sgh_array_cnt);
}

#endif /* PROFILING */
