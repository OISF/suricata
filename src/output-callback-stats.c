/**
 * \file
 *
 * \author Angelo Mirabella <mirabellaa@vmware.com>
 *
 * Generate stats events and invoke corresponding callback.
 *
 */

#include "suricata-common.h"
#include "output-callback-stats.h"
#include "util-debug.h"


typedef struct CallbackStatsCtx {
    uint32_t flags;
    CallbackFuncStats *cb;
    void *user_ctx;
} CallbackStatsCtx;

static CallbackStatsCtx StatsCtx;

void CallbackStatsLogInit(void *user_ctx, CallbackFuncStats cb) {
    bool stats_totals = true;
    bool stats_per_thread = false;

    memset(&StatsCtx, 0, sizeof(StatsCtx));

    StatsCtx.cb = cb;
    StatsCtx.user_ctx = user_ctx;

    ConfNode *root = ConfGetNode("outputs");
    ConfNode *node = NULL;
    ConfNode *stats = NULL;
    if (root != NULL) {
        TAILQ_FOREACH(node, &root->head, next) {
            if (strcmp(node->val, "stats") == 0) {
                stats = node->head.tqh_first;
                break;
            }
        }
    }

    if (stats != NULL) {
        int b;
        int ret = ConfGetChildValueBool(stats, "totals", &b);
        if (ret) {
            stats_totals = (b == 1);
        }
        ret = ConfGetChildValueBool(stats, "threads", &b);
        if (ret) {
            stats_per_thread = (b == 1);
        }
    }

    if (stats_totals) {
        StatsCtx.flags |= JSON_STATS_TOTALS;
    }
    if (stats_per_thread) {
        StatsCtx.flags |= JSON_STATS_THREADS;
    }

    SCLogDebug("stats flags %08x", flags);
}

void CallbackStatsLogger(const StatsTable *st) {
    if (StatsCtx.cb == NULL) {
        SCLogError("Stats callback is NULL, stats cannot be provided");
        return;
    }

    struct timeval tval;
    gettimeofday(&tval, NULL);

    json_t *js = json_object();
    if (unlikely(js == NULL)) {
        return;
    }

    char timebuf[64];
    CreateIsoTimeString(SCTIME_FROM_TIMEVAL(&tval), timebuf, sizeof(timebuf));
    json_object_set_new(js, "timestamp", json_string(timebuf));
    json_object_set_new(js, "event_type", json_string("stats"));

    json_t *js_stats = StatsToJSON(st, StatsCtx.flags);
    if (js_stats == NULL) {
        json_decref(js);
        return;
    }

    json_object_set_new(js, "stats", js_stats);

    /* Invoke stats callback. */
    const char *line = json_dumps(js, 0);
    if (line != NULL) {
        StatsCtx.cb((void *)line, strlen(line), StatsCtx.user_ctx);
        SCFree((void *)line);
    }

    json_object_clear(js_stats);
    json_object_del(js, "stats");
    json_object_clear(js);
    json_decref(js);
}
